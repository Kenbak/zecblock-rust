//! Indexer module - main indexing logic

mod flows;
mod reorg;
mod transactions;

pub use transactions::TransactionParser;

use crate::config::Config;
use crate::db::{BlockSpool, PostgresWriter, ZebraState};
use crate::models::ShieldedFlow;
use crate::util::unix_timestamp_secs;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct LiveSourceBlock {
    height: u32,
    hash: String,
    data: Arc<[u8]>,
    source: &'static str,
    source_elapsed_ms: u64,
}

fn cached_prev_output(
    key: &(String, u32),
    current: &HashMap<(String, u32), (i64, Option<String>)>,
    database: &HashMap<(String, u32), (i64, Option<String>)>,
) -> Option<(i64, Option<String>)> {
    current.get(key).or_else(|| database.get(key)).cloned()
}
fn checkpoint_progress_height(
    current_height: u32,
    end_height: u32,
    last_successful_height: Option<u32>,
) -> Option<u32> {
    if current_height.is_multiple_of(100) || current_height == end_height {
        last_successful_height
    } else {
        None
    }
}

/// Main indexer orchestrator
pub struct Indexer {
    config: Config,
    zebra: ZebraState,
    postgres: PostgresWriter,
    block_spool: BlockSpool,
}

impl Indexer {
    const FAILURE_STATE_KEYS: [&'static str; 5] = [
        "last_failed_height",
        "last_failed_mode",
        "last_failed_error",
        "last_failed_at",
        "consecutive_failure_count",
    ];
    /// Create new indexer
    pub async fn new(config: Config) -> Result<Self, String> {
        let zebra = ZebraState::open(&config)?;
        let postgres = PostgresWriter::connect(&config.database_url)
            .await
            .map_err(|e| format!("PostgreSQL error: {}", e))?;
        let block_spool =
            BlockSpool::open(config.block_spool_path.clone(), config.max_reorg_depth)?;

        Ok(Self {
            config,
            zebra,
            postgres,
            block_spool,
        })
    }

    async fn record_failure(&self, mode: &str, height: u32, error: &str) -> Result<(), String> {
        let current_count = self
            .postgres
            .get_state("consecutive_failure_count")
            .await
            .map_err(|e| format!("Failure state read error: {}", e))?
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(0);

        let truncated_error: String = error.chars().take(500).collect();
        let timestamp = unix_timestamp_secs().to_string();
        let failure_count = current_count.saturating_add(1).to_string();

        self.postgres
            .update_checkpoint("last_failed_height", &height.to_string())
            .await
            .map_err(|e| format!("Failure state write error: {}", e))?;
        self.postgres
            .update_checkpoint("last_failed_mode", mode)
            .await
            .map_err(|e| format!("Failure state write error: {}", e))?;
        self.postgres
            .update_checkpoint("last_failed_error", &truncated_error)
            .await
            .map_err(|e| format!("Failure state write error: {}", e))?;
        self.postgres
            .update_checkpoint("last_failed_at", &timestamp)
            .await
            .map_err(|e| format!("Failure state write error: {}", e))?;
        self.postgres
            .update_checkpoint("consecutive_failure_count", &failure_count)
            .await
            .map_err(|e| format!("Failure state write error: {}", e))?;

        Ok(())
    }

    async fn clear_failure_state(&self) -> Result<(), String> {
        for key in Self::FAILURE_STATE_KEYS {
            self.postgres
                .delete_state(key)
                .await
                .map_err(|e| format!("Failure state cleanup error: {}", e))?;
        }

        Ok(())
    }

    async fn record_tip_heartbeat(&self, rpc_tip: u32) -> Result<(), String> {
        let now = unix_timestamp_secs().to_string();

        self.postgres
            .update_checkpoint("last_seen_rpc_tip", &rpc_tip.to_string())
            .await
            .map_err(|e| format!("Heartbeat write error: {}", e))?;
        self.postgres
            .update_checkpoint("last_tip_check_at", &now)
            .await
            .map_err(|e| format!("Heartbeat write error: {}", e))?;

        Ok(())
    }

    async fn record_success_heartbeat(&self) -> Result<(), String> {
        let now = unix_timestamp_secs().to_string();

        self.postgres
            .update_checkpoint("last_success_at", &now)
            .await
            .map_err(|e| format!("Heartbeat write error: {}", e))?;

        Ok(())
    }

    async fn has_active_failure_state(&self) -> Result<bool, String> {
        let failure_count = self
            .postgres
            .get_state("consecutive_failure_count")
            .await
            .map_err(|e| format!("Failure state read error: {}", e))?
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(0);

        Ok(failure_count > 0)
    }

    /// Detect chain reorganizations by comparing our stored block hash with the
    /// canonical hash from Zebra RPC. Walks backward to find the fork point, then
    /// rolls back all data from that height onward.
    ///
    /// Returns the fork height if a reorg was detected (caller should re-index from there),
    /// or None if the chain is consistent.
    async fn detect_and_handle_reorg(
        &self,
        rpc: &crate::db::ZebraRpc,
        last_indexed: u32,
        node_tip: u32,
    ) -> Result<Option<u32>, String> {
        let db_hash = self
            .postgres
            .get_block_hash_at_height(last_indexed)
            .await
            .map_err(|e| format!("DB read error: {}", e))?;

        let db_hash = match db_hash {
            Some(h) => h,
            None => return Ok(None), // no block at this height yet
        };

        let mut ancestor = None;
        for check_height in
            reorg::ancestor_heights(last_indexed, node_tip, self.config.max_reorg_depth)?
        {
            let stored = self.postgres.get_block_hash_at_height(check_height).await
                .map_err(|e| format!("DB read error at {check_height}: {e}"))?
                .ok_or_else(|| format!("Missing indexed block at {check_height}; cannot establish a common ancestor"))?;
            let canonical = rpc
                .get_block_hash(check_height as u64)
                .await
                .map_err(|e| format!("RPC error checking hash at {check_height}: {e}"))?;
            if stored == canonical {
                if check_height == last_indexed {
                    return Ok(None);
                }
                ancestor = Some((check_height, stored));
                break;
            }
        }
        let (ancestor_height, ancestor_hash) = ancestor.ok_or_else(|| {
            format!(
                "No common ancestor within {} blocks — manual intervention required",
                self.config.max_reorg_depth
            )
        })?;
        let fork_height = ancestor_height + 1;
        println!("🔄 REORG DETECTED: common ancestor {ancestor_height}, indexed tip {last_indexed}, node tip {node_tip}");

        let reorg_depth = last_indexed - fork_height + 1;
        let description = format!(
            "Chain reorg detected: depth {}, rolling back heights {}-{}",
            reorg_depth, fork_height, last_indexed
        );

        // Capture orphan bytes from RPC when still available, otherwise use the
        // bounded recent-block spool written before the reorg was observed.
        let mut raw_blocks: Vec<(String, String)> = Vec::new();
        for h in fork_height..=last_indexed {
            let hash = self
                .postgres
                .get_block_hash_at_height(h)
                .await
                .map_err(|e| format!("DB read error at {h}: {e}"))?;
            if let Some(hash) = hash {
                match rpc.get_raw_block_hex(&hash).await {
                    Ok(hex) => {
                        println!(
                            "   📦 Captured raw orphan block {} ({} bytes)",
                            h,
                            hex.len() / 2
                        );
                        raw_blocks.push((hash, hex));
                    }
                    Err(rpc_error) => match self.block_spool.read(h, &hash).await {
                        Ok(Some(bytes)) => {
                            println!(
                                "   📦 Recovered orphan block {} from bounded spool ({} bytes)",
                                h,
                                bytes.len()
                            );
                            raw_blocks.push((hash, hex::encode(bytes)));
                        }
                        Ok(None) => {
                            println!(
                                "   ⚠️ Orphan block {} unavailable via RPC or bounded spool: {}",
                                h, rpc_error
                            );
                        }
                        Err(spool_error) => {
                            println!(
                                "   ⚠️ Orphan block {} unavailable via RPC ({}); spool error: {}",
                                h, rpc_error, spool_error
                            );
                        }
                    },
                }
            }
        }

        // The node can change again while orphan bytes are captured. Never roll
        // back using an ancestor that is no longer canonical, or after the old
        // indexed branch has already been restored.
        if rpc.get_block_hash(ancestor_height as u64).await? != ancestor_hash {
            return Err("Node changed during reorg planning; retrying".into());
        }
        if rpc.get_block_count().await? >= last_indexed as u64
            && rpc.get_block_hash(last_indexed as u64).await? == db_hash
        {
            return Ok(None);
        }

        println!(
            "   🗑️ Rolling back {} blocks from height {}",
            reorg_depth, fork_height
        );

        let rolled_back = self
            .postgres
            .rollback_from_height_with_raw(fork_height, &description, &raw_blocks)
            .await
            .map_err(|e| format!("Rollback error: {}", e))?;

        println!(
            "   ✅ Rolled back {} blocks, archived to orphaned_blocks ({} with raw hex)",
            rolled_back,
            raw_blocks.len()
        );

        Ok(Some(fork_height.saturating_sub(1)))
    }

    /// Index a single block and all its transactions
    async fn index_block(&self, height: u32) -> Result<(u32, u32), String> {
        let hash_bytes = self.zebra.get_block_hash(height)?;
        let block_hash = crate::util::display_hash(&hash_bytes);

        // Get block header for timestamp and other fields
        let header = self.zebra.get_block_header(height)?;
        let block_time = header.time;

        // Get all transactions in block
        let raw_txs = self.zebra.iter_block_transactions(height)?;
        let tx_count = raw_txs.len() as u32;

        // Parse all transactions
        let mut transactions = Vec::with_capacity(raw_txs.len());
        let mut flows = Vec::new();

        for (tx_index, raw) in &raw_txs {
            let tx = TransactionParser::parse(raw, height, &block_hash, self.config.network)
                .map_err(|e| format!("Failed to parse tx {}:{}: {}", height, tx_index, e))?;
            transactions.push(tx);
        }
        TransactionParser::resolve_block_inputs(&mut transactions, &self.zebra)
            .map_err(|e| format!("Input resolution failed at {height}: {e}"))?;
        for transaction in &transactions {
            flows.extend(ShieldedFlow::from_transaction(transaction));
        }

        // Write block, transactions, and flows atomically.
        let (_, flow_count) = self
            .postgres
            .batch_insert_with_header_and_flows(
                height,
                &block_hash,
                block_time,
                &transactions,
                &flows,
                &header,
            )
            .await
            .map_err(|e| format!("DB insert error: {}", e))?;

        Ok((tx_count, flow_count as u32))
    }

    /// Run backfill from start_height to end_height (or tip)
    pub async fn backfill(
        &self,
        start_height: Option<u32>,
        end_height: Option<u32>,
    ) -> Result<(), String> {
        let tip = self.zebra.get_tip_height()?;

        // If no start specified, resume from backfill checkpoint
        let start = match start_height {
            Some(h) => h,
            None => {
                let checkpoint = self
                    .postgres
                    .get_checkpoint_key("backfill_height")
                    .await
                    .map_err(|e| format!("Checkpoint error: {}", e))?
                    .unwrap_or(0);
                if checkpoint > 0 {
                    println!("📍 Resuming from checkpoint: {}", checkpoint);
                    checkpoint + 1 // Start from next block
                } else {
                    0
                }
            }
        };
        let end = end_height.unwrap_or(tip);

        println!("🚀 Starting backfill from {} to {}", start, end);
        println!("────────────────────────────────────────────────────────────");

        let overall_start = Instant::now();
        let mut current = start;
        let mut total_txs = 0u64;
        let mut total_flows = 0u64;
        let mut total_blocks = 0u64;
        let mut last_successful_height = start.checked_sub(1);
        let mut checkpointed_height = start.checked_sub(1);
        let mut failure_state_active = self.has_active_failure_state().await?;

        while current <= end {
            // Index single block
            match self.index_block(current).await {
                Ok((tx_count, flow_count)) => {
                    total_txs += tx_count as u64;
                    total_flows += flow_count as u64;
                    total_blocks += 1;
                    last_successful_height = Some(current);
                    self.record_success_heartbeat().await?;
                    if failure_state_active {
                        self.clear_failure_state().await?;
                        failure_state_active = false;
                    }
                }
                Err(e) => {
                    self.record_failure("backfill", current, &e).await?;

                    if let Some(last_success) = last_successful_height {
                        if Some(last_success) != checkpointed_height {
                            self.postgres
                                .update_checkpoint("backfill_height", &last_success.to_string())
                                .await
                                .map_err(|err| format!("Checkpoint error: {}", err))?;
                        }
                    }

                    return Err(format!("Backfill aborted at height {}: {}", current, e));
                }
            }

            if let Some(progress_height) =
                checkpoint_progress_height(current, end, last_successful_height)
            {
                let elapsed = overall_start.elapsed();
                let rate = if total_blocks > 0 {
                    total_blocks as f64 / elapsed.as_secs_f64().max(f64::EPSILON)
                } else {
                    0.0
                };
                let remaining_blocks = (end - current) as f64;
                let eta_secs = if rate > 0.0 {
                    remaining_blocks / rate
                } else {
                    0.0
                };

                println!(
                    "📦 {} / {} ({:.1}%) | {:.1} blk/s | txs:{} flows:{} | ETA: {:.0}s",
                    current,
                    end,
                    (current - start) as f64 / (end - start).max(1) as f64 * 100.0,
                    rate,
                    total_txs,
                    total_flows,
                    eta_secs
                );

                // Update backfill checkpoint to the last successfully indexed height.
                self.postgres
                    .update_checkpoint("backfill_height", &progress_height.to_string())
                    .await
                    .map_err(|e| format!("Checkpoint error: {}", e))?;
                checkpointed_height = Some(progress_height);
            }

            current += 1;
        }

        let elapsed = overall_start.elapsed();
        println!("────────────────────────────────────────────────────────────");
        println!("✅ Backfill complete!");
        println!("   Blocks: {}", total_blocks);
        println!("   Transactions: {}", total_txs);
        println!("   Flows: {}", total_flows);
        println!("   Time: {:.1}s", elapsed.as_secs_f64());
        println!(
            "   Rate: {:.1} blocks/s, {:.1} tx/s",
            total_blocks as f64 / elapsed.as_secs_f64(),
            total_txs as f64 / elapsed.as_secs_f64()
        );

        Ok(())
    }

    fn parse_encoded_block(
        &self,
        height: u32,
        expected_hash: &str,
        raw_block: &[u8],
    ) -> Result<
        (
            Vec<crate::models::Transaction>,
            crate::db::ParsedBlockHeader,
        ),
        String,
    > {
        use std::sync::Arc;
        use zakura_chain::block::Block;
        use zakura_chain::serialization::{ZcashDeserialize, ZcashSerialize};

        let block = Block::zcash_deserialize(&mut std::io::Cursor::new(raw_block))
            .map_err(|e| format!("Failed to deserialize block {height}: {e:?}"))?;
        let decoded_hash = block.hash().to_string();
        if decoded_hash != expected_hash {
            return Err(format!(
                "Block {height} hash mismatch: expected {expected_hash}, decoded {decoded_hash}"
            ));
        }
        let decoded_height = block
            .coinbase_height()
            .map(|height| height.0)
            .ok_or_else(|| format!("Block {height} has no coinbase height"))?;
        if decoded_height != height {
            return Err(format!(
                "Block height mismatch: expected {height}, decoded {decoded_height}"
            ));
        }

        let header = crate::db::ParsedBlockHeader::from_chain_header(&block.header);
        let mut transactions = Vec::with_capacity(block.transactions.len());
        for transaction in block.transactions {
            let size = transaction.zcash_serialized_size();
            let transaction =
                Arc::try_unwrap(transaction).unwrap_or_else(|shared| (*shared).clone());
            transactions.push(TransactionParser::from_chain_tx(
                transaction,
                height,
                expected_hash,
                size,
                self.config.network,
            )?);
        }

        Ok((transactions, header))
    }

    async fn resolve_live_prevouts(
        &self,
        rpc: &crate::db::ZebraRpc,
        transactions: &mut [crate::models::Transaction],
    ) -> Result<Vec<ShieldedFlow>, String> {
        let current_outputs: HashMap<(String, u32), (i64, Option<String>)> = transactions
            .iter()
            .flat_map(|tx| {
                tx.vout.iter().map(move |output| {
                    (
                        (tx.txid.clone(), output.n),
                        (output.value, output.address.clone()),
                    )
                })
            })
            .collect();
        let mut references: Vec<(String, u32)> = transactions
            .iter()
            .flat_map(|tx| {
                tx.vin
                    .iter()
                    .filter(|input| {
                        !input.is_coinbase
                            && !current_outputs.contains_key(&(input.txid.clone(), input.vout))
                    })
                    .map(|input| (input.txid.clone(), input.vout))
            })
            .collect();
        references.sort_unstable();
        references.dedup();
        let database_outputs = self
            .postgres
            .get_prev_outputs(&references)
            .await
            .map_err(|e| format!("prevout database lookup failed: {e}"))?;
        let mut raw_fallbacks: HashMap<String, crate::models::Transaction> = HashMap::new();
        let mut flows = Vec::new();

        for tx in transactions {
            if !tx.is_coinbase() && !tx.vin.is_empty() {
                let mut total_input: i64 = 0;
                for input in &mut tx.vin {
                    if input.is_coinbase {
                        continue;
                    }
                    let key = (input.txid.clone(), input.vout);
                    let resolved = cached_prev_output(&key, &current_outputs, &database_outputs);
                    let (value, address) = match resolved {
                        Some(output) => output,
                        None => {
                            if !raw_fallbacks.contains_key(&input.txid) {
                                let raw_hex = rpc
                                    .get_raw_transaction_hex(&input.txid)
                                    .await
                                    .map_err(|e| {
                                        format!(
                                            "unresolved prevout transaction {}: {}",
                                            input.txid, e
                                        )
                                    })?;
                                let raw = hex::decode(&raw_hex)
                                    .map_err(|e| format!("invalid prevout transaction hex: {e}"))?;
                                let parsed =
                                    TransactionParser::parse(&raw, 0, "", self.config.network)
                                        .map_err(|e| {
                                            format!("failed to parse prevout transaction: {e}")
                                        })?;
                                raw_fallbacks.insert(input.txid.clone(), parsed);
                            }
                            let previous = raw_fallbacks.get(&input.txid).ok_or_else(|| {
                                format!("missing cached prevout transaction {}", input.txid)
                            })?;
                            let output =
                                previous.vout.get(input.vout as usize).ok_or_else(|| {
                                    format!("missing prevout {}:{}", input.txid, input.vout)
                                })?;
                            (output.value, output.address.clone())
                        }
                    };
                    input.value = Some(value);
                    input.address = address;
                    total_input = total_input
                        .checked_add(value)
                        .ok_or_else(|| format!("transparent input overflow for {}", tx.txid))?;
                }
                tx.transparent_value_in = total_input;
            }

            if !tx.is_coinbase() {
                let fee = tx
                    .transparent_value_in
                    .checked_sub(tx.transparent_value_out)
                    .and_then(|value| value.checked_add(tx.sapling_value_balance))
                    .and_then(|value| value.checked_add(tx.orchard_value_balance))
                    .and_then(|value| value.checked_add(tx.ironwood_value_balance))
                    .ok_or_else(|| format!("fee overflow for {}", tx.txid))?;
                if fee >= 0 {
                    tx.fee = Some(fee);
                }
            }

            flows.extend(ShieldedFlow::from_transaction(tx));
        }

        Ok(flows)
    }

    async fn index_block_from_bytes(
        &self,
        rpc: &crate::db::ZebraRpc,
        height: u32,
        block_hash: &str,
        raw_block: &[u8],
    ) -> Result<(u32, u32), String> {
        let (mut transactions, mut header) =
            self.parse_encoded_block(height, block_hash, raw_block)?;
        let flows = self.resolve_live_prevouts(rpc, &mut transactions).await?;

        // Raw headers do not expose Zebra's interpreted final pool roots.
        // Preserve the existing API contract with one metadata RPC call while
        // eliminating the old per-transaction RPC fan-out.
        let block_info = rpc.get_block(block_hash).await?;
        if block_info.hash != block_hash {
            return Err(format!(
                "RPC metadata hash mismatch at {height}: expected {block_hash}, got {}",
                block_info.hash
            ));
        }
        header.final_sapling_root = block_info.finalsaplingroot.unwrap_or_default();
        header.final_orchard_root = block_info.finalorchardroot;
        header.final_ironwood_root = block_info.finalironwoodroot;
        header.difficulty = block_info.difficulty;

        let (_, flow_count) = self
            .postgres
            .batch_insert_with_header_and_flows(
                height,
                block_hash,
                header.time,
                &transactions,
                &flows,
                &header,
            )
            .await
            .map_err(|e| format!("DB insert error: {e}"))?;

        if let Err(error) = self.block_spool.store(height, block_hash, raw_block).await {
            tracing::warn!(
                height,
                %error,
                spool = ?self.block_spool.directory(),
                "canonical block committed but recent-block spool write failed"
            );
        }

        Ok((transactions.len() as u32, flow_count as u32))
    }

    /// RPC fallback for live mode: one raw-block request and one metadata
    /// request, rather than one request per transaction.
    async fn index_block_from_rpc(
        &self,
        rpc: &crate::db::ZebraRpc,
        height: u32,
        block_hash: &str,
    ) -> Result<(u32, u32), String> {
        let raw_hex = rpc.get_raw_block_hex(block_hash).await?;
        let raw_block =
            hex::decode(raw_hex).map_err(|e| format!("Invalid raw block hex at {height}: {e}"))?;
        self.index_block_from_bytes(rpc, height, block_hash, &raw_block)
            .await
    }

    /// Capture authoritative Zebra pool sizes at a 256-block boundary height.
    async fn capture_boundary_snapshot(
        &self,
        rpc: &crate::db::ZebraRpc,
        height: u32,
    ) -> Result<(), String> {
        let info = rpc.get_blockchain_info().await?;
        let value_pools = info
            .get("valuePools")
            .and_then(|v| v.as_array())
            .ok_or("Missing valuePools in getblockchaininfo")?;

        let mut orchard: i64 = 0;
        let mut ironwood: i64 = 0;
        let mut sapling: i64 = 0;
        let mut sprout: i64 = 0;
        let mut transparent: Option<i64> = None;

        for pool in value_pools {
            let id = pool.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let zat = pool
                .get("chainValueZat")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            match id {
                "orchard" => orchard = zat,
                "ironwood" => ironwood = zat,
                "sapling" => sapling = zat,
                "sprout" => sprout = zat,
                "transparent" => transparent = Some(zat),
                _ => {}
            }
        }

        let chain_supply = info
            .get("chainSupply")
            .and_then(|v| v.get("chainValueZat"))
            .and_then(|v| v.as_i64());

        // Get block time for this boundary height
        let block_info = rpc.get_block_by_height(height as u64).await?;

        self.postgres
            .insert_boundary_pool_snapshot(
                height,
                block_info.time as i64,
                orchard,
                ironwood,
                sapling,
                sprout,
                transparent,
                chain_supply,
            )
            .await
            .map_err(|e| format!("DB error: {}", e))?;

        println!(
            "   📊 Boundary snapshot at {} | O:{} I:{} S:{} Sp:{}",
            height,
            orchard / 100_000_000,
            ironwood / 100_000_000,
            sapling / 100_000_000,
            sprout / 100_000_000,
        );
        Ok(())
    }

    async fn produce_live_blocks(
        rpc: crate::db::ZebraRpc,
        payload_cache: Option<crate::db::BlockPayloadCache>,
        start_height: u32,
        end_height: u32,
        payload_wait: Duration,
        sender: tokio::sync::mpsc::Sender<Result<LiveSourceBlock, String>>,
    ) {
        for height in start_height..=end_height {
            let source_started = Instant::now();
            let result = async {
                let hash = rpc.get_block_hash(height as u64).await?;
                let encoded = if let Some(cache) = payload_cache.as_ref() {
                    if height == end_height {
                        cache.take_wait(&hash, payload_wait).await
                    } else {
                        cache.take(&hash).await
                    }
                } else {
                    None
                };

                if let Some(encoded) = encoded {
                    return Ok(LiveSourceBlock {
                        height,
                        hash,
                        data: encoded.data,
                        source: "grpc",
                        source_elapsed_ms: source_started.elapsed().as_millis() as u64,
                    });
                }

                let raw_hex = rpc.get_raw_block_hex(&hash).await?;
                let bytes = hex::decode(raw_hex)
                    .map_err(|e| format!("Invalid raw block hex at {height}: {e}"))?;
                if bytes.len() as u64 > zakura_chain::block::MAX_BLOCK_BYTES {
                    return Err(format!(
                        "Raw block {height} exceeds protocol limit: {} bytes",
                        bytes.len()
                    ));
                }
                Ok(LiveSourceBlock {
                    height,
                    hash,
                    data: Arc::from(bytes),
                    source: "rpc",
                    source_elapsed_ms: source_started.elapsed().as_millis() as u64,
                })
            }
            .await;

            let failed = result.is_err();
            if sender.send(result).await.is_err() || failed {
                return;
            }
        }
    }

    /// Run live mode (follow chain tip)
    /// Uses gRPC streaming for instant block notifications when available,
    /// falls back to bounded JSON-RPC polling otherwise.
    pub async fn live(&self) -> Result<(), String> {
        use crate::db::grpc::proto::BlockHashAndHeight;
        use crate::db::{
            connect_chain_tip_stream, supervise_block_stream, BlockPayloadCache, ZebraRpc,
        };
        use tonic::Streaming;

        println!("🔴 Starting live indexer...");
        println!("   Press Ctrl+C to stop");
        println!("────────────────────────────────────────────────────────────");

        let rpc = ZebraRpc::from_env()?;
        println!("   ✅ JSON-RPC client initialized");
        tokio::spawn(crate::db::observations::observe_local_tip(
            rpc.clone(),
            self.postgres.pool().clone(),
        ));

        if let (Some(path), Some(url)) = (
            self.config.orphan_capture_path.clone(),
            self.config.zebra_grpc_url.clone(),
        ) {
            let network = self.config.network_name().to_owned();
            tokio::spawn(async move {
                if let Err(error) =
                    crate::db::orphan_capture::run_capture(&url, &path, &network, None, None).await
                {
                    tracing::error!(%error, "candidate capture stopped; canonical indexing continues");
                }
            });
        }

        let grpc_url = self.config.zebra_grpc_url.clone();
        let mut grpc_stream: Option<Streaming<BlockHashAndHeight>> = None;
        let mut failure_state_active = self.has_active_failure_state().await?;
        let payload_cache = if grpc_url.is_some() && self.config.enable_full_block_grpc {
            Some(BlockPayloadCache::new(
                self.config.grpc_payload_cache_blocks,
                self.config.grpc_payload_cache_bytes,
            )?)
        } else {
            None
        };

        if let Some(ref url) = grpc_url {
            println!("🔗 Connecting to Zakura gRPC at {}...", url);
            match connect_chain_tip_stream(url).await {
                Ok(stream) => {
                    grpc_stream = Some(stream);
                    println!("   ✅ gRPC connected — instant block notifications enabled");
                }
                Err(e) => {
                    println!(
                        "   ⚠️ gRPC unavailable ({}), using configured fallback polling",
                        e
                    );
                }
            }
            if let Some(cache) = payload_cache.clone() {
                tokio::spawn(supervise_block_stream(url.clone(), cache));
                println!("   ✅ Full-block gRPC supervisor started");
            } else {
                println!("   ℹ️ Full-block gRPC disabled pending successful shadow verification");
            }
        } else {
            println!("   ℹ️ ZEBRA_GRPC_URL not set — using configured fallback polling");
        }

        loop {
            // Wait for trigger: gRPC tip notification OR configured polling timeout
            if let Some(ref mut stream) = grpc_stream {
                tokio::select! {
                    msg = stream.message() => {
                        match msg {
                            Ok(Some(tip)) => {
                                let hash = hex::encode(&tip.hash);
                                println!("📦 [gRPC] New block: {} ({}...)", tip.height, &hash[..16.min(hash.len())]);
                            }
                            Ok(None) => {
                                println!("⚠️ [gRPC] Stream ended, falling back to polling");
                                grpc_stream = None;
                            }
                            Err(e) => {
                                println!("⚠️ [gRPC] Stream error: {}, falling back to polling", e);
                                grpc_stream = None;
                            }
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_secs(self.config.live_poll_interval_secs)) => {
                        // Periodic poll even with gRPC, as a safety net
                    }
                }
            } else {
                tokio::time::sleep(Duration::from_secs(self.config.live_poll_interval_secs)).await;

                // Periodically try to reconnect gRPC
                if let Some(ref url) = grpc_url {
                    if let Ok(stream) = connect_chain_tip_stream(url).await {
                        println!("   ✅ [gRPC] Reconnected");
                        grpc_stream = Some(stream);
                    }
                }
            }

            // Get authoritative tip from JSON-RPC
            let rpc_tip = match rpc.get_block_count().await {
                Ok(tip) => tip as u32,
                Err(e) => {
                    println!("   ⚠️ RPC error: {}", e);
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    continue;
                }
            };

            self.record_tip_heartbeat(rpc_tip).await?;

            let mut last_indexed = self
                .postgres
                .get_checkpoint()
                .await
                .map_err(|e| format!("Checkpoint error: {}", e))?
                .unwrap_or(0);

            // Check for reorgs before indexing new blocks
            let mut reorg_fork_height: Option<u32> = None;
            if last_indexed > 0 {
                match self
                    .detect_and_handle_reorg(&rpc, last_indexed, rpc_tip)
                    .await
                {
                    Ok(Some(new_checkpoint)) => {
                        reorg_fork_height = Some(new_checkpoint + 1);
                        println!(
                            "   🔄 Reorg handled, resuming from height {}",
                            new_checkpoint + 1
                        );
                        last_indexed = new_checkpoint;
                    }
                    Ok(None) => {} // no reorg
                    Err(e) => {
                        println!("   ⚠️ Reorg detection error: {}", e);
                        tokio::time::sleep(Duration::from_secs(
                            self.config.live_poll_interval_secs,
                        ))
                        .await;
                        continue;
                    }
                }
            }

            if rpc_tip > last_indexed {
                let blocks_behind = rpc_tip - last_indexed;
                println!(
                    "📥 New blocks: {} → {} ({} behind)",
                    last_indexed + 1,
                    rpc_tip,
                    blocks_behind
                );

                let mut last_success = last_indexed;
                let (source_sender, mut source_receiver) =
                    tokio::sync::mpsc::channel(self.config.live_pipeline_capacity);
                tokio::spawn(Self::produce_live_blocks(
                    rpc.clone(),
                    payload_cache.clone(),
                    last_indexed + 1,
                    rpc_tip,
                    Duration::from_millis(self.config.grpc_payload_wait_ms),
                    source_sender,
                ));

                while let Some(source_result) = source_receiver.recv().await {
                    let source_block = match source_result {
                        Ok(block) => block,
                        Err(error) => {
                            let height = last_success.saturating_add(1);
                            self.record_failure("live_source", height, &error).await?;
                            failure_state_active = true;
                            println!("   ❌ Block {} source error: {}", height, error);
                            break;
                        }
                    };
                    let height = source_block.height;
                    let ingest_started = Instant::now();
                    let mut source = source_block.source;
                    let mut result = self
                        .index_block_from_bytes(
                            &rpc,
                            height,
                            &source_block.hash,
                            source_block.data.as_ref(),
                        )
                        .await;
                    if result.is_err() && source == "grpc" {
                        let grpc_error =
                            result.as_ref().expect_err("checked gRPC indexing failure");
                        println!(
                            "   ⚠️ Block {} gRPC payload failed ({}); using RPC fallback",
                            height, grpc_error
                        );
                        source = "rpc_fallback";
                        result = self
                            .index_block_from_rpc(&rpc, height, &source_block.hash)
                            .await;
                    };

                    match result {
                        Ok((tx_count, flow_count)) => {
                            let processing_ms = ingest_started.elapsed().as_millis() as u64;
                            let elapsed_ms =
                                source_block.source_elapsed_ms.saturating_add(processing_ms);
                            println!(
                                "   ✅ Block {} | {} txs, {} flows [{}] | {}ms source + {}ms process",
                                height,
                                tx_count,
                                flow_count,
                                source,
                                source_block.source_elapsed_ms,
                                processing_ms
                            );
                            last_success = height;
                            self.postgres
                                .update_live_progress(
                                    height,
                                    rpc_tip,
                                    source,
                                    elapsed_ms,
                                    source_block.source_elapsed_ms,
                                    processing_ms,
                                    tx_count,
                                    flow_count,
                                    rpc_tip.saturating_sub(height),
                                    source_receiver.len(),
                                )
                                .await
                                .map_err(|e| format!("Live progress write error: {e}"))?;
                            if failure_state_active {
                                self.clear_failure_state().await?;
                                failure_state_active = false;
                            }
                            // Capture authoritative pool snapshot at 256-block boundaries
                            if height % 256 == 0 {
                                if let Err(e) = self.capture_boundary_snapshot(&rpc, height).await {
                                    println!("   ⚠️ Boundary snapshot error at {}: {}", height, e);
                                }
                            }
                        }
                        Err(e) => {
                            self.record_failure("live", height, &e).await?;
                            failure_state_active = true;
                            println!("   ❌ Block {} error: {}", height, e);
                            break;
                        }
                    }
                }

                if last_success > last_indexed {
                    println!("   ✅ Synced to block {}", last_success);

                    // After re-indexing post-reorg, backfill canonical hashes and clean false orphans
                    if let Some(fork_h) = reorg_fork_height {
                        if let Err(e) = self
                            .postgres
                            .finalize_orphans_after_reindex(fork_h, last_success)
                            .await
                        {
                            println!("   ⚠️ Orphan finalization error: {}", e);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{cached_prev_output, checkpoint_progress_height};
    use std::collections::HashMap;

    #[test]
    fn checkpoint_progress_uses_last_success_only() {
        assert_eq!(checkpoint_progress_height(100, 200, Some(99)), Some(99));
        assert_eq!(checkpoint_progress_height(200, 200, Some(198)), Some(198));
    }

    #[test]
    fn checkpoint_progress_skips_non_boundary_heights() {
        assert_eq!(checkpoint_progress_height(42, 200, Some(42)), None);
    }

    #[test]
    fn current_block_prevout_wins_before_database() {
        let key = ("same-block".to_string(), 0);
        let current = HashMap::from([(key.clone(), (42, None))]);
        let database = HashMap::from([(key.clone(), (7, Some("stale".to_string())))]);
        assert_eq!(
            cached_prev_output(&key, &current, &database),
            Some((42, None))
        );
    }
}
