//! PostgreSQL writer for indexed data
//!
//! Writes processed blockchain data to PostgreSQL for querying.
//! Uses UPSERT (INSERT ON CONFLICT) to allow parallel backfill and live indexing.

use crate::models::{ShieldedFlow, Transaction};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, QueryBuilder};
use std::collections::HashMap;
use std::time::Instant;

// ZIP-214 FPF/ZCG recipients are funding streams, not miner identities.
// Exclude both networks; shielded miner recipients remain unknown.
pub(crate) fn miner_address_candidate(address: Option<&str>) -> Option<String> {
    address
        .filter(|address| {
            !matches!(
                *address,
                "t3cFfPt1Bcvgez9ZbMBFWeZsskxTkPzGCow" | "t2HifwjUj9uyxr9bknR8LFuQbc98c3vkXtu"
            )
        })
        .map(str::to_owned)
}

#[derive(Debug, Clone, Default)]
pub struct BlockWriteMetrics {
    pub metadata_us: u64,
    pub transaction_data_us: u64,
    pub pubkey_exposures_us: u64,
    pub spent_marking_us: u64,
    pub flows_us: u64,
    pub address_summaries_us: u64,
    pub commit_us: u64,
    pub total_us: u64,
    pub replay: bool,
}

#[derive(Debug, Clone)]
pub struct BlockWriteResult {
    pub transaction_count: u64,
    pub flow_count: u64,
    pub metrics: BlockWriteMetrics,
}

/// PostgreSQL connection and writer
pub struct PostgresWriter {
    pool: PgPool,
}

impl PostgresWriter {
    const BLOCK_WRITE_LOCK: i64 = 0x4349_5048_4552;
    // Namespace for per-address advisory locks taken in update_addresses_for_block.
    // Serializes concurrent writers (e.g. parallel backfill workers at different
    // heights) that touch the same address, without affecting writers touching
    // disjoint addresses. See update_addresses_for_block for the full rationale.
    const ADDRESS_LOCK_NAMESPACE: i32 = 0x4144_4452; // 'ADDR'
    /// Connect to PostgreSQL
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;

        tracing::info!("Connected to PostgreSQL");

        Ok(Self { pool })
    }

    /// Access the underlying connection pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn get_prev_outputs(
        &self,
        references: &[(String, u32)],
    ) -> Result<HashMap<(String, u32), (i64, Option<String>)>, sqlx::Error> {
        if references.is_empty() {
            return Ok(HashMap::new());
        }
        let txids: Vec<&str> = references.iter().map(|(txid, _)| txid.as_str()).collect();
        let vouts: Vec<i32> = references.iter().map(|(_, vout)| *vout as i32).collect();
        let rows: Vec<(String, i32, Option<i64>, Option<String>)> = sqlx::query_as(
            r#"SELECT requested.txid,requested.vout,output.value,output.address
               FROM UNNEST($1::text[],$2::int[]) requested(txid,vout)
               JOIN transaction_outputs output
                 ON output.txid=requested.txid AND output.vout_index=requested.vout"#,
        )
        .bind(&txids)
        .bind(&vouts)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(txid, vout, value, address)| {
                let value = value.ok_or_else(|| {
                    sqlx::Error::Protocol(format!("null prevout value for {txid}:{vout}"))
                })?;
                Ok(((txid, vout as u32), (value, address)))
            })
            .collect()
    }

    /// Update indexer state (checkpoint)
    pub async fn update_checkpoint(&self, key: &str, value: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO indexer_state (key, value, updated_at)
            VALUES ($1, $2, NOW())
            ON CONFLICT (key) DO UPDATE SET
                value = EXCLUDED.value,
                updated_at = NOW()
            "#,
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get indexer state value
    pub async fn get_state(&self, key: &str) -> Result<Option<String>, sqlx::Error> {
        let result: Option<(String,)> =
            sqlx::query_as("SELECT value FROM indexer_state WHERE key = $1")
                .bind(key)
                .fetch_optional(&self.pool)
                .await?;

        Ok(result.map(|(v,)| v))
    }

    /// Delete an indexer state value when it no longer applies.
    pub async fn delete_state(&self, key: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM indexer_state WHERE key = $1")
            .bind(key)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Get checkpoint (convenience method)
    pub async fn get_checkpoint(&self) -> Result<Option<u32>, sqlx::Error> {
        match self.get_state("last_indexed_height").await? {
            Some(v) => Ok(v.parse().ok()),
            None => Ok(None),
        }
    }

    /// Persist the committed live height, heartbeat, and privacy-safe ingest
    /// metrics in one round trip.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_live_progress(
        &self,
        height: u32,
        rpc_tip: u32,
        source: &str,
        elapsed_ms: u64,
        source_ms: u64,
        processing_ms: u64,
        transaction_count: u32,
        flow_count: u32,
        backlog_blocks: u32,
        queue_depth: usize,
    ) -> Result<(), sqlx::Error> {
        let now = crate::util::unix_timestamp_secs().to_string();
        let metrics = serde_json::json!({
            "height": height,
            "rpc_tip": rpc_tip,
            "source": source,
            "elapsed_ms": elapsed_ms,
            "source_ms": source_ms,
            "processing_ms": processing_ms,
            "transaction_count": transaction_count,
            "flow_count": flow_count,
            "backlog_blocks": backlog_blocks,
            "queue_depth": queue_depth,
        })
        .to_string();
        let keys = [
            "last_indexed_height",
            "last_success_at",
            "last_live_metrics",
        ];
        let values = [height.to_string(), now, metrics];

        sqlx::query(
            r#"
            INSERT INTO indexer_state (key, value, updated_at)
            SELECT key, value, NOW()
            FROM UNNEST($1::text[], $2::text[]) AS progress(key, value)
            ON CONFLICT (key) DO UPDATE SET
                value = EXCLUDED.value,
                updated_at = NOW()
            "#,
        )
        .bind(keys)
        .bind(values)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Get checkpoint by specific key
    pub async fn get_checkpoint_key(&self, key: &str) -> Result<Option<u32>, sqlx::Error> {
        match self.get_state(key).await? {
            Some(v) => Ok(v.parse().ok()),
            None => Ok(None),
        }
    }

    /// Batch insert with full block header info and optional flows in one DB transaction.
    pub async fn batch_insert_with_header_and_flows(
        &self,
        height: u32,
        hash: &str,
        timestamp: u64,
        transactions: &[Transaction],
        flows: &[ShieldedFlow],
        header: &crate::db::ParsedBlockHeader,
    ) -> Result<(u64, u64), sqlx::Error> {
        let result = self
            .batch_insert_with_header_and_flows_measured(
                height,
                hash,
                timestamp,
                transactions,
                flows,
                header,
            )
            .await?;
        Ok((result.transaction_count, result.flow_count))
    }

    pub async fn batch_insert_with_header_and_flows_measured(
        &self,
        height: u32,
        hash: &str,
        timestamp: u64,
        transactions: &[Transaction],
        flows: &[ShieldedFlow],
        header: &crate::db::ParsedBlockHeader,
    ) -> Result<BlockWriteResult, sqlx::Error> {
        let total_start = Instant::now();
        let mut metrics = BlockWriteMetrics::default();
        for tx in transactions {
            if !tx.is_coinbase() && tx.vin.iter().any(|input| input.value.is_none()) {
                return Err(sqlx::Error::Protocol(format!(
                    "transaction {} contains an unresolved transparent input",
                    tx.txid
                )));
            }
            tx.sapling_value_balance
                .checked_add(tx.orchard_value_balance)
                .and_then(|value| value.checked_add(tx.ironwood_value_balance))
                .ok_or_else(|| {
                    sqlx::Error::Protocol(format!(
                        "shielded value balance overflow for {}",
                        tx.txid
                    ))
                })?;
        }
        let mut db_tx = self.pool.begin().await?;
        // Block writers cooperate through a shared lock; integrity cutover and
        // reorg rollback take the exclusive form without serializing backfills.
        sqlx::query("SELECT pg_advisory_xact_lock_shared($1)")
            .bind(Self::BLOCK_WRITE_LOCK)
            .execute(&mut *db_tx)
            .await?;
        // Serialize only duplicate writers for the same height. Distinct
        // backfill heights remain parallel, while replay detection is atomic.
        sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
            .bind(0x424c_4f43_i32)
            .bind(height as i32)
            .execute(&mut *db_tx)
            .await?;
        let is_replay: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM blocks WHERE height=$1)")
                .bind(height as i64)
                .fetch_one(&mut *db_tx)
                .await?;
        let mut count = 0u64;

        // Calculate block-level aggregates
        let total_fees = transactions
            .iter()
            .filter_map(|tx| tx.fee)
            .try_fold(0i64, |total, fee| total.checked_add(fee))
            .ok_or_else(|| sqlx::Error::Protocol("block fee total overflow".to_string()))?;

        // Block size = sum of all tx sizes + header size (~1487 bytes for Zcash)
        // Header: 4 (version) + 32 (prev_hash) + 32 (merkle) + 32 (reserved) + 4 (time)
        //       + 4 (bits) + 32 (nonce) + 3 (solution length) + 1344 (solution) = ~1487
        const HEADER_SIZE: i32 = 1487;
        let tx_sizes = transactions
            .iter()
            .try_fold(0i32, |total, tx| total.checked_add(tx.size as i32))
            .ok_or_else(|| sqlx::Error::Protocol("block size overflow".to_string()))?;
        let block_size = tx_sizes
            .checked_add(HEADER_SIZE)
            .ok_or_else(|| sqlx::Error::Protocol("block size overflow".to_string()))?;

        // Miner address = first transparent coinbase output, except the known
        // ZIP-214 FPF/ZCG funding-stream recipients. A shielded miner payout
        // cannot be attributed without separate recipient extraction, so keep
        // miner_address NULL rather than misattributing the funding stream.
        let miner_address: Option<String> = transactions.first().and_then(|coinbase| {
            if coinbase.vin.first().map(|v| v.is_coinbase).unwrap_or(false) {
                coinbase
                    .vout
                    .first()
                    .and_then(|out| miner_address_candidate(out.address.as_deref()))
            } else {
                None
            }
        });

        // Coinbase hex = script_sig of the coinbase input (miner's embedded data)
        let coinbase_hex: Option<String> = transactions.first().and_then(|coinbase| {
            coinbase.vin.first().and_then(|input| {
                if input.is_coinbase {
                    input.script_sig.clone()
                } else {
                    None
                }
            })
        });

        // Insert block with all header fields
        sqlx::query(
            r#"
            INSERT INTO blocks (
                height, hash, timestamp, transaction_count, total_fees,
                version, merkle_root, final_sapling_root, final_orchard_root,
                bits, nonce, solution,
                difficulty, previous_block_hash, size, miner_address, coinbase_hex,
                final_ironwood_root
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
            ON CONFLICT (height) DO UPDATE SET
                hash = EXCLUDED.hash,
                transaction_count = EXCLUDED.transaction_count,
                total_fees = EXCLUDED.total_fees,
                version = EXCLUDED.version,
                merkle_root = EXCLUDED.merkle_root,
                final_sapling_root = EXCLUDED.final_sapling_root,
                final_orchard_root = EXCLUDED.final_orchard_root,
                bits = EXCLUDED.bits,
                nonce = EXCLUDED.nonce,
                solution = EXCLUDED.solution,
                difficulty = EXCLUDED.difficulty,
                previous_block_hash = EXCLUDED.previous_block_hash,
                size = EXCLUDED.size,
                miner_address = EXCLUDED.miner_address,
                coinbase_hex = EXCLUDED.coinbase_hex,
                final_ironwood_root = EXCLUDED.final_ironwood_root
            "#,
        )
        .bind(height as i64)
        .bind(hash)
        .bind(timestamp as i64)
        .bind(transactions.len() as i32)
        .bind(total_fees)
        .bind(header.version)
        .bind(&header.merkle_root)
        .bind(&header.final_sapling_root)
        .bind(&header.final_orchard_root)
        .bind(&header.bits)
        .bind(&header.nonce)
        .bind(&header.solution)
        .bind(header.difficulty)
        .bind(&header.previous_block_hash)
        .bind(block_size)
        .bind(&miner_address)
        .bind(&coinbase_hex)
        .bind(&header.final_ironwood_root)
        .execute(&mut *db_tx)
        .await?;
        metrics.metadata_us = total_start.elapsed().as_micros() as u64;
        metrics.replay = is_replay;

        let transaction_data_start = Instant::now();
        let old_activity_addresses = if is_replay {
            self.reset_address_activity(&mut db_tx, transactions)
                .await?
        } else {
            Vec::new()
        };
        let use_rowwise_writes = std::env::var_os("CIPHERSCAN_ROWWISE_WRITES").is_some();
        if !use_rowwise_writes {
            // Collapse the transaction, input, output, and address-activity writes
            // into chunked multi-row UPSERTs. The previous row-wise path incurred
            // thousands of local client/server round trips for transparent blocks.
            self.bulk_insert_transaction_data(&mut db_tx, transactions, timestamp)
                .await?;
            count = transactions.len() as u64;
        }

        // Keep an emergency rollback path while the bulk implementation is being
        // introduced. Setting CIPHERSCAN_ROWWISE_WRITES restores the old behavior.
        if use_rowwise_writes {
            count = 0;
            for (tx_idx, tx) in transactions.iter().enumerate() {
                // Insert transaction
                let has_sapling = tx.sapling_spends > 0 || tx.sapling_outputs > 0;
                let has_orchard = tx.orchard_actions > 0;
                let has_ironwood = tx.ironwood_actions > 0;
                let is_coinbase = tx.vin.first().map(|v| v.is_coinbase).unwrap_or(false);

                let has_sprout = tx.joinsplit_count > 0;
                let has_shielded_data = has_sapling || has_orchard || has_ironwood || has_sprout;

                sqlx::query(
                    r#"
                INSERT INTO transactions (
                    txid, block_height, block_hash, version, locktime,
                    size, fee, total_input, total_output,
                    orchard_actions,
                    value_balance_sapling, value_balance_orchard,
                    is_coinbase, has_sapling, has_orchard,
                    vin_count, vout_count, block_time, tx_index,
                    ironwood_actions, value_balance_ironwood, has_ironwood, value_balance,
                    expiry_height, sapling_spend_count, sapling_output_count,
                    sprout_joinsplit_count, has_sprout,
                    orchard_anchor, ironwood_anchor, has_shielded_data
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9,
                    $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
                    $20, $21, $22, $23,
                    $24, $25, $26, $27, $28,
                    $29, $30, $31
                )
                ON CONFLICT (txid) DO UPDATE SET
                    block_height = EXCLUDED.block_height,
                    block_hash = EXCLUDED.block_hash,
                    fee = EXCLUDED.fee,
                    total_input = EXCLUDED.total_input,
                    total_output = EXCLUDED.total_output,
                    is_coinbase = EXCLUDED.is_coinbase,
                    tx_index = EXCLUDED.tx_index,
                    ironwood_actions = EXCLUDED.ironwood_actions,
                    value_balance_ironwood = EXCLUDED.value_balance_ironwood,
                    has_ironwood = EXCLUDED.has_ironwood,
                    value_balance = EXCLUDED.value_balance,
                    locktime = EXCLUDED.locktime,
                    expiry_height = EXCLUDED.expiry_height,
                    sapling_spend_count = EXCLUDED.sapling_spend_count,
                    sapling_output_count = EXCLUDED.sapling_output_count,
                    sprout_joinsplit_count = EXCLUDED.sprout_joinsplit_count,
                    has_sprout = EXCLUDED.has_sprout,
                    orchard_anchor = EXCLUDED.orchard_anchor,
                    ironwood_anchor = EXCLUDED.ironwood_anchor,
                    has_shielded_data = EXCLUDED.has_shielded_data
                "#,
                )
                .bind(&tx.txid) // $1
                .bind(tx.block_height as i64) // $2
                .bind(&tx.block_hash) // $3
                .bind(tx.version) // $4
                .bind(tx.lock_time as i64) // $5
                .bind(tx.size as i32) // $6
                .bind(tx.fee.unwrap_or(0)) // $7
                .bind(tx.transparent_value_in) // $8
                .bind(tx.transparent_value_out) // $9
                .bind(tx.orchard_actions as i32) // $10
                .bind(tx.sapling_value_balance) // $11
                .bind(tx.orchard_value_balance) // $12
                .bind(is_coinbase) // $13
                .bind(has_sapling) // $14
                .bind(has_orchard) // $15
                .bind(tx.vin_count as i32) // $16
                .bind(tx.vout_count as i32) // $17
                .bind(timestamp as i64) // $18
                .bind(tx_idx as i32) // $19
                .bind(tx.ironwood_actions as i32) // $20
                .bind(tx.ironwood_value_balance) // $21
                .bind(has_ironwood) // $22
                .bind(
                    tx.sapling_value_balance + tx.orchard_value_balance + tx.ironwood_value_balance,
                ) // $23
                .bind(tx.expiry_height.map(|h| h as i32)) // $24
                .bind(tx.sapling_spends as i32) // $25
                .bind(tx.sapling_outputs as i32) // $26
                .bind(tx.joinsplit_count as i32) // $27
                .bind(has_sprout) // $28
                .bind(&tx.orchard_anchor) // $29
                .bind(&tx.ironwood_anchor) // $30
                .bind(has_shielded_data) // $31
                .execute(&mut *db_tx)
                .await?;

                // Insert outputs
                for output in &tx.vout {
                    sqlx::query(
                        r#"
                    INSERT INTO transaction_outputs (txid, vout_index, value, address, script_type, script_pubkey)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    ON CONFLICT (txid, vout_index) DO UPDATE SET
                        value = EXCLUDED.value,
                        address = EXCLUDED.address,
                        script_type = EXCLUDED.script_type,
                        script_pubkey = EXCLUDED.script_pubkey
                    "#,
                    )
                    .bind(&tx.txid)
                    .bind(output.n as i32)
                    .bind(output.value)
                    .bind(&output.address)
                    .bind(&output.script_type)
                    .bind(&output.script_pub_key)
                    .execute(&mut *db_tx)
                    .await?;
                }

                // Insert inputs (skip coinbase)
                for (i, input) in tx.vin.iter().enumerate() {
                    if input.is_coinbase {
                        continue;
                    }

                    sqlx::query(
                    r#"
                    INSERT INTO transaction_inputs (txid, vout_index, prev_txid, prev_vout, address, value)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    ON CONFLICT (txid, vout_index) DO UPDATE SET
                        prev_txid = EXCLUDED.prev_txid,
                        prev_vout = EXCLUDED.prev_vout,
                        address = EXCLUDED.address,
                        value = EXCLUDED.value
                    "#
                )
                .bind(&tx.txid)
                .bind(i as i32)
                .bind(&input.txid)
                .bind(input.vout as i32)
                .bind(&input.address)
                .bind(input.value)
                .execute(&mut *db_tx)
                .await?;
                }

                // Insert into address_transactions (denormalized lookup table)
                {
                    use std::collections::HashMap;
                    let mut addr_map: HashMap<&str, (i64, i64)> = HashMap::new();

                    for output in &tx.vout {
                        if let Some(ref addr) = output.address {
                            let entry = addr_map.entry(addr.as_str()).or_insert((0, 0));
                            entry.1 = entry.1.checked_add(output.value).ok_or_else(|| {
                                sqlx::Error::Protocol(format!(
                                    "address output total overflow for {}",
                                    tx.txid
                                ))
                            })?;
                        }
                    }
                    for input in &tx.vin {
                        if input.is_coinbase {
                            continue;
                        }
                        if let Some(ref addr) = input.address {
                            let entry = addr_map.entry(addr.as_str()).or_insert((0, 0));
                            entry.0 =
                                entry
                                    .0
                                    .checked_add(input.value.unwrap_or(0))
                                    .ok_or_else(|| {
                                        sqlx::Error::Protocol(format!(
                                            "address input total overflow for {}",
                                            tx.txid
                                        ))
                                    })?;
                        }
                    }

                    for (addr, (val_in, val_out)) in &addr_map {
                        sqlx::query(
                        r#"
                        INSERT INTO address_transactions (address, txid, block_height, tx_index, block_time, is_input, is_output, value_in, value_out)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                        ON CONFLICT (address, block_height, tx_index, txid)
                        DO UPDATE SET is_input = EXCLUDED.is_input OR address_transactions.is_input,
                                      is_output = EXCLUDED.is_output OR address_transactions.is_output,
                                      value_in = EXCLUDED.value_in,
                                      value_out = EXCLUDED.value_out
                        "#
                    )
                    .bind(addr)
                    .bind(&tx.txid)
                    .bind(tx.block_height as i32)
                    .bind(tx_idx as i32)
                    .bind(timestamp as i64)
                    .bind(*val_in > 0)
                    .bind(*val_out > 0)
                    .bind(*val_in)
                    .bind(*val_out)
                    .execute(&mut *db_tx)
                    .await?;
                    }
                }

                count += 1;
            }
        }
        metrics.transaction_data_us = transaction_data_start.elapsed().as_micros() as u64;

        let pubkey_start = Instant::now();
        self.insert_pubkey_exposures(&mut db_tx, transactions)
            .await?;
        metrics.pubkey_exposures_us = pubkey_start.elapsed().as_micros() as u64;

        let spent_start = Instant::now();
        self.mark_spent_outputs(&mut db_tx, transactions).await?;
        metrics.spent_marking_us = spent_start.elapsed().as_micros() as u64;

        let flows_start = Instant::now();
        let flow_count = self.insert_flows_tx(&mut db_tx, flows, timestamp).await?;
        metrics.flows_us = flows_start.elapsed().as_micros() as u64;

        let addresses_start = Instant::now();
        if is_replay {
            // Replay or corrective reprocessing: derive exact summaries from
            // the idempotent activity ledger, including removed owners. Full
            // recompute is O(that address's total history), so this path is
            // intentionally reserved for the rare replay/backfill-overlap
            // case rather than every new block (see 2026-08-15 incident:
            // routing all new blocks through recompute made ordinary blocks
            // that touch a high-volume address take 10-20s each).
            self.update_addresses_for_block(&mut db_tx, transactions, &old_activity_addresses)
                .await?;
        } else {
            // New block: apply its delta once. This is a plain relative
            // `UPDATE ... SET balance = addresses.balance + delta`, which
            // Postgres row-locking already makes safe against other
            // concurrent deltas on the same address (the second UPDATE
            // blocks on the row lock and sees the first's committed value —
            // no lost update). The per-address advisory lock taken inside
            // apply_address_deltas_for_new_block exists only to serialize
            // against a concurrent REPLAY on the same address, whose
            // absolute-recompute write is not safe to interleave with.
            self.apply_address_deltas_for_new_block(&mut db_tx, transactions, timestamp)
                .await?;
        }
        metrics.address_summaries_us = addresses_start.elapsed().as_micros() as u64;

        let commit_start = Instant::now();
        db_tx.commit().await?;
        metrics.commit_us = commit_start.elapsed().as_micros() as u64;
        metrics.total_us = total_start.elapsed().as_micros() as u64;

        tracing::debug!(
            height,
            transactions = count,
            flows = flow_count,
            replay = metrics.replay,
            metadata_us = metrics.metadata_us,
            transaction_data_us = metrics.transaction_data_us,
            pubkey_exposures_us = metrics.pubkey_exposures_us,
            spent_marking_us = metrics.spent_marking_us,
            flows_us = metrics.flows_us,
            address_summaries_us = metrics.address_summaries_us,
            commit_us = metrics.commit_us,
            total_us = metrics.total_us,
            "committed indexed block"
        );

        Ok(BlockWriteResult {
            transaction_count: count,
            flow_count,
            metrics,
        })
    }

    async fn reset_address_activity(
        &self,
        db_tx: &mut sqlx::Transaction<'_, Postgres>,
        transactions: &[Transaction],
    ) -> Result<Vec<String>, sqlx::Error> {
        let txids: Vec<&str> = transactions.iter().map(|tx| tx.txid.as_str()).collect();
        if txids.is_empty() {
            return Ok(Vec::new());
        }
        let old_addresses = sqlx::query_scalar::<_, String>(
            "SELECT DISTINCT address FROM address_transactions WHERE txid = ANY($1)",
        )
        .bind(&txids)
        .fetch_all(&mut **db_tx)
        .await?;
        sqlx::query("DELETE FROM address_transactions WHERE txid = ANY($1)")
            .bind(&txids)
            .execute(&mut **db_tx)
            .await?;
        Ok(old_addresses)
    }

    async fn mark_spent_outputs(
        &self,
        db_tx: &mut sqlx::Transaction<'_, Postgres>,
        transactions: &[Transaction],
    ) -> Result<(), sqlx::Error> {
        let txids: Vec<&str> = transactions.iter().map(|tx| tx.txid.as_str()).collect();
        if txids.is_empty() {
            return Ok(());
        }
        sqlx::query(
            r#"
            UPDATE transaction_outputs output
            SET spent = TRUE, spent_txid = input.txid,
                spent_at = to_timestamp(spender.block_time) AT TIME ZONE 'UTC'
            FROM transaction_inputs input
            JOIN transactions spender ON spender.txid = input.txid
            WHERE input.txid = ANY($1)
              AND output.txid = input.prev_txid
              AND output.vout_index = input.prev_vout
            "#,
        )
        .bind(&txids)
        .execute(&mut **db_tx)
        .await?;
        Ok(())
    }

    async fn insert_pubkey_exposures(
        &self,
        db_tx: &mut sqlx::Transaction<'_, Postgres>,
        transactions: &[Transaction],
    ) -> Result<(), sqlx::Error> {
        let rows: Vec<_> = transactions
            .iter()
            .flat_map(|transaction| {
                transaction.vout.iter().flat_map(move |output| {
                    output.pubkey_exposures.iter().map(move |exposure| {
                        (
                            transaction.txid.as_str(),
                            output.n,
                            output.script_type.as_str(),
                            exposure,
                        )
                    })
                })
            })
            .collect();

        const EXPOSURE_CHUNK_SIZE: usize = 8_000;
        for chunk in rows.chunks(EXPOSURE_CHUNK_SIZE) {
            let mut query = QueryBuilder::<Postgres>::new(
                "INSERT INTO transparent_key_exposures \
                 (txid, vout_index, key_index, pubkey_hex, script_type, derived_address) ",
            );
            query.push_values(
                chunk,
                |mut row, (txid, output_index, script_type, exposure)| {
                    row.push_bind(*txid)
                        .push_bind(*output_index as i32)
                        .push_bind(exposure.pubkey_index as i32)
                        .push_bind(&exposure.pubkey_hex)
                        .push_bind(*script_type)
                        .push_bind(&exposure.derived_p2pkh);
                },
            );
            query.push(
                " ON CONFLICT (txid, vout_index, key_index) DO UPDATE SET \
                  pubkey_hex = EXCLUDED.pubkey_hex, \
                  script_type = EXCLUDED.script_type, \
                  derived_address = EXCLUDED.derived_address",
            );
            query.build().execute(&mut **db_tx).await?;
        }
        Ok(())
    }

    async fn bulk_insert_transaction_data(
        &self,
        db_tx: &mut sqlx::Transaction<'_, Postgres>,
        transactions: &[Transaction],
        timestamp: u64,
    ) -> Result<(), sqlx::Error> {
        const TX_CHUNK_SIZE: usize = 2_000;
        for (chunk_index, chunk) in transactions.chunks(TX_CHUNK_SIZE).enumerate() {
            let tx_index_offset = chunk_index * TX_CHUNK_SIZE;
            let mut query = QueryBuilder::<Postgres>::new(
                r#"
                INSERT INTO transactions (
                    txid, block_height, block_hash, version, locktime,
                    size, fee, total_input, total_output,
                    orchard_actions,
                    value_balance_sapling, value_balance_orchard,
                    is_coinbase, has_sapling, has_orchard,
                    vin_count, vout_count, block_time, tx_index,
                    ironwood_actions, value_balance_ironwood, has_ironwood, value_balance,
                    expiry_height, sapling_spend_count, sapling_output_count,
                    sprout_joinsplit_count, has_sprout,
                    orchard_anchor, ironwood_anchor, has_shielded_data
                ) "#,
            );
            query.push_values(chunk.iter().enumerate(), |mut row, (index, tx)| {
                let has_sapling = tx.sapling_spends > 0 || tx.sapling_outputs > 0;
                let has_orchard = tx.orchard_actions > 0;
                let has_ironwood = tx.ironwood_actions > 0;
                let has_sprout = tx.joinsplit_count > 0;
                let has_shielded_data = has_sapling || has_orchard || has_ironwood || has_sprout;
                let is_coinbase = tx.vin.first().map(|vin| vin.is_coinbase).unwrap_or(false);
                let value_balance =
                    tx.sapling_value_balance + tx.orchard_value_balance + tx.ironwood_value_balance;

                row.push_bind(&tx.txid)
                    .push_bind(tx.block_height as i64)
                    .push_bind(&tx.block_hash)
                    .push_bind(tx.version)
                    .push_bind(tx.lock_time as i64)
                    .push_bind(tx.size as i32)
                    .push_bind(tx.fee.unwrap_or(0))
                    .push_bind(tx.transparent_value_in)
                    .push_bind(tx.transparent_value_out)
                    .push_bind(tx.orchard_actions as i32)
                    .push_bind(tx.sapling_value_balance)
                    .push_bind(tx.orchard_value_balance)
                    .push_bind(is_coinbase)
                    .push_bind(has_sapling)
                    .push_bind(has_orchard)
                    .push_bind(tx.vin_count as i32)
                    .push_bind(tx.vout_count as i32)
                    .push_bind(timestamp as i64)
                    .push_bind((tx_index_offset + index) as i32)
                    .push_bind(tx.ironwood_actions as i32)
                    .push_bind(tx.ironwood_value_balance)
                    .push_bind(has_ironwood)
                    .push_bind(value_balance)
                    .push_bind(tx.expiry_height.map(|height| height as i32))
                    .push_bind(tx.sapling_spends as i32)
                    .push_bind(tx.sapling_outputs as i32)
                    .push_bind(tx.joinsplit_count as i32)
                    .push_bind(has_sprout)
                    .push_bind(&tx.orchard_anchor)
                    .push_bind(&tx.ironwood_anchor)
                    .push_bind(has_shielded_data);
            });
            query.push(
                r#"
                ON CONFLICT (txid) DO UPDATE SET
                    block_height = EXCLUDED.block_height,
                    block_hash = EXCLUDED.block_hash,
                    fee = EXCLUDED.fee,
                    total_input = EXCLUDED.total_input,
                    total_output = EXCLUDED.total_output,
                    is_coinbase = EXCLUDED.is_coinbase,
                    tx_index = EXCLUDED.tx_index,
                    ironwood_actions = EXCLUDED.ironwood_actions,
                    value_balance_ironwood = EXCLUDED.value_balance_ironwood,
                    has_ironwood = EXCLUDED.has_ironwood,
                    value_balance = EXCLUDED.value_balance,
                    locktime = EXCLUDED.locktime,
                    expiry_height = EXCLUDED.expiry_height,
                    sapling_spend_count = EXCLUDED.sapling_spend_count,
                    sapling_output_count = EXCLUDED.sapling_output_count,
                    sprout_joinsplit_count = EXCLUDED.sprout_joinsplit_count,
                    has_sprout = EXCLUDED.has_sprout,
                    orchard_anchor = EXCLUDED.orchard_anchor,
                    ironwood_anchor = EXCLUDED.ironwood_anchor,
                    has_shielded_data = EXCLUDED.has_shielded_data
                "#,
            );
            query.build().execute(&mut **db_tx).await?;
        }

        let outputs: Vec<_> = transactions
            .iter()
            .flat_map(|tx| tx.vout.iter().map(move |output| (&tx.txid, output)))
            .collect();
        const OUTPUT_CHUNK_SIZE: usize = 10_000;
        for chunk in outputs.chunks(OUTPUT_CHUNK_SIZE) {
            let mut query = QueryBuilder::<Postgres>::new(
                "INSERT INTO transaction_outputs (txid, vout_index, value, address, script_type, script_pubkey) ",
            );
            query.push_values(chunk, |mut row, (txid, output)| {
                row.push_bind(*txid)
                    .push_bind(output.n as i32)
                    .push_bind(output.value)
                    .push_bind(&output.address)
                    .push_bind(&output.script_type)
                    .push_bind(&output.script_pub_key);
            });
            query.push(
                r#"
                ON CONFLICT (txid, vout_index) DO UPDATE SET
                    value = EXCLUDED.value,
                    address = EXCLUDED.address,
                    script_type = EXCLUDED.script_type,
                    script_pubkey = EXCLUDED.script_pubkey
                "#,
            );
            query.build().execute(&mut **db_tx).await?;
        }

        let inputs: Vec<_> = transactions
            .iter()
            .flat_map(|tx| {
                tx.vin
                    .iter()
                    .enumerate()
                    .filter(|(_, input)| !input.is_coinbase)
                    .map(move |(index, input)| (&tx.txid, index, input))
            })
            .collect();
        const INPUT_CHUNK_SIZE: usize = 10_000;
        for chunk in inputs.chunks(INPUT_CHUNK_SIZE) {
            let mut query = QueryBuilder::<Postgres>::new(
                "INSERT INTO transaction_inputs (txid, vout_index, prev_txid, prev_vout, address, value) ",
            );
            query.push_values(chunk, |mut row, (txid, index, input)| {
                row.push_bind(*txid)
                    .push_bind(*index as i32)
                    .push_bind(&input.txid)
                    .push_bind(input.vout as i32)
                    .push_bind(&input.address)
                    .push_bind(input.value);
            });
            query.push(
                r#"
                ON CONFLICT (txid, vout_index) DO UPDATE SET
                    prev_txid = EXCLUDED.prev_txid,
                    prev_vout = EXCLUDED.prev_vout,
                    address = EXCLUDED.address,
                    value = EXCLUDED.value
                "#,
            );
            query.build().execute(&mut **db_tx).await?;
        }

        struct AddressTransactionRow<'a> {
            address: &'a str,
            txid: &'a str,
            block_height: i32,
            tx_index: i32,
            value_in: i64,
            value_out: i64,
        }

        let mut address_transactions = Vec::new();
        for (tx_index, tx) in transactions.iter().enumerate() {
            use std::collections::HashMap;
            let mut addresses: HashMap<&str, (i64, i64)> = HashMap::new();

            for output in &tx.vout {
                if let Some(address) = output.address.as_deref() {
                    let e = addresses.entry(address).or_insert((0, 0));
                    e.1 = e.1.checked_add(output.value).ok_or_else(|| {
                        sqlx::Error::Protocol(format!(
                            "address output total overflow for {}",
                            tx.txid
                        ))
                    })?;
                }
            }
            for input in &tx.vin {
                if !input.is_coinbase {
                    if let Some(address) = input.address.as_deref() {
                        let e = addresses.entry(address).or_insert((0, 0));
                        e.0 = e.0.checked_add(input.value.unwrap_or(0)).ok_or_else(|| {
                            sqlx::Error::Protocol(format!(
                                "address input total overflow for {}",
                                tx.txid
                            ))
                        })?;
                    }
                }
            }

            address_transactions.extend(addresses.into_iter().map(
                |(address, (value_in, value_out))| AddressTransactionRow {
                    address,
                    txid: &tx.txid,
                    block_height: tx.block_height as i32,
                    tx_index: tx_index as i32,
                    value_in,
                    value_out,
                },
            ));
        }

        const ADDRESS_TX_CHUNK_SIZE: usize = 7_000;
        for chunk in address_transactions.chunks(ADDRESS_TX_CHUNK_SIZE) {
            let mut query = QueryBuilder::<Postgres>::new(
                r#"
                INSERT INTO address_transactions (
                    address, txid, block_height, tx_index, block_time,
                    is_input, is_output, value_in, value_out
                ) "#,
            );
            query.push_values(chunk, |mut row, item| {
                row.push_bind(item.address)
                    .push_bind(item.txid)
                    .push_bind(item.block_height)
                    .push_bind(item.tx_index)
                    .push_bind(timestamp as i64)
                    .push_bind(item.value_in > 0)
                    .push_bind(item.value_out > 0)
                    .push_bind(item.value_in)
                    .push_bind(item.value_out);
            });
            query.push(
                r#"
                ON CONFLICT (address, block_height, tx_index, txid)
                DO UPDATE SET
                    is_input = EXCLUDED.is_input OR address_transactions.is_input,
                    is_output = EXCLUDED.is_output OR address_transactions.is_output,
                    value_in = EXCLUDED.value_in,
                    value_out = EXCLUDED.value_out
                "#,
            );
            query.build().execute(&mut **db_tx).await?;
        }

        Ok(())
    }

    /// Applies each touched address's net delta for a genuinely new block via
    /// a single relative `UPDATE ... SET balance = addresses.balance +
    /// EXCLUDED.balance`. This is O(1) per address regardless of that
    /// address's total history (unlike update_addresses_for_block's full
    /// recompute), which matters for high-volume addresses (exchange hot
    /// wallets) that appear in many blocks. The relative UPDATE is already
    /// safe against another concurrent delta on the same address — Postgres
    /// serializes it via the row lock, so the second UPDATE always sees the
    /// first's committed value — but is NOT safe to interleave with a
    /// concurrent REPLAY's absolute overwrite on the same address, hence the
    /// per-address advisory lock before writing.
    async fn apply_address_deltas_for_new_block(
        &self,
        db_tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        transactions: &[Transaction],
        block_time: u64,
    ) -> Result<(), sqlx::Error> {
        struct Delta {
            received: i64,
            sent: i64,
            txids: std::collections::HashSet<String>,
        }

        let mut deltas: HashMap<String, Delta> = HashMap::new();
        for tx in transactions {
            for output in &tx.vout {
                if let Some(address) = &output.address {
                    let delta = deltas.entry(address.clone()).or_insert_with(|| Delta {
                        received: 0,
                        sent: 0,
                        txids: std::collections::HashSet::new(),
                    });
                    delta.received = delta.received.checked_add(output.value).ok_or_else(|| {
                        sqlx::Error::Protocol(format!(
                            "address receive delta overflow for {}",
                            tx.txid
                        ))
                    })?;
                    delta.txids.insert(tx.txid.clone());
                }
            }
            for input in &tx.vin {
                if input.is_coinbase {
                    continue;
                }
                if let (Some(address), Some(value)) = (&input.address, input.value) {
                    let delta = deltas.entry(address.clone()).or_insert_with(|| Delta {
                        received: 0,
                        sent: 0,
                        txids: std::collections::HashSet::new(),
                    });
                    delta.sent = delta.sent.checked_add(value).ok_or_else(|| {
                        sqlx::Error::Protocol(format!(
                            "address send delta overflow for {}",
                            tx.txid
                        ))
                    })?;
                    delta.txids.insert(tx.txid.clone());
                }
            }
        }

        let mut rows: Vec<_> = deltas.iter().collect();
        rows.sort_unstable_by_key(|(left, _)| *left);
        if rows.is_empty() {
            return Ok(());
        }

        let lock_addresses: Vec<&str> = rows.iter().map(|(addr, _)| addr.as_str()).collect();
        self.lock_addresses_for_write(db_tx, &lock_addresses)
            .await?;

        const CHUNK_SIZE: usize = 8_000;
        for chunk in rows.chunks(CHUNK_SIZE) {
            let mut query = QueryBuilder::<Postgres>::new(
                "INSERT INTO addresses \
                 (address,balance,total_received,total_sent,tx_count,first_seen,last_seen,address_type) ",
            );
            query.push_values(chunk, |mut row, (address, delta)| {
                row.push_bind(*address)
                    .push_bind(delta.received - delta.sent)
                    .push_bind(delta.received)
                    .push_bind(delta.sent)
                    .push_bind(delta.txids.len() as i32)
                    .push_bind(block_time as i64)
                    .push_bind(block_time as i64)
                    .push_bind("transparent");
            });
            query.push(
                " ON CONFLICT(address) DO UPDATE SET \
                 balance=addresses.balance+EXCLUDED.balance, \
                 total_received=addresses.total_received+EXCLUDED.total_received, \
                 total_sent=addresses.total_sent+EXCLUDED.total_sent, \
                 tx_count=addresses.tx_count+EXCLUDED.tx_count, \
                 first_seen=LEAST(addresses.first_seen,EXCLUDED.first_seen), \
                 last_seen=GREATEST(addresses.last_seen,EXCLUDED.last_seen), \
                 updated_at=NOW()",
            );
            query.build().execute(&mut **db_tx).await?;
        }
        Ok(())
    }

    /// Acquires a per-address, xact-scoped advisory lock for every address in
    /// `addresses` (which must already be sorted and deduped), in that same
    /// sorted order. Concurrent transactions with overlapping address sets
    /// therefore always acquire in the same relative order (no deadlock),
    /// and whichever transaction acquires a given address's lock second is
    /// guaranteed to see the first transaction's fully committed writes to
    /// that address (the lock is xact-scoped, so it cannot be acquired until
    /// the holder commits or rolls back). Disjoint address sets stay fully
    /// parallel — this is not a substitute for the plain relative `UPDATE
    /// balance = balance + delta` pattern's own safety on the fast path;
    /// it exists to prevent a concurrent REPLAY (absolute recompute) from
    /// interleaving unsafely with either a delta apply or another replay on
    /// the same address. See apply_address_deltas_for_new_block and
    /// update_addresses_for_block for how each side uses it.
    async fn lock_addresses_for_write(
        &self,
        db_tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        addresses: &[&str],
    ) -> Result<(), sqlx::Error> {
        if addresses.is_empty() {
            return Ok(());
        }
        sqlx::query(
            "SELECT pg_advisory_xact_lock($1, hashtext(addr)) \
             FROM unnest($2::text[]) AS addr ORDER BY addr",
        )
        .bind(Self::ADDRESS_LOCK_NAMESPACE)
        .bind(addresses)
        .execute(&mut **db_tx)
        .await?;
        Ok(())
    }

    /// Recompute exact address summaries for replayed or corrected
    /// transactions. Full recompute from the address_transactions ledger is
    /// O(that address's total history) — reserved for replay/backfill, NOT
    /// used for ordinary new blocks (see apply_address_deltas_for_new_block).
    async fn update_addresses_for_block(
        &self,
        db_tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        transactions: &[Transaction],
        old_activity_addresses: &[String],
    ) -> Result<(), sqlx::Error> {
        let mut addresses: Vec<&str> = old_activity_addresses
            .iter()
            .map(String::as_str)
            .chain(transactions.iter().flat_map(|tx| {
                tx.vout
                    .iter()
                    .filter_map(|output| output.address.as_deref())
                    .chain(tx.vin.iter().filter_map(|input| input.address.as_deref()))
            }))
            .collect();
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() {
            return Ok(());
        }

        self.lock_addresses_for_write(db_tx, &addresses).await?;

        sqlx::query(
            r#"
            INSERT INTO addresses (
                address, balance, total_received, total_sent,
                tx_count, first_seen, last_seen, address_type, updated_at
            )
            SELECT
                activity.address,
                SUM(activity.value_out) - SUM(activity.value_in),
                SUM(activity.value_out),
                SUM(activity.value_in),
                COUNT(DISTINCT activity.txid),
                MIN(activity.block_time),
                MAX(activity.block_time),
                'transparent',
                NOW()
            FROM address_transactions activity
            WHERE activity.address = ANY($1)
            GROUP BY activity.address
            ON CONFLICT (address) DO UPDATE SET
                balance = EXCLUDED.balance,
                total_received = EXCLUDED.total_received,
                total_sent = EXCLUDED.total_sent,
                tx_count = EXCLUDED.tx_count,
                first_seen = EXCLUDED.first_seen,
                last_seen = EXCLUDED.last_seen,
                updated_at = NOW()
            "#,
        )
        .bind(&addresses)
        .execute(&mut **db_tx)
        .await?;
        sqlx::query(
            r#"DELETE FROM addresses summary
               WHERE summary.address = ANY($1)
                 AND NOT EXISTS (
                     SELECT 1 FROM address_transactions activity
                     WHERE activity.address = summary.address
                 )"#,
        )
        .bind(&addresses)
        .execute(&mut **db_tx)
        .await?;
        Ok(())
    }

    async fn insert_flows_tx(
        &self,
        db_tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        flows: &[ShieldedFlow],
        block_time: u64,
    ) -> Result<u64, sqlx::Error> {
        if flows.is_empty() {
            return Ok(0);
        }

        const FLOW_CHUNK_SIZE: usize = 8_000;
        for chunk in flows.chunks(FLOW_CHUNK_SIZE) {
            let mut query = QueryBuilder::<Postgres>::new(
                r#"
                INSERT INTO shielded_flows (
                    txid, block_height, block_time, flow_type, amount_zat, pool,
                    transparent_addresses, transparent_value_zat
                ) "#,
            );
            query.push_values(chunk, |mut row, flow| {
                row.push_bind(&flow.txid)
                    .push_bind(flow.block_height as i32)
                    .push_bind(block_time as i32)
                    .push_bind(&flow.flow_type)
                    .push_bind(flow.amount)
                    .push_bind(&flow.pool)
                    .push_bind(&flow.transparent_addresses)
                    .push_bind(flow.amount);
            });
            query.push(
                r#"
                ON CONFLICT (txid, flow_type) DO UPDATE SET
                    amount_zat = EXCLUDED.amount_zat,
                    transparent_addresses = EXCLUDED.transparent_addresses
                "#,
            );
            query.build().execute(&mut **db_tx).await?;
        }

        Ok(flows.len() as u64)
    }

    /// Batch-update only the metadata columns for a set of transactions.
    /// Used by the backfill-metadata subcommand to fill in expiry_height, locktime,
    /// sapling/sprout counts without touching outputs, inputs, or flows.
    pub async fn batch_update_metadata(
        &self,
        txs: &[crate::models::Transaction],
    ) -> Result<u64, sqlx::Error> {
        if txs.is_empty() {
            return Ok(0);
        }

        let mut db_tx = self.pool.begin().await?;
        let mut updated = 0u64;

        for tx in txs {
            let has_sprout = tx.joinsplit_count > 0;

            let result = sqlx::query(
                r#"
                UPDATE transactions SET
                    locktime = $2,
                    expiry_height = $3,
                    sapling_spend_count = $4,
                    sapling_output_count = $5,
                    sprout_joinsplit_count = $6,
                    has_sprout = $7
                WHERE txid = $1
                "#,
            )
            .bind(&tx.txid) // $1
            .bind(tx.lock_time as i64) // $2
            .bind(tx.expiry_height.map(|h| h as i32)) // $3
            .bind(tx.sapling_spends as i32) // $4
            .bind(tx.sapling_outputs as i32) // $5
            .bind(tx.joinsplit_count as i32) // $6
            .bind(has_sprout) // $7
            .execute(&mut *db_tx)
            .await?;

            updated += result.rows_affected();
        }

        db_tx.commit().await?;
        Ok(updated)
    }

    /// Get the stored block hash at a given height, if any.
    pub async fn get_block_hash_at_height(
        &self,
        height: u32,
    ) -> Result<Option<String>, sqlx::Error> {
        let result: Option<(String,)> = sqlx::query_as("SELECT hash FROM blocks WHERE height = $1")
            .bind(height as i64)
            .fetch_optional(&self.pool)
            .await?;
        Ok(result.map(|(h,)| h))
    }

    /// Roll back all data from `fork_height` onward, archiving orphaned blocks.
    ///
    /// Uses txid-indexed deletes for performance on large tables.
    /// Reverses address balance deltas before deleting transaction data.
    pub async fn rollback_from_height(
        &self,
        fork_height: u32,
        description: &str,
    ) -> Result<u32, sqlx::Error> {
        self.rollback_from_height_with_raw(fork_height, description, &[])
            .await
    }

    /// Raw evidence and structured metadata commit atomically with rollback.
    pub async fn rollback_from_height_with_raw(
        &self,
        fork_height: u32,
        description: &str,
        raw_blocks: &[(String, String)],
    ) -> Result<u32, sqlx::Error> {
        let mut db_tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(Self::BLOCK_WRITE_LOCK)
            .execute(&mut *db_tx)
            .await?;

        // Count blocks being rolled back
        let orphan_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM blocks WHERE height >= $1")
            .bind(fork_height as i64)
            .fetch_one(&mut *db_tx)
            .await?;
        let orphan_count = orphan_count.0 as u32;

        if orphan_count == 0 {
            db_tx.rollback().await?;
            return Ok(0);
        }

        // Record fork event
        let fork_event_id: (i32,) = sqlx::query_as(
            r#"INSERT INTO fork_events (fork_height, depth, canonical_tip, orphaned_count, source, description, detected_at, resolved_at)
               VALUES ($1, $2, $1, $3, 'indexer', $4, NOW(), NULL)
               RETURNING id"#
        )
        .bind(fork_height as i64)
        .bind(orphan_count as i32)
        .bind(orphan_count as i32)
        .bind(description)
        .fetch_one(&mut *db_tx)
        .await?;

        // Archive orphaned blocks (include roots for anchor debugging + coinbase for miner fingerprinting)
        sqlx::query(
            r#"INSERT INTO orphaned_blocks (height, hash, timestamp, transaction_count, size, difficulty, miner_address, previous_block_hash, final_sapling_root, final_orchard_root, final_ironwood_root, coinbase_hex, fork_event_id, source, first_indexed_at, block_metadata)
               SELECT b.height, b.hash, b.timestamp, b.transaction_count, b.size, b.difficulty::text, b.miner_address, b.previous_block_hash, b.final_sapling_root, b.final_orchard_root, b.final_ironwood_root, b.coinbase_hex, $1, 'indexer', b.created_at, to_jsonb(b)
               FROM blocks b WHERE b.height >= $2
               ON CONFLICT (hash) DO UPDATE SET
                   timestamp = EXCLUDED.timestamp,
                   transaction_count = EXCLUDED.transaction_count,
                   size = EXCLUDED.size,
                   difficulty = EXCLUDED.difficulty,
                   miner_address = EXCLUDED.miner_address,
                   previous_block_hash = EXCLUDED.previous_block_hash,
                   final_sapling_root = EXCLUDED.final_sapling_root,
                   final_orchard_root = EXCLUDED.final_orchard_root,
                   final_ironwood_root = EXCLUDED.final_ironwood_root,
                   coinbase_hex = EXCLUDED.coinbase_hex,
                   source = EXCLUDED.source,
                   block_metadata = EXCLUDED.block_metadata,
                   first_indexed_at = COALESCE(orphaned_blocks.first_indexed_at, EXCLUDED.first_indexed_at),
                   fork_event_id = EXCLUDED.fork_event_id"#
        )
        .bind(fork_event_id.0)
        .bind(fork_height as i64)
        .execute(&mut *db_tx)
        .await?;

        // Never leave a committed rollback with captured bytes still only in memory.
        for (hash, raw_hex) in raw_blocks {
            sqlx::query("UPDATE orphaned_blocks SET raw_hex = $1 WHERE hash = $2")
                .bind(raw_hex)
                .bind(hash)
                .execute(&mut *db_tx)
                .await?;
        }

        // Archive orphaned transactions before deletion
        sqlx::query(
            r#"INSERT INTO orphaned_transactions (
                   txid, block_height, block_hash, "timestamp", tx_index, version, locktime,
                   expiry_height, size, fee, is_coinbase,
                   vin_count, vout_count, total_input, total_output,
                   has_sapling, has_orchard, has_sprout, has_ironwood, has_shielded_data,
                   sapling_spend_count, sapling_output_count, orchard_actions, ironwood_actions,
                   sprout_joinsplit_count,
                   value_balance, value_balance_sapling, value_balance_orchard, value_balance_ironwood,
                   flow_type, privacy_score, fork_event_id, first_indexed_at,
                   orchard_anchor, ironwood_anchor
               )
               SELECT
                   t.txid, t.block_height, t.block_hash, t.block_time, t.tx_index, t.version, t.locktime,
                   t.expiry_height, t.size, t.fee, t.is_coinbase,
                   t.vin_count, t.vout_count, t.total_input, t.total_output,
                   t.has_sapling, t.has_orchard, t.has_sprout, t.has_ironwood, t.has_shielded_data,
                   t.sapling_spend_count, t.sapling_output_count, t.orchard_actions, t.ironwood_actions,
                   t.sprout_joinsplit_count,
                   t.value_balance, t.value_balance_sapling, t.value_balance_orchard, t.value_balance_ironwood,
                   t.flow_type, t.privacy_score, $1, t.created_at,
                   t.orchard_anchor, t.ironwood_anchor
               FROM transactions t WHERE t.block_height >= $2
               ON CONFLICT (txid, block_hash) DO NOTHING"#
        )
        .bind(fork_event_id.0)
        .bind(fork_height as i64)
        .execute(&mut *db_tx)
        .await?;

        // Archive transparent inputs for orphaned transactions
        sqlx::query(
            r#"INSERT INTO orphaned_transaction_inputs (txid, block_hash, vout_index, prev_txid, prev_vout, address, value, coinbase)
               SELECT ti.txid, t.block_hash, ti.vout_index, ti.prev_txid, ti.prev_vout, ti.address, ti.value, ti.coinbase
               FROM transaction_inputs ti
               JOIN transactions t ON ti.txid = t.txid
               WHERE t.block_height >= $1"#
        )
        .bind(fork_height as i64)
        .execute(&mut *db_tx)
        .await?;

        // Archive transparent outputs for orphaned transactions
        sqlx::query(
            r#"INSERT INTO orphaned_transaction_outputs (txid, block_hash, vout_index, value, address, script_type)
               SELECT to2.txid, t.block_hash, to2.vout_index, to2.value, to2.address, to2.script_type
               FROM transaction_outputs to2
               JOIN transactions t ON to2.txid = t.txid
               WHERE t.block_height >= $1"#
        )
        .bind(fork_height as i64)
        .execute(&mut *db_tx)
        .await?;

        // Preserve the complete affected set before removing orphan movements.
        sqlx::query(
            r#"CREATE TEMP TABLE integrity_reorg_addresses
               ON COMMIT DROP AS
               SELECT DISTINCT address
               FROM address_transactions
               WHERE txid IN (
                   SELECT txid FROM transactions WHERE block_height >= $1
               )"#,
        )
        .bind(fork_height as i32)
        .execute(&mut *db_tx)
        .await?;
        // Temporary tables are not analyzed by autovacuum. Without statistics,
        // PostgreSQL assumes 1,360 touched addresses and can scan the entire
        // movement ledger even for a one-block reorg affecting two addresses.
        sqlx::query("ANALYZE integrity_reorg_addresses")
            .execute(&mut *db_tx)
            .await?;
        // Outputs on the surviving chain must no longer point at orphan spends.
        sqlx::query(
            r#"UPDATE transaction_outputs
               SET spent = FALSE, spent_txid = NULL, spent_at = NULL
               WHERE spent_txid IN (
                   SELECT txid FROM transactions WHERE block_height >= $1
               )"#,
        )
        .bind(fork_height as i64)
        .execute(&mut *db_tx)
        .await?;

        // Delete dependent rows using txid index (fast)
        sqlx::query(
            "DELETE FROM address_transactions WHERE txid IN (SELECT txid FROM transactions WHERE block_height >= $1)"
        )
        .bind(fork_height as i64)
        .execute(&mut *db_tx)
        .await?;

        // Rebuild summaries from the surviving idempotent movement ledger.
        sqlx::query(
            r#"INSERT INTO addresses (
                   address, balance, total_received, total_sent,
                   tx_count, first_seen, last_seen, address_type, updated_at
               )
               SELECT at.address,
                      SUM(at.value_out) - SUM(at.value_in),
                      SUM(at.value_out), SUM(at.value_in),
                      COUNT(DISTINCT at.txid),
                      MIN(at.block_time), MAX(at.block_time),
                      'transparent', NOW()
               FROM address_transactions at
               JOIN integrity_reorg_addresses touched ON touched.address = at.address
               GROUP BY at.address
               ON CONFLICT (address) DO UPDATE SET
                   balance = EXCLUDED.balance,
                   total_received = EXCLUDED.total_received,
                   total_sent = EXCLUDED.total_sent,
                   tx_count = EXCLUDED.tx_count,
                   first_seen = EXCLUDED.first_seen,
                   last_seen = EXCLUDED.last_seen,
                   updated_at = NOW()"#,
        )
        .execute(&mut *db_tx)
        .await?;
        sqlx::query(
            r#"DELETE FROM addresses a
               USING integrity_reorg_addresses touched
               WHERE a.address = touched.address
                 AND NOT EXISTS (
                     SELECT 1 FROM address_transactions at
                     WHERE at.address = a.address
                 )"#,
        )
        .execute(&mut *db_tx)
        .await?;

        sqlx::query(
            "DELETE FROM shielded_flows WHERE txid IN (SELECT txid FROM transactions WHERE block_height >= $1)"
        )
        .bind(fork_height as i64)
        .execute(&mut *db_tx)
        .await?;

        sqlx::query(
            "DELETE FROM transaction_inputs WHERE txid IN (SELECT txid FROM transactions WHERE block_height >= $1)"
        )
        .bind(fork_height as i64)
        .execute(&mut *db_tx)
        .await?;

        sqlx::query(
            "DELETE FROM transaction_outputs WHERE txid IN (SELECT txid FROM transactions WHERE block_height >= $1)"
        )
        .bind(fork_height as i64)
        .execute(&mut *db_tx)
        .await?;

        // Delete transactions and blocks
        sqlx::query("DELETE FROM transactions WHERE block_height >= $1")
            .bind(fork_height as i64)
            .execute(&mut *db_tx)
            .await?;

        sqlx::query("DELETE FROM blocks WHERE height >= $1")
            .bind(fork_height as i64)
            .execute(&mut *db_tx)
            .await?;

        // Reset checkpoint
        let new_checkpoint = fork_height.saturating_sub(1);
        sqlx::query(
            r#"INSERT INTO indexer_state (key, value, updated_at) VALUES ('last_indexed_height', $1, NOW())
               ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()"#
        )
        .bind(new_checkpoint.to_string())
        .execute(&mut *db_tx)
        .await?;

        db_tx.commit().await?;
        Ok(orphan_count)
    }

    /// After re-indexing replacement blocks, backfill canonical_hash on orphaned_blocks
    /// and remove false orphans (where the orphaned hash matches the new canonical hash,
    /// which happens during double-reorgs: A->B->A).
    pub async fn finalize_orphans_after_reindex(
        &self,
        fork_height: u32,
        last_height: u32,
    ) -> Result<(), sqlx::Error> {
        // Backfill canonical_hash from the (now re-indexed) blocks table
        sqlx::query(
            r#"UPDATE orphaned_blocks ob
               SET canonical_hash = b.hash
               FROM blocks b
               WHERE ob.height = b.height
               AND ob.canonical_hash IS NULL
               AND ob.height >= $1 AND ob.height <= $2"#,
        )
        .bind(fork_height as i64)
        .bind(last_height as i64)
        .execute(&self.pool)
        .await?;

        // Remove false orphans: if orphaned hash == canonical hash, it was a double-reorg
        let removed = sqlx::query(
            r#"DELETE FROM orphaned_blocks
               WHERE canonical_hash IS NOT NULL
               AND hash = canonical_hash
               AND height >= $1 AND height <= $2"#,
        )
        .bind(fork_height as i64)
        .bind(last_height as i64)
        .execute(&self.pool)
        .await?;

        if removed.rows_affected() > 0 {
            tracing::info!(
                "Cleaned {} false orphan(s) from double-reorg",
                removed.rows_affected()
            );
        }

        Ok(())
    }

    /// Store raw block hex on an already-archived orphaned_blocks row.
    pub async fn store_orphan_raw_hex(
        &self,
        block_hash: &str,
        raw_hex: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE orphaned_blocks SET raw_hex = $1 WHERE hash = $2")
            .bind(raw_hex)
            .bind(block_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Batch-update anchor roots for transactions that were indexed before anchors were stored.
    /// Used by the backfill-anchors subcommand.
    pub async fn batch_update_anchors(
        &self,
        updates: &[(String, Option<String>, Option<String>)], // (txid, orchard_anchor, ironwood_anchor)
    ) -> Result<u64, sqlx::Error> {
        if updates.is_empty() {
            return Ok(0);
        }

        let mut db_tx = self.pool.begin().await?;
        let mut updated = 0u64;

        for (txid, orchard_anchor, ironwood_anchor) in updates {
            let result = sqlx::query(
                r#"
                UPDATE transactions SET
                    orchard_anchor = COALESCE($2, orchard_anchor),
                    ironwood_anchor = COALESCE($3, ironwood_anchor)
                WHERE txid = $1
                "#,
            )
            .bind(txid)
            .bind(orchard_anchor)
            .bind(ironwood_anchor)
            .execute(&mut *db_tx)
            .await?;

            updated += result.rows_affected();
        }

        db_tx.commit().await?;
        Ok(updated)
    }

    /// Insert a boundary pool snapshot (authoritative Zebra pool sizes at a 256-block boundary).
    /// Uses ON CONFLICT to allow idempotent re-inserts (e.g. after reorg re-indexing).
    /// Each argument maps 1:1 to a column; bundling into a struct would only
    /// move the same 8 fields to a call site with no correctness benefit.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_boundary_pool_snapshot(
        &self,
        boundary_height: u32,
        block_time: i64,
        orchard_zat: i64,
        ironwood_zat: i64,
        sapling_zat: i64,
        sprout_zat: i64,
        transparent_zat: Option<i64>,
        chain_supply_zat: Option<i64>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"INSERT INTO boundary_pool_snapshots
                 (boundary_height, block_time, orchard_zat, ironwood_zat,
                  sapling_zat, sprout_zat, transparent_zat, chain_supply_zat)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               ON CONFLICT (boundary_height)
               DO UPDATE SET
                 block_time = EXCLUDED.block_time,
                 orchard_zat = EXCLUDED.orchard_zat,
                 ironwood_zat = EXCLUDED.ironwood_zat,
                 sapling_zat = EXCLUDED.sapling_zat,
                 sprout_zat = EXCLUDED.sprout_zat,
                 transparent_zat = EXCLUDED.transparent_zat,
                 chain_supply_zat = EXCLUDED.chain_supply_zat"#,
        )
        .bind(boundary_height as i64)
        .bind(block_time)
        .bind(orchard_zat)
        .bind(ironwood_zat)
        .bind(sapling_zat)
        .bind(sprout_zat)
        .bind(transparent_zat)
        .bind(chain_supply_zat)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod integrity_write_tests {
    #[test]
    fn funding_recipients_are_never_miner_candidates() {
        use super::miner_address_candidate;
        for address in [
            "t3cFfPt1Bcvgez9ZbMBFWeZsskxTkPzGCow",
            "t2HifwjUj9uyxr9bknR8LFuQbc98c3vkXtu",
        ] {
            assert_eq!(miner_address_candidate(Some(address)), None);
        }
        assert_eq!(miner_address_candidate(None), None);
        let miner = "t1MKn34KBa8Xh4g8qU8psibBXvURafphVn7";
        assert_eq!(miner_address_candidate(Some(miner)), Some(miner.to_owned()));
    }

    #[test]
    fn spent_metadata_uses_spending_block_time() {
        let source = include_str!("postgres.rs");
        assert!(source.contains("to_timestamp(spender.block_time) AT TIME ZONE 'UTC'"));
    }

    #[test]
    fn replay_resets_activity_and_deletes_removed_owners() {
        let source = include_str!("postgres.rs");
        assert!(source.contains("DELETE FROM address_transactions WHERE txid = ANY($1)"));
        assert!(source.contains("DELETE FROM addresses summary"));
    }
}
