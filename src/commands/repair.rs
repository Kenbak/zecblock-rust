use crate::config::Config;
use crate::db::{PostgresWriter, ZebraRpc, ZebraState};
use crate::models::{ShieldedFlow, Transaction};
use sqlx::{Postgres, Row};
use std::collections::{BTreeMap, BTreeSet, HashMap};

const BLOCK_WRITE_LOCK: i64 = 0x4349_5048_4552;
const BLOCK_HEIGHT_LOCK: i32 = 0x424c_4f43;
const SPROUT_REPAIR_CHECKPOINT: &str = "sprout_fee_repair_height";
const MAX_REPAIR_WINDOW: u32 = 10_000;

/// Fee from stored columns. Any unknown component or a negative result is an
/// unknown fee (NULL); the caller never substitutes zero.
fn stored_fee(
    total_input: Option<i64>,
    total_output: Option<i64>,
    balances: [Option<i64>; 4],
) -> Option<i64> {
    let mut fee = total_input?;
    for balance in balances {
        fee = fee.checked_add(balance?)?;
    }
    let fee = fee.checked_sub(total_output?)?;
    (fee >= 0).then_some(fee)
}

/// Recalculate fees for transactions with a nonzero Ironwood value balance,
/// using the full formula (transparent in + every shielded pool - transparent out).
pub(crate) async fn repair_ironwood_fees(
    config: &Config,
    batch_size: usize,
    dry_run: bool,
) -> Result<(), String> {
    if config.database_url.is_empty() {
        return Err("DATABASE_URL not configured".to_string());
    }
    let batch_size = batch_size.max(1);

    let postgres = PostgresWriter::connect(&config.database_url)
        .await
        .map_err(|e| format!("PostgreSQL error: {}", e))?;

    println!("🔧 Repair: recalculating fees for Ironwood transactions");
    if dry_run {
        println!("   (DRY RUN — no changes will be written)");
    }
    println!("────────────────────────────────────────────────────────────");

    // Unknown components stay NULL so the computed fee stays unknown.
    let rows: Vec<_> = sqlx::query(
        r#"SELECT txid, fee, total_input, total_output,
                  value_balance_sprout, value_balance_sapling,
                  value_balance_orchard, value_balance_ironwood
           FROM transactions
           WHERE has_ironwood = TRUE
             AND value_balance_ironwood IS NOT NULL
             AND value_balance_ironwood != 0
             AND is_coinbase = FALSE
           ORDER BY block_height ASC"#,
    )
    .fetch_all(postgres.pool())
    .await
    .map_err(|e| format!("Query error: {}", e))?;

    let total = rows.len();
    println!(
        "   Found {} transactions with nonzero ironwood_value_balance",
        total
    );
    if total == 0 {
        println!("   ✅ Nothing to repair");
        return Ok(());
    }

    let mut updated = 0u64;
    let mut skipped = 0u64;

    for chunk in rows.chunks(batch_size) {
        let mut db_tx = postgres
            .pool()
            .begin()
            .await
            .map_err(|e| format!("Transaction begin error: {}", e))?;

        for row in chunk {
            let txid: &str = row.get("txid");
            let old_fee: Option<i64> = row.get("fee");
            let new_fee = stored_fee(
                row.get("total_input"),
                row.get("total_output"),
                [
                    row.get("value_balance_sprout"),
                    row.get("value_balance_sapling"),
                    row.get("value_balance_orchard"),
                    row.get("value_balance_ironwood"),
                ],
            );

            if new_fee == old_fee {
                skipped += 1;
                continue;
            }

            if dry_run {
                println!(
                    "   WOULD FIX {}: fee {} → {}",
                    &txid[..16.min(txid.len())],
                    fmt_opt(old_fee),
                    fmt_opt(new_fee),
                );
            } else {
                sqlx::query("UPDATE transactions SET fee = $1 WHERE txid = $2")
                    .bind(new_fee)
                    .bind(txid)
                    .execute(&mut *db_tx)
                    .await
                    .map_err(|e| format!("Update error for {}: {}", txid, e))?;
            }
            updated += 1;
        }

        if !dry_run {
            db_tx
                .commit()
                .await
                .map_err(|e| format!("Commit error: {}", e))?;
        }
    }

    println!("────────────────────────────────────────────────────────────");
    println!(
        "   ✅ {} fees {}, {} already correct",
        updated,
        if dry_run {
            "would be updated"
        } else {
            "updated"
        },
        skipped,
    );
    Ok(())
}

fn fmt_opt(value: Option<i64>) -> String {
    value.map_or_else(|| "NULL".to_string(), |v| v.to_string())
}

/// Stored transaction columns that the Sprout repair may rewrite or checks.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredTx {
    fee: Option<i64>,
    value_balance_sprout: Option<i64>,
    joinsplit_count: Option<i32>,
    has_sprout: Option<bool>,
    total_input: Option<i64>,
    total_output: Option<i64>,
    block_time: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FlowKey {
    flow_type: String,
    pool: String,
    amount: i64,
}

/// One transaction whose stored Sprout-derived columns differ from the node.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TxChange {
    txid: String,
    height: u32,
    old_fee: Option<i64>,
    new_fee: Option<i64>,
    old_sprout: Option<i64>,
    new_sprout: i64,
    old_joinsplits: Option<i32>,
    new_joinsplits: i32,
}

/// Compare a node-derived transaction with its stored row. `None` = no change.
fn diff_transaction(computed: &Transaction, stored: &StoredTx) -> Option<TxChange> {
    let new_joinsplits = i32::from(computed.joinsplit_count);
    let unchanged = stored.fee == computed.fee
        && stored.value_balance_sprout == Some(computed.sprout_value_balance)
        && stored.joinsplit_count == Some(new_joinsplits)
        && stored.has_sprout == Some(new_joinsplits > 0);
    (!unchanged).then(|| TxChange {
        txid: computed.txid.clone(),
        height: computed.block_height,
        old_fee: stored.fee,
        new_fee: computed.fee,
        old_sprout: stored.value_balance_sprout,
        new_sprout: computed.sprout_value_balance,
        old_joinsplits: stored.joinsplit_count,
        new_joinsplits,
    })
}

/// Transparent totals are not rewritten here; a mismatch is reported for the
/// separate address-accounting integrity repair.
fn transparent_mismatch(computed: &Transaction, stored: &StoredTx) -> bool {
    stored.total_input != Some(computed.transparent_value_in)
        || stored.total_output != Some(computed.transparent_value_out)
}

fn computed_flows(tx: &Transaction) -> Vec<FlowKey> {
    let mut flows: Vec<FlowKey> = ShieldedFlow::from_transaction(tx)
        .into_iter()
        .map(|flow| FlowKey {
            flow_type: flow.flow_type,
            pool: flow.pool,
            amount: flow.amount,
        })
        .collect();
    flows.sort();
    flows
}

#[derive(Debug, Default)]
struct SproutRepairReport {
    blocks_scanned: u64,
    sprout_blocks: u64,
    sprout_txs: u64,
    tx_changes: u64,
    fee_changes: u64,
    fee_to_null: u64,
    fee_from_null: u64,
    sprout_balance_changes: u64,
    joinsplit_count_changes: u64,
    /// Sum of (old - new) over fee changes where both sides are known.
    fee_delta_zat: i128,
    block_total_changes: u64,
    block_total_delta_zat: i128,
    flow_changes: u64,
    hash_mismatches: u64,
    missing_rows: u64,
    transparent_mismatches: u64,
    /// Non-Sprout transactions in repaired blocks whose stored fee differs
    /// from the node; reported only, never rewritten by this command.
    other_fee_mismatches: u64,
    tx_samples: Vec<TxChange>,
    block_samples: Vec<(u32, Option<i64>, Option<i64>)>,
    anomaly_samples: Vec<String>,
}

/// Where raw blocks come from. RocksDB is fast for history; RPC also serves
/// tip blocks that the node has not yet flushed to SST files, which a
/// secondary RocksDB view cannot see.
enum BlockSource {
    Rocks(ZebraState),
    Rpc(ZebraRpc),
}

impl BlockSource {
    async fn tip(&self) -> Result<u32, String> {
        match self {
            BlockSource::Rocks(zebra) => zebra.get_tip_height(),
            BlockSource::Rpc(rpc) => u32::try_from(rpc.get_block_count().await?)
                .map_err(|_| "RPC tip out of range".to_string()),
        }
    }

    /// Parse one block; returns its hash and transactions (inputs unresolved).
    async fn load(
        &self,
        height: u32,
        network: crate::config::Network,
    ) -> Result<(String, Vec<Transaction>), String> {
        use crate::indexer::TransactionParser;
        match self {
            BlockSource::Rocks(zebra) => {
                let hash = crate::util::display_hash(&zebra.get_block_hash(height)?);
                let mut transactions = Vec::new();
                for (index, raw) in zebra.iter_block_transactions(height)? {
                    transactions.push(
                        TransactionParser::parse(&raw, height, &hash, network)
                            .map_err(|e| format!("parse error at {height}:{index}: {e}"))?,
                    );
                }
                Ok((hash, transactions))
            }
            BlockSource::Rpc(rpc) => {
                use zakura_chain::block::Block;
                use zakura_chain::serialization::{ZcashDeserialize, ZcashSerialize};
                let hash = rpc.get_block_hash(u64::from(height)).await?;
                let raw = hex::decode(rpc.get_raw_block_hex(&hash).await?)
                    .map_err(|e| format!("invalid block hex at {height}: {e}"))?;
                let block = Block::zcash_deserialize(&mut std::io::Cursor::new(&raw))
                    .map_err(|e| format!("failed to deserialize block {height}: {e:?}"))?;
                if block.hash().to_string() != hash {
                    return Err(format!("block {height} hash mismatch"));
                }
                if block.coinbase_height().map(|h| h.0) != Some(height) {
                    return Err(format!("block {height} coinbase height mismatch"));
                }
                let mut transactions = Vec::with_capacity(block.transactions.len());
                for (index, tx) in block.transactions.iter().enumerate() {
                    let mut bytes = Vec::new();
                    tx.zcash_serialize(&mut bytes)
                        .map_err(|e| format!("serialize error at {height}:{index}: {e}"))?;
                    transactions.push(
                        TransactionParser::parse(&bytes, height, &hash, network)
                            .map_err(|e| format!("parse error at {height}:{index}: {e}"))?,
                    );
                }
                Ok((hash, transactions))
            }
        }
    }

    /// Resolve every transparent input and compute fees for one full block.
    async fn resolve(
        &self,
        postgres: &PostgresWriter,
        transactions: &mut [Transaction],
        network: crate::config::Network,
    ) -> Result<(), String> {
        use crate::indexer::TransactionParser;
        match self {
            BlockSource::Rocks(zebra) => {
                TransactionParser::resolve_block_inputs(transactions, zebra)
            }
            BlockSource::Rpc(rpc) => resolve_inputs_rpc(rpc, postgres, transactions, network).await,
        }
    }
}

/// Same-block outputs first, then stored outputs, then the node over RPC.
async fn resolve_inputs_rpc(
    rpc: &ZebraRpc,
    postgres: &PostgresWriter,
    transactions: &mut [Transaction],
    network: crate::config::Network,
) -> Result<(), String> {
    use crate::indexer::TransactionParser;
    let current: HashMap<(String, u32), (i64, Option<String>)> = transactions
        .iter()
        .flat_map(|tx| {
            tx.vout
                .iter()
                .map(move |o| ((tx.txid.clone(), o.n), (o.value, o.address.clone())))
        })
        .collect();
    let mut references: Vec<(String, u32)> = transactions
        .iter()
        .flat_map(|tx| {
            tx.vin
                .iter()
                .filter(|i| !i.is_coinbase)
                .map(|i| (i.txid.clone(), i.vout))
        })
        .filter(|key| !current.contains_key(key))
        .collect();
    references.sort_unstable();
    references.dedup();
    let stored = postgres
        .get_prev_outputs(&references)
        .await
        .map_err(|e| format!("prevout database lookup failed: {e}"))?;
    let mut fetched: HashMap<String, Transaction> = HashMap::new();
    for tx in transactions.iter_mut() {
        if tx.is_coinbase() {
            tx.fee = None;
            continue;
        }
        let mut total = 0i64;
        for input in tx.vin.iter_mut() {
            let key = (input.txid.clone(), input.vout);
            let (value, address) = match current.get(&key).or_else(|| stored.get(&key)) {
                Some(found) => found.clone(),
                None => {
                    if !fetched.contains_key(&input.txid) {
                        let raw = hex::decode(rpc.get_raw_transaction_hex(&input.txid).await?)
                            .map_err(|e| format!("invalid prevout hex: {e}"))?;
                        let parsed = TransactionParser::parse(&raw, 0, "", network)?;
                        fetched.insert(input.txid.clone(), parsed);
                    }
                    let output = fetched
                        .get(&input.txid)
                        .and_then(|prev| prev.vout.get(input.vout as usize))
                        .ok_or_else(|| format!("missing prevout {}:{}", input.txid, input.vout))?;
                    (output.value, output.address.clone())
                }
            };
            input.value = Some(value);
            input.address = address;
            total = total
                .checked_add(value)
                .ok_or_else(|| format!("transparent input overflow for {}", tx.txid))?;
        }
        tx.transparent_value_in = total;
        tx.fee = tx.compute_fee()?;
    }
    Ok(())
}

struct BlockPlan {
    height: u32,
    hash: String,
    total_fees: Option<i64>,
    transactions: Vec<Transaction>,
}

/// Recompute Sprout value balances, fees, block fee totals and flows from the
/// node's raw blocks for a bounded height range. Resumable through
/// indexer_state.sprout_fee_repair_height (advanced only by real runs).
/// `no_resume` ignores and never writes that shared checkpoint, for parallel
/// or targeted range runs; writes are idempotent, so reruns are safe.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn repair_sprout_fees(
    config: &Config,
    from: u32,
    to: u32,
    window: u32,
    dry_run: bool,
    no_resume: bool,
    rpc_source: bool,
    samples: usize,
    lock_timeout_ms: u64,
    statement_timeout_ms: u64,
) -> Result<(), String> {
    if config.database_url.is_empty() {
        return Err("DATABASE_URL not configured".to_string());
    }
    if from > to {
        return Err("invalid height range".to_string());
    }
    let window = window.clamp(1, MAX_REPAIR_WINDOW);

    let source = if rpc_source {
        BlockSource::Rpc(ZebraRpc::from_env()?)
    } else {
        let zebra = ZebraState::open(config)?;
        // Include blocks still only in the node's WAL (recent tip history).
        zebra.catch_up_with_primary()?;
        BlockSource::Rocks(zebra)
    };
    let tip = source.tip().await?;
    if to > tip {
        return Err(format!("--to {to} is above the node tip {tip}"));
    }
    let postgres = PostgresWriter::connect(&config.database_url)
        .await
        .map_err(|e| format!("PostgreSQL error: {}", e))?;

    let checkpoint = !dry_run && !no_resume;
    let start = if !checkpoint {
        from
    } else {
        match postgres
            .get_checkpoint_key(SPROUT_REPAIR_CHECKPOINT)
            .await
            .map_err(|e| format!("Checkpoint read error: {}", e))?
        {
            Some(saved) if saved >= to => {
                println!("✅ Sprout repair checkpoint {saved} already covers {from}..={to}");
                return Ok(());
            }
            Some(saved) if saved >= from => saved + 1,
            _ => from,
        }
    };

    println!(
        "🔧 Sprout fee repair {}..={} (window={}{})",
        start,
        to,
        window,
        if dry_run {
            ", DRY RUN — nothing is written"
        } else {
            ""
        }
    );
    println!("────────────────────────────────────────────────────────────");

    let mut report = SproutRepairReport::default();
    let mut current = start;
    loop {
        let window_end = current.saturating_add(window - 1).min(to);
        repair_window(
            &source,
            &postgres,
            config,
            current,
            window_end,
            dry_run,
            checkpoint,
            samples,
            lock_timeout_ms,
            statement_timeout_ms,
            &mut report,
        )
        .await?;
        println!(
            "   ..={}: sprout blocks {}, tx changes {}, block totals {}, anomalies {}",
            window_end,
            report.sprout_blocks,
            report.tx_changes,
            report.block_total_changes,
            report.hash_mismatches + report.missing_rows + report.transparent_mismatches
        );
        if window_end >= to {
            break;
        }
        current = window_end + 1;
    }

    print_sprout_report(&report, dry_run);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn repair_window(
    source: &BlockSource,
    postgres: &PostgresWriter,
    config: &Config,
    from: u32,
    to: u32,
    dry_run: bool,
    checkpoint: bool,
    samples: usize,
    lock_timeout_ms: u64,
    statement_timeout_ms: u64,
    report: &mut SproutRepairReport,
) -> Result<(), String> {
    // Blocks the database already marks as Sprout must be rechecked even if
    // the node shows no JoinSplits, so stale flags are cleared too.
    let flagged: BTreeSet<i64> = sqlx::query_scalar(
        "SELECT DISTINCT block_height FROM transactions \
         WHERE block_height BETWEEN $1 AND $2 AND has_sprout = TRUE",
    )
    .bind(i64::from(from))
    .bind(i64::from(to))
    .fetch_all(postgres.pool())
    .await
    .map_err(|e| format!("Sprout height scan failed: {e}"))?
    .into_iter()
    .collect();

    let mut plans = Vec::new();
    for height in from..=to {
        report.blocks_scanned += 1;
        let (hash, mut transactions) = source.load(height, config.network).await?;
        let has_joinsplit = transactions.iter().any(|tx| tx.joinsplit_count > 0);
        if !has_joinsplit && !flagged.contains(&i64::from(height)) {
            continue;
        }
        // Full-block resolution keeps same-block prevouts exact and yields
        // every fee in the block, so the block total is node-derived too.
        source
            .resolve(postgres, &mut transactions, config.network)
            .await?;
        let total_fees = crate::db::postgres::block_total_fees(&transactions)
            .map_err(|e| format!("{e} at {height}"))?;
        report.sprout_blocks += 1;
        plans.push(BlockPlan {
            height,
            hash,
            total_fees,
            transactions,
        });
    }
    if plans.is_empty() {
        if checkpoint {
            save_checkpoint(postgres, to).await?;
        }
        return Ok(());
    }

    let mut db_tx = postgres
        .pool()
        .begin()
        .await
        .map_err(|e| format!("transaction begin failed: {e}"))?;
    sqlx::query(
        "SELECT set_config('lock_timeout',$1,true),set_config('statement_timeout',$2,true)",
    )
    .bind(format!("{lock_timeout_ms}ms"))
    .bind(format!("{statement_timeout_ms}ms"))
    .execute(&mut *db_tx)
    .await
    .map_err(|e| format!("timeout setup failed: {e}"))?;
    // Same lock order as block writers: shared global lock, then per-height
    // locks ascending. Reorg rollback takes the exclusive global lock.
    sqlx::query("SELECT pg_advisory_xact_lock_shared($1)")
        .bind(BLOCK_WRITE_LOCK)
        .execute(&mut *db_tx)
        .await
        .map_err(|e| format!("block write lock failed: {e}"))?;
    for plan in &plans {
        sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
            .bind(BLOCK_HEIGHT_LOCK)
            .bind(plan.height as i32)
            .execute(&mut *db_tx)
            .await
            .map_err(|e| format!("height lock failed: {e}"))?;
    }

    let heights: Vec<i64> = plans.iter().map(|plan| i64::from(plan.height)).collect();
    let stored_blocks: HashMap<i64, (String, Option<i64>)> =
        sqlx::query("SELECT height, hash, total_fees FROM blocks WHERE height = ANY($1)")
            .bind(&heights)
            .fetch_all(&mut *db_tx)
            .await
            .map_err(|e| format!("block read failed: {e}"))?
            .into_iter()
            .map(|row| (row.get("height"), (row.get("hash"), row.get("total_fees"))))
            .collect();

    let txids: Vec<String> = plans
        .iter()
        .flat_map(|plan| plan.transactions.iter().map(|tx| tx.txid.clone()))
        .collect();
    let stored_txs: HashMap<String, (String, StoredTx)> = sqlx::query(
        "SELECT txid, block_hash, fee, value_balance_sprout, sprout_joinsplit_count, \
                has_sprout, total_input, total_output, block_time \
         FROM transactions WHERE txid = ANY($1)",
    )
    .bind(&txids)
    .fetch_all(&mut *db_tx)
    .await
    .map_err(|e| format!("transaction read failed: {e}"))?
    .into_iter()
    .map(|row| {
        (
            row.get("txid"),
            (
                row.get("block_hash"),
                StoredTx {
                    fee: row.get("fee"),
                    value_balance_sprout: row.get("value_balance_sprout"),
                    joinsplit_count: row.get("sprout_joinsplit_count"),
                    has_sprout: row.get("has_sprout"),
                    total_input: row.get("total_input"),
                    total_output: row.get("total_output"),
                    block_time: row.get("block_time"),
                },
            ),
        )
    })
    .collect();

    let sprout_txids: Vec<String> = plans
        .iter()
        .flat_map(|plan| plan.transactions.iter())
        .filter(|tx| {
            tx.joinsplit_count > 0
                || stored_txs
                    .get(&tx.txid)
                    .is_some_and(|(_, stored)| stored.has_sprout == Some(true))
        })
        .map(|tx| tx.txid.clone())
        .collect();
    let mut stored_flows: BTreeMap<String, Vec<FlowKey>> = BTreeMap::new();
    for row in sqlx::query(
        "SELECT txid, flow_type, pool, amount_zat FROM shielded_flows WHERE txid = ANY($1)",
    )
    .bind(&sprout_txids)
    .fetch_all(&mut *db_tx)
    .await
    .map_err(|e| format!("flow read failed: {e}"))?
    {
        stored_flows
            .entry(row.get("txid"))
            .or_default()
            .push(FlowKey {
                flow_type: row.get("flow_type"),
                pool: row.get("pool"),
                amount: row.get("amount_zat"),
            });
    }
    for flows in stored_flows.values_mut() {
        flows.sort();
    }
    let sprout_set: BTreeSet<&str> = sprout_txids.iter().map(String::as_str).collect();

    let mut tx_updates: Vec<&Transaction> = Vec::new();
    let mut block_updates: Vec<(i64, String, Option<i64>)> = Vec::new();
    let mut flow_rewrites: Vec<(&Transaction, i64)> = Vec::new();

    for plan in &plans {
        let Some((stored_hash, stored_total)) = stored_blocks.get(&i64::from(plan.height)) else {
            report.missing_rows += 1;
            push_sample(
                &mut report.anomaly_samples,
                samples,
                format!("block {} missing from database", plan.height),
            );
            continue;
        };
        if *stored_hash != plan.hash {
            report.hash_mismatches += 1;
            push_sample(
                &mut report.anomaly_samples,
                samples,
                format!(
                    "block {} hash differs (db {}, node {}); skipped",
                    plan.height, stored_hash, plan.hash
                ),
            );
            continue;
        }

        let mut block_complete = true;
        for tx in &plan.transactions {
            let Some((tx_hash, stored)) = stored_txs.get(&tx.txid) else {
                report.missing_rows += 1;
                block_complete = false;
                push_sample(
                    &mut report.anomaly_samples,
                    samples,
                    format!("tx {} at {} missing from database", tx.txid, plan.height),
                );
                continue;
            };
            if *tx_hash != plan.hash {
                report.hash_mismatches += 1;
                block_complete = false;
                push_sample(
                    &mut report.anomaly_samples,
                    samples,
                    format!("tx {} stored under another block hash; skipped", tx.txid),
                );
                continue;
            }
            if !sprout_set.contains(tx.txid.as_str()) {
                // Coinbase rows have no fee; legacy rows store 0 there.
                if !tx.is_coinbase() && stored.fee != tx.fee {
                    report.other_fee_mismatches += 1;
                    push_sample(
                        &mut report.anomaly_samples,
                        samples,
                        format!(
                            "non-Sprout tx {} fee differs (db {}, node {}); not rewritten",
                            tx.txid,
                            fmt_opt(stored.fee),
                            fmt_opt(tx.fee)
                        ),
                    );
                }
                continue;
            }
            report.sprout_txs += 1;
            if !tx.is_coinbase() && transparent_mismatch(tx, stored) {
                report.transparent_mismatches += 1;
                push_sample(
                    &mut report.anomaly_samples,
                    samples,
                    format!(
                        "tx {} transparent totals differ (db in {} out {}, node in {} out {})",
                        tx.txid,
                        fmt_opt(stored.total_input),
                        fmt_opt(stored.total_output),
                        tx.transparent_value_in,
                        tx.transparent_value_out
                    ),
                );
            }
            if let Some(change) = diff_transaction(tx, stored) {
                record_tx_change(report, &change, samples);
                tx_updates.push(tx);
            }
            let wanted = computed_flows(tx);
            let current = stored_flows.get(&tx.txid).cloned().unwrap_or_default();
            if wanted != current {
                report.flow_changes += 1;
                flow_rewrites.push((tx, stored.block_time));
            }
        }

        // Only a block whose every transaction row matched gets a new total.
        if block_complete && *stored_total != plan.total_fees {
            report.block_total_changes += 1;
            if let (Some(old), Some(new)) = (stored_total, plan.total_fees) {
                report.block_total_delta_zat += i128::from(*old) - i128::from(new);
            }
            if report.block_samples.len() < samples {
                report
                    .block_samples
                    .push((plan.height, *stored_total, plan.total_fees));
            }
            block_updates.push((i64::from(plan.height), plan.hash.clone(), plan.total_fees));
        }
    }

    if dry_run {
        db_tx
            .rollback()
            .await
            .map_err(|e| format!("rollback failed: {e}"))?;
        return Ok(());
    }

    write_tx_updates(&mut db_tx, &tx_updates).await?;
    write_block_updates(&mut db_tx, &block_updates).await?;
    write_flow_rewrites(&mut db_tx, &flow_rewrites).await?;
    if checkpoint {
        sqlx::query(
            "INSERT INTO indexer_state (key, value, updated_at) VALUES ($1, $2, NOW()) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
        )
        .bind(SPROUT_REPAIR_CHECKPOINT)
        .bind(to.to_string())
        .execute(&mut *db_tx)
        .await
        .map_err(|e| format!("checkpoint write failed: {e}"))?;
    }
    db_tx
        .commit()
        .await
        .map_err(|e| format!("commit failed: {e}"))
}

async fn save_checkpoint(postgres: &PostgresWriter, height: u32) -> Result<(), String> {
    sqlx::query(
        "INSERT INTO indexer_state (key, value, updated_at) VALUES ($1, $2, NOW()) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
    )
    .bind(SPROUT_REPAIR_CHECKPOINT)
    .bind(height.to_string())
    .execute(postgres.pool())
    .await
    .map(|_| ())
    .map_err(|e| format!("checkpoint write failed: {e}"))
}

fn push_sample(samples: &mut Vec<String>, limit: usize, message: String) {
    if samples.len() < limit {
        samples.push(message);
    }
}

fn record_tx_change(report: &mut SproutRepairReport, change: &TxChange, samples: usize) {
    report.tx_changes += 1;
    if change.old_fee != change.new_fee {
        report.fee_changes += 1;
        match (change.old_fee, change.new_fee) {
            (Some(old), Some(new)) => report.fee_delta_zat += i128::from(old) - i128::from(new),
            (Some(_), None) => report.fee_to_null += 1,
            (None, Some(_)) => report.fee_from_null += 1,
            (None, None) => {}
        }
    }
    if change.old_sprout != Some(change.new_sprout) {
        report.sprout_balance_changes += 1;
    }
    if change.old_joinsplits != Some(change.new_joinsplits) {
        report.joinsplit_count_changes += 1;
    }
    if report.tx_samples.len() < samples {
        report.tx_samples.push(change.clone());
    }
}

async fn write_tx_updates(
    db_tx: &mut sqlx::Transaction<'_, Postgres>,
    updates: &[&Transaction],
) -> Result<(), String> {
    if updates.is_empty() {
        return Ok(());
    }
    let txids: Vec<&str> = updates.iter().map(|tx| tx.txid.as_str()).collect();
    let hashes: Vec<&str> = updates.iter().map(|tx| tx.block_hash.as_str()).collect();
    let fees: Vec<Option<i64>> = updates.iter().map(|tx| tx.fee).collect();
    let balances: Vec<i64> = updates.iter().map(|tx| tx.sprout_value_balance).collect();
    let counts: Vec<i32> = updates
        .iter()
        .map(|tx| i32::from(tx.joinsplit_count))
        .collect();
    sqlx::query(
        r#"
        UPDATE transactions t
        SET fee = u.fee,
            value_balance_sprout = u.value_balance_sprout,
            sprout_joinsplit_count = u.joinsplit_count,
            has_sprout = u.joinsplit_count > 0,
            has_shielded_data = COALESCE(t.has_sapling, FALSE) OR COALESCE(t.has_orchard, FALSE)
                OR COALESCE(t.has_ironwood, FALSE) OR u.joinsplit_count > 0
        FROM UNNEST($1::text[], $2::text[], $3::bigint[], $4::bigint[], $5::integer[])
             AS u(txid, block_hash, fee, value_balance_sprout, joinsplit_count)
        WHERE t.txid = u.txid AND t.block_hash = u.block_hash
        "#,
    )
    .bind(&txids)
    .bind(&hashes)
    .bind(&fees)
    .bind(&balances)
    .bind(&counts)
    .execute(&mut **db_tx)
    .await
    .map(|_| ())
    .map_err(|e| format!("transaction update failed: {e}"))
}

async fn write_block_updates(
    db_tx: &mut sqlx::Transaction<'_, Postgres>,
    updates: &[(i64, String, Option<i64>)],
) -> Result<(), String> {
    if updates.is_empty() {
        return Ok(());
    }
    let heights: Vec<i64> = updates.iter().map(|(height, _, _)| *height).collect();
    let hashes: Vec<&str> = updates.iter().map(|(_, hash, _)| hash.as_str()).collect();
    let totals: Vec<Option<i64>> = updates.iter().map(|(_, _, total)| *total).collect();
    sqlx::query(
        r#"
        UPDATE blocks b SET total_fees = u.total_fees
        FROM UNNEST($1::bigint[], $2::text[], $3::bigint[]) AS u(height, hash, total_fees)
        WHERE b.height = u.height AND b.hash = u.hash
        "#,
    )
    .bind(&heights)
    .bind(&hashes)
    .bind(&totals)
    .execute(&mut **db_tx)
    .await
    .map(|_| ())
    .map_err(|e| format!("block update failed: {e}"))
}

async fn write_flow_rewrites(
    db_tx: &mut sqlx::Transaction<'_, Postgres>,
    rewrites: &[(&Transaction, i64)],
) -> Result<(), String> {
    if rewrites.is_empty() {
        return Ok(());
    }
    let txids: Vec<&str> = rewrites.iter().map(|(tx, _)| tx.txid.as_str()).collect();
    sqlx::query("DELETE FROM shielded_flows WHERE txid = ANY($1)")
        .bind(&txids)
        .execute(&mut **db_tx)
        .await
        .map_err(|e| format!("flow delete failed: {e}"))?;
    for (tx, block_time) in rewrites {
        let block_time = i32::try_from(*block_time)
            .map_err(|_| format!("block_time out of range for {}", tx.txid))?;
        for flow in ShieldedFlow::from_transaction(tx) {
            sqlx::query(
                "INSERT INTO shielded_flows (txid, block_height, block_time, flow_type, \
                 amount_zat, pool, transparent_addresses, transparent_value_zat) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(&flow.txid)
            .bind(flow.block_height as i32)
            .bind(block_time)
            .bind(&flow.flow_type)
            .bind(flow.amount)
            .bind(&flow.pool)
            .bind(&flow.transparent_addresses)
            .bind(flow.amount)
            .execute(&mut **db_tx)
            .await
            .map_err(|e| format!("flow insert failed for {}: {e}", flow.txid))?;
        }
    }
    Ok(())
}

fn print_sprout_report(report: &SproutRepairReport, dry_run: bool) {
    let verb = if dry_run { "would change" } else { "changed" };
    println!("────────────────────────────────────────────────────────────");
    println!("   Blocks scanned:            {}", report.blocks_scanned);
    println!("   Blocks with Sprout:        {}", report.sprout_blocks);
    println!("   Sprout transactions:       {}", report.sprout_txs);
    println!("   Transactions {verb}: {}", report.tx_changes);
    println!(
        "     fee changes:             {} (to NULL {}, from NULL {})",
        report.fee_changes, report.fee_to_null, report.fee_from_null
    );
    println!(
        "     fee delta old-new (zat): {} (known-to-known only)",
        report.fee_delta_zat
    );
    println!(
        "     Sprout balance changes:  {}",
        report.sprout_balance_changes
    );
    println!(
        "     JoinSplit count changes: {}",
        report.joinsplit_count_changes
    );
    println!(
        "   Block totals {verb}: {} (delta old-new zat {})",
        report.block_total_changes, report.block_total_delta_zat
    );
    println!("   Flow sets {verb}:    {}", report.flow_changes);
    println!(
        "   Anomalies: hash mismatches {}, missing rows {}, transparent mismatches {}, \
         non-Sprout fee mismatches {}",
        report.hash_mismatches,
        report.missing_rows,
        report.transparent_mismatches,
        report.other_fee_mismatches
    );
    for change in &report.tx_samples {
        println!(
            "   tx {} @{}: fee {} → {}, sprout {} → {}, joinsplits {} → {}",
            change.txid,
            change.height,
            fmt_opt(change.old_fee),
            fmt_opt(change.new_fee),
            fmt_opt(change.old_sprout),
            change.new_sprout,
            change
                .old_joinsplits
                .map_or_else(|| "NULL".to_string(), |v| v.to_string()),
            change.new_joinsplits,
        );
    }
    for (height, old, new) in &report.block_samples {
        println!(
            "   block {}: total_fees {} → {}",
            height,
            fmt_opt(*old),
            fmt_opt(*new)
        );
    }
    for anomaly in &report.anomaly_samples {
        println!("   ⚠️ {anomaly}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::TransparentInput;

    fn sprout_tx(
        txid: &str,
        height: u32,
        transparent_in: i64,
        transparent_out: i64,
        sprout: i64,
        sapling: i64,
    ) -> Transaction {
        let vin = if transparent_in > 0 {
            vec![TransparentInput {
                txid: "prev".to_string(),
                vout: 0,
                address: Some("t1prev".to_string()),
                value: Some(transparent_in),
                is_coinbase: false,
                script_sig: None,
            }]
        } else {
            Vec::new()
        };
        let mut tx = Transaction {
            txid: txid.to_string(),
            block_height: height,
            block_hash: "hash".to_string(),
            version: 4,
            lock_time: 0,
            expiry_height: None,
            size: 2000,
            vin_count: vin.len() as u16,
            vout_count: u16::from(transparent_out > 0),
            transparent_value_in: transparent_in,
            transparent_value_out: transparent_out,
            joinsplit_count: 1,
            sapling_spends: 0,
            sapling_outputs: u16::from(sapling != 0) * 2,
            orchard_actions: 0,
            ironwood_actions: 0,
            sapling_value_balance: sapling,
            orchard_value_balance: 0,
            ironwood_value_balance: 0,
            sprout_value_balance: sprout,
            orchard_anchor: None,
            ironwood_anchor: None,
            fee: None,
            vin,
            vout: Vec::new(),
        };
        tx.fee = tx.compute_fee().unwrap();
        tx
    }

    /// 9329552a…c047 at 500758: t→Sprout deposit, stored fee was the deposit.
    fn deposit() -> Transaction {
        sprout_tx(
            "9329552a2acb3d686989b467bdd98ad1ae9ef77a608d7a731e093498df69c047",
            500_758,
            4_625_281_439_411,
            0,
            -4_625_281_429_411,
            0,
        )
    }

    /// c0174bcd…7e1a at 3537885: Sprout→Sapling migration, stored fee was 0.
    fn migration() -> Transaction {
        sprout_tx(
            "c0174bcd6bbd798a88ed73d96b94e9089fd05d1c2d17b71a3a1979e5ecfc7e1a",
            3_537_885,
            0,
            0,
            909_361_122_623,
            -909_361_102_623,
        )
    }

    fn stored(fee: Option<i64>, sprout: Option<i64>, tx: &Transaction) -> StoredTx {
        StoredTx {
            fee,
            value_balance_sprout: sprout,
            joinsplit_count: Some(1),
            has_sprout: Some(true),
            total_input: Some(tx.transparent_value_in),
            total_output: Some(tx.transparent_value_out),
            block_time: 0,
        }
    }

    #[test]
    fn deposit_fee_is_ten_thousand_zatoshis() {
        assert_eq!(deposit().fee, Some(10_000));
    }

    #[test]
    fn migration_fee_is_twenty_thousand_zatoshis() {
        assert_eq!(migration().fee, Some(20_000));
    }

    #[test]
    fn repair_replaces_the_stored_deposit_as_fee() {
        let tx = deposit();
        let change = diff_transaction(&tx, &stored(Some(4_625_281_439_411), Some(0), &tx))
            .expect("wrong stored fee must be repaired");
        assert_eq!(change.old_fee, Some(4_625_281_439_411));
        assert_eq!(change.new_fee, Some(10_000));
        assert_eq!(change.new_sprout, -4_625_281_429_411);
        let mut report = SproutRepairReport::default();
        record_tx_change(&mut report, &change, 5);
        assert_eq!(report.fee_delta_zat, 4_625_281_429_411);
        assert!(!transparent_mismatch(&tx, &stored(None, None, &tx)));
    }

    #[test]
    fn repair_replaces_the_clamped_zero_migration_fee() {
        let tx = migration();
        let change = diff_transaction(&tx, &stored(Some(0), Some(0), &tx)).unwrap();
        assert_eq!((change.old_fee, change.new_fee), (Some(0), Some(20_000)));
        assert_eq!(change.new_sprout, 909_361_122_623);
    }

    #[test]
    fn already_repaired_rows_are_unchanged() {
        let tx = migration();
        assert!(diff_transaction(&tx, &stored(Some(20_000), Some(909_361_122_623), &tx)).is_none());
    }

    #[test]
    fn stale_sprout_flag_is_cleared() {
        let mut tx = migration();
        tx.joinsplit_count = 0;
        tx.sprout_value_balance = 0;
        tx.sapling_value_balance = 0;
        tx.fee = tx.compute_fee().unwrap();
        let change = diff_transaction(&tx, &stored(Some(0), Some(0), &tx)).unwrap();
        assert_eq!(change.new_joinsplits, 0);
    }

    #[test]
    fn deposit_is_a_sprout_shield_flow() {
        assert_eq!(
            computed_flows(&deposit()),
            vec![FlowKey {
                flow_type: "shield".to_string(),
                pool: "sprout".to_string(),
                amount: 4_625_281_429_411,
            }]
        );
    }

    #[test]
    fn pure_sprout_to_sapling_migration_has_no_boundary_flow() {
        assert!(computed_flows(&migration()).is_empty());
    }

    /// Exercises the real UPDATE/flow SQL against the CI schema, then rolls back.
    #[tokio::test]
    async fn repair_writes_hash_guarded_rows_and_flows() {
        let url = std::env::var("DATABASE_URL").expect("disposable DATABASE_URL required");
        let pool = sqlx::PgPool::connect(&url).await.unwrap();
        let mut db_tx = pool.begin().await.unwrap();
        let mut deposit = deposit();
        deposit.block_height = 99_000_001;
        deposit.block_hash = "repair-test-block".to_string();
        sqlx::query(
            "INSERT INTO blocks (height, hash, timestamp, total_fees) VALUES ($1, $2, 1, $3)",
        )
        .bind(99_000_001i64)
        .bind("repair-test-block")
        .bind(4_625_281_439_411i64)
        .execute(&mut *db_tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO transactions (txid, block_height, block_hash, block_time, fee, \
             total_input, total_output, has_sprout, sprout_joinsplit_count, value_balance_sprout) \
             VALUES ($1, $2, $3, 1, $4, $4, 0, FALSE, 0, 0)",
        )
        .bind(&deposit.txid)
        .bind(99_000_001i64)
        .bind("repair-test-block")
        .bind(4_625_281_439_411i64)
        .execute(&mut *db_tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO shielded_flows (txid, block_height, block_time, flow_type, amount_zat, pool) \
             VALUES ($1, 99000001, 1, 'deshield', 1, 'sapling')",
        )
        .bind(&deposit.txid)
        .execute(&mut *db_tx)
        .await
        .unwrap();

        write_tx_updates(&mut db_tx, &[&deposit]).await.unwrap();
        write_block_updates(
            &mut db_tx,
            &[
                (99_000_001, "repair-test-block".to_string(), Some(10_000)),
                (99_000_001, "some-other-hash".to_string(), None),
            ],
        )
        .await
        .unwrap();
        write_flow_rewrites(&mut db_tx, &[(&deposit, 1)])
            .await
            .unwrap();

        let row = sqlx::query(
            "SELECT fee, value_balance_sprout, sprout_joinsplit_count, has_sprout, has_shielded_data \
             FROM transactions WHERE txid = $1",
        )
        .bind(&deposit.txid)
        .fetch_one(&mut *db_tx)
        .await
        .unwrap();
        assert_eq!(row.get::<Option<i64>, _>("fee"), Some(10_000));
        assert_eq!(
            row.get::<Option<i64>, _>("value_balance_sprout"),
            Some(-4_625_281_429_411)
        );
        assert_eq!(row.get::<Option<i32>, _>("sprout_joinsplit_count"), Some(1));
        assert_eq!(row.get::<Option<bool>, _>("has_sprout"), Some(true));
        assert_eq!(row.get::<Option<bool>, _>("has_shielded_data"), Some(true));
        let total: Option<i64> =
            sqlx::query_scalar("SELECT total_fees FROM blocks WHERE height = 99000001")
                .fetch_one(&mut *db_tx)
                .await
                .unwrap();
        assert_eq!(total, Some(10_000), "the hash guard skips the other hash");
        let flows: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT flow_type, pool, amount_zat FROM shielded_flows WHERE txid = $1",
        )
        .bind(&deposit.txid)
        .fetch_all(&mut *db_tx)
        .await
        .unwrap();
        assert_eq!(
            flows,
            vec![(
                "shield".to_string(),
                "sprout".to_string(),
                4_625_281_429_411
            )]
        );
        db_tx.rollback().await.unwrap();
    }

    #[test]
    fn stored_fee_keeps_unknown_components_unknown() {
        assert_eq!(
            stored_fee(Some(100), Some(90), [Some(0), Some(0), Some(0), Some(0)]),
            Some(10)
        );
        assert_eq!(
            stored_fee(Some(100), Some(90), [None, Some(0), Some(0), Some(0)]),
            None
        );
        assert_eq!(
            stored_fee(Some(100), Some(190), [Some(0), Some(0), Some(0), Some(0)]),
            None
        );
    }
}
