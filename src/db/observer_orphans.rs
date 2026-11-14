//! Parsed archive of observer-only orphan blocks (migration 045).
//!
//! An observer-only orphan is a `captured_blocks` row whose hash is in neither
//! `blocks` nor `orphaned_blocks` while `blocks` holds a different hash at the
//! same height. Its raw bytes stay retained (the capture retention pass only
//! prunes blocks that became canonical), so this job parses them with the
//! indexer's own parser and stores block, transaction, input and output rows in
//! the `observer_orphan_*` tables, which mirror the `orphaned_*` column shapes.
//!
//! These rows never enter `orphaned_*`, fork events or rate calculations: those
//! tables mean "our node reorged this block". Merging the two needs a separate
//! release decision. This job never writes canonical chain or accounting tables.

use crate::config::Network;
use crate::db::postgres::{block_total_fees, miner_address_candidate, PostgresWriter};
use crate::db::ParsedBlockHeader;
use crate::indexer::TransactionParser;
use crate::models::Transaction;
use serde::Serialize;
use sqlx::{PgPool, Postgres, QueryBuilder};
use std::collections::{HashMap, HashSet};
use zakura_chain::block::Block;
use zakura_chain::serialization::{ZcashDeserialize, ZcashSerialize};

/// Bump when the parsed shape changes; older archives are then rebuilt.
pub const ARCHIVE_VERSION: i16 = 1;

/// Captures that are observer-only orphans and still need (re)archiving.
/// Mirrors the explorer's `OBSERVER_ONLY_SQL`, plus retained raw bytes.
const CANDIDATES_SQL: &str = r#"
SELECT c.hash, c.height, r.hash AS canonical_hash
FROM captured_blocks c
JOIN blocks r ON r.height = c.height
WHERE c.network = $1
  AND r.hash <> c.hash
  AND c.raw_block IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM blocks canonical WHERE canonical.hash = c.hash)
  AND NOT EXISTS (SELECT 1 FROM orphaned_blocks ob WHERE ob.hash = c.hash)
  AND ($2 OR NOT EXISTS (
        SELECT 1 FROM observer_orphan_blocks a
        WHERE a.hash = c.hash AND a.archive_version >= $3))
ORDER BY c.height, c.hash
LIMIT $4"#;

/// Archives whose block is no longer an observer-only orphan: it became
/// canonical, or our node indexed and reorged it (the node archive wins).
const STALE_WHERE: &str = "EXISTS (SELECT 1 FROM blocks b WHERE b.hash = a.hash) \
    OR EXISTS (SELECT 1 FROM orphaned_blocks ob WHERE ob.hash = a.hash)";

/// Prevout lookup across every place a spent output can already be recorded.
/// A txid commits to its transparent outputs, so any copy has the same values.
const PREVOUTS_SQL: &str = r#"
SELECT r.txid, r.vout, o.value, o.address
FROM UNNEST($1::text[], $2::int[]) r(txid, vout)
CROSS JOIN LATERAL (
    SELECT value, address FROM transaction_outputs
     WHERE txid = r.txid AND vout_index = r.vout AND value IS NOT NULL
    UNION ALL
    SELECT value, address FROM observer_orphan_transaction_outputs
     WHERE txid = r.txid AND vout_index = r.vout
    UNION ALL
    SELECT value, address FROM orphaned_transaction_outputs
     WHERE txid = r.txid AND vout_index = r.vout AND value IS NOT NULL
    LIMIT 1
) o"#;

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct ArchiveSummary {
    pub dry_run: bool,
    pub candidates: u64,
    pub archived: u64,
    pub failed: u64,
    pub transactions: u64,
    pub inputs: u64,
    pub outputs: u64,
    pub unresolved_inputs: u64,
    pub stale_archives: u64,
    pub canonical_hash_updates: u64,
}

/// A raw captured block decoded into archive rows.
#[derive(Debug, Clone)]
pub struct ParsedOrphan {
    pub hash: String,
    pub height: u32,
    pub size: usize,
    pub header: ParsedBlockHeader,
    pub transactions: Vec<Transaction>,
}

/// Decode and verify a captured block: whole input consumed, hash and coinbase
/// height equal to what the capture recorded.
pub fn parse_captured_block(
    raw: &[u8],
    expected_hash: &str,
    expected_height: u32,
    network: Network,
) -> Result<ParsedOrphan, String> {
    let mut reader = std::io::Cursor::new(raw);
    let block = Block::zcash_deserialize(&mut reader)
        .map_err(|e| format!("block {expected_hash} decoding failed: {e:?}"))?;
    if reader.position() != raw.len() as u64 {
        return Err(format!("block {expected_hash} has trailing bytes"));
    }
    let hash = block.hash().to_string();
    if hash != expected_hash {
        return Err(format!(
            "captured hash mismatch: expected {expected_hash}, decoded {hash}"
        ));
    }
    let height = block
        .coinbase_height()
        .ok_or_else(|| format!("block {hash} has no coinbase height"))?
        .0;
    if height != expected_height {
        return Err(format!(
            "block {hash} height mismatch: captured {expected_height}, decoded {height}"
        ));
    }
    let mut header = ParsedBlockHeader::from_chain_header(&block.header);
    // Post-Heartwood headers carry a commitment hash, not the Sapling root, and
    // the node cannot report final roots for a block it never adopted.
    header.final_sapling_root = String::new();
    header.final_orchard_root = None;
    header.final_ironwood_root = None;
    let mut transactions = Vec::with_capacity(block.transactions.len());
    for transaction in block.transactions {
        let size = transaction.zcash_serialized_size();
        let transaction =
            std::sync::Arc::try_unwrap(transaction).unwrap_or_else(|shared| (*shared).clone());
        transactions.push(TransactionParser::from_chain_tx(
            transaction,
            height,
            &hash,
            size,
            network,
        )?);
    }
    Ok(ParsedOrphan {
        hash,
        height,
        size: raw.len(),
        header,
        transactions,
    })
}

/// Transparent prevouts referenced by `transactions` that the block itself
/// does not create, sorted and deduplicated.
pub fn external_prevouts(transactions: &[Transaction]) -> Vec<(String, u32)> {
    let created: HashSet<(&str, u32)> = transactions
        .iter()
        .flat_map(|tx| tx.vout.iter().map(move |o| (tx.txid.as_str(), o.n)))
        .collect();
    let mut references: Vec<(String, u32)> = transactions
        .iter()
        .flat_map(|tx| tx.vin.iter())
        .filter(|input| !input.is_coinbase && !created.contains(&(input.txid.as_str(), input.vout)))
        .map(|input| (input.txid.clone(), input.vout))
        .collect();
    references.sort_unstable();
    references.dedup();
    references
}

/// Per-transaction totals once prevouts are applied. `None` means unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTotals {
    pub total_input: Option<i64>,
    pub fee: Option<i64>,
}

/// Fill input values/addresses from the block's own outputs, then `known`.
/// Unresolved inputs keep `value = None`; their transaction's total input and
/// fee become unknown rather than a partial sum. Returns totals per
/// transaction (same order) and the number of unresolved inputs.
pub fn resolve_inputs(
    transactions: &mut [Transaction],
    known: &HashMap<(String, u32), (i64, Option<String>)>,
) -> Result<(Vec<ResolvedTotals>, u64), String> {
    let created: HashMap<(String, u32), (i64, Option<String>)> = transactions
        .iter()
        .flat_map(|tx| {
            tx.vout
                .iter()
                .map(move |o| ((tx.txid.clone(), o.n), (o.value, o.address.clone())))
        })
        .collect();
    let mut totals = Vec::with_capacity(transactions.len());
    let mut unresolved = 0u64;
    for tx in transactions.iter_mut() {
        if tx.is_coinbase() {
            tx.fee = None;
            totals.push(ResolvedTotals {
                total_input: Some(0),
                fee: None,
            });
            continue;
        }
        let mut sum = Some(0i64);
        for input in tx.vin.iter_mut().filter(|input| !input.is_coinbase) {
            let key = (input.txid.clone(), input.vout);
            match created.get(&key).or_else(|| known.get(&key)) {
                Some((value, address)) => {
                    input.value = Some(*value);
                    input.address = address.clone();
                    sum = match sum {
                        Some(total) => Some(total.checked_add(*value).ok_or_else(|| {
                            format!("transparent input overflow for {}", tx.txid)
                        })?),
                        None => None,
                    };
                }
                None => {
                    input.value = None;
                    input.address = None;
                    unresolved += 1;
                    sum = None;
                }
            }
        }
        let fee = match sum {
            Some(total) => {
                tx.transparent_value_in = total;
                tx.compute_fee()?
            }
            None => None,
        };
        tx.fee = fee;
        totals.push(ResolvedTotals {
            total_input: sum,
            fee,
        });
    }
    Ok((totals, unresolved))
}

/// The `to_jsonb(blocks)` shape that node-reorg archives keep in
/// `block_metadata`, built from the parsed block. Unknown values are null.
pub fn block_metadata(
    orphan: &ParsedOrphan,
    miner_address: Option<&str>,
    coinbase_hex: Option<&str>,
    total_fees: Option<i64>,
) -> serde_json::Value {
    let h = &orphan.header;
    serde_json::json!({
        "height": orphan.height,
        "hash": orphan.hash,
        "timestamp": h.time,
        "transaction_count": orphan.transactions.len(),
        "total_fees": total_fees,
        "version": h.version,
        "merkle_root": h.merkle_root,
        "final_sapling_root": serde_json::Value::Null,
        "final_orchard_root": serde_json::Value::Null,
        "final_ironwood_root": serde_json::Value::Null,
        "bits": h.bits,
        "nonce": h.nonce,
        "solution": h.solution,
        "difficulty": h.difficulty,
        "previous_block_hash": h.previous_block_hash,
        "size": orphan.size,
        "miner_address": miner_address,
        "coinbase_hex": coinbase_hex,
        "archive_source": "captured_blocks",
    })
}

fn coinbase_facts(transactions: &[Transaction]) -> (Option<String>, Option<String>) {
    let Some(coinbase) = transactions
        .first()
        .filter(|tx| tx.vin.first().is_some_and(|v| v.is_coinbase))
    else {
        return (None, None);
    };
    let miner = coinbase
        .vout
        .first()
        .and_then(|out| miner_address_candidate(out.address.as_deref()));
    let script = coinbase.vin.first().and_then(|v| v.script_sig.clone());
    (miner, script)
}

async fn known_prevouts(
    pool: &PgPool,
    references: &[(String, u32)],
) -> Result<HashMap<(String, u32), (i64, Option<String>)>, sqlx::Error> {
    if references.is_empty() {
        return Ok(HashMap::new());
    }
    let txids: Vec<&str> = references.iter().map(|(t, _)| t.as_str()).collect();
    let vouts: Vec<i32> = references.iter().map(|(_, v)| *v as i32).collect();
    let rows: Vec<(String, i32, i64, Option<String>)> = sqlx::query_as(PREVOUTS_SQL)
        .bind(&txids)
        .bind(&vouts)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(txid, vout, value, address)| ((txid, vout as u32), (value, address)))
        .collect())
}

struct Prepared {
    orphan: ParsedOrphan,
    canonical_hash: String,
    totals: Vec<ResolvedTotals>,
    unresolved: u64,
}

async fn prepare(
    pool: &PgPool,
    hash: &str,
    height: u32,
    canonical_hash: String,
    network: Network,
) -> Result<Prepared, String> {
    let raw: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT raw_block FROM captured_blocks WHERE hash = $1")
            .bind(hash)
            .fetch_optional(pool)
            .await
            .map_err(|e| format!("raw block read failed: {e}"))?
            .flatten();
    let raw = raw.ok_or_else(|| format!("raw block {hash} no longer retained"))?;
    let mut orphan = parse_captured_block(&raw, hash, height, network)?;
    let references = external_prevouts(&orphan.transactions);
    let known = known_prevouts(pool, &references)
        .await
        .map_err(|e| format!("prevout lookup failed: {e}"))?;
    let (totals, unresolved) = resolve_inputs(&mut orphan.transactions, &known)?;
    Ok(Prepared {
        orphan,
        canonical_hash,
        totals,
        unresolved,
    })
}

/// Atomically replace one block's archive. Takes the shared block-write lock
/// so a concurrent node reorg (exclusive lock) cannot interleave, and re-checks
/// observer-only status inside the transaction. Returns false when skipped.
async fn write_archive(pool: &PgPool, p: &Prepared) -> Result<bool, sqlx::Error> {
    let o = &p.orphan;
    let mut db = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock_shared($1)")
        .bind(PostgresWriter::BLOCK_WRITE_LOCK)
        .execute(&mut *db)
        .await?;
    let still_orphan: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS (SELECT 1 FROM blocks WHERE hash = $1) \
           AND NOT EXISTS (SELECT 1 FROM orphaned_blocks WHERE hash = $1) \
           AND EXISTS (SELECT 1 FROM blocks WHERE height = $2 AND hash <> $1)",
    )
    .bind(&o.hash)
    .bind(o.height as i64)
    .fetch_one(&mut *db)
    .await?;
    if !still_orphan {
        db.rollback().await?;
        return Ok(false);
    }
    sqlx::query("DELETE FROM observer_orphan_blocks WHERE hash = $1")
        .bind(&o.hash)
        .execute(&mut *db)
        .await?;

    let (miner, coinbase_hex) = coinbase_facts(&o.transactions);
    let total_fees =
        block_total_fees(&o.transactions).map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    let metadata = block_metadata(o, miner.as_deref(), coinbase_hex.as_deref(), total_fees);
    let size = i32::try_from(o.size).map_err(|_| sqlx::Error::Protocol("size".into()))?;
    sqlx::query(
        r#"INSERT INTO observer_orphan_blocks (
               hash, height, canonical_hash, "timestamp", transaction_count, size,
               difficulty, miner_address, previous_block_hash, coinbase_hex,
               block_metadata, archive_version, unresolved_inputs)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13)"#,
    )
    .bind(&o.hash)
    .bind(o.height as i64)
    .bind(&p.canonical_hash)
    .bind(o.header.time as i64)
    .bind(o.transactions.len() as i32)
    .bind(size)
    .bind(o.header.difficulty.to_string())
    .bind(&miner)
    .bind(&o.header.previous_block_hash)
    .bind(&coinbase_hex)
    .bind(metadata.to_string())
    .bind(ARCHIVE_VERSION)
    .bind(p.unresolved as i32)
    .execute(&mut *db)
    .await?;

    for (chunk_index, chunk) in o.transactions.chunks(1_000).enumerate() {
        let offset = chunk_index * 1_000;
        let mut q = QueryBuilder::<Postgres>::new(
            r#"INSERT INTO observer_orphan_transactions (
                txid, block_height, block_hash, "timestamp", tx_index, version, locktime,
                expiry_height, size, fee, is_coinbase, vin_count, vout_count,
                total_input, total_output, has_sapling, has_orchard, has_sprout,
                has_ironwood, has_shielded_data, sapling_spend_count, sapling_output_count,
                orchard_actions, ironwood_actions, sprout_joinsplit_count, value_balance,
                value_balance_sapling, value_balance_orchard, value_balance_ironwood,
                value_balance_sprout, orchard_anchor, ironwood_anchor, first_indexed_at) "#,
        );
        q.push_values(chunk.iter().enumerate(), |mut row, (i, tx)| {
            let index = offset + i;
            let has_sapling = tx.sapling_spends > 0 || tx.sapling_outputs > 0;
            let has_orchard = tx.orchard_actions > 0;
            let has_ironwood = tx.ironwood_actions > 0;
            let has_sprout = tx.joinsplit_count > 0;
            // Same definition as canonical transactions.value_balance.
            let value_balance =
                tx.sapling_value_balance + tx.orchard_value_balance + tx.ironwood_value_balance;
            row.push_bind(&tx.txid)
                .push_bind(o.height as i64)
                .push_bind(&o.hash)
                .push_bind(o.header.time as i64)
                .push_bind(index as i32)
                .push_bind(tx.version)
                .push_bind(tx.lock_time as i64)
                .push_bind(tx.expiry_height.map(|h| h as i32))
                .push_bind(tx.size as i32)
                .push_bind(p.totals[index].fee)
                .push_bind(tx.is_coinbase())
                .push_bind(tx.vin_count as i32)
                .push_bind(tx.vout_count as i32)
                .push_bind(p.totals[index].total_input)
                .push_bind(tx.transparent_value_out)
                .push_bind(has_sapling)
                .push_bind(has_orchard)
                .push_bind(has_sprout)
                .push_bind(has_ironwood)
                .push_bind(has_sapling || has_orchard || has_ironwood || has_sprout)
                .push_bind(tx.sapling_spends as i32)
                .push_bind(tx.sapling_outputs as i32)
                .push_bind(tx.orchard_actions as i32)
                .push_bind(tx.ironwood_actions as i32)
                .push_bind(tx.joinsplit_count as i32)
                .push_bind(value_balance)
                .push_bind(tx.sapling_value_balance)
                .push_bind(tx.orchard_value_balance)
                .push_bind(tx.ironwood_value_balance)
                .push_bind(tx.sprout_value_balance)
                .push_bind(&tx.orchard_anchor)
                .push_bind(&tx.ironwood_anchor)
                .push_unseparated(", now()");
        });
        q.build().execute(&mut *db).await?;
    }

    // Same row semantics as canonical transaction_inputs: coinbase inputs are
    // not rows; vout_index is the input's position in the transaction.
    let inputs: Vec<_> = o
        .transactions
        .iter()
        .flat_map(|tx| {
            tx.vin
                .iter()
                .enumerate()
                .filter(|(_, input)| !input.is_coinbase)
                .map(move |(index, input)| (&tx.txid, index, input))
        })
        .collect();
    for chunk in inputs.chunks(5_000) {
        let mut q = QueryBuilder::<Postgres>::new(
            "INSERT INTO observer_orphan_transaction_inputs \
             (txid, block_hash, vout_index, prev_txid, prev_vout, address, value) ",
        );
        q.push_values(chunk, |mut row, (txid, index, input)| {
            row.push_bind(*txid)
                .push_bind(&o.hash)
                .push_bind(*index as i32)
                .push_bind(&input.txid)
                .push_bind(input.vout as i32)
                .push_bind(&input.address)
                .push_bind(input.value);
        });
        q.build().execute(&mut *db).await?;
    }
    let outputs: Vec<_> = o
        .transactions
        .iter()
        .flat_map(|tx| tx.vout.iter().map(move |output| (&tx.txid, output)))
        .collect();
    for chunk in outputs.chunks(5_000) {
        let mut q = QueryBuilder::<Postgres>::new(
            "INSERT INTO observer_orphan_transaction_outputs \
             (txid, block_hash, vout_index, value, address, script_type) ",
        );
        q.push_values(chunk, |mut row, (txid, output)| {
            row.push_bind(*txid)
                .push_bind(&o.hash)
                .push_bind(output.n as i32)
                .push_bind(output.value)
                .push_bind(&output.address)
                .push_bind(&output.script_type);
        });
        q.build().execute(&mut *db).await?;
    }
    db.commit().await?;
    Ok(true)
}

/// Options for one archive pass.
#[derive(Debug, Clone, Copy)]
pub struct ArchiveOptions {
    pub dry_run: bool,
    pub limit: u32,
    /// Rebuild archives that already exist at the current version.
    pub rearchive: bool,
}

/// One idempotent pass: drop stale archives, refresh winning hashes, then
/// parse and archive up to `limit` candidates in height order. A dry run
/// parses and resolves every candidate but writes nothing.
pub async fn archive_pass(
    pool: &PgPool,
    network: Network,
    options: ArchiveOptions,
) -> Result<ArchiveSummary, String> {
    let network_name = match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
    };
    let mut summary = ArchiveSummary {
        dry_run: options.dry_run,
        ..ArchiveSummary::default()
    };
    let db = |e: sqlx::Error| format!("observer orphan archive query failed: {e}");
    if options.dry_run {
        summary.stale_archives = sqlx::query_scalar::<_, i64>(&format!(
            "SELECT count(*) FROM observer_orphan_blocks a WHERE {STALE_WHERE}"
        ))
        .fetch_one(pool)
        .await
        .map_err(db)? as u64;
    } else {
        let mut tx = pool.begin().await.map_err(db)?;
        sqlx::query("SELECT pg_advisory_xact_lock_shared($1)")
            .bind(PostgresWriter::BLOCK_WRITE_LOCK)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        summary.stale_archives = sqlx::query(&format!(
            "DELETE FROM observer_orphan_blocks a WHERE {STALE_WHERE}"
        ))
        .execute(&mut *tx)
        .await
        .map_err(db)?
        .rows_affected();
        summary.canonical_hash_updates = sqlx::query(
            "UPDATE observer_orphan_blocks a SET canonical_hash = b.hash FROM blocks b \
             WHERE b.height = a.height AND b.hash <> a.hash \
               AND a.canonical_hash IS DISTINCT FROM b.hash",
        )
        .execute(&mut *tx)
        .await
        .map_err(db)?
        .rows_affected();
        tx.commit().await.map_err(db)?;
    }

    let candidates: Vec<(String, i64, String)> = sqlx::query_as(CANDIDATES_SQL)
        .bind(network_name)
        .bind(options.rearchive)
        .bind(ARCHIVE_VERSION)
        .bind(options.limit as i64)
        .fetch_all(pool)
        .await
        .map_err(db)?;
    summary.candidates = candidates.len() as u64;
    for (hash, height, canonical_hash) in candidates {
        let Ok(height) = u32::try_from(height) else {
            summary.failed += 1;
            continue;
        };
        let prepared = match prepare(pool, &hash, height, canonical_hash, network).await {
            Ok(prepared) => prepared,
            Err(error) => {
                tracing::warn!(%hash, height, %error, "observer orphan not archived");
                summary.failed += 1;
                continue;
            }
        };
        let txs = &prepared.orphan.transactions;
        let counts = (
            txs.len() as u64,
            txs.iter()
                .flat_map(|t| &t.vin)
                .filter(|i| !i.is_coinbase)
                .count() as u64,
            txs.iter().map(|t| t.vout.len() as u64).sum::<u64>(),
        );
        if !options.dry_run {
            match write_archive(pool, &prepared).await {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => {
                    tracing::warn!(%hash, height, %error, "observer orphan archive write failed");
                    summary.failed += 1;
                    continue;
                }
            }
        }
        summary.archived += 1;
        summary.transactions += counts.0;
        summary.inputs += counts.1;
        summary.outputs += counts.2;
        summary.unresolved_inputs += prepared.unresolved;
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures() -> Vec<serde_json::Value> {
        serde_json::from_str(include_str!("../../tests/fixtures/parser-blocks.json")).unwrap()
    }

    fn fixture(height: u64) -> (Vec<u8>, String) {
        let row = fixtures()
            .into_iter()
            .find(|r| r["network"] == "mainnet" && r["height"] == height)
            .unwrap();
        (
            hex::decode(row["hex"].as_str().unwrap()).unwrap(),
            row["hash"].as_str().unwrap().to_owned(),
        )
    }

    #[test]
    fn parses_and_verifies_captured_blocks() {
        let (raw, hash) = fixture(3_428_142);
        let parsed = parse_captured_block(&raw, &hash, 3_428_142, Network::Mainnet).unwrap();
        assert_eq!(parsed.size, raw.len());
        assert!(parsed.transactions[0].is_coinbase());
        assert!(parsed.header.final_orchard_root.is_none());
        assert!(parsed.header.final_sapling_root.is_empty());
        assert!(parse_captured_block(&raw, &hash, 3_428_141, Network::Mainnet).is_err());
        assert!(parse_captured_block(&raw, &"0".repeat(64), 3_428_142, Network::Mainnet).is_err());
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(parse_captured_block(&trailing, &hash, 3_428_142, Network::Mainnet).is_err());
    }

    #[test]
    fn unresolved_prevouts_stay_unknown_and_resolved_fees_are_exact() {
        let (raw, hash) = fixture(3_428_142);
        let mut parsed = parse_captured_block(&raw, &hash, 3_428_142, Network::Mainnet).unwrap();
        let references = external_prevouts(&parsed.transactions);
        assert!(
            !references.is_empty(),
            "fixture must spend transparent outputs"
        );

        let mut none = parsed.transactions.clone();
        let (totals, unresolved) = resolve_inputs(&mut none, &HashMap::new()).unwrap();
        assert_eq!(unresolved as usize, {
            let created: HashSet<_> = none
                .iter()
                .flat_map(|t| t.vout.iter().map(move |o| (t.txid.clone(), o.n)))
                .collect();
            none.iter()
                .flat_map(|t| &t.vin)
                .filter(|i| !i.is_coinbase && !created.contains(&(i.txid.clone(), i.vout)))
                .count()
        });
        assert_eq!(totals[0].fee, None);
        for (tx, total) in none.iter().zip(&totals).skip(1) {
            if tx.vin.iter().any(|i| i.value.is_none()) {
                assert_eq!(
                    total,
                    &ResolvedTotals {
                        total_input: None,
                        fee: None
                    }
                );
            }
        }
        assert_eq!(block_total_fees(&none).unwrap(), None);

        // Every external prevout known with a large value: every fee is exact.
        let known: HashMap<_, _> = references
            .iter()
            .map(|r| (r.clone(), (5_000_000_000i64, Some("t1known".to_owned()))))
            .collect();
        let (totals, unresolved) = resolve_inputs(&mut parsed.transactions, &known).unwrap();
        assert_eq!(unresolved, 0);
        for (tx, total) in parsed.transactions.iter().zip(&totals).skip(1) {
            let expected_in: i64 = tx.vin.iter().map(|i| i.value.unwrap()).sum();
            assert_eq!(total.total_input, Some(expected_in));
            let shielded = tx.shielded_value_balance().unwrap();
            let fee = expected_in + shielded - tx.transparent_value_out;
            assert_eq!(total.fee, (fee >= 0).then_some(fee));
        }
    }

    #[test]
    fn metadata_matches_block_row_keys_with_unknown_roots() {
        let (raw, hash) = fixture(3_364_600);
        let parsed = parse_captured_block(&raw, &hash, 3_364_600, Network::Mainnet).unwrap();
        let (miner, coinbase) = coinbase_facts(&parsed.transactions);
        let metadata = block_metadata(&parsed, miner.as_deref(), coinbase.as_deref(), None);
        assert_eq!(metadata["hash"], hash);
        assert_eq!(metadata["size"], raw.len());
        assert!(metadata["final_sapling_root"].is_null());
        assert!(metadata["total_fees"].is_null());
        assert_eq!(metadata["coinbase_hex"].as_str(), coinbase.as_deref());
        for key in [
            "version",
            "merkle_root",
            "bits",
            "nonce",
            "solution",
            "previous_block_hash",
        ] {
            assert!(!metadata[key].is_null(), "{key}");
        }
    }

    #[test]
    fn candidate_rule_matches_explorer_observer_only_definition() {
        for clause in [
            "JOIN blocks r ON r.height = c.height",
            "r.hash <> c.hash",
            "NOT EXISTS (SELECT 1 FROM blocks canonical WHERE canonical.hash = c.hash)",
            "NOT EXISTS (SELECT 1 FROM orphaned_blocks ob WHERE ob.hash = c.hash)",
        ] {
            assert!(CANDIDATES_SQL.contains(clause), "{clause}");
        }
        // The archive never writes node-reorg or canonical tables.
        let source = include_str!("observer_orphans.rs");
        let code = source.split("#[cfg(test)]").next().unwrap();
        for table in [
            "INTO orphaned_",
            "INTO blocks",
            "INTO transactions",
            "INTO transaction_",
            "INTO address",
            "UPDATE blocks",
            "UPDATE transaction",
            "INTO fork_events",
        ] {
            assert!(!code.contains(table), "{table}");
        }
    }
}
