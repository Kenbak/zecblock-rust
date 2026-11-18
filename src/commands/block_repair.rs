//! Repairs for block-level columns that earlier releases wrote incorrectly.
//!
//! * `backfill-block-roots` replaces the stored note commitment tree roots
//!   with the node's answer. Blocks written by the RocksDB backfill carried
//!   the header's commitment field as the "Sapling root" (wrong since
//!   Heartwood) and no Orchard root, and no block had an Ironwood root.
//! * `repair-block-sizes` recomputes `blocks.size`, which omitted the
//!   CompactSize transaction count.
//!
//! Both are idempotent, bounded per window, and safe beside the live writer:
//! every write is guarded by height and hash.

use crate::config::Config;
use crate::db::postgres::StoredBlockRoots;
use crate::db::rpc::{normalize_root_hex, BlockInfo, BlockRoots};
use crate::db::{PostgresWriter, ZebraRpc};
use std::time::Instant;

/// Blocks this close to the indexed tip are left to the live writer, which
/// already stores node-reported roots and may still reorganize them.
const TIP_MARGIN_BLOCKS: u32 = 100;
const ROOTS_CHECKPOINT_KEY: &str = "block_roots_backfill_height";

/// `getblock` carries the Sapling and Orchard roots. The slower
/// `z_gettreestate` is only needed for an Ironwood root we do not have yet.
fn needs_tree_state(stored: &StoredBlockRoots, block: &BlockInfo) -> bool {
    block.has_ironwood_tree() && stored.final_ironwood_root.is_none()
}

/// The roots to store for one block, from the node's answers. Refuses any
/// answer that is for another block or that disagrees with itself, so a
/// wrong value is never written over a stored one.
fn reconcile_roots(
    stored: &StoredBlockRoots,
    block: BlockInfo,
    tree_state: Option<BlockRoots>,
) -> Result<StoredBlockRoots, String> {
    let height = stored.height;
    if !block.hash.eq_ignore_ascii_case(&stored.hash) {
        return Err(format!(
            "node returned block {} for indexed block {} at height {height}",
            block.hash, stored.hash
        ));
    }
    let sapling = normalize_root_hex(block.finalsaplingroot)
        .map_err(|e| format!("Sapling root at {height}: {e}"))?
        .ok_or_else(|| format!("node reported no Sapling root field at {height}"))?;
    let orchard = normalize_root_hex(block.finalorchardroot)
        .map_err(|e| format!("Orchard root at {height}: {e}"))?;

    let ironwood = match tree_state {
        None => stored.final_ironwood_root.clone(),
        Some(roots) => {
            if !roots.hash.eq_ignore_ascii_case(&stored.hash) {
                return Err(format!("tree state at {height} is for another block"));
            }
            if roots.sapling.as_deref().is_some_and(|root| root != sapling)
                || roots.orchard != orchard
            {
                return Err(format!(
                    "getblock and z_gettreestate disagree on the roots at {height}"
                ));
            }
            roots
                .ironwood
                .or_else(|| stored.final_ironwood_root.clone())
        }
    };

    Ok(StoredBlockRoots {
        height,
        hash: stored.hash.clone(),
        final_sapling_root: Some(sapling),
        final_orchard_root: orchard,
        final_ironwood_root: ironwood,
    })
}

fn require_database(config: &Config) -> Result<(), String> {
    if config.database_url.is_empty() {
        return Err(
            "DATABASE_URL not configured. Set it in .env or pass --database-url".to_string(),
        );
    }
    Ok(())
}

/// Last height a repair may touch by default: the indexed tip less a margin.
async fn default_end(postgres: &PostgresWriter) -> Result<u32, String> {
    let tip = postgres
        .get_checkpoint()
        .await
        .map_err(|e| format!("Checkpoint read error: {e}"))?
        .ok_or("the indexer has no indexed tip yet")?;
    Ok(tip.saturating_sub(TIP_MARGIN_BLOCKS))
}

/// Replace stored block roots with the node's, and fill missing Ironwood roots.
pub(crate) async fn run_backfill_block_roots(
    config: &Config,
    from: Option<u32>,
    to: Option<u32>,
    batch: u32,
    dry_run: bool,
) -> Result<(), String> {
    require_database(config)?;
    if batch == 0 {
        return Err("--batch must be at least 1".to_string());
    }
    let rpc = ZebraRpc::from_env().map_err(|e| format!("RPC not configured: {e}"))?;
    let postgres = PostgresWriter::connect(&config.database_url)
        .await
        .map_err(|e| format!("PostgreSQL error: {e}"))?;

    let end = match to {
        Some(height) => height,
        None => default_end(&postgres).await?,
    };
    // An explicit --from is a targeted run and leaves the resume point alone.
    let resumable = from.is_none() && !dry_run;
    let start = match from {
        Some(height) => height,
        None => postgres
            .get_checkpoint_key(ROOTS_CHECKPOINT_KEY)
            .await
            .map_err(|e| format!("Checkpoint read error: {e}"))?
            .map_or(0, |height| height.saturating_add(1)),
    };
    if start > end {
        println!("✅ Block roots already processed through {end}.");
        return Ok(());
    }

    println!("🔧 Block root backfill: heights {start}–{end} (batch={batch}, dry_run={dry_run})");
    let started = Instant::now();
    let (mut seen, mut changed, mut tree_states) = (0u64, 0u64, 0u64);
    let mut window_start = start;

    loop {
        let window_end = window_start.saturating_add(batch - 1).min(end);
        let rows = postgres
            .get_block_roots_in_range(window_start, window_end)
            .await
            .map_err(|e| format!("Block read error: {e}"))?;

        let mut updates = Vec::new();
        for stored in &rows {
            let block = rpc
                .get_block(&stored.hash)
                .await
                .map_err(|e| format!("getblock failed at {}: {e}", stored.height))?;
            let tree_state = if needs_tree_state(stored, &block) {
                tree_states += 1;
                Some(
                    rpc.get_block_roots(&stored.hash)
                        .await
                        .map_err(|e| format!("z_gettreestate failed at {}: {e}", stored.height))?,
                )
            } else {
                None
            };
            let wanted = reconcile_roots(stored, block, tree_state)?;
            if wanted != *stored {
                updates.push(wanted);
            }
        }
        seen += rows.len() as u64;
        changed += updates.len() as u64;

        if !dry_run {
            postgres
                .update_block_roots(&updates)
                .await
                .map_err(|e| format!("Block root write error: {e}"))?;
            if resumable {
                postgres
                    .update_checkpoint(ROOTS_CHECKPOINT_KEY, &window_end.to_string())
                    .await
                    .map_err(|e| format!("Checkpoint write error: {e}"))?;
            }
        }

        let rate = seen as f64 / started.elapsed().as_secs_f64().max(f64::EPSILON);
        println!(
            "📦 through {window_end} | {seen} blocks | {changed} need new roots | {tree_states} tree states | {rate:.0} blk/s"
        );
        if window_end >= end {
            break;
        }
        window_start = window_end + 1;
    }

    println!(
        "✅ Block root backfill {}: {seen} blocks checked, {changed} {} in {:.1}s",
        if dry_run { "dry run" } else { "complete" },
        if dry_run { "would change" } else { "changed" },
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// Recompute `blocks.size` from stored transaction sizes.
pub(crate) async fn run_repair_block_sizes(
    config: &Config,
    from: u32,
    to: Option<u32>,
    batch: u32,
    dry_run: bool,
) -> Result<(), String> {
    require_database(config)?;
    if batch == 0 {
        return Err("--batch must be at least 1".to_string());
    }
    let postgres = PostgresWriter::connect(&config.database_url)
        .await
        .map_err(|e| format!("PostgreSQL error: {e}"))?;
    let end = match to {
        Some(height) => height,
        None => default_end(&postgres).await?,
    };
    if from > end {
        println!("✅ Nothing to repair: --from {from} is above {end}.");
        return Ok(());
    }

    println!("🔧 Block size repair: heights {from}–{end} (batch={batch}, dry_run={dry_run})");
    let started = Instant::now();
    let (mut incorrect, mut incomplete) = (0u64, 0u64);
    let mut window_start = from;
    loop {
        let window_end = window_start.saturating_add(batch - 1).min(end);
        let window = postgres
            .repair_block_sizes(window_start, window_end, dry_run)
            .await
            .map_err(|e| format!("Block size repair error at {window_start}: {e}"))?;
        incorrect += window.incorrect;
        incomplete += window.incomplete;
        println!(
            "📦 through {window_end} | {incorrect} sizes {} | {incomplete} skipped (incomplete transactions)",
            if dry_run { "to correct" } else { "corrected" }
        );
        if window_end >= end {
            break;
        }
        window_start = window_end + 1;
    }

    println!(
        "✅ Block size repair {} in {:.1}s",
        if dry_run {
            "dry run finished"
        } else {
            "complete"
        },
        started.elapsed().as_secs_f64()
    );
    if incomplete > 0 {
        return Err(format!(
            "{incomplete} blocks have incomplete transaction rows and were not changed"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(ironwood: Option<&str>) -> StoredBlockRoots {
        StoredBlockRoots {
            height: 2_000_000,
            hash: "aa".repeat(32),
            // What the RocksDB backfill used to write: the header commitment.
            final_sapling_root: Some("e1".repeat(32)),
            final_orchard_root: None,
            final_ironwood_root: ironwood.map(str::to_owned),
        }
    }

    fn block(json: serde_json::Value) -> BlockInfo {
        serde_json::from_value(json).expect("valid getblock fixture")
    }

    fn node_block(with_ironwood: bool) -> BlockInfo {
        let trees = if with_ironwood {
            serde_json::json!({"sapling": {"size": 1}, "orchard": {"size": 2}, "ironwood": {"size": 3}})
        } else {
            serde_json::json!({"sapling": {"size": 1}, "orchard": {"size": 2}})
        };
        block(serde_json::json!({
            "hash": "aa".repeat(32),
            "time": 1,
            "finalsaplingroot": "23".repeat(32),
            "finalorchardroot": "13".repeat(32),
            "trees": trees,
        }))
    }

    fn tree_state(orchard: &str, ironwood: Option<&str>) -> BlockRoots {
        BlockRoots {
            hash: "aa".repeat(32),
            sapling: Some("23".repeat(32)),
            orchard: Some(orchard.repeat(32)),
            ironwood: ironwood.map(|root| root.repeat(32)),
        }
    }

    #[test]
    fn header_commitment_is_replaced_by_the_node_roots() {
        let repaired = reconcile_roots(&stored(None), node_block(false), None).unwrap();
        assert_eq!(repaired.final_sapling_root, Some("23".repeat(32)));
        assert_eq!(repaired.final_orchard_root, Some("13".repeat(32)));
        assert_eq!(repaired.final_ironwood_root, None);
    }

    #[test]
    fn tree_state_is_only_requested_for_a_missing_ironwood_root() {
        assert!(!needs_tree_state(&stored(None), &node_block(false)));
        assert!(needs_tree_state(&stored(None), &node_block(true)));
        let known = "77".repeat(32);
        assert!(!needs_tree_state(&stored(Some(&known)), &node_block(true)));
    }

    #[test]
    fn ironwood_root_comes_from_a_consistent_tree_state() {
        let repaired = reconcile_roots(
            &stored(None),
            node_block(true),
            Some(tree_state("13", Some("77"))),
        )
        .unwrap();
        assert_eq!(repaired.final_ironwood_root, Some("77".repeat(32)));
    }

    #[test]
    fn disagreeing_tree_state_is_refused() {
        let error = reconcile_roots(
            &stored(None),
            node_block(true),
            Some(tree_state("99", Some("77"))),
        )
        .unwrap_err();
        assert!(error.contains("disagree"), "{error}");
    }

    #[test]
    fn a_known_ironwood_root_is_never_cleared() {
        let known = "77".repeat(32);
        let repaired = reconcile_roots(&stored(Some(&known)), node_block(true), None).unwrap();
        assert_eq!(repaired.final_ironwood_root, Some(known));
    }

    #[test]
    fn answers_for_another_block_or_without_a_sapling_root_are_refused() {
        let other = block(serde_json::json!({
            "hash": "bb".repeat(32), "time": 1, "finalsaplingroot": "23".repeat(32),
        }));
        assert!(reconcile_roots(&stored(None), other, None).is_err());

        let rootless = block(serde_json::json!({"hash": "aa".repeat(32), "time": 1}));
        assert!(reconcile_roots(&stored(None), rootless, None).is_err());

        let malformed = block(serde_json::json!({
            "hash": "aa".repeat(32), "time": 1, "finalsaplingroot": "zz",
        }));
        assert!(reconcile_roots(&stored(None), malformed, None).is_err());
    }
}
