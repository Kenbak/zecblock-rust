//! Periodic coverage audit for the competing-block collector.
//!
//! The node is the authority for which side branches it validated. Every audit
//! asks it for `getchaintips`, walks each `valid-fork` branch back through the
//! captured parent links, and records blocks the collector never stored. A block
//! must be missing on two consecutive audits (at least one interval apart) before
//! it is recorded, so normal stream/delivery latency is never counted as a miss.
//! It also counts recent canonical indexed blocks absent from `captured_blocks`,
//! which directly measures silent stream drops.
//!
//! Limits: this proves coverage only relative to blocks this node validated. A
//! competing block that never reached the node is invisible to both.
//! Runs as its own task with its own connection: it never blocks the stream.

use super::orphan_capture::read_journal_parent;
use super::rpc::ChainTip;
use super::ZebraRpc;
use sqlx::PgPool;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_INTERVAL_SECS: u64 = 300;
const FIRST_AUDIT_DELAY: Duration = Duration::from_secs(60);
const AUDIT_TIMEOUT: Duration = Duration::from_secs(60);
// Zakura's MAX_BLOCK_REORG_HEIGHT bounds a valid non-finalized branch.
const MAX_BRANCH_LEN: u64 = 1000;
const MAX_FORK_TIPS: usize = 64;
const MAX_LOOKUPS: usize = 2000;
const CANONICAL_WINDOW: i64 = 1000;
// Newest canonical heights may still be in flight from the stream to the DB.
const CANONICAL_SETTLE: i64 = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ForkTip {
    pub hash: String,
    pub height: u64,
    pub branch_len: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Missing {
    pub hash: String,
    pub height: u64,
    pub branch_len: u64,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub fork_tips: usize,
    pub fork_blocks: usize,
    pub confirmed: Vec<Missing>,
    pub canonical_checked: i32,
    pub canonical_missing: i32,
}

fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Node-reported validated side branches, bounded and sanity-checked.
pub(crate) fn fork_tips(tips: &[ChainTip]) -> Result<Vec<ForkTip>, String> {
    let mut forks = Vec::new();
    for tip in tips.iter().filter(|tip| tip.status == "valid-fork") {
        if !valid_hash(&tip.hash)
            || tip.branchlen == 0
            || tip.branchlen > MAX_BRANCH_LEN
            || tip.height < tip.branchlen
        {
            return Err("node reported a malformed fork tip".into());
        }
        if !forks.iter().any(|f: &ForkTip| f.hash == tip.hash) {
            forks.push(ForkTip {
                hash: tip.hash.clone(),
                height: tip.height,
                branch_len: tip.branchlen,
            });
        }
    }
    if forks.len() > MAX_FORK_TIPS {
        return Err("node reported more fork tips than the audit bound".into());
    }
    Ok(forks)
}

/// Keeps only misses already seen by the previous audit; remembers the rest.
pub(crate) fn confirm(
    candidates: &mut HashMap<String, Missing>,
    missing_now: Vec<Missing>,
) -> Vec<Missing> {
    let confirmed = missing_now
        .iter()
        .filter(|m| candidates.contains_key(&m.hash))
        .cloned()
        .collect();
    *candidates = missing_now
        .into_iter()
        .map(|m| (m.hash.clone(), m))
        .collect();
    confirmed
}

/// Parent of a captured block, from the pending journal or the database.
async fn captured_parent(
    pool: &PgPool,
    directory: &Path,
    hash: &str,
) -> Result<Option<String>, String> {
    if let Some(parent) = read_journal_parent(directory, hash) {
        return Ok(Some(parent));
    }
    // A file may be acknowledged and removed between these reads; the DB has it then.
    sqlx::query_scalar("SELECT previous_block_hash FROM captured_blocks WHERE hash = $1")
        .bind(hash)
        .fetch_optional(pool)
        .await
        .map_err(|_| "capture audit lookup failed".into())
}

/// Walks every fork branch from its tip; returns uncaptured blocks (first gap per branch).
pub(crate) async fn uncaptured_fork_blocks(
    pool: &PgPool,
    directory: &Path,
    forks: &[ForkTip],
) -> Result<(usize, Vec<Missing>), String> {
    let mut lookups = 0;
    let mut checked = 0;
    let mut missing = Vec::new();
    for fork in forks {
        let mut hash = fork.hash.clone();
        let mut height = fork.height;
        for _ in 0..fork.branch_len {
            lookups += 1;
            if lookups > MAX_LOOKUPS {
                return Err("capture audit lookup budget exceeded".into());
            }
            checked += 1;
            match captured_parent(pool, directory, &hash).await? {
                Some(parent) if valid_hash(&parent) => {
                    hash = parent;
                    height = height.saturating_sub(1);
                }
                Some(_) => return Err("captured parent hash malformed".into()),
                None => {
                    // Without the block we cannot learn its parent; stop this branch.
                    missing.push(Missing {
                        hash,
                        height,
                        branch_len: fork.branch_len,
                    });
                    break;
                }
            }
        }
    }
    Ok((checked, missing))
}

/// Recent canonical blocks since collection start that the collector never stored.
async fn canonical_gaps(
    pool: &PgPool,
    directory: &Path,
    observer: &str,
) -> Result<(i32, i32), String> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "WITH tip AS (SELECT max(height) AS h FROM blocks),
              start AS (SELECT extract(epoch FROM collection_started_at)::bigint AS t
                        FROM block_capture_observers WHERE observer = $1)
         SELECT b.hash FROM blocks b, tip, start
         WHERE b.height > tip.h - $2 AND b.height <= tip.h - $3 AND b.timestamp >= start.t
           AND NOT EXISTS (SELECT 1 FROM captured_blocks c WHERE c.hash = b.hash)
         ORDER BY b.height",
    )
    .bind(observer)
    .bind(CANONICAL_WINDOW)
    .bind(CANONICAL_SETTLE)
    .fetch_all(pool)
    .await
    .map_err(|_| "capture audit canonical query failed")?;
    let checked: i64 = sqlx::query_scalar(
        "WITH tip AS (SELECT max(height) AS h FROM blocks),
              start AS (SELECT extract(epoch FROM collection_started_at)::bigint AS t
                        FROM block_capture_observers WHERE observer = $1)
         SELECT count(*) FROM blocks b, tip, start
         WHERE b.height > tip.h - $2 AND b.height <= tip.h - $3 AND b.timestamp >= start.t",
    )
    .bind(observer)
    .bind(CANONICAL_WINDOW)
    .bind(CANONICAL_SETTLE)
    .fetch_one(pool)
    .await
    .map_err(|_| "capture audit canonical query failed")?;
    // Still-pending journal files are captured, just not yet delivered.
    let missing = rows
        .iter()
        .filter(|(hash,)| !valid_hash(hash) || read_journal_parent(directory, hash).is_none())
        .count();
    Ok((
        i32::try_from(checked).unwrap_or(i32::MAX),
        i32::try_from(missing).unwrap_or(i32::MAX),
    ))
}

#[cfg(test)]
pub(crate) async fn canonical_gaps_for_test(
    pool: &PgPool,
    directory: &Path,
    observer: &str,
) -> Result<(i32, i32), String> {
    canonical_gaps(pool, directory, observer).await
}

pub(crate) async fn audit_once(
    rpc: &ZebraRpc,
    pool: &PgPool,
    directory: &Path,
    observer: &str,
    candidates: &mut HashMap<String, Missing>,
) -> Result<Outcome, String> {
    let forks = fork_tips(&rpc.get_chain_tips().await?)?;
    let (fork_blocks, missing_now) = uncaptured_fork_blocks(pool, directory, &forks).await?;
    let confirmed = confirm(candidates, missing_now);
    let (canonical_checked, canonical_missing) = canonical_gaps(pool, directory, observer).await?;
    Ok(Outcome {
        fork_tips: forks.len(),
        fork_blocks,
        confirmed,
        canonical_checked,
        canonical_missing,
    })
}

pub(crate) async fn record(
    pool: &PgPool,
    observer: &str,
    network: &str,
    result: &Result<Outcome, String>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL statement_timeout = '5s'")
        .execute(&mut *tx)
        .await?;
    if let Ok(outcome) = result {
        for miss in &outcome.confirmed {
            sqlx::query("INSERT INTO block_capture_audit_misses (observer,hash,network,height,branch_len) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (observer,hash) DO NOTHING")
                .bind(observer).bind(&miss.hash).bind(network)
                .bind(i64::try_from(miss.height).unwrap_or(i64::MAX))
                .bind(i32::try_from(miss.branch_len).unwrap_or(i32::MAX))
                .execute(&mut *tx).await?;
        }
    }
    // A recorded miss later delivered (e.g. retained replay) is kept, marked late.
    sqlx::query("UPDATE block_capture_audit_misses m SET captured_later_at = now() FROM captured_blocks c WHERE m.observer = $1 AND m.captured_later_at IS NULL AND c.hash = m.hash")
        .bind(observer).execute(&mut *tx).await?;
    let (status, tips, blocks, checked, canonical_missing) = match result {
        Ok(o) => (
            "ok".to_string(),
            Some(i32::try_from(o.fork_tips).unwrap_or(i32::MAX)),
            Some(i32::try_from(o.fork_blocks).unwrap_or(i32::MAX)),
            Some(o.canonical_checked),
            Some(o.canonical_missing),
        ),
        Err(error) => (
            format!("error: {}", error.chars().take(200).collect::<String>()),
            None,
            None,
            None,
            None,
        ),
    };
    sqlx::query("UPDATE block_capture_observers SET audit_checked_at = now(), audit_status = $3, audit_fork_tips = COALESCE($4, audit_fork_tips), audit_fork_blocks = COALESCE($5, audit_fork_blocks), audit_canonical_checked = COALESCE($6, audit_canonical_checked), audit_canonical_missing = COALESCE($7, audit_canonical_missing) WHERE observer = $1 AND network = $2")
        .bind(observer).bind(network).bind(status)
        .bind(tips).bind(blocks).bind(checked).bind(canonical_missing)
        .execute(&mut *tx).await?;
    tx.commit().await
}

async fn schema_ready(pool: &PgPool, network: &str) -> Result<bool, String> {
    let genesis: Option<String> = sqlx::query_scalar("SELECT hash FROM blocks WHERE height = 0")
        .fetch_optional(pool)
        .await
        .map_err(|_| "capture audit database unavailable")?;
    let expected = if network == "mainnet" {
        "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08"
    } else {
        "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38"
    };
    if genesis.as_deref() != Some(expected) {
        return Err("capture audit database network mismatch".into());
    }
    // The miss table and the audit columns arrive together in migration 042.
    sqlx::query_scalar("SELECT to_regclass('block_capture_audit_misses') IS NOT NULL AND (SELECT count(*) = 6 FROM pg_attribute WHERE attrelid = to_regclass('block_capture_observers') AND NOT attisdropped AND attname IN ('audit_checked_at','audit_status','audit_fork_tips','audit_fork_blocks','audit_canonical_checked','audit_canonical_missing'))")
        .fetch_one(pool)
        .await
        .map_err(|_| "capture audit database unavailable".into())
}

fn interval() -> Duration {
    let secs = std::env::var("CAPTURE_AUDIT_INTERVAL_SECONDS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|v| v.clamp(60, 3600))
        .unwrap_or(DEFAULT_INTERVAL_SECS);
    Duration::from_secs(secs)
}

/// Runs until aborted. Failures are recorded and retried; they never stop capture.
pub(crate) async fn run_audit_loop(
    rpc: ZebraRpc,
    pool: PgPool,
    directory: PathBuf,
    observer: String,
    network: String,
) {
    let period = interval();
    let mut candidates = HashMap::new();
    let mut warned_schema = false;
    tokio::time::sleep(FIRST_AUDIT_DELAY).await;
    loop {
        match schema_ready(&pool, &network).await {
            Ok(true) => {
                let result = tokio::time::timeout(
                    AUDIT_TIMEOUT,
                    audit_once(&rpc, &pool, &directory, &observer, &mut candidates),
                )
                .await
                .unwrap_or_else(|_| Err("capture audit timed out".into()));
                match &result {
                    Ok(o) if !o.confirmed.is_empty() || o.canonical_missing > 0 => tracing::warn!(
                        fork_tips = o.fork_tips,
                        uncaptured_fork_blocks = o.confirmed.len(),
                        canonical_missing = o.canonical_missing,
                        "capture audit found blocks the node validated but the collector did not store"
                    ),
                    Ok(_) => {}
                    Err(error) => tracing::warn!(%error, "capture audit failed; retrying next interval"),
                }
                if record(&pool, &observer, &network, &result).await.is_err() {
                    tracing::warn!("capture audit result could not be recorded");
                }
            }
            Ok(false) => {
                if !warned_schema {
                    tracing::warn!("capture audit waiting for migration 042");
                    warned_schema = true;
                }
            }
            Err(error) => tracing::warn!(%error, "capture audit skipped"),
        }
        tokio::time::sleep(period).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tip(hash: &str, status: &str, height: u64, branchlen: u64) -> ChainTip {
        ChainTip {
            hash: hash.into(),
            status: status.into(),
            height,
            branchlen,
        }
    }

    fn miss(hash: &str) -> Missing {
        Missing {
            hash: hash.into(),
            height: 10,
            branch_len: 1,
        }
    }

    #[test]
    fn only_valid_forks_are_audited_and_malformed_tips_fail() {
        let forks = fork_tips(&[
            tip(&"aa".repeat(32), "active", 100, 0),
            tip(&"bb".repeat(32), "valid-fork", 99, 1),
            tip(&"bb".repeat(32), "valid-fork", 99, 1),
            tip(&"cc".repeat(32), "headers-only", 99, 1),
            tip(&"dd".repeat(32), "invalid", 99, 1),
        ])
        .unwrap();
        assert_eq!(
            forks,
            vec![ForkTip {
                hash: "bb".repeat(32),
                height: 99,
                branch_len: 1
            }]
        );
        for bad in [
            tip("../etc/passwd", "valid-fork", 99, 1),
            tip(&"BB".repeat(32), "valid-fork", 99, 1),
            tip(&"bb".repeat(32), "valid-fork", 99, 0),
            tip(&"bb".repeat(32), "valid-fork", 99, MAX_BRANCH_LEN + 1),
            tip(&"bb".repeat(32), "valid-fork", 1, 2),
        ] {
            assert!(fork_tips(&[bad]).is_err());
        }
    }

    #[test]
    fn a_miss_needs_two_consecutive_audits() {
        let mut candidates = HashMap::new();
        assert!(confirm(&mut candidates, vec![miss("a"), miss("b")]).is_empty());
        // "a" was delivered in between; "c" is new; only "b" is confirmed.
        assert_eq!(
            confirm(&mut candidates, vec![miss("b"), miss("c")]),
            vec![miss("b")]
        );
        assert_eq!(confirm(&mut candidates, vec![]), vec![]);
        assert!(candidates.is_empty());
    }
}
