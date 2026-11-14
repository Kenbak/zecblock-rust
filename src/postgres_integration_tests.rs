//! Integration tests against a real PostgreSQL instance.
//!
//! Requires `DATABASE_URL` to point at a disposable database with the
//! schema from `schema/postgres.sql` applied (CI provides this via a
//! service container; see .github/workflows/ci.yml). Never point this at
//! a database containing real chain data — these tests delete rows in the
//! height ranges they use.
//!
//! Each test uses a distinct, non-overlapping height range and address
//! prefix so tests can run concurrently (`cargo test` default) without
//! interfering with each other, and are safe to re-run.
//!
//! This lives inside the crate (not `tests/`) because cipherscan-indexer
//! is a bin-only crate: several `commands::*` helpers are `pub(crate)`,
//! so a separate `tests/` integration crate (which would need a `[lib]`
//! target) could not see them without a much larger, riskier refactor.
//! Gated `#[cfg(test)]` via the `mod` declaration in main.rs.

use crate::db::{ParsedBlockHeader, PostgresWriter};
use crate::models::{Transaction, TransparentInput, TransparentOutput};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// Rollback removes every height at or above the fork, so rollback tests must
/// not run while another one has rows in the database.
static ROLLBACK_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn test_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set to a disposable test database");
    PgPoolOptions::new()
        .max_connections(10)
        .connect(&url)
        .await
        .expect("failed to connect to test database")
}

async fn writer() -> PostgresWriter {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    PostgresWriter::connect(&url)
        .await
        .expect("failed to connect PostgresWriter")
}

/// Deletes any rows left over from a previous run in `[from, to]`, and
/// removes the address summaries for `addresses` so each test starts clean.
async fn cleanup(pool: &PgPool, from: u32, to: u32, addresses: &[&str]) {
    sqlx::query("DELETE FROM blocks WHERE height BETWEEN $1 AND $2")
        .bind(from as i64)
        .bind(to as i64)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM transactions WHERE block_height BETWEEN $1 AND $2")
        .bind(from as i64)
        .bind(to as i64)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM address_transactions WHERE block_height BETWEEN $1 AND $2")
        .bind(from as i64)
        .bind(to as i64)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM addresses WHERE address = ANY($1)")
        .bind(addresses)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM orphaned_blocks WHERE height BETWEEN $1 AND $2")
        .bind(from as i64)
        .bind(to as i64)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM fork_events WHERE fork_height BETWEEN $1 AND $2")
        .bind(from as i64)
        .bind(to as i64)
        .execute(pool)
        .await
        .unwrap();
}

fn header(time: u64) -> ParsedBlockHeader {
    ParsedBlockHeader {
        version: 4,
        previous_block_hash: "00".repeat(32),
        merkle_root: "11".repeat(32),
        final_sapling_root: "22".repeat(32),
        final_orchard_root: None,
        final_ironwood_root: None,
        time,
        bits: "1d00ffff".to_string(),
        difficulty: 1.0,
        nonce: "33".repeat(32),
        solution: "".to_string(),
    }
}

fn coinbase_tx(txid: &str, height: u32, block_hash: &str, miner: &str, reward: i64) -> Transaction {
    Transaction {
        txid: txid.to_string(),
        block_height: height,
        block_hash: block_hash.to_string(),
        version: 4,
        lock_time: 0,
        expiry_height: None,
        size: 100,
        vin_count: 1,
        vout_count: 1,
        transparent_value_in: 0,
        transparent_value_out: reward,
        joinsplit_count: 0,
        sapling_spends: 0,
        sapling_outputs: 0,
        orchard_actions: 0,
        ironwood_actions: 0,
        sapling_value_balance: 0,
        orchard_value_balance: 0,
        ironwood_value_balance: 0,
        sprout_value_balance: 0,
        orchard_anchor: None,
        ironwood_anchor: None,
        fee: None,
        vin: vec![TransparentInput {
            txid: "00".repeat(32),
            vout: 0xffffffff,
            address: None,
            value: None,
            is_coinbase: true,
            script_sig: None,
        }],
        vout: vec![TransparentOutput {
            n: 0,
            value: reward,
            address: Some(miner.to_string()),
            script_type: "pubkeyhash".to_string(),
            script_pub_key: None,
            pubkey_exposures: vec![],
        }],
    }
}

async fn address_row(pool: &PgPool, address: &str) -> Option<(i64, i64, i64, i32)> {
    sqlx::query_as::<_, (i64, i64, i64, i32)>(
        "SELECT balance, total_received, total_sent, tx_count FROM addresses WHERE address = $1",
    )
    .bind(address)
    .fetch_optional(pool)
    .await
    .unwrap()
}

/// Test 1: replay idempotency. Indexing a block, then indexing the exact
/// same block again (the `is_replay` path, e.g. after a crash-and-resume),
/// must converge to identical address-summary state, not double-apply.
#[tokio::test]
async fn replay_idempotency_converges_to_identical_state() {
    let pool = test_pool().await;
    let w = writer().await;
    let (from, to) = (90_000_001u32, 90_000_001u32);
    let miner = "tTEST1replayminer00000000000000000";
    cleanup(&pool, from, to, &[miner]).await;

    let hash = "aa".repeat(32);
    let tx = coinbase_tx(&"cb".repeat(32), from, &hash, miner, 625_000_000);

    w.batch_insert_with_header_and_flows(
        from,
        &hash,
        1_700_000_000,
        std::slice::from_ref(&tx),
        &[],
        &header(1_700_000_000),
    )
    .await
    .expect("first index failed");
    let after_first = address_row(&pool, miner)
        .await
        .expect("address missing after first index");

    // Replay the SAME block (is_replay = true, since the blocks row already exists).
    w.batch_insert_with_header_and_flows(
        from,
        &hash,
        1_700_000_000,
        &[tx],
        &[],
        &header(1_700_000_000),
    )
    .await
    .expect("replay index failed");
    let after_replay = address_row(&pool, miner)
        .await
        .expect("address missing after replay");

    assert_eq!(
        after_first, after_replay,
        "replaying an already-indexed block must not change address summary state"
    );
    assert_eq!(
        after_replay.0, 625_000_000,
        "balance should equal the single coinbase reward"
    );
    assert_eq!(
        after_replay.3, 1,
        "tx_count must not double-count on replay"
    );

    cleanup(&pool, from, to, &[miner]).await;
}

/// Test 2: the lost-update race this session's fix closes. A REPLAY (full
/// recompute) on one height and a NEW-BLOCK delta on a different height,
/// both touching the SAME address concurrently, must not lose either
/// side's contribution — this is exactly the F1 race from 2026-08-15.
#[tokio::test]
async fn concurrent_replay_and_new_block_do_not_lose_updates() {
    let pool = test_pool().await;
    let (from, to) = (90_000_100u32, 90_000_101u32);
    let shared_addr = "tTEST2sharedaddr0000000000000000000";
    cleanup(&pool, from, to, &[shared_addr]).await;

    let hash1 = "bb".repeat(32);
    let hash2 = "cc".repeat(32);
    let tx1 = coinbase_tx(&"c1".repeat(32), from, &hash1, shared_addr, 100_000_000);
    let tx2 = coinbase_tx(&"c2".repeat(32), to, &hash2, shared_addr, 200_000_000);

    // Index height `from` first and normally (this is what makes the second
    // call to batch_insert_with_header_and_flows(from, ...) below a REPLAY).
    let w0 = writer().await;
    w0.batch_insert_with_header_and_flows(
        from,
        &hash1,
        1_700_000_100,
        std::slice::from_ref(&tx1),
        &[],
        &header(1_700_000_100),
    )
    .await
    .expect("seed index failed");

    // Now race: replay height `from` (full recompute) concurrently with a
    // genuinely new block at height `to` (delta apply), both touching
    // `shared_addr`, on two independent connections/writers.
    let w_replay = writer().await;
    let w_new = writer().await;
    let tx1_replay = tx1.clone();
    let replay_fut = tokio::spawn(async move {
        w_replay
            .batch_insert_with_header_and_flows(
                from,
                &hash1,
                1_700_000_100,
                &[tx1_replay],
                &[],
                &header(1_700_000_100),
            )
            .await
    });
    let new_fut = tokio::spawn(async move {
        w_new
            .batch_insert_with_header_and_flows(
                to,
                &hash2,
                1_700_000_160,
                &[tx2],
                &[],
                &header(1_700_000_160),
            )
            .await
    });

    let (replay_res, new_res) = tokio::join!(replay_fut, new_fut);
    replay_res.unwrap().expect("replay failed");
    new_res.unwrap().expect("new-block index failed");

    let final_state = address_row(&pool, shared_addr)
        .await
        .expect("address missing");
    assert_eq!(
        final_state.0, 300_000_000,
        "both blocks' rewards must be reflected in balance — a lost update would show only 100_000_000 or 200_000_000"
    );
    assert_eq!(
        final_state.1, 300_000_000,
        "total_received must include both blocks"
    );
    assert_eq!(
        final_state.3, 2,
        "tx_count must reflect both blocks' coinbase txs"
    );

    cleanup(&pool, from, to, &[shared_addr]).await;
}

/// Test 3: two new blocks touching DIFFERENT addresses must both complete
/// correctly when run concurrently (the per-address advisory lock must not
/// degrade into a global lock). Companion to the 2026-08-15 performance
/// incident where an earlier version of the F1 fix made every block slow;
/// this asserts correctness under concurrency, the same property that
/// incident's design also satisfied — performance itself is guarded by
/// the fix commit's design note, not a timing assertion here (which would
/// be flaky in CI).
#[tokio::test]
async fn disjoint_addresses_both_update_correctly_when_concurrent() {
    let pool = test_pool().await;
    let (from, to) = (90_000_200u32, 90_000_201u32);
    let addr_a = "tTEST3addrA00000000000000000000000";
    let addr_b = "tTEST3addrB00000000000000000000000";
    cleanup(&pool, from, to, &[addr_a, addr_b]).await;

    let hash_a = "dd".repeat(32);
    let hash_b = "ee".repeat(32);
    let tx_a = coinbase_tx(&"a1".repeat(32), from, &hash_a, addr_a, 111_000_000);
    let tx_b = coinbase_tx(&"b1".repeat(32), to, &hash_b, addr_b, 222_000_000);

    let w_a = writer().await;
    let w_b = writer().await;
    let fut_a = tokio::spawn(async move {
        w_a.batch_insert_with_header_and_flows(
            from,
            &hash_a,
            1_700_000_200,
            &[tx_a],
            &[],
            &header(1_700_000_200),
        )
        .await
    });
    let fut_b = tokio::spawn(async move {
        w_b.batch_insert_with_header_and_flows(
            to,
            &hash_b,
            1_700_000_260,
            &[tx_b],
            &[],
            &header(1_700_000_260),
        )
        .await
    });
    let (res_a, res_b) = tokio::join!(fut_a, fut_b);
    res_a.unwrap().expect("addr_a index failed");
    res_b.unwrap().expect("addr_b index failed");

    assert_eq!(address_row(&pool, addr_a).await.unwrap().0, 111_000_000);
    assert_eq!(address_row(&pool, addr_b).await.unwrap().0, 222_000_000);

    cleanup(&pool, from, to, &[addr_a, addr_b]).await;
}

/// Test 4: reorg rollback correctness. After rolling back to a fork height,
/// no rows above the fork remain, the touched address summary is recomputed
/// from the surviving ledger only, and the block is archived to
/// orphaned_blocks.
#[tokio::test]
async fn reorg_rollback_removes_orphaned_rows_and_recomputes_summary() {
    let _serial = ROLLBACK_TESTS.lock().await;
    let pool = test_pool().await;
    let w = writer().await;
    let (from, to) = (90_000_300u32, 90_000_302u32);
    let miner = "tTEST4reorgminer0000000000000000000";
    cleanup(&pool, from, to, &[miner]).await;

    for h in from..=to {
        let hash = format!("{:02x}", h % 256).repeat(32);
        let tx = coinbase_tx(
            &format!("{:02x}", h % 256).repeat(32),
            h,
            &hash,
            miner,
            50_000_000,
        );
        w.batch_insert_with_header_and_flows(
            h,
            &hash,
            1_700_000_300 + (h - from) as u64 * 60,
            &[tx],
            &[],
            &header(1_700_000_300),
        )
        .await
        .unwrap_or_else(|e| panic!("seed index at {} failed: {}", h, e));
    }
    let before_rollback = address_row(&pool, miner).await.unwrap();
    assert_eq!(
        before_rollback.0, 150_000_000,
        "3 blocks x 50_000_000 reward"
    );

    let fork_height = from + 1; // roll back the last 2 blocks (from+1, from+2)
    let rolled_back = w
        .rollback_from_height(fork_height, "integration-test reorg")
        .await
        .expect("rollback failed");
    assert_eq!(rolled_back, 2, "should roll back exactly 2 blocks");

    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blocks WHERE height >= $1")
        .bind(fork_height as i64)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        remaining, 0,
        "no block rows at/above the fork height may remain"
    );

    let orphaned: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM orphaned_blocks WHERE height >= $1")
            .bind(fork_height as i64)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        orphaned, 2,
        "rolled-back blocks must be archived to orphaned_blocks"
    );

    let after_rollback = address_row(&pool, miner).await.unwrap();
    assert_eq!(
        after_rollback.0, 50_000_000,
        "address summary must be recomputed from the surviving ledger only (1 remaining block)"
    );

    cleanup(&pool, from, to, &[miner]).await;
}

/// Test 5: crash-safety semantics of the checkpoint helpers. A checkpoint
/// must never report progress beyond what was actually recorded, and
/// resuming from a checkpoint must be safe to call repeatedly (idempotent
/// key/value upsert) — modeling "indexer crashes after committing a block
/// but before advancing the checkpoint, then resumes".
#[tokio::test]
async fn checkpoint_never_exceeds_last_recorded_value_and_upsert_is_idempotent() {
    let w = writer().await;

    w.update_checkpoint("integration_test_checkpoint", "12345")
        .await
        .expect("first checkpoint write failed");
    let first = w
        .get_checkpoint_key("integration_test_checkpoint")
        .await
        .expect("read failed")
        .expect("checkpoint missing after write");
    assert_eq!(first, 12345);

    // Simulate a crash between block commit and checkpoint advance: the
    // checkpoint must still read the OLD value until explicitly advanced.
    let unchanged = w
        .get_checkpoint_key("integration_test_checkpoint")
        .await
        .expect("read failed")
        .expect("checkpoint missing");
    assert_eq!(unchanged, 12345, "checkpoint must not advance on its own");

    // Resume: advance it, and confirm repeated identical writes are safe (idempotent).
    w.update_checkpoint("integration_test_checkpoint", "12346")
        .await
        .expect("second checkpoint write failed");
    w.update_checkpoint("integration_test_checkpoint", "12346")
        .await
        .expect("idempotent re-write failed");
    let advanced = w
        .get_checkpoint_key("integration_test_checkpoint")
        .await
        .expect("read failed")
        .expect("checkpoint missing");
    assert_eq!(advanced, 12346);
}

/// Test 6: `has_shielded_data` is populated correctly on insert (not left
/// at its schema default of false) for a transaction with shielded
/// activity — a regression test for the F4 fix (previously always false,
/// only read during reorg archival, so a stale `false` was silent).
#[tokio::test]
async fn has_shielded_data_reflects_actual_shielded_activity() {
    let pool = test_pool().await;
    let w = writer().await;
    let (from, to) = (90_000_400u32, 90_000_400u32);
    let miner = "tTEST6shieldedminer000000000000000";
    cleanup(&pool, from, to, &[miner]).await;

    let hash = "ff".repeat(32);
    let mut shielded_tx = coinbase_tx(&"9a".repeat(32), from, &hash, miner, 1_000_000);
    shielded_tx.txid = "9b".repeat(32);
    shielded_tx.orchard_actions = 2;

    w.batch_insert_with_header_and_flows(
        from,
        &hash,
        1_700_000_400,
        &[shielded_tx.clone()],
        &[],
        &header(1_700_000_400),
    )
    .await
    .expect("index failed");

    let has_shielded: bool =
        sqlx::query_scalar("SELECT has_shielded_data FROM transactions WHERE txid = $1")
            .bind(&shielded_tx.txid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        has_shielded,
        "tx with orchard_actions > 0 must have has_shielded_data = true"
    );

    cleanup(&pool, from, to, &[miner]).await;
}

/// Collector timestamps remain immutable across polls, replay and archival.
#[tokio::test]
async fn first_observation_and_raw_orphan_evidence_survive_rollback() {
    let _serial = ROLLBACK_TESTS.lock().await;
    let pool = test_pool().await;
    let w = writer().await;
    let height = 90_001_000u32;
    let hash = "ed".repeat(32);
    let miner = "tTESTobservationminer0000000000000";
    cleanup(&pool, height, height, &[miner]).await;
    sqlx::query("DELETE FROM block_observations WHERE hash=$1")
        .bind(&hash)
        .execute(&pool)
        .await
        .unwrap();
    let first_ms = 1_790_152_000_123i64;
    crate::db::observations::record_observation(&pool, &hash, height as i64, first_ms)
        .await
        .unwrap();
    crate::db::observations::record_observation(&pool, &hash, height as i64, first_ms + 1000)
        .await
        .unwrap();
    sqlx::query("DELETE FROM node_accounting_observations WHERE hash=$1")
        .bind(&hash)
        .execute(&pool)
        .await
        .unwrap();
    let info = serde_json::json!({"blocks":height, "bestblockhash":hash,
        "chain":"test", "nsmValueBalanceZat":-9_007_199_254_740_993_i64,
        "chainSupply":{"chainValueZat":123,"monitored":true},
        "valuePools":[{"id":"ironwood", "chainValueZat":100,"monitored":true}, {"id":"sapling","chainValueZat":0,"monitored":false}]});
    crate::db::observations::record_accounting(&pool, &info, None, first_ms)
        .await
        .unwrap();
    let mut changed = info.clone();
    changed["nsmValueBalanceZat"] = serde_json::json!(0);
    crate::db::observations::record_accounting(&pool, &changed, None, first_ms + 1000)
        .await
        .unwrap();
    let tx = coinbase_tx(&"ee".repeat(32), height, &hash, miner, 50_000_000);
    w.batch_insert_with_header_and_flows(
        height,
        &hash,
        1_790_151_999,
        &[tx],
        &[],
        &header(1_790_151_999),
    )
    .await
    .unwrap();
    // An earlier lightweight external report must be enriched, not block archival.
    sqlx::query("INSERT INTO orphaned_blocks(height, hash, source) VALUES ($1,$2,'external')")
        .bind(height as i64)
        .bind(&hash)
        .execute(&pool)
        .await
        .unwrap();
    w.rollback_from_height_with_raw(
        height,
        "observation archive regression",
        &[(hash.clone(), "aabbccdd".into())],
    )
    .await
    .unwrap();
    let observed: i64 = sqlx::query_scalar("SELECT (EXTRACT(EPOCH FROM first_seen_at)*1000)::bigint FROM block_observations WHERE hash=$1")
        .bind(&hash).fetch_one(&pool).await.unwrap();
    assert_eq!(observed, first_ms);
    let balance: i64 = sqlx::query_scalar(
        "SELECT nsm_balance_zat FROM node_accounting_observations WHERE hash=$1",
    )
    .bind(&hash)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(balance, -9_007_199_254_740_993_i64);
    let pools: serde_json::Value = sqlx::query_scalar(
        "SELECT pool_balances_zat FROM node_accounting_observations WHERE hash=$1",
    )
    .bind(&hash)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pools["ironwood"], "100");
    assert!(
        pools["sapling"].is_null(),
        "unmonitored balances must remain unavailable"
    );
    let canonical: i64 = sqlx::query_scalar("SELECT count(*) FROM node_accounting_observations a JOIN blocks b ON b.hash=a.hash AND b.height=a.height WHERE a.hash=$1")
        .bind(&hash).fetch_one(&pool).await.unwrap();
    assert_eq!(
        canonical, 0,
        "orphan reserve observations must not enter canonical charts"
    );
    sqlx::query("DELETE FROM node_accounting_observations WHERE hash=$1")
        .bind(&hash)
        .execute(&pool)
        .await
        .unwrap();
    let archive: (String, i32, String, String) = sqlx::query_as(
        "SELECT raw_hex, transaction_count, block_metadata->>'hash', source FROM orphaned_blocks WHERE hash=$1")
        .bind(&hash).fetch_one(&pool).await.unwrap();
    assert_eq!(
        archive,
        ("aabbccdd".into(), 1, hash.clone(), "indexer".into())
    );
    let tx_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM orphaned_transactions WHERE block_hash=$1")
            .bind(&hash)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(tx_count, 1);
    cleanup(&pool, height, height, &[miner]).await;
    sqlx::query("DELETE FROM block_observations WHERE hash=$1")
        .bind(&hash)
        .execute(&pool)
        .await
        .unwrap();
}

/// A reorg at the node's full rollback limit must commit as one transaction and
/// leave the surviving block and its address summary intact.
#[tokio::test]
async fn rollback_at_the_node_limit_archives_every_orphaned_block() {
    let _serial = ROLLBACK_TESTS.lock().await;
    const DEPTH: u32 = 1000;
    let pool = test_pool().await;
    let w = writer().await;
    let base = 90_100_000u32;
    let (fork, tip) = (base + 1, base + DEPTH);
    let miner = "tTEST1deepreorgminer00000000000000";
    let block_hash = |height: u32| format!("{height:064x}");
    let txid = |height: u32| format!("cb{height:062x}");
    let hashes: Vec<String> = (base..=tip).map(block_hash).collect();
    let txids: Vec<String> = (base..=tip).map(txid).collect();
    let clear_archives = || async {
        for sql in [
            "DELETE FROM orphaned_transaction_inputs WHERE block_hash = ANY($1)",
            "DELETE FROM orphaned_transaction_outputs WHERE block_hash = ANY($1)",
            "DELETE FROM orphaned_transactions WHERE block_hash = ANY($1)",
        ] {
            sqlx::query(sql).bind(&hashes).execute(&pool).await.unwrap();
        }
    };
    clear_archives().await;
    cleanup(&pool, base, tip, &[miner]).await;
    for sql in [
        "DELETE FROM transaction_outputs WHERE txid = ANY($1)",
        "DELETE FROM transaction_inputs WHERE txid = ANY($1)",
    ] {
        sqlx::query(sql).bind(&txids).execute(&pool).await.unwrap();
    }

    const REWARD: i64 = 26_041_666;
    for height in base..=tip {
        let hash = block_hash(height);
        let time = 1_800_000_000 + u64::from(height - base) * 25;
        let tx = coinbase_tx(&txid(height), height, &hash, miner, REWARD);
        w.batch_insert_with_header_and_flows(height, &hash, time, &[tx], &[], &header(time))
            .await
            .expect("insert failed");
    }

    // Partial evidence is the expected shape once the capture budget is reached.
    let raw: Vec<(String, String)> = (fork..fork + 10)
        .map(|height| (block_hash(height), "aabbccdd".to_string()))
        .collect();
    let started = std::time::Instant::now();
    let rolled_back = w
        .rollback_from_height_with_raw(fork, "deep reorg regression", &raw)
        .await
        .expect("rollback failed");
    println!(
        "rolled back {rolled_back} blocks in {} ms",
        started.elapsed().as_millis()
    );
    assert_eq!(rolled_back, DEPTH);

    let count = |sql: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(sql)
                .bind(i64::from(base))
                .bind(i64::from(tip))
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    assert_eq!(
        count("SELECT count(*) FROM blocks WHERE height BETWEEN $1 AND $2").await,
        1
    );
    assert_eq!(
        count("SELECT count(*) FROM transactions WHERE block_height BETWEEN $1 AND $2").await,
        1
    );
    assert_eq!(
        count("SELECT count(*) FROM orphaned_blocks WHERE height BETWEEN $1 AND $2").await,
        i64::from(DEPTH)
    );
    assert_eq!(
        count("SELECT count(*) FROM orphaned_blocks WHERE height BETWEEN $1 AND $2 AND raw_hex IS NOT NULL").await,
        10
    );
    assert_eq!(
        count("SELECT count(*) FROM orphaned_transactions WHERE block_height BETWEEN $1 AND $2")
            .await,
        i64::from(DEPTH)
    );
    let depth: i32 = sqlx::query_scalar("SELECT depth FROM fork_events WHERE fork_height = $1")
        .bind(i64::from(fork))
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(depth, DEPTH as i32);
    assert_eq!(
        address_row(&pool, miner).await,
        Some((REWARD, REWARD, 0, 1)),
        "the surviving block alone must remain in the address summary"
    );

    clear_archives().await;
    cleanup(&pool, base, tip, &[miner]).await;
}

/// Observer-only orphan archive (migration 045): a real mainnet block captured
/// by observers loses to a different canonical hash at its height.
#[tokio::test]
async fn observer_orphan_archive_is_idempotent_and_never_touches_node_archives() {
    use crate::config::Network;
    use crate::db::observer_orphans::{
        archive_pass, external_prevouts, parse_captured_block, ArchiveOptions,
    };
    let _serial = ROLLBACK_TESTS.lock().await;
    let pool = test_pool().await;
    let w = writer().await;
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("../tests/fixtures/parser-blocks.json")).unwrap();
    let fixture = rows
        .iter()
        .find(|r| r["network"] == "mainnet" && r["height"] == 3_428_142)
        .unwrap();
    let height = 3_428_142u32;
    let hash = fixture["hash"].as_str().unwrap().to_owned();
    let raw = hex::decode(fixture["hex"].as_str().unwrap()).unwrap();
    let parsed = parse_captured_block(&raw, &hash, height, Network::Mainnet).unwrap();
    let (seed_txid, seed_vout) = external_prevouts(&parsed.transactions)[0].clone();
    let canonical = "ab".repeat(32);
    let miner = "tTESTobserverorphanminer000000000";

    let reset = || async {
        sqlx::query("DELETE FROM observer_orphan_blocks WHERE hash = $1")
            .bind(&hash)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM captured_blocks WHERE hash = $1")
            .bind(&hash)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM transaction_outputs WHERE txid = $1")
            .bind(&seed_txid)
            .execute(&pool)
            .await
            .unwrap();
        cleanup(&pool, height - 1, height, &[miner, "t1TESTseededprevout"]).await;
    };
    reset().await;

    let tx = coinbase_tx(&"ac".repeat(32), height, &canonical, miner, 50_000_000);
    w.batch_insert_with_header_and_flows(
        height,
        &canonical,
        1_700_000_000,
        &[tx],
        &[],
        &header(1_700_000_000),
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO captured_blocks (hash,network,height,previous_block_hash,timestamp,first_seen_at,raw_block) \
         VALUES ($1,'mainnet',$2,$3,$4,now(),$5)",
    )
    .bind(&hash)
    .bind(height as i64)
    .bind(&parsed.header.previous_block_hash)
    .bind(parsed.header.time as i64)
    .bind(&raw)
    .execute(&pool)
    .await
    .unwrap();
    // One prevout is known canonically (written by the indexer's own path);
    // exact integer zatoshis must carry over.
    let seed_value = 9_007_199_254_740_993i64;
    let mut parent = coinbase_tx(&seed_txid, height - 1, &"ad".repeat(32), miner, 0);
    parent.vout = (0..=seed_vout)
        .map(|n| TransparentOutput {
            n,
            value: if n == seed_vout { seed_value } else { 0 },
            address: Some(
                if n == seed_vout {
                    "t1TESTseededprevout"
                } else {
                    miner
                }
                .to_string(),
            ),
            script_type: "pubkeyhash".to_string(),
            script_pub_key: None,
            pubkey_exposures: vec![],
        })
        .collect();
    parent.vout_count = parent.vout.len() as u16;
    parent.transparent_value_out = seed_value;
    w.batch_insert_with_header_and_flows(
        height - 1,
        &"ad".repeat(32),
        1_699_999_000,
        &[parent],
        &[],
        &header(1_699_999_000),
    )
    .await
    .unwrap();

    let counts = || async {
        let row: (i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM observer_orphan_blocks WHERE hash=$1),
                    (SELECT count(*) FROM observer_orphan_transactions WHERE block_hash=$1),
                    (SELECT count(*) FROM observer_orphan_transaction_inputs WHERE block_hash=$1),
                    (SELECT count(*) FROM observer_orphan_transaction_outputs WHERE block_hash=$1),
                    (SELECT count(*) FROM orphaned_blocks WHERE hash=$1)
                  + (SELECT count(*) FROM orphaned_transactions WHERE block_hash=$1)",
        )
        .bind(&hash)
        .fetch_one(&pool)
        .await
        .unwrap();
        row
    };
    let options = ArchiveOptions {
        dry_run: true,
        limit: 1_000,
        rearchive: false,
    };
    let dry = archive_pass(&pool, Network::Mainnet, options)
        .await
        .unwrap();
    assert!(dry.candidates >= 1 && dry.archived >= 1);
    assert_eq!(counts().await, (0, 0, 0, 0, 0), "dry run writes nothing");

    let first = archive_pass(
        &pool,
        Network::Mainnet,
        ArchiveOptions {
            dry_run: false,
            ..options
        },
    )
    .await
    .unwrap();
    assert_eq!(first.failed, 0);
    let inputs: i64 = parsed
        .transactions
        .iter()
        .flat_map(|t| &t.vin)
        .filter(|i| !i.is_coinbase)
        .count() as i64;
    let outputs: i64 = parsed
        .transactions
        .iter()
        .map(|t| t.vout.len() as i64)
        .sum();
    let expected = (1, parsed.transactions.len() as i64, inputs, outputs, 0);
    assert_eq!(counts().await, expected);

    let block: (String, i32, i32, String, bool, Option<i64>) = sqlx::query_as(
        "SELECT canonical_hash, size, transaction_count, source,
                block_metadata->'final_sapling_root' = 'null'::jsonb,
                (block_metadata->>'total_fees')::bigint
         FROM observer_orphan_blocks WHERE hash=$1",
    )
    .bind(&hash)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(block.0, canonical);
    assert_eq!(block.1 as usize, raw.len());
    assert_eq!(block.2 as usize, parsed.transactions.len());
    assert_eq!(block.3, "observer");
    assert!(block.4);
    let seeded: (Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT value, address FROM observer_orphan_transaction_inputs
         WHERE block_hash=$1 AND prev_txid=$2 AND prev_vout=$3",
    )
    .bind(&hash)
    .bind(&seed_txid)
    .bind(seed_vout as i32)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        seeded,
        (
            Some(9_007_199_254_740_993),
            Some("t1TESTseededprevout".into())
        )
    );
    // Every other external prevout is unknown here: values and fees stay NULL.
    let (null_values, unresolved, null_fee_txs): (i64, i32, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM observer_orphan_transaction_inputs WHERE block_hash=$1 AND value IS NULL),
                (SELECT unresolved_inputs FROM observer_orphan_blocks WHERE hash=$1),
                (SELECT count(*) FROM observer_orphan_transactions
                  WHERE block_hash=$1 AND NOT is_coinbase AND fee IS NULL AND total_input IS NULL)",
    )
    .bind(&hash)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(null_values, unresolved as i64);
    assert!(unresolved > 0 && null_fee_txs > 0);
    assert_eq!(
        block.5, None,
        "a block with an unknown fee has no fee total"
    );

    // Idempotent: nothing left to do, and a forced rebuild leaves identical rows.
    let again = archive_pass(
        &pool,
        Network::Mainnet,
        ArchiveOptions {
            dry_run: false,
            ..options
        },
    )
    .await
    .unwrap();
    assert_eq!(again.archived, 0);
    let rebuilt = archive_pass(
        &pool,
        Network::Mainnet,
        ArchiveOptions {
            dry_run: false,
            rearchive: true,
            ..options
        },
    )
    .await
    .unwrap();
    assert!(rebuilt.archived >= 1);
    assert_eq!(counts().await, expected);

    // Once the node archives the hash itself (a real reorg), the observer copy
    // goes and the node row is untouched.
    sqlx::query("INSERT INTO orphaned_blocks (height, hash, source) VALUES ($1,$2,'indexer')")
        .bind(height as i64)
        .bind(&hash)
        .execute(&pool)
        .await
        .unwrap();
    let stale = archive_pass(
        &pool,
        Network::Mainnet,
        ArchiveOptions {
            dry_run: false,
            ..options
        },
    )
    .await
    .unwrap();
    assert!(stale.stale_archives >= 1);
    assert_eq!(counts().await, (0, 0, 0, 0, 1));
    let source: String = sqlx::query_scalar("SELECT source FROM orphaned_blocks WHERE hash=$1")
        .bind(&hash)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(source, "indexer");

    reset().await;
}
