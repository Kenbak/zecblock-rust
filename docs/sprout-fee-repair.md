# Sprout fee repair

Status (2026-11-01): code and migration ready; **not applied or run on any
production host**. Running the migration, the repair, the downstream recomputes
or a deploy requires the product owner's explicit go-ahead.

## Defect

Before this change the indexer ignored Sprout JoinSplit values:

- The fee was `transparent_in + Sapling + Orchard + Ironwood - transparent_out`.
  A t→Sprout deposit stored the whole deposit as fee. A Sprout withdrawal or a
  Sprout→Sapling migration came out negative and was then stored as `0`.
- `fee.unwrap_or(0)` stored unknown fees as `0` instead of NULL.
- `blocks.total_fees` summed those values.
- v2 (pre-Overwinter) JoinSplits were never counted. `has_sprout`,
  `sprout_joinsplit_count` and `has_shielded_data` are false/0 for every
  v2 Sprout transaction.
- `repair-fees` (Ironwood) selected nonexistent columns and could not run.
  `integrity repair` recomputed the fee without Sprout and without NULL handling.

Measured on the public mainnet dataset (2026-11-01):

| Measure | Value |
|---|---|
| Transactions below height 347500 (Overwinter) | 3,109,987 |
| Of those, flagged shielded | 0 |
| Of those, stored fee > 1 ZEC | 181,191, totalling 5,359,750.77 ZEC |
| Example: v2 `99c3dfa1…af19` (h 100000) | stored 1,000,020,000 zat, true fee 10,000 |
| Example: v4 `9329552a…c047` (h 500758) | stored 4,625,281,439,411 zat, true fee 10,000 |
| Example: v4 `c0174bcd…7e1a` (h 3537885) | stored 0, true fee 20,000 |

**Why heights below 347501 were never flagged.** Commit `4b87151` (2026-01-21,
"Use zebra-chain for transaction parsing") matched `V1 { .. } | V2 { .. }` to
zero JoinSplits. It was the first Rust parser of whole-chain history, so every
v2 row it wrote, or that `backfill-metadata` rewrote, has `has_sprout=false`,
`sprout_joinsplit_count=0` and `has_shielded_data=false`. Overwinter activates
at 347500, and the first v3 transaction (whose JoinSplits were counted) is at
347501, which is where the public dataset's first shielded transaction appears.

**Independent node audit (2026-11-01, sibling session).** JoinSplits were
confirmed in transactions stored with `has_sprout=false`, for example
`eba96965633a…` (h150000), `fe5eff321d75…` and `c852de496bae…` (h250000), and
`fd7020561d29…` (h300000). Sapling, Orchard and Ironwood balances and counts,
transparent values and non-Sprout fees matched the node on 308 sampled txs in
37 blocks plus 30 Ironwood txs. Orchard fees of 2^32+N zat (for example
`b20ca0332fec…` at h2891527) are real on-chain overpayments that the coinbase
claimed. This repair recomputes those from the node, so it leaves them unchanged.

## Fix

- The parser sums `vpub_new - vpub_old` for v2–v4 into `sprout_value_balance`.
  Positive means value leaving Sprout, the same sign as the other pools. It
  also counts v2 JoinSplits.
- `Transaction::compute_fee` is the single fee formula, used by live indexing
  and block backfill: transparent in + Sprout + Sapling + Orchard + Ironwood −
  transparent out. A negative result or coinbase gives `None`, which is
  written as NULL.
- `blocks.total_fees` is NULL when any non-coinbase fee in the block is unknown.
- Migration **041_sprout_value_balance.sql** adds `value_balance_sprout` to
  `transactions` and `orphaned_transactions`.
  - It uses a fast metadata default of 0, then drops the default, so writers
    that omit the column store NULL.
  - `transactions.value_balance` keeps its old meaning: Sapling + Orchard +
    Ironwood.
- Flows now include Sprout. t→Sprout is `shield`/`sprout`, Sprout→t is
  `deshield`/`sprout`, and a Sprout+other-pool transaction with transparent
  value is `mixed`. A pure Sprout→Sapling migration with no transparent I/O
  produces no boundary flow, like Orchard→Ironwood. The `shielded_flows` CHECK
  constraint already allowed `sprout`.

## Repair command

```sh
cipherscan-indexer repair-sprout-fees --from 0 --to <H> --dry-run --samples 50
cipherscan-indexer repair-sprout-fees --from 0 --to <H> --window 1000
```

- Reads raw blocks from Zebra's RocksDB (`ZEBRA_STATE_PATH`). `--to` must not
  exceed the node tip.
- For every block that contains a JoinSplit, or that the database flags
  `has_sprout`, it resolves every prevout from node state and recomputes
  fee, `value_balance_sprout`, the JoinSplit count/flags and the block total
  from the node.
- Writes only rows that differ, guarded by `block_hash`. Blocks whose stored
  hash differs from the node are skipped and reported, as are missing rows.
- Takes the shared block-write lock and per-height locks in the same order
  as block writers, so reorg rollback serializes against it.
- Rewrites `shielded_flows` for a Sprout transaction only when the
  classification changed (delete, then insert).
- Does **not** rewrite `total_input`/`total_output`. Transparent mismatches
  and non-Sprout fee mismatches are reported for the separate `integrity`
  repair.
- Resumable: `indexer_state.sprout_fee_repair_height` advances per committed
  window. A dry run never writes or checkpoints.
- Dry run reports counts (tx/fee/NULL/Sprout-balance/JoinSplit/block-total/flow
  changes, the summed old−new fee delta, and anomalies) plus sample diffs.

Suggested order: first a dry run and real run of `--from 0 --to 347500` (all
v2 history, where every Sprout row is wrong), then `--from 347501 --to <tip>`.
Run the full range up to the current tip after the new indexer binary is live,
so every row written before the deploy is covered. Sprout stops changing at NU7
(height 3,543,405): v4 transactions, and with them Sprout spends, are invalid
afterwards. A final run to a height above activation therefore leaves Sprout
history final.

The write volume is about the number of affected rows: transactions (more than
181k before Overwinter alone, plus later Sprout), their blocks and their flows.
Check the Ask logical-replication guard before the real run: the feed is
disabled when the slot retains ≥48 GiB of WAL or free disk falls below
256 GiB/20%. Small windows keep each transaction short.

## Downstream recompute after the repair

Persisted (needs action):

1. **Ask replica** (`server/deploy/ask-analytics/subscriber-core-v1.sql`):
   `blocks.total_fees`, `transactions.fee` and `shielded_flows` replicate
   automatically. `value_balance_sprout` is not published; add it to
   `server/api/scripts/profile-ask-logical-sync.js` if Ask should expose it.
2. **`analytics_meta.activity_daily` / `flow_daily`**
   (`refresh-ask-summaries.js`): replicated UPDATEs mark dirty days through
   triggers. The timer refreshes at most 100 days per run and both datasets
   stay hidden while any completed day is dirty. A full-history repair dirties
   about 3,650 days, so expect at least 37 runs. Done when
   `SELECT count(*) FROM analytics_meta.summary_dirty_days WHERE date<CURRENT_DATE`
   returns 0.
3. **`analytics_history_daily.fees`**
   (`server/jobs/backfill-analytics-history.js`): there is no date-range
   recompute; forcing a gap replays every later day. Needs a fees-only jsonb
   patch script (precedent: `server/scripts/repair-mining-attribution.js`).
   Afterwards delete Redis `analytics:fee-dist:v2:*`. The job's own
   invalidation uses the stale key `analytics:fee-dist:all`.
4. **`metric_anomalies` `daily_fees_zat`** (upsert-only): delete the range,
   then run `node server/jobs/detect-anomalies.js --days=N` (N ≤ 3660).
5. **`trading_signals.fee_pressure`**: `node server/signals/compute.js --backfill`.
6. **Shielded transaction counts** (`has_sprout`/`has_shielded_data` change for
   v2 history):
   - **`privacy_stats`** (all-time shielded/transparent/mixed/fully-shielded
     counts and percentage): recomputed by the next
     `server/jobs/update-privacy-stats.js` run, which counts the whole table
     through `SHIELDED` in `server/lib/transaction-activity.js`.
   - **`privacy_trends_daily` counts**: the job reconciles only the last 7 days.
     For history, preview with
     `node server/scripts/repair-activity-counts.js --start=2016-10-31 --end=<first uncovered completed day>`
     (2016-10-31 is the `HISTORY_START` constant),
     then add `--apply`. It rewrites counts and percentage only, never
     balances or scores.
   - **Historical privacy scores** stored in `privacy_trends_daily` use 30-day
     transaction windows, so 2016–2018 scores are affected.
     `server/scripts/backfill-privacy-trends.js --skip-rpc --exact --days=N`
     recomputes them from stored pool columns. Check that it updates existing
     rows the intended way before applying, because `repair-activity-counts.js`
     deliberately leaves scores unchanged.
   - **Ask `activity_daily.shielded_transactions`/`transparent_transactions`**:
     replicated `has_sprout` UPDATEs mark those days dirty (item 2).
   - **Computed per request:** `/v1/shielded-pools/activity` Sprout counts
     (`server/api/lib/pool-activity.js`) and the bot's Sprout exclusions.
7. **Changed flows only**: `REFRESH MATERIALIZED VIEW CONCURRENTLY flow_daily`;
   `server/jobs/refresh-turnstile.js --date=…` per affected date (or
   `--rebuild`); `server/signals/build-pool-realized-cap.js --rebuild`, then
   the MVRV rebuild.

Computed per request (expire caches): `issuance_query` fees and miner revenue,
mining pool rewards (`mining.js`, Redis `mining:history-v3:*`), network stats,
fee-distribution charts, privacy fee lanes, NU7 accounting, block and tx pages
(Next.js revalidate ≤300 s, `/v1` max-age 300).

Explorer code follow-ups, separate from this repository:

- `app/block/[height]/components/transformBlockData.ts` recomputes fees from
  Sapling/Orchard/Ironwood only and floors negatives at 0. Use `total_fees`/`fee`.
- NULL is shown as 0 in `mining.js`, `network-analytics.js`, `blocks.js`, the
  tx-detail metadata, `transform-tx-data.ts` and `lib/seo.ts`. Preserve unknown.
- `tx-detail.js` should expose `valueBalanceSprout`/`valueBalanceSproutZat`, and
  only after the repair checkpoint covers the history.
- The bot's `VALID_FLOWS` check ignores Sprout value.
