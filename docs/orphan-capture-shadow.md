# Competing-block capture

`orphan-collect` is the continuous database-backed mode. `orphan-shadow` remains
an isolated filesystem-only diagnostic and does not change public rates.

Apply migration **035_live_block_capture.sql** before starting the collector.
Run it as the separate `deploy/cipherscan-orphan-collector.service`, with an
independently installed tested binary and a protected environment file containing
DATABASE_URL, NETWORK, ZEBRA_RPC_URL, ZEBRA_GRPC_URL and the node's RPC credentials.
Use a dedicated DB login with SELECT on blocks and SELECT/INSERT/UPDATE only on
captured_blocks, block_capture_observers and block_capture_receipts. It must not
write blocks, transactions, balances, sync_state or the canonical indexer archive.
The DB's genesis must match the configured node network. Standby writers stay off.

Continuous mode fsyncs each block to a bounded local buffer, commits blocks and
per-observer receipts in one PostgreSQL transaction, then removes acknowledged
files. Hash primary keys make crash replay and duplicate delivery safe. Database
failure retains files; reconnect/heartbeat delivery retries. If the outage fills
the buffer, collection fails visibly and systemd retries after ten seconds.
No unacknowledged evidence is deleted to make room. Limits protect disk during
outages; successful delivery makes room continuously. The UI reports stale
collector heartbeats as unavailable and retains previously stored observations.
A collector with backlog is not reported healthy.

Raw bodies of matching canonical blocks more than 500 heights behind the indexed
tip are cleared in batches of 64. Metadata and per-observer receipts remain.
Competing bodies remain stored. This avoids indefinitely duplicating the entire
canonical blockchain. Resume markers keep the most recently observed tips within
the node request limit. They only suppress replay: forgetting an older marker
allows more retained blocks to replay, without deleting journal or database
evidence. Old markers remain usable across long outages instead of taking a fresh
baseline that could skip recoverable history. Oversized legacy checkpoints are
compacted automatically on startup. Outages/restarts remain explicitly unverified.

Public method **observed-block-capture-v2** unions indexer reorg archives with
captured competitors, deduplicates by full hash and compares against the current
indexed chain in one SQL snapshot. Captures ahead of indexed heights do not count.
Restored canonical hashes immediately stop counting. Archive attribution wins
when both sources contain a hash. Invalid/external-only reports stay excluded.
Header-time windows and fraction units are unchanged. Historical coverage remains
unverified; capture.startedAt describes only this new collection source, not
historical completeness or the node's peer-arrival time. Existing orphan detail
pages still describe the canonical indexer's archive; captured evidence is stored
separately and does not manufacture archived transactions or fork events.

Rollout: migrate, install/start the separate collector, verify fresh DB receipts
and bounded disk use, deploy frontend support for both method versions, then
activate the API's new source. Rollback stops the collector and restores the prior
API module; retain additive tables and buffered evidence. Check actual service
PID/artifact, canonical indexer health and standby inactivity independently.

Shadow trials:

Run against matching mainnet RPC and gRPC endpoints, using the usual RPC cookie
configuration, with a dedicated journal directory:

```sh
cipherscan-indexer orphan-shadow --journal /private/path/orphan-trial \
  --events 2 --timeout 240 --reconnect-after 1
```

`--timeout` is 1–900 seconds. `--events` is the minimum number of **new unique**
durably captured blocks required for success, not the number already retained.
`--reconnect-after` intentionally interrupts the stream once to test replay.
Restart the same command/journal to test process recovery and deduplication.
Use separate directories for separate observers and networks.

The collector checks the RPC network and compares the gRPC snapshot to the RPC
hash before accepting a subscription. Initial canonical and valid-fork tips
are a disclosed baseline, not a historical backfill. Subsequent subscriptions
resume from durable journal heads and the optional node receipt session; they
do not replace the checkpoint with a fresh canonical tip on reconnect.

The node is the consensus authority. Full deserialization, complete byte
consumption, block hash and coinbase height are checked locally. This establishes
payload integrity; it is not an independent consensus verifier. Node receipt
order is stored only with its optional source-local session, never as a public
timestamp or cross-node ordering claim.

Each binary record has bounded JSON metadata and the original raw block. File
and parent directory fsync precede checkpoint advancement. Existing records
are hash-deduplicated, exclusive OS file locking prevents concurrent journal
writers, and restart checks re-decode committed data before trusting it.
Recognized uncommitted `.tmp` files are removed under that lock on restart;
uncertain interruption coverage stays recorded.

Resource limits: eight queued block messages, a <=2,000,000-byte payload per
message (current parser bound), 4,096 records, and 256 MiB of committed record
bytes including envelopes. Health/checkpoint files use at most 64 KiB; a single
in-progress record is additional transient disk use. These are queue/journal
bounds, not a measured total process RSS limit. Decode/fsync use an independent
task, with file persistence moved off asynchronous executor workers. There is
no database connection pool. Queue stalls, disconnects, source-session changes,
invalid payloads and capacity failures remain visible. A full journal stops
capture without deleting evidence; canonical indexing continues.

`health.json` has a 15-second connected heartbeat, stopped state, reconnect
count, startup/uncertainty events and latest gap reason/time. `coverage` is always
`unverified`. Replayed retained blocks cannot prove that a short-lived branch
was not pruned during an outage. Source-local receipt ordering is not presently
used to assert gap-free delivery.

The summary compares up to 128 retained records with current RPC canonical
hashes. Remaining/failed checks are unresolved. `non_canonical_at_check` is a
reversible point-in-time branch status, not a permanent orphan classification.
Neither this status nor advertised hashes enter rate calculations.

Additional coverage validation should verify
contextually valid competing forks and restored branches on an isolated node,
exercise slow-consumer/restart/node-session transitions, measure on-server
memory/latency/IO under representative load, and coordinate a reviewed schema,
API method/coverage contract and rate-source start date. Never infer complete
network coverage from healthy transport or one observer.

## Coverage audit and timed gaps (migration 042)

The continuous collector (`orphan-collect`) now measures its own coverage:

- **Timed gaps.** Every interval where it was not streaming (process down,
  disconnected) is recorded with start/end/reason. `unobserved_ms` is the
  running total since `coverage_since`; `recent_gaps` keeps the latest 32;
  `outage_since` is set while an interval is open. Retained replay can still
  recover blocks from these intervals, so they bound unverified time, not
  missed blocks.
- **Fork-tip audit.** Every `CAPTURE_AUDIT_INTERVAL_SECONDS` (default 300,
  60–3600) a separate task asks the node for `getchaintips` and walks each
  `valid-fork` branch through captured parent links (pending journal first,
  then `captured_blocks`). A block missing on two consecutive audits goes into
  `block_capture_audit_misses`; if it is delivered later it is marked
  `captured_later_at`, never deleted.
- **Canonical stream-drop check.** The same audit counts the last 1,000
  settled canonical heights since collection start that are absent from
  `captured_blocks` (`audit_canonical_missing`).
- **Journal budget.** Pending (undelivered) bytes default to 1 GiB, about
  3.5 hours of maximum-size blocks at 25-second spacing, configurable with
  `CAPTURE_JOURNAL_MAX_BYTES` (64 MiB–16 GiB). The collector warns once the
  journal passes half full and reports `pending_bytes`/`journal_max_bytes`.

Limits: the audit only proves coverage relative to blocks this node validated.
A competing block that never reached the node is invisible to both. Apply
migration 042 before or after the binary; without it the collector keeps the
035 contract and the audit waits. The audit uses the role's second allowed
connection (`CONNECTION LIMIT 2`).

## Observer-only orphan archive

`archive-observer-orphans` parses retained observer-only orphan bodies into
`observer_orphan_blocks`, `observer_orphan_transactions`,
`observer_orphan_transaction_inputs` and `observer_orphan_transaction_outputs`
(migration **045_observer_orphan_archive.sql**). An observer-only orphan is a
captured block whose hash is in neither `blocks` nor `orphaned_blocks` while
`blocks` holds a different hash at the same height: the same rule as the
explorer's "Observers only" reorg list.

These tables are deliberately separate from `orphaned_*`. Node-reorg archives,
fork events, orphan rates, Ask analytics and open data keep their meaning; the
columns match so block pages can render both. Moving captures into `orphaned_*`
or any rate needs a separate release decision.

- Parsing uses the indexer's block/transaction parser and re-verifies the hash,
  full-input consumption and coinbase height of the captured bytes.
- Transparent prevouts resolve from the same block, then canonical
  `transaction_outputs`, then archived observer/node orphan outputs. An
  unresolved prevout keeps its input value and address, the transaction's
  `total_input` and `fee`, and the block's `total_fees` NULL. Amounts are
  integer zatoshis.
- `size` is the exact serialized block length. Final pool roots are NULL: raw
  headers carry a commitment hash and the node cannot report roots for a block
  it never adopted. `difficulty` is derived from the header bits.
- Each block is replaced atomically under the shared block-write lock, after
  re-checking observer-only status. A pass first deletes archives whose hash
  became canonical or was archived by a node reorg, and refreshes
  `canonical_hash`. Rows are keyed by hash so reruns are idempotent;
  `--rearchive` rebuilds current-version archives, and a version bump rebuilds
  older ones.
- It never writes canonical chain, accounting or node-reorg tables.

One-shot backfill (dry run first, then write):

```sh
cipherscan-indexer archive-observer-orphans --dry-run --limit 100000
cipherscan-indexer archive-observer-orphans --limit 100000
```

Ongoing: `deploy/cipherscan-observer-orphan-archive.service` runs
`--watch --interval 60`. Its DB login needs SELECT on blocks, orphaned_blocks,
transaction_outputs, orphaned_transaction_outputs, captured_blocks, and
SELECT/INSERT/UPDATE/DELETE on the four `observer_orphan_*` tables.
