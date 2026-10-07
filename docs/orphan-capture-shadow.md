# Experimental orphan-evidence capture

This is a filesystem-only trial of `NonFinalizedStateChange` capture. It does
not access PostgreSQL, insert orphan rows, or change the displayed orphan rate.
It is disabled in normal live indexing unless both `ENABLE_ORPHAN_CAPTURE=true`
and `ORPHAN_CAPTURE_PATH` are explicitly configured. Do not enable it for
unattended production collection yet: retention/export and real competing-fork
recovery remain release gates.

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

Before enabling an API/rate source: implement bounded retention/export, verify
contextually valid competing forks and restored branches on an isolated node,
exercise slow-consumer/restart/node-session transitions, measure on-server
memory/latency/IO under representative load, and coordinate a reviewed schema,
API method/coverage contract and rate-source start date. Never infer complete
network coverage from healthy transport or one observer.
