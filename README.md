# CipherScan Rust Indexer

High-performance Zcash blockchain indexer written in Rust. Reads directly from Zebra's RocksDB state for maximum speed. Powers [CipherScan](https://cipherscan.app).

## Features

- **Direct RocksDB access**: No RPC overhead, reads Zebra's state directly
- **~100 blocks/sec backfill**: 20-50x faster than JSON-RPC indexing
- **Live mode with gRPC**: Instant block notifications via Zebra's gRPC stream
- **Reorg handling**: Automatic fork detection, rollback, and orphan archival
- **Full Ironwood/NU6.3 support**: v6 transactions, Ironwood pool balances, anchors
- **Shielded flow classification**: Shield/deshield detection across all pools
- **Health monitoring**: Telegram alerts, heartbeat tracking, systemd integration
- **PostgreSQL output**: Atomic batch writes with COPY protocol

## Requirements

- Rust 1.97.1 (pinned by `rust-toolchain.toml`)
- Running Zebra node with synced state
- PostgreSQL 14+
- ~50GB disk space for the indexed database

## Installation

```bash
# Clone the repository
git clone https://github.com/Kenbak/cipherscan-rust.git
cd cipherscan-rust

# Build release binary
cargo build --release

# Binary will be at ./target/release/cipherscan-indexer
```

## Configuration

Create a `.env` file or set environment variables:

```bash
# Required: Path to Zebra/Zakura's RocksDB state
ZEBRA_STATE_PATH=~/.cache/zakura/state/v29/mainnet

# Required: PostgreSQL connection URL
DATABASE_URL=postgres://user:password@localhost/zcash_explorer

# Optional: Network (mainnet or testnet)
NETWORK=mainnet

# Optional: Zebra gRPC for instant live notifications
ZEBRA_GRPC_URL=http://127.0.0.1:8230

# Optional: Telegram alerting for health checks
TELEGRAM_BOT_TOKEN=YOUR_BOT_TOKEN
TELEGRAM_CHAT_ID=YOUR_CHAT_ID

# Optional: health thresholds and repeat cooldown
INDEXER_MAX_LAG=3
INDEXER_MAX_CONSECUTIVE_FAILURES=0
INDEXER_MAX_HEARTBEAT_AGE_SECONDS=600
INDEXER_ALERT_COOLDOWN_SECONDS=1800
INDEXER_HEALTH_TIMEOUT_SECONDS=45
```

## Usage

### Commands

```bash
# Show help
./target/release/cipherscan-indexer --help

# Analyze Zebra's database structure
./target/release/cipherscan-indexer analyze

# Show indexer status
./target/release/cipherscan-indexer status

# Show machine-readable status for monitoring
./target/release/cipherscan-indexer status --json

# Return non-zero if lag or failures exceed thresholds
./target/release/cipherscan-indexer health

# Override thresholds explicitly
./target/release/cipherscan-indexer health --max-lag 3 --max-consecutive-failures 0

# Machine-readable health output
./target/release/cipherscan-indexer health --json

# Backfill from genesis (or checkpoint) to current tip
./target/release/cipherscan-indexer backfill

# Backfill specific range
./target/release/cipherscan-indexer backfill --from 3000000 --to 3100000

# Follow chain tip in real-time
./target/release/cipherscan-indexer live

# Validate against production database
./target/release/cipherscan-indexer validate \
  --prod-db "postgres://user:pass@localhost/prod_db" \
  --test-db "postgres://user:pass@localhost/test_db" \
  --from-height 3200000 \
  --to-height 3200100
```

### Validation Mode

The `validate` command is essential before replacing the Node.js indexer:

1. Indexes a range of blocks into a test database
2. Compares every field with the production database
3. Reports any mismatches with detailed diffs
4. Benchmarks performance

```bash
# Validate 10,000 blocks
./target/release/cipherscan-indexer validate \
  --from-height 3190000 --to-height 3200000 \
  --prod-db "postgres://..." \
  --test-db "postgres://..."
```

Expected output:
```
🎉 VALIDATION PASSED! Rust indexer matches production data.

🚀 Performance:
   Rust: 102.3s for 10001 blocks (97.8 blk/s, 691.2 tx/s)

🔍 Data Comparison:
   Transactions: 71234/71234 matched (100.0%)
   Outputs:      129456/129456 matched (100.0%)
   Inputs:       101234/101234 matched (100.0%)
   Flows:        8923/8923 matched (100.0%)
```

## Database Schema

Uses the same PostgreSQL schema as the Node.js indexer. Key tables:

| Table | Description |
|-------|-------------|
| `blocks` | Block headers with all fields (version, difficulty, nonce, etc.) |
| `transactions` | Transaction data with fees, value balances, counts |
| `transaction_inputs` | Transparent inputs with resolved addresses and values |
| `transaction_outputs` | Transparent outputs |
| `shielded_flows` | Shield/deshield flows for privacy analysis |
| `indexer_state` | Checkpoint for resumable indexing |

### Schema Setup

```bash
# Apply the schema to a new database
psql -U user -d zcash_test_rust -f schema/postgres.sql

# Or use the migration for existing databases
psql -U user -d zcash_explorer -f schema/migrations/001_rust_indexer_support.sql
```

## Architecture

```
src/
├── main.rs              CLI definitions + dispatch (329 lines)
├── config.rs            Environment-based configuration
├── util.rs              Shared utilities (hash encoding, timestamps)
├── commands/
│   ├── analyze.rs       RocksDB structure analysis
│   ├── backfill.rs      Bulk indexing (genesis → tip)
│   ├── compare.rs       Production data comparison
│   ├── inspect.rs       Block/transaction inspection
│   ├── live.rs          Chain-tip follower
│   ├── repair.rs        Fee recalculation (Ironwood fix)
│   ├── status.rs        Health + status reporting
│   ├── validate.rs      Full index validation suite
│   └── verify.rs        RPC cross-check verification
├── db/
│   ├── rocks.rs         Zebra RocksDB reader
│   ├── postgres.rs      PostgreSQL writer (bulk + rowwise)
│   ├── rpc.rs           Zebra JSON-RPC client
│   └── grpc.rs          Zebra gRPC chain-tip stream
├── indexer/
│   ├── mod.rs           Backfill + live orchestration, reorg handling
│   └── transactions.rs  Transaction parsing (zebra-chain)
└── models/
    ├── transaction.rs   Transaction/Input/Output data types
    └── flow.rs          Shielded flow classification
```

Data flow:
```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Zebra Node    │────▶│  Rust Indexer   │────▶│   PostgreSQL    │
│   (RocksDB)     │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │
        │                       ├── Block parsing (zebra-chain)
        │                       ├── Transaction parsing
        │                       ├── Input resolution (UTXO lookup)
        │                       ├── Flow generation
        │                       └── Batch PostgreSQL writes
        │
        └── Direct column family access:
            ├── block_header_by_height
            ├── hash_by_height
            ├── tx_loc_by_hash
            ├── utxo_by_out_loc
            └── height_by_hash
```

## Performance

Benchmarks on AMD EPYC (8 cores, 32GB RAM, NVMe SSD):

| Metric | Node.js Indexer | Rust Indexer | Speedup |
|--------|-----------------|--------------|---------|
| Blocks/sec | ~2-5 | ~100 | **20-50x** |
| Transactions/sec | ~20-50 | ~700 | **15-35x** |
| Memory usage | ~500MB | ~100MB | **5x less** |

## Data Indexed

### Blocks
- Height, hash, timestamp
- Version, difficulty, bits, nonce
- Merkle root, final Sapling root
- Previous block hash
- Size, transaction count
- Total fees, miner address

### Transactions
- txid, block height, version, locktime, expiry height
- Size, fee (calculated from inputs - outputs - value balances)
- Input/output counts
- Value balances (Sapling, Orchard, Ironwood)
- Shielded component counts (joinsplits, sapling spends/outputs, orchard/ironwood actions)
- Anchor roots (Orchard, Ironwood) for ZIP-318 compliance analysis
- is_coinbase flag

### Transparent Inputs
- Previous output reference (txid, vout)
- Resolved address and value (via UTXO lookup)
- Script signature

### Transparent Outputs
- Address, value
- Script type, script hex

### Shielded Flows
- Flow type: shield or deshield
- Pool: sapling, orchard, ironwood, or mixed
- Amount (net total)
- Associated transparent addresses

## Troubleshooting

### "RocksDB: Invalid argument"
Zebra is still running. Stop Zebra or wait for it to release the lock.

### "column family not found"
The Zebra state version may be different. Check `ZEBRA_STATE_PATH` points to the correct version (e.g., `v29` for Zakura 1.5.0).

### Slow performance
- Ensure NVMe SSD for both RocksDB and PostgreSQL
- Increase PostgreSQL `shared_buffers` and `work_mem`
- Use `--release` build (debug builds are 10x slower)

## Health Monitoring

The first production-ready monitoring path lives under `deploy/`:

- `deploy/check-indexer-health.sh`
- `deploy/cipherscan-rust-health.service`
- `deploy/cipherscan-rust-health.timer`

How it works:

1. systemd runs the health check every 5 minutes by default
2. the script verifies `cipherscan-rust.service` is active, then calls `cipherscan-indexer health --json`
3. healthy runs send no Telegram message
4. unhealthy runs send one Telegram alert when the problem first appears
5. repeated alerts are suppressed unless the failure fingerprint changes or the cooldown expires
6. one recovery message is sent when the indexer becomes healthy again

The monitoring path is optimized to avoid reopening RocksDB on each run. `health` now relies on PostgreSQL state plus Zebra RPC, checks polling liveness separately from pending-work progress, and the steady-state cost is one lightweight health check every 5 minutes with zero outbound Telegram calls while healthy.

### Install The Timer

```bash
sudo cp deploy/cipherscan-rust-health.service /etc/systemd/system/
sudo cp deploy/cipherscan-rust-health.timer /etc/systemd/system/
sudo cp deploy/check-indexer-health.sh $INSTALL_DIR/deploy/
sudo chmod +x $INSTALL_DIR/deploy/check-indexer-health.sh

sudo systemctl daemon-reload
sudo systemctl enable --now cipherscan-rust-health.timer
sudo systemctl status cipherscan-rust-health.timer
```

### Telegram Setup

Add these to your `.env` file:

```bash
TELEGRAM_BOT_TOKEN=YOUR_BOT_TOKEN
TELEGRAM_CHAT_ID=YOUR_CHAT_ID
INDEXER_MAX_LAG=3
INDEXER_MAX_CONSECUTIVE_FAILURES=0
INDEXER_MAX_HEARTBEAT_AGE_SECONDS=600
INDEXER_ALERT_COOLDOWN_SECONDS=1800
```

Recommended behavior for the first version:

- `INDEXER_MAX_LAG=3` means alert if the live checkpoint falls more than 3 blocks behind the local Zebra tip
- `INDEXER_MAX_CONSECUTIVE_FAILURES=0` means alert on the first persistent failure state
- `INDEXER_MAX_HEARTBEAT_AGE_SECONDS=600` bounds successful tip polling and progress on pending work. A caught-up writer may wait indefinitely for a block while its tip polls remain fresh. `last_success_at` retains the actual last committed ingestion time. The durable `pending_work_since` clock starts when the writer observes outstanding blocks or a reorg check fails; repeated retries cannot reset it. Pending progress is measured from the later of that clock and the last successful ingestion, so a new block after a long idle period gets the full grace window. The pending clock clears only after a successful canonical-chain check confirms the writer is caught up. Missing or future clocks are unhealthy; a newly arrived RPC tip not yet observed by the writer receives bounded grace from its last successful tip poll.
- `INDEXER_ALERT_COOLDOWN_SECONDS=1800` means resend at most every 30 minutes unless the failure category changes. JSON `reason_codes` provide stable categories; changing ages, heights, and metrics do not bypass the cooldown.
- `INDEXER_HEALTH_TIMEOUT_SECONDS=45` bounds the health command; a stuck RPC or database read produces a timeout alert. The monitor requires GNU `timeout` and Python 3 (the standard server environment).
- the systemd timer defaults to every 5 minutes to keep monitoring overhead low while still alerting fast enough for operator response

### Test It

```bash
sudo systemctl start cipherscan-rust-health.service
sudo journalctl -u cipherscan-rust-health.service -n 50 --no-pager
```

## Development

```bash
# Fast compiler/lint parity with CI
make verify-fast

# Full CI-equivalent check, including an isolated disposable PostgreSQL cluster
# (requires local PostgreSQL server tools: initdb, pg_ctl, psql, createdb)
make verify-full

# Check for errors without building
cargo check

# Format code
cargo fmt

# Run with debug logging
RUST_LOG=debug cargo run -- status
```

## License

MIT — see [LICENSE](LICENSE) file.

## Related Projects

- [Zebra](https://github.com/ZcashFoundation/zebra) - Zcash node implementation
- [CipherScan Explorer](https://github.com/Kenbak/zcash-explorer) - Frontend and API


### Zakura 1.5.0 / NU7 preparation

The indexer pins `zakura-chain` 8.0.0 to Zakura tag `v1.5.0`; Cargo.lock
records the exact source. Preserve a stopped-node state snapshot before upgrading
Zakura: state format 29 cannot be safely reopened by the previous node binary.
Update `ZEBRA_STATE_PATH` to the migrated v29 directory on each host.

Live gRPC tip notifications remain preferred. `LIVE_POLL_INTERVAL_SECONDS`
controls fallback polling (default 5 seconds, clamped to 1–60), independently of
the consensus block target. Full-block gRPC remains separately opt-in.

Regression tests retain real historical v4/v5/v6 blocks and exercise the NU7
branch ID structurally. Synthetic branch-ID transactions are not signed NU7
activation fixtures. This maintenance release does not certify sustained-load
or official testnet activation compatibility.
