//! CipherScan Rust Indexer
//!
//! Fast indexer that reads directly from Zebra's RocksDB state database.
//! ~100-1000x faster than JSON-RPC for backfills.
//!
//! Usage:
//!   cargo run --release -- analyze      # Analyze database structure
//!   cargo run --release -- backfill     # Index from start to tip
//!   cargo run --release -- live         # Follow chain tip
//!   cargo run --release -- status       # Show indexer status

mod commands;
#[cfg(test)]
mod postgres_integration_tests;

pub use cipherscan_indexer::{config, db, indexer, models, util};

use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::Config;

/// CipherScan Rust Indexer - High-performance Zcash blockchain indexer
#[derive(Parser)]
#[command(name = "cipherscan-indexer")]
#[command(version = "0.1.0")]
#[command(about = "Fast Zcash indexer reading directly from Zebra's RocksDB")]
struct Cli {
    /// Path to Zebra state directory
    #[arg(long, env = "ZEBRA_STATE_PATH")]
    zebra_path: Option<String>,

    /// PostgreSQL connection URL
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: Option<String>,

    /// Batch size for database operations
    #[arg(long, default_value = "1000")]
    batch_size: usize,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze Zebra's RocksDB structure
    Analyze,

    /// Run backfill from genesis (or checkpoint) to current tip
    Backfill {
        /// Start from specific height (overrides checkpoint)
        #[arg(long)]
        from: Option<u32>,

        /// Stop at specific height
        #[arg(long)]
        to: Option<u32>,
    },

    /// Run live indexer (follow chain tip)
    Live,

    /// Verify full-block gRPC delivery without database writes
    Shadow {
        /// Number of canonical tip events to verify
        #[arg(long, default_value = "1")]
        events: u32,
        /// Overall timeout in seconds
        #[arg(long, default_value = "180")]
        timeout: u64,
    },

    /// Capture non-finalized block evidence to an isolated bounded journal; no DB access
    OrphanShadow {
        #[arg(long)]
        journal: std::path::PathBuf,
        /// Minimum new unique blocks required for the trial to pass
        #[arg(long, default_value = "2")]
        events: u64,
        #[arg(long, default_value = "240")]
        timeout: u64,
        /// Exercise reconnect/resume after this many new durable captures
        #[arg(long)]
        reconnect_after: Option<u64>,
    },

    /// Show indexer status
    Status {
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },

    /// Return non-zero when indexer health is degraded
    Health {
        /// Maximum acceptable lag behind the local chain tip
        #[arg(long, default_value = "3")]
        max_lag: u32,

        /// Maximum acceptable consecutive failures before unhealthy
        #[arg(long, default_value = "0")]
        max_consecutive_failures: u32,

        /// Maximum acceptable age for live heartbeat state in seconds
        #[arg(long, env = "INDEXER_MAX_HEARTBEAT_AGE_SECONDS", default_value = "600")]
        max_heartbeat_age: u64,

        /// Maximum acceptable latency for the last committed live block
        #[arg(long, env = "INDEXER_MAX_INGEST_MS", default_value = "5000")]
        max_ingest_ms: u64,

        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },

    /// Decode and show specific block
    Block {
        /// Block height to show
        height: u32,
    },

    /// Verify parsing by comparing RocksDB data with RPC
    Verify {
        /// Block height to verify
        #[arg(long, default_value = "1000000")]
        height: u32,

        /// Number of blocks to verify
        #[arg(long, default_value = "10")]
        count: u32,

        /// Zebra RPC URL
        #[arg(long, env = "ZEBRA_RPC_URL", default_value = "http://127.0.0.1:8232")]
        rpc_url: String,

        /// Cookie file path for auth
        #[arg(
            long,
            env = "ZEBRA_RPC_COOKIE_FILE",
            default_value = "/root/.cache/zebra/.cookie"
        )]
        cookie_file: String,
    },

    /// Parse and display a transaction from RocksDB
    Tx {
        /// Block height
        height: u32,

        /// Transaction index within block
        #[arg(default_value = "0")]
        index: u16,
    },

    /// Compare Rust parsing with existing PostgreSQL data
    Compare {
        /// Number of transactions to sample
        #[arg(long, default_value = "50")]
        sample: usize,

        /// Start height for sampling
        #[arg(long, default_value = "3200000")]
        from_height: u32,

        /// PostgreSQL connection URL
        #[arg(long, env = "DATABASE_URL")]
        database_url: Option<String>,
    },

    /// Backfill only metadata columns (locktime, expiry_height, sapling/sprout counts)
    /// for existing transactions. Does NOT touch outputs, inputs, or flows.
    BackfillMetadata {
        /// Start from specific height (default: Overwinter activation = 347500)
        #[arg(long, default_value = "347500")]
        from: u32,

        /// Stop at specific height (default: chain tip)
        #[arg(long)]
        to: Option<u32>,

        /// Number of blocks to process per DB commit
        #[arg(long, default_value = "5000")]
        batch: u32,
    },

    /// Backfill anchor roots (orchard_anchor, ironwood_anchor) for existing
    /// transactions. Fetches raw tx bytes via RPC, parses with zakura-chain,
    /// and UPDATEs the transactions table.
    BackfillAnchors {
        /// Only process v6 transactions (Ironwood era). Faster but skips v5 Orchard anchors.
        #[arg(long)]
        v6_only: bool,

        /// Number of transactions per DB commit batch
        #[arg(long, default_value = "500")]
        batch: usize,
    },

    /// Reclassify nonstandard outputs as P2PK or bare-multisig.
    /// Scans transaction_outputs WHERE script_type = 'nonstandard' AND address IS NULL,
    /// re-parses raw scripts from Zebra RocksDB, and updates the DB.
    BackfillScripts {
        /// Number of outputs to process per DB commit batch
        #[arg(long, default_value = "5000")]
        batch: u32,
    },

    /// Full validation: index into test DB, compare with prod, benchmark
    Validate {
        /// Production database URL
        #[arg(long, env = "DATABASE_URL")]
        prod_db: Option<String>,

        /// Test database URL (will be created/cleared)
        #[arg(long)]
        test_db: String,

        /// Start height for validation
        #[arg(long, default_value = "3200000")]
        from_height: u32,

        /// End height for validation
        #[arg(long, default_value = "3200100")]
        to_height: u32,
    },

    /// Recalculate fees for transactions with nonzero ironwood_value_balance.
    /// Fixes fees that were computed without including the Ironwood pool balance.
    RepairFees {
        /// Number of transactions to process per DB commit batch
        #[arg(long, default_value = "5000")]
        batch: usize,

        /// Dry-run: show what would change without writing
        #[arg(long)]
        dry_run: bool,
    },

    /// NU7 capacity benchmark: replay blocks from RocksDB into an isolated DB
    Benchmark {
        /// Database URL for benchmark writes (isolated test DB)
        #[arg(long, env = "DATABASE_URL")]
        benchmark_db: Option<String>,
        /// Start height
        #[arg(long, default_value = "3200000")]
        from: u32,
        /// End height
        #[arg(long, default_value = "3201000")]
        to: u32,
        /// Warm up RocksDB page cache with this many blocks before the measured range
        #[arg(long, default_value = "100")]
        warmup: u32,
        /// Skip SQL writes — measure source+parse+prevout only
        #[arg(long)]
        parse_only: bool,
        /// Emit machine-readable JSON instead of human-readable output
        #[arg(long)]
        json: bool,
    },

    /// Audit or repair the known transparent address-accounting defects.
    Integrity {
        #[arg(value_enum)]
        phase: commands::integrity::IntegrityPhase,
        #[arg(long)]
        from: u32,
        #[arg(long)]
        to: u32,
        /// Also recompute summaries for every address touched in this range.
        /// Use for a known summary-only incident range.
        #[arg(long)]
        repair_range_summaries: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value = "5000")]
        lock_timeout_ms: u64,
        #[arg(long, default_value = "600000")]
        statement_timeout_ms: u64,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load .env if present
    let _ = dotenvy::dotenv();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("cipherscan_indexer=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    // Build config
    let mut config = Config::from_env();
    if let Some(path) = cli.zebra_path {
        config.zebra_state_path = path.into();
    }
    if let Some(url) = cli.database_url {
        config.database_url = url;
    }
    config.batch_size = cli.batch_size;

    let suppress_banner = matches!(
        &cli.command,
        Commands::Status { json: true }
            | Commands::Health { json: true, .. }
            | Commands::Benchmark { json: true, .. }
    );

    if !suppress_banner {
        println!("════════════════════════════════════════════════════════════");
        println!("🚀 CipherScan Rust Indexer v0.1.0");
        println!("════════════════════════════════════════════════════════════");
        println!("📂 Zebra state: {:?}", config.zebra_state_path);
        println!("🌐 Network: {}", config.network_name());
        println!();
    }

    match cli.command {
        Commands::Analyze => {
            commands::analyze::analyze_database(&config)?;
        }
        Commands::Backfill { from, to } => {
            commands::backfill::run_backfill(&config, from, to).await?;
        }
        Commands::Live => {
            commands::live::run_live(&config).await?;
        }
        Commands::Shadow { events, timeout } => {
            commands::shadow::verify_full_block_stream(&config, events, timeout).await?;
        }
        Commands::OrphanShadow {
            journal,
            events,
            timeout,
            reconnect_after,
        } => {
            if events == 0 || !(1..=900).contains(&timeout) || reconnect_after == Some(0) {
                return Err("invalid shadow trial bounds".into());
            }
            let url = config
                .zebra_grpc_url
                .as_deref()
                .ok_or("ZEBRA_GRPC_URL required")?;
            let summary = db::orphan_capture::run_capture(
                url,
                &journal,
                config.network_name(),
                Some(std::time::Duration::from_secs(timeout)),
                reconnect_after,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            if summary.new_blocks < events {
                return Err(format!(
                    "only {} new blocks captured; required {events}",
                    summary.new_blocks
                )
                .into());
            }
        }
        Commands::Status { json } => {
            commands::status::show_status(&config, json).await?;
        }
        Commands::Health {
            max_lag,
            max_consecutive_failures,
            max_heartbeat_age,
            max_ingest_ms,
            json,
        } => {
            commands::status::check_health(
                &config,
                max_lag,
                max_consecutive_failures,
                max_heartbeat_age,
                max_ingest_ms,
                json,
            )
            .await?;
        }
        Commands::Block { height } => {
            commands::inspect::show_block(&config, height)?;
        }
        Commands::Verify {
            height,
            count,
            rpc_url,
            cookie_file,
        } => {
            commands::verify::verify_parsing(&config, height, count, &rpc_url, &cookie_file)
                .await?;
        }
        Commands::Tx { height, index } => {
            commands::inspect::show_transaction(&config, height, index)?;
        }
        Commands::Compare {
            sample,
            from_height,
            database_url,
        } => {
            let db_url = database_url.unwrap_or_else(|| config.database_url.clone());
            commands::compare::compare_with_postgres(&config, &db_url, sample, from_height).await?;
        }
        Commands::BackfillMetadata { from, to, batch } => {
            commands::backfill::run_backfill_metadata(&config, from, to, batch).await?;
        }
        Commands::BackfillAnchors { v6_only, batch } => {
            commands::backfill::run_backfill_anchors(&config, v6_only, batch).await?;
        }
        Commands::BackfillScripts { batch } => {
            commands::backfill::run_backfill_scripts(&config, batch).await?;
        }
        Commands::Validate {
            prod_db,
            test_db,
            from_height,
            to_height,
        } => {
            let prod_url = prod_db.unwrap_or_else(|| config.database_url.clone());
            commands::validate::validate_full(&config, &prod_url, &test_db, from_height, to_height)
                .await?;
        }
        Commands::RepairFees { batch, dry_run } => {
            commands::repair::repair_ironwood_fees(&config, batch, dry_run).await?;
        }
        Commands::Benchmark {
            benchmark_db,
            from,
            to,
            warmup,
            parse_only,
            json,
        } => {
            let db_url = benchmark_db.unwrap_or_else(|| config.database_url.clone());
            commands::benchmark::run_benchmark(
                &config, &db_url, from, to, warmup, parse_only, json,
            )
            .await?;
        }
        Commands::Integrity {
            phase,
            from,
            to,
            repair_range_summaries,
            dry_run,
            lock_timeout_ms,
            statement_timeout_ms,
        } => {
            commands::integrity::run(
                &config,
                phase,
                from,
                to,
                repair_range_summaries,
                dry_run,
                lock_timeout_ms,
                statement_timeout_ms,
            )
            .await?;
        }
    }

    Ok(())
}
