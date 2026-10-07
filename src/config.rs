//! Configuration for CipherScan Rust Indexer

use std::env;
use std::path::PathBuf;

/// Main configuration struct
#[derive(Debug, Clone)]
pub struct Config {
    /// Path to Zebra's RocksDB state
    pub zebra_state_path: PathBuf,

    /// PostgreSQL connection URL
    pub database_url: String,

    /// Batch size for PostgreSQL inserts
    pub batch_size: usize,

    /// Whether we're in mainnet or testnet
    pub network: Network,

    /// Maximum RocksDB open files (to avoid ulimit issues)
    pub max_open_files: i32,

    /// Zebra gRPC indexer URL (e.g. "http://127.0.0.1:8230")
    /// When set, enables instant block notifications with polling as a fallback
    pub zebra_grpc_url: Option<String>,

    /// Fallback live-tip polling interval; independent of consensus block spacing.
    pub live_poll_interval_secs: u64,

    /// Maximum reorg depth the indexer will handle automatically.
    /// Reorgs deeper than this require manual intervention (mainnet safety).
    /// Testnet should use a higher value since deep reorgs are routine.
    pub max_reorg_depth: u32,

    /// Maximum encoded blocks retained in the in-memory gRPC payload cache.
    pub grpc_payload_cache_blocks: usize,

    /// Maximum bytes retained in the in-memory gRPC payload cache.
    pub grpc_payload_cache_bytes: usize,

    /// Time to wait for a matching full-block payload after a tip event.
    pub grpc_payload_wait_ms: u64,

    /// Opt-in for NonFinalizedStateChange after shadow verification succeeds.
    pub enable_full_block_grpc: bool,

    /// Directory for the bounded recent-block reorg spool.
    pub block_spool_path: PathBuf,

    /// Encoded blocks that may be prefetched while ordered writes commit.
    pub live_pipeline_capacity: usize,

    /// Opt-in filesystem-only candidate capture. Never changes canonical/orphan DB rows.
    pub orphan_capture_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            zebra_state_path: PathBuf::from("/root/.cache/zakura/state/v29/mainnet"),
            database_url: String::from("postgres://localhost/zcash_explorer_mainnet"),
            batch_size: 1000,
            network: Network::Mainnet,
            max_open_files: 256,
            zebra_grpc_url: None,
            live_poll_interval_secs: 5,
            max_reorg_depth: 100,
            grpc_payload_cache_blocks: 32,
            grpc_payload_cache_bytes: 64 * 1024 * 1024,
            grpc_payload_wait_ms: 1_500,
            enable_full_block_grpc: false,
            block_spool_path: PathBuf::from("/var/lib/cipherscan-indexer/block-spool"),
            live_pipeline_capacity: 4,
            orphan_capture_path: None,
        }
    }
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(value) = env::var("LIVE_POLL_INTERVAL_SECONDS") {
            if let Ok(seconds) = value.parse::<u64>() {
                config.live_poll_interval_secs = seconds.clamp(1, 60);
            }
        }

        // Zebra state path
        if let Ok(path) = env::var("ZEBRA_STATE_PATH") {
            config.zebra_state_path = PathBuf::from(path);
        }

        // Database URL
        if let Ok(url) = env::var("DATABASE_URL") {
            config.database_url = url;
        }

        // Batch size
        if let Ok(size) = env::var("BATCH_SIZE") {
            if let Ok(n) = size.parse() {
                config.batch_size = n;
            }
        }

        // Network detection (from path or explicit)
        if let Ok(net) = env::var("NETWORK") {
            config.network = match net.to_lowercase().as_str() {
                "testnet" => Network::Testnet,
                _ => Network::Mainnet,
            };
        } else if config
            .zebra_state_path
            .to_string_lossy()
            .contains("testnet")
        {
            config.network = Network::Testnet;
        }

        if let Ok(url) = env::var("ZEBRA_GRPC_URL") {
            let url = url.trim().to_string();
            if !url.is_empty() {
                config.zebra_grpc_url = Some(if url.starts_with("http") {
                    url
                } else {
                    format!("http://{}", url)
                });
            }
        }

        if let Ok(val) = env::var("MAX_REORG_DEPTH") {
            if let Ok(n) = val.parse::<u32>() {
                config.max_reorg_depth = n;
            }
        }
        if let Ok(val) = env::var("GRPC_PAYLOAD_CACHE_BLOCKS") {
            if let Ok(n) = val.parse::<usize>() {
                if n > 0 {
                    config.grpc_payload_cache_blocks = n;
                }
            }
        }
        if let Ok(val) = env::var("GRPC_PAYLOAD_CACHE_BYTES") {
            if let Ok(n) = val.parse::<usize>() {
                if n > 0 {
                    config.grpc_payload_cache_bytes = n;
                }
            }
        }
        if let Ok(val) = env::var("GRPC_PAYLOAD_WAIT_MS") {
            if let Ok(n) = val.parse::<u64>() {
                config.grpc_payload_wait_ms = n;
            }
        }
        if let Ok(value) = env::var("ENABLE_FULL_BLOCK_GRPC") {
            config.enable_full_block_grpc =
                matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes");
        }
        if let Ok(path) = env::var("BLOCK_SPOOL_PATH") {
            if !path.trim().is_empty() {
                config.block_spool_path = PathBuf::from(path);
            }
        }
        if let Ok(value) = env::var("LIVE_PIPELINE_CAPACITY") {
            if let Ok(capacity) = value.parse::<usize>() {
                if (1..=64).contains(&capacity) {
                    config.live_pipeline_capacity = capacity;
                }
            }
        }

        if env::var("ENABLE_ORPHAN_CAPTURE").as_deref() == Ok("true") {
            config.orphan_capture_path = env::var("ORPHAN_CAPTURE_PATH")
                .ok()
                .filter(|path| !path.trim().is_empty())
                .map(PathBuf::from);
        }

        config
    }

    /// Get display name for the network
    pub fn network_name(&self) -> &'static str {
        match self.network {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.network, Network::Mainnet);
        assert_eq!(config.batch_size, 1000);
        assert!(config.orphan_capture_path.is_none());
    }
}
