//! RocksDB reader for Zebra state
//!
//! Reads directly from Zebra's RocksDB state database.
//! This is ~100-1000x faster than JSON-RPC calls.
//!
//! Uses RocksDB secondary mode to follow Zebra's writes in real-time.

use crate::config::Config;
use rocksdb::{IteratorMode, Options, DB};
use std::collections::HashMap;
use std::io::Cursor;
use std::time::Instant;
use zakura_chain::block::Header as ZebraHeader;
use zakura_chain::serialization::ZcashDeserialize;

/// Wrapper around Zebra's RocksDB state
pub struct ZebraState {
    db: DB,
    config: Config,
    _secondary_path: std::path::PathBuf,
}

impl ZebraState {
    /// Open Zebra state in secondary mode (can follow primary writes)
    pub fn open(config: &Config) -> Result<Self, String> {
        let path = &config.zebra_state_path;

        if !path.exists() {
            return Err(format!("Zebra state not found at: {:?}", path));
        }

        let mut opts = Options::default();
        opts.set_error_if_exists(false);
        opts.create_if_missing(false);
        opts.set_max_open_files(config.max_open_files);

        // Get actual column families from database
        let cf_names = DB::list_cf(&Options::default(), path)
            .map_err(|e| format!("Failed to list column families: {}", e))?;

        // RocksDB secondary instances require an exclusive secondary directory.
        // Include the PID so bounded parallel backfill workers can safely read the
        // same Zebra primary without sharing lock or catch-up state.
        let secondary_path =
            std::env::temp_dir().join(format!("cipherscan-rocks-secondary-{}", std::process::id()));
        std::fs::create_dir_all(&secondary_path)
            .map_err(|e| format!("Failed to create secondary path: {}", e))?;

        let start = Instant::now();
        let db = DB::open_cf_as_secondary(&opts, path, &secondary_path, &cf_names)
            .map_err(|e| format!("Failed to open RocksDB as secondary: {}", e))?;

        tracing::info!("RocksDB opened in {:?}", start.elapsed());

        Ok(Self {
            db,
            config: config.clone(),
            _secondary_path: secondary_path,
        })
    }

    /// Replay the primary's latest MANIFEST and WAL into this secondary view.
    /// Without it, blocks Zebra has not yet flushed to SST files are invisible.
    pub fn catch_up_with_primary(&self) -> Result<(), String> {
        self.db
            .try_catch_up_with_primary()
            .map_err(|e| format!("RocksDB secondary catch-up failed: {}", e))
    }

    /// Get current chain tip height
    pub fn get_tip_height(&self) -> Result<u32, String> {
        let cf = self
            .db
            .cf_handle("hash_by_height")
            .ok_or("hash_by_height CF not found")?;

        let mut last_height = 0u32;

        // RocksDB is sorted; only the last entry is needed.
        if let Some(item) = self.db.iterator_cf(cf, IteratorMode::End).next() {
            let (key, _) = item.map_err(|e| format!("Error reading tip: {}", e))?;
            if key.len() >= 3 {
                // 3-byte big-endian height
                last_height = ((key[0] as u32) << 16) | ((key[1] as u32) << 8) | (key[2] as u32);
            }
        }

        Ok(last_height)
    }

    /// Get block hash by height
    pub fn get_block_hash(&self, height: u32) -> Result<[u8; 32], String> {
        let cf = self
            .db
            .cf_handle("hash_by_height")
            .ok_or("hash_by_height CF not found")?;

        // Encode height as 3-byte big-endian
        let key = [
            ((height >> 16) & 0xFF) as u8,
            ((height >> 8) & 0xFF) as u8,
            (height & 0xFF) as u8,
        ];

        match self.db.get_cf(cf, key) {
            Ok(Some(value)) => {
                if value.len() >= 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&value[..32]);
                    Ok(hash)
                } else {
                    Err(format!("Invalid hash length: {}", value.len()))
                }
            }
            Ok(None) => Err(format!("Block not found at height {}", height)),
            Err(e) => Err(format!("Error reading block hash: {}", e)),
        }
    }

    /// Get and parse block header
    pub fn get_block_header(&self, height: u32) -> Result<ParsedBlockHeader, String> {
        let cf = self
            .db
            .cf_handle("block_header_by_height")
            .ok_or("block_header_by_height CF not found")?;

        // Encode height as 3-byte big-endian
        let key = [
            ((height >> 16) & 0xFF) as u8,
            ((height >> 8) & 0xFF) as u8,
            (height & 0xFF) as u8,
        ];

        match self.db.get_cf(cf, key) {
            Ok(Some(value)) => {
                // Parse header using zakura-chain
                let mut cursor = Cursor::new(&value[..]);
                let header = ZebraHeader::zcash_deserialize(&mut cursor)
                    .map_err(|e| format!("Failed to parse header: {:?}", e))?;
                Ok(ParsedBlockHeader::from_chain_header(&header))
            }
            Ok(None) => Err(format!("Block header not found at height {}", height)),
            Err(e) => Err(format!("Error reading block header: {}", e)),
        }
    }

    /// Get transaction by location (block height + tx index)
    pub fn get_transaction_by_loc(&self, height: u32, tx_index: u16) -> Result<Vec<u8>, String> {
        let cf = self
            .db
            .cf_handle("tx_by_loc")
            .ok_or("tx_by_loc CF not found")?;

        // Encode location: 3-byte height BE + 2-byte tx_index BE
        let key = [
            ((height >> 16) & 0xFF) as u8,
            ((height >> 8) & 0xFF) as u8,
            (height & 0xFF) as u8,
            ((tx_index >> 8) & 0xFF) as u8,
            (tx_index & 0xFF) as u8,
        ];

        match self.db.get_cf(cf, key) {
            Ok(Some(value)) => Ok(value.to_vec()),
            Ok(None) => Err(format!("Transaction not found at {}:{}", height, tx_index)),
            Err(e) => Err(format!("Error reading transaction: {}", e)),
        }
    }

    /// Get transaction hash by location
    pub fn get_tx_hash_by_loc(&self, height: u32, tx_index: u16) -> Result<[u8; 32], String> {
        let cf = self
            .db
            .cf_handle("hash_by_tx_loc")
            .ok_or("hash_by_tx_loc CF not found")?;

        // Same key format as tx_by_loc
        let key = [
            ((height >> 16) & 0xFF) as u8,
            ((height >> 8) & 0xFF) as u8,
            (height & 0xFF) as u8,
            ((tx_index >> 8) & 0xFF) as u8,
            (tx_index & 0xFF) as u8,
        ];

        match self.db.get_cf(cf, key) {
            Ok(Some(value)) => {
                if value.len() >= 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&value[..32]);
                    Ok(hash)
                } else {
                    Err(format!("Invalid hash length: {}", value.len()))
                }
            }
            Ok(None) => Err(format!("TX hash not found at {}:{}", height, tx_index)),
            Err(e) => Err(format!("Error reading tx hash: {}", e)),
        }
    }

    /// Iterate over all transactions in a block
    /// Returns (tx_index, raw_tx_bytes) for each transaction
    pub fn iter_block_transactions(&self, height: u32) -> Result<Vec<(u16, Vec<u8>)>, String> {
        let cf = self
            .db
            .cf_handle("tx_by_loc")
            .ok_or("tx_by_loc CF not found")?;

        // Prefix for this block height (3 bytes BE)
        let prefix = [
            ((height >> 16) & 0xFF) as u8,
            ((height >> 8) & 0xFF) as u8,
            (height & 0xFF) as u8,
        ];

        let mut transactions = Vec::new();

        // Iterate from the start of this height's prefix
        for item in self.db.prefix_iterator_cf(cf, prefix) {
            match item {
                Ok((key, value)) => {
                    // Check if still in same block (first 3 bytes match)
                    if key.len() >= 5 && key[0..3] == prefix {
                        let tx_index = ((key[3] as u16) << 8) | (key[4] as u16);
                        transactions.push((tx_index, value.to_vec()));
                    } else {
                        // Moved to next block, stop
                        break;
                    }
                }
                Err(e) => return Err(format!("Error iterating transactions: {}", e)),
            }
        }

        Ok(transactions)
    }

    /// Get count of transactions in a block
    pub fn get_block_tx_count(&self, height: u32) -> Result<u16, String> {
        let txs = self.iter_block_transactions(height)?;
        Ok(txs.len() as u16)
    }

    /// Get transaction location (height, index) by txid hash
    /// The txid should be in internal byte order (not display order)
    pub fn get_tx_loc_by_hash(&self, txid_bytes: &[u8; 32]) -> Result<(u32, u16), String> {
        let cf = self
            .db
            .cf_handle("tx_loc_by_hash")
            .ok_or("tx_loc_by_hash CF not found")?;

        match self.db.get_cf(cf, txid_bytes) {
            Ok(Some(value)) => {
                if value.len() >= 5 {
                    // 3-byte height BE + 2-byte tx_index BE
                    let height =
                        ((value[0] as u32) << 16) | ((value[1] as u32) << 8) | (value[2] as u32);
                    let tx_index = ((value[3] as u16) << 8) | (value[4] as u16);
                    Ok((height, tx_index))
                } else {
                    Err(format!("Invalid tx_loc length: {}", value.len()))
                }
            }
            Ok(None) => Err("Transaction not found by hash".to_string()),
            Err(e) => Err(format!("Error looking up tx by hash: {}", e)),
        }
    }

    /// Resolve multiple outputs from one previous transaction with a single
    /// location lookup, raw transaction read, and transaction parse.
    pub fn get_outputs_by_txid(
        &self,
        prev_txid_hex: &str,
        output_indexes: &[u32],
    ) -> Result<HashMap<u32, (i64, Option<String>)>, String> {
        let txid_bytes =
            hex::decode(prev_txid_hex).map_err(|e| format!("Invalid txid hex: {e}"))?;
        if txid_bytes.len() != 32 {
            return Err(format!("Invalid txid length: {}", txid_bytes.len()));
        }

        let mut txid_internal = [0u8; 32];
        for (index, byte) in txid_bytes.iter().enumerate() {
            txid_internal[31 - index] = *byte;
        }
        let (height, tx_index) = self.get_tx_loc_by_hash(&txid_internal)?;
        let raw_tx = self.get_transaction_by_loc(height, tx_index)?;
        let transaction =
            crate::indexer::TransactionParser::parse(&raw_tx, height, "", self.config.network)?;

        output_indexes
            .iter()
            .copied()
            .map(|output_index| {
                let output = transaction.vout.get(output_index as usize).ok_or_else(|| {
                    format!("Output {output_index} not found in transaction {prev_txid_hex}")
                })?;
                Ok((output_index, (output.value, output.address.clone())))
            })
            .collect()
    }
}

/// Parsed block header with all fields
#[derive(Debug, Clone)]
pub struct ParsedBlockHeader {
    pub version: i32,
    pub previous_block_hash: String,
    pub merkle_root: String,
    pub final_sapling_root: String,
    pub final_orchard_root: Option<String>,
    pub final_ironwood_root: Option<String>,
    pub time: u64,
    pub bits: String,
    pub difficulty: f64,
    pub nonce: String,
    pub solution: String,
}

impl ParsedBlockHeader {
    pub fn from_chain_header(header: &ZebraHeader) -> Self {
        let version = format!("{:?}", header.version)
            .trim_start_matches("Version(")
            .trim_end_matches(')')
            .parse::<i32>()
            .unwrap_or(4);

        let display_hash = |mut bytes: [u8; 32]| {
            bytes.reverse();
            hex::encode(bytes)
        };

        let bits_debug = format!("{:?}", header.difficulty_threshold);
        let bits = bits_debug
            .find("0x")
            .map(|start| {
                bits_debug[start + 2..]
                    .chars()
                    .take_while(|character| character.is_ascii_hexdigit())
                    .collect::<String>()
            })
            .unwrap_or_default();
        let bits_value = u32::from_str_radix(&bits, 16).unwrap_or(0);

        let nonce_debug = format!("{:?}", header.nonce);
        let nonce_raw = nonce_debug
            .find('"')
            .and_then(|start| {
                nonce_debug
                    .rfind('"')
                    .filter(|end| *end > start)
                    .map(|end| nonce_debug[start + 1..end].to_string())
            })
            .unwrap_or(nonce_debug);
        let nonce = if nonce_raw.len() == 64 {
            hex::decode(&nonce_raw)
                .map(|mut bytes| {
                    bytes.reverse();
                    hex::encode(bytes)
                })
                .unwrap_or(nonce_raw)
        } else {
            nonce_raw
        };

        let solution_debug = format!("{:?}", header.solution);
        let solution = solution_debug
            .find('"')
            .and_then(|start| {
                solution_debug
                    .rfind('"')
                    .filter(|end| *end > start)
                    .map(|end| solution_debug[start + 1..end].to_string())
            })
            .unwrap_or_default();

        Self {
            version,
            previous_block_hash: display_hash(header.previous_block_hash.0),
            merkle_root: display_hash(header.merkle_root.0),
            final_sapling_root: display_hash(header.commitment_bytes.0),
            final_orchard_root: None,
            final_ironwood_root: None,
            time: header.time.timestamp() as u64,
            bits,
            difficulty: Self::compact_to_difficulty(bits_value),
            nonce,
            solution,
        }
    }

    fn compact_to_difficulty(compact: u32) -> f64 {
        let exponent = (compact >> 24) as i32;
        let mantissa = (compact & 0x00ff_ffff) as f64;
        if mantissa == 0.0 {
            return 0.0;
        }

        let max_target = 0x07ffff as f64 * 256.0_f64.powi(0x1f - 3);
        let current_target = mantissa * 256.0_f64.powi(exponent - 3);
        max_target / current_target
    }
}
