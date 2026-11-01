//! Transaction data model

use serde::{Deserialize, Serialize};

/// Zcash transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub txid: String,
    pub block_height: u32,
    pub block_hash: String,
    pub version: i32,
    pub lock_time: u32,
    pub expiry_height: Option<u32>,
    pub size: u32,

    // Transparent
    pub vin_count: u16,
    pub vout_count: u16,
    pub transparent_value_in: i64,
    pub transparent_value_out: i64,

    // Shielded counts
    pub joinsplit_count: u16, // Sprout
    pub sapling_spends: u16,
    pub sapling_outputs: u16,
    pub orchard_actions: u16,
    pub ironwood_actions: u16, // NU6.3 Ironwood pool (v6 tx)

    // Value balances (negative = into shielded, positive = out of shielded)
    pub sapling_value_balance: i64,
    pub orchard_value_balance: i64,
    pub ironwood_value_balance: i64, // NU6.3 Ironwood pool (v6 tx)
    /// Sprout JoinSplit value balance: sum(vpub_new) - sum(vpub_old) over
    /// every JoinSplit (v2-v4). Positive = value leaving Sprout into the
    /// transparent value pool of this transaction, matching the other pools.
    pub sprout_value_balance: i64,

    // Anchor roots (hex-encoded 32-byte tree roots from shielded bundles)
    pub orchard_anchor: Option<String>,
    pub ironwood_anchor: Option<String>,

    // Computed
    pub fee: Option<i64>,

    // Detailed data (optional, for API responses)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vin: Vec<TransparentInput>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vout: Vec<TransparentOutput>,
}

impl Transaction {
    pub fn is_coinbase(&self) -> bool {
        self.vin_count == 1 && self.vin.first().map(|v| v.is_coinbase).unwrap_or(false)
    }

    /// Net value leaving every shielded pool (Sprout, Sapling, Orchard,
    /// Ironwood) into this transaction's transparent value pool.
    pub fn shielded_value_balance(&self) -> Option<i64> {
        self.sprout_value_balance
            .checked_add(self.sapling_value_balance)?
            .checked_add(self.orchard_value_balance)?
            .checked_add(self.ironwood_value_balance)
    }

    /// Consensus fee: transparent inputs plus all shielded value balances
    /// minus transparent outputs. `Ok(None)` means the fee is not knowable
    /// (coinbase, or a negative result that a valid chain cannot produce);
    /// callers must store NULL rather than a guessed zero.
    pub fn compute_fee(&self) -> Result<Option<i64>, String> {
        if self.is_coinbase() {
            return Ok(None);
        }
        let fee = self
            .shielded_value_balance()
            .and_then(|balance| self.transparent_value_in.checked_add(balance))
            .and_then(|value| value.checked_sub(self.transparent_value_out))
            .ok_or_else(|| format!("fee overflow for {}", self.txid))?;
        Ok((fee >= 0).then_some(fee))
    }
}

/// Transparent input (vin)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparentInput {
    pub txid: String, // Previous output txid
    pub vout: u32,    // Previous output index
    pub address: Option<String>,
    pub value: Option<i64>, // In zatoshis
    pub is_coinbase: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_sig: Option<String>,
}

/// Transparent output (vout)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparentOutput {
    pub n: u32,     // Output index
    pub value: i64, // In zatoshis
    pub address: Option<String>,
    pub script_type: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_pub_key: Option<String>,

    /// Public keys disclosed by P2PK and bare multisig scripts. These are
    /// analytics metadata only and never imply ownership by a derived address.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pubkey_exposures: Vec<PubkeyExposure>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PubkeyExposure {
    pub pubkey_index: u16,
    pub pubkey_hex: String,
    pub derived_p2pkh: String,
}
