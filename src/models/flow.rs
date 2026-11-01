//! Shielded flow models
//!
//! Flows represent value moving between transparent and shielded pools.

use crate::models::Transaction;
use serde::{Deserialize, Serialize};

/// Type of shielded flow
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowType {
    /// Transparent to shielded
    Shield,
    /// Shielded to transparent
    Deshield,
    /// Between shielded pools (e.g., Sapling → Orchard)
    PoolMigration,
    /// Fully shielded (no transparent involvement)
    FullyShielded,
}

impl FlowType {
    pub fn as_str(&self) -> &'static str {
        match self {
            FlowType::Shield => "shield",
            FlowType::Deshield => "deshield",
            FlowType::PoolMigration => "pool_migration",
            FlowType::FullyShielded => "fully_shielded",
        }
    }
}

impl std::fmt::Display for FlowType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Shielded pool
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Pool {
    Sprout,
    Sapling,
    Orchard,
    Ironwood,
}

impl Pool {
    pub fn as_str(&self) -> &'static str {
        match self {
            Pool::Sprout => "sprout",
            Pool::Sapling => "sapling",
            Pool::Orchard => "orchard",
            Pool::Ironwood => "ironwood",
        }
    }
}

impl std::fmt::Display for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A shielded flow record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldedFlow {
    pub txid: String,
    pub flow_type: String,
    pub pool: String,
    pub amount: i64, // In zatoshis (always positive)
    pub block_height: u32,
    pub transparent_addresses: Vec<String>,
}

impl ShieldedFlow {
    /// Analyze a transaction and extract flows
    /// - NET total = Sprout + Sapling + Orchard + Ironwood value balances
    /// - If total > 0 → ONE deshield flow
    /// - If total < 0 → ONE shield flow
    /// - Pool = "mixed" if 2+ pools have non-zero balance
    ///
    /// Sprout counts like every other pool: t→Sprout deposits are shields,
    /// Sprout→t withdrawals are deshields, and a Sprout→Sapling migration
    /// with a transparent change output is a mixed deshield of the net amount,
    /// never a Sapling shield.
    pub fn from_transaction(tx: &Transaction) -> Vec<ShieldedFlow> {
        let mut flows = Vec::new();

        // Skip coinbase
        if tx.is_coinbase() {
            return flows;
        }

        // Calculate NET total across all shielded pools.
        // Checked arithmetic: a malformed/adversarial value balance must not panic
        // the indexer. Zcash value balances are bounded well within i64, so this
        // is not expected to trigger on well-formed chain data.
        let total_value_balance = match tx.shielded_value_balance() {
            Some(total) => total,
            None => {
                eprintln!(
                    "⚠️ Shielded value-balance overflow for tx {} — skipping flow classification",
                    tx.txid
                );
                return flows;
            }
        };

        // Only create a flow if there's net movement
        if total_value_balance == 0 {
            return flows;
        }

        // No transparent inputs or outputs — check if this is a pool migration
        // or just a fully shielded tx where the value balance is the fee.
        // Pool migrations have opposing signs (one pool positive, another negative).
        // Post-NU6.3 the canonical migration is Orchard(+) → Ironwood(-).
        if tx.vin_count == 0 && tx.vout_count == 0 {
            let balances = [
                tx.sprout_value_balance,
                tx.sapling_value_balance,
                tx.orchard_value_balance,
                tx.ironwood_value_balance,
            ];
            let has_positive = balances.iter().any(|&b| b > 0);
            let has_negative = balances.iter().any(|&b| b < 0);
            let is_pool_migration = has_positive && has_negative;
            // Pool migrations move value between shielded pools — no transparent
            // involvement. The net positive balance is just the fee, not an unshield.
            // Don't create a shield/deshield flow for these.
            if is_pool_migration {
                return flows;
            }
            // Not a pool migration and no transparent I/O — fully shielded (fee only)
            return flows;
        }

        // Collect transparent addresses for context
        let addresses: Vec<String> = tx
            .vin
            .iter()
            .filter_map(|v| v.address.clone())
            .chain(tx.vout.iter().filter_map(|v| v.address.clone()))
            .collect();

        // Determine flow type based on NET total (Node.js logic)
        let flow_type = if total_value_balance > 0 {
            FlowType::Deshield
        } else {
            FlowType::Shield
        };

        // Determine pool type.
        // "mixed" if 2+ pools have non-zero balance (regardless of sign).
        let active_pools = (tx.sprout_value_balance != 0) as u8
            + (tx.sapling_value_balance != 0) as u8
            + (tx.orchard_value_balance != 0) as u8
            + (tx.ironwood_value_balance != 0) as u8;
        let pool = if active_pools >= 2 {
            "mixed".to_string()
        } else if tx.ironwood_value_balance != 0 {
            Pool::Ironwood.to_string()
        } else if tx.orchard_value_balance != 0 {
            Pool::Orchard.to_string()
        } else if tx.sprout_value_balance != 0 {
            Pool::Sprout.to_string()
        } else {
            Pool::Sapling.to_string()
        };

        // checked_abs guards the i64::MIN edge case (its magnitude does not fit
        // in i64), which plain `.abs()` would panic on.
        let amount = match total_value_balance.checked_abs() {
            Some(amount) => amount,
            None => {
                eprintln!(
                    "⚠️ Shielded value-balance abs() overflow for tx {} — skipping flow classification",
                    tx.txid
                );
                return flows;
            }
        };

        flows.push(ShieldedFlow {
            txid: tx.txid.clone(),
            flow_type: flow_type.to_string(),
            pool,
            amount, // Always positive
            block_height: tx.block_height,
            transparent_addresses: addresses,
        });

        flows
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Transaction;

    #[test]
    fn test_flow_type_display() {
        assert_eq!(FlowType::Shield.as_str(), "shield");
        assert_eq!(FlowType::Deshield.as_str(), "deshield");
    }

    #[test]
    fn test_fully_shielded_tx_produces_no_flow() {
        let tx = Transaction {
            txid: "fully_shielded".to_string(),
            block_height: 3244398,
            block_hash: "hash".to_string(),
            version: 5,
            lock_time: 0,
            expiry_height: None,
            size: 200,
            vin_count: 0,
            vout_count: 0,
            transparent_value_in: 0,
            transparent_value_out: 0,
            joinsplit_count: 0,
            sapling_spends: 0,
            sapling_outputs: 0,
            orchard_actions: 2,
            ironwood_actions: 0,
            sapling_value_balance: 0,
            orchard_value_balance: 10000, // fee only
            ironwood_value_balance: 0,
            sprout_value_balance: 0,
            orchard_anchor: None,
            ironwood_anchor: None,
            fee: Some(10000),
            vin: vec![],
            vout: vec![],
        };

        let flows = ShieldedFlow::from_transaction(&tx);
        assert!(
            flows.is_empty(),
            "Fully shielded tx should produce no flows"
        );
    }

    #[test]
    fn test_pool_migration_produces_no_flow() {
        // Pool migrations move value between shielded pools — they should NOT
        // create shield/deshield flows since no transparent value is involved.
        let tx = Transaction {
            txid: "pool_migration".to_string(),
            block_height: 3000000,
            block_hash: "hash".to_string(),
            version: 5,
            lock_time: 0,
            expiry_height: None,
            size: 500,
            vin_count: 0,
            vout_count: 0,
            transparent_value_in: 0,
            transparent_value_out: 0,
            joinsplit_count: 0,
            sapling_spends: 2,
            sapling_outputs: 0,
            orchard_actions: 2,
            ironwood_actions: 0,
            sapling_value_balance: 5000000, // 0.05 ZEC leaving Sapling
            orchard_value_balance: -4990000, // ~0.05 ZEC entering Orchard (minus fee)
            ironwood_value_balance: 0,
            sprout_value_balance: 0,
            orchard_anchor: None,
            ironwood_anchor: None,
            fee: Some(10000),
            vin: vec![],
            vout: vec![],
        };

        let flows = ShieldedFlow::from_transaction(&tx);
        assert!(
            flows.is_empty(),
            "Pool migration should NOT produce a shield/deshield flow"
        );
    }

    #[test]
    fn test_orchard_to_ironwood_migration_produces_no_flow() {
        // NU6.3 canonical migration: value leaves Orchard, enters Ironwood,
        // no transparent I/O. The net positive balance is just the fee.
        let tx = Transaction {
            txid: "orchard_to_ironwood".to_string(),
            block_height: 4200000,
            block_hash: "hash".to_string(),
            version: 6,
            lock_time: 0,
            expiry_height: None,
            size: 600,
            vin_count: 0,
            vout_count: 0,
            transparent_value_in: 0,
            transparent_value_out: 0,
            joinsplit_count: 0,
            sapling_spends: 0,
            sapling_outputs: 0,
            orchard_actions: 2,
            ironwood_actions: 2,
            sapling_value_balance: 0,
            orchard_value_balance: 10010000, // 0.1 ZEC + fee leaving Orchard
            ironwood_value_balance: -10000000, // 0.1 ZEC entering Ironwood
            sprout_value_balance: 0,
            orchard_anchor: None,
            ironwood_anchor: None,
            fee: Some(10000),
            vin: vec![],
            vout: vec![],
        };

        let flows = ShieldedFlow::from_transaction(&tx);
        assert!(
            flows.is_empty(),
            "Orchard→Ironwood migration should NOT produce a shield/deshield flow"
        );
    }
}
