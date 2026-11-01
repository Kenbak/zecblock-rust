//! Flow analysis logic
//!
//! Flow extraction is handled by `ShieldedFlow::from_transaction` in the
//! models layer. This module is retained for tests that exercise the flow
//! classification pipeline end-to-end.

#[cfg(test)]
mod tests {
    use crate::models::{FlowType, ShieldedFlow, Transaction, TransparentInput};

    fn create_shielding_tx() -> Transaction {
        Transaction {
            txid: "test".to_string(),
            block_height: 1000,
            block_hash: "blockhash".to_string(),
            version: 5,
            lock_time: 0,
            expiry_height: Some(1100),
            size: 500,
            vin_count: 1,
            vout_count: 0,
            transparent_value_in: 10000000,
            transparent_value_out: 0,
            joinsplit_count: 0,
            sapling_spends: 0,
            sapling_outputs: 1,
            orchard_actions: 0,
            ironwood_actions: 0,
            sapling_value_balance: -9999000,
            orchard_value_balance: 0,
            ironwood_value_balance: 0,
            sprout_value_balance: 0,
            orchard_anchor: None,
            ironwood_anchor: None,
            fee: Some(1000),
            vin: vec![TransparentInput {
                txid: "prev".to_string(),
                vout: 0,
                script_sig: None,
                address: Some("t1addr".to_string()),
                value: Some(10000000),
                is_coinbase: false,
            }],
            vout: vec![],
        }
    }

    #[test]
    fn shielding_tx_produces_shield_flow() {
        let tx = create_shielding_tx();
        let flows = ShieldedFlow::from_transaction(&tx);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].flow_type, FlowType::Shield.as_str());
    }

    #[test]
    fn orchard_to_ironwood_migration_produces_no_flow() {
        let tx = Transaction {
            txid: "migration".to_string(),
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
            orchard_value_balance: 10010000,
            ironwood_value_balance: -10000000,
            sprout_value_balance: 0,
            orchard_anchor: None,
            ironwood_anchor: None,
            fee: Some(10000),
            vin: vec![],
            vout: vec![],
        };

        let flows = ShieldedFlow::from_transaction(&tx);
        assert!(flows.is_empty());
    }
}
