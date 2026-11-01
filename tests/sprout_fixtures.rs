//! Real mainnet Sprout transactions: JoinSplit values must reach the fee.
//!
//! Raw bytes are public chain data. The parser recomputes each txid from the
//! bytes, so the txid assertion authenticates the fixture. Expected JoinSplit
//! values come from an independent decoder; transparent input values are the
//! resolved prevout sums stored in the production database on 2026-11-01.

use cipherscan_indexer::{config::Network, indexer::TransactionParser};

#[test]
fn sprout_value_balances_and_fees_match_mainnet() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/sprout-transactions.json")).unwrap();
    let fixtures = fixtures.as_array().unwrap();
    assert_eq!(fixtures.len(), 3);
    for fixture in fixtures {
        let txid = fixture["txid"].as_str().unwrap();
        let height = fixture["height"].as_u64().unwrap() as u32;
        let expected = &fixture["expected"];
        let raw = hex::decode(fixture["hex"].as_str().unwrap()).unwrap();
        let mut tx = TransactionParser::parse(&raw, height, "hash", Network::Mainnet).unwrap();

        assert_eq!(tx.txid, txid, "fixture bytes do not hash to {txid}");
        assert_eq!(i64::from(tx.version), expected["version"].as_i64().unwrap());
        assert_eq!(
            u64::from(tx.joinsplit_count),
            expected["joinsplit_count"].as_u64().unwrap(),
            "{txid}: JoinSplit count"
        );
        assert_eq!(
            tx.sprout_value_balance,
            expected["sprout_value_balance"].as_i64().unwrap(),
            "{txid}: Sprout value balance"
        );
        assert_eq!(
            tx.sapling_value_balance,
            expected["sapling_value_balance"].as_i64().unwrap()
        );
        assert_eq!(
            tx.transparent_value_out,
            expected["transparent_value_out"].as_i64().unwrap()
        );
        assert_eq!(
            u64::from(tx.vin_count),
            expected["vin_count"].as_u64().unwrap()
        );

        // Supply the resolved prevout values that block indexing would add.
        let transparent_in = fixture["transparent_value_in"].as_i64().unwrap();
        if let Some(input) = tx.vin.first_mut() {
            input.value = Some(transparent_in);
        }
        tx.transparent_value_in = transparent_in;
        assert_eq!(
            tx.compute_fee().unwrap(),
            Some(expected["fee"].as_i64().unwrap()),
            "{txid}: fee"
        );
    }
}

#[test]
fn pre_overwinter_v2_joinsplits_are_counted() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/sprout-transactions.json")).unwrap();
    let v2 = fixtures
        .as_array()
        .unwrap()
        .iter()
        .find(|fixture| fixture["expected"]["version"] == 2)
        .expect("a v2 fixture");
    let raw = hex::decode(v2["hex"].as_str().unwrap()).unwrap();
    let tx = TransactionParser::parse(&raw, 100_000, "hash", Network::Mainnet).unwrap();
    assert_eq!(tx.version, 2);
    assert!(tx.joinsplit_count > 0, "v2 JoinSplits must set has_sprout");
}
