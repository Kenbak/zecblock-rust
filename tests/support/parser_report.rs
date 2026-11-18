use cipherscan_indexer::{config::Network, db::ParsedBlockHeader, indexer::TransactionParser};
use serde_json::{json, Value};
use std::io::Cursor;
use zakura_chain::{
    block::Block,
    serialization::{ZcashDeserialize, ZcashSerialize},
};

pub fn report(fixtures: &Value) -> Result<Value, Box<dyn std::error::Error>> {
    let mut reports = Vec::new();
    for fixture in fixtures.as_array().ok_or("expected fixture array")? {
        let network = match fixture["network"].as_str() {
            Some("mainnet") => Network::Mainnet,
            Some("testnet") => Network::Testnet,
            _ => return Err("unknown fixture network".into()),
        };
        let height = u32::try_from(fixture["height"].as_u64().ok_or("missing height")?)?;
        let hash = fixture["hash"].as_str().ok_or("missing hash")?;
        let raw = hex::decode(fixture["hex"].as_str().ok_or("missing block bytes")?)?;
        let mut cursor = Cursor::new(&raw);
        let block = Block::zcash_deserialize(&mut cursor)?;
        assert_eq!(
            cursor.position() as usize,
            raw.len(),
            "trailing block bytes"
        );
        assert_eq!(block.hash().to_string(), hash, "RPC block hash at {height}");
        assert_eq!(block.coinbase_height().map(|h| h.0), Some(height));
        let mut serialized = Vec::new();
        block.zcash_serialize(&mut serialized)?;
        assert_eq!(serialized, raw, "block roundtrip at {height}");
        let mut transactions = Vec::new();
        let mut txids = Vec::new();
        for tx in &block.transactions {
            let mut bytes = Vec::new();
            tx.zcash_serialize(&mut bytes)?;
            let parsed = TransactionParser::parse(&bytes, height, hash, network)?;
            txids.push(parsed.txid.clone());
            transactions.push(parsed);
        }
        assert_eq!(
            json!(txids),
            fixture["txids"],
            "RPC transaction hashes at {height}"
        );
        let h = ParsedBlockHeader::from_chain_header(&block.header);
        reports.push(json!({
            "network":fixture["network"], "height":height, "hash":hash,
            "header": {"version":h.version,"previous_block_hash":h.previous_block_hash,
                "merkle_root":h.merkle_root,"block_commitments":h.block_commitments,
                "final_sapling_root":h.final_sapling_root,
                "final_orchard_root":h.final_orchard_root,"final_ironwood_root":h.final_ironwood_root,
                "time":h.time,"bits":h.bits,"difficulty":h.difficulty,"nonce":h.nonce,"solution":h.solution},
            "transactions":transactions
        }));
    }
    Ok(Value::Array(reports))
}
