//! Transaction parsing logic using zakura-chain
//!
//! Uses zakura-chain's native deserialization for proper parsing of all tx versions.

use crate::config::Network;
use crate::models::{PubkeyExposure, Transaction, TransparentInput, TransparentOutput};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Cursor;
use zakura_chain::serialization::ZcashDeserialize;
use zakura_chain::transaction::Transaction as ChainTransaction;

/// Transaction parser using zakura-chain
pub struct TransactionParser;

impl TransactionParser {
    /// Get address version prefixes for the given network
    fn addr_prefixes(network: Network) -> ([u8; 2], [u8; 2]) {
        match network {
            Network::Mainnet => ([0x1C, 0xB8], [0x1C, 0xBD]), // t1, t3
            Network::Testnet => ([0x1D, 0x25], [0x1C, 0xBA]), // tm, t2
        }
    }

    /// Parse a raw transaction from bytes using zakura-chain
    pub fn parse(
        raw: &[u8],
        block_height: u32,
        block_hash: &str,
        network: Network,
    ) -> Result<Transaction, String> {
        // Use zakura-chain to deserialize
        let mut cursor = Cursor::new(raw);
        let zebra_tx = ChainTransaction::zcash_deserialize(&mut cursor)
            .map_err(|e| format!("Failed to deserialize transaction: {:?}", e))?;

        // Convert to our Transaction type
        Self::from_chain_tx(zebra_tx, block_height, block_hash, raw.len(), network)
    }

    /// Convert zakura-chain Transaction to our Transaction model
    pub(crate) fn from_chain_tx(
        tx: ChainTransaction,
        block_height: u32,
        block_hash: &str,
        size: usize,
        network: Network,
    ) -> Result<Transaction, String> {
        use zakura_chain::transaction::Transaction::*;

        // Get txid
        let txid = tx.hash().to_string();

        let lock_time_raw = tx.raw_lock_time();

        let (version, expiry_height_raw): (i32, Option<u32>) = match &tx {
            V1 { .. } => (1, None),
            V2 { .. } => (2, None),
            V3 { expiry_height, .. } => (3, Some(expiry_height.0)),
            V4 { expiry_height, .. } => (4, Some(expiry_height.0)),
            V5 { expiry_height, .. } => (5, Some(expiry_height.0)),
            V6 { expiry_height, .. } => (6, Some(expiry_height.0)),
        };

        // Get transparent inputs/outputs
        let inputs = tx.inputs();
        let outputs = tx.outputs();

        // Parse transparent inputs
        let mut vin: Vec<TransparentInput> = Vec::new();
        let transparent_value_in: i64 = 0;
        let mut is_coinbase = false;

        for input in inputs.iter() {
            use zakura_chain::transparent::Input;
            match input {
                Input::Coinbase { data, .. } => {
                    is_coinbase = true;
                    vin.push(TransparentInput {
                        txid: "0".repeat(64),
                        vout: 0xFFFFFFFF,
                        address: None,
                        value: None,
                        is_coinbase: true,
                        script_sig: Some(hex::encode(data)),
                    });
                }
                Input::PrevOut {
                    outpoint,
                    unlock_script,
                    ..
                } => {
                    vin.push(TransparentInput {
                        txid: outpoint.hash.to_string(),
                        vout: outpoint.index,
                        address: None, // Would need UTXO lookup
                        value: None,   // Would need UTXO lookup
                        is_coinbase: false,
                        script_sig: Some(hex::encode(unlock_script.as_raw_bytes())),
                    });
                }
            }
        }

        // Parse transparent outputs
        let mut vout: Vec<TransparentOutput> = Vec::new();
        let mut transparent_value_out: i64 = 0;

        for (n, output) in outputs.iter().enumerate() {
            let value_zat = i64::from(output.value);
            transparent_value_out = transparent_value_out
                .checked_add(value_zat)
                .ok_or_else(|| format!("Overflow in transparent_value_out at output {}", n))?;

            // Try to get address from lock script
            let (address, script_type, pubkey_exposures) =
                Self::parse_output_script(&output.lock_script, network);

            vout.push(TransparentOutput {
                n: n as u32,
                value: value_zat,
                address,
                script_type,
                script_pub_key: Some(hex::encode(output.lock_script.as_raw_bytes())),
                pubkey_exposures,
            });
        }

        // Sprout JoinSplits exist in v2 (BCTV14), v3 (BCTV14) and v4 (Groth16).
        // vpub_old moves transparent value into Sprout; vpub_new moves value
        // out of Sprout. Each amount is consensus-bounded, but sums are still
        // checked because this is untrusted input.
        let joinsplit_count = u16::try_from(tx.output_values_to_sprout().count())
            .map_err(|_| format!("too many JoinSplits in {}", txid))?;
        let sprout_value_balance = Self::sprout_value_balance(&tx)
            .ok_or_else(|| format!("Sprout value balance overflow for {}", txid))?;

        let (sapling_spends, sapling_outputs, orchard_actions) = match &tx {
            V1 { .. } | V2 { .. } | V3 { .. } => (0, 0, 0),
            V4 {
                sapling_shielded_data,
                ..
            } => {
                let (spends, outputs) = sapling_shielded_data
                    .as_ref()
                    .map(|d| (d.spends().count(), d.outputs().count()))
                    .unwrap_or((0, 0));
                (spends as u16, outputs as u16, 0)
            }
            V5 {
                sapling_shielded_data,
                orchard_shielded_data,
                ..
            } => {
                let (spends, outputs) = sapling_shielded_data
                    .as_ref()
                    .map(|d| (d.spends().count(), d.outputs().count()))
                    .unwrap_or((0, 0));
                let actions = orchard_shielded_data
                    .as_ref()
                    .map(|d| d.actions.len())
                    .unwrap_or(0);
                (spends as u16, outputs as u16, actions as u16)
            }
            // NU6.3 v6: Zakura exposes Orchard bundle fields directly.
            // Ironwood is counted separately below.
            V6 {
                sapling_shielded_data,
                orchard_shielded_data,
                ..
            } => {
                let (spends, outputs) = sapling_shielded_data
                    .as_ref()
                    .map(|d| (d.spends().count(), d.outputs().count()))
                    .unwrap_or((0, 0));
                let actions = orchard_shielded_data
                    .as_ref()
                    .map(|d| d.actions.len())
                    .unwrap_or(0);
                (spends as u16, outputs as u16, actions as u16)
            }
        };

        // NU6.3 Ironwood actions (v6 only). Zakura shares the Orchard
        // bundle representation; the pools remain separate in our model.
        let ironwood_actions: u16 = match &tx {
            V6 {
                ironwood_shielded_data,
                ..
            } => ironwood_shielded_data
                .as_ref()
                .map(|d| d.actions.len())
                .unwrap_or(0) as u16,
            _ => 0,
        };

        // Get value balances
        let sapling_value_balance: i64 = match &tx {
            V4 {
                sapling_shielded_data,
                ..
            } => sapling_shielded_data
                .as_ref()
                .map(|d| i64::from(d.value_balance))
                .unwrap_or(0),
            V5 {
                sapling_shielded_data,
                ..
            } => sapling_shielded_data
                .as_ref()
                .map(|d| i64::from(d.value_balance))
                .unwrap_or(0),
            V6 {
                sapling_shielded_data,
                ..
            } => sapling_shielded_data
                .as_ref()
                .map(|d| i64::from(d.value_balance))
                .unwrap_or(0),
            _ => 0,
        };

        let orchard_value_balance: i64 = match &tx {
            V5 {
                orchard_shielded_data,
                ..
            } => orchard_shielded_data
                .as_ref()
                .map(|d| i64::from(d.value_balance))
                .unwrap_or(0),
            V6 {
                orchard_shielded_data,
                ..
            } => orchard_shielded_data
                .as_ref()
                .map(|d| i64::from(d.value_balance))
                .unwrap_or(0),
            _ => 0,
        };

        // NU6.3 Ironwood value balance (v6 only). Negative = into Ironwood,
        // positive = out of Ironwood — same sign convention as Orchard.
        let ironwood_value_balance: i64 = match &tx {
            V6 {
                ironwood_shielded_data,
                ..
            } => ironwood_shielded_data
                .as_ref()
                .map(|d| i64::from(d.value_balance))
                .unwrap_or(0),
            _ => 0,
        };

        // Per-transaction anchor roots (hex-encoded Orchard note commitment tree roots).
        // ZIP-318 compliance requires the Orchard anchor to reference a boundary-aligned
        // block height (height % 144 == 0).
        let orchard_anchor: Option<String> = match &tx {
            V5 {
                orchard_shielded_data,
                ..
            } => orchard_shielded_data
                .as_ref()
                .map(|d| hex::encode(<[u8; 32]>::from(d.shared_anchor))),
            V6 {
                orchard_shielded_data,
                ..
            } => orchard_shielded_data
                .as_ref()
                .map(|d| hex::encode(<[u8; 32]>::from(d.shared_anchor))),
            _ => None,
        };

        let ironwood_anchor: Option<String> = match &tx {
            V6 {
                ironwood_shielded_data,
                ..
            } => ironwood_shielded_data
                .as_ref()
                .map(|d| hex::encode(<[u8; 32]>::from(d.shared_anchor))),
            _ => None,
        };
        // Calculate fee (for non-coinbase)
        let fee = if is_coinbase {
            None
        } else {
            // Fee = transparent_in + shielded_in - transparent_out - shielded_out
            // For now, we'd need UTXO values for transparent_in
            None
        };

        Ok(Transaction {
            txid,
            block_height,
            block_hash: block_hash.to_string(),
            version,
            lock_time: lock_time_raw,
            expiry_height: expiry_height_raw,
            size: size as u32,
            vin_count: vin.len() as u16,
            vout_count: vout.len() as u16,
            transparent_value_in,
            transparent_value_out,
            joinsplit_count,
            sapling_spends,
            sapling_outputs,
            orchard_actions,
            ironwood_actions,
            sapling_value_balance,
            orchard_value_balance,
            ironwood_value_balance,
            sprout_value_balance,
            orchard_anchor,
            ironwood_anchor,
            fee,
            vin,
            vout,
        })
    }

    /// Sum of Sprout `vpub_new` minus sum of `vpub_old` (positive = leaving
    /// Sprout). Zero for versions without JoinSplits. `None` on overflow.
    pub(crate) fn sprout_value_balance(tx: &ChainTransaction) -> Option<i64> {
        let leaving = tx
            .input_values_from_sprout()
            .try_fold(0i64, |total, value| total.checked_add(i64::from(*value)))?;
        let entering = tx
            .output_values_to_sprout()
            .try_fold(0i64, |total, value| total.checked_add(i64::from(*value)))?;
        leaving.checked_sub(entering)
    }

    /// Parse output script to get address and type
    fn parse_output_script(
        script: &zakura_chain::transparent::Script,
        network: Network,
    ) -> (Option<String>, String, Vec<PubkeyExposure>) {
        let bytes = script.as_raw_bytes();

        if bytes.is_empty() {
            return (None, "empty".to_string(), Vec::new());
        }

        let (p2pkh_prefix, p2sh_prefix) = Self::addr_prefixes(network);

        // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        if bytes.len() == 25
            && bytes[0] == 0x76  // OP_DUP
            && bytes[1] == 0xa9  // OP_HASH160
            && bytes[2] == 0x14  // Push 20 bytes
            && bytes[23] == 0x88 // OP_EQUALVERIFY
            && bytes[24] == 0xac
        // OP_CHECKSIG
        {
            let hash = &bytes[3..23];
            let address = Self::encode_address(&p2pkh_prefix, hash);
            return (Some(address), "pubkeyhash".to_string(), Vec::new());
        }

        // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
        if bytes.len() == 23
            && bytes[0] == 0xa9  // OP_HASH160
            && bytes[1] == 0x14  // Push 20 bytes
            && bytes[22] == 0x87
        // OP_EQUAL
        {
            let hash = &bytes[2..22];
            let address = Self::encode_address(&p2sh_prefix, hash);
            return (Some(address), "scripthash".to_string(), Vec::new());
        }

        // P2PK (compressed): <0x21><33-byte-pubkey><OP_CHECKSIG>
        if bytes.len() == 35
            && bytes[0] == 0x21
            && (bytes[1] == 0x02 || bytes[1] == 0x03)
            && bytes[34] == 0xac
        {
            let pubkey = &bytes[1..34];
            return (
                None,
                "pubkey".to_string(),
                vec![Self::pubkey_exposure(0, pubkey, &p2pkh_prefix)],
            );
        }

        // P2PK (uncompressed): <0x41><65-byte-pubkey><OP_CHECKSIG>
        if bytes.len() == 67 && bytes[0] == 0x41 && bytes[1] == 0x04 && bytes[66] == 0xac {
            let pubkey = &bytes[1..66];
            return (
                None,
                "pubkey".to_string(),
                vec![Self::pubkey_exposure(0, pubkey, &p2pkh_prefix)],
            );
        }

        // Bare multisig: OP_m <pubkeys...> OP_n OP_CHECKMULTISIG
        if bytes.len() >= 37 && bytes[bytes.len() - 1] == 0xae {
            let m = bytes[0] as i32 - 0x50; // OP_1..OP_16
            let n_byte = bytes[bytes.len() - 2];
            let n = n_byte as i32 - 0x50;
            if (1..=16).contains(&m) && (1..=16).contains(&n) && m <= n {
                if let Some(pubkeys) =
                    Self::extract_multisig_pubkeys(&bytes[1..bytes.len() - 2], n as usize)
                {
                    let exposures = pubkeys
                        .into_iter()
                        .enumerate()
                        .map(|(index, pubkey)| {
                            Self::pubkey_exposure(index as u16, pubkey, &p2pkh_prefix)
                        })
                        .collect();
                    return (None, "multisig".to_string(), exposures);
                }
            }
        }

        // OP_RETURN
        if !bytes.is_empty() && bytes[0] == 0x6a {
            return (None, "nulldata".to_string(), Vec::new());
        }

        (None, "nonstandard".to_string(), Vec::new())
    }

    /// SHA256 + RIPEMD160 (standard Bitcoin/Zcash pubkey-to-address hash)
    fn hash160(data: &[u8]) -> [u8; 20] {
        use ripemd::Ripemd160;
        use sha2::{Digest, Sha256};

        let sha = Sha256::digest(data);
        let ripe = Ripemd160::digest(sha);
        let mut out = [0u8; 20];
        out.copy_from_slice(&ripe);
        out
    }

    fn pubkey_exposure(index: u16, pubkey: &[u8], prefix: &[u8]) -> PubkeyExposure {
        PubkeyExposure {
            pubkey_index: index,
            pubkey_hex: hex::encode(pubkey),
            derived_p2pkh: Self::encode_address(prefix, &Self::hash160(pubkey)),
        }
    }

    /// Parse every canonical direct pubkey push and require the declared key count.
    fn extract_multisig_pubkeys(script_body: &[u8], expected_n: usize) -> Option<Vec<&[u8]>> {
        let mut cursor = 0;
        let mut pubkeys = Vec::with_capacity(expected_n);
        while cursor < script_body.len() {
            let push_len = *script_body.get(cursor)? as usize;
            if push_len != 33 && push_len != 65 {
                return None;
            }
            let start = cursor.checked_add(1)?;
            let end = start.checked_add(push_len)?;
            let pubkey = script_body.get(start..end)?;
            let valid = (push_len == 33 && matches!(pubkey[0], 0x02 | 0x03))
                || (push_len == 65 && pubkey[0] == 0x04);
            if !valid {
                return None;
            }
            pubkeys.push(pubkey);
            cursor = end;
        }
        (pubkeys.len() == expected_n).then_some(pubkeys)
    }

    /// Encode address with Base58Check
    fn encode_address(prefix: &[u8], hash: &[u8]) -> String {
        use sha2::{Digest, Sha256};

        let mut data = Vec::with_capacity(prefix.len() + hash.len() + 4);
        data.extend_from_slice(prefix);
        data.extend_from_slice(hash);

        // Checksum
        let first = Sha256::digest(&data);
        let second = Sha256::digest(first);
        data.extend_from_slice(&second[0..4]);

        bs58::encode(&data).into_string()
    }

    /// Resolve all transparent inputs in a block while parsing each referenced
    /// previous transaction at most once. Same-block outputs always win.
    pub fn resolve_block_inputs(
        transactions: &mut [Transaction],
        zebra: &crate::db::ZebraState,
    ) -> Result<(), String> {
        let current_outputs: HashMap<(String, u32), (i64, Option<String>)> = transactions
            .iter()
            .flat_map(|tx| {
                tx.vout.iter().map(move |output| {
                    (
                        (tx.txid.clone(), output.n),
                        (output.value, output.address.clone()),
                    )
                })
            })
            .collect();

        let mut external_references: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
        for tx in transactions.iter() {
            for input in tx.vin.iter().filter(|input| !input.is_coinbase) {
                let key = (input.txid.clone(), input.vout);
                if !current_outputs.contains_key(&key) {
                    external_references
                        .entry(input.txid.clone())
                        .or_default()
                        .insert(input.vout);
                }
            }
        }

        let mut resolved_outputs = current_outputs;
        for (txid, output_indexes) in external_references {
            let output_indexes: Vec<u32> = output_indexes.into_iter().collect();
            let outputs = zebra
                .get_outputs_by_txid(&txid, &output_indexes)
                .map_err(|error| format!("failed to resolve outputs for {txid}: {error}"))?;
            resolved_outputs.extend(
                outputs
                    .into_iter()
                    .map(|(output_index, output)| ((txid.clone(), output_index), output)),
            );
        }

        for tx in transactions {
            if tx.vin.iter().any(|input| input.is_coinbase) {
                tx.fee = None;
                continue;
            }

            for input in &mut tx.vin {
                let (value, address) = resolved_outputs
                    .get(&(input.txid.clone(), input.vout))
                    .cloned()
                    .ok_or_else(|| {
                        format!(
                            "unresolved prevout {}:{} for {}",
                            input.txid, input.vout, tx.txid
                        )
                    })?;
                input.value = Some(value);
                input.address = address;
            }

            tx.transparent_value_in = tx.vin.iter().try_fold(0i64, |total, input| {
                total
                    .checked_add(input.value.unwrap_or(0))
                    .ok_or_else(|| format!("transparent input overflow for {}", tx.txid))
            })?;

            tx.fee = tx.compute_fee()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_chain::block::Height;
    use zakura_chain::serialization::ZcashSerialize;
    use zakura_chain::transaction::LockTime;

    #[test]
    fn test_address_encoding_mainnet() {
        let hash = hex::decode("0000000000000000000000000000000000000000").unwrap();
        let (p2pkh, p2sh) = TransactionParser::addr_prefixes(Network::Mainnet);
        assert!(TransactionParser::encode_address(&p2pkh, &hash).starts_with("t1"));
        assert!(TransactionParser::encode_address(&p2sh, &hash).starts_with("t3"));
    }

    #[test]
    fn test_address_encoding_testnet() {
        let hash = hex::decode("0000000000000000000000000000000000000000").unwrap();
        let (p2pkh, p2sh) = TransactionParser::addr_prefixes(Network::Testnet);
        assert!(TransactionParser::encode_address(&p2pkh, &hash).starts_with("tm"));
        assert!(TransactionParser::encode_address(&p2sh, &hash).starts_with("t2"));
    }

    fn lock_time_to_u32(lt: LockTime) -> u32 {
        let mut buf = Vec::new();
        lt.zcash_serialize(&mut buf).unwrap();
        u32::from_le_bytes(buf.try_into().unwrap())
    }

    #[test]
    fn lock_time_unlocked_is_zero() {
        let lt = LockTime::unlocked();
        assert_eq!(lock_time_to_u32(lt), 0);
    }

    #[test]
    fn lock_time_height_preserves_value() {
        let lt = LockTime::Height(Height(400_000));
        assert_eq!(lock_time_to_u32(lt), 400_000);
    }

    #[test]
    fn lock_time_high_height_below_threshold() {
        let lt = LockTime::Height(Height(499_999_999));
        assert_eq!(lock_time_to_u32(lt), 499_999_999);
    }

    #[test]
    fn lock_time_time_above_threshold() {
        let lt = LockTime::min_lock_time_timestamp();
        assert_eq!(lock_time_to_u32(lt), 500_000_000);
    }

    /// Helper to create a Script from raw bytes for testing parse_output_script
    fn make_script(bytes: &[u8]) -> zakura_chain::transparent::Script {
        zakura_chain::transparent::Script::new(bytes)
    }

    #[test]
    fn test_p2pk_compressed() {
        // Compressed P2PK: <0x21><02 + 32 bytes><OP_CHECKSIG>
        let mut script = vec![0x21]; // push 33 bytes
        script.push(0x02); // compressed pubkey prefix
        script.extend_from_slice(&[0xaa; 32]); // 32 bytes of pubkey data
        script.push(0xac); // OP_CHECKSIG
        assert_eq!(script.len(), 35);

        let s = make_script(&script);
        let (addr, stype, exposures) = TransactionParser::parse_output_script(&s, Network::Mainnet);
        assert_eq!(stype, "pubkey");
        assert!(addr.is_none());
        assert_eq!(exposures.len(), 1);
        assert!(exposures[0].derived_p2pkh.starts_with("t1"));
    }

    #[test]
    fn test_p2pk_uncompressed() {
        // Uncompressed P2PK: <0x41><04 + 64 bytes><OP_CHECKSIG>
        let mut script = vec![0x41]; // push 65 bytes
        script.push(0x04); // uncompressed pubkey prefix
        script.extend_from_slice(&[0xbb; 64]); // 64 bytes of pubkey data
        script.push(0xac); // OP_CHECKSIG
        assert_eq!(script.len(), 67);

        let s = make_script(&script);
        let (addr, stype, exposures) = TransactionParser::parse_output_script(&s, Network::Mainnet);
        assert_eq!(stype, "pubkey");
        assert!(addr.is_none());
        assert_eq!(exposures.len(), 1);
    }

    #[test]
    fn test_p2pk_compressed_testnet() {
        let mut script = vec![0x21];
        script.push(0x03); // alternate compressed prefix
        script.extend_from_slice(&[0xcc; 32]);
        script.push(0xac);

        let s = make_script(&script);
        let (addr, stype, exposures) = TransactionParser::parse_output_script(&s, Network::Testnet);
        assert_eq!(stype, "pubkey");
        assert!(addr.is_none());
        assert!(exposures[0].derived_p2pkh.starts_with("tm"));
    }

    #[test]
    fn test_bare_multisig_2_of_3_compressed() {
        // OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_CHECKMULTISIG
        let mut script = vec![0x52]; // OP_2
        for i in 0..3u8 {
            script.push(0x21); // push 33 bytes
            script.push(0x02); // compressed prefix
            script.extend_from_slice(&[i + 1; 32]);
        }
        script.push(0x53); // OP_3
        script.push(0xae); // OP_CHECKMULTISIG

        let s = make_script(&script);
        let (addr, stype, exposures) = TransactionParser::parse_output_script(&s, Network::Mainnet);
        assert_eq!(stype, "multisig");
        assert!(addr.is_none());
        assert_eq!(exposures.len(), 3);
        assert!(exposures
            .iter()
            .all(|item| item.derived_p2pkh.starts_with("t1")));
    }

    #[test]
    fn test_p2pkh_still_works() {
        // Standard P2PKH script
        let mut script = vec![0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 push20
        script.extend_from_slice(&[0xdd; 20]); // 20-byte hash
        script.push(0x88); // OP_EQUALVERIFY
        script.push(0xac); // OP_CHECKSIG
        assert_eq!(script.len(), 25);

        let s = make_script(&script);
        let (addr, stype, _) = TransactionParser::parse_output_script(&s, Network::Mainnet);
        assert_eq!(stype, "pubkeyhash");
        assert!(addr.is_some());
        assert!(addr.unwrap().starts_with("t1"));
    }

    #[test]
    fn test_p2sh_still_works() {
        // Standard P2SH script
        let mut script = vec![0xa9, 0x14]; // OP_HASH160 push20
        script.extend_from_slice(&[0xee; 20]); // 20-byte hash
        script.push(0x87); // OP_EQUAL
        assert_eq!(script.len(), 23);

        let s = make_script(&script);
        let (addr, stype, _) = TransactionParser::parse_output_script(&s, Network::Mainnet);
        assert_eq!(stype, "scripthash");
        assert!(addr.is_some());
        assert!(addr.unwrap().starts_with("t3"));
    }

    #[test]
    fn test_nulldata_still_works() {
        let script = vec![0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef]; // OP_RETURN + data
        let s = make_script(&script);
        let (addr, stype, _) = TransactionParser::parse_output_script(&s, Network::Mainnet);
        assert_eq!(stype, "nulldata");
        assert!(addr.is_none());
    }

    #[test]
    fn test_hash160() {
        // Known test vector: hash160 of empty byte slice
        let result = TransactionParser::hash160(&[]);
        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // RIPEMD160(above) = b472a266d0bd89c13706a4132ccfb16f7c3b9fcb
        let expected = hex::decode("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb").unwrap();
        assert_eq!(result.to_vec(), expected);
    }
}
