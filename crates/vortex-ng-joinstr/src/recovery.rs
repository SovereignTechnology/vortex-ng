//! The recovery round (joinstr `NIP.md` "DoS Mitigation"; RULES.md R8).
//!
//! When fewer inputs than outputs were registered, somebody registered an output and withheld its input.
//! Nobody can tell which output that was, so the outputs are thrown away and registered again, this time
//! under a ring signature by the owner of a registered input ([`crate::lsag`]): one output per input owner,
//! without revealing which owner. Every peer then builds the same new transaction from those inputs and
//! outputs and signs its input again, with plain `SIGHASH_ALL`.
//!
//! Only P2WPKH inputs take part: the ring is made of the public keys in their witnesses, as the reference
//! client builds it. The round goes ahead only when every ring member re-registered; otherwise the
//! transaction would not balance, and it is abandoned.

use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{
    Address, CompressedPublicKey, EcdsaSighashType, Network, OutPoint, Psbt, ScriptBuf,
    Transaction, TxIn, TxOut, Witness, ecdsa,
};

use crate::lsag::{self, LsagError, Signature};
use crate::message::PoolMessage;
use crate::rules;
use crate::tx::{REGISTRATION_SEQUENCE, Registration, TxError, template};

/// A registered input that takes part in the recovery round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingMember {
    /// The key that controls the coin, taken from its registration's witness.
    pub key: PublicKey,
    /// The coin.
    pub outpoint: OutPoint,
    /// The coin's output.
    pub coin: TxOut,
}

/// The ring member a registration contributes: its coin must be P2WPKH and the public key in its witness
/// must be the one the coin pays, so nobody adds a key it does not control.
pub fn ring_member(registration: &Registration) -> Option<RingMember> {
    if !registration.coin.script_pubkey.is_p2wpkh() {
        return None;
    }
    let key = CompressedPublicKey::from_slice(registration.witness.last()?).ok()?;
    if ScriptBuf::new_p2wpkh(&key.wpubkey_hash()) != registration.coin.script_pubkey {
        return None;
    }
    Some(RingMember {
        key: key.0,
        outpoint: registration.outpoint,
        coin: registration.coin.clone(),
    })
}

/// The ring of a pool: one member per registered P2WPKH input, each key and each coin once, sorted by key
/// as every client sorts it.
pub fn ring_members(registrations: &[Registration]) -> Vec<RingMember> {
    let mut members: Vec<RingMember> = Vec::new();
    for member in registrations.iter().filter_map(ring_member) {
        if !members
            .iter()
            .any(|m| m.key == member.key || m.outpoint == member.outpoint)
        {
            members.push(member);
        }
    }
    members.sort_by_key(|m| m.key.serialize());
    members
}

/// What a `reregister` signs: `SHA256(address + pool_id)`, the address exactly as sent, no separator.
pub fn reregister_message(address: &str, pool_id: &str) -> [u8; 32] {
    sha256::Hash::hash(format!("{address}{pool_id}").as_bytes()).to_byte_array()
}

/// Phase 3: our output for the new transaction, signed as one of the ring.
pub fn build_reregister(
    address: &str,
    pool_id: &str,
    ring: &[PublicKey],
    key: &SecretKey,
) -> Result<PoolMessage, LsagError> {
    let signature = lsag::sign(&reregister_message(address, pool_id), ring, key)?;
    Ok(PoolMessage::Reregister {
        address: address.to_string(),
        sig: signature.to_field(),
        key_image: signature.y0,
        pool_id: pool_id.to_string(),
    })
}

/// A re-registered output a pool accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reregistered {
    /// The address as it was sent (the signature covers this text).
    pub sent: String,
    /// The address.
    pub address: Address,
    /// The verified key image: one per input owner.
    pub key_image: String,
}

/// Phase 3: check one decrypted message as a re-registration for our pool, or `None` to skip it. The
/// signature must verify under `ring` for the address as sent and OUR pool id (not the one the message
/// names), and the output is refused if its key image or its script is already among `accepted`. The key
/// image is the one inside the verified signature, never the message's `key_image` field, which anyone
/// can set.
pub fn accept_reregister(
    plaintext: &str,
    pool_id: &str,
    ring: &[PublicKey],
    network: Network,
    accepted: &[Reregistered],
) -> Option<Reregistered> {
    let PoolMessage::Reregister {
        address: sent, sig, ..
    } = PoolMessage::parse(plaintext)?
    else {
        return None;
    };
    let address = rules::output_address(&sent, network)?;
    let signature = Signature::from_field(&sig)?;
    if !lsag::verify(&reregister_message(&sent, pool_id), &signature, ring) {
        return None;
    }
    let script = address.script_pubkey();
    if accepted
        .iter()
        .any(|a| a.key_image == signature.y0 || a.address.script_pubkey() == script)
    {
        return None;
    }
    Some(Reregistered {
        sent,
        address,
        key_image: signature.y0,
    })
}

/// Phase 3: the outputs re-registered in a pool's decrypted messages, in arrival order, at most one per
/// ring member.
pub fn collect_reregistrations<'a>(
    plaintexts: impl IntoIterator<Item = &'a str>,
    pool_id: &str,
    ring: &[PublicKey],
    network: Network,
) -> Vec<Reregistered> {
    let mut accepted: Vec<Reregistered> = Vec::new();
    for text in plaintexts {
        if accepted.len() >= ring.len() {
            break;
        }
        if let Some(output) = accept_reregister(text, pool_id, ring, network, &accepted) {
            accepted.push(output);
        }
    }
    accepted
}

/// The transaction of the recovery round and the coins it spends, in input order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovery {
    /// The unsigned transaction every peer builds.
    pub tx: Transaction,
    /// The coin each input spends.
    pub coins: Vec<TxOut>,
}

/// Phase 4: the transaction every peer builds from the ring's inputs and the re-registered outputs:
/// version 2, locktime 0, inputs in BIP69 order with nSequence `0xfffffffe`, outputs in BIP69 order, each
/// paying [`rules::recovery_output_amount`]. Refused unless every ring member re-registered (one output per
/// input), the outputs clear dust, the inputs exceed them, and, with `fee_bounds`, the fee is within 100 to
/// 10,000 sats per input.
pub fn recovery_transaction(
    members: &[RingMember],
    outputs: &[ScriptBuf],
    denomination_btc: f64,
    fee_rate: f64,
    fee_bounds: bool,
) -> Result<Recovery, TxError> {
    if members.is_empty() || outputs.len() != members.len() {
        return Err(TxError::Combine("not every ring member re-registered"));
    }
    let count = |n: usize| u32::try_from(n).map_err(|_| TxError::Combine("too many peers"));
    let amount = rules::recovery_output_amount(
        denomination_btc,
        fee_rate,
        count(outputs.len())?,
        count(members.len())?,
    );
    let dust = outputs
        .iter()
        .map(|s| rules::dust_limit(s))
        .max()
        .unwrap_or(546);
    if amount < dust {
        return Err(TxError::Combine("outputs below dust"));
    }
    let amount = u64::try_from(amount).map_err(|_| TxError::Combine("outputs below dust"))?;
    let outputs = template(outputs, amount);
    let mut inputs: Vec<&RingMember> = members.iter().collect();
    inputs.sort_by_key(|m| (m.outpoint.txid.to_string(), m.outpoint.vout));
    let paid_in: u64 = inputs.iter().map(|m| m.coin.value.to_sat()).sum();
    let paid_out = amount.saturating_mul(outputs.len() as u64);
    if paid_in <= paid_out {
        return Err(TxError::Combine("inputs do not exceed outputs"));
    }
    if fee_bounds && !rules::fee_in_bounds(paid_in - paid_out, inputs.len()) {
        return Err(TxError::Combine("fee outside 100 to 10000 sats per input"));
    }
    Ok(Recovery {
        tx: Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .iter()
                .map(|m| TxIn {
                    previous_output: m.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: REGISTRATION_SEQUENCE,
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs,
        },
        coins: inputs.iter().map(|m| m.coin.clone()).collect(),
    })
}

fn all_digest(tx: &Transaction, index: usize, coin: &TxOut) -> Option<Message> {
    let hash = SighashCache::new(tx)
        .p2wpkh_signature_hash(
            index,
            &coin.script_pubkey,
            coin.value,
            EcdsaSighashType::All,
        )
        .ok()?;
    Some(Message::from_digest(hash.to_byte_array()))
}

/// Phase 4: our `resign` message: the recovery transaction as a PSBT with every input's `witness_utxo` and
/// our own input signed `SIGHASH_ALL` and finalized. Refused unless our output is in the transaction.
pub fn build_resign(
    recovery: &Recovery,
    my_script: &ScriptBuf,
    key: &SecretKey,
) -> Result<PoolMessage, TxError> {
    if !recovery
        .tx
        .output
        .iter()
        .any(|o| o.script_pubkey == *my_script)
    {
        return Err(TxError::Template("our output is missing"));
    }
    let secp = Secp256k1::new();
    let public = key.public_key(&secp);
    let script = ScriptBuf::new_p2wpkh(&CompressedPublicKey(public).wpubkey_hash());
    let index = recovery
        .coins
        .iter()
        .position(|c| c.script_pubkey == script)
        .ok_or(TxError::Key("not the key of a ring input"))?;
    let digest =
        all_digest(&recovery.tx, index, &recovery.coins[index]).ok_or(TxError::Key("sighash"))?;
    let signature = ecdsa::Signature {
        signature: secp.sign_ecdsa(&digest, key),
        sighash_type: EcdsaSighashType::All,
    };
    let mut psbt = Psbt::from_unsigned_tx(recovery.tx.clone()).map_err(|_| TxError::Key("psbt"))?;
    for (input, coin) in psbt.inputs.iter_mut().zip(&recovery.coins) {
        input.witness_utxo = Some(coin.clone());
    }
    psbt.inputs[index].final_script_witness = Some(Witness::p2wpkh(&signature, &public));
    psbt.inputs[index].final_script_sig = Some(ScriptBuf::new());
    Ok(PoolMessage::Resign {
        psbt: psbt.to_string(),
    })
}

/// Phase 4: the signed inputs a `resign` PSBT (base64) carries for our recovery transaction, as
/// `(input index, witness)`. It must be the same unsigned transaction; each finalized P2WPKH input (or one
/// carrying a partial signature) is verified as `SIGHASH_ALL` by the coin's key. Inputs that do not verify
/// are left out, so a bad chunk cannot overwrite a good witness.
pub fn accept_resign(
    psbt_base64: &str,
    recovery: &Recovery,
) -> Result<Vec<(usize, Witness)>, TxError> {
    let psbt =
        Psbt::from_str(psbt_base64.trim()).map_err(|_| TxError::Registration("unreadable PSBT"))?;
    if psbt.unsigned_tx != recovery.tx {
        return Err(TxError::Outputs);
    }
    let secp = Secp256k1::verification_only();
    let mut signed = Vec::new();
    for (index, (input, coin)) in psbt.inputs.iter().zip(&recovery.coins).enumerate() {
        let witness = match (
            &input.final_script_witness,
            input.partial_sigs.iter().next(),
        ) {
            (Some(witness), _) if !witness.is_empty() => witness.clone(),
            (_, Some((public, signature))) => Witness::p2wpkh(signature, &public.inner),
            _ => continue,
        };
        let (Some(sig), Some(public), 2) = (witness.nth(0), witness.nth(1), witness.len()) else {
            continue;
        };
        let (Ok(signature), Ok(public)) = (
            ecdsa::Signature::from_slice(sig),
            CompressedPublicKey::from_slice(public),
        ) else {
            continue;
        };
        let good = signature.sighash_type == EcdsaSighashType::All
            && ScriptBuf::new_p2wpkh(&public.wpubkey_hash()) == coin.script_pubkey
            && all_digest(&recovery.tx, index, coin).is_some_and(|digest| {
                secp.verify_ecdsa(&digest, &signature.signature, &public.0)
                    .is_ok()
            });
        if good {
            signed.push((index, witness));
        }
    }
    Ok(signed)
}

/// Phase 4: the finished transaction once every input has a witness, or `None` while some are missing.
pub fn finish(recovery: &Recovery, witnesses: &[Option<Witness>]) -> Option<Transaction> {
    if witnesses.len() != recovery.tx.input.len() {
        return None;
    }
    let mut tx = recovery.tx.clone();
    for (input, witness) in tx.input.iter_mut().zip(witnesses) {
        input.witness = witness.clone()?;
    }
    Some(tx)
}

#[cfg(test)]
mod tests {
    use bitcoin::{Amount, Txid};

    use super::*;
    use crate::tx::{build_registration, read_registration};

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn p2wpkh(k: &SecretKey) -> ScriptBuf {
        let public = CompressedPublicKey(k.public_key(&Secp256k1::new()));
        Address::p2wpkh(&public, Network::Regtest).script_pubkey()
    }

    fn address(k: &SecretKey) -> String {
        let public = CompressedPublicKey(k.public_key(&Secp256k1::new()));
        Address::p2wpkh(&public, Network::Regtest).to_string()
    }

    const DENOM: f64 = 0.001;
    const FEE: f64 = 2.5;

    /// Three peers whose inputs were registered in the failed round (the fourth output's owner withheld
    /// its input). Returns their registrations and keys.
    fn registered() -> (Vec<Registration>, Vec<SecretKey>) {
        let keys = vec![key(1), key(2), key(3)];
        let outputs: Vec<ScriptBuf> = (11..=13).map(|i| p2wpkh(&key(i))).collect();
        let template = template(&outputs, 99_750);
        let regs = keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let coin = TxOut {
                    value: Amount::from_sat(101_000 + i as u64),
                    script_pubkey: p2wpkh(k),
                };
                let outpoint = OutPoint {
                    txid: Txid::from_byte_array([0x10 + i as u8; 32]),
                    vout: i as u32,
                };
                let psbt =
                    build_registration(outpoint, &coin, &template, &outputs[i], 3, k).unwrap();
                read_registration(&psbt.to_string(), Some(&template)).unwrap()
            })
            .collect();
        (regs, keys)
    }

    #[test]
    fn the_ring_is_the_registered_inputs_keys_sorted_and_unique() {
        let (mut regs, keys) = registered();
        let members = ring_members(&regs);
        assert_eq!(members.len(), 3);
        let secp = Secp256k1::new();
        let mut expect: Vec<PublicKey> = keys.iter().map(|k| k.public_key(&secp)).collect();
        expect.sort_by_key(PublicKey::serialize);
        assert_eq!(members.iter().map(|m| m.key).collect::<Vec<_>>(), expect);
        // The same registration twice adds nothing; a witness naming another key is left out.
        regs.push(regs[0].clone());
        assert_eq!(ring_members(&regs).len(), 3);
        let mut forged = regs[1].clone();
        let sig = forged.witness.nth(0).unwrap().to_vec();
        forged.witness = Witness::from_slice(&[sig, key(9).public_key(&secp).serialize().to_vec()]);
        assert!(ring_member(&forged).is_none());
    }

    #[test]
    fn a_whole_recovery_round() {
        let (regs, keys) = registered();
        let members = ring_members(&regs);
        let ring: Vec<PublicKey> = members.iter().map(|m| m.key).collect();
        // Phase 3: each owner re-registers a fresh address; an outsider and a double registration fail.
        let fresh: Vec<SecretKey> = (21..=23).map(key).collect();
        let mut messages: Vec<String> = Vec::new();
        messages.push("junk".into());
        for (k, out) in keys.iter().zip(&fresh) {
            messages.push(
                build_reregister(&address(out), "pool1", &ring, k)
                    .unwrap()
                    .to_plaintext(),
            );
        }
        // The first owner tries a second output: same key image, refused.
        messages.push(
            build_reregister(&address(&key(30)), "pool1", &ring, &keys[0])
                .unwrap()
                .to_plaintext(),
        );
        assert_eq!(
            build_reregister(&address(&key(31)), "pool1", &ring, &key(99)),
            Err(LsagError::NotInRing)
        );
        let accepted = collect_reregistrations(
            messages.iter().map(String::as_str),
            "pool1",
            &ring,
            Network::Regtest,
        );
        assert_eq!(accepted.len(), 3);
        let images: std::collections::HashSet<&str> =
            accepted.iter().map(|a| a.key_image.as_str()).collect();
        assert_eq!(images.len(), 3);

        // Phase 4: everyone builds the same transaction and signs its own input.
        let outputs: Vec<ScriptBuf> = accepted.iter().map(|a| a.address.script_pubkey()).collect();
        let recovery = recovery_transaction(&members, &outputs, DENOM, FEE, true).unwrap();
        // 100 * 3 + 68 * 3 + 100 = 604 vbytes at 2.5 sat/vB = 1510; 1510 // 3 = 503 per output.
        assert!(
            recovery
                .tx
                .output
                .iter()
                .all(|o| o.value.to_sat() == 100_000 - 503)
        );
        assert!(
            recovery
                .tx
                .input
                .iter()
                .all(|i| i.sequence == REGISTRATION_SEQUENCE)
        );
        let mut shuffled = outputs.clone();
        shuffled.reverse();
        assert_eq!(
            recovery_transaction(&members, &shuffled, DENOM, FEE, true).unwrap(),
            recovery
        );

        let mut witnesses: Vec<Option<Witness>> = vec![None; 3];
        for (k, out) in keys.iter().zip(&fresh) {
            assert!(finish(&recovery, &witnesses).is_none());
            let PoolMessage::Resign { psbt } = build_resign(&recovery, &p2wpkh(out), k).unwrap()
            else {
                panic!("not a resign")
            };
            for (index, witness) in accept_resign(&psbt, &recovery).unwrap() {
                witnesses[index] = Some(witness);
            }
        }
        let tx = finish(&recovery, &witnesses).unwrap();
        assert!(tx.input.iter().all(|i| i.witness.len() == 2));
    }

    #[test]
    fn reregistrations_are_bound_to_the_pool_the_text_and_the_ring() {
        let (regs, keys) = registered();
        let ring: Vec<PublicKey> = ring_members(&regs).iter().map(|m| m.key).collect();
        let addr = address(&key(21));
        let text = build_reregister(&addr, "pool1", &ring, &keys[0])
            .unwrap()
            .to_plaintext();
        let accept =
            |text: &str, pool: &str| accept_reregister(text, pool, &ring, Network::Regtest, &[]);
        let ok = accept(&text, "pool1").unwrap();
        assert_eq!(ok.sent, addr);
        // Compact JSON is the same message; another pool id, an upper-cased address, a lying key image
        // field (ignored: the verified image is returned) and a tampered response.
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(accept(&value.to_string(), "pool1").is_some());
        assert!(accept(&text, "pool1x").is_none());
        let mut upper = value.clone();
        upper["address"] = serde_json::json!(addr.to_uppercase());
        assert!(accept(&upper.to_string(), "pool1").is_none());
        let mut lie = value.clone();
        lie["key_image"] = serde_json::json!(format!("02{}", "11".repeat(32)));
        assert_eq!(
            accept(&lie.to_string(), "pool1").unwrap().key_image,
            ok.key_image
        );
        let mut sig = Signature::from_field(value["sig"].as_str().unwrap()).unwrap();
        sig.s[0] = "0x1".into();
        let mut tampered = value.clone();
        tampered["sig"] = serde_json::json!(sig.to_field());
        assert!(accept(&tampered.to_string(), "pool1").is_none());
        // An output whose script is already taken is refused even from another owner.
        let other = build_reregister(&addr, "pool1", &ring, &keys[1])
            .unwrap()
            .to_plaintext();
        assert!(
            accept_reregister(
                &other,
                "pool1",
                &ring,
                Network::Regtest,
                std::slice::from_ref(&ok)
            )
            .is_none()
        );
    }

    #[test]
    fn the_recovery_transaction_and_resigns_are_checked() {
        let (regs, keys) = registered();
        let members = ring_members(&regs);
        let outputs: Vec<ScriptBuf> = (21..=23).map(|i| p2wpkh(&key(i))).collect();
        // Not every member re-registered: abandoned, the transaction would not balance.
        assert_eq!(
            recovery_transaction(&members, &outputs[..2], DENOM, FEE, true),
            Err(TxError::Combine("not every ring member re-registered"))
        );
        assert_eq!(
            recovery_transaction(&members, &outputs, 0.000004, 1.0, true),
            Err(TxError::Combine("outputs below dust"))
        );
        let recovery = recovery_transaction(&members, &outputs, DENOM, FEE, true).unwrap();
        // A key outside the ring, and an output that is not ours.
        assert_eq!(
            build_resign(&recovery, &outputs[0], &key(99)),
            Err(TxError::Key("not the key of a ring input"))
        );
        assert_eq!(
            build_resign(&recovery, &p2wpkh(&key(50)), &keys[0]),
            Err(TxError::Template("our output is missing"))
        );
        // A resign for another transaction is refused; one with a broken signature contributes nothing.
        let other = recovery_transaction(&members, &outputs, DENOM, 3.0, true).unwrap();
        let PoolMessage::Resign { psbt } = build_resign(&other, &outputs[0], &keys[0]).unwrap()
        else {
            panic!()
        };
        assert_eq!(accept_resign(&psbt, &recovery), Err(TxError::Outputs));
        let PoolMessage::Resign { psbt } = build_resign(&recovery, &outputs[0], &keys[0]).unwrap()
        else {
            panic!()
        };
        assert_eq!(accept_resign(&psbt, &recovery).unwrap().len(), 1);
        let mut broken = Psbt::from_str(&psbt).unwrap();
        for input in &mut broken.inputs {
            if let Some(w) = &input.final_script_witness {
                let mut items: Vec<Vec<u8>> = w.iter().map(<[u8]>::to_vec).collect();
                items[0][10] ^= 1;
                input.final_script_witness = Some(Witness::from_slice(&items));
            }
        }
        assert!(
            accept_resign(&broken.to_string(), &recovery)
                .unwrap()
                .is_empty()
        );
    }
}
