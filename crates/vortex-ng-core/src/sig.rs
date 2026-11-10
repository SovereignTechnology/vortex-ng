//! `!sig` payloads per pit, and the taker's verification before a signature enters the transaction.
//!
//! After NaCl decryption a `!sig` carries one input's signature data, base64-encoded:
//!
//! | pit | payload | final witness |
//! |---|---|---|
//! | `sw0` (JMP-0001) | `push(DER sig ‖ 0x01) ‖ push(pubkey33)` | `[sig, pubkey]` |
//! | `tr0` (JMP-0010) | `0x40 ‖ sig64 ‖ 0x20 ‖ output_key32` | `[sig64]` |
//! | `wsh0` (draft) | `push(sig1) ‖ push(sig2) ‖ push(witness_script)` | `[ε, sig1, sig2, witness_script]` |
//!
//! Every signature is verified against the input's real sighash (BIP143 `SIGHASH_ALL`, or BIP341
//! `SIGHASH_DEFAULT` over all prevouts) and the script must match the prevout, before the witness is used.

use bitcoin::base64::Engine;
use bitcoin::base64::engine::general_purpose::STANDARD;
use bitcoin::script::{Builder, Instruction, PushBytesBuf};
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, Verification, XOnlyPublicKey, schnorr};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{CompressedPublicKey, Script, ScriptBuf, Transaction, TxOut, Witness, ecdsa};

use crate::offer::Pit;
use crate::script::wsh0_witness_script;

/// Why a `!sig` was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigError {
    /// Not the pit's payload format.
    Malformed(&'static str),
    /// The key or script does not match the input's prevout.
    WrongScript,
    /// A signature does not verify, or uses another sighash type.
    BadSignature,
    /// The input index or prevouts are inconsistent with the transaction.
    Inputs,
}

impl std::fmt::Display for SigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rejected !sig: {self:?}")
    }
}

impl std::error::Error for SigError {}

fn pushes(items: &[&[u8]]) -> Vec<u8> {
    let mut builder = Builder::new();
    for item in items {
        // Items are at most a 520-byte script; PushBytesBuf accepts that.
        let push = PushBytesBuf::try_from(item.to_vec()).unwrap_or_default();
        builder = builder.push_slice(push);
    }
    builder.into_bytes()
}

fn parse_pushes(bytes: &[u8]) -> Result<Vec<Vec<u8>>, SigError> {
    let mut items = Vec::new();
    for instruction in Script::from_bytes(bytes).instructions_minimal() {
        match instruction.map_err(|_| SigError::Malformed("script pushes"))? {
            Instruction::PushBytes(p) if !p.is_empty() => items.push(p.as_bytes().to_vec()),
            _ => return Err(SigError::Malformed("only non-empty pushes")),
        }
    }
    Ok(items)
}

/// The `sw0` payload for a P2WPKH input.
pub fn encode_sw0(sig: &ecdsa::Signature, pubkey: &PublicKey) -> String {
    STANDARD.encode(pushes(&[&sig.serialize(), &pubkey.serialize()]))
}

/// The `tr0` payload for a P2TR key-path input (`SIGHASH_DEFAULT`, 64-byte signature).
pub fn encode_tr0(sig: &schnorr::Signature, output_key: &XOnlyPublicKey) -> String {
    let mut out = vec![0x40];
    out.extend_from_slice(sig.as_ref());
    out.push(0x20);
    out.extend_from_slice(&output_key.serialize());
    STANDARD.encode(out)
}

/// The `wsh0` payload: both signatures in the witness script's key order, then the script.
pub fn encode_wsh0(
    sig1: &ecdsa::Signature,
    sig2: &ecdsa::Signature,
    witness_script: &Script,
) -> String {
    STANDARD.encode(pushes(&[
        &sig1.serialize(),
        &sig2.serialize(),
        witness_script.as_bytes(),
    ]))
}

fn ecdsa_all(bytes: &[u8]) -> Result<ecdsa::Signature, SigError> {
    let sig =
        ecdsa::Signature::from_slice(bytes).map_err(|_| SigError::Malformed("ecdsa signature"))?;
    if sig.sighash_type != EcdsaSighashType::All {
        return Err(SigError::BadSignature);
    }
    Ok(sig)
}

/// The two keys of a `wsh0` witness script, in script order, or `None` if it is not exactly one.
pub fn wsh0_keys(witness_script: &Script) -> Option<(PublicKey, PublicKey)> {
    let bytes = witness_script.as_bytes();
    if bytes.len() != 71 || bytes[1] != 33 || bytes[35] != 33 {
        return None;
    }
    let k1 = PublicKey::from_slice(&bytes[2..35]).ok()?;
    let k2 = PublicKey::from_slice(&bytes[36..69]).ok()?;
    (wsh0_witness_script(&k1, &k2)?.as_bytes() == bytes).then_some((k1, k2))
}

/// Verify a decrypted `!sig` payload for `tx`'s input `index` in `pit`, given every input's prevout, and
/// return the input's final witness.
pub fn verify_sig<C: Verification>(
    secp: &Secp256k1<C>,
    pit: Pit,
    payload_b64: &str,
    tx: &Transaction,
    index: usize,
    prevouts: &[TxOut],
) -> Result<Witness, SigError> {
    if prevouts.len() != tx.input.len() || index >= tx.input.len() {
        return Err(SigError::Inputs);
    }
    let prevout = &prevouts[index];
    let raw = STANDARD
        .decode(payload_b64)
        .map_err(|_| SigError::Malformed("base64"))?;
    let mut cache = SighashCache::new(tx);
    match pit {
        Pit::Sw0 => {
            let [sig, key] = parse_pushes(&raw)?
                .try_into()
                .map_err(|_| SigError::Malformed("two pushes"))?;
            let sig = ecdsa_all(&sig)?;
            let key = PublicKey::from_slice(&key).map_err(|_| SigError::Malformed("pubkey"))?;
            if key.serialize().len() != 33
                || prevout.script_pubkey
                    != ScriptBuf::new_p2wpkh(&CompressedPublicKey(key).wpubkey_hash())
            {
                return Err(SigError::WrongScript);
            }
            let sighash = cache
                .p2wpkh_signature_hash(
                    index,
                    &prevout.script_pubkey,
                    prevout.value,
                    EcdsaSighashType::All,
                )
                .map_err(|_| SigError::Inputs)?;
            secp.verify_ecdsa(&Message::from(sighash), &sig.signature, &key)
                .map_err(|_| SigError::BadSignature)?;
            Ok(Witness::from_slice(&[
                sig.serialize().to_vec(),
                key.serialize().to_vec(),
            ]))
        }
        Pit::Tr0 => {
            if raw.len() != 98 || raw[0] != 0x40 || raw[65] != 0x20 {
                return Err(SigError::Malformed("tr0 payload"));
            }
            let sig = schnorr::Signature::from_slice(&raw[1..65])
                .map_err(|_| SigError::Malformed("signature"))?;
            let key = XOnlyPublicKey::from_slice(&raw[66..98])
                .map_err(|_| SigError::Malformed("output key"))?;
            let mut expected = vec![0x51, 0x20];
            expected.extend_from_slice(&key.serialize());
            if prevout.script_pubkey.as_bytes() != expected.as_slice() {
                return Err(SigError::WrongScript);
            }
            let sighash = cache
                .taproot_key_spend_signature_hash(
                    index,
                    &Prevouts::All(prevouts),
                    TapSighashType::Default,
                )
                .map_err(|_| SigError::Inputs)?;
            secp.verify_schnorr(&sig, &Message::from(sighash), &key)
                .map_err(|_| SigError::BadSignature)?;
            Ok(Witness::from_slice(&[sig.as_ref().to_vec()]))
        }
        Pit::Wsh0 => {
            let [sig1, sig2, script] = parse_pushes(&raw)?
                .try_into()
                .map_err(|_| SigError::Malformed("three pushes"))?;
            let script = ScriptBuf::from_bytes(script);
            let (k1, k2) = wsh0_keys(&script).ok_or(SigError::Malformed("witness script"))?;
            if prevout.script_pubkey != ScriptBuf::new_p2wsh(&script.wscript_hash()) {
                return Err(SigError::WrongScript);
            }
            let (sig1, sig2) = (ecdsa_all(&sig1)?, ecdsa_all(&sig2)?);
            let sighash = cache
                .p2wsh_signature_hash(index, &script, prevout.value, EcdsaSighashType::All)
                .map_err(|_| SigError::Inputs)?;
            let msg = Message::from(sighash);
            secp.verify_ecdsa(&msg, &sig1.signature, &k1)
                .map_err(|_| SigError::BadSignature)?;
            secp.verify_ecdsa(&msg, &sig2.signature, &k2)
                .map_err(|_| SigError::BadSignature)?;
            Ok(Witness::from_slice(&[
                Vec::new(),
                sig1.serialize().to_vec(),
                sig2.serialize().to_vec(),
                script.as_bytes().to_vec(),
            ]))
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::key::{Keypair, TapTweak};
    use bitcoin::secp256k1::{All, SecretKey};
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, Sequence, TxIn, Txid};

    use super::*;
    use crate::script::wsh0_script_pubkey;

    fn secp() -> Secp256k1<All> {
        Secp256k1::new()
    }
    fn sk(b: u8) -> SecretKey {
        SecretKey::from_slice(&[b; 32]).unwrap()
    }
    fn pk(b: u8) -> PublicKey {
        PublicKey::from_secret_key(&secp(), &sk(b))
    }

    fn tx() -> Transaction {
        let input = |n: u8| TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([n; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![input(1), input(2)],
            output: vec![TxOut {
                value: Amount::from_sat(150_000),
                script_pubkey: wsh0_script_pubkey(&pk(8), &pk(9)).unwrap(),
            }],
        }
    }

    fn ecdsa_sign(msg: Message, key: &SecretKey) -> ecdsa::Signature {
        ecdsa::Signature::sighash_all(secp().sign_ecdsa(&msg, key))
    }

    #[test]
    fn sw0_round_trip_and_failures() {
        let s = secp();
        let tx = tx();
        let spk = ScriptBuf::new_p2wpkh(&CompressedPublicKey(pk(1)).wpubkey_hash());
        let prevouts = vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: spk.clone(),
            },
            TxOut::NULL,
        ];
        let sighash = SighashCache::new(&tx)
            .p2wpkh_signature_hash(0, &spk, Amount::from_sat(100_000), EcdsaSighashType::All)
            .unwrap();
        let sig = ecdsa_sign(Message::from(sighash), &sk(1));
        let payload = encode_sw0(&sig, &pk(1));
        let witness = verify_sig(&s, Pit::Sw0, &payload, &tx, 0, &prevouts).unwrap();
        assert_eq!(witness.len(), 2);
        // Wrong amount (the maker signed another value), wrong input, wrong key.
        let mut other = prevouts.clone();
        other[0].value = Amount::from_sat(100_001);
        assert_eq!(
            verify_sig(&s, Pit::Sw0, &payload, &tx, 0, &other),
            Err(SigError::BadSignature)
        );
        assert_eq!(
            verify_sig(&s, Pit::Sw0, &payload, &tx, 1, &prevouts),
            Err(SigError::WrongScript)
        );
        assert_eq!(
            verify_sig(&s, Pit::Sw0, &encode_sw0(&sig, &pk(2)), &tx, 0, &prevouts),
            Err(SigError::WrongScript)
        );
        // Another sighash type.
        let none = ecdsa::Signature {
            signature: sig.signature,
            sighash_type: EcdsaSighashType::None,
        };
        assert_eq!(
            verify_sig(&s, Pit::Sw0, &encode_sw0(&none, &pk(1)), &tx, 0, &prevouts),
            Err(SigError::BadSignature)
        );
        // Garbage, too few prevouts.
        assert!(verify_sig(&s, Pit::Sw0, "AAAA", &tx, 0, &prevouts).is_err());
        assert_eq!(
            verify_sig(&s, Pit::Sw0, &payload, &tx, 0, &prevouts[..1]),
            Err(SigError::Inputs)
        );
    }

    #[test]
    fn tr0_round_trip_and_failures() {
        let s = secp();
        let tx = tx();
        let tweaked = Keypair::from_secret_key(&s, &sk(3))
            .tap_tweak(&s, None)
            .to_keypair();
        let (output_key, _) = tweaked.x_only_public_key();
        let mut spk = vec![0x51, 0x20];
        spk.extend_from_slice(&output_key.serialize());
        let spk = ScriptBuf::from_bytes(spk);
        let other_spk = ScriptBuf::new_p2wpkh(&CompressedPublicKey(pk(4)).wpubkey_hash());
        let prevouts = vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: spk,
            },
            TxOut {
                value: Amount::from_sat(60_000),
                script_pubkey: other_spk,
            },
        ];
        let sighash = SighashCache::new(&tx)
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        let sig = s.sign_schnorr_no_aux_rand(&Message::from(sighash), &tweaked);
        let payload = encode_tr0(&sig, &output_key);
        assert_eq!(STANDARD.decode(&payload).unwrap().len(), 98);
        assert_eq!(
            verify_sig(&s, Pit::Tr0, &payload, &tx, 0, &prevouts)
                .unwrap()
                .len(),
            1
        );
        // BIP341 commits to every prevout: changing the other input's amount breaks the signature.
        let mut other = prevouts.clone();
        other[1].value = Amount::from_sat(60_001);
        assert_eq!(
            verify_sig(&s, Pit::Tr0, &payload, &tx, 0, &other),
            Err(SigError::BadSignature)
        );
        // 65-byte form (with a sighash byte) is rejected.
        let mut long = STANDARD.decode(&payload).unwrap();
        long.insert(65, 0x00);
        assert!(verify_sig(&s, Pit::Tr0, &STANDARD.encode(long), &tx, 0, &prevouts).is_err());
        // The untweaked internal key does not match the output.
        let (internal, _) = sk(3).x_only_public_key(&s);
        assert_eq!(
            verify_sig(
                &s,
                Pit::Tr0,
                &encode_tr0(&sig, &internal),
                &tx,
                0,
                &prevouts
            ),
            Err(SigError::WrongScript)
        );
    }

    #[test]
    fn wsh0_round_trip_and_failures() {
        let s = secp();
        let tx = tx();
        let script = wsh0_witness_script(&pk(5), &pk(6)).unwrap();
        let (k1, k2) = wsh0_keys(&script).unwrap();
        assert!(k1.serialize() < k2.serialize(), "script order is sorted");
        let (s1, s2) = if k1 == pk(5) {
            (sk(5), sk(6))
        } else {
            (sk(6), sk(5))
        };
        let spk = ScriptBuf::new_p2wsh(&script.wscript_hash());
        let prevouts = vec![
            TxOut::NULL,
            TxOut {
                value: Amount::from_sat(80_000),
                script_pubkey: spk,
            },
        ];
        let sighash = SighashCache::new(&tx)
            .p2wsh_signature_hash(1, &script, Amount::from_sat(80_000), EcdsaSighashType::All)
            .unwrap();
        let (sig1, sig2) = (
            ecdsa_sign(Message::from(sighash), &s1),
            ecdsa_sign(Message::from(sighash), &s2),
        );
        let witness = verify_sig(
            &s,
            Pit::Wsh0,
            &encode_wsh0(&sig1, &sig2, &script),
            &tx,
            1,
            &prevouts,
        )
        .unwrap();
        assert_eq!(witness.len(), 4);
        assert!(witness.nth(0).unwrap().is_empty());
        // Signatures swapped (not in key order) fail.
        assert_eq!(
            verify_sig(
                &s,
                Pit::Wsh0,
                &encode_wsh0(&sig2, &sig1, &script),
                &tx,
                1,
                &prevouts
            ),
            Err(SigError::BadSignature)
        );
        // A different script (a 1-of-1) is not a wsh0 script.
        let one = Builder::new()
            .push_key(&bitcoin::PublicKey::new(pk(5)))
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        assert!(
            verify_sig(
                &s,
                Pit::Wsh0,
                &encode_wsh0(&sig1, &sig2, &one),
                &tx,
                1,
                &prevouts
            )
            .is_err()
        );
        assert!(wsh0_keys(&one).is_none());
    }
}
