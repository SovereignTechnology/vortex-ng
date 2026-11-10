//! Fidelity-bond proofs (JMP-0001 "Fidelity Bonds").
//!
//! A maker proves, per taker, that it controls a timelocked P2WSH bond: a 252-byte structure
//! `<72s72s33sH33s32sII` (little-endian) holding the nick signature, the certificate signature, the
//! certificate key, the certificate expiry (a 2016-block period), the bond UTXO's key, its txid (display
//! order), vout and locktime, sent base64-encoded as `!tbond`. Both signatures are Bitcoin Signed Message
//! ECDSA, DER, left-padded to 72 bytes with `0xff`. The nick signature (certificate key) covers
//! `<taker_nick>|<maker_nick>`; the certificate signature (UTXO key) covers
//! `fidelity-bond-cert|<cert_pubkey>|<expiry>` with the raw 33-byte key, or the legacy hex form.

use bitcoin::base64::Engine;
use bitcoin::base64::engine::general_purpose::STANDARD;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CLTV, OP_DROP};
use bitcoin::script::Builder;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, Signing, Verification};
use bitcoin::{OutPoint, Script, ScriptBuf, Txid};

use crate::sigmsg;

/// Serialized proof length.
pub const PROOF_LEN: usize = 252;
/// Blocks per certificate-expiry period (one difficulty retarget).
pub const RETARGET_INTERVAL: u32 = 2016;
const SIG_FIELD: usize = 72;

/// Why a proof was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BondError {
    /// Not base64 of 252 bytes, or a field does not parse.
    Malformed(&'static str),
    /// The nick signature does not verify.
    BadNickSignature,
    /// The certificate signature does not verify (binary or legacy hex form).
    BadCertSignature,
    /// The certificate has expired at the given height.
    Expired,
    /// The UTXO's scriptPubKey is not the P2WSH of the freeze script.
    ScriptMismatch,
    /// The bond UTXO is missing or unconfirmed.
    Unconfirmed,
}

impl std::fmt::Display for BondError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BondError::Malformed(why) => write!(f, "malformed fidelity-bond proof: {why}"),
            BondError::BadNickSignature => {
                f.write_str("fidelity-bond nick signature does not verify")
            }
            BondError::BadCertSignature => {
                f.write_str("fidelity-bond certificate signature does not verify")
            }
            BondError::Expired => f.write_str("fidelity-bond certificate expired"),
            BondError::ScriptMismatch => {
                f.write_str("fidelity-bond UTXO is not the timelocked script")
            }
            BondError::Unconfirmed => f.write_str("fidelity-bond UTXO missing or unconfirmed"),
        }
    }
}

impl std::error::Error for BondError {}

/// The certificate message, binary form (raw 33-byte key).
pub fn cert_message(cert_pubkey: &PublicKey, cert_expiry: u16) -> Vec<u8> {
    let mut m = b"fidelity-bond-cert|".to_vec();
    m.extend_from_slice(&cert_pubkey.serialize());
    m.push(b'|');
    m.extend_from_slice(cert_expiry.to_string().as_bytes());
    m
}

/// The certificate message, legacy form (66-character hex key). Verifiers accept either.
pub fn cert_message_ascii(cert_pubkey: &PublicKey, cert_expiry: u16) -> Vec<u8> {
    use bitcoin::hex::DisplayHex;
    format!(
        "fidelity-bond-cert|{}|{cert_expiry}",
        cert_pubkey.serialize().to_lower_hex_string()
    )
    .into_bytes()
}

/// The bond's witness script: `<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <pubkey> OP_CHECKSIG`.
pub fn freeze_script(utxo_pubkey: &PublicKey, locktime: u32) -> ScriptBuf {
    Builder::new()
        .push_int(i64::from(locktime))
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_key(&bitcoin::PublicKey::new(*utxo_pubkey))
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// A parsed fidelity-bond proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondProof {
    /// DER nick signature by the certificate key.
    pub nick_sig: Vec<u8>,
    /// DER certificate signature by the UTXO key.
    pub cert_sig: Vec<u8>,
    /// The certificate (delegated signing) key.
    pub cert_pubkey: PublicKey,
    /// The 2016-block period in which the certificate expires.
    pub cert_expiry: u16,
    /// The key that can spend the bond UTXO after the locktime.
    pub utxo_pubkey: PublicKey,
    /// The bond UTXO.
    pub outpoint: OutPoint,
    /// The bond's absolute locktime.
    pub locktime: u32,
}

fn pad(der: &[u8]) -> Result<[u8; SIG_FIELD], BondError> {
    if der.len() > SIG_FIELD || der.first() != Some(&0x30) {
        return Err(BondError::Malformed("signature"));
    }
    let mut out = [0xffu8; SIG_FIELD];
    out[SIG_FIELD - der.len()..].copy_from_slice(der);
    Ok(out)
}

fn unpad(field: &[u8]) -> Result<Vec<u8>, BondError> {
    let start = field
        .iter()
        .position(|b| *b != 0xff)
        .ok_or(BondError::Malformed("signature"))?;
    if field[start] != 0x30 {
        return Err(BondError::Malformed("signature header"));
    }
    Ok(field[start..].to_vec())
}

impl BondProof {
    /// Sign the certificate: the UTXO key delegates to `cert_pubkey` until `cert_expiry`. Returns DER.
    pub fn sign_certificate<C: Signing>(
        secp: &Secp256k1<C>,
        utxo_key: &SecretKey,
        cert_pubkey: &PublicKey,
        cert_expiry: u16,
    ) -> Vec<u8> {
        sigmsg::sign_der(secp, &cert_message(cert_pubkey, cert_expiry), utxo_key)
    }

    /// Build a proof for `taker_nick`, signing the nick message with the certificate key.
    #[allow(clippy::too_many_arguments)]
    pub fn create<C: Signing>(
        secp: &Secp256k1<C>,
        cert_key: &SecretKey,
        cert_sig: Vec<u8>,
        cert_expiry: u16,
        utxo_pubkey: PublicKey,
        outpoint: OutPoint,
        locktime: u32,
        taker_nick: &str,
        maker_nick: &str,
    ) -> BondProof {
        let nick_sig = sigmsg::sign_der(
            secp,
            format!("{taker_nick}|{maker_nick}").as_bytes(),
            cert_key,
        );
        BondProof {
            nick_sig,
            cert_sig,
            cert_pubkey: PublicKey::from_secret_key(secp, cert_key),
            cert_expiry,
            utxo_pubkey,
            outpoint,
            locktime,
        }
    }

    /// The 252-byte serialization, base64-encoded for `!tbond`.
    pub fn to_base64(&self) -> Result<String, BondError> {
        let mut out = Vec::with_capacity(PROOF_LEN);
        out.extend_from_slice(&pad(&self.nick_sig)?);
        out.extend_from_slice(&pad(&self.cert_sig)?);
        out.extend_from_slice(&self.cert_pubkey.serialize());
        out.extend_from_slice(&self.cert_expiry.to_le_bytes());
        out.extend_from_slice(&self.utxo_pubkey.serialize());
        let mut txid = self.outpoint.txid.to_byte_array();
        txid.reverse(); // display order
        out.extend_from_slice(&txid);
        out.extend_from_slice(&self.outpoint.vout.to_le_bytes());
        out.extend_from_slice(&self.locktime.to_le_bytes());
        Ok(STANDARD.encode(out))
    }

    /// Parse a `!tbond` argument.
    pub fn from_base64(data: &str) -> Result<BondProof, BondError> {
        let raw = STANDARD
            .decode(data)
            .map_err(|_| BondError::Malformed("base64"))?;
        if raw.len() != PROOF_LEN {
            return Err(BondError::Malformed("length"));
        }
        let key = |r: std::ops::Range<usize>| {
            PublicKey::from_slice(&raw[r]).map_err(|_| BondError::Malformed("public key"))
        };
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&raw[212..244]);
        txid.reverse(); // display order on the wire
        let u32_at = |i: usize| u32::from_le_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]]);
        Ok(BondProof {
            nick_sig: unpad(&raw[0..72])?,
            cert_sig: unpad(&raw[72..144])?,
            cert_pubkey: key(144..177)?,
            cert_expiry: u16::from_le_bytes([raw[177], raw[178]]),
            utxo_pubkey: key(179..212)?,
            outpoint: OutPoint {
                txid: Txid::from_byte_array(txid),
                vout: u32_at(244),
            },
            locktime: u32_at(248),
        })
    }

    /// Verify both signatures for a proof the maker `maker_nick` sent to `taker_nick`.
    pub fn verify_signatures<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        taker_nick: &str,
        maker_nick: &str,
    ) -> Result<(), BondError> {
        let nick_msg = format!("{taker_nick}|{maker_nick}");
        if !sigmsg::verify_der(secp, nick_msg.as_bytes(), &self.nick_sig, &self.cert_pubkey) {
            return Err(BondError::BadNickSignature);
        }
        let binary = cert_message(&self.cert_pubkey, self.cert_expiry);
        let ascii = cert_message_ascii(&self.cert_pubkey, self.cert_expiry);
        if !sigmsg::verify_der(secp, &binary, &self.cert_sig, &self.utxo_pubkey)
            && !sigmsg::verify_der(secp, &ascii, &self.cert_sig, &self.utxo_pubkey)
        {
            return Err(BondError::BadCertSignature);
        }
        Ok(())
    }

    /// The scriptPubKey the bond UTXO must have.
    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2wsh(&freeze_script(&self.utxo_pubkey, self.locktime).wscript_hash())
    }

    /// The chain checks a taker applies with the UTXO it looked up: the UTXO exists and is confirmed,
    /// the certificate has not expired at `height`, and the scriptPubKey is the freeze script's P2WSH.
    pub fn check_utxo(
        &self,
        height: u32,
        utxo_spk: Option<&Script>,
        confirmations: u32,
    ) -> Result<(), BondError> {
        let spk = utxo_spk.ok_or(BondError::Unconfirmed)?;
        if confirmations == 0 {
            return Err(BondError::Unconfirmed);
        }
        if height > u32::from(self.cert_expiry).saturating_mul(RETARGET_INTERVAL) {
            return Err(BondError::Expired);
        }
        if spk != self.script_pubkey().as_script() {
            return Err(BondError::ScriptMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    // From `tools/ref-vectors/ref.py` (independent; RFC 6979 + DER + the reference's packing).
    const PROOF: &str = "//8wRAIgWS6q77OqfhHxDZnx11nOfkhuJa0FwIjA2FaMrB0egSICICUtSg085/+R7eNNHfXeIn0Tm4XBEC1mkQoImw0yE4oN//8wRAIgFd3wQcCS35ZGCyTpvuBlEYn2dkX4q96dr8jYjfF3zV4CIBzrVG5x/63S8Rv8/CiA4VptLQ51f7x24sKo0mrJn0d0AlazKLMMi/WDniQFh0eHlAi9s2JB3JwufGGfqhKykglnNAAD92o50FaG40pEIIl+NZNxg2FF3Tlz45glaLYPhDOt3m6rq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urqwEAAAAAuVVp";

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn outpoint() -> OutPoint {
        OutPoint {
            txid: Txid::from_str(&"ab".repeat(32)).unwrap(),
            vout: 1,
        }
    }

    #[test]
    fn reference_vector_parses_verifies_and_reserializes() {
        let secp = Secp256k1::new();
        let proof = BondProof::from_base64(PROOF).unwrap();
        assert_eq!(proof.cert_expiry, 52);
        assert_eq!(proof.locktime, 1_767_225_600);
        assert_eq!(proof.outpoint, outpoint());
        assert_eq!(
            proof.cert_pubkey,
            PublicKey::from_secret_key(&secp, &key(9))
        );
        assert_eq!(
            proof.utxo_pubkey,
            PublicKey::from_secret_key(&secp, &key(10))
        );
        proof
            .verify_signatures(&secp, "J5TestTaker", "J52TestMaker")
            .unwrap();
        assert_eq!(proof.to_base64().unwrap(), PROOF);
        // Built here from the same inputs, it is byte-identical.
        let cert_sig = BondProof::sign_certificate(&secp, &key(10), &proof.cert_pubkey, 52);
        let built = BondProof::create(
            &secp,
            &key(9),
            cert_sig,
            52,
            proof.utxo_pubkey,
            outpoint(),
            1_767_225_600,
            "J5TestTaker",
            "J52TestMaker",
        );
        assert_eq!(built.to_base64().unwrap(), PROOF);
    }

    #[test]
    fn signature_failures() {
        let secp = Secp256k1::new();
        let proof = BondProof::from_base64(PROOF).unwrap();
        // Replayed to another taker, or claimed by another maker.
        assert_eq!(
            proof.verify_signatures(&secp, "J5OtherTaker", "J52TestMaker"),
            Err(BondError::BadNickSignature)
        );
        assert_eq!(
            proof.verify_signatures(&secp, "J5TestTaker", "J5OtherMaker"),
            Err(BondError::BadNickSignature)
        );
        // Certificate expiry changed.
        let mut bad = proof.clone();
        bad.cert_expiry = 53;
        assert_eq!(
            bad.verify_signatures(&secp, "J5TestTaker", "J52TestMaker"),
            Err(BondError::BadCertSignature)
        );
        // Legacy hex certificate form is accepted.
        let mut legacy = proof.clone();
        legacy.cert_sig =
            sigmsg::sign_der(&secp, &cert_message_ascii(&proof.cert_pubkey, 52), &key(10));
        legacy
            .verify_signatures(&secp, "J5TestTaker", "J52TestMaker")
            .unwrap();
    }

    #[test]
    fn chain_checks() {
        let proof = BondProof::from_base64(PROOF).unwrap();
        let spk = proof.script_pubkey();
        let last_valid = 52 * RETARGET_INTERVAL;
        proof.check_utxo(last_valid, Some(&spk), 1).unwrap();
        assert_eq!(
            proof.check_utxo(last_valid + 1, Some(&spk), 1),
            Err(BondError::Expired)
        );
        assert_eq!(
            proof.check_utxo(100, Some(&spk), 0),
            Err(BondError::Unconfirmed)
        );
        assert_eq!(proof.check_utxo(100, None, 6), Err(BondError::Unconfirmed));
        let other = ScriptBuf::new_p2wsh(
            &freeze_script(&proof.utxo_pubkey, proof.locktime + 1).wscript_hash(),
        );
        assert_eq!(
            proof.check_utxo(100, Some(&other), 6),
            Err(BondError::ScriptMismatch)
        );
    }

    #[test]
    fn malformed() {
        assert!(BondProof::from_base64("").is_err());
        assert!(BondProof::from_base64(&PROOF[4..]).is_err());
        let mut raw = STANDARD.decode(PROOF).unwrap();
        raw[2] = 0x00; // break the 0xff padding before the DER header
        raw[3] = 0x00;
        assert!(BondProof::from_base64(&STANDARD.encode(&raw)).is_err());
    }
}
