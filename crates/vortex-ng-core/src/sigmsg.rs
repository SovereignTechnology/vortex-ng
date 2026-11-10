//! Bitcoin Signed Message ECDSA, as JoinMarket uses it for nick signatures and fidelity-bond
//! certificates (JMP-0001 "Nick Signature Verification", "Fidelity Bonds").
//!
//! The digest is `SHA256d("\x18Bitcoin Signed Message:\n" || compact_size(len) || message)`. Signatures
//! are strict DER and low-S, base64-encoded (standard alphabet, padded). Signing uses libsecp256k1's
//! RFC 6979 nonces without low-R grinding, so a signature is byte-identical to joinmarket-ng's
//! (`jmcore.crypto.ecdsa_sign`).

use bitcoin::base64::Engine;
use bitcoin::base64::engine::general_purpose::STANDARD;
use bitcoin::hashes::{Hash, sha256d};
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey, Signing, Verification};

const MAGIC: &[u8] = b"\x18Bitcoin Signed Message:\n";

/// Bitcoin's CompactSize encoding of `n`.
pub(crate) fn compact_size(n: u64) -> Vec<u8> {
    match n {
        0..=0xfc => vec![n as u8],
        0xfd..=0xffff => {
            let mut v = vec![0xfd];
            v.extend_from_slice(&(n as u16).to_le_bytes());
            v
        }
        0x1_0000..=0xffff_ffff => {
            let mut v = vec![0xfe];
            v.extend_from_slice(&(n as u32).to_le_bytes());
            v
        }
        _ => {
            let mut v = vec![0xff];
            v.extend_from_slice(&n.to_le_bytes());
            v
        }
    }
}

/// The Bitcoin Signed Message digest of `message`.
pub fn signed_message_hash(message: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(MAGIC.len() + 9 + message.len());
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&compact_size(message.len() as u64));
    buf.extend_from_slice(message);
    sha256d::Hash::hash(&buf).to_byte_array()
}

/// Sign `message`; returns the base64 of the DER signature.
pub fn sign<C: Signing>(secp: &Secp256k1<C>, message: &[u8], key: &SecretKey) -> String {
    let digest = Message::from_digest(signed_message_hash(message));
    STANDARD.encode(secp.sign_ecdsa(&digest, key).serialize_der())
}

/// The DER signature over `message`, for binary containers such as the fidelity-bond proof.
pub fn sign_der<C: Signing>(secp: &Secp256k1<C>, message: &[u8], key: &SecretKey) -> Vec<u8> {
    let digest = Message::from_digest(signed_message_hash(message));
    secp.sign_ecdsa(&digest, key).serialize_der().to_vec()
}

/// Verify a strict-DER, low-S `der` signature over `message` by `key`.
pub fn verify_der<C: Verification>(
    secp: &Secp256k1<C>,
    message: &[u8],
    der: &[u8],
    key: &PublicKey,
) -> bool {
    // `from_der` is strict DER; libsecp256k1's verification rejects high-S signatures.
    let Ok(signature) = Signature::from_der(der) else {
        return false;
    };
    let digest = Message::from_digest(signed_message_hash(message));
    secp.verify_ecdsa(&digest, &signature, key).is_ok()
}

/// Verify a base64 DER signature over `message` by `key`. Malformed input verifies as false.
pub fn verify<C: Verification>(
    secp: &Secp256k1<C>,
    message: &[u8],
    signature_b64: &str,
    key: &PublicKey,
) -> bool {
    match STANDARD.decode(signature_b64) {
        Ok(der) => verify_der(secp, message, &der, key),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    #[test]
    fn compact_size_boundaries() {
        assert_eq!(compact_size(0), [0x00]);
        assert_eq!(compact_size(0xfc), [0xfc]);
        assert_eq!(compact_size(0xfd), [0xfd, 0xfd, 0x00]);
        assert_eq!(compact_size(0xffff), [0xfd, 0xff, 0xff]);
        assert_eq!(compact_size(0x1_0000), [0xfe, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(compact_size(0x1_0000_0000).len(), 9);
    }

    #[test]
    fn sign_then_verify() {
        let secp = Secp256k1::new();
        let sk = key(1);
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let sig = sign(&secp, b"hello nostr-network", &sk);
        assert!(verify(&secp, b"hello nostr-network", &sig, &pk));
        assert!(!verify(&secp, b"hello onion-network", &sig, &pk));
        assert!(!verify(
            &secp,
            b"hello nostr-network",
            &sig,
            &PublicKey::from_secret_key(&secp, &key(2))
        ));
        assert!(!verify(&secp, b"hello nostr-network", "not base64!", &pk));
        assert!(!verify(&secp, b"hello nostr-network", "", &pk));
    }

    /// From `tools/ref-vectors/ref.py` (independent pure-Python RFC 6979 + low-S + strict DER).
    const SIGN_VECTORS: &[(u8, &str, &str)] = &[
        (
            1,
            "hello nostr-network",
            "MEQCIFMZSzJTEaZJSPmedhet84b/Xw2NE2iv233FQG+cE+dWAiAlE5MoMpJTn9JZ3cR/Ej3I2pnN93Mnh71vJ5HGkePAKg==",
        ),
        (
            7,
            "0 1000000 abcd Pdeadbeefnostr-network",
            "MEQCICPIKjmgRwW7SmlCdR+aD51Ojxy6v+woBTsypxJXFFbbAiAHjgQGe/27dllQ3nsISLBA83qNjsruMO7dv39H1rC0yw==",
        ),
        (
            3,
            "",
            "MEUCIQDL5Bony9jhCksLSQd8S6R1pYIXEuRYSL3GqlyQq9G69wIgJCnNAGuS8xE1PSQw42fIyCElPRSGoB5zPL27DcdUzps=",
        ),
    ];

    #[test]
    fn signatures_match_independent_reference() {
        let secp = Secp256k1::new();
        for (kb, message, expected) in SIGN_VECTORS {
            let sk = key(*kb);
            assert_eq!(sign(&secp, message.as_bytes(), &sk), *expected, "key {kb}");
            assert!(verify(
                &secp,
                message.as_bytes(),
                expected,
                &PublicKey::from_secret_key(&secp, &sk)
            ));
        }
    }

    #[test]
    fn signing_is_deterministic() {
        let secp = Secp256k1::new();
        assert_eq!(sign(&secp, b"m", &key(7)), sign(&secp, b"m", &key(7)));
    }

    #[test]
    fn high_s_is_rejected() {
        let secp = Secp256k1::new();
        let sk = key(3);
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let digest = Message::from_digest(signed_message_hash(b"m"));
        let low = secp.sign_ecdsa(&digest, &sk);
        // Flip s to n - s: the same signature in its high-S form.
        let mut compact = low.serialize_compact();
        let s = bitcoin::secp256k1::SecretKey::from_slice(&compact[32..])
            .unwrap()
            .negate();
        compact[32..].copy_from_slice(&s.secret_bytes());
        let high = Signature::from_compact(&compact).unwrap();
        assert!(verify_der(&secp, b"m", &low.serialize_der(), &pk));
        assert!(!verify_der(&secp, b"m", &high.serialize_der(), &pk));
    }
}
