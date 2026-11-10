//! NaCl sessions for encrypted commands (JMP-0001 "Encryption").
//!
//! `!fill` and `!pubkey` exchange 32-byte Curve25519 public keys as lowercase hex; afterwards `!auth`,
//! `!ioauth`, `!tx` and `!sig` carry `base64(nonce || ciphertext)` of ASCII plaintext, with NaCl's
//! `crypto_box` (Curve25519-XSalsa20-Poly1305, 24-byte random nonce), as libsodium/libnacl implement it.

use bitcoin::base64::Engine;
use bitcoin::base64::engine::general_purpose::STANDARD;
use bitcoin::hex::{DisplayHex, FromHex};
use crypto_box::aead::{Aead, AeadCore, OsRng};
use crypto_box::{Nonce, PublicKey, SalsaBox, SecretKey};

const NONCE_LEN: usize = 24;

/// Why a NaCl operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NaclError {
    /// The counterparty's key is not 64 hex characters.
    BadPublicKey,
    /// Not base64, too short, or the authenticator does not verify.
    Decrypt,
    /// The plaintext is not ASCII.
    NotAscii,
}

impl std::fmt::Display for NaclError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            NaclError::BadPublicKey => "bad NaCl public key",
            NaclError::Decrypt => "NaCl decryption failed",
            NaclError::NotAscii => "NaCl plaintext is not ASCII",
        })
    }
}

impl std::error::Error for NaclError {}

/// An ephemeral NaCl key pair, one per CoinJoin session.
pub struct NaclKeypair {
    secret: SecretKey,
}

impl NaclKeypair {
    /// A fresh random key pair.
    pub fn generate() -> NaclKeypair {
        NaclKeypair {
            secret: SecretKey::generate(&mut OsRng),
        }
    }

    /// From fixed secret bytes (tests and vectors only).
    pub fn from_secret_bytes(bytes: [u8; 32]) -> NaclKeypair {
        NaclKeypair {
            secret: SecretKey::from(bytes),
        }
    }

    /// The public key as sent in `!fill` / `!pubkey`.
    pub fn public_hex(&self) -> String {
        self.secret.public_key().as_bytes().to_lower_hex_string()
    }

    /// Open a session with the counterparty's hex public key.
    pub fn session(&self, their_public_hex: &str) -> Result<Session, NaclError> {
        let bytes = Vec::<u8>::from_hex(their_public_hex).map_err(|_| NaclError::BadPublicKey)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| NaclError::BadPublicKey)?;
        Ok(Session {
            inner: SalsaBox::new(&PublicKey::from(bytes), &self.secret),
        })
    }
}

/// An established encrypted session with one counterparty.
pub struct Session {
    inner: SalsaBox,
}

impl Session {
    /// Encrypt an ASCII plaintext; returns `base64(nonce || ciphertext)`.
    pub fn encrypt(&self, plaintext: &str) -> Result<String, NaclError> {
        if !plaintext.is_ascii() {
            return Err(NaclError::NotAscii);
        }
        let nonce = SalsaBox::generate_nonce(&mut OsRng);
        let ciphertext = self
            .inner
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| NaclError::Decrypt)?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ciphertext);
        Ok(STANDARD.encode(out))
    }

    /// Decrypt `base64(nonce || ciphertext)` to its ASCII plaintext.
    pub fn decrypt(&self, data: &str) -> Result<String, NaclError> {
        let raw = STANDARD.decode(data).map_err(|_| NaclError::Decrypt)?;
        if raw.len() <= NONCE_LEN {
            return Err(NaclError::Decrypt);
        }
        let (nonce, ciphertext) = raw.split_at(NONCE_LEN);
        let plain = self
            .inner
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| NaclError::Decrypt)?;
        let text = String::from_utf8(plain).map_err(|_| NaclError::NotAscii)?;
        if !text.is_ascii() {
            return Err(NaclError::NotAscii);
        }
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_directions() {
        let (taker, maker) = (NaclKeypair::generate(), NaclKeypair::generate());
        let t = taker.session(&maker.public_hex()).unwrap();
        let m = maker.session(&taker.public_hex()).unwrap();
        let wire = t.encrypt("utxo|P|P2|s|e").unwrap();
        assert_eq!(m.decrypt(&wire).unwrap(), "utxo|P|P2|s|e");
        assert_eq!(t.decrypt(&m.encrypt("ioauth").unwrap()).unwrap(), "ioauth");
        // Fresh nonce per message.
        assert_ne!(t.encrypt("x").unwrap(), t.encrypt("x").unwrap());
    }

    #[test]
    fn third_party_and_tampering_fail() {
        let (taker, maker, eve) = (
            NaclKeypair::generate(),
            NaclKeypair::generate(),
            NaclKeypair::generate(),
        );
        let wire = taker
            .session(&maker.public_hex())
            .unwrap()
            .encrypt("secret")
            .unwrap();
        assert_eq!(
            eve.session(&taker.public_hex()).unwrap().decrypt(&wire),
            Err(NaclError::Decrypt)
        );
        let m = maker.session(&taker.public_hex()).unwrap();
        let mut raw = STANDARD.decode(&wire).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert_eq!(m.decrypt(&STANDARD.encode(&raw)), Err(NaclError::Decrypt));
        assert_eq!(m.decrypt("AAAA"), Err(NaclError::Decrypt));
        assert_eq!(m.decrypt("not base64"), Err(NaclError::Decrypt));
    }

    #[test]
    fn keys_and_ascii() {
        let a = NaclKeypair::from_secret_bytes([7; 32]);
        assert_eq!(a.public_hex().len(), 64);
        assert_eq!(
            a.public_hex(),
            NaclKeypair::from_secret_bytes([7; 32]).public_hex()
        );
        assert!(a.session("abcd").is_err());
        assert!(a.session(&"zz".repeat(32)).is_err());
        let s = a.session(&NaclKeypair::generate().public_hex()).unwrap();
        assert_eq!(s.encrypt("é"), Err(NaclError::NotAscii));
    }
}
