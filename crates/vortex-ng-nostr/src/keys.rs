//! A nick's key, usable both as the JoinMarket nick key (rust-bitcoin's secp256k1) and as the Nostr key
//! (rust-nostr's). The two libraries use different secp256k1 versions; the key crosses as bytes.

use vortex_ng_core::bitcoin::hex::DisplayHex;
use vortex_ng_core::bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use vortex_ng_core::nick::{nick_from_pubkey, random_nick_key};

use crate::ChannelError;

/// A nick and its key pair.
pub struct NickKeys {
    secret: SecretKey,
    public: PublicKey,
    nick: String,
    nostr: nostr::key::Keys,
}

impl std::fmt::Debug for NickKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NickKeys")
            .field("nick", &self.nick)
            .finish_non_exhaustive()
    }
}

impl NickKeys {
    /// A fresh nick.
    pub fn generate() -> NickKeys {
        // A key from `random_nick_key` is valid for both libraries, so this cannot fail.
        loop {
            if let Ok(keys) = NickKeys::from_secret(random_nick_key()) {
                return keys;
            }
        }
    }

    /// The nick of an existing key.
    pub fn from_secret(secret: SecretKey) -> Result<NickKeys, ChannelError> {
        let public = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
        let nostr_secret = nostr::key::SecretKey::from_slice(&secret.secret_bytes())
            .map_err(|e| ChannelError::Crypto(e.to_string()))?;
        Ok(NickKeys {
            secret,
            public,
            nick: nick_from_pubkey(&public),
            nostr: nostr::key::Keys::new(nostr_secret),
        })
    }

    /// The JoinMarket nick.
    pub fn nick(&self) -> &str {
        &self.nick
    }

    /// The nick key's secret, for signing JMP-0001 lines.
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// The compressed nick public key.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Lowercase hex of the compressed key: the `jmpk` tag.
    pub fn jmpk_hex(&self) -> String {
        self.public.serialize().to_lower_hex_string()
    }

    /// The same key as Nostr keys.
    pub fn nostr(&self) -> &nostr::key::Keys {
        &self.nostr
    }
}

/// The Nostr (x-only) form of a compressed nick key.
pub fn nostr_public(public: &PublicKey) -> Result<nostr::key::PublicKey, ChannelError> {
    nostr::key::PublicKey::from_slice(&public.x_only_public_key().0.serialize())
        .map_err(|e| ChannelError::Crypto(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_key_in_both_libraries() {
        let keys = NickKeys::from_secret(SecretKey::from_slice(&[1; 32]).unwrap()).unwrap();
        assert_eq!(keys.nick(), nick_from_pubkey(keys.public()));
        assert_eq!(keys.nick().len(), 16);
        assert_eq!(
            keys.jmpk_hex(),
            "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
        );
        assert_eq!(
            keys.nostr().public_key(),
            nostr_public(keys.public()).unwrap()
        );
        let fresh = NickKeys::generate();
        assert_eq!(
            fresh.nostr().public_key(),
            nostr_public(fresh.public()).unwrap()
        );
        assert_ne!(fresh.nick(), keys.nick());
        assert!(!format!("{fresh:?}").contains(&fresh.secret().display_secret().to_string()));
    }
}
