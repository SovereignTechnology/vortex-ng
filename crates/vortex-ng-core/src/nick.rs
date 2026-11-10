//! JoinMarket nicks (JMP-0001 "Nick Format").
//!
//! `J` + version + `base58(SHA256(hex(pubkey))[:10])`, right-padded with `O` to 14 characters.
//! The hash input is the ASCII lowercase hex of the 33-byte compressed key, not the key bytes.

use bitcoin::hashes::{Hash, sha256};
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::PublicKey;

use crate::protocol::{JM_VERSION, NICK_HASH_LENGTH, NICK_HEADER, NICK_MAX_ENCODED, NICK_PADDING};

/// The unpadded base58 hash portion of the nick for `pubkey`.
fn hash_part(pubkey: &PublicKey) -> String {
    let hex = pubkey.serialize().to_lower_hex_string();
    let digest = sha256::Hash::hash(hex.as_bytes()).to_byte_array();
    bitcoin::base58::encode(&digest[..NICK_HASH_LENGTH])
}

/// The nick a peer with the ephemeral key `pubkey` uses.
pub fn nick_from_pubkey(pubkey: &PublicKey) -> String {
    let mut encoded = hash_part(pubkey);
    while encoded.chars().count() < NICK_MAX_ENCODED {
        encoded.push(NICK_PADDING);
    }
    format!("{NICK_HEADER}{JM_VERSION}{encoded}")
}

/// Whether `nick` is exactly the nick of `pubkey`: the strict check, and the one the Nostr channel
/// requires ("the nick derived from `hex_pubkey` equals the line's `from_nick`").
pub fn nick_matches_pubkey(nick: &str, pubkey: &PublicKey) -> bool {
    nick == nick_from_pubkey(pubkey)
}

/// The lenient check of JMP-0001 "Nick Signature Verification" step 2, as the deployed onion-channel
/// implementations apply it: only the 14-character hash portion is compared, with every `O` removed.
/// It ignores the header and version characters and anything after the hash portion, so several
/// strings pass for one key. Use [`nick_matches_pubkey`] unless matching that legacy behaviour.
pub fn nick_hash_matches_pubkey_jmp0001(nick: &str, pubkey: &PublicKey) -> bool {
    let Some(portion) = nick.get(2..) else {
        return false;
    };
    let portion: String = portion.chars().take(NICK_MAX_ENCODED).collect();
    let unpadded: String = portion.chars().filter(|c| *c != NICK_PADDING).collect();
    unpadded == hash_part(pubkey)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    // Expected nicks computed by an independent implementation of the JMP-0001 recipe
    // (Python hashlib + a standalone base58 encoder), not by JoinMarket code.
    const VECTORS: &[(&str, &str)] = &[
        (
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "J5Ckon1LuuapPSBM",
        ),
        (
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "J5BGti5vv34qZj9h",
        ),
    ];

    #[test]
    fn nick_vectors() {
        for (pubkey, nick) in VECTORS {
            let pubkey = PublicKey::from_str(pubkey).unwrap();
            assert_eq!(nick_from_pubkey(&pubkey), *nick);
            assert_eq!(nick_from_pubkey(&pubkey).len(), 16);
            assert!(nick_matches_pubkey(nick, &pubkey));
            assert!(nick_hash_matches_pubkey_jmp0001(nick, &pubkey));
        }
    }

    #[test]
    fn nick_of_another_key_does_not_match() {
        let a = PublicKey::from_str(VECTORS[0].0).unwrap();
        for check in [nick_matches_pubkey, nick_hash_matches_pubkey_jmp0001] {
            assert!(!check(VECTORS[1].1, &a));
            assert!(!check("J5", &a));
            assert!(!check("", &a));
            assert!(!check("J5é", &a));
        }
    }

    #[test]
    fn strict_check_rejects_aliases_the_lenient_one_accepts() {
        let (pubkey, nick) = VECTORS[0];
        let pubkey = PublicKey::from_str(pubkey).unwrap();
        let hash = &nick[2..];
        for alias in [
            format!("J4{hash}"),
            format!("X5{hash}"),
            format!("{nick}trailing"),
            format!("J5O{hash}"),
        ] {
            assert!(!nick_matches_pubkey(&alias, &pubkey), "{alias}");
        }
        // The JMP-0001 check ignores the header, version and what follows the hash portion.
        assert!(nick_hash_matches_pubkey_jmp0001(
            &format!("J4{hash}"),
            &pubkey
        ));
        assert!(nick_hash_matches_pubkey_jmp0001(
            &format!("{nick}trailing"),
            &pubkey
        ));
    }
}
