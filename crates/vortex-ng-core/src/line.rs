//! Signed private-message lines (JMP-0001 "Private Messages", "Nick Signature Verification").
//!
//! A line is `<from_nick>!<to_nick>!<command> <body> <hex_pubkey> <base64_signature>`, where the
//! signature is the Bitcoin Signed Message ECDSA of `<body> + <hostid>` by the sender's nick key and
//! `<body>` is everything between the command and the key (it may itself contain `!`-joined commands,
//! as in an offer followed by `!tbond`). On the Nostr channel `hostid` is
//! [`crate::protocol::NOSTR_HOSTID`] and the nick must equal the key's nick exactly.

use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, Signing, Verification};

use crate::nick::{nick_from_pubkey, nick_matches_pubkey};
use crate::sigmsg;

/// A verified private message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivMsg {
    /// The sender's nick.
    pub from: String,
    /// The recipient's nick.
    pub to: String,
    /// The first command, without `!` (for example `fill`).
    pub command: String,
    /// The signed body: the command's arguments and any further `!`-joined commands.
    pub body: String,
    /// The sender's nick key.
    pub key: PublicKey,
}

/// Why a line was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LineError {
    /// Not `<from>!<to>!<command> <body> <key> <sig>`.
    Malformed(&'static str),
    /// The nick does not belong to the key.
    NickMismatch,
    /// The signature does not verify.
    BadSignature,
}

impl std::fmt::Display for LineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LineError::Malformed(why) => write!(f, "malformed private message: {why}"),
            LineError::NickMismatch => f.write_str("nick does not belong to the signing key"),
            LineError::BadSignature => f.write_str("bad nick signature"),
        }
    }
}

impl std::error::Error for LineError {}

/// Build and sign a private-message line from the holder of `key` to `to_nick`.
///
/// `command` is without `!`; `body` must be non-empty and contain no space-separated token that would
/// be mistaken for the trailing key and signature (it never does: those are always appended last).
pub fn sign_line<C: Signing>(
    secp: &Secp256k1<C>,
    key: &SecretKey,
    to_nick: &str,
    command: &str,
    body: &str,
    hostid: &str,
) -> Result<String, LineError> {
    if body.is_empty() {
        return Err(LineError::Malformed("empty body"));
    }
    if command.is_empty()
        || command.contains([' ', '!'])
        || to_nick.contains(['!', ' '])
        || to_nick.is_empty()
    {
        return Err(LineError::Malformed("command or nick"));
    }
    let public = PublicKey::from_secret_key(secp, key);
    let signed = format!("{body}{hostid}");
    let signature = sigmsg::sign(secp, signed.as_bytes(), key);
    Ok(format!(
        "{}!{to_nick}!{command} {body} {} {signature}",
        nick_from_pubkey(&public),
        public.serialize().to_lower_hex_string()
    ))
}

/// Parse and verify a private-message line received on the channel with `hostid`, addressed to
/// `own_nick`.
pub fn verify_line<C: Verification>(
    secp: &Secp256k1<C>,
    line: &str,
    hostid: &str,
    own_nick: &str,
) -> Result<PrivMsg, LineError> {
    let mut parts = line.splitn(3, '!');
    let (Some(from), Some(to), Some(rest)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(LineError::Malformed("missing nicks"));
    };
    if from.is_empty() || to.is_empty() || from.contains(' ') || to.contains(' ') {
        return Err(LineError::Malformed("nick"));
    }
    if to != own_nick {
        return Err(LineError::Malformed("not addressed to us"));
    }
    let tokens: Vec<&str> = rest.split(' ').collect();
    // command, at least one body token, key, signature.
    if tokens.len() < 4 || tokens.iter().any(|t| t.is_empty()) {
        return Err(LineError::Malformed("fields"));
    }
    let command = tokens[0];
    let (key_hex, signature) = (tokens[tokens.len() - 2], tokens[tokens.len() - 1]);
    let body = tokens[1..tokens.len() - 2].join(" ");
    let key_bytes = Vec::<u8>::from_hex(key_hex).map_err(|_| LineError::Malformed("key"))?;
    if key_bytes.len() != 33 {
        return Err(LineError::Malformed("key must be compressed"));
    }
    let key = PublicKey::from_slice(&key_bytes).map_err(|_| LineError::Malformed("key"))?;
    if !nick_matches_pubkey(from, &key) {
        return Err(LineError::NickMismatch);
    }
    if !sigmsg::verify(secp, format!("{body}{hostid}").as_bytes(), signature, &key) {
        return Err(LineError::BadSignature);
    }
    Ok(PrivMsg {
        from: from.to_string(),
        to: to.to_string(),
        command: command.to_string(),
        body,
        key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::NOSTR_HOSTID;

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    #[test]
    fn round_trip() {
        let secp = Secp256k1::new();
        let taker = key(1);
        let maker_nick = nick_from_pubkey(&PublicKey::from_secret_key(&secp, &key(2)));
        let line = sign_line(
            &secp,
            &taker,
            &maker_nick,
            "fill",
            "0 1000000 abcd Pdeadbeef",
            NOSTR_HOSTID,
        )
        .unwrap();
        let msg = verify_line(&secp, &line, NOSTR_HOSTID, &maker_nick).unwrap();
        assert_eq!(msg.command, "fill");
        assert_eq!(msg.body, "0 1000000 abcd Pdeadbeef");
        assert_eq!(
            msg.from,
            nick_from_pubkey(&PublicKey::from_secret_key(&secp, &taker))
        );
    }

    #[test]
    fn multi_command_body() {
        let secp = Secp256k1::new();
        let to = nick_from_pubkey(&PublicKey::from_secret_key(&secp, &key(2)));
        let body = "0 50000 10000000 0 0.00025!tbond AAAA";
        let line = sign_line(&secp, &key(1), &to, "sw0reloffer", body, NOSTR_HOSTID).unwrap();
        let msg = verify_line(&secp, &line, NOSTR_HOSTID, &to).unwrap();
        assert_eq!(
            (msg.command.as_str(), msg.body.as_str()),
            ("sw0reloffer", body)
        );
    }

    #[test]
    fn rejections() {
        let secp = Secp256k1::new();
        let to = nick_from_pubkey(&PublicKey::from_secret_key(&secp, &key(2)));
        let line = sign_line(&secp, &key(1), &to, "fill", "0 1", NOSTR_HOSTID).unwrap();
        // Another channel's hostid: cross-channel replay fails.
        assert_eq!(
            verify_line(&secp, &line, "onion-network", &to),
            Err(LineError::BadSignature)
        );
        // Not for us.
        assert!(verify_line(&secp, &line, NOSTR_HOSTID, "J5someoneelseOOO").is_err());
        // Tampered body.
        let tampered = line.replacen("0 1", "0 2", 1);
        assert_eq!(
            verify_line(&secp, &tampered, NOSTR_HOSTID, &to),
            Err(LineError::BadSignature)
        );
        // Spoofed sender nick.
        let spoofed = format!("J5spoofedspoofOO{}", &line[line.find('!').unwrap()..]);
        assert_eq!(
            verify_line(&secp, &spoofed, NOSTR_HOSTID, &to),
            Err(LineError::NickMismatch)
        );
        // Missing body, double spaces, garbage.
        for bad in [
            "",
            "a!b",
            "a!b!fill",
            &format!("x!{to}!fill  k s"),
            &format!("x!{to}!fill k s"),
        ] {
            assert!(verify_line(&secp, bad, NOSTR_HOSTID, &to).is_err(), "{bad}");
        }
        assert!(sign_line(&secp, &key(1), &to, "fill", "", NOSTR_HOSTID).is_err());
        assert!(sign_line(&secp, &key(1), &to, "fi ll", "x", NOSTR_HOSTID).is_err());
    }
}
