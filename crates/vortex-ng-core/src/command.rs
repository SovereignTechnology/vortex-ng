//! JoinMarket commands (JMP-0001 "CoinJoin Protocol", "Encryption").
//!
//! [`Command`] is one parsed command. Plaintext messages may concatenate several commands with `!`
//! ([`parse_plaintext`]); encrypted commands (`auth`, `ioauth`, `tx`, `sig`) are single and carry
//! `base64(nonce || ciphertext)` until [`crate::nacl::Session::decrypt`] yields their plaintext, which
//! [`Ioauth::parse`] and friends then read.

use bitcoin::OutPoint;
use bitcoin::hex::FromHex;
use bitcoin::secp256k1::PublicKey;

use crate::offer::{Offer, OfferType};
use crate::podle::{parse_commitment, parse_utxo};

/// Commands whose payload is NaCl-encrypted. They never move between categories.
pub const ENCRYPTED: [&str; 4] = ["auth", "ioauth", "tx", "sig"];

/// One JoinMarket command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// `!orderbook`: request offers.
    Orderbook,
    /// An offer (`!sw0reloffer …`, `!tr0absoffer …`, …).
    Offer(Offer),
    /// `!tbond <base64 proof>`, following an offer in a private answer.
    Tbond(String),
    /// `!cancel <oid>`.
    Cancel(u64),
    /// `!fill <oid> <amount> <taker NaCl pubkey hex> <P-commitment>`.
    Fill {
        /// The maker's order id.
        oid: u64,
        /// The coinjoin amount, satoshis.
        amount: u64,
        /// The taker's NaCl public key, 64 hex characters.
        nacl_pubkey: String,
        /// The PoDLE commitment.
        commitment: [u8; 32],
    },
    /// `!pubkey <maker NaCl pubkey hex> [extensions…]`; joinmarket-ng appends `key=value` extensions.
    Pubkey {
        /// The maker's NaCl public key, 64 hex characters.
        nacl_pubkey: String,
        /// Further space-separated tokens, unparsed.
        extensions: Vec<String>,
    },
    /// An encrypted command and its ciphertext.
    Encrypted {
        /// `auth`, `ioauth`, `tx` or `sig`.
        name: String,
        /// `base64(nonce || ciphertext)`.
        ciphertext: String,
    },
    /// `!push <base64 transaction>`.
    Push(String),
    /// `!error <message>`.
    Error(String),
    /// `!hp2 <commitment hex>`: a used PoDLE commitment.
    Hp2([u8; 32]),
    /// Any other command, kept so a caller can ignore it as JoinMarket does.
    Unknown {
        /// The command name.
        name: String,
        /// Its arguments.
        args: String,
    },
}

fn int(s: &str) -> Option<u64> {
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

fn hex32(s: &str) -> bool {
    s.len() == 64 && Vec::<u8>::from_hex(s).is_ok()
}

impl Command {
    /// Parse one command from its name (without `!`) and arguments. `None` for a known command with
    /// malformed arguments; unknown names become [`Command::Unknown`].
    pub fn parse(name: &str, args: &str) -> Option<Command> {
        let fields: Vec<&str> = if args.is_empty() {
            Vec::new()
        } else {
            args.split(' ').collect()
        };
        if fields.iter().any(|f| f.is_empty()) {
            return None;
        }
        Some(match (name, fields.as_slice()) {
            ("orderbook", []) => Command::Orderbook,
            ("tbond", [proof]) => Command::Tbond((*proof).to_string()),
            ("cancel", [oid]) => Command::Cancel(int(oid)?),
            ("fill", [oid, amount, pubkey, commitment]) => {
                if !hex32(pubkey) {
                    return None;
                }
                Command::Fill {
                    oid: int(oid)?,
                    amount: int(amount)?,
                    nacl_pubkey: pubkey.to_ascii_lowercase(),
                    commitment: parse_commitment(commitment).ok()?,
                }
            }
            ("pubkey", [pubkey, rest @ ..]) => {
                if !hex32(pubkey) {
                    return None;
                }
                Command::Pubkey {
                    nacl_pubkey: pubkey.to_ascii_lowercase(),
                    extensions: rest.iter().map(|s| (*s).to_string()).collect(),
                }
            }
            (n, [ciphertext]) if ENCRYPTED.contains(&n) => Command::Encrypted {
                name: n.to_string(),
                ciphertext: (*ciphertext).to_string(),
            },
            ("push", [tx]) => Command::Push((*tx).to_string()),
            ("error", _) => Command::Error(args.to_string()),
            ("hp2", [commitment]) => {
                Command::Hp2(<[u8; 32]>::try_from(Vec::<u8>::from_hex(commitment).ok()?).ok()?)
            }
            (n, _) if OfferType::from_command(n).is_some() => {
                Command::Offer(Offer::parse(n, args)?)
            }
            ("orderbook" | "tbond" | "cancel" | "fill" | "pubkey" | "push" | "hp2", _) => {
                return None;
            }
            (n, _) if ENCRYPTED.contains(&n) => return None,
            (n, _) => Command::Unknown {
                name: n.to_string(),
                args: args.to_string(),
            },
        })
    }
}

/// Split a plaintext message (`!cmd args!cmd args…`) into commands. Returns `None` if any known command
/// is malformed, if an encrypted command appears among several, or if the text does not start with `!`.
pub fn parse_plaintext(message: &str) -> Option<Vec<Command>> {
    let rest = message.strip_prefix('!')?;
    let parts: Vec<&str> = rest.split('!').collect();
    let mut out = Vec::with_capacity(parts.len());
    for part in &parts {
        let (name, args) = part.split_once(' ').unwrap_or((part, ""));
        if name.is_empty() {
            return None;
        }
        if parts.len() > 1 && ENCRYPTED.contains(&name) {
            return None;
        }
        out.push(Command::parse(name, args)?);
    }
    Some(out)
}

/// A message a maker or taker wants sent; the transport signs (JMP-0001 line) and wraps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outgoing {
    /// A private message to `to`: the first command (without `!`) and its body.
    Private {
        /// Recipient nick.
        to: String,
        /// Command name.
        command: String,
        /// Body (arguments and any further `!`-joined commands, or a ciphertext).
        body: String,
    },
    /// A public message from a throwaway nick (the `!hp2` commitment broadcast).
    PublicEphemeral(String),
}

/// The decrypted `!ioauth` plaintext: `<utxo,utxo,…> <auth_pubkey> <cj_address> <change_address>
/// <btc_signature> [hold_seconds]`. In `wsh0` the auth key is the 132-hex concatenation of two keys;
/// `hold_seconds` is JMP-0014's sixth field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ioauth {
    /// The maker's coinjoin inputs.
    pub utxos: Vec<OutPoint>,
    /// The key the maker authenticates with.
    pub auth_pubkey: PublicKey,
    /// For `wsh0`, the other key of the authenticated UTXO's 2-of-2.
    pub auth_cosigner: Option<PublicKey>,
    /// The maker's coinjoin output address.
    pub cj_address: String,
    /// The maker's change address.
    pub change_address: String,
    /// Base64 signature by `auth_pubkey` over the taker's NaCl public key hex.
    pub btc_signature: String,
    /// JMP-0014 input hold, seconds (0..=3600), when present.
    pub hold_seconds: Option<u32>,
}

impl Ioauth {
    /// Parse the decrypted plaintext.
    pub fn parse(plaintext: &str) -> Option<Ioauth> {
        let fields: Vec<&str> = plaintext.split(' ').collect();
        let (utxos, auth, cj, change, sig, hold) = match fields.as_slice() {
            [u, a, c, ch, s] => (u, a, c, ch, s, None),
            [u, a, c, ch, s, h] => (u, a, c, ch, s, Some(*h)),
            _ => return None,
        };
        let utxos = utxos
            .split(',')
            .map(|u| parse_utxo(u).ok())
            .collect::<Option<Vec<OutPoint>>>()
            .filter(|v| !v.is_empty())?;
        let key = |hex: &str| PublicKey::from_slice(&Vec::<u8>::from_hex(hex).ok()?).ok();
        let (auth_pubkey, auth_cosigner) = match auth.len() {
            66 => (key(auth)?, None),
            132 => (key(&auth[..66])?, Some(key(&auth[66..])?)),
            _ => return None,
        };
        let hold_seconds = match hold {
            None => None,
            // Decimal 0..=3600 without leading zeros (JMP-0014 "Input Hold").
            Some(h) if h == "0" || (!h.starts_with('0') && h.len() <= 4) => Some(
                int(h)
                    .and_then(|v| u32::try_from(v).ok())
                    .filter(|v| *v <= 3600)?,
            ),
            Some(_) => return None,
        };
        if [cj, change, sig].iter().any(|f| f.is_empty()) {
            return None;
        }
        Some(Ioauth {
            utxos,
            auth_pubkey,
            auth_cosigner,
            cj_address: (*cj).to_string(),
            change_address: (*change).to_string(),
            btc_signature: (*sig).to_string(),
            hold_seconds,
        })
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hex::DisplayHex;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    use super::*;

    #[test]
    fn plaintext_commands() {
        let cmds = parse_plaintext("!sw0reloffer 0 50000 10000000 0 0.00025!tbond AAAA").unwrap();
        assert!(matches!(cmds[0], Command::Offer(_)));
        assert_eq!(cmds[1], Command::Tbond("AAAA".into()));
        assert_eq!(
            parse_plaintext("!orderbook").unwrap(),
            vec![Command::Orderbook]
        );
        assert_eq!(
            parse_plaintext("!cancel 3").unwrap(),
            vec![Command::Cancel(3)]
        );
        let fill = format!("!fill 0 1000000 {} P{}", "ab".repeat(32), "cd".repeat(32));
        assert!(matches!(
            parse_plaintext(&fill).unwrap()[0],
            Command::Fill {
                oid: 0,
                amount: 1_000_000,
                ..
            }
        ));
        let pubkey = format!(
            "!pubkey {} features=private_channel_ring ring_open_diagnostics=1",
            "ef".repeat(32)
        );
        let Command::Pubkey { extensions, .. } = &parse_plaintext(&pubkey).unwrap()[0] else {
            panic!()
        };
        assert_eq!(extensions.len(), 2);
        assert_eq!(
            parse_plaintext(&format!("!hp2 {}", "11".repeat(32))).unwrap(),
            vec![Command::Hp2([0x11; 32])]
        );
        assert!(
            matches!(&parse_plaintext("!newthing x y").unwrap()[0], Command::Unknown { name, .. } if name == "newthing")
        );
        assert!(matches!(
            parse_plaintext("!auth Zm9v").unwrap()[0],
            Command::Encrypted { .. }
        ));
    }

    #[test]
    fn malformed_plaintext() {
        for bad in [
            "",
            "orderbook",
            "!",
            "!orderbook extra",
            "!cancel x",
            "!fill 0 1000000 abcd Pdeadbeef",
            "!fill 0 1000000",
            "!pubkey 1234",
            "!hp2 zz",
            "!sw0reloffer 0 1",
            "!auth a!tx b",
            "!sw0reloffer 0 50000 10000000 0 0.00025!auth x",
            "!cancel  3",
        ] {
            assert!(parse_plaintext(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn ioauth() {
        let secp = Secp256k1::new();
        let k =
            |b: u8| PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[b; 32]).unwrap());
        let a = k(1).serialize().to_lower_hex_string();
        let c = k(2).serialize().to_lower_hex_string();
        let utxos = format!("{}:0,{}:1", "aa".repeat(32), "bb".repeat(32));
        let base = format!("{utxos} {a} bc1qcj bc1qchange c2lnbmF0dXJl");
        let parsed = Ioauth::parse(&base).unwrap();
        assert_eq!(
            (
                parsed.utxos.len(),
                parsed.auth_cosigner,
                parsed.hold_seconds
            ),
            (2, None, None)
        );
        let wsh0 = Ioauth::parse(&format!("{utxos} {a}{c} bc1qcj bc1qchange c2ln")).unwrap();
        assert_eq!(wsh0.auth_cosigner, Some(k(2)));
        assert_eq!(
            Ioauth::parse(&format!("{base} 0")).unwrap().hold_seconds,
            Some(0)
        );
        assert_eq!(
            Ioauth::parse(&format!("{base} 3600")).unwrap().hold_seconds,
            Some(3600)
        );
        for bad_hold in ["3601", "060", "-1", "", "x"] {
            assert!(
                Ioauth::parse(&format!("{base} {bad_hold}")).is_none(),
                "{bad_hold}"
            );
        }
        assert!(Ioauth::parse(&format!(" {a} x y z")).is_none());
        assert!(Ioauth::parse(&format!("{utxos} {} x y z", &a[..64])).is_none());
        assert!(Ioauth::parse(&format!("{utxos} {a} x y")).is_none());
    }
}
