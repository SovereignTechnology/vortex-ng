//! Pool announcements (kind 2022) and the credentials a creator hands a joiner (RULES.md R1, R3).
//!
//! Both arrive from strangers. An announcement that cannot be read is an error for that one event and
//! never for the listing; credentials are accepted only when they carry the announced pool's private key
//! and repeat its terms, because NIP-04 does not say who sent them.

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use serde_json::{Map, Value, json};

use crate::pyjson::{self, is_int, is_number, py_eq, truthy};
use crate::rules::denom_sats;

/// The Nostr event kind of a pool announcement.
pub const POOL_KIND: u16 = 2022;

/// How a pool's peers reach the relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// Over Tor, a new circuit for each request.
    Tor,
    /// Through one VPN gateway shared by the pool, so all peers show the same address.
    Vpn,
}

impl Transport {
    /// The wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Tor => "tor",
            Transport::Vpn => "vpn",
        }
    }
}

/// Why an announcement is not a pool we can list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PoolError {
    /// The content is not a JSON object.
    NotAnObject,
    /// The object's `type` is not `new_pool`.
    NotNewPool,
    /// The event is not signed by the pool key it names (R1.1).
    Author,
    /// A field is missing or has the wrong type or range (R1.2 to R1.8).
    Field(&'static str),
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolError::NotAnObject => f.write_str("announcement is not a JSON object"),
            PoolError::NotNewPool => f.write_str("announcement is not a new_pool"),
            PoolError::Author => f.write_str("announcement is not signed by its pool key"),
            PoolError::Field(name) => {
                write!(f, "announcement field `{name}` is missing or invalid")
            }
        }
    }
}

impl std::error::Error for PoolError {}

/// A pool as announced.
#[derive(Clone, Debug, PartialEq)]
pub struct Pool {
    /// The pool's id.
    pub id: String,
    /// The pool's Nostr public key (x-only, hex), which signs the announcement.
    pub public_key: String,
    /// The denomination in BTC, as announced. Use [`Pool::denom_sats`] for amounts.
    pub denomination: f64,
    /// How many peers the pool takes (at least 2).
    pub peers: u32,
    /// Unix time after which the pool cannot be joined.
    pub timeout: i64,
    /// The relay the pool runs on (`ws://` or `wss://`).
    pub relay: String,
    /// The fee rate in sat/vB (greater than 0, may be fractional).
    pub fee_rate: f64,
    /// How peers reach the relay.
    pub transport: Transport,
    /// The VPN gateway, empty for Tor pools.
    pub vpn_gateway: String,
    /// The aut-ct requirement, when the pool has one.
    pub autct: Option<Autct>,
    /// The announcement as decoded, for comparing credentials against it value by value.
    raw: Map<String, Value>,
}

/// A pool's aut-ct requirement (NIP "Sybil Resistance with aut-ct").
#[derive(Clone, Debug, PartialEq)]
pub struct Autct {
    /// The keyset file name, `autct-<height>-<min sats>-<age>-<depth>-<width>.aks`.
    pub keyset: String,
    /// The requirement as announced.
    pub terms: Map<String, Value>,
}

impl Autct {
    /// Whether a UTXO may be the proving UTXO this pool asks for: at least `min_amount` sats, at least
    /// `min_confirmations` confirmations (1 when the pool names none), and of `script_type` when the pool
    /// names one (`p2wpkh`, `p2tr`, `p2pkh`). The proving UTXO is never the coin that enters the coinjoin.
    pub fn accepts(
        &self,
        value_sats: u64,
        confirmations: u32,
        script_pubkey: &bitcoin::Script,
    ) -> bool {
        let number = |name: &str, default: u64| {
            self.terms
                .get(name)
                .map_or(Some(default), |v| if is_int(v) { v.as_u64() } else { None })
        };
        let (Some(min_amount), Some(min_confirmations)) =
            (number("min_amount", 0), number("min_confirmations", 1))
        else {
            return false;
        };
        let type_ok = match self
            .terms
            .get("script_type")
            .and_then(Value::as_str)
            .unwrap_or("")
        {
            "" => true,
            "p2wpkh" => script_pubkey.is_p2wpkh(),
            "p2tr" => script_pubkey.is_p2tr(),
            "p2pkh" => script_pubkey.is_p2pkh(),
            _ => false,
        };
        value_sats >= min_amount && u64::from(confirmations) >= min_confirmations && type_ok
    }
}

/// Whether `name` is a canonical keyset file name. It reaches file paths and a daemon's arguments, and it
/// comes from a stranger's event, so nothing else is accepted.
pub fn is_keyset_name(name: &str) -> bool {
    let Some(body) = name
        .strip_prefix("autct-")
        .and_then(|n| n.strip_suffix(".aks"))
    else {
        return false;
    };
    let parts: Vec<&str> = body.split('-').collect();
    parts.len() == 5
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn finite(v: &Value) -> Option<f64> {
    if is_number(v) {
        v.as_f64().filter(|f| f.is_finite())
    } else {
        None
    }
}

fn autct_of(raw: &Map<String, Value>) -> Result<Option<Autct>, PoolError> {
    match raw.get("autct") {
        Some(v) if truthy(v) => {
            let terms = v.as_object().ok_or(PoolError::Field("autct"))?;
            let keyset = terms
                .get("keyset")
                .and_then(Value::as_str)
                .ok_or(PoolError::Field("autct"))?;
            if !is_keyset_name(keyset) {
                return Err(PoolError::Field("autct"));
            }
            Ok(Some(Autct {
                keyset: keyset.to_string(),
                terms: terms.clone(),
            }))
        }
        _ => Ok(None),
    }
}

impl Pool {
    /// Read a kind 2022 event's `content`, signed by `author` (the event's pubkey, hex).
    pub fn from_announcement(author: &str, content: &str) -> Result<Pool, PoolError> {
        let Ok(Value::Object(raw)) = serde_json::from_str::<Value>(content) else {
            return Err(PoolError::NotAnObject);
        };
        if raw.get("type").and_then(Value::as_str) != Some("new_pool") {
            return Err(PoolError::NotNewPool);
        }
        let string = |name: &'static str| {
            raw.get(name)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or(PoolError::Field(name))
        };
        let public_key = string("public_key")?;
        if public_key != author {
            return Err(PoolError::Author);
        }
        let id = string("id")?;
        let timeout = raw
            .get("timeout")
            .filter(|v| is_int(v))
            .and_then(Value::as_i64)
            .ok_or(PoolError::Field("timeout"))?;
        let peers = raw
            .get("peers")
            .filter(|v| is_int(v))
            .and_then(Value::as_u64)
            .and_then(|p| u32::try_from(p).ok())
            .filter(|p| *p >= 2)
            .ok_or(PoolError::Field("peers"))?;
        let denomination = raw
            .get("denomination")
            .and_then(finite)
            .filter(|d| *d > 0.0)
            .ok_or(PoolError::Field("denomination"))?;
        let relay = string("relay")?;
        if !(relay.starts_with("ws://") || relay.starts_with("wss://")) {
            return Err(PoolError::Field("relay"));
        }
        let fee_rate = raw
            .get("fee_rate")
            .and_then(finite)
            .filter(|f| *f > 0.0)
            .ok_or(PoolError::Field("fee_rate"))?;
        let transport = match raw.get("transport") {
            None => Transport::Tor,
            Some(Value::String(t)) if t == "tor" => Transport::Tor,
            Some(Value::String(t)) if t == "vpn" => Transport::Vpn,
            Some(_) => return Err(PoolError::Field("transport")),
        };
        let vpn_gateway = match raw.get("vpn_gateway") {
            None => String::new(),
            Some(Value::String(g)) => g.clone(),
            Some(_) => return Err(PoolError::Field("vpn_gateway")),
        };
        let autct = autct_of(&raw)?;
        Ok(Pool {
            id,
            public_key,
            denomination,
            peers,
            timeout,
            relay,
            fee_rate,
            transport,
            vpn_gateway,
            autct,
            raw,
        })
    }

    /// A pool we create: its key signs the announcement and is later handed to every peer.
    pub fn create(
        pool_key: &SecretKey,
        id: &str,
        denomination_btc: f64,
        peers: u32,
        timeout: i64,
        relay: &str,
        fee_rate: f64,
    ) -> Result<Pool, PoolError> {
        let content = pyjson::object(&[
            ("type", json!("new_pool")),
            ("id", json!(id)),
            ("public_key", json!(public_key_hex(pool_key))),
            ("denomination", json!(denomination_btc)),
            ("peers", json!(peers)),
            ("timeout", json!(timeout)),
            ("relay", json!(relay)),
            ("fee_rate", json!(fee_rate)),
            ("transport", json!("tor")),
            ("vpn_gateway", json!("")),
        ]);
        Pool::from_announcement(&public_key_hex(pool_key), &content)
    }

    /// This pool with an aut-ct requirement: joiners must prove they own a UTXO in `keyset` worth at least
    /// `min_amount` sats with `min_confirmations` confirmations, of `script_type` (`""` for any).
    pub fn require_autct(
        &self,
        keyset: &str,
        min_amount: u64,
        min_confirmations: u32,
        script_type: &str,
    ) -> Result<Pool, PoolError> {
        let mut content = self.raw.clone();
        content.insert(
            "autct".into(),
            json!({
                "keyset": keyset, "min_amount": min_amount,
                "min_confirmations": min_confirmations, "script_type": script_type,
            }),
        );
        Pool::from_announcement(&self.public_key, &Value::Object(content).to_string())
    }

    /// The denomination in satoshis (R5.1).
    pub fn denom_sats(&self) -> i64 {
        denom_sats(self.denomination)
    }

    /// Whether the pool can still be joined at `now` (R1.6).
    pub fn open_at(&self, now: i64) -> bool {
        self.timeout > now
    }

    /// The event content announcing this pool, keys in the order the reference clients write them.
    pub fn announcement(&self) -> String {
        let mut pairs = self.terms(None);
        pairs.insert(0, ("type", json!("new_pool")));
        pyjson::object(&pairs)
    }

    /// The credentials the creator sends an admitted joiner: the announced terms plus the pool's private
    /// key, one flat object (R3.1).
    pub fn credentials(&self, pool_key: &SecretKey) -> String {
        pyjson::object(&self.terms(Some(pool_key)))
    }

    fn terms(&self, key: Option<&SecretKey>) -> Vec<(&'static str, Value)> {
        let announced =
            |name: &str, fallback: Value| self.raw.get(name).cloned().unwrap_or(fallback);
        let mut pairs = vec![
            ("id", json!(self.id)),
            ("public_key", json!(self.public_key)),
            (
                "denomination",
                announced("denomination", json!(self.denomination)),
            ),
            ("peers", json!(self.peers)),
            ("timeout", json!(self.timeout)),
            ("relay", json!(self.relay)),
        ];
        if let Some(key) = key {
            pairs.push(("private_key", json!(hex(&key.secret_bytes()))));
        }
        pairs.push(("fee_rate", announced("fee_rate", json!(self.fee_rate))));
        pairs.push(("transport", json!(self.transport.as_str())));
        pairs.push(("vpn_gateway", json!(self.vpn_gateway)));
        if let Some(autct) = &self.autct {
            pairs.push(("autct", Value::Object(autct.terms.clone())));
        }
        pairs
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The Nostr public key (x-only, hex) of a private key.
pub fn public_key_hex(key: &SecretKey) -> String {
    hex(&key.x_only_public_key(&Secp256k1::new()).0.serialize())
}

/// A private key from hex as Python's `bytes.fromhex` reads it (either case, ASCII whitespace skipped),
/// or `None` if it is not one.
fn secret_from_hex(text: &str) -> Option<SecretKey> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if digits.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (i, pair) in digits.chunks(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        bytes[i] = (hi * 16 + lo) as u8;
    }
    SecretKey::from_slice(&bytes).ok()
}

/// Why credentials are refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialsError {
    /// The message is not a JSON object.
    NotAnObject,
    /// The creator refused the join request (`reject`), with its reason.
    Rejected(String),
    /// `private_key` is missing or does not derive the announced pool key: someone other than the creator
    /// answered.
    NotThePool,
    /// A term differs from the announcement (R3.2, R3.5), or the aut-ct requirement was dropped or changed.
    Mismatch(&'static str),
    /// `fee_rate` is not a number greater than 0 (R3.3).
    FeeRate,
}

impl std::fmt::Display for CredentialsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialsError::NotAnObject => f.write_str("credentials are not a JSON object"),
            CredentialsError::Rejected(why) => {
                write!(f, "the pool refused the join request: {why}")
            }
            CredentialsError::NotThePool => {
                f.write_str("credentials do not carry the pool's private key")
            }
            CredentialsError::Mismatch(name) => {
                write!(f, "credentials change the announced `{name}`")
            }
            CredentialsError::FeeRate => f.write_str("credentials carry no usable fee rate"),
        }
    }
}

impl std::error::Error for CredentialsError {}

/// The terms a joiner checks against the announcement (the plugin's list, RULES.md R3.2 and R3.5).
const CREDENTIAL_TERMS: [&str; 7] = [
    "id",
    "public_key",
    "denomination",
    "peers",
    "timeout",
    "relay",
    "fee_rate",
];

/// Check a decrypted answer to our join request against the `pool` we chose (R3) and return the pool's
/// private key. Anyone reading the relay can answer a join request; only the creator holds this key.
pub fn accept_credentials(plaintext: &str, pool: &Pool) -> Result<SecretKey, CredentialsError> {
    let Ok(Value::Object(creds)) = serde_json::from_str::<Value>(plaintext) else {
        return Err(CredentialsError::NotAnObject);
    };
    if creds.get("type").and_then(Value::as_str) == Some("reject") {
        let reason = creds
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("Unknown");
        return Err(CredentialsError::Rejected(reason.to_string()));
    }
    let key = creds
        .get("private_key")
        .and_then(Value::as_str)
        .and_then(secret_from_hex)
        .filter(|key| public_key_hex(key) == pool.public_key)
        .ok_or(CredentialsError::NotThePool)?;
    if let Some(autct) = &pool.autct {
        let keyset = creds
            .get("autct")
            .and_then(|a| a.get("keyset"))
            .and_then(Value::as_str);
        if keyset != Some(autct.keyset.as_str()) {
            return Err(CredentialsError::Mismatch("autct"));
        }
    }
    for name in CREDENTIAL_TERMS {
        if let Some(announced) = pool.raw.get(name)
            && !creds.get(name).is_some_and(|given| py_eq(given, announced))
        {
            return Err(CredentialsError::Mismatch(name));
        }
    }
    match creds.get("fee_rate").and_then(finite) {
        Some(rate) if rate > 0.0 => Ok(key),
        _ => Err(CredentialsError::FeeRate),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn announcement(edit: impl FnOnce(&mut Map<String, Value>)) -> (String, String) {
        let pool_key = public_key_hex(&key(9));
        let mut content = json!({
            "type": "new_pool", "id": "abc123", "public_key": pool_key, "denomination": 0.001,
            "peers": 3, "timeout": 2_000_000_000, "relay": "wss://relay.example", "fee_rate": 2.5,
            "transport": "tor", "vpn_gateway": ""
        });
        edit(content.as_object_mut().unwrap());
        (pool_key, content.to_string())
    }

    #[test]
    fn a_well_formed_announcement_is_listed() {
        let (author, content) = announcement(|_| {});
        let pool = Pool::from_announcement(&author, &content).unwrap();
        assert_eq!(
            (pool.denom_sats(), pool.peers, pool.fee_rate),
            (100_000, 3, 2.5)
        );
        assert_eq!(pool.transport, Transport::Tor);
        assert!(pool.open_at(1_999_999_999) && !pool.open_at(2_000_000_000));
        // Unknown keys are ignored; an integer denomination is BTC; transport may be absent.
        let (author, content) = announcement(|c| {
            c.insert("versions".into(), json!(["1"]));
            c.insert("denomination".into(), json!(1));
            c.remove("transport");
            c.remove("vpn_gateway");
        });
        let pool = Pool::from_announcement(&author, &content).unwrap();
        assert_eq!(pool.denom_sats(), 100_000_000);
    }

    #[test]
    fn malformed_announcements_are_refused_field_by_field() {
        let refused = |edit: fn(&mut Map<String, Value>)| {
            let (author, content) = announcement(edit);
            Pool::from_announcement(&author, &content).unwrap_err()
        };
        assert_eq!(
            refused(|c| {
                c.insert("type".into(), json!("other"));
            }),
            PoolError::NotNewPool
        );
        assert_eq!(
            refused(|c| {
                c.insert("public_key".into(), json!("00".repeat(32)));
            }),
            PoolError::Author
        );
        assert_eq!(
            refused(|c| {
                c.insert("peers".into(), json!(1));
            }),
            PoolError::Field("peers")
        );
        assert_eq!(
            refused(|c| {
                c.insert("peers".into(), json!(3.0));
            }),
            PoolError::Field("peers")
        );
        assert_eq!(
            refused(|c| {
                c.insert("peers".into(), json!(true));
            }),
            PoolError::Field("peers")
        );
        assert_eq!(
            refused(|c| {
                c.insert("timeout".into(), json!("soon"));
            }),
            PoolError::Field("timeout")
        );
        assert_eq!(
            refused(|c| {
                c.insert("timeout".into(), json!(1.5e9));
            }),
            PoolError::Field("timeout")
        );
        assert_eq!(
            refused(|c| {
                c.insert("denomination".into(), json!("0.001"));
            }),
            PoolError::Field("denomination")
        );
        assert_eq!(
            refused(|c| {
                c.insert("denomination".into(), json!(0));
            }),
            PoolError::Field("denomination")
        );
        assert_eq!(
            refused(|c| {
                c.insert("relay".into(), json!("https://relay.example"));
            }),
            PoolError::Field("relay")
        );
        assert_eq!(
            refused(|c| {
                c.insert("relay".into(), json!(["wss://a"]));
            }),
            PoolError::Field("relay")
        );
        assert_eq!(
            refused(|c| {
                c.insert("fee_rate".into(), json!(0));
            }),
            PoolError::Field("fee_rate")
        );
        assert_eq!(
            refused(|c| {
                c.remove("fee_rate");
            }),
            PoolError::Field("fee_rate")
        );
        assert_eq!(
            refused(|c| {
                c.insert("transport".into(), json!("Tor"));
            }),
            PoolError::Field("transport")
        );
        assert_eq!(
            refused(|c| {
                c.insert("autct".into(), json!({"keyset": "../../etc/passwd"}));
            }),
            PoolError::Field("autct")
        );
        assert_eq!(
            Pool::from_announcement("x", "[1]"),
            Err(PoolError::NotAnObject)
        );
        assert_eq!(
            Pool::from_announcement("x", "not json"),
            Err(PoolError::NotAnObject)
        );
    }

    #[test]
    fn a_created_pool_round_trips_through_its_own_announcement() {
        let pool = Pool::create(
            &key(9),
            "abc123",
            0.001,
            3,
            2_000_000_000,
            "wss://relay.example",
            2.5,
        )
        .unwrap();
        assert_eq!(
            pool.announcement(),
            format!(
                r#"{{"type": "new_pool", "id": "abc123", "public_key": "{}", "denomination": 0.001, "peers": 3, "timeout": 2000000000, "relay": "wss://relay.example", "fee_rate": 2.5, "transport": "tor", "vpn_gateway": ""}}"#,
                pool.public_key
            )
        );
        assert_eq!(
            Pool::from_announcement(&pool.public_key, &pool.announcement()).unwrap(),
            pool
        );
        // A joiner accepts the creator's credentials and gets the pool key.
        let creds = pool.credentials(&key(9));
        assert!(creds.contains(r#""private_key": "0909"#));
        assert_eq!(accept_credentials(&creds, &pool).unwrap(), key(9));
    }

    #[test]
    fn credentials_must_come_from_the_pool_and_repeat_its_terms() {
        let (author, content) = announcement(|_| {});
        let pool = Pool::from_announcement(&author, &content).unwrap();
        let with = |edit: fn(&mut Map<String, Value>)| {
            let mut creds: Value = serde_json::from_str(&pool.credentials(&key(9))).unwrap();
            edit(creds.as_object_mut().unwrap());
            accept_credentials(&creds.to_string(), &pool)
        };
        assert!(with(|_| {}).is_ok());
        // Extra keys, 1 for 1.0 and other spellings of the same number are fine (Python's ==).
        assert!(
            with(|c| {
                c.insert("version".into(), json!("1"));
                c.insert("peers".into(), json!(3.0));
            })
            .is_ok()
        );
        // Someone else answering: another key, or none.
        let other = hex(&key(8).secret_bytes());
        assert_eq!(
            accept_credentials(&format!(r#"{{"private_key": "{other}"}}"#), &pool),
            Err(CredentialsError::NotThePool)
        );
        assert_eq!(
            with(|c| {
                c.remove("private_key");
            }),
            Err(CredentialsError::NotThePool)
        );
        assert_eq!(
            with(|c| {
                c.insert("private_key".into(), json!(5));
            }),
            Err(CredentialsError::NotThePool)
        );
        // The creator changing the deal after the joiner chose it.
        assert_eq!(
            with(|c| {
                c.insert("fee_rate".into(), json!(50));
            }),
            Err(CredentialsError::Mismatch("fee_rate"))
        );
        assert_eq!(
            with(|c| {
                c.insert("denomination".into(), json!(0.01));
            }),
            Err(CredentialsError::Mismatch("denomination"))
        );
        assert_eq!(
            with(|c| {
                c.insert("relay".into(), json!("wss://evil.example"));
            }),
            Err(CredentialsError::Mismatch("relay"))
        );
        assert_eq!(
            with(|c| {
                c.remove("peers");
            }),
            Err(CredentialsError::Mismatch("peers"))
        );
        assert_eq!(
            accept_credentials(r#"{"type": "reject", "reason": "invalid_proof"}"#, &pool),
            Err(CredentialsError::Rejected("invalid_proof".into()))
        );
        assert_eq!(
            accept_credentials("[]", &pool),
            Err(CredentialsError::NotAnObject)
        );
    }

    #[test]
    fn an_autct_pool_is_announced_with_its_requirement_and_picks_proving_coins() {
        let plain = Pool::create(
            &key(9),
            "abc123",
            0.001,
            3,
            2_000_000_000,
            "wss://relay.example",
            2.5,
        )
        .unwrap();
        let pool = plain
            .require_autct("autct-830000-100000-0-2-1024.aks", 100_000, 6, "p2wpkh")
            .unwrap();
        let listed = Pool::from_announcement(&pool.public_key, &pool.announcement()).unwrap();
        let autct = listed.autct.expect("the requirement is announced");
        assert_eq!(autct.keyset, "autct-830000-100000-0-2-1024.aks");
        assert!(plain.require_autct("../evil.aks", 0, 1, "").is_err());
        let secp = Secp256k1::new();
        let public = bitcoin::CompressedPublicKey(key(3).public_key(&secp));
        let wpkh = bitcoin::Address::p2wpkh(&public, bitcoin::Network::Regtest).script_pubkey();
        let pkh = bitcoin::Address::p2pkh(public, bitcoin::Network::Regtest).script_pubkey();
        assert!(autct.accepts(100_000, 6, &wpkh));
        assert!(!autct.accepts(99_999, 6, &wpkh), "too small");
        assert!(!autct.accepts(100_000, 5, &wpkh), "too young");
        assert!(!autct.accepts(100_000, 6, &pkh), "wrong script type");
        // No script type named: any type; no confirmations named: one.
        let any = plain
            .require_autct("autct-1-2-3-4-5.aks", 0, 1, "")
            .unwrap()
            .autct
            .unwrap();
        assert!(any.accepts(1, 1, &pkh) && !any.accepts(1, 0, &pkh));
    }

    #[test]
    fn an_autct_requirement_cannot_be_dropped_by_the_credentials() {
        let (author, content) = announcement(|c| {
            c.insert(
                "autct".into(),
                json!({"keyset": "autct-830000-100000-0-2-1024.aks", "min_amount": 100000}),
            );
        });
        let pool = Pool::from_announcement(&author, &content).unwrap();
        assert_eq!(
            pool.autct.as_ref().unwrap().keyset,
            "autct-830000-100000-0-2-1024.aks"
        );
        assert!(accept_credentials(&pool.credentials(&key(9)), &pool).is_ok());
        let mut creds: Value = serde_json::from_str(&pool.credentials(&key(9))).unwrap();
        creds.as_object_mut().unwrap().remove("autct");
        assert_eq!(
            accept_credentials(&creds.to_string(), &pool),
            Err(CredentialsError::Mismatch("autct"))
        );
        assert!(
            is_keyset_name("autct-1-2-3-4-5.aks")
                && !is_keyset_name("autct-1-2-3-4.aks")
                && !is_keyset_name("autct-1-2-3-4-x.aks")
        );
    }
}
