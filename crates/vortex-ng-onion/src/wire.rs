//! The onion message channel's wire format, without I/O.
//!
//! One JSON object `{"type": <int>, "line": <string>}` per line, lines ending in `\r\n` (joinmarket-clientserver
//! `jmdaemon/onionmc.py`, JoinMarket-NG `jmcore/network.py`). A handshake's `line` is itself a JSON object.
//! Public lines are `<from>!PUBLIC!<command> <args>`; private lines are JMP-0001 lines
//! `<from>!<to>!<command> <body> <pubkey> <signature>` signed with `hostid` `onion-network`.

use serde_json::{Map, Value, json};
use vortex_ng_core::protocol::JM_VERSION;

/// A private message.
pub const PRIVMSG: u64 = 685;
/// A public message.
pub const PUBMSG: u64 = 687;
/// A list of peers and where they are.
pub const PEERLIST: u64 = 789;
/// A request for the peer list.
pub const GETPEERLIST: u64 = 791;
/// A peer's handshake.
pub const HANDSHAKE: u64 = 793;
/// A directory's handshake.
pub const DN_HANDSHAKE: u64 = 795;
/// A heartbeat (JoinMarket-NG; joinmarket-clientserver's 797 collides with a local event and is not used).
pub const PING: u64 = 798;
/// The answer to [`PING`].
pub const PONG: u64 = 799;
/// JMP-0005 nick authentication: the directory's challenge.
pub const NICK_AUTH_CHALLENGE: u64 = 803;
/// JMP-0005: the peer's proof.
pub const NICK_AUTH_PROOF: u64 = 805;
/// JMP-0005: the directory's verdict.
pub const NICK_AUTH_RESULT: u64 = 807;

/// What a peer that serves no onion of its own advertises as its location.
pub const NOT_SERVING_ONION: &str = "NOT-SERVING-ONION";
/// The application name in handshakes.
pub const APP_NAME: &str = "joinmarket";
/// The longest line we send, JSON included: joinmarket-clientserver drops a connection above 40,000 bytes.
pub const MAX_SEND_LINE: usize = 40_000;
/// The longest line we accept, JSON included: JoinMarket-NG's directories forward up to 65,536 bytes.
pub const MAX_RECEIVE_LINE: usize = 65_536;

/// Why a line was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError(pub &'static str);

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// One line on the wire, `\r\n` included. Refused when longer than [`MAX_SEND_LINE`].
pub fn encode(kind: u64, line: &str) -> Result<String, WireError> {
    let encoded = json!({ "type": kind, "line": line }).to_string();
    if encoded.len() > MAX_SEND_LINE {
        return Err(WireError("line too long for the onion channel"));
    }
    Ok(encoded + "\r\n")
}

/// The type and line of a received line (its terminator already removed). Other fields are ignored.
pub fn decode(raw: &str) -> Result<(u64, String), WireError> {
    let value: Value = serde_json::from_str(raw).map_err(|_| WireError("not JSON"))?;
    let object = value.as_object().ok_or(WireError("not an object"))?;
    let kind = object
        .get("type")
        .and_then(Value::as_u64)
        .ok_or(WireError("no type"))?;
    let line = object
        .get("line")
        .and_then(Value::as_str)
        .ok_or(WireError("no line"))?;
    Ok((kind, line.to_string()))
}

/// The handshake a peer that serves no onion sends to a directory (the inner JSON, as sent: a nick
/// authentication proof covers these exact bytes).
pub fn client_handshake(nick: &str, network: &str, features: &[&str]) -> String {
    let features: Map<String, Value> = features
        .iter()
        .map(|f| (f.to_string(), Value::Bool(true)))
        .collect();
    json!({
        "app-name": APP_NAME,
        "directory": false,
        "location-string": NOT_SERVING_ONION,
        "proto-ver": JM_VERSION,
        "features": features,
        "nick": nick,
        "network": network,
    })
    .to_string()
}

/// What a directory said in its handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryHello {
    /// The directory's nick.
    pub nick: String,
    /// Its message of the day.
    pub motd: String,
    /// The features it advertised (`true` values only).
    pub features: Vec<String>,
}

/// Check a directory's handshake answer: accepted, a directory, the same network, protocol version 5 in its
/// range (a reference directory sends only `proto-ver`).
pub fn read_directory_hello(line: &str, network: &str) -> Result<DirectoryHello, WireError> {
    let value: Value =
        serde_json::from_str(line).map_err(|_| WireError("handshake is not JSON"))?;
    let object = value
        .as_object()
        .ok_or(WireError("handshake is not an object"))?;
    if object.get("accepted").and_then(Value::as_bool) != Some(true) {
        return Err(WireError("the directory did not accept us"));
    }
    if object.get("directory").and_then(Value::as_bool) != Some(true) {
        return Err(WireError("not a directory"));
    }
    if object.get("network").and_then(Value::as_str) != Some(network) {
        return Err(WireError("the directory is on another network"));
    }
    let version = |key: &str| object.get(key).and_then(Value::as_u64);
    let (min, max) = match (version("proto-ver-min"), version("proto-ver-max")) {
        (Some(min), Some(max)) => (min, max),
        _ => {
            let single = version("proto-ver").unwrap_or(u64::from(JM_VERSION));
            (single, single)
        }
    };
    if !(min..=max).contains(&u64::from(JM_VERSION)) {
        return Err(WireError("no common protocol version"));
    }
    let features = object
        .get("features")
        .and_then(Value::as_object)
        .map(|f| {
            f.iter()
                .filter(|(_, v)| **v == Value::Bool(true))
                .map(|(k, _)| k.clone())
                .collect()
        })
        .unwrap_or_default();
    let text = |key: &str| {
        object
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .chars()
            .filter(|c| !c.is_control())
            .take(200)
            .collect::<String>()
    };
    Ok(DirectoryHello {
        nick: text("nick"),
        motd: text("motd"),
        features,
    })
}

/// A public line from `nick`: `message` is one command with its leading `!` (`!orderbook`,
/// `!sw0absoffer 0 …`).
pub fn public_line(nick: &str, message: &str) -> String {
    format!("{nick}!PUBLIC{message}")
}

/// The sender and the commands text (with its leading `!`) of a public line. `None` unless it is one, from
/// a well-formed nick.
pub fn read_public_line(line: &str) -> Option<(&str, &str)> {
    let (from, rest) = line.split_once("!PUBLIC")?;
    let well_formed = from.len() == 16
        && from.starts_with('J')
        && from.bytes().all(|b| b.is_ascii_alphanumeric());
    (well_formed && rest.starts_with('!')).then_some((from, rest))
}

/// The directory id a JMP-0005 proof binds to: `<host>:<port>` of a v3 onion, lower case. Other hosts have
/// none unless configured.
pub fn directory_id(host: &str, port: u16) -> Option<String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let label = host.strip_suffix(".onion")?;
    let v3 = label.len() == 56
        && label
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'));
    v3.then(|| format!("{host}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_round_trip_and_are_bounded() {
        let encoded = encode(PRIVMSG, "J5a!J5b!fill 0 1 2 3 key sig").unwrap();
        assert!(encoded.ends_with("\r\n"));
        assert_eq!(
            decode(encoded.trim_end()).unwrap(),
            (PRIVMSG, "J5a!J5b!fill 0 1 2 3 key sig".to_string())
        );
        // Quotes and backslashes survive the JSON.
        let tricky = "J5a!PUBLIC!x \"quoted\" \\back";
        assert_eq!(
            decode(encode(PUBMSG, tricky).unwrap().trim_end())
                .unwrap()
                .1,
            tricky
        );
        // Too long to send; malformed input refused.
        assert!(encode(PRIVMSG, &"a".repeat(MAX_SEND_LINE)).is_err());
        for raw in [
            "",
            "[]",
            "{}",
            r#"{"type":"685","line":"x"}"#,
            r#"{"type":685}"#,
            r#"{"type":685,"line":5}"#,
        ] {
            assert!(decode(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn handshakes() {
        let ours = client_handshake("J5abcdefghijklmn", "regtest", &["ping"]);
        let value: Value = serde_json::from_str(&ours).unwrap();
        assert_eq!(value["location-string"], NOT_SERVING_ONION);
        assert_eq!(value["proto-ver"], 5);
        assert_eq!(value["features"]["ping"], true);
        assert_eq!(value["directory"], false);
        // JoinMarket-NG's answer, and the reference's (a single proto-ver, no features).
        let ng = r#"{"app-name":"joinmarket","directory":true,"proto-ver-min":5,"proto-ver-max":5,"features":{"ping":true,"peerlist_features":true,"nope":false},"accepted":true,"nick":"J5dir","network":"regtest","motd":"hi\u0007"}"#;
        let hello = read_directory_hello(ng, "regtest").unwrap();
        assert_eq!(hello.motd, "hi");
        assert!(hello.features.contains(&"ping".to_string()));
        assert!(!hello.features.contains(&"nope".to_string()));
        let reference = r#"{"app-name":"joinmarket","directory":true,"proto-ver":5,"features":{},"accepted":true,"nick":"J5dir","network":"regtest","motd":"m"}"#;
        assert!(read_directory_hello(reference, "regtest").is_ok());
        // Refusals.
        assert!(read_directory_hello(reference, "signet").is_err());
        for (from, to) in [
            (r#""accepted":true"#, r#""accepted":false"#),
            (r#""directory":true"#, r#""directory":false"#),
            (r#""proto-ver":5"#, r#""proto-ver":6"#),
        ] {
            assert!(
                read_directory_hello(&reference.replace(from, to), "regtest").is_err(),
                "{to}"
            );
        }
    }

    #[test]
    fn public_lines() {
        let line = public_line("J5abcdefghijklmn", "!orderbook");
        assert_eq!(line, "J5abcdefghijklmn!PUBLIC!orderbook");
        assert_eq!(
            read_public_line(&line),
            Some(("J5abcdefghijklmn", "!orderbook"))
        );
        assert_eq!(read_public_line("J5abcdefghijklmn!PUBLICorderbook"), None);
        assert_eq!(read_public_line("J5a b!PUBLIC!orderbook"), None);
        assert_eq!(read_public_line("J5abcdefghijklmn!J5other!fill 1"), None);
    }

    #[test]
    fn directory_ids() {
        let host = format!("{}.onion", "a".repeat(56));
        assert_eq!(
            directory_id(&host.to_uppercase(), 5222),
            Some(format!("{host}:5222"))
        );
        assert_eq!(directory_id("127.0.0.1", 5222), None);
        assert_eq!(directory_id("short.onion", 5222), None);
    }
}
