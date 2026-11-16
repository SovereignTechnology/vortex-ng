//! vortex-ng's adapter for joinstr-difffuzz (`driver/PROTOCOL.md`): JSON lines on stdin and stdout, each op
//! answered by `vortex-ng-joinstr`.

use std::io::{BufRead, Write};
use std::str::FromStr;

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Network, OutPoint, PrivateKey, ScriptBuf, Transaction};
use serde_json::{Value, json};
use vortex_ng_joinstr::message::{PoolMessage, admit_join};
use vortex_ng_joinstr::pool::{Pool, Transport, accept_credentials, public_key_hex};
use vortex_ng_joinstr::{pyjson, rules, tx};

/// The harness runs every implementation on regtest.
const NET: Network = Network::Regtest;

/// A refusal: a short class and free text.
struct Reject(&'static str, String);

type Reply = Result<Value, Reject>;

fn rej(class: &'static str, detail: impl std::fmt::Display) -> Reject {
    Reject(class, detail.to_string())
}

fn text<'a>(args: &'a Value, key: &str) -> &'a str {
    args[key].as_str().unwrap_or_default()
}

fn now() -> i64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    since.map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn secret(hex: &str) -> Result<SecretKey, Reject> {
    SecretKey::from_str(hex).map_err(|e| rej("key", e))
}

/// The pool an announcement event describes, as a joiner would list it: kind 2022, signed by its own key,
/// still open, and reachable over Tor.
fn listed(event: &Value) -> Result<Pool, Reject> {
    if event["kind"].as_u64() != Some(2022) {
        return Err(rej("kind", &event["kind"]));
    }
    let pool = Pool::from_announcement(text(event, "pubkey"), text(event, "content"))
        .map_err(|e| rej("not_listed", e))?;
    if !pool.open_at(now()) {
        return Err(rej("not_listed", "timeout has passed"));
    }
    if pool.transport != Transport::Tor {
        return Err(rej("transport", pool.transport.as_str()));
    }
    Ok(pool)
}

fn parse_announcement(args: &Value) -> Reply {
    let pool = listed(&args["event"])?;
    Ok(json!({
        "id": pool.id, "public_key": pool.public_key, "denomination_sats": pool.denom_sats(),
        "peers": pool.peers, "timeout": pool.timeout, "relay": pool.relay,
        "transport": pool.transport.as_str(), "fee_rate": pool.fee_rate,
    }))
}

/// The harness's neutral pool terms: `denomination_btc` is a decimal string, read as Python's `float`.
struct Terms {
    denomination: f64,
    fee_rate: f64,
    peers: u32,
}

fn terms(args: &Value) -> Result<Terms, Reject> {
    let t = &args["terms"];
    let denomination = match &t["denomination_btc"] {
        Value::String(s) => s.parse::<f64>().map_err(|e| rej("terms", e))?,
        other => other
            .as_f64()
            .ok_or_else(|| rej("terms", "denomination_btc"))?,
    };
    let fee_rate = t["fee_rate"]
        .as_f64()
        .ok_or_else(|| rej("terms", "fee_rate"))?;
    let peers = t["peers"]
        .as_u64()
        .and_then(|p| u32::try_from(p).ok())
        .ok_or_else(|| rej("terms", "peers"))?;
    Ok(Terms {
        denomination,
        fee_rate,
        peers,
    })
}

fn build_announcement(args: &Value) -> Reply {
    if text(args, "transport") != "tor" {
        return Err(rej("transport", text(args, "transport")));
    }
    let key = secret(text(args, "pool_priv"))?;
    let denomination = match &args["denomination_btc"] {
        Value::String(s) => s.parse::<f64>().map_err(|e| rej("terms", e))?,
        other => other
            .as_f64()
            .ok_or_else(|| rej("terms", "denomination_btc"))?,
    };
    let pool = Pool::create(
        &key,
        text(args, "id"),
        denomination,
        args["peers"]
            .as_u64()
            .and_then(|p| u32::try_from(p).ok())
            .ok_or_else(|| rej("terms", "peers"))?,
        args["timeout"]
            .as_i64()
            .ok_or_else(|| rej("terms", "timeout"))?,
        text(args, "relay"),
        args["fee_rate"]
            .as_f64()
            .ok_or_else(|| rej("terms", "fee_rate"))?,
    )
    .map_err(|e| rej("create", e))?;
    Ok(json!({"event": {"pubkey": pool.public_key, "kind": 2022, "content": pool.announcement()}}))
}

/// The creator's credentials for its announcement. The harness may pass a `fee_rate` other than the
/// announced one, to see which joiners notice; a vortex-ng creator never does, so it is patched in here.
fn build_credentials(args: &Value) -> Reply {
    let key = secret(text(args, "pool_priv"))?;
    let pool = Pool::from_announcement(&public_key_hex(&key), text(args, "announcement"))
        .map_err(|e| rej("announcement", e))?;
    let mut creds: Value =
        serde_json::from_str(&pool.credentials(&key)).map_err(|e| rej("credentials", e))?;
    if !args["fee_rate"].is_null() {
        creds["fee_rate"] = args["fee_rate"].clone();
    }
    Ok(json!({"plaintext": pyjson::dumps(&creds)}))
}

fn validate_credentials(args: &Value) -> Reply {
    let event = &args["event"];
    let pool = Pool::from_announcement(text(event, "pubkey"), text(event, "content"))
        .map_err(|e| rej("not_listed", e))?;
    accept_credentials(text(args, "credentials"), &pool).map_err(|e| rej("credentials", e))?;
    Ok(json!({
        "fee_rate": pool.fee_rate, "relay": pool.relay,
        "denomination_sats": pool.denom_sats(), "peers": pool.peers,
    }))
}

fn build_join_request(_: &Value) -> Reply {
    let join = PoolMessage::JoinPool {
        autct_proof: None,
        autct_token: None,
    };
    Ok(json!({"plaintext": join.to_plaintext()}))
}

fn admit(args: &Value) -> Reply {
    admit_join(
        text(args, "plaintext"),
        text(args, "sender"),
        text(args, "pool_pubkey"),
        &[],
    )
    .map(|_| json!({}))
    .ok_or_else(|| rej("not_join", ""))
}

fn build_output_msg(args: &Value) -> Reply {
    let msg = PoolMessage::Output {
        address: text(args, "address").to_string(),
    };
    Ok(json!({"plaintext": msg.to_plaintext()}))
}

fn build_input_msg(args: &Value) -> Reply {
    let msg = PoolMessage::Input {
        psbt: text(args, "psbt").to_string(),
    };
    Ok(json!({"plaintext": msg.to_plaintext()}))
}

fn strings(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// The outputs registered, each as the address text that was sent for it.
fn collect_outputs(args: &Value) -> Reply {
    let peers = args["peers"]
        .as_u64()
        .and_then(|p| u32::try_from(p).ok())
        .ok_or_else(|| rej("terms", "peers"))?;
    let plaintexts = strings(&args["plaintexts"]);
    let outputs = rules::collect_outputs(plaintexts.iter().copied(), peers, NET);
    let sent: Vec<String> = plaintexts
        .iter()
        .filter_map(|t| match PoolMessage::parse(t) {
            Some(PoolMessage::Output { address }) => Some(address),
            _ => None,
        })
        .collect();
    let as_sent: Vec<&str> = outputs
        .iter()
        .filter_map(|a| {
            sent.iter().map(String::as_str).find(|s| {
                rules::output_address(s, NET)
                    .is_some_and(|b| b.script_pubkey() == a.script_pubkey())
            })
        })
        .collect();
    Ok(json!({"outputs": as_sent}))
}

fn collect_inputs(args: &Value) -> Reply {
    let t = terms(args)?;
    let pool_terms = tx::Terms {
        denomination: t.denomination,
        peers: t.peers,
    };
    let collected = tx::collect_inputs(strings(&args["plaintexts"]), None, pool_terms);
    let psbts: Vec<String> = collected.into_iter().map(|(psbt, _)| psbt).collect();
    Ok(json!({"inputs": psbts}))
}

fn scripts(args: &Value) -> Result<Vec<ScriptBuf>, Reject> {
    strings(&args["outputs"])
        .into_iter()
        .map(|a| {
            rules::output_address(a, NET)
                .map(|a| a.script_pubkey())
                .ok_or_else(|| rej("address", a))
        })
        .collect()
}

/// The pool's template and output amount for the harness's terms and outputs.
fn template(args: &Value) -> Result<(Terms, Vec<bitcoin::TxOut>, u64), Reject> {
    let t = terms(args)?;
    let outputs = scripts(args)?;
    if outputs.len() != t.peers as usize {
        return Err(rej("peer_count", outputs.len()));
    }
    let sats = rules::check_amounts(t.denomination, t.fee_rate, t.peers, &outputs)
        .map_err(|e| rej("amount", e))?;
    let template = tx::template(&outputs, sats);
    Ok((t, template, sats))
}

fn output_amount(args: &Value) -> Reply {
    let (_, _, sats) = template(args)?;
    Ok(json!({"output_sats": sats}))
}

fn registration(args: &Value) -> Reply {
    let (t, template, sats) = template(args)?;
    let funding: Transaction =
        deserialize_hex(text(args, "funding_tx")).map_err(|e| rej("funding", e))?;
    let vout = args["vout"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);
    let coin = funding
        .output
        .get(vout as usize)
        .ok_or_else(|| rej("funding", vout))?;
    rules::check_input(coin.value.to_sat(), t.denomination, sats).map_err(|e| rej("input", e))?;
    let key = PrivateKey::from_wif(text(args, "wif")).map_err(|e| rej("wif", e))?;
    let mine = rules::output_address(text(args, "my_address"), NET)
        .ok_or_else(|| rej("address", "my_address"))?;
    let psbt = tx::build_registration(
        OutPoint {
            txid: funding.compute_txid(),
            vout,
        },
        coin,
        &template,
        &mine.script_pubkey(),
        t.peers,
        &key.inner,
    )
    .map_err(|e| rej("registration", e))?;
    Ok(json!({"psbt": psbt.to_string(), "output_sats": sats}))
}

fn combine(args: &Value) -> Reply {
    let (_, template, _) = template(args)?;
    let registrations = strings(&args["psbts"])
        .into_iter()
        .map(|p| tx::read_registration(p, Some(&template)).map_err(|e| rej("registration", e)))
        .collect::<Result<Vec<_>, _>>()?;
    let tx = tx::combine(&registrations, &template, true).map_err(|e| rej("combine", e))?;
    Ok(json!({"tx": serialize_hex(&tx)}))
}

fn recovery_amount(args: &Value) -> Reply {
    let t = terms(args)?;
    let count = |key: &str| {
        args[key]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| rej("terms", key.to_string()))
    };
    let sats = rules::recovery_output_amount(
        t.denomination,
        t.fee_rate,
        count("n_outputs")?,
        count("n_inputs")?,
    );
    Ok(json!({"output_sats": sats}))
}

fn nip04_encrypt(args: &Value) -> Reply {
    let sk =
        nostr::key::SecretKey::from_hex(text(args, "private_key")).map_err(|e| rej("key", e))?;
    let pk = nostr::key::PublicKey::from_hex(text(args, "recipient")).map_err(|e| rej("key", e))?;
    let content = nostr::nips::nip04::encrypt(&sk, &pk, text(args, "plaintext"))
        .map_err(|e| rej("encrypt", e))?;
    Ok(json!({"content": content}))
}

fn nip04_decrypt(args: &Value) -> Reply {
    let sk =
        nostr::key::SecretKey::from_hex(text(args, "private_key")).map_err(|e| rej("key", e))?;
    let pk = nostr::key::PublicKey::from_hex(text(args, "sender")).map_err(|e| rej("key", e))?;
    let plaintext = nostr::nips::nip04::decrypt(&sk, &pk, text(args, "content"))
        .map_err(|e| rej("decrypt", e))?;
    Ok(json!({"plaintext": plaintext}))
}

type Op = fn(&Value) -> Reply;

const OPS: &[(&str, Op)] = &[
    ("parse_announcement", parse_announcement),
    ("build_announcement", build_announcement),
    ("build_credentials", build_credentials),
    ("validate_credentials", validate_credentials),
    ("build_join_request", build_join_request),
    ("admit_join", admit),
    ("build_output_msg", build_output_msg),
    ("build_input_msg", build_input_msg),
    ("collect_outputs", collect_outputs),
    ("collect_inputs", collect_inputs),
    ("output_amount", output_amount),
    ("registration", registration),
    ("combine", combine),
    ("recovery_amount", recovery_amount),
    ("nip04_encrypt", nip04_encrypt),
    ("nip04_decrypt", nip04_decrypt),
];

/// Answer one request line.
fn answer(line: &str) -> Value {
    let Ok(request) = serde_json::from_str::<Value>(line) else {
        return json!({"reject": "request", "detail": "not JSON"});
    };
    let Some((_, op)) = OPS
        .iter()
        .find(|(name, _)| request["op"].as_str() == Some(name))
    else {
        return json!({"unsupported": true});
    };
    // A panic inside an op is a finding ("crash"), not the end of the adapter.
    match std::panic::catch_unwind(|| op(&request["args"])) {
        Ok(Ok(value)) => json!({"ok": value}),
        Ok(Err(Reject(class, detail))) => json!({"reject": class, "detail": detail}),
        Err(_) => json!({"crash": "panic in vortex-ng-joinstr"}),
    }
}

fn main() {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let ops: Vec<&str> = OPS.iter().map(|(name, _)| *name).collect();
    let _ = writeln!(out, "{}", json!({"ready": ops}));
    let _ = out.flush();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let _ = writeln!(out, "{}", answer(&line));
        let _ = out.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(op: &str, args: Value) -> Value {
        answer(&json!({"op": op, "args": args}).to_string())
    }

    const POOL_PRIV: &str = "0909090909090909090909090909090909090909090909090909090909090909";

    fn announce() -> Value {
        let reply = call(
            "build_announcement",
            json!({"pool_priv": POOL_PRIV, "id": "pool1", "denomination_btc": "0.001", "peers": 3,
                   "timeout": now() + 3600, "relay": "wss://relay.example", "fee_rate": 2.5, "transport": "tor"}),
        );
        reply["ok"]["event"].clone()
    }

    #[test]
    fn an_announcement_we_build_is_one_we_list_and_whose_credentials_we_accept() {
        let event = announce();
        let listed = call("parse_announcement", json!({"event": event}));
        assert_eq!(listed["ok"]["denomination_sats"], 100_000);
        assert_eq!(listed["ok"]["peers"], 3);
        let creds = call(
            "build_credentials",
            json!({"announcement": event["content"], "pool_priv": POOL_PRIV, "fee_rate": 2.5}),
        );
        let ok = call(
            "validate_credentials",
            json!({"event": event, "credentials": creds["ok"]["plaintext"]}),
        );
        assert_eq!(ok["ok"]["fee_rate"], 2.5);
        // A creator raising the fee rate in the credentials is caught.
        let raised = call(
            "build_credentials",
            json!({"announcement": event["content"], "pool_priv": POOL_PRIV, "fee_rate": 50}),
        );
        let refused = call(
            "validate_credentials",
            json!({"event": event, "credentials": raised["ok"]["plaintext"]}),
        );
        assert_eq!(refused["reject"], "credentials");
    }

    #[test]
    fn refusals_unknown_ops_and_bad_requests() {
        let mut event = announce();
        event["kind"] = json!(1);
        assert_eq!(
            call("parse_announcement", json!({"event": event}))["reject"],
            "kind"
        );
        assert_eq!(call("build_reregister", json!({}))["unsupported"], true);
        assert_eq!(answer("not json")["reject"], "request");
        let join = call("build_join_request", json!({}));
        assert_eq!(join["ok"]["plaintext"], r#"{"type": "join_pool"}"#);
        let admitted = call(
            "admit_join",
            json!({"plaintext": join["ok"]["plaintext"], "sender": "a", "pool_pubkey": "b"}),
        );
        assert_eq!(admitted["ok"], json!({}));
        assert_eq!(
            call(
                "admit_join",
                json!({"plaintext": "x", "sender": "a", "pool_pubkey": "b"})
            )["reject"],
            "not_join"
        );
        let terms = json!({"denomination_btc": "0.0003", "fee_rate": 1.5, "peers": 3});
        let amount = call(
            "recovery_amount",
            json!({"terms": terms, "n_outputs": 3, "n_inputs": 3}),
        );
        assert_eq!(amount["ok"]["output_sats"], 29_698);
    }
}
