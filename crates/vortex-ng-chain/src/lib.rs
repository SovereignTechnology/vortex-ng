//! Chain backend over Core-compatible JSON-RPC: Bitcoin Core or rbitcoin (ADR 0005).
//!
//! Only the calls JoinMarket needs: the chain and its tip, a UTXO lookup (`gettxout`, mempool included, so
//! an output already spent in the mempool reads as gone), raw transactions, broadcast and test-accept, fee
//! estimates, and blocks for wallet sync. Responses are read as plain JSON rather than version-specific
//! structs, so the same code serves Core releases and rbitcoin.

use std::path::Path;
use std::time::Duration;

use jsonrpc::Client;
use jsonrpc::simple_http::Builder;
use serde_json::{Value, json};
use vortex_ng_core::bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use vortex_ng_core::bitcoin::hex::FromHex;
use vortex_ng_core::bitcoin::{
    Amount, Block, BlockHash, FeeRate, Network, OutPoint, ScriptBuf, Transaction, Txid,
};

/// Core's RPC error code for an unknown transaction or block (`RPC_INVALID_ADDRESS_OR_KEY`).
pub const RPC_NOT_FOUND: i32 = -5;
/// Core's RPC error code for a transaction already in the chain (`RPC_VERIFY_ALREADY_IN_CHAIN`).
pub const RPC_ALREADY_IN_CHAIN: i32 = -27;

/// Why a chain call failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainError {
    /// The node could not be reached or the HTTP exchange failed.
    Transport(String),
    /// The node answered with an RPC error.
    Rpc {
        /// Core's error code.
        code: i32,
        /// Core's message.
        message: String,
    },
    /// The answer did not have the expected shape.
    Parse(&'static str),
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::Transport(e) => write!(f, "chain backend unreachable: {e}"),
            ChainError::Rpc { code, message } => write!(f, "chain backend error {code}: {message}"),
            ChainError::Parse(what) => write!(f, "unexpected chain backend answer: {what}"),
        }
    }
}

impl std::error::Error for ChainError {}

/// How to authenticate to the node.
#[derive(Clone, Debug)]
pub enum Auth {
    /// `rpcuser` / `rpcpassword`.
    UserPass(String, String),
    /// The node's `.cookie` file (`__cookie__:<password>`), re-read at connection time.
    CookieFile(std::path::PathBuf),
}

/// An unspent output as the node sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    /// Its value.
    pub value: Amount,
    /// Its scriptPubKey.
    pub script_pubkey: ScriptBuf,
    /// Confirmations; 0 while in the mempool.
    pub confirmations: u32,
    /// Whether it is a coinbase output (unspendable for 100 blocks).
    pub coinbase: bool,
}

/// Convert a BTC amount as Core prints it (a JSON number) to satoshis, as Core's `AmountFromValue` does:
/// round `btc * 1e8`. Exact for every valid amount, since `21e14 < 2^53`.
fn btc_to_amount(value: &Value) -> Result<Amount, ChainError> {
    let btc = value.as_f64().ok_or(ChainError::Parse("amount"))?;
    if !(0.0..=21_000_000.0).contains(&btc) {
        return Err(ChainError::Parse("amount out of range"));
    }
    Ok(Amount::from_sat((btc * 100_000_000.0).round() as u64))
}

/// A Core-compatible JSON-RPC node.
pub struct CoreRpc {
    client: Client,
}

impl std::fmt::Debug for CoreRpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CoreRpc")
    }
}

impl CoreRpc {
    /// Connect to `url` (for example `http://127.0.0.1:18443`). No request is made yet.
    pub fn new(url: &str, auth: &Auth, timeout: Duration) -> Result<CoreRpc, ChainError> {
        let builder = Builder::new()
            .url(url)
            .map_err(|e| ChainError::Transport(e.to_string()))?
            .timeout(timeout);
        let builder = match auth {
            Auth::UserPass(user, pass) => builder.auth(user.as_str(), Some(pass.as_str())),
            Auth::CookieFile(path) => builder.cookie_auth(read_cookie(path)?),
        };
        Ok(CoreRpc {
            client: Client::with_transport(builder.build()),
        })
    }

    /// Use another transport (tests).
    pub fn with_transport<T: jsonrpc::Transport>(transport: T) -> CoreRpc {
        CoreRpc {
            client: Client::with_transport(transport),
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, ChainError> {
        let params = jsonrpc::try_arg(params).map_err(|_| ChainError::Parse("params"))?;
        match self.client.call::<Value>(method, Some(&params)) {
            Ok(v) => Ok(v),
            Err(jsonrpc::Error::Rpc(e)) => Err(ChainError::Rpc {
                code: e.code,
                message: e.message,
            }),
            Err(e) => Err(ChainError::Transport(e.to_string())),
        }
    }

    /// The node's network, from `getblockchaininfo`.
    pub fn network(&self) -> Result<Network, ChainError> {
        let info = self.call("getblockchaininfo", json!([]))?;
        match info["chain"].as_str() {
            Some("main") => Ok(Network::Bitcoin),
            Some("test") => Ok(Network::Testnet),
            Some("testnet4") => Ok(Network::Testnet4),
            Some("signet") => Ok(Network::Signet),
            Some("regtest") => Ok(Network::Regtest),
            _ => Err(ChainError::Parse("chain")),
        }
    }

    /// The height of the best block.
    pub fn tip_height(&self) -> Result<u32, ChainError> {
        let info = self.call("getblockchaininfo", json!([]))?;
        info["blocks"]
            .as_u64()
            .and_then(|h| u32::try_from(h).ok())
            .ok_or(ChainError::Parse("blocks"))
    }

    /// The output at `outpoint` if it is unspent, mempool included (`gettxout txid n true`).
    pub fn utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, ChainError> {
        let v = self.call(
            "gettxout",
            json!([outpoint.txid.to_string(), outpoint.vout, true]),
        )?;
        if v.is_null() {
            return Ok(None);
        }
        let hex = v["scriptPubKey"]["hex"]
            .as_str()
            .ok_or(ChainError::Parse("scriptPubKey"))?;
        let script = Vec::<u8>::from_hex(hex).map_err(|_| ChainError::Parse("scriptPubKey hex"))?;
        Ok(Some(Utxo {
            value: btc_to_amount(&v["value"])?,
            script_pubkey: ScriptBuf::from_bytes(script),
            confirmations: v["confirmations"]
                .as_u64()
                .and_then(|c| u32::try_from(c).ok())
                .ok_or(ChainError::Parse("confirmations"))?,
            coinbase: v["coinbase"]
                .as_bool()
                .ok_or(ChainError::Parse("coinbase"))?,
        }))
    }

    /// A transaction by id, or `None` if the node does not know it (needs `txindex` for confirmed
    /// transactions outside the node's wallet).
    pub fn raw_transaction(&self, txid: &Txid) -> Result<Option<Transaction>, ChainError> {
        match self.call("getrawtransaction", json!([txid.to_string(), false])) {
            Ok(v) => {
                let hex = v.as_str().ok_or(ChainError::Parse("raw transaction"))?;
                deserialize_hex(hex)
                    .map(Some)
                    .map_err(|_| ChainError::Parse("raw transaction hex"))
            }
            Err(ChainError::Rpc {
                code: RPC_NOT_FOUND,
                ..
            }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Broadcast; an already-confirmed transaction counts as success.
    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid, ChainError> {
        match self.call("sendrawtransaction", json!([serialize_hex(tx)])) {
            Ok(v) => v
                .as_str()
                .and_then(|s| s.parse().ok())
                .ok_or(ChainError::Parse("txid")),
            Err(ChainError::Rpc {
                code: RPC_ALREADY_IN_CHAIN,
                ..
            }) => Ok(tx.compute_txid()),
            Err(e) => Err(e),
        }
    }

    /// Whether the mempool would accept `tx`; `Err(reason)` inside `Ok` when it would not.
    pub fn test_accept(&self, tx: &Transaction) -> Result<Result<(), String>, ChainError> {
        let v = self.call("testmempoolaccept", json!([[serialize_hex(tx)]]))?;
        let first = v.get(0).ok_or(ChainError::Parse("testmempoolaccept"))?;
        match first["allowed"].as_bool() {
            Some(true) => Ok(Ok(())),
            Some(false) => Ok(Err(first["reject-reason"]
                .as_str()
                .unwrap_or("rejected")
                .to_string())),
            None => Err(ChainError::Parse("allowed")),
        }
    }

    /// The node's fee estimate for confirmation within `target` blocks, or `None` when it has none
    /// (for example on regtest).
    pub fn estimate_fee_rate(&self, target: u16) -> Result<Option<FeeRate>, ChainError> {
        let v = self.call("estimatesmartfee", json!([target]))?;
        if v.get("feerate").is_none() {
            return Ok(None);
        }
        let sat_per_kvb = btc_to_amount(&v["feerate"])?.to_sat();
        Ok(Some(FeeRate::from_sat_per_kwu(sat_per_kvb / 4)))
    }

    /// The hash of the block at `height`.
    pub fn block_hash(&self, height: u32) -> Result<BlockHash, ChainError> {
        let v = self.call("getblockhash", json!([height]))?;
        v.as_str()
            .and_then(|s| s.parse().ok())
            .ok_or(ChainError::Parse("block hash"))
    }

    /// The timestamp of the block at `height` (`getblockheader`), for a fidelity bond's confirmation time.
    pub fn block_time(&self, height: u32) -> Result<u32, ChainError> {
        let hash = self.block_hash(height)?;
        let header = self.call("getblockheader", json!([hash.to_string(), true]))?;
        header["time"]
            .as_u64()
            .and_then(|t| u32::try_from(t).ok())
            .ok_or(ChainError::Parse("block time"))
    }

    /// The block with `hash`.
    pub fn block(&self, hash: &BlockHash) -> Result<Block, ChainError> {
        let v = self.call("getblock", json!([hash.to_string(), 0]))?;
        let hex = v.as_str().ok_or(ChainError::Parse("block"))?;
        deserialize_hex(hex).map_err(|_| ChainError::Parse("block hex"))
    }
}

/// The lookups a maker or taker needs from the chain. `CoreRpc` implements it; tests use fakes.
pub trait ChainLookup {
    /// The output at `outpoint` if unspent (mempool included).
    fn utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, String>;
    /// The best block's height.
    fn tip_height(&self) -> Result<u32, String>;
    /// The timestamp of the block at `height`.
    fn block_time(&self, height: u32) -> Result<u32, String>;
}

impl ChainLookup for CoreRpc {
    fn utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, String> {
        CoreRpc::utxo(self, outpoint).map_err(|e| e.to_string())
    }
    fn tip_height(&self) -> Result<u32, String> {
        CoreRpc::tip_height(self).map_err(|e| e.to_string())
    }
    fn block_time(&self, height: u32) -> Result<u32, String> {
        CoreRpc::block_time(self, height).map_err(|e| e.to_string())
    }
}

/// Read a `.cookie` file (`user:password`), trimming the trailing newline.
fn read_cookie(path: &Path) -> Result<String, ChainError> {
    let cookie = std::fs::read_to_string(path)
        .map_err(|e| ChainError::Transport(format!("cookie file: {e}")))?;
    let cookie = cookie.trim_end().to_string();
    if !cookie.contains(':') {
        return Err(ChainError::Parse("cookie file"));
    }
    Ok(cookie)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fmt;

    use jsonrpc::error::RpcError;
    use jsonrpc::{Request, Response};
    use serde_json::value::RawValue;
    use vortex_ng_core::bitcoin::hashes::Hash;

    use super::*;

    /// A canned result (JSON text) or RPC error (code, message).
    type Canned = Result<&'static str, (i32, &'static str)>;

    /// Answers by method name with a canned result or RPC error.
    struct Fake(HashMap<&'static str, Canned>);

    impl jsonrpc::Transport for Fake {
        fn send_request(&self, req: Request) -> Result<Response, jsonrpc::Error> {
            let (result, error) = match self.0.get(req.method) {
                Some(Ok(json)) => (
                    Some(RawValue::from_string((*json).to_string()).unwrap()),
                    None,
                ),
                Some(Err((code, message))) => (
                    None,
                    Some(RpcError {
                        code: *code,
                        message: (*message).to_string(),
                        data: None,
                    }),
                ),
                None => (
                    None,
                    Some(RpcError {
                        code: -32601,
                        message: "Method not found".into(),
                        data: None,
                    }),
                ),
            };
            Ok(Response {
                result,
                error,
                id: req.id.clone(),
                jsonrpc: Some("2.0".into()),
            })
        }
        fn send_batch(&self, _: &[Request]) -> Result<Vec<Response>, jsonrpc::Error> {
            unimplemented!()
        }
        fn fmt_target(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("fake")
        }
    }

    fn rpc(entries: &[(&'static str, Canned)]) -> CoreRpc {
        CoreRpc::with_transport(Fake(entries.iter().cloned().collect()))
    }

    #[test]
    fn chain_and_tip() {
        let node = rpc(&[(
            "getblockchaininfo",
            Ok(r#"{"chain":"regtest","blocks":203,"headers":203}"#),
        )]);
        assert_eq!(node.network().unwrap(), Network::Regtest);
        assert_eq!(node.tip_height().unwrap(), 203);
        let odd = rpc(&[("getblockchaininfo", Ok(r#"{"chain":"weird","blocks":-1}"#))]);
        assert!(odd.network().is_err());
        assert!(odd.tip_height().is_err());
    }

    #[test]
    fn utxo_lookup() {
        let node = rpc(&[(
            "gettxout",
            Ok(r#"{"bestblock":"00","confirmations":6,"value":0.12345678,
                  "scriptPubKey":{"hex":"0014751e76e8199196d454941c45d1b3a323f1433bd6","type":"witness_v0_keyhash"},
                  "coinbase":false}"#),
        )]);
        let op = OutPoint {
            txid: Txid::from_byte_array([1; 32]),
            vout: 0,
        };
        let utxo = node.utxo(&op).unwrap().unwrap();
        assert_eq!(utxo.value, Amount::from_sat(12_345_678));
        assert_eq!(utxo.confirmations, 6);
        assert!(utxo.script_pubkey.is_p2wpkh());
        assert!(!utxo.coinbase);
        let spent = rpc(&[("gettxout", Ok("null"))]);
        assert_eq!(spent.utxo(&op).unwrap(), None);
    }

    #[test]
    fn amounts_round_like_core() {
        for (json, sats) in [
            ("0.00000001", 1),
            ("20999999.97690000", 2_099_999_997_690_000),
            ("0.1", 10_000_000),
            ("1e-8", 1),
        ] {
            assert_eq!(
                btc_to_amount(&serde_json::from_str(json).unwrap())
                    .unwrap()
                    .to_sat(),
                sats,
                "{json}"
            );
        }
        for bad in ["-0.1", "21000000.1", "\"1\"", "null"] {
            assert!(
                btc_to_amount(&serde_json::from_str(bad).unwrap()).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn errors_and_not_found() {
        let txid = Txid::from_byte_array([2; 32]);
        let node = rpc(&[
            (
                "getrawtransaction",
                Err((RPC_NOT_FOUND, "No such mempool or blockchain transaction")),
            ),
            ("sendrawtransaction", Err((-26, "min relay fee not met"))),
        ]);
        assert_eq!(node.raw_transaction(&txid).unwrap(), None);
        let tx = Transaction {
            version: vortex_ng_core::bitcoin::transaction::Version::TWO,
            lock_time: vortex_ng_core::bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        assert_eq!(
            node.broadcast(&tx),
            Err(ChainError::Rpc {
                code: -26,
                message: "min relay fee not met".into()
            })
        );
        let in_chain = rpc(&[(
            "sendrawtransaction",
            Err((RPC_ALREADY_IN_CHAIN, "Transaction already in block chain")),
        )]);
        assert_eq!(in_chain.broadcast(&tx).unwrap(), tx.compute_txid());
    }

    #[test]
    fn fees_and_test_accept() {
        let node = rpc(&[
            ("estimatesmartfee", Ok(r#"{"feerate":0.00012,"blocks":2}"#)),
            (
                "testmempoolaccept",
                Ok(
                    r#"[{"txid":"00","allowed":false,"reject-reason":"bad-txns-inputs-missingorspent"}]"#,
                ),
            ),
        ]);
        // 0.00012 BTC/kvB = 12,000 sat/kvB = 3,000 sat/kwu = 12 sat/vB.
        assert_eq!(
            node.estimate_fee_rate(2).unwrap(),
            Some(FeeRate::from_sat_per_kwu(3_000))
        );
        let tx = Transaction {
            version: vortex_ng_core::bitcoin::transaction::Version::TWO,
            lock_time: vortex_ng_core::bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        assert_eq!(
            node.test_accept(&tx).unwrap(),
            Err("bad-txns-inputs-missingorspent".to_string())
        );
        let none = rpc(&[(
            "estimatesmartfee",
            Ok(r#"{"errors":["Insufficient data or no feerate found"],"blocks":0}"#),
        )]);
        assert_eq!(none.estimate_fee_rate(2).unwrap(), None);
    }

    #[test]
    fn block_time_from_header() {
        let node = rpc(&[
            (
                "getblockhash",
                Ok(r#""0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206""#),
            ),
            (
                "getblockheader",
                Ok(r#"{"hash":"0f91","height":0,"time":1296688602}"#),
            ),
        ]);
        assert_eq!(node.block_time(0).unwrap(), 1_296_688_602);
    }

    #[test]
    fn cookie_file() {
        let dir = std::env::temp_dir().join(format!("vortex-ng-cookie-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(".cookie");
        std::fs::write(&path, "__cookie__:abc123\n").unwrap();
        assert_eq!(read_cookie(&path).unwrap(), "__cookie__:abc123");
        std::fs::write(&path, "garbage").unwrap();
        assert!(read_cookie(&path).is_err());
        assert!(read_cookie(&dir.join("missing")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
