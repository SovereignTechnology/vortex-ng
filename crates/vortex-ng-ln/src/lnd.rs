//! An LND node's on-chain wallet as a source of coins for a CoinJoin, over its REST API.
//!
//! LND holds the keys and never hands one out. It tells us which coins it has and which of them a channel
//! close paid it, keeps them from being spent elsewhere while a round runs (a lease), and signs our inputs
//! of the finished transaction (`signrpc.ComputeInputScript`). Checked against LND v0.21.8-beta's
//! `signer.proto`, `walletkit.proto`, `lightning.proto` and their REST mappings.
//!
//! - **The connection** is TLS to the one certificate in the node's `tls.cert`, compared byte for byte, so
//!   neither a CA nor the host name is trusted. The macaroon is read from a file nobody else can read, and
//!   goes in one header.
//! - **What is kept from the answers** is outpoints, amounts, scripts, depths and close kinds. A channel's
//!   funding outpoint, the peer's key and the node's identity are in those answers and are never parsed
//!   into anything.
//! - **The macaroon is a spending credential** once it may call `ComputeInputScript`: with it, any coin of
//!   the node's wallet can be signed away. Bake one limited to the calls used, by `uri:` permission (never
//!   `signer:generate`, which also reaches the node's channel and identity keys through `SignOutputRaw`):
//!   the list is in the README. It must be in a file only its owner can read.
//! - **A round must not take what the node needs to stay safe.** LND keeps a reserve to fee-bump the force
//!   close of its anchor channels and enforces it on its own sends. It does not on a spend it only signs,
//!   so [`keeps_reserve`] does.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use serde_json::{Value, json};
use vortex_ng_core::bitcoin::base64::Engine;
use vortex_ng_core::bitcoin::base64::engine::general_purpose::STANDARD;
use vortex_ng_core::bitcoin::consensus::encode::serialize;
use vortex_ng_core::bitcoin::hex::DisplayHex;
use vortex_ng_core::bitcoin::secp256k1::{PublicKey, XOnlyPublicKey, schnorr};
use vortex_ng_core::bitcoin::transaction::Version;
use vortex_ng_core::bitcoin::{
    Address, Amount, Network, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness, absolute, ecdsa,
};
use vortex_ng_core::lnclose::CloseKind;
use vortex_ng_core::sig::{InputSigner, encode_sw0, encode_tr0};
use vortex_ng_core::tx::random_u64;
use zeroize::{Zeroize, Zeroizing};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(60);
/// The largest answer read. A node with a long channel history answers in megabytes at most.
const MAX_RESPONSE: usize = 32 * 1024 * 1024;
/// The largest macaroon file read.
const MAX_MACAROON: u64 = 64 * 1024;
/// The largest `tls.cert` read.
const MAX_CERT: u64 = 64 * 1024;
/// How long a lease holds a coin if nothing releases it: longer than the longest round `coinjoin` runs.
const LEASE_SECONDS: u64 = 1_200;
/// How long the coins stay held when a broadcast failed in a way that does not say whether it got out.
const UNKNOWN_BROADCAST_SECONDS: u64 = 86_400;
/// Confirmations of the spending transaction after which the node may forget a broadcast round's lease.
const HOLD_UNTIL_SPEND_CONFS: u32 = 6;
const SIGHASH_ALL: u32 = 1;
const SIGHASH_DEFAULT: u32 = 0;

/// Why a call to the node failed. Holds no macaroon, and from the node's answers only its error message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LndError(pub String);

impl std::fmt::Display for LndError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "lnd: {}", self.0)
    }
}

impl std::error::Error for LndError {}

fn fail(why: impl std::fmt::Display) -> LndError {
    LndError(why.to_string())
}

/// A confirmed coin of the node's wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LndCoin {
    /// The coin.
    pub outpoint: OutPoint,
    /// Its value and script.
    pub txout: TxOut,
    /// Its depth.
    pub confirmations: u32,
    /// The kind of channel close that paid it, by the node's own records; none if it was not one.
    pub close: Option<CloseKind>,
}

/// Accepts the one certificate in the node's `tls.cert` and no other, and still checks that the peer holds
/// its key.
#[derive(Debug)]
struct Pinned {
    cert: CertificateDer<'static>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if intermediates.is_empty() && end_entity.as_ref() == self.cert.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// An open file of at most `limit` bytes (`path` is for the error).
fn read_limited(file: std::fs::File, path: &Path, limit: u64) -> Result<Vec<u8>, LndError> {
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| fail(format!("{}: {e}", path.display())))?;
    if bytes.is_empty() || bytes.len() as u64 > limit {
        return Err(fail(format!(
            "{}: empty, or too long to be what it should be",
            path.display()
        )));
    }
    Ok(bytes)
}

/// A connection to one LND node's REST API. Each call is a connection of its own.
pub struct Lnd {
    address: String,
    tls: Arc<ClientConfig>,
    macaroon: Zeroizing<String>,
}

impl std::fmt::Debug for Lnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lnd")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl Lnd {
    /// The node at `address` (`host:port`, its `restlisten`), which must present the certificate in
    /// `tls_cert`, authenticated with the macaroon in `macaroon`: a file no other user may read.
    pub fn open(address: &str, tls_cert: &Path, macaroon: &Path) -> Result<Lnd, LndError> {
        // The file that is checked is the file that is read: one handle for both.
        let file = std::fs::File::open(macaroon)
            .map_err(|e| fail(format!("{}: {e}", macaroon.display())))?;
        let mode = file
            .metadata()
            .map_err(|e| fail(format!("{}: {e}", macaroon.display())))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(fail(format!(
                "{} can be read by other users: it can spend the node's coins (chmod 600)",
                macaroon.display()
            )));
        }
        let mut raw = read_limited(file, macaroon, MAX_MACAROON)?;
        let hex = Zeroizing::new(raw.to_lower_hex_string());
        raw.zeroize();

        let cert_file = std::fs::File::open(tls_cert)
            .map_err(|e| fail(format!("{}: {e}", tls_cert.display())))?;
        let pem = read_limited(cert_file, tls_cert, MAX_CERT)?;
        let cert = CertificateDer::from_pem_slice(&pem)
            .map_err(|_| fail(format!("{}: no certificate in it", tls_cert.display())))?
            .into_owned();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let algorithms = provider.signature_verification_algorithms;
        let tls = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(fail)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pinned { cert, algorithms }))
            .with_no_client_auth();
        Ok(Lnd {
            address: address.to_string(),
            tls: Arc::new(tls),
            macaroon: hex,
        })
    }

    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, LndError> {
        let to = self
            .address
            .to_socket_addrs()
            .map_err(|e| fail(format!("{}: {e}", self.address)))?
            .next()
            .ok_or_else(|| fail(format!("{}: no address", self.address)))?;
        let tcp = TcpStream::connect_timeout(&to, CONNECT_TIMEOUT)
            .map_err(|e| fail(format!("{}: {e}", self.address)))?;
        tcp.set_read_timeout(Some(IO_TIMEOUT)).map_err(fail)?;
        tcp.set_write_timeout(Some(IO_TIMEOUT)).map_err(fail)?;
        // The name is not what is checked (the certificate is), and this one tells a watcher nothing.
        let name = ServerName::try_from("localhost").map_err(fail)?;
        let connection = ClientConnection::new(self.tls.clone(), name).map_err(fail)?;
        let mut stream = StreamOwned::new(connection, tcp);

        let body = body.map(Value::to_string).unwrap_or_default();
        let request = Zeroizing::new(format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nGrpc-Metadata-macaroon: {macaroon}\r\n\
             Content-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n",
            macaroon = self.macaroon.as_str(),
            length = body.len(),
        ));
        stream
            .write_all(request.as_bytes())
            .and_then(|()| stream.write_all(body.as_bytes()))
            .and_then(|()| stream.flush())
            .map_err(|e| fail(format!("{}: {e}", self.address)))?;

        let mut raw = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        let mut clean_end = true;
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&chunk[..n]);
                    if raw.len() > MAX_RESPONSE {
                        return Err(fail("the answer is too long"));
                    }
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                // The peer closed without TLS's goodbye: fine if the framing says the answer is whole.
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                    clean_end = false;
                    break;
                }
                Err(e) => return Err(fail(format!("{}: {e}", self.address))),
            }
        }
        let (status, answer) = parse_http(&raw, clean_end).map_err(fail)?;
        let value: Value = serde_json::from_slice(&answer)
            .map_err(|_| fail(format!("{path}: the answer ({status}) is not JSON")))?;
        if status != 200 {
            let message: String = value
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("no message")
                .chars()
                .take(200)
                .collect();
            return Err(fail(format!("{path}: {status}: {message}")));
        }
        Ok(value)
    }

    /// The network the node is on, as LND names it (`regtest`, `signet`, `testnet`, `mainnet`, ...).
    pub fn network(&self) -> Result<String, LndError> {
        let info = self.call("GET", "/v1/getinfo", None)?;
        info.get("chains")
            .and_then(|chains| chains.get(0))
            .and_then(|chain| chain.get("network"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| fail("the node does not say which network it is on"))
    }

    /// The confirmed coins of the wallet's default account (the one LND can sign for at any time), each
    /// with the kind of close that paid it if one did.
    pub fn coins(&self) -> Result<Vec<LndCoin>, LndError> {
        let utxos = self.call(
            "POST",
            "/v2/wallet/utxos",
            Some(&json!({"min_confs": 1, "max_confs": i32::MAX, "account": "default"})),
        )?;
        let closed = self.call("GET", "/v1/channels/closed", None)?;
        parse_coins(&utxos, &parse_closes(&closed)?)
    }

    /// What the node must keep in its wallet to fee-bump the force close of its open anchor channels.
    /// LND enforces this on its own sends. A spend it only signs for, as a round is, has to enforce it
    /// here ([`keeps_reserve`]): without those funds a commitment transaction may never confirm, and the
    /// channel's HTLCs can be lost. An answer without the figure is an error, never a reserve of zero.
    pub fn anchor_reserve(&self) -> Result<u64, LndError> {
        let balance = self.call("GET", "/v1/balance/blockchain", None)?;
        int(balance.get("reserved_balance_anchor_chan"))
            .ok_or_else(|| fail("the node does not say what it must keep for its anchor channels"))
    }

    /// A fresh change address of the node's wallet, as a script: P2TR or P2WPKH, on `network`. A round's
    /// change goes back where the coin came from, so that it does not carry a channel's history into a
    /// mixdepth, and so that a small round does not move a whole coin out of the node.
    pub fn next_change_script(
        &self,
        network: Network,
        taproot: bool,
    ) -> Result<ScriptBuf, LndError> {
        let kind = if taproot {
            "TAPROOT_PUBKEY"
        } else {
            "WITNESS_PUBKEY_HASH"
        };
        let answer = self.call(
            "POST",
            "/v2/wallet/address/next",
            Some(&json!({"type": kind, "change": true})),
        )?;
        let script = answer
            .get("addr")
            .and_then(Value::as_str)
            .and_then(|text| Address::from_str(text).ok())
            .and_then(|address| address.require_network(network).ok())
            .map(|address| address.script_pubkey())
            .ok_or_else(|| fail("the node's change address is not one for this network"))?;
        if script.is_p2tr() != taproot || script.is_p2wpkh() == taproot {
            return Err(fail("the node's change address is of another type"));
        }
        Ok(script)
    }

    /// Whether the node will sign for `coins`, found out before any maker has seen them. It signs a
    /// throwaway transaction that states each coin's value one satoshi too high. Both BIP143 and BIP341
    /// commit to the amount, so these signatures can never be valid on chain, whoever gets them.
    pub fn check_can_sign(&self, coins: &[(OutPoint, TxOut)]) -> Result<(), LndError> {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: coins
                .iter()
                .map(|(outpoint, _)| TxIn {
                    previous_output: *outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_op_return([0u8; 4]),
            }],
        };
        let wrong: Vec<TxOut> = coins
            .iter()
            .map(|(_, out)| TxOut {
                value: out.value + Amount::from_sat(1),
                script_pubkey: out.script_pubkey.clone(),
            })
            .collect();
        let declared: Vec<OutPoint> = coins.iter().map(|(outpoint, _)| *outpoint).collect();
        let request = sign_request(&tx, &wrong, &declared).map_err(fail)?;
        let answer = self.call("POST", "/v2/signer/inputscript", Some(&request.json))?;
        let signed = answer
            .get("input_scripts")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        if signed != coins.len() {
            return Err(fail("the node will not sign for these coins"));
        }
        Ok(())
    }

    /// Keep `outpoints` from being spent by the node until the returned [`Lease`] is dropped (or, if this
    /// process dies, for twenty minutes).
    pub fn lease(&self, outpoints: &[OutPoint]) -> Result<Lease<'_>, LndError> {
        let mut id = [0u8; 32];
        for part in id.as_chunks_mut::<8>().0 {
            *part = random_u64().to_le_bytes();
        }
        let mut lease = Lease {
            lnd: self,
            id,
            outpoints: Vec::with_capacity(outpoints.len()),
        };
        for outpoint in outpoints {
            self.call(
                "POST",
                "/v2/wallet/utxos/lease",
                Some(&json!({
                    "id": STANDARD.encode(id),
                    "outpoint": outpoint_json(outpoint),
                    "expiration_seconds": LEASE_SECONDS.to_string(),
                })),
            )?;
            lease.outpoints.push(*outpoint);
        }
        Ok(lease)
    }
}

/// Coins the node holds back for a round. Dropping it gives them back, which is right only while nothing
/// has been broadcast: after that, [`Lease::hold_until_spent`] or [`Lease::hold_for_a_day`].
#[derive(Debug)]
pub struct Lease<'a> {
    lnd: &'a Lnd,
    id: [u8; 32],
    outpoints: Vec<OutPoint>,
}

impl Lease<'_> {
    fn renew(&mut self, terms: &Value) {
        for outpoint in std::mem::take(&mut self.outpoints) {
            let mut request = json!({
                "id": STANDARD.encode(self.id),
                "outpoint": outpoint_json(&outpoint),
            });
            if let (Some(request), Some(terms)) = (request.as_object_mut(), terms.as_object()) {
                request.extend(terms.clone());
            }
            // Best effort: the lease already held runs on until its time.
            let _ = self
                .lnd
                .call("POST", "/v2/wallet/utxos/lease", Some(&request));
        }
    }

    /// The round was broadcast: the node holds the coins until the spend is buried, so it cannot pick one
    /// while the transaction is unconfirmed, whatever its backend sees of the mempool.
    pub fn hold_until_spent(mut self) {
        self.renew(&json!({"release_after_spend_confs": HOLD_UNTIL_SPEND_CONFS}));
    }

    /// The broadcast failed without saying whether the transaction got out. A spend that never comes must
    /// not hold the coins for good, so this one has a time limit.
    pub fn hold_for_a_day(mut self) {
        self.renew(&json!({"expiration_seconds": UNKNOWN_BROADCAST_SECONDS.to_string()}));
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        for outpoint in &self.outpoints {
            // Best effort: a lease that is not released expires.
            let _ = self.lnd.call(
                "POST",
                "/v2/wallet/utxos/release",
                Some(&json!({
                    "id": STANDARD.encode(self.id),
                    "outpoint": outpoint_json(outpoint),
                })),
            );
        }
    }
}

impl InputSigner for Lnd {
    fn sign_own_inputs(
        &self,
        _mixdepth: u32,
        tx: &Transaction,
        prevouts: &[TxOut],
        declared: &[OutPoint],
    ) -> Result<Vec<(usize, String)>, String> {
        let body = sign_request(tx, prevouts, declared)?;
        let answer = self
            .call("POST", "/v2/signer/inputscript", Some(&body.json))
            .map_err(|e| e.to_string())?;
        let scripts = answer
            .get("input_scripts")
            .and_then(Value::as_array)
            .filter(|scripts| scripts.len() == body.indices.len())
            .ok_or("the node did not sign every input it was asked to")?;
        body.indices
            .iter()
            .zip(scripts)
            .map(|(&index, script)| {
                let witness = parse_input_script(script)?;
                Ok((
                    index,
                    payload_from_witness(&prevouts[index].script_pubkey, &witness)?,
                ))
            })
            .collect()
    }
}

/// `ComputeInputScript`'s request, and which input each of its descriptors is for.
struct SignRequest {
    json: Value,
    indices: Vec<usize>,
}

fn txout_json(out: &TxOut) -> Value {
    json!({
        "value": out.value.to_sat().to_string(),
        "pk_script": STANDARD.encode(out.script_pubkey.as_bytes()),
    })
}

/// LND takes either the bytes or the string of a txid, and refuses both.
fn outpoint_json(outpoint: &OutPoint) -> Value {
    json!({"txid_str": outpoint.txid.to_string(), "output_index": outpoint.vout})
}

/// The request that signs the inputs of `tx` spending `declared`, and nothing else: `SIGHASH_ALL` for
/// P2WPKH and `SIGHASH_DEFAULT` for a P2TR key path, so the signatures commit to the whole transaction.
fn sign_request(
    tx: &Transaction,
    prevouts: &[TxOut],
    declared: &[OutPoint],
) -> Result<SignRequest, String> {
    if prevouts.len() != tx.input.len() {
        return Err("one prevout per input".into());
    }
    let indices: Vec<usize> = tx
        .input
        .iter()
        .enumerate()
        .filter(|(_, input)| declared.contains(&input.previous_output))
        .map(|(index, _)| index)
        .collect();
    if indices.is_empty() || indices.len() != declared.len() {
        return Err("the coins to sign are not all inputs of the transaction".into());
    }
    let descriptors = indices
        .iter()
        .map(|&index| {
            let prevout = &prevouts[index];
            let sighash = if prevout.script_pubkey.is_p2wpkh() {
                SIGHASH_ALL
            } else if prevout.script_pubkey.is_p2tr() {
                SIGHASH_DEFAULT
            } else {
                return Err(format!("input {index} is neither P2WPKH nor P2TR"));
            };
            Ok(json!({
                "output": txout_json(prevout),
                "sighash": sighash,
                "input_index": index,
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut unsigned = tx.clone();
    for input in &mut unsigned.input {
        input.witness.clear();
    }
    Ok(SignRequest {
        json: json!({
            "raw_tx_bytes": STANDARD.encode(serialize(&unsigned)),
            "sign_descs": descriptors,
            "prev_outputs": prevouts.iter().map(txout_json).collect::<Vec<_>>(),
        }),
        indices,
    })
}

/// One `InputScript`: its witness stack. A nested (P2SH) script is not something a pit can spend.
fn parse_input_script(script: &Value) -> Result<Vec<Vec<u8>>, String> {
    if script
        .get("sig_script")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty())
    {
        return Err("the node answered with a scriptSig".into());
    }
    script
        .get("witness")
        .and_then(Value::as_array)
        .ok_or("the node's answer has no witness")?
        .iter()
        .map(|item| {
            item.as_str()
                .and_then(|text| STANDARD.decode(text).ok())
                .ok_or_else(|| "the node's witness is not base64".to_string())
        })
        .collect()
}

/// The `!sig` payload of a witness LND made for `script`.
fn payload_from_witness(script: &Script, witness: &[Vec<u8>]) -> Result<String, String> {
    if script.is_p2wpkh() {
        let [signature, key] = witness else {
            return Err("a P2WPKH witness has two items".into());
        };
        let signature = ecdsa::Signature::from_slice(signature).map_err(|e| e.to_string())?;
        let key = PublicKey::from_slice(key).map_err(|e| e.to_string())?;
        Ok(encode_sw0(&signature, &key))
    } else if script.is_p2tr() {
        let [signature] = witness else {
            return Err("a P2TR key-path witness has one item".into());
        };
        // 64 bytes is SIGHASH_DEFAULT; a 65th would be another sighash, which was not asked for.
        if signature.len() != 64 {
            return Err("not a SIGHASH_DEFAULT signature".into());
        }
        let signature = schnorr::Signature::from_slice(signature).map_err(|e| e.to_string())?;
        let program = script.as_bytes().get(2..34).ok_or("not P2TR")?;
        let key = XOnlyPublicKey::from_slice(program).map_err(|e| e.to_string())?;
        Ok(encode_tr0(&signature, &key))
    } else {
        Err("neither P2WPKH nor P2TR".into())
    }
}

/// Whether the coins left after spending `spending` still cover `reserve`. Only confirmed coins of the
/// default account count ([`Lnd::coins`]), which is stricter than LND's own check: a round's change goes to
/// the vortex-ng wallet and gives the node nothing back.
pub fn keeps_reserve(coins: &[LndCoin], spending: &[OutPoint], reserve: u64) -> bool {
    let left: u64 = coins
        .iter()
        .filter(|coin| !spending.contains(&coin.outpoint))
        .map(|coin| coin.txout.value.to_sat())
        .sum();
    left >= reserve
}

/// Whether a resolution's sweep is this node's own claim. Others are recorded too: a timed-out incoming HTLC
/// is the peer's sweep, a claimed outgoing one the peer's, an anchor may be a third party's, and an anchor
/// we did sweep was paid for with an unrelated wallet coin, so its change is not a channel's money.
fn swept_by_us(resolution: &Value) -> bool {
    let field = |name| resolution.get(name).and_then(Value::as_str);
    matches!(
        (field("resolution_type"), field("outcome")),
        (Some("COMMIT" | "INCOMING_HTLC"), Some("CLAIMED"))
            | (Some("OUTGOING_HTLC"), Some("TIMEOUT"))
    )
}

/// A protobuf integer in JSON: a number, or for 64-bit fields a string.
fn int(value: Option<&Value>) -> Option<u64> {
    let value = value?;
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}

/// Which transactions closed a channel or swept what a close left, from `ClosedChannels`. Funding that was
/// cancelled or a channel abandoned paid nobody and counts as neither.
fn parse_closes(closed: &Value) -> Result<HashMap<Txid, CloseKind>, LndError> {
    let mut closes = HashMap::new();
    let channels = closed.get("channels").and_then(Value::as_array);
    for channel in channels.into_iter().flatten() {
        let kind = match channel.get("close_type").and_then(Value::as_str) {
            // proto3 JSON may leave out the zero value of an enum.
            None | Some("COOPERATIVE_CLOSE") => CloseKind::Cooperative,
            Some("LOCAL_FORCE_CLOSE" | "REMOTE_FORCE_CLOSE" | "BREACH_CLOSE") => {
                CloseKind::Unilateral
            }
            Some(_) => continue,
        };
        let txid = |value: Option<&Value>| {
            value
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .map(Txid::from_str)
                .transpose()
                .map_err(|_| fail("a txid in the close records is malformed"))
        };
        if let Some(closing) = txid(channel.get("closing_tx_hash"))? {
            closes.insert(closing, kind);
        }
        let resolutions = channel.get("resolutions").and_then(Value::as_array);
        for resolution in resolutions.into_iter().flatten().filter(|r| swept_by_us(r)) {
            if let Some(sweep) = txid(resolution.get("sweep_txid"))? {
                closes.entry(sweep).or_insert(CloseKind::Sweep);
            }
        }
    }
    Ok(closes)
}

/// The coins of a `ListUnspent` answer, marked from `closes`.
fn parse_coins(utxos: &Value, closes: &HashMap<Txid, CloseKind>) -> Result<Vec<LndCoin>, LndError> {
    let malformed = || fail("a coin in the node's answer is malformed");
    let list = utxos.get("utxos").and_then(Value::as_array);
    list.into_iter()
        .flatten()
        .map(|utxo| {
            let point = utxo.get("outpoint").ok_or_else(malformed)?;
            let txid = point
                .get("txid_str")
                .and_then(Value::as_str)
                .and_then(|text| Txid::from_str(text).ok())
                .ok_or_else(malformed)?;
            // proto3 JSON may leave out a zero.
            let vout = match point.get("output_index") {
                None => 0,
                some => u32::try_from(int(some).ok_or_else(malformed)?).map_err(|_| malformed())?,
            };
            let sats = int(utxo.get("amount_sat")).ok_or_else(malformed)?;
            if sats > Amount::MAX_MONEY.to_sat() {
                return Err(malformed());
            }
            let script_pubkey = utxo
                .get("pk_script")
                .and_then(Value::as_str)
                .and_then(|text| ScriptBuf::from_hex(text).ok())
                .ok_or_else(malformed)?;
            let confirmations = int(utxo.get("confirmations"))
                .and_then(|depth| u32::try_from(depth).ok())
                .ok_or_else(malformed)?;
            Ok(LndCoin {
                outpoint: OutPoint { txid, vout },
                txout: TxOut {
                    value: Amount::from_sat(sats),
                    script_pubkey,
                },
                confirmations,
                close: closes.get(&txid).copied(),
            })
        })
        .collect()
}

/// `(status, body)` of an HTTP/1.1 response read to the end of the connection. `clean_end` says the
/// connection ended properly: without it, only a body whose framing proves it complete is accepted.
fn parse_http(raw: &[u8], clean_end: bool) -> Result<(u16, Vec<u8>), String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no complete HTTP header in the answer")?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| "the HTTP header is not text")?;
    let rest = &raw[split + 4..];
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| {
            let mut parts = line.split(' ');
            let version = parts.next()?;
            version.starts_with("HTTP/1.").then(|| parts.next())?
        })
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or("not an HTTP status line")?;
    let (mut length, mut chunked) = (None, false);
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| "a malformed Content-Length")?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if !value.eq_ignore_ascii_case("chunked") {
                return Err(format!("unsupported Transfer-Encoding {value}"));
            }
            chunked = true;
        }
    }
    if chunked {
        return Ok((status, dechunk(rest)?));
    }
    match length {
        Some(length) => rest
            .get(..length)
            .map(|body| (status, body.to_vec()))
            .ok_or_else(|| "the answer was cut short".to_string()),
        None if clean_end => Ok((status, rest.to_vec())),
        None => Err("the answer was cut short".into()),
    }
}

/// A chunked body, whole: it must end in the zero-length chunk.
fn dechunk(mut rest: &[u8]) -> Result<Vec<u8>, String> {
    let short = || "the answer was cut short".to_string();
    let mut body = Vec::new();
    loop {
        let end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(short)?;
        let line = std::str::from_utf8(&rest[..end]).map_err(|_| "a malformed chunk size")?;
        let size = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size, 16).map_err(|_| "a malformed chunk size")?;
        rest = &rest[end + 2..];
        if size == 0 {
            return Ok(body);
        }
        let total = size.checked_add(2).ok_or("a malformed chunk size")?;
        let chunk = rest.get(..total).ok_or_else(short)?;
        if &chunk[size..] != b"\r\n" {
            return Err("a malformed chunk".into());
        }
        body.extend_from_slice(&chunk[..size]);
        rest = &rest[total..];
    }
}

#[cfg(test)]
mod tests {
    use vortex_ng_core::bitcoin::CompressedPublicKey;
    use vortex_ng_core::bitcoin::hashes::Hash;
    use vortex_ng_core::bitcoin::key::TapTweak;
    use vortex_ng_core::bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use vortex_ng_core::bitcoin::sighash::{
        EcdsaSighashType, Prevouts, SighashCache, TapSighashType,
    };
    use vortex_ng_core::offer::Pit;
    use vortex_ng_core::sig::verify_sig;

    use super::*;

    const TX1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const TX2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const TX3: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const TX4: &str = "4444444444444444444444444444444444444444444444444444444444444444";
    const TX5: &str = "5555555555555555555555555555555555555555555555555555555555555555";
    const TX6: &str = "6666666666666666666666666666666666666666666666666666666666666666";
    const TX7: &str = "7777777777777777777777777777777777777777777777777777777777777777";
    const TX8: &str = "8888888888888888888888888888888888888888888888888888888888888888";

    fn txid(text: &str) -> Txid {
        Txid::from_str(text).unwrap()
    }

    #[test]
    fn close_records_name_the_closing_transaction_and_the_sweeps() {
        let closes = parse_closes(&json!({"channels": [
            {"close_type": "COOPERATIVE_CLOSE", "closing_tx_hash": TX1, "resolutions": []},
            {"close_type": "LOCAL_FORCE_CLOSE", "closing_tx_hash": TX2, "resolutions": [
                {"resolution_type": "COMMIT", "outcome": "CLAIMED", "sweep_txid": TX3},
                {"resolution_type": "ANCHOR", "outcome": "CLAIMED", "sweep_txid": TX5},
                {"resolution_type": "INCOMING_HTLC", "outcome": "TIMEOUT", "sweep_txid": TX6},
                {"resolution_type": "OUTGOING_HTLC", "outcome": "CLAIMED", "sweep_txid": TX7},
                {"resolution_type": "OUTGOING_HTLC", "outcome": "TIMEOUT", "sweep_txid": TX8},
                {"resolution_type": "COMMIT", "outcome": "CLAIMED", "sweep_txid": ""},
            ]},
            {"close_type": "FUNDING_CANCELED", "closing_tx_hash": TX4},
        ]}))
        .unwrap();
        assert_eq!(closes.get(&txid(TX1)), Some(&CloseKind::Cooperative));
        assert_eq!(closes.get(&txid(TX2)), Some(&CloseKind::Unilateral));
        assert_eq!(closes.get(&txid(TX3)), Some(&CloseKind::Sweep));
        assert_eq!(closes.get(&txid(TX8)), Some(&CloseKind::Sweep));
        // The peer's sweeps, an anchor's, and a channel that never paid anyone.
        for other in [TX4, TX5, TX6, TX7] {
            assert_eq!(closes.get(&txid(other)), None, "{other}");
        }
        assert_eq!(closes.len(), 4);
        // A close without a close_type field is proto3's zero value, cooperative.
        let zero = parse_closes(&json!({"channels": [{"closing_tx_hash": TX1}]})).unwrap();
        assert_eq!(zero.get(&txid(TX1)), Some(&CloseKind::Cooperative));
        assert!(parse_closes(&json!({})).unwrap().is_empty());
        assert!(parse_closes(&json!({"channels": [{"closing_tx_hash": "zz"}]})).is_err());
    }

    #[test]
    fn coins_are_marked_from_the_close_records() {
        let closes = HashMap::from([(txid(TX1), CloseKind::Cooperative)]);
        let script = "0014".to_string() + &"ab".repeat(20);
        let coins = parse_coins(
            &json!({"utxos": [
                {"amount_sat": "150000", "pk_script": script, "confirmations": "7",
                 "address": "not kept", "outpoint": {"txid_str": TX1, "output_index": 1}},
                {"amount_sat": 9000, "pk_script": script, "confirmations": 2,
                 "outpoint": {"txid_str": TX2}},
            ]}),
            &closes,
        )
        .unwrap();
        assert_eq!(coins[0].close, Some(CloseKind::Cooperative));
        assert_eq!(coins[0].outpoint.vout, 1);
        assert_eq!(coins[0].txout.value.to_sat(), 150_000);
        assert_eq!(coins[0].confirmations, 7);
        assert_eq!(coins[1].close, None);
        assert_eq!(coins[1].outpoint.vout, 0, "proto3 leaves out a zero");
        for bad in [
            json!({"amount_sat": "1", "pk_script": script, "confirmations": 1}),
            json!({"amount_sat": "x", "pk_script": script, "confirmations": 1,
                   "outpoint": {"txid_str": TX1}}),
            json!({"amount_sat": "2100000000000001", "pk_script": script, "confirmations": 1,
                   "outpoint": {"txid_str": TX1}}),
            json!({"amount_sat": "1", "pk_script": "zz", "confirmations": 1,
                   "outpoint": {"txid_str": TX1}}),
        ] {
            assert!(parse_coins(&json!({"utxos": [bad]}), &closes).is_err());
        }
    }

    #[test]
    fn a_round_must_leave_the_anchor_reserve() {
        let coin = |text: &str, sats: u64| LndCoin {
            outpoint: OutPoint {
                txid: txid(text),
                vout: 0,
            },
            txout: TxOut {
                value: Amount::from_sat(sats),
                script_pubkey: ScriptBuf::new(),
            },
            confirmations: 6,
            close: None,
        };
        let coins = [coin(TX1, 500_000), coin(TX2, 10_000), coin(TX3, 9_999)];
        let spend = |texts: &[&str]| -> Vec<OutPoint> {
            texts
                .iter()
                .map(|text| OutPoint {
                    txid: txid(text),
                    vout: 0,
                })
                .collect()
        };
        // What is left is exactly the reserve, one sat short of it, or nothing.
        assert!(keeps_reserve(&coins, &spend(&[TX1, TX3]), 10_000));
        assert!(!keeps_reserve(&coins, &spend(&[TX1, TX2]), 10_000));
        assert!(!keeps_reserve(&coins, &spend(&[TX1, TX2, TX3]), 10_000));
        // No anchor channel open: nothing to keep.
        assert!(keeps_reserve(&coins, &spend(&[TX1, TX2, TX3]), 0));
    }

    #[test]
    fn http_framing() {
        let ok = |raw: &[u8], clean| parse_http(raw, clean).unwrap();
        assert_eq!(
            ok(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", false),
            (200, b"{}".to_vec())
        );
        assert_eq!(
            ok(
                b"HTTP/1.1 500 Oops\r\ntransfer-encoding: chunked\r\n\r\n2;x=1\r\n{\"\r\n1\r\n}\r\n0\r\n\r\n",
                false
            ),
            (500, b"{\"}".to_vec())
        );
        assert_eq!(
            ok(b"HTTP/1.1 200 OK\r\n\r\n{}", true),
            (200, b"{}".to_vec())
        );
        for (raw, clean) in [
            // Cut short: by the length, in a chunk, before the last chunk, with no framing.
            (&b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n{}"[..], true),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\n{}",
                true,
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n",
                true,
            ),
            (b"HTTP/1.1 200 OK\r\n\r\n{}", false),
            // Malformed.
            (b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n", true),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", true),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nx",
                true,
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}xx0\r\n\r\n",
                true,
            ),
            (b"SMTP ready\r\n\r\n", true),
            (b"HTTP/1.1 200 OK\r\n", true),
        ] {
            assert!(
                parse_http(raw, clean).is_err(),
                "{}",
                String::from_utf8_lossy(raw)
            );
        }
    }

    fn spending(n: usize) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: (0..n)
                .map(|i| TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([i as u8 + 1; 32]),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::new_p2wpkh(
                    &CompressedPublicKey(
                        SecretKey::from_slice(&[9; 32])
                            .unwrap()
                            .public_key(&Secp256k1::new()),
                    )
                    .wpubkey_hash(),
                ),
            }],
        }
    }

    fn p2wpkh(key: &SecretKey, sats: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: ScriptBuf::new_p2wpkh(
                &CompressedPublicKey(key.public_key(&Secp256k1::new())).wpubkey_hash(),
            ),
        }
    }

    #[test]
    fn only_the_declared_inputs_are_asked_for_with_the_right_sighash() {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[3; 32]).unwrap();
        let (xonly, _) = key.public_key(&secp).x_only_public_key();
        let taproot = TxOut {
            value: Amount::from_sat(70_000),
            script_pubkey: ScriptBuf::new_p2tr(&secp, xonly, None),
        };
        let tx = spending(3);
        let prevouts = [p2wpkh(&key, 50_000), p2wpkh(&key, 60_000), taproot];
        let declared = [tx.input[2].previous_output, tx.input[1].previous_output];
        let request = sign_request(&tx, &prevouts, &declared).unwrap();
        assert_eq!(request.indices, vec![1, 2]);
        let descriptors = request.json["sign_descs"].as_array().unwrap();
        assert_eq!(descriptors.len(), 2);
        assert_eq!(descriptors[0]["input_index"], 1);
        assert_eq!(descriptors[0]["sighash"], SIGHASH_ALL);
        assert_eq!(descriptors[1]["input_index"], 2);
        assert_eq!(descriptors[1]["sighash"], SIGHASH_DEFAULT);
        // Taproot's sighash commits to every prevout: all of them go along.
        assert_eq!(request.json["prev_outputs"].as_array().unwrap().len(), 3);

        // A coin that is not an input, none at all, or a script a pit cannot spend.
        let stranger = OutPoint {
            txid: Txid::from_byte_array([9; 32]),
            vout: 0,
        };
        assert!(sign_request(&tx, &prevouts, &[declared[0], stranger]).is_err());
        assert!(sign_request(&tx, &prevouts, &[]).is_err());
        assert!(sign_request(&tx, &prevouts[..2], &declared).is_err());
        let mut odd = prevouts.clone();
        odd[1].script_pubkey = ScriptBuf::new_op_return([1u8; 4]);
        assert!(sign_request(&tx, &odd, &declared).is_err());
    }

    #[test]
    fn a_p2wpkh_witness_becomes_a_payload_the_taker_accepts() {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[4; 32]).unwrap();
        let tx = spending(1);
        let prevouts = [p2wpkh(&key, 100_000)];
        let hash = SighashCache::new(&tx)
            .p2wpkh_signature_hash(
                0,
                &prevouts[0].script_pubkey,
                prevouts[0].value,
                EcdsaSighashType::All,
            )
            .unwrap();
        let signature = ecdsa::Signature {
            signature: secp.sign_ecdsa(&Message::from_digest(hash.to_byte_array()), &key),
            sighash_type: EcdsaSighashType::All,
        };
        let witness = vec![
            signature.serialize().to_vec(),
            key.public_key(&secp).serialize().to_vec(),
        ];
        let payload = payload_from_witness(&prevouts[0].script_pubkey, &witness).unwrap();
        verify_sig(&secp, Pit::Sw0, &payload, &tx, 0, &prevouts).unwrap();
        assert!(payload_from_witness(&prevouts[0].script_pubkey, &witness[..1]).is_err());
    }

    #[test]
    fn a_p2tr_witness_becomes_a_payload_the_taker_accepts() {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[5; 32]).unwrap());
        let (internal, _) = keypair.x_only_public_key();
        let tx = spending(1);
        let prevouts = [TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new_p2tr(&secp, internal, None),
        }];
        let hash = SighashCache::new(&tx)
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        let tweaked = keypair.tap_tweak(&secp, None).to_keypair();
        let signature =
            secp.sign_schnorr_no_aux_rand(&Message::from_digest(hash.to_byte_array()), &tweaked);
        let bytes = signature.as_ref().to_vec();
        let payload =
            payload_from_witness(&prevouts[0].script_pubkey, std::slice::from_ref(&bytes)).unwrap();
        verify_sig(&secp, Pit::Tr0, &payload, &tx, 0, &prevouts).unwrap();
        // A signature with a sighash byte was not asked for.
        let mut other = bytes;
        other.push(0x83);
        assert!(payload_from_witness(&prevouts[0].script_pubkey, &[other]).is_err());
    }

    #[test]
    fn a_nested_or_garbled_answer_is_refused() {
        assert!(parse_input_script(&json!({"witness": [], "sig_script": "AAAA"})).is_err());
        assert!(parse_input_script(&json!({"witness": ["***"]})).is_err());
        assert!(parse_input_script(&json!({})).is_err());
        assert_eq!(
            parse_input_script(&json!({"witness": ["AQI="], "sig_script": ""})).unwrap(),
            vec![vec![1u8, 2]]
        );
    }

    #[test]
    fn a_macaroon_others_can_read_is_refused() {
        let dir = std::env::temp_dir().join(format!(
            "vortex-ng-lnd-{}-{:016x}",
            std::process::id(),
            random_u64()
        ));
        std::fs::create_dir(&dir).unwrap();
        let macaroon = dir.join("m");
        std::fs::write(&macaroon, [1u8, 2, 3]).unwrap();
        let cert = dir.join("c");
        std::fs::write(&cert, b"no certificate here").unwrap();
        for (mode, why) in [
            (0o644, "other users"),
            (0o640, "other users"),
            (0o600, "no certificate"),
        ] {
            std::fs::set_permissions(&macaroon, std::fs::Permissions::from_mode(mode)).unwrap();
            let error = Lnd::open("127.0.0.1:1", &cert, &macaroon).unwrap_err();
            assert!(error.0.contains(why), "{mode:o}: {error}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
