//! A directory node in memory, for tests: this crate's, and (feature `test-util`) other crates'. Nothing
//! here is needed to run vortex-ng.
//!
//! It behaves as JoinMarket-NG's directory server does where a client can tell: it answers the handshake
//! (refusing another network and a nick already connected), offers ping and, when given an identity, nick
//! authentication (JMP-0005); it forwards a public line to every other peer and a private line to its
//! recipient, and only from the nick that connected. It records what it received, and a test can make it
//! send any line to a peer.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use vortex_ng_core::bitcoin::hashes::{Hash, sha256};
use vortex_ng_core::bitcoin::hex::{DisplayHex, FromHex};
use vortex_ng_core::bitcoin::secp256k1::{PublicKey, Secp256k1};
use vortex_ng_core::nick::nick_from_pubkey;
use vortex_ng_core::sigmsg;
use vortex_ng_core::tx::random_bytes;

use crate::wire::{
    DN_HANDSHAKE, HANDSHAKE, NICK_AUTH_CHALLENGE, NICK_AUTH_PROOF, NICK_AUTH_RESULT, PING, PONG,
    PRIVMSG, PUBMSG, encode,
};
use crate::{Directory, NICK_AUTH_DOMAIN, read_line};

#[derive(Default)]
struct State {
    peers: HashMap<String, mpsc::UnboundedSender<String>>,
    verified: Vec<String>,
    pongs: usize,
    received: Vec<(String, u64, String)>,
}

/// A directory node on `127.0.0.1:<ephemeral>`.
pub struct TestDirectory {
    addr: SocketAddr,
    id: Option<String>,
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestDirectory {
    /// A directory for `network`. With `id`, it offers nick authentication under that identity.
    pub async fn start(network: &str, id: Option<&str>) -> TestDirectory {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("address: {e}"));
        let state = Arc::new(Mutex::new(State::default()));
        let (network, id_owned) = (network.to_string(), id.map(str::to_string));
        let task_state = Arc::clone(&state);
        let task = tokio::spawn(async move {
            while let Ok((conn, _)) = listener.accept().await {
                let (state, network, id) =
                    (Arc::clone(&task_state), network.clone(), id_owned.clone());
                tokio::spawn(async move {
                    let _ = serve(conn, state, network, id).await;
                });
            }
        });
        TestDirectory {
            addr,
            id: id.map(str::to_string),
            state,
            task,
        }
    }

    /// How to reach it.
    pub fn directory(&self) -> Directory {
        Directory {
            host: self.addr.ip().to_string(),
            port: self.addr.port(),
            id: self.id.clone(),
        }
    }

    /// The nicks connected now.
    pub fn nicks(&self) -> Vec<String> {
        self.state
            .lock()
            .map(|s| s.peers.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// The nicks that proved their key (JMP-0005).
    pub fn verified(&self) -> Vec<String> {
        self.state
            .lock()
            .map(|s| s.verified.clone())
            .unwrap_or_default()
    }

    /// Pongs received.
    pub fn pongs(&self) -> usize {
        self.state.lock().map(|s| s.pongs).unwrap_or_default()
    }

    /// Every line received after the handshakes: the connection's nick, the type, the line.
    pub fn received(&self) -> Vec<(String, u64, String)> {
        self.state
            .lock()
            .map(|s| s.received.clone())
            .unwrap_or_default()
    }

    /// Send `line` of type `kind` to the peer connected as `nick`, as if the directory relayed it.
    pub fn send(&self, nick: &str, kind: u64, line: &str) -> bool {
        let Ok(encoded) = encode(kind, line) else {
            return false;
        };
        self.state
            .lock()
            .ok()
            .and_then(|s| s.peers.get(nick).map(|tx| tx.send(encoded).is_ok()))
            .unwrap_or(false)
    }

    /// Ping every connected peer.
    pub fn ping_all(&self) {
        for nick in self.nicks() {
            self.send(&nick, PING, "");
        }
    }
}

async fn serve(
    conn: TcpStream,
    state: Arc<Mutex<State>>,
    network: String,
    id: Option<String>,
) -> Result<(), String> {
    let (read, mut write) = conn.into_split();
    let mut reader = BufReader::new(read);
    let (kind, handshake) = tokio::time::timeout(Duration::from_secs(10), read_line(&mut reader))
        .await
        .map_err(|_| "no handshake")??;
    if kind != HANDSHAKE {
        return Err("expected a handshake".into());
    }
    let hello: Value = serde_json::from_str(&handshake).map_err(|_| "handshake JSON")?;
    let nick = hello["nick"].as_str().unwrap_or_default().to_string();
    let wants_auth = hello["features"]["nick_auth"] == Value::Bool(true);
    let taken = state
        .lock()
        .map(|s| s.peers.contains_key(&nick))
        .unwrap_or(true);
    let accepted =
        hello["network"].as_str() == Some(network.as_str()) && !nick.is_empty() && !taken;
    let mut features = serde_json::Map::new();
    features.insert("ping".into(), Value::Bool(true));
    if id.is_some() {
        features.insert("nick_auth".into(), Value::Bool(true));
    }
    let answer = json!({
        "app-name": "joinmarket", "directory": true, "proto-ver-min": 5, "proto-ver-max": 5,
        "features": features, "accepted": accepted, "nick": "J5testdirectoryOO",
        "network": network, "motd": "test directory",
    });
    let line = encode(DN_HANDSHAKE, &answer.to_string()).map_err(|e| e.to_string())?;
    write
        .write_all(line.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    if !accepted {
        return Ok(());
    }
    if let (Some(id), true) = (&id, wants_auth) {
        let challenge = random_bytes::<32>()[..].to_lower_hex_string();
        let line = encode(
            NICK_AUTH_CHALLENGE,
            &json!({ "challenge": challenge, "directory-id": id }).to_string(),
        )
        .map_err(|e| e.to_string())?;
        write
            .write_all(line.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let (kind, proof) = read_line(&mut reader).await?;
        let proof: Value = serde_json::from_str(&proof).map_err(|_| "proof JSON")?;
        let pubkey = proof["pubkey"].as_str().unwrap_or_default().to_string();
        let key = Vec::<u8>::from_hex(&pubkey)
            .ok()
            .and_then(|k| PublicKey::from_slice(&k).ok());
        let transcript = format!(
            "nick-auth|{challenge}|{id}|{}|{nick}|{pubkey}",
            sha256::Hash::hash(handshake.as_bytes())
                .to_byte_array()
                .to_lower_hex_string()
        );
        let mut message = transcript.into_bytes();
        message.extend_from_slice(NICK_AUTH_DOMAIN);
        let ok = kind == NICK_AUTH_PROOF
            && key.is_some_and(|key| {
                nick_from_pubkey(&key) == nick
                    && sigmsg::verify(
                        &Secp256k1::verification_only(),
                        &message,
                        proof["signature"].as_str().unwrap_or_default(),
                        &key,
                    )
            });
        let (code, verified) = if ok { ("ok", true) } else { ("invalid", false) };
        let line = encode(
            NICK_AUTH_RESULT,
            &json!({ "code": code, "verified": verified }).to_string(),
        )
        .map_err(|e| e.to_string())?;
        write
            .write_all(line.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        if !ok {
            return Ok(());
        }
        if let Ok(mut s) = state.lock() {
            s.verified.push(nick.clone());
        }
    }
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    if let Ok(mut s) = state.lock() {
        s.peers.insert(nick.clone(), tx);
    }
    let writer = tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if write.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    });
    while let Ok((kind, line)) = read_line(&mut reader).await {
        let Ok(mut s) = state.lock() else { break };
        s.received.push((nick.clone(), kind, line.clone()));
        let Ok(encoded) = encode(kind, &line) else {
            continue;
        };
        match kind {
            // Only from the nick that connected, as JoinMarket-NG's directory requires.
            PUBMSG if line.starts_with(&format!("{nick}!PUBLIC")) => {
                for (other, peer) in &s.peers {
                    if *other != nick {
                        let _ = peer.send(encoded.clone());
                    }
                }
            }
            PRIVMSG => {
                let mut parts = line.splitn(3, '!');
                if let (Some(from), Some(to)) = (parts.next(), parts.next())
                    && from == nick
                    && let Some(peer) = s.peers.get(to)
                {
                    let _ = peer.send(encoded);
                }
            }
            PONG => s.pongs += 1,
            _ => {}
        }
    }
    if let Ok(mut s) = state.lock() {
        s.peers.remove(&nick);
    }
    writer.abort();
    Ok(())
}
