//! JoinMarket's onion message channel: directory nodes, as joinmarket-clientserver (`jmdaemon/onionmc.py`)
//! and JoinMarket-NG (`jmcore/directory_client.py`) speak it (ADR 0007).
//!
//! An [`OnionChannel`] is one nick connected to every configured directory node at once. It serves no onion
//! of its own (`NOT-SERVING-ONION`), so a private line is relayed by a directory unless a direct connection
//! carries it: the directory sees who talks to whom, when, and how much, and the plain-text steps of a round
//! (`!fill`, `!pubkey`); the encrypted steps stay encrypted. Private lines are JMP-0001 lines signed with
//! `hostid` `onion-network`; public lines are unsigned.
//!
//! Direct connections (a taker's, issue #45): directories tell where peers that serve an onion are (peer
//! lists, which joinmarket-clientserver's directories send when they relay a line and JoinMarket-NG's on
//! request). When a taker has chosen its makers ([`Channel::prepare`]), the channel connects to each one that
//! serves an onion, on a way out of its own (its own Tor circuit), says its handshake, and from then on sends
//! that maker's private lines there and reads the maker's answers there; the directory no longer sees them. A
//! connection that fails or drops leaves the lines to the directories. Nothing is ever accepted inbound.
//!
//! Each directory has a task that connects (through the nick's own [`NickConnector`], so a Tor daemon gives
//! this nick circuits of its own), does the handshake (and JoinMarket-NG's nick authentication, JMP-0005,
//! when the directory's identity is known and it offers it), answers pings, forwards what arrives, and
//! reconnects with back-off when the connection drops. A line delivered by several directories is seen once.

pub mod wire;

#[cfg(any(test, feature = "test-util"))]
pub mod testing;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use vortex_ng_channel::socks::{BoxedStream, NickConnector, Outbound};
use vortex_ng_channel::{Channel, ChannelError, Incoming, Next};
use vortex_ng_core::bitcoin::hashes::{Hash, sha256};
use vortex_ng_core::bitcoin::hex::DisplayHex;
use vortex_ng_core::bitcoin::secp256k1::Secp256k1;
use vortex_ng_core::command::{Command, parse_plaintext};
use vortex_ng_core::line::{sign_line, verify_line};
use vortex_ng_core::nick::NickIdentity;
use vortex_ng_core::offer::{Offer, Pit};
use vortex_ng_core::protocol::ONION_HOSTID;
use vortex_ng_core::sigmsg;

use crate::wire::{
    DN_HANDSHAKE, GETPEERLIST, HANDSHAKE, NICK_AUTH_CHALLENGE, NICK_AUTH_PROOF, NICK_AUTH_RESULT,
    PEERLIST, PING, PONG, PRIVMSG, PUBMSG, encode, parse_peerlist, public_line,
    read_directory_hello, read_peer_hello, read_public_line,
};

/// The port directory nodes listen on.
pub const DIRECTORY_PORT: u16 = 5222;
/// How long a line is remembered to recognise its copies from other directories.
const DEDUP_WINDOW: Duration = Duration::from_secs(60);
/// Most lines remembered for that.
const DEDUP_CAP: usize = 50_000;
/// Lines from all directories waiting to be read.
const INBOX: usize = 1_024;
/// Lines waiting to be written to one directory.
const OUTBOX: usize = 256;
/// The longest wait between reconnection attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(600);
/// How long a nick-authentication step may take (JoinMarket-NG's limit).
const NICK_AUTH_TIMEOUT: Duration = Duration::from_secs(30);
/// The domain JoinMarket-NG's nick-authentication proof ends with (JMP-0005).
const NICK_AUTH_DOMAIN: &[u8] = b"nick-auth-v1";
/// Most peer locations remembered.
const MAX_LOCATIONS: usize = 10_000;
/// How long a peer location is trusted after a directory named it.
const LOCATION_TTL: Duration = Duration::from_secs(3_600);
/// Most direct connections open at once.
const MAX_LINKS: usize = 32;
/// How long a peer may take to answer our handshake on a direct connection (it need not answer at all).
const PEER_HELLO_WAIT: Duration = Duration::from_secs(2);
/// How long `prepare` waits for directories to name unknown peers' locations.
const LOCATION_WAIT: Duration = Duration::from_secs(3);
/// The longest `prepare` takes, at most `config.timeout`.
const PREPARE_LIMIT: Duration = Duration::from_secs(30);

fn transport(e: impl std::fmt::Display) -> ChannelError {
    ChannelError::Transport(format!("onion directory: {e}"))
}

/// A directory node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Directory {
    /// Its host: a `.onion` name, or an address on a test network.
    pub host: String,
    /// Its port.
    pub port: u16,
    /// The identity its nick-authentication challenges name (JMP-0005): derived for a v3 onion, set by hand
    /// for anything else; none means no nick authentication.
    pub id: Option<String>,
}

impl Directory {
    /// From `host:port` (the port defaults to [`DIRECTORY_PORT`]).
    pub fn parse(text: &str) -> Option<Directory> {
        let text = text.trim();
        let (host, port) = match text.rsplit_once(':') {
            Some((host, port)) => (host, port.parse().ok()?),
            None => (text, DIRECTORY_PORT),
        };
        let valid = !host.is_empty()
            && host.len() <= 255
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
        valid.then(|| Directory {
            host: host.to_string(),
            port,
            id: wire::directory_id(host, port),
        })
    }
}

/// Whether, and where, a taker connects to makers directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerPolicy {
    /// Never: every private line goes through the directories.
    Relay,
    /// To makers that serve a v3 onion, through the way out (a Tor daemon's SOCKS port).
    Onion,
    /// Also to loopback addresses: regtest setups that run without Tor (joinmarket-clientserver's testing
    /// mode). Never outside regtest.
    Local,
}

/// What an [`OnionChannel`] connects to.
#[derive(Clone, Debug)]
pub struct OnionConfig {
    /// The directory nodes, at least one.
    pub directories: Vec<Directory>,
    /// The network name in handshakes (`mainnet`, `testnet`, `signet`, `regtest`); a directory refuses
    /// another network's peers.
    pub network: String,
    /// How long a connection and its handshake may take.
    pub timeout: Duration,
    /// Direct connections to makers.
    pub peers: PeerPolicy,
}

/// Where a line came from.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Via {
    Directory(usize),
    Peer(String),
}

/// The directory or direct connection a line came through; an answer goes back the most direct way open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnionRoute {
    via: Via,
}

/// Lines recently seen, to drop the copies other directories deliver.
#[derive(Default)]
struct Seen(HashMap<[u8; 32], Instant>);

impl Seen {
    /// Whether this line is new (and remember it).
    fn fresh(&mut self, kind: u64, line: &str) -> bool {
        let mut data = kind.to_be_bytes().to_vec();
        data.extend_from_slice(line.as_bytes());
        let key = sha256::Hash::hash(&data).to_byte_array();
        let now = Instant::now();
        if let Some(at) = self.0.get(&key)
            && now.duration_since(*at) < DEDUP_WINDOW
        {
            return false;
        }
        if self.0.len() >= DEDUP_CAP {
            self.0
                .retain(|_, at| now.duration_since(*at) < DEDUP_WINDOW);
            if self.0.len() >= DEDUP_CAP {
                // Under a flood, letting a copy through is better than refusing new lines.
                self.0.clear();
            }
        }
        self.0.insert(key, now);
        true
    }
}

/// What the tasks share.
struct Shared {
    identity: NickIdentity,
    config: OnionConfig,
    connector: NickConnector,
    /// Per directory, the writer while connected.
    writers: Vec<Mutex<Option<mpsc::Sender<String>>>>,
    inbox: mpsc::Sender<(Via, u64, String)>,
    stop: AtomicBool,
    /// Where peers serve, as directories named them: nick -> (host, port, when).
    locations: Mutex<HashMap<String, (String, u16, Instant)>>,
    /// Open direct connections: nick -> writer.
    links: Mutex<HashMap<String, mpsc::Sender<String>>>,
}

impl Shared {
    /// Take in a directory's peer list.
    fn learn(&self, line: &str) {
        if self.config.peers == PeerPolicy::Relay {
            return;
        }
        let entries = parse_peerlist(line, self.config.peers == PeerPolicy::Local);
        let Ok(mut locations) = self.locations.lock() else {
            return;
        };
        let now = Instant::now();
        for entry in entries {
            if entry.gone {
                locations.remove(&entry.nick);
                continue;
            }
            if locations.len() >= MAX_LOCATIONS && !locations.contains_key(&entry.nick) {
                locations.retain(|_, (_, _, at)| now.duration_since(*at) < LOCATION_TTL);
                if locations.len() >= MAX_LOCATIONS {
                    continue;
                }
            }
            locations.insert(entry.nick, (entry.host, entry.port, now));
        }
    }

    /// Where `nick` serves, if a directory said so recently.
    fn location(&self, nick: &str) -> Option<(String, u16)> {
        let locations = self.locations.lock().ok()?;
        let (host, port, at) = locations.get(nick)?;
        (at.elapsed() < LOCATION_TTL).then(|| (host.clone(), *port))
    }

    /// The writer of the direct connection to `nick`, if one is open.
    fn link(&self, nick: &str) -> Option<mpsc::Sender<String>> {
        let links = self.links.lock().ok()?;
        links.get(nick).filter(|w| !w.is_closed()).cloned()
    }
}

/// One nick on JoinMarket's onion directories. See the crate documentation.
pub struct OnionChannel {
    shared: Arc<Shared>,
    outbound: Outbound,
    inbox: Mutex<mpsc::Receiver<(Via, u64, String)>>,
    seen: Mutex<Seen>,
    /// Bit 0: offers wanted; bit 1: public messages wanted.
    wants: AtomicU8,
    announced: Mutex<HashMap<Pit, Vec<u64>>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl std::fmt::Debug for OnionChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnionChannel")
            .field("nick", &self.shared.identity.nick())
            .field("directories", &self.shared.config.directories.len())
            .finish_non_exhaustive()
    }
}

impl Drop for OnionChannel {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Ok(tasks) = self.tasks.get_mut() {
            for task in tasks.drain(..) {
                task.abort();
            }
        }
    }
}

type Reader = BufReader<tokio::io::ReadHalf<BoxedStream>>;
type Writer = tokio::io::WriteHalf<BoxedStream>;

/// Read one line: bounded in size, its terminator removed, decoded.
async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<(u64, String), String> {
    let mut buf = Vec::new();
    let limit = wire::MAX_RECEIVE_LINE as u64 + 2;
    let read = (&mut *reader)
        .take(limit)
        .read_until(b'\n', &mut buf)
        .await
        .map_err(|e| e.to_string())?;
    if read == 0 {
        return Err("closed".into());
    }
    if buf.last() != Some(&b'\n') {
        return Err("a line too long, or cut short".into());
    }
    buf.pop();
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    let text = String::from_utf8(buf).map_err(|_| "a line that is not UTF-8".to_string())?;
    wire::decode(&text).map_err(|e| e.to_string())
}

async fn write_line<W: AsyncWrite + Unpin>(
    writer: &mut W,
    kind: u64,
    line: &str,
) -> Result<(), String> {
    let encoded = encode(kind, line).map_err(|e| e.to_string())?;
    writer
        .write_all(encoded.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    writer.flush().await.map_err(|e| e.to_string())
}

/// JMP-0005: answer the directory's challenge with a signature over the transcript, by the nick key.
async fn authenticate_nick(
    reader: &mut Reader,
    writer: &mut Writer,
    identity: &NickIdentity,
    directory_id: &str,
    handshake: &str,
) -> Result<(), String> {
    let (kind, line) = tokio::time::timeout(NICK_AUTH_TIMEOUT, read_line(reader))
        .await
        .map_err(|_| "no nick-authentication challenge".to_string())??;
    if kind != NICK_AUTH_CHALLENGE {
        return Err("expected a nick-authentication challenge".into());
    }
    let challenge: Value = serde_json::from_str(&line).map_err(|_| "challenge is not JSON")?;
    let nonce = challenge
        .get("challenge")
        .and_then(Value::as_str)
        .filter(|c| c.len() == 64 && c.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .ok_or("malformed challenge")?;
    if challenge.get("directory-id").and_then(Value::as_str) != Some(directory_id) {
        return Err("the challenge names another directory".into());
    }
    let pubkey = identity.public().serialize().to_lower_hex_string();
    let handshake_hash = sha256::Hash::hash(handshake.as_bytes()).to_byte_array();
    let mut message = format!(
        "nick-auth|{nonce}|{directory_id}|{}|{}|{pubkey}",
        handshake_hash.to_lower_hex_string(),
        identity.nick()
    )
    .into_bytes();
    message.extend_from_slice(NICK_AUTH_DOMAIN);
    let signature = sigmsg::sign(&Secp256k1::signing_only(), &message, identity.secret());
    let proof = json!({ "pubkey": pubkey, "signature": signature }).to_string();
    write_line(writer, NICK_AUTH_PROOF, &proof).await?;
    let (kind, line) = tokio::time::timeout(NICK_AUTH_TIMEOUT, read_line(reader))
        .await
        .map_err(|_| "no nick-authentication result".to_string())??;
    if kind != NICK_AUTH_RESULT {
        return Err("expected a nick-authentication result".into());
    }
    let result: Value = serde_json::from_str(&line).map_err(|_| "result is not JSON")?;
    if result.get("code").and_then(Value::as_str) != Some("ok")
        || result.get("verified").and_then(Value::as_bool) != Some(true)
    {
        return Err("the directory did not verify our nick".into());
    }
    Ok(())
}

/// Connect to `directory` as `identity` and complete the handshake.
async fn open(
    connector: &NickConnector,
    directory: &Directory,
    identity: &NickIdentity,
    network: &str,
) -> Result<(Reader, Writer), String> {
    let stream = connector
        .connect(&directory.host, directory.port)
        .await
        .map_err(|e| e.to_string())?;
    let (read, mut write) = tokio::io::split(stream);
    let mut reader = BufReader::new(read);
    let mut features = vec!["ping"];
    if directory.id.is_some() {
        features.push("nick_auth");
    }
    let handshake = wire::client_handshake(identity.nick(), network, &features);
    write_line(&mut write, HANDSHAKE, &handshake).await?;
    let (kind, line) = read_line(&mut reader).await?;
    if kind != DN_HANDSHAKE && kind != HANDSHAKE {
        return Err("expected the directory's handshake".into());
    }
    let hello = read_directory_hello(&line, network).map_err(|e| e.to_string())?;
    if let Some(id) = &directory.id
        && hello.features.iter().any(|f| f == "nick_auth")
    {
        authenticate_nick(&mut reader, &mut write, identity, id, &handshake).await?;
    }
    Ok((reader, write))
}

/// One connection's life: connect, handshake, then read until it drops. `ready` hears of the first
/// handshake's outcome.
async fn session(
    shared: &Shared,
    index: usize,
    ready: &mut Option<mpsc::Sender<Result<(), String>>>,
) -> Result<(), String> {
    let directory = &shared.config.directories[index];
    let opened = tokio::time::timeout(
        shared.config.timeout,
        open(
            &shared.connector,
            directory,
            &shared.identity,
            &shared.config.network,
        ),
    )
    .await
    .map_err(|_| "timed out".to_string())
    .and_then(|r| r);
    let (mut reader, mut writer) = match opened {
        Ok(io) => io,
        Err(e) => {
            if let Some(ready) = ready.take() {
                let _ = ready.send(Err(e.clone())).await;
            }
            return Err(e);
        }
    };
    let (out_tx, mut out_rx) = mpsc::channel::<String>(OUTBOX);
    if let Ok(mut slot) = shared.writers[index].lock() {
        *slot = Some(out_tx.clone());
    }
    if let Some(ready) = ready.take() {
        let _ = ready.send(Ok(())).await;
    }
    let write_task = tokio::spawn(async move {
        while let Some(line) = out_rx.recv().await {
            if writer.write_all(line.as_bytes()).await.is_err() || writer.flush().await.is_err() {
                break;
            }
        }
    });
    let result = loop {
        match read_line(&mut reader).await {
            Ok((kind @ (PRIVMSG | PUBMSG), line)) => {
                if shared
                    .inbox
                    .send((Via::Directory(index), kind, line))
                    .await
                    .is_err()
                {
                    break Ok(());
                }
            }
            Ok((PEERLIST, line)) => shared.learn(&line),
            Ok((PING, _)) => {
                if let Ok(pong) = encode(PONG, "") {
                    let _ = out_tx.try_send(pong);
                }
            }
            Ok((NICK_AUTH_CHALLENGE | NICK_AUTH_PROOF | NICK_AUTH_RESULT, _)) => {
                break Err("nick authentication after the handshake".into());
            }
            // Pongs and anything else.
            Ok(_) => {}
            Err(e) => break Err(e),
        }
    };
    if let Ok(mut slot) = shared.writers[index].lock() {
        *slot = None;
    }
    write_task.abort();
    result
}

/// Keep directory `index` connected until the channel stops.
async fn supervise(shared: Arc<Shared>, index: usize, ready: mpsc::Sender<Result<(), String>>) {
    let mut ready = Some(ready);
    let mut backoff = Duration::from_secs(5);
    while !shared.stop.load(Ordering::SeqCst) {
        let started = Instant::now();
        let _ = session(&shared, index, &mut ready).await;
        if started.elapsed() > Duration::from_secs(120) {
            backoff = Duration::from_secs(5);
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

impl OnionChannel {
    /// Connect `identity`'s nick to the directories in `config`, through its own way out from `outbound`.
    /// Returns once one directory has accepted it (the others keep trying in the background), or fails when
    /// none has within `config.timeout`.
    pub async fn connect(
        identity: NickIdentity,
        config: OnionConfig,
        outbound: &Outbound,
    ) -> Result<OnionChannel, ChannelError> {
        let count = config.directories.len();
        if count == 0 {
            return Err(ChannelError::Invalid("at least one directory"));
        }
        let (inbox_tx, inbox_rx) = mpsc::channel(INBOX);
        let timeout = config.timeout;
        let shared = Arc::new(Shared {
            identity,
            writers: (0..count).map(|_| Mutex::new(None)).collect(),
            config,
            connector: outbound.connector(),
            inbox: inbox_tx,
            stop: AtomicBool::new(false),
            locations: Mutex::new(HashMap::new()),
            links: Mutex::new(HashMap::new()),
        });
        let (ready_tx, mut ready_rx) = mpsc::channel(count);
        let tasks = (0..count)
            .map(|i| tokio::spawn(supervise(Arc::clone(&shared), i, ready_tx.clone())))
            .collect();
        let channel = OnionChannel {
            shared,
            outbound: outbound.clone(),
            inbox: Mutex::new(inbox_rx),
            seen: Mutex::new(Seen::default()),
            wants: AtomicU8::new(0),
            announced: Mutex::new(HashMap::new()),
            tasks: Mutex::new(tasks),
        };
        let deadline = tokio::time::Instant::now() + timeout + Duration::from_secs(1);
        let mut failures = Vec::new();
        loop {
            match tokio::time::timeout_at(deadline, ready_rx.recv()).await {
                Ok(Some(Ok(()))) => return Ok(channel),
                Ok(Some(Err(e))) => {
                    failures.push(e);
                    if failures.len() == count {
                        return Err(transport(format!(
                            "no directory accepted us: {}",
                            failures.join("; ")
                        )));
                    }
                }
                Ok(None) | Err(_) => return Err(transport("no directory answered in time")),
            }
        }
    }

    /// Send one line to directory `index`.
    fn send_to(&self, index: usize, kind: u64, line: &str) -> Result<(), ChannelError> {
        let encoded = encode(kind, line).map_err(|e| ChannelError::Invalid(e.0))?;
        let writer = self
            .shared
            .writers
            .get(index)
            .and_then(|slot| slot.lock().ok().and_then(|w| w.clone()))
            .ok_or_else(|| transport("not connected to that directory"))?;
        writer
            .try_send(encoded)
            .map_err(|_| transport("that directory's send queue is full or closed"))
    }

    /// Send one line to every connected directory; `Ok` if one took it.
    fn send_all(&self, kind: u64, line: &str) -> Result<(), ChannelError> {
        let mut result = Err(transport("not connected to any directory"));
        for index in 0..self.shared.writers.len() {
            match self.send_to(index, kind, line) {
                Ok(()) => result = Ok(()),
                Err(e @ ChannelError::Invalid(_)) => return Err(e),
                Err(_) => {}
            }
        }
        result
    }

    /// How many directories are connected now.
    pub fn connected(&self) -> usize {
        self.shared
            .writers
            .iter()
            .filter(|slot| slot.lock().is_ok_and(|w| w.is_some()))
            .count()
    }

    /// What arrived through `via`, as a message for the drivers, if it is one. A direct connection carries
    /// only private lines from the peer it leads to.
    fn message(&self, via: Via, kind: u64, line: &str) -> Option<Incoming<OnionRoute>> {
        let nick = self.shared.identity.nick();
        let wants = self.wants.load(Ordering::SeqCst);
        if kind == PRIVMSG {
            let msg =
                verify_line(&Secp256k1::verification_only(), line, ONION_HOSTID, nick).ok()?;
            if let Via::Peer(peer) = &via
                && msg.from != *peer
            {
                return None;
            }
            return Some(Incoming::Private {
                msg,
                route: OnionRoute { via },
            });
        }
        if matches!(via, Via::Peer(_)) {
            return None;
        }
        let route = OnionRoute { via };
        let (from, text) = read_public_line(line)?;
        if from == nick {
            return None;
        }
        let commands = parse_plaintext(text)?;
        let offers: Vec<Offer> = commands
            .iter()
            .filter_map(|c| match c {
                Command::Offer(offer) => Some(offer.clone()),
                _ => None,
            })
            .collect();
        if !offers.is_empty() {
            return (wants & 1 != 0).then(|| Incoming::Offers {
                nick: from.to_string(),
                offers,
                route,
            });
        }
        let commands: Vec<Command> = commands
            .into_iter()
            .filter(|c| matches!(c, Command::Orderbook | Command::Hp2(_) | Command::Cancel(_)))
            .collect();
        (wants & 2 != 0 && !commands.is_empty()).then(|| Incoming::Public {
            nick: from.to_string(),
            commands,
            route,
        })
    }
}

impl Channel for OnionChannel {
    type Route = OnionRoute;

    fn nick(&self) -> &str {
        self.shared.identity.nick()
    }

    // A directory forwards lines and need not check who sent them; any directory can deliver a line again. A
    // direct connection's peer location came from a directory too.
    fn authenticates(&self, _route: &OnionRoute) -> bool {
        false
    }

    async fn listen(&self, offers: bool, public: bool) -> Result<(), ChannelError> {
        self.wants
            .store(u8::from(offers) | (u8::from(public) << 1), Ordering::SeqCst);
        Ok(())
    }

    async fn send_private(
        &self,
        route: &OnionRoute,
        to: &str,
        command: &str,
        body: &str,
    ) -> Result<(), ChannelError> {
        let line = sign_line(
            &Secp256k1::signing_only(),
            self.shared.identity.secret(),
            to,
            command,
            body,
            ONION_HOSTID,
        )
        .map_err(ChannelError::Line)?;
        // A direct connection first; then the directory the peer's line came through, which holds its
        // connection; then any other.
        if let Some(link) = self.shared.link(to) {
            let encoded = encode(PRIVMSG, &line).map_err(|e| ChannelError::Invalid(e.0))?;
            if link.try_send(encoded).is_ok() {
                return Ok(());
            }
        }
        let sent = match &route.via {
            Via::Directory(index) => self.send_to(*index, PRIVMSG, &line),
            Via::Peer(_) => Err(transport("no directory named")),
        };
        match sent {
            Ok(()) => Ok(()),
            Err(e @ ChannelError::Invalid(_)) => Err(e),
            Err(_) => self.send_all(PRIVMSG, &line),
        }
    }

    async fn prepare(&self, peers: &[(String, OnionRoute)]) {
        if self.shared.config.peers == PeerPolicy::Relay {
            return;
        }
        let wanted: Vec<&str> = peers
            .iter()
            .map(|(nick, _)| nick.as_str())
            .filter(|nick| self.shared.link(nick).is_none())
            .collect();
        if wanted.is_empty() {
            return;
        }
        // Ask the directories for peers they have not named yet (JoinMarket-NG's answer; joinmarket-clientserver's
        // ignore it, and name a peer when they relay its line).
        if wanted
            .iter()
            .any(|nick| self.shared.location(nick).is_none())
        {
            let _ = self.send_all(GETPEERLIST, "");
            let until = Instant::now() + LOCATION_WAIT;
            while Instant::now() < until
                && wanted
                    .iter()
                    .any(|nick| self.shared.location(nick).is_none())
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        let limit = self.shared.config.timeout.min(PREPARE_LIMIT);
        let mut attempts = Vec::new();
        for nick in wanted {
            let Some((host, port)) = self.shared.location(nick) else {
                continue;
            };
            let open_links = self
                .shared
                .links
                .lock()
                .map(|l| l.len())
                .unwrap_or(MAX_LINKS);
            if open_links + attempts.len() >= MAX_LINKS {
                break;
            }
            let shared = Arc::clone(&self.shared);
            let connector = self.outbound.connector();
            let nick = nick.to_string();
            attempts.push(tokio::spawn(async move {
                let opened = tokio::time::timeout(
                    limit,
                    open_peer(
                        &connector,
                        &host,
                        port,
                        &shared.identity,
                        &shared.config.network,
                    ),
                )
                .await;
                match opened {
                    Ok(Ok((reader, writer, first))) => Some((nick, reader, writer, first)),
                    _ => None,
                }
            }));
        }
        for attempt in attempts {
            let Ok(Some((nick, reader, writer, first))) = attempt.await else {
                continue;
            };
            let task = start_link(Arc::clone(&self.shared), nick, reader, writer, first);
            if let Ok(mut tasks) = self.tasks.lock() {
                tasks.extend(task);
            }
        }
    }

    async fn ask_orderbook(&self) -> Result<(), ChannelError> {
        self.send_all(PUBMSG, &public_line(self.nick(), "!orderbook"))
    }

    async fn announce_offers(&self, pit: Pit, offers: &[Offer]) -> Result<(), ChannelError> {
        for offer in offers {
            self.send_all(PUBMSG, &public_line(self.nick(), &offer.to_command()))?;
        }
        if let Ok(mut announced) = self.announced.lock() {
            announced.insert(pit, offers.iter().map(|o| o.oid).collect());
        }
        Ok(())
    }

    async fn withdraw_offers(&self, pit: Pit) -> Result<(), ChannelError> {
        let oids = self
            .announced
            .lock()
            .ok()
            .and_then(|mut a| a.remove(&pit))
            .unwrap_or_default();
        for oid in oids {
            self.send_all(PUBMSG, &public_line(self.nick(), &format!("!cancel {oid}")))?;
        }
        Ok(())
    }

    async fn publish_unlinked(&self, line: &str) -> Result<(), ChannelError> {
        // A fresh nick on a way out of its own, for each directory; nothing about it leads back to ours.
        let throwaway = NickIdentity::generate();
        let connector = Arc::new(self.outbound.connector());
        let public = public_line(throwaway.nick(), line);
        let mut tasks = Vec::new();
        for directory in self.shared.config.directories.clone() {
            let (connector, throwaway, public) =
                (Arc::clone(&connector), throwaway.clone(), public.clone());
            let (network, timeout) = (
                self.shared.config.network.clone(),
                self.shared.config.timeout,
            );
            tasks.push(tokio::spawn(async move {
                let sent = async {
                    let (_reader, mut writer) =
                        open(&connector, &directory, &throwaway, &network).await?;
                    write_line(&mut writer, PUBMSG, &public).await?;
                    let _ = writer.shutdown().await;
                    Ok::<(), String>(())
                };
                matches!(tokio::time::timeout(timeout, sent).await, Ok(Ok(())))
            }));
        }
        let mut any = false;
        for task in tasks {
            any |= task.await.unwrap_or(false);
        }
        if any {
            Ok(())
        } else {
            Err(transport("no directory took the unlinked line"))
        }
    }

    async fn receive(&mut self, wait: Duration) -> Next<OnionRoute> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let Ok(inbox) = self.inbox.get_mut() else {
                return Next::Closed;
            };
            let (via, kind, line) = match tokio::time::timeout_at(deadline, inbox.recv()).await {
                Ok(Some(item)) => item,
                Ok(None) => return Next::Closed,
                Err(_) => return Next::Timeout,
            };
            let fresh = self
                .seen
                .get_mut()
                .map(|seen| seen.fresh(kind, &line))
                .unwrap_or(true);
            if !fresh {
                continue;
            }
            if let Some(message) = self.message(via, kind, &line) {
                return Next::Message(message);
            }
        }
    }

    async fn shutdown(&self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Ok(mut tasks) = self.tasks.lock() {
            for task in tasks.drain(..) {
                task.abort();
            }
        }
        for slot in &self.shared.writers {
            if let Ok(mut writer) = slot.lock() {
                *writer = None;
            }
        }
        if let Ok(mut links) = self.shared.links.lock() {
            links.clear();
        }
    }
}

/// Connect to a peer that serves an onion and say our handshake. Returns the connection and, if the peer
/// sent a line other than a handshake straight away, that line.
async fn open_peer(
    connector: &NickConnector,
    host: &str,
    port: u16,
    identity: &NickIdentity,
    network: &str,
) -> Result<(Reader, Writer, Option<(u64, String)>), String> {
    let stream = connector
        .connect(host, port)
        .await
        .map_err(|e| e.to_string())?;
    let (read, mut write) = tokio::io::split(stream);
    let mut reader = BufReader::new(read);
    let handshake = wire::client_handshake(identity.nick(), network, &[]);
    write_line(&mut write, HANDSHAKE, &handshake).await?;
    // JoinMarket-NG answers with a handshake of its own; joinmarket-clientserver accepts silently.
    let first = match tokio::time::timeout(PEER_HELLO_WAIT, read_line(&mut reader)).await {
        Err(_) => None,
        Ok(Err(e)) => return Err(e),
        Ok(Ok((HANDSHAKE, line))) => {
            read_peer_hello(&line, network).map_err(|e| e.to_string())?;
            None
        }
        Ok(Ok(other)) => Some(other),
    };
    Ok((reader, write, first))
}

/// Keep a direct connection to `nick`: its writer goes into the shared links, its reader hands that peer's
/// private lines on. The connection is forgotten when it drops.
fn start_link(
    shared: Arc<Shared>,
    nick: String,
    mut reader: Reader,
    mut writer: Writer,
    first: Option<(u64, String)>,
) -> Vec<JoinHandle<()>> {
    let (out_tx, mut out_rx) = mpsc::channel::<String>(OUTBOX);
    if let Ok(mut links) = shared.links.lock() {
        links.insert(nick.clone(), out_tx.clone());
    }
    let write_task = tokio::spawn(async move {
        while let Some(line) = out_rx.recv().await {
            if writer.write_all(line.as_bytes()).await.is_err() || writer.flush().await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });
    let read_task = tokio::spawn(async move {
        let mut next = first;
        loop {
            let (kind, line) = match next.take() {
                Some(item) => item,
                None => match read_line(&mut reader).await {
                    Ok(item) => item,
                    Err(_) => break,
                },
            };
            match kind {
                PRIVMSG => {
                    if shared
                        .inbox
                        .send((Via::Peer(nick.clone()), kind, line))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                PING => {
                    if let Ok(pong) = encode(PONG, "") {
                        let _ = out_tx.try_send(pong);
                    }
                }
                // A late handshake, or anything else a peer has no business sending here.
                _ => {}
            }
        }
        if let Ok(mut links) = shared.links.lock()
            && links.get(&nick).is_some_and(|w| w.same_channel(&out_tx))
        {
            links.remove(&nick);
        }
    });
    vec![write_task, read_task]
}

#[cfg(test)]
mod tests;
