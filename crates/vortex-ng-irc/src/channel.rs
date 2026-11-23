//! [`IrcChannel`]: one nick on one IRC server's pit channel, as joinmarket-clientserver uses it.
//!
//! A task keeps the connection: it registers the nick, takes the server's signature domain from its first
//! `005` line (see [`Hostid`]), joins the pit channel, answers pings, and hands on what arrives; it
//! reconnects with back-off when the connection drops, and waits before retrying a nick in use (the nick
//! cannot change: it is derived from the key). Lines go out through a queue at the line rate servers
//! tolerate, so a long message never holds up the others' turn to be read.
//!
//! The server, and anyone it forwards to, sees every private line's sender, recipient and size, and the
//! plain-text steps of a round; the encrypted steps stay encrypted. Public lines are vouched for by the
//! server's prefix only; private lines are JMP-0001 lines signed over the server's domain.
//!
//! The connection to the server is TLS with certificate checks, except to an onion host (Tor already encrypts
//! and authenticates it) and on loopback. A failed check ends the attempt: it never falls back to plain text.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use vortex_ng_channel::socks::{NickConnector, Outbound};
use vortex_ng_channel::{Channel, ChannelError, Incoming, MAX_UNLINKED, Next, SideTasks};
use vortex_ng_core::bitcoin::secp256k1::Secp256k1;
use vortex_ng_core::command::{Command, parse_plaintext};
use vortex_ng_core::line::{sign_line, verify_line};
use vortex_ng_core::nick::NickIdentity;
use vortex_ng_core::offer::{Offer, Pit};

use crate::codec::{
    Hostid, MAX_LINE, Pacer, Reassembler, build, is_ctcp, offer_lines, parse, pit_channel,
    private_lines, public_text,
};

/// Lines received and waiting to be read.
const INBOX: usize = 1_024;
/// Lines waiting to be sent (a 40,000-byte private message is about 100).
const OUTBOX: usize = 1_024;
/// Lines anyone can ask for (see [`is_free_to_ask`]) waiting to be sent, about 40 s at the line rate. They go
/// out only when no round's line is waiting, and past this they are dropped.
const BULK_QUEUE: usize = 32;
#[cfg(test)]
pub(crate) const BULK_QUEUE_FOR_TESTS: usize = BULK_QUEUE;
/// The longest wait between reconnection attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(600);
/// Silence after which we ping the server, and after which a connection counts as dead.
const IDLE_PING: Duration = Duration::from_secs(120);
const DEAD: Duration = Duration::from_secs(300);

fn transport(e: impl std::fmt::Display) -> ChannelError {
    ChannelError::Transport(format!("IRC: {e}"))
}

/// An IRC server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrcServer {
    /// Its host.
    pub host: String,
    /// Its port.
    pub port: u16,
    /// The `NETWORK=` name it is expected to announce; a server announcing another is refused.
    pub expected_network: Option<String>,
    /// Whether the connection is TLS, with the server's certificate checked against its host name.
    pub tls: bool,
}

/// Whether the way to `host` is private without TLS: Tor's for an onion, this machine's for loopback.
fn private_without_tls(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host.ends_with(".onion")
        || host == "localhost"
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback())
}

impl IrcServer {
    /// From `host:port`, which is TLS unless the host is an onion or loopback; or from `ircs://host:port`
    /// (always TLS) or `irc://host:port` (plain text, for regtest).
    pub fn parse(text: &str) -> Option<IrcServer> {
        let text = text.trim();
        let (scheme, address) = match text.split_once("://") {
            Some(("ircs", address)) => (Some(true), address),
            Some(("irc", address)) => (Some(false), address),
            Some(_) => return None,
            None => (None, text),
        };
        let (host, port) = address.rsplit_once(':')?;
        let valid = !host.is_empty()
            && host.len() <= 255
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
        let port = port.parse().ok().filter(|p| *p > 0)?;
        valid.then(|| IrcServer {
            host: host.to_string(),
            port,
            expected_network: None,
            tls: scheme.unwrap_or_else(|| !private_without_tls(host)),
        })
    }

    /// Whether lines to this server would cross a network in the clear.
    pub fn is_exposed(&self) -> bool {
        !self.tls && !private_without_tls(&self.host)
    }
}

/// What an [`IrcChannel`] connects to.
#[derive(Clone, Debug)]
pub struct IrcConfig {
    /// The server.
    pub server: IrcServer,
    /// The Bitcoin network's name (`mainnet`, `testnet`, `signet`, `regtest`): it picks the pit channel.
    pub network: String,
    /// How long registering may take.
    pub timeout: Duration,
}

/// How to answer a peer: on this server, by nick (nothing else to remember).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrcRoute;

enum Arrived {
    Private(String, String),
    Public(String, String),
}

struct Shared {
    identity: NickIdentity,
    config: IrcConfig,
    channel: String,
    connector: NickConnector,
    /// The TLS settings, for a server reached over TLS.
    tls: Option<Arc<ClientConfig>>,
    hostid: Mutex<String>,
    writer: Mutex<Option<Writers>>,
    inbox: mpsc::Sender<Arrived>,
    stop: AtomicBool,
}

/// The connection's two send queues.
#[derive(Clone)]
struct Writers {
    /// Everything that must not wait behind `!orderbook` answers.
    round: mpsc::Sender<String>,
    /// `!orderbook` answers.
    bulk: mpsc::Sender<String>,
}

/// Whether a private line is one anyone can get out of us for free: an answer to `!orderbook`, or a maker's
/// first reply to a `!fill` (`!pubkey`, `!error`), which proves nothing yet. These wait behind the lines of
/// rounds under way, in a small queue of their own.
fn is_free_to_ask(command: &str) -> bool {
    command.ends_with("offer") || matches!(command, "tbond" | "pubkey" | "error")
}

/// One nick on one IRC server's pit channel. See the module documentation.
pub struct IrcChannel {
    shared: Arc<Shared>,
    outbound: Outbound,
    inbox: Mutex<mpsc::Receiver<Arrived>>,
    reassembler: Mutex<Reassembler>,
    wants: AtomicU8,
    announced: Mutex<HashMap<Pit, Vec<u64>>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    /// Unlinked lines being published.
    unlinked: SideTasks,
}

impl std::fmt::Debug for IrcChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IrcChannel")
            .field("nick", &self.shared.identity.nick())
            .field("server", &self.shared.config.server.host)
            .finish_non_exhaustive()
    }
}

impl Drop for IrcChannel {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Ok(tasks) = self.tasks.get_mut() {
            for task in tasks.drain(..) {
                task.abort();
            }
        }
    }
}

/// Read one IRC line, bounded, without its terminator; invalid UTF-8 is replaced.
async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<String, String> {
    let mut buf = Vec::new();
    let read = (&mut *reader)
        .take(MAX_LINE as u64 * 16)
        .read_until(b'\n', &mut buf)
        .await
        .map_err(|e| e.to_string())?;
    if read == 0 {
        return Err("closed".into());
    }
    if buf.last() != Some(&b'\n') {
        return Err("a line too long, or cut short".into());
    }
    Ok(String::from_utf8_lossy(&buf)
        .trim_end_matches(['\r', '\n'])
        .to_string())
}

type Reader = BufReader<tokio::io::ReadHalf<vortex_ng_channel::socks::BoxedStream>>;
type Writer = tokio::io::WriteHalf<vortex_ng_channel::socks::BoxedStream>;

/// Register `nick`, take the server's domain, join the pit channel. Returns the reader and writer.
async fn register(shared: &Shared) -> Result<(Reader, Writer), String> {
    let server = &shared.config.server;
    let stream = shared
        .connector
        .connect(&server.host, server.port)
        .await
        .map_err(|e| e.to_string())?;
    // Nothing is said to the server before its certificate has checked out.
    let stream = match &shared.tls {
        Some(tls) => crate::tls::secure(stream, &server.host, tls).await?,
        None => stream,
    };
    let (read, mut write) = tokio::io::split(stream);
    let mut reader = BufReader::new(read);
    let nick = shared.identity.nick();
    let hello = [
        build("NICK", &[nick]).ok_or("nick")?,
        build("USER", &[nick, "0", "*", nick]).ok_or("user")?,
    ]
    .concat();
    write
        .write_all(hello.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut hostid = Hostid::new(&server.host, server.port);
    let mut joined = false;
    while !joined {
        let line = read_line(&mut reader).await?;
        let Some(message) = parse(&line) else {
            continue;
        };
        match message.command.as_str() {
            "PING" => {
                let token = message.params.first().map(String::as_str).unwrap_or("");
                let pong = build("PONG", &[token]).ok_or("pong")?;
                write
                    .write_all(pong.as_bytes())
                    .await
                    .map_err(|e| e.to_string())?;
            }
            "005" => hostid
                .read_isupport(&message.params, server.expected_network.as_deref())
                .map_err(|e| e.to_string())?,
            // End of the welcome (or no message of the day): what the server said is all it will say.
            "376" | "422" => {
                hostid.freeze();
                let join = build("JOIN", &[&shared.channel]).ok_or("join")?;
                write
                    .write_all(join.as_bytes())
                    .await
                    .map_err(|e| e.to_string())?;
            }
            "433" | "436" => return Err("nick in use".into()),
            "JOIN" if message.nick() == Some(nick) => {
                let mode = build("MODE", &[nick, "+B"]).ok_or("mode")?;
                write
                    .write_all(mode.as_bytes())
                    .await
                    .map_err(|e| e.to_string())?;
                joined = true;
            }
            "ERROR" | "465" | "471" | "473" | "474" | "475" => {
                return Err(format!("refused: {line}"));
            }
            _ => {}
        }
    }
    if let Ok(mut domain) = shared.hostid.lock() {
        // Other channels' domains were checked against this one when the channel started; a server that
        // comes back with another must not get lines signed for it.
        if !domain.is_empty() && *domain != hostid.value() {
            return Err("the server's signature domain changed".into());
        }
        *domain = hostid.value().to_string();
    }
    Ok((reader, write))
}

/// One connection's life. `ready` hears of the first registration's outcome.
async fn session(
    shared: &Shared,
    ready: &mut Option<mpsc::Sender<Result<(), String>>>,
) -> Result<(), String> {
    let registered = tokio::time::timeout(shared.config.timeout, register(shared))
        .await
        .map_err(|_| "registration timed out".to_string())
        .and_then(|r| r);
    let (mut reader, mut writer) = match registered {
        Ok(io) => io,
        Err(e) => {
            if let Some(ready) = ready.take() {
                let _ = ready.send(Err(e.clone())).await;
            }
            return Err(e);
        }
    };
    let (out_tx, mut out_rx) = mpsc::channel::<String>(OUTBOX);
    let (bulk_tx, mut bulk_rx) = mpsc::channel::<String>(BULK_QUEUE);
    if let Ok(mut slot) = shared.writer.lock() {
        *slot = Some(Writers {
            round: out_tx.clone(),
            bulk: bulk_tx,
        });
    }
    if let Some(ready) = ready.take() {
        let _ = ready.send(Ok(())).await;
    }
    // The writer keeps to the line rate, and a round's lines go before `!orderbook` answers.
    let write_task = tokio::spawn(async move {
        let mut pacer = Pacer::default();
        loop {
            let line = tokio::select! {
                biased;
                Some(line) = out_rx.recv() => line,
                Some(line) = bulk_rx.recv() => line,
                else => break,
            };
            tokio::time::sleep_until(pacer.slot(Instant::now()).into()).await;
            if writer.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    });
    let nick = shared.identity.nick();
    let (idle_tx, idle_rx) = watch::channel(Instant::now());
    let pinger = {
        let out = out_tx.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(IDLE_PING).await;
                if idle_rx.borrow().elapsed() >= IDLE_PING
                    && let Some(ping) = build("PING", &["vortex-ng"])
                    && out.send(ping).await.is_err()
                {
                    break;
                }
            }
        })
    };
    let result = loop {
        let line = match tokio::time::timeout(DEAD, read_line(&mut reader)).await {
            Ok(Ok(line)) => line,
            Ok(Err(e)) => break Err(e),
            Err(_) => break Err("the server went silent".into()),
        };
        let _ = idle_tx.send(Instant::now());
        let Some(message) = parse(&line) else {
            continue;
        };
        match message.command.as_str() {
            "PING" => {
                let token = message.params.first().map(String::as_str).unwrap_or("");
                if let Some(pong) = build("PONG", &[token]) {
                    let _ = out_tx.try_send(pong);
                }
            }
            "PRIVMSG" => {
                let (Some(from), [target, text]) = (message.nick(), message.params.as_slice())
                else {
                    continue;
                };
                if from == nick || is_ctcp(text) {
                    continue;
                }
                let arrived = if target == nick {
                    Arrived::Private(from.to_string(), text.clone())
                } else if target.eq_ignore_ascii_case(&shared.channel) {
                    Arrived::Public(from.to_string(), text.clone())
                } else {
                    continue;
                };
                if shared.inbox.send(arrived).await.is_err() {
                    break Ok(());
                }
            }
            "ERROR" => break Err(format!("the server closed: {line}")),
            _ => {}
        }
    };
    if let Ok(mut slot) = shared.writer.lock() {
        *slot = None;
    }
    write_task.abort();
    pinger.abort();
    result
}

async fn supervise(shared: Arc<Shared>, ready: mpsc::Sender<Result<(), String>>) {
    let mut ready = Some(ready);
    let mut backoff = Duration::from_secs(10);
    while !shared.stop.load(Ordering::SeqCst) {
        let started = Instant::now();
        let _ = session(&shared, &mut ready).await;
        if started.elapsed() > Duration::from_secs(120) {
            backoff = Duration::from_secs(10);
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

impl IrcChannel {
    /// Connect `identity`'s nick to the server in `config`, through its own way out from `outbound`. Returns
    /// once the nick has joined the pit channel (later drops are reconnected in the background), or fails if
    /// the first attempt does. A server's certificate is checked against the Mozilla root store.
    pub async fn connect(
        identity: NickIdentity,
        config: IrcConfig,
        outbound: &Outbound,
    ) -> Result<IrcChannel, ChannelError> {
        Self::connect_trusting(identity, config, outbound, crate::tls::web_roots()).await
    }

    /// [`IrcChannel::connect`], trusting only the certificate authorities in `roots`.
    #[cfg(any(test, feature = "test-util"))]
    pub async fn connect_with_roots(
        identity: NickIdentity,
        config: IrcConfig,
        outbound: &Outbound,
        roots: RootCertStore,
    ) -> Result<IrcChannel, ChannelError> {
        Self::connect_trusting(identity, config, outbound, roots).await
    }

    async fn connect_trusting(
        identity: NickIdentity,
        config: IrcConfig,
        outbound: &Outbound,
        roots: RootCertStore,
    ) -> Result<IrcChannel, ChannelError> {
        if config.server.is_exposed() && config.network != "regtest" {
            return Err(ChannelError::Invalid(
                "plain-text IRC is for regtest: use TLS, or an onion server through Tor",
            ));
        }
        let tls = match config.server.tls {
            true => Some(crate::tls::client_config(roots).map_err(transport)?),
            false => None,
        };
        let (inbox_tx, inbox_rx) = mpsc::channel(INBOX);
        let timeout = config.timeout;
        let shared = Arc::new(Shared {
            channel: pit_channel(&config.network),
            hostid: Mutex::new(String::new()),
            identity,
            config,
            connector: outbound.connector(),
            tls,
            writer: Mutex::new(None),
            inbox: inbox_tx,
            stop: AtomicBool::new(false),
        });
        let (ready_tx, mut ready_rx) = mpsc::channel(1);
        let task = tokio::spawn(supervise(Arc::clone(&shared), ready_tx));
        let channel = IrcChannel {
            shared,
            outbound: outbound.clone(),
            inbox: Mutex::new(inbox_rx),
            reassembler: Mutex::new(Reassembler::default()),
            wants: AtomicU8::new(0),
            announced: Mutex::new(HashMap::new()),
            tasks: Mutex::new(vec![task]),
            unlinked: SideTasks::new(MAX_UNLINKED),
        };
        match tokio::time::timeout(timeout + Duration::from_secs(1), ready_rx.recv()).await {
            Ok(Some(Ok(()))) => Ok(channel),
            Ok(Some(Err(e))) => Err(transport(e)),
            Ok(None) | Err(_) => Err(transport("the server did not answer in time")),
        }
    }

    /// The server's signature domain (`hostid`), as taken when the nick registered.
    pub fn hostid(&self) -> String {
        self.shared
            .hostid
            .lock()
            .map(|h| h.clone())
            .unwrap_or_default()
    }

    /// Whether the nick is on the server now.
    pub fn connected(&self) -> bool {
        self.shared.writer.lock().is_ok_and(|w| w.is_some())
    }

    fn writers(&self) -> Result<Writers, ChannelError> {
        self.shared
            .writer
            .lock()
            .ok()
            .and_then(|w| w.clone())
            .ok_or_else(|| transport("not connected"))
    }

    fn send_lines(&self, lines: Vec<String>) -> Result<(), ChannelError> {
        let writers = self.writers()?;
        for line in lines {
            writers
                .round
                .try_send(line)
                .map_err(|_| transport("the send queue is full or closed"))?;
        }
        Ok(())
    }

    /// Queue an `!orderbook` answer, whole or not at all.
    fn send_bulk(&self, lines: Vec<String>) -> Result<(), ChannelError> {
        let writers = self.writers()?;
        if writers.bulk.capacity() < lines.len() {
            return Err(transport("too many orderbook answers waiting"));
        }
        for line in lines {
            writers
                .bulk
                .try_send(line)
                .map_err(|_| transport("the send queue is full or closed"))?;
        }
        Ok(())
    }

    fn public(&self, text: &str) -> Result<(), ChannelError> {
        let line = build("PRIVMSG", &[&self.shared.channel, text])
            .ok_or(ChannelError::Invalid("a public line too long for IRC"))?;
        self.send_lines(vec![line])
    }

    fn message(&self, arrived: Arrived, now: Instant) -> Option<Incoming<IrcRoute>> {
        let nick = self.shared.identity.nick();
        let wants = self.wants.load(Ordering::SeqCst);
        match arrived {
            Arrived::Private(from, text) => {
                let whole = self.reassembler.lock().ok()?.push(&from, &text, now)?;
                // `!command body key signature`, from the server's prefix to us: a JMP-0001 line again.
                let line = format!("{from}!{nick}!{}", whole.strip_prefix('!')?);
                let msg = verify_line(&Secp256k1::verification_only(), &line, &self.hostid(), nick)
                    .ok()?;
                Some(Incoming::Private {
                    msg,
                    route: IrcRoute,
                })
            }
            Arrived::Public(from, text) => {
                let commands = parse_plaintext(public_text(&text))?;
                let offers: Vec<Offer> = commands
                    .iter()
                    .filter_map(|c| match c {
                        Command::Offer(offer) => Some(offer.clone()),
                        _ => None,
                    })
                    .collect();
                if !offers.is_empty() {
                    return (wants & 1 != 0).then_some(Incoming::Offers {
                        nick: from,
                        offers,
                        route: IrcRoute,
                    });
                }
                let commands: Vec<Command> = commands
                    .into_iter()
                    .filter(|c| {
                        matches!(c, Command::Orderbook | Command::Hp2(_) | Command::Cancel(_))
                    })
                    .collect();
                (wants & 2 != 0 && !commands.is_empty()).then_some(Incoming::Public {
                    nick: from,
                    commands,
                    route: IrcRoute,
                })
            }
        }
    }
}

impl Channel for IrcChannel {
    type Route = IrcRoute;

    fn nick(&self) -> &str {
        self.shared.identity.nick()
    }

    // The server vouches for prefixes, but anyone who saw a private line can send its text again.
    fn authenticates(&self, _route: &IrcRoute) -> bool {
        false
    }

    async fn listen(&self, offers: bool, public: bool) -> Result<(), ChannelError> {
        self.wants
            .store(u8::from(offers) | (u8::from(public) << 1), Ordering::SeqCst);
        Ok(())
    }

    async fn send_private(
        &self,
        _route: &IrcRoute,
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
            &self.hostid(),
        )
        .map_err(ChannelError::Line)?;
        // The JMP-0001 line after `from!to!command `: what goes in the pieces.
        let message = line
            .splitn(3, '!')
            .nth(2)
            .and_then(|rest| rest.split_once(' '))
            .map(|(_, message)| message)
            .ok_or(ChannelError::Invalid("a malformed line"))?;
        let lines = private_lines(to, command, message)
            .ok_or(ChannelError::Invalid("a private line IRC cannot carry"))?;
        if is_free_to_ask(command) {
            self.send_bulk(lines)
        } else {
            self.send_lines(lines)
        }
    }

    async fn ask_orderbook(&self) -> Result<(), ChannelError> {
        self.public("!orderbook")
    }

    async fn announce_offers(&self, pit: Pit, offers: &[Offer]) -> Result<(), ChannelError> {
        let texts: Vec<String> = offers.iter().map(Offer::to_command).collect();
        self.send_lines(offer_lines(&self.shared.channel, &texts))?;
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
            self.public(&format!("!cancel {oid}"))?;
        }
        Ok(())
    }

    // A throwaway nick on a way out of its own joins the pit and says it in public, so the line is not tied to
    // the nick that relays it.
    // On the side: a server that stalls the throwaway nick must not hold up the driver's loop.
    async fn publish_unlinked(&self, line: &str) -> Result<(), ChannelError> {
        let throwaway = NickIdentity::generate();
        let config = IrcConfig {
            server: self.shared.config.server.clone(),
            network: self.shared.config.network.clone(),
            timeout: self.shared.config.timeout,
        };
        let outbound = self.outbound.clone();
        let line = line.to_string();
        self.unlinked.spawn(async move {
            let Ok(temporary) = IrcChannel::connect(throwaway, config, &outbound).await else {
                return;
            };
            if temporary.public(&line).is_ok() {
                // The line has to leave the queue before the connection goes.
                for _ in 0..50 {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    let empty = temporary
                        .shared
                        .writer
                        .lock()
                        .ok()
                        .and_then(|w| {
                            w.as_ref()
                                .map(|w| w.round.capacity() == w.round.max_capacity())
                        })
                        .unwrap_or(true);
                    if empty {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            temporary.shutdown().await;
        })
    }

    async fn receive(&mut self, wait: Duration) -> Next<IrcRoute> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let Ok(inbox) = self.inbox.get_mut() else {
                return Next::Closed;
            };
            let arrived = match tokio::time::timeout_at(deadline, inbox.recv()).await {
                Ok(Some(arrived)) => arrived,
                Ok(None) => return Next::Closed,
                Err(_) => return Next::Timeout,
            };
            if let Some(message) = self.message(arrived, Instant::now()) {
                return Next::Message(message);
            }
        }
    }

    async fn shutdown(&self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Ok(mut writer) = self.shared.writer.lock()
            && let Some(quit) = build("QUIT", &["bye"])
            && let Some(w) = writer.take()
        {
            let _ = w.round.try_send(quit);
        }
        if let Ok(mut tasks) = self.tasks.lock() {
            for task in tasks.drain(..) {
                task.abort();
            }
        }
    }
}
