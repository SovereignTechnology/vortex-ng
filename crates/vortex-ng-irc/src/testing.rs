//! An IRC server in memory, for tests: this crate's and (feature `test-util`) other crates'. Nothing here is
//! needed to run vortex-ng.
//!
//! Enough of a server for JoinMarket: registration (`001`, an optional `005 NETWORK=`, `376`), a nick in use
//! refused with `433`, channels, `PRIVMSG` to a channel (to every other member) or to a nick, `PING`. It
//! records what it received and can send any line to a nick.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{RootCertStore, ServerConfig};

use crate::channel::IrcServer;
use crate::codec::parse;

#[derive(Default)]
struct State {
    nicks: HashMap<String, mpsc::UnboundedSender<String>>,
    members: HashMap<String, HashSet<String>>,
    received: Vec<(String, String)>,
}

/// The certificate authority that issued [`TestIrc::start_tls`]'s certificate (for `irc.test` and 127.0.0.1).
/// A fixture: its key was thrown away, and the server's key below protects nothing.
const TEST_CA: &[u8] = include_bytes!("testdata/ca.der");
/// An authority that issued nothing here.
const OTHER_CA: &[u8] = include_bytes!("testdata/other-ca.der");
const SERVER_CERT: &[u8] = include_bytes!("testdata/server.der");
const SERVER_KEY: &[u8] = include_bytes!("testdata/server.key.der");

fn roots_of(ca: &'static [u8]) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_slice(ca))
        .unwrap_or_else(|e| panic!("test CA: {e}"));
    roots
}

/// Roots that trust [`TestIrc::start_tls`]'s certificate.
pub fn test_roots() -> RootCertStore {
    roots_of(TEST_CA)
}

/// Roots of one certificate authority, from its DER certificate.
pub fn roots_from_der(der: &[u8]) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_slice(der).into_owned())
        .unwrap_or_else(|e| panic!("CA certificate: {e}"));
    roots
}

/// Roots that do not.
pub fn other_roots() -> RootCertStore {
    roots_of(OTHER_CA)
}

fn acceptor() -> TlsAcceptor {
    let key = PrivateKeyDer::try_from(SERVER_KEY.to_vec()).unwrap_or_else(|e| panic!("key: {e}"));
    let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .and_then(|builder| {
            builder.with_no_client_auth().with_single_cert(
                vec![CertificateDer::from_slice(SERVER_CERT).into_owned()],
                key,
            )
        })
        .unwrap_or_else(|e| panic!("TLS: {e}"));
    TlsAcceptor::from(Arc::new(config))
}

/// An IRC server on `127.0.0.1:<ephemeral>`.
pub struct TestIrc {
    addr: SocketAddr,
    tls: bool,
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}

impl Drop for TestIrc {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestIrc {
    /// A server that announces `network` in its `005` line, or none.
    pub async fn start(network: Option<&str>) -> TestIrc {
        TestIrc::listen(network, None).await
    }

    /// The same server behind TLS, with a certificate from [`test_roots`].
    pub async fn start_tls(network: Option<&str>) -> TestIrc {
        TestIrc::listen(network, Some(acceptor())).await
    }

    async fn listen(network: Option<&str>, tls: Option<TlsAcceptor>) -> TestIrc {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("address: {e}"));
        let state = Arc::new(Mutex::new(State::default()));
        let network = network.map(str::to_string);
        let tls_on = tls.is_some();
        let task_state = Arc::clone(&state);
        let task = tokio::spawn(async move {
            while let Ok((conn, _)) = listener.accept().await {
                let (state, network) = (Arc::clone(&task_state), network.clone());
                let tls = tls.clone();
                tokio::spawn(async move {
                    let _ = match tls {
                        Some(tls) => match tls.accept(conn).await {
                            Ok(conn) => serve(conn, state, network).await,
                            Err(e) => Err(e.to_string()),
                        },
                        None => serve(conn, state, network).await,
                    };
                });
            }
        });
        TestIrc {
            addr,
            tls: tls_on,
            state,
            task,
        }
    }

    /// How to reach it.
    pub fn server(&self) -> IrcServer {
        IrcServer {
            host: self.addr.ip().to_string(),
            port: self.addr.port(),
            expected_network: None,
            tls: self.tls,
        }
    }

    /// Nicks registered now.
    pub fn nicks(&self) -> Vec<String> {
        self.state
            .lock()
            .map(|s| s.nicks.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Every line received after registration: the nick, the line.
    pub fn received(&self) -> Vec<(String, String)> {
        self.state
            .lock()
            .map(|s| s.received.clone())
            .unwrap_or_default()
    }

    /// Send a raw line (without `\r\n`) to `nick`.
    pub fn send(&self, nick: &str, line: &str) -> bool {
        self.state
            .lock()
            .ok()
            .and_then(|s| {
                s.nicks
                    .get(nick)
                    .map(|tx| tx.send(format!("{line}\r\n")).is_ok())
            })
            .unwrap_or(false)
    }
}

async fn serve<S: AsyncRead + AsyncWrite + Send + 'static>(
    conn: S,
    state: Arc<Mutex<State>>,
    network: Option<String>,
) -> Result<(), String> {
    let (read, mut write) = tokio::io::split(conn);
    let mut reader = BufReader::new(read);
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let writer = tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if write.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    });
    let mut nick: Option<String> = None;
    let mut user = false;
    let prefix = |n: &str| format!(":{n}!user@test");
    let result = loop {
        let mut line = String::new();
        use tokio::io::AsyncBufReadExt;
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => break Ok(()),
            Ok(_) => {}
        }
        let Some(message) = parse(&line) else {
            continue;
        };
        let Ok(mut s) = state.lock() else {
            break Ok(());
        };
        if let Some(n) = &nick {
            s.received.push((n.clone(), line.trim_end().to_string()));
        }
        match message.command.as_str() {
            "NICK" => {
                let wanted = message.params.first().cloned().unwrap_or_default();
                if s.nicks.contains_key(&wanted) {
                    let _ = tx.send(format!(
                        ":test 433 * {wanted} :Nickname is already in use\r\n"
                    ));
                    continue;
                }
                s.nicks.insert(wanted.clone(), tx.clone());
                nick = Some(wanted);
            }
            "USER" => user = true,
            "PING" => {
                let token = message.params.first().cloned().unwrap_or_default();
                let _ = tx.send(format!(":test PONG test :{token}\r\n"));
            }
            "JOIN" => {
                let (Some(n), Some(channel)) = (&nick, message.params.first()) else {
                    continue;
                };
                s.members
                    .entry(channel.to_ascii_lowercase())
                    .or_default()
                    .insert(n.clone());
                let _ = tx.send(format!("{} JOIN {channel}\r\n", prefix(n)));
            }
            "PRIVMSG" => {
                let (Some(n), [target, text]) = (&nick, message.params.as_slice()) else {
                    continue;
                };
                let relayed = format!("{} PRIVMSG {target} :{text}\r\n", prefix(n));
                if target.starts_with('#') {
                    let members = s
                        .members
                        .get(&target.to_ascii_lowercase())
                        .cloned()
                        .unwrap_or_default();
                    for member in members.iter().filter(|m| *m != n) {
                        if let Some(peer) = s.nicks.get(member) {
                            let _ = peer.send(relayed.clone());
                        }
                    }
                } else if let Some(peer) = s.nicks.get(target) {
                    let _ = peer.send(relayed);
                }
            }
            "QUIT" => break Ok(()),
            _ => {}
        }
        if user
            && let Some(n) = &nick
            && message.command == "USER"
        {
            let _ = tx.send(format!(":test 001 {n} :Welcome\r\n"));
            let isupport = match &network {
                Some(network) => {
                    format!(":test 005 {n} NETWORK={network} CHANTYPES=# :are supported\r\n")
                }
                None => format!(":test 005 {n} CHANTYPES=# :are supported\r\n"),
            };
            let _ = tx.send(isupport);
            let _ = tx.send(format!(":test 376 {n} :End of MOTD\r\n"));
        }
    };
    if let (Some(n), Ok(mut s)) = (&nick, state.lock()) {
        s.nicks.remove(n);
        for members in s.members.values_mut() {
            members.remove(n);
        }
    }
    writer.abort();
    result
}
