//! Helpers for tests, this crate's and (with feature `test-util`) other crates'. Nothing here is needed to
//! run vortex-ng.

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use vortex_ng_core::line::PrivMsg;
use vortex_ng_core::nick::NickIdentity;
use vortex_ng_core::offer::{Offer, Pit};

use crate::{Channel, ChannelError, Incoming, Next};

/// A SOCKS5 proxy on loopback that behaves, as far as a client can tell, like a Tor daemon's SOCKS port:
/// it insists on a username and password, takes any, and connects on the client's behalf, resolving names
/// itself. It remembers which username asked for which destination, so a test can see whether two nicks
/// came in under different credentials (which Tor would give circuits of their own).
///
/// Any host name ending in `.test` is taken to be this machine: a relay named so can only be reached
/// through the proxy, which shows that nothing connected to it directly. A `.onion` name is reached only
/// when the test gave its address ([`AuthSocks::start_with_onions`]); any other is refused, as Tor refuses
/// an onion it cannot find, and never looked up.
#[derive(Debug)]
pub struct AuthSocks {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<(String, String)>>>,
    task: JoinHandle<()>,
}

impl AuthSocks {
    /// Listen on `127.0.0.1:<ephemeral>`.
    pub async fn start() -> io::Result<AuthSocks> {
        AuthSocks::start_with_onions(HashMap::new()).await
    }

    /// Listen on `127.0.0.1:<ephemeral>`, with `onions` saying where each onion name (`<name>.onion`, any
    /// port) really is.
    pub async fn start_with_onions(onions: HashMap<String, IpAddr>) -> io::Result<AuthSocks> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let onions = Arc::new(onions);
        let task = tokio::spawn(async move {
            while let Ok((conn, _)) = listener.accept().await {
                let record = Arc::clone(&record);
                let onions = Arc::clone(&onions);
                tokio::spawn(async move {
                    let _ = serve(conn, record, &onions).await;
                });
            }
        });
        Ok(AuthSocks { addr, seen, task })
    }

    /// The proxy's address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Every connection asked for so far: the username, and the destination as `host:port`.
    pub fn seen(&self) -> Vec<(String, String)> {
        self.seen
            .lock()
            .map(|seen| seen.clone())
            .unwrap_or_default()
    }

    /// The different usernames seen so far.
    pub fn usernames(&self) -> BTreeSet<String> {
        self.seen().into_iter().map(|(user, _)| user).collect()
    }
}

impl Drop for AuthSocks {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn bad(why: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why)
}

async fn serve(
    mut conn: TcpStream,
    seen: Arc<Mutex<Vec<(String, String)>>>,
    onions: &HashMap<String, IpAddr>,
) -> io::Result<()> {
    // Greeting: only username/password will do.
    let mut head = [0u8; 2];
    conn.read_exact(&mut head).await?;
    let mut methods = vec![0u8; usize::from(head[1])];
    conn.read_exact(&mut methods).await?;
    if head[0] != 5 || !methods.contains(&2) {
        conn.write_all(&[5, 0xff]).await?;
        return Err(bad("no username/password offered"));
    }
    conn.write_all(&[5, 2]).await?;
    // RFC 1929: VER ULEN UNAME PLEN PASSWD.
    let mut field = [0u8; 2];
    conn.read_exact(&mut field).await?;
    let mut user = vec![0u8; usize::from(field[1])];
    conn.read_exact(&mut user).await?;
    let mut len = [0u8; 1];
    conn.read_exact(&mut len).await?;
    let mut pass = vec![0u8; usize::from(len[0])];
    conn.read_exact(&mut pass).await?;
    conn.write_all(&[1, 0]).await?;
    // CONNECT.
    let mut request = [0u8; 4];
    conn.read_exact(&mut request).await?;
    if request[..2] != [5, 1] {
        return Err(bad("only CONNECT"));
    }
    let host = match request[3] {
        1 => {
            let mut a = [0u8; 4];
            conn.read_exact(&mut a).await?;
            Ipv4Addr::from(a).to_string()
        }
        3 => {
            conn.read_exact(&mut len).await?;
            let mut name = vec![0u8; usize::from(len[0])];
            conn.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| bad("host name"))?
        }
        4 => {
            let mut a = [0u8; 16];
            conn.read_exact(&mut a).await?;
            Ipv6Addr::from(a).to_string()
        }
        _ => return Err(bad("address type")),
    };
    let mut port = [0u8; 2];
    conn.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    if let Ok(mut seen) = seen.lock() {
        seen.push((
            String::from_utf8_lossy(&user).into_owned(),
            format!("{host}:{port}"),
        ));
    }
    let connected = if host.ends_with(".test") {
        TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await
    } else if host.ends_with(".onion") {
        match onions.get(&host) {
            Some(ip) => TcpStream::connect((*ip, port)).await,
            None => {
                // Host unreachable.
                conn.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                return Err(bad("an onion nobody serves"));
            }
        }
    } else {
        TcpStream::connect((host.as_str(), port)).await
    };
    let mut upstream = match connected {
        Ok(upstream) => upstream,
        Err(e) => {
            conn.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            return Err(e);
        }
    };
    conn.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    copy_bidirectional(&mut conn, &mut upstream).await?;
    Ok(())
}

/// The route of a [`MockChannel`]: a label the test picks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MockRoute(pub String);

/// What a [`MockChannel`] was asked to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sent {
    /// `listen`.
    Listen {
        /// Offers asked for.
        offers: bool,
        /// Public messages asked for.
        public: bool,
    },
    /// `send_private`.
    Private {
        /// The route given.
        route: MockRoute,
        /// The recipient.
        to: String,
        /// The command.
        command: String,
        /// The body.
        body: String,
    },
    /// `ask_orderbook`.
    AskOrderbook,
    /// `announce_offers`.
    Announce(Pit, Vec<Offer>),
    /// `withdraw_offers`.
    Withdraw(Pit),
    /// `publish_unlinked`.
    Unlinked(String),
}

/// A channel in memory: a test delivers messages to it through its [`MockHandle`] and reads back what it
/// was asked to send. `receive` is cancel-safe.
pub struct MockChannel {
    nick: String,
    authenticated: bool,
    inbox: Mutex<mpsc::UnboundedReceiver<Next<MockRoute>>>,
    sent: Arc<Mutex<Vec<Sent>>>,
    failing: Arc<std::sync::atomic::AtomicBool>,
}

/// The test's side of a [`MockChannel`].
#[derive(Clone)]
pub struct MockHandle {
    inbox: mpsc::UnboundedSender<Next<MockRoute>>,
    sent: Arc<Mutex<Vec<Sent>>>,
    failing: Arc<std::sync::atomic::AtomicBool>,
}

/// A mock channel for `nick`; `authenticated` is what [`Channel::authenticates`] answers.
pub fn mock_channel(nick: &str, authenticated: bool) -> (MockChannel, MockHandle) {
    let (tx, rx) = mpsc::unbounded_channel();
    let sent = Arc::new(Mutex::new(Vec::new()));
    let failing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    (
        MockChannel {
            nick: nick.to_string(),
            authenticated,
            inbox: Mutex::new(rx),
            sent: Arc::clone(&sent),
            failing: Arc::clone(&failing),
        },
        MockHandle {
            inbox: tx,
            sent,
            failing,
        },
    )
}

impl MockHandle {
    /// Deliver a message to the channel.
    pub fn deliver(&self, incoming: Incoming<MockRoute>) {
        let _ = self.inbox.send(Next::Message(incoming));
    }

    /// Deliver a private line `!command body` from `from` to `to`, as if verified.
    pub fn deliver_private(
        &self,
        from: &NickIdentity,
        to: &str,
        command: &str,
        body: &str,
        route: &str,
    ) {
        self.deliver(Incoming::Private {
            msg: PrivMsg {
                from: from.nick().to_string(),
                to: to.to_string(),
                command: command.to_string(),
                body: body.to_string(),
                key: *from.public(),
            },
            route: MockRoute(route.to_string()),
        });
    }

    /// Make the channel report that it closed.
    pub fn close(&self) {
        let _ = self.inbox.send(Next::Closed);
    }

    /// Everything the channel was asked to do, in order.
    pub fn sent(&self) -> Vec<Sent> {
        self.sent.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// Make every send fail (or succeed again).
    pub fn fail_sends(&self, failing: bool) {
        self.failing
            .store(failing, std::sync::atomic::Ordering::SeqCst);
    }
}

impl MockChannel {
    fn record(&self, sent: Sent) -> Result<(), ChannelError> {
        if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ChannelError::Transport("mock: sends fail".into()));
        }
        if let Ok(mut log) = self.sent.lock() {
            log.push(sent);
        }
        Ok(())
    }
}

impl Channel for MockChannel {
    type Route = MockRoute;

    fn nick(&self) -> &str {
        &self.nick
    }

    fn authenticates(&self, _route: &MockRoute) -> bool {
        self.authenticated
    }

    async fn listen(&self, offers: bool, public: bool) -> Result<(), ChannelError> {
        self.record(Sent::Listen { offers, public })
    }

    async fn send_private(
        &self,
        route: &MockRoute,
        to: &str,
        command: &str,
        body: &str,
    ) -> Result<(), ChannelError> {
        self.record(Sent::Private {
            route: route.clone(),
            to: to.to_string(),
            command: command.to_string(),
            body: body.to_string(),
        })
    }

    async fn ask_orderbook(&self) -> Result<(), ChannelError> {
        self.record(Sent::AskOrderbook)
    }

    async fn announce_offers(&self, pit: Pit, offers: &[Offer]) -> Result<(), ChannelError> {
        self.record(Sent::Announce(pit, offers.to_vec()))
    }

    async fn withdraw_offers(&self, pit: Pit) -> Result<(), ChannelError> {
        self.record(Sent::Withdraw(pit))
    }

    async fn publish_unlinked(&self, line: &str) -> Result<(), ChannelError> {
        self.record(Sent::Unlinked(line.to_string()))
    }

    async fn receive(&mut self, wait: std::time::Duration) -> Next<MockRoute> {
        let Ok(inbox) = self.inbox.get_mut() else {
            return Next::Closed;
        };
        match tokio::time::timeout(wait, inbox.recv()).await {
            Ok(Some(next)) => next,
            Ok(None) => Next::Closed,
            Err(_) => Next::Timeout,
        }
    }

    async fn shutdown(&self) {}
}
