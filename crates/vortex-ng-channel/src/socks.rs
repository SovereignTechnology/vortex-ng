//! How a nick reaches the network: directly, through a SOCKS5 proxy, or through in-process Tor.
//!
//! [`Outbound`] says how; each nick takes a way out of its own from it, so that with a proxy that can
//! isolate streams no two nicks of a process share a circuit. A channel that opens its own TCP streams
//! (onion directories, IRC) asks for a [`NickConnector`]; one that needs a SOCKS address to hand to a
//! library (Nostr, through nostr-sdk, which cannot send SOCKS credentials) asks for a [`NickPath`]: a minimal
//! local SOCKS5 server (RFC 1928, `CONNECT` only, no authentication) on `127.0.0.1:<ephemeral>` in front of
//! the nick's own connector. Host names are passed through unresolved, so DNS happens at the far end.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional};

/// A byte stream a [`NickConnector`] opened: TCP, or a Tor stream.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Stream for T {}

/// A [`Stream`] of whichever kind.
pub type BoxedStream = Box<dyn Stream>;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Opens outbound streams for the shim.
pub trait Connector: Send + Sync + 'static {
    /// The stream type.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    /// Connect to `host:port` (`host` may be a name; resolve it at the far end).
    fn connect(
        &self,
        host: String,
        port: u16,
    ) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

/// Plain TCP, resolving locally. For tests and for running without Tor.
#[derive(Clone, Copy, Debug, Default)]
pub struct DirectConnector;

impl Connector for DirectConnector {
    type Stream = TcpStream;
    async fn connect(&self, host: String, port: u16) -> io::Result<TcpStream> {
        // The system's resolver would be asked for the name, telling whoever runs it where we are going.
        if is_onion(&host) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an onion address needs a Tor proxy",
            ));
        }
        TcpStream::connect((host.as_str(), port)).await
    }
}

/// Whether `host` is an onion name, however it is written.
fn is_onion(host: &str) -> bool {
    host.trim_end_matches('.')
        .to_ascii_lowercase()
        .ends_with(".onion")
}

/// Outbound through another SOCKS5 proxy, normally under a username and password of this connector's own.
///
/// For a Tor daemon's SOCKS port: Tor gives streams with different SOCKS credentials circuits of their own
/// (`IsolateSOCKSAuth`, its default), so two connectors never share one. nostr-sdk cannot send SOCKS
/// credentials itself; a nick's [`SocksShim`] in front of one of these does it for all of that nick's
/// connections. Host names are passed on unresolved.
///
/// An isolated connector requires username/password authentication (RFC 1929): a proxy that does not take
/// it could not keep nicks apart, and is refused rather than used. A [`UpstreamSocks::plain`] connector
/// uses no authentication, for a proxy that is already one nick's own.
#[derive(Clone)]
pub struct UpstreamSocks {
    proxy: SocketAddr,
    credentials: Option<(String, String)>,
}

impl std::fmt::Debug for UpstreamSocks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamSocks")
            .field("proxy", &self.proxy)
            .finish_non_exhaustive()
    }
}

impl UpstreamSocks {
    /// Through `proxy`, apart from every other connector: fresh random credentials.
    pub fn isolated(proxy: SocketAddr) -> UpstreamSocks {
        use vortex_ng_core::bitcoin::hex::DisplayHex;
        use vortex_ng_core::tx::random_bytes;
        UpstreamSocks {
            proxy,
            credentials: Some((
                random_bytes::<16>()[..].to_lower_hex_string(),
                random_bytes::<16>()[..].to_lower_hex_string(),
            )),
        }
    }

    /// Through `proxy` without authentication: no isolation of its own.
    pub fn plain(proxy: SocketAddr) -> UpstreamSocks {
        UpstreamSocks {
            proxy,
            credentials: None,
        }
    }

    /// The SOCKS username this connector presents (what the proxy isolates on), if any.
    pub fn username(&self) -> Option<&str> {
        self.credentials.as_ref().map(|(user, _)| user.as_str())
    }
}

const AUTH_USERPASS: u8 = 2;
const AUTH_VERSION: u8 = 1;

impl Connector for UpstreamSocks {
    type Stream = TcpStream;
    async fn connect(&self, host: String, port: u16) -> io::Result<TcpStream> {
        let mut conn = TcpStream::connect(self.proxy).await?;
        let Some((username, password)) = &self.credentials else {
            conn.write_all(&[VERSION, 1, NO_AUTH]).await?;
            let mut chosen = [0u8; 2];
            conn.read_exact(&mut chosen).await?;
            if chosen != [VERSION, NO_AUTH] {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "the proxy wants authentication",
                ));
            }
            return request_connect(conn, &host, port).await;
        };
        // Offer username/password only: without it the proxy cannot keep nicks apart.
        conn.write_all(&[VERSION, 1, AUTH_USERPASS]).await?;
        let mut chosen = [0u8; 2];
        conn.read_exact(&mut chosen).await?;
        if chosen != [VERSION, AUTH_USERPASS] {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the proxy takes no SOCKS username and password, so it cannot isolate streams",
            ));
        }
        let (user, pass) = (username.as_bytes(), password.as_bytes());
        let (Ok(user_len), Ok(pass_len)) = (u8::try_from(user.len()), u8::try_from(pass.len()))
        else {
            return Err(bad("credentials too long"));
        };
        let mut auth = vec![AUTH_VERSION, user_len];
        auth.extend_from_slice(user);
        auth.push(pass_len);
        auth.extend_from_slice(pass);
        conn.write_all(&auth).await?;
        let mut status = [0u8; 2];
        conn.read_exact(&mut status).await?;
        if status[1] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the proxy refused the SOCKS credentials",
            ));
        }
        request_connect(conn, &host, port).await
    }
}

/// The SOCKS5 `CONNECT` request on an authenticated connection, and the reply.
async fn request_connect(mut conn: TcpStream, host: &str, port: u16) -> io::Result<TcpStream> {
    // CONNECT, the address as given: a name is resolved by the proxy, never here.
    let mut request = vec![VERSION, CONNECT, 0];
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        request.push(1);
        request.extend_from_slice(&v4.octets());
    } else if let Ok(v6) = host.parse::<Ipv6Addr>() {
        request.push(4);
        request.extend_from_slice(&v6.octets());
    } else {
        let Ok(len) = u8::try_from(host.len()) else {
            return Err(bad("host name too long"));
        };
        request.push(3);
        request.push(len);
        request.extend_from_slice(host.as_bytes());
    }
    request.extend_from_slice(&port.to_be_bytes());
    conn.write_all(&request).await?;
    let mut head = [0u8; 4];
    conn.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(bad("not SOCKS5"));
    }
    if head[1] != REPLY_OK {
        let kind = if head[1] == 5 || head[1] == REPLY_UNREACHABLE {
            io::ErrorKind::ConnectionRefused
        } else {
            io::ErrorKind::Other
        };
        return Err(io::Error::new(
            kind,
            format!("the proxy answered {}", head[1]),
        ));
    }
    // The bound address the reply carries is of no use: read past it.
    let rest = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut len = [0u8; 1];
            conn.read_exact(&mut len).await?;
            usize::from(len[0]) + 2
        }
        _ => return Err(bad("address type")),
    };
    let mut bound = vec![0u8; rest];
    conn.read_exact(&mut bound).await?;
    Ok(conn)
}

/// One nick's way to open its own byte streams, as [`Outbound`] says: for channels that speak their own
/// protocol over TCP (onion directories, IRC). Each one from an isolating [`Outbound`] has its own
/// credentials or Tor client, so its streams share no circuit with another nick's.
#[derive(Debug)]
pub enum NickConnector {
    /// Plain TCP.
    Direct,
    /// Through a SOCKS5 proxy.
    Socks(UpstreamSocks),
    /// Through in-process Tor.
    #[cfg(feature = "tor")]
    Tor(crate::tor::TorConnector),
}

impl NickConnector {
    /// Open a stream to `host:port` (`host` may be a name, `.onion` included when the way out is Tor).
    pub async fn connect(&self, host: &str, port: u16) -> io::Result<BoxedStream> {
        Ok(match self {
            NickConnector::Direct => Box::new(DirectConnector.connect(host.into(), port).await?),
            NickConnector::Socks(socks) => Box::new(socks.connect(host.into(), port).await?),
            #[cfg(feature = "tor")]
            NickConnector::Tor(tor) => Box::new(tor.connect(host.into(), port).await?),
        })
    }

    /// Whether streams leave this machine directly (the far end sees its address).
    pub fn is_direct(&self) -> bool {
        matches!(self, NickConnector::Direct)
    }
}

/// How nicks reach their relays.
///
/// Each nick takes a [`NickPath`] of its own from it ([`Outbound::path`]), so that with a proxy that can
/// isolate streams no two nicks of this process share a path: not a maker and the throwaway nick it sends
/// `!hp2` from, nor two rounds' takers.
#[derive(Clone, Default)]
pub enum Outbound {
    /// Directly: the relays see this machine's address.
    #[default]
    Direct,
    /// Through one SOCKS5 address as it is, for every nick alike. No isolation unless the address is
    /// already a path of one nick's own (a [`SocksShim`]).
    Proxy(SocketAddr),
    /// Through a SOCKS5 proxy that isolates streams by username and password (a Tor daemon's SOCKS port):
    /// every nick gets credentials of its own ([`UpstreamSocks`]).
    IsolatingProxy(SocketAddr),
    /// Through in-process Tor: every nick gets an isolated client of its own (feature `tor`).
    #[cfg(feature = "tor")]
    Tor(Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>),
}

impl std::fmt::Debug for Outbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outbound::Direct => f.write_str("Direct"),
            Outbound::Proxy(addr) => write!(f, "Proxy({addr})"),
            Outbound::IsolatingProxy(addr) => write!(f, "IsolatingProxy({addr})"),
            #[cfg(feature = "tor")]
            Outbound::Tor(_) => f.write_str("Tor"),
        }
    }
}

impl Outbound {
    /// Whether relays see this machine's address.
    pub fn is_direct(&self) -> bool {
        matches!(self, Outbound::Direct)
    }

    /// A connector for one nick's own streams.
    pub fn connector(&self) -> NickConnector {
        match self {
            Outbound::Direct => NickConnector::Direct,
            Outbound::Proxy(addr) => NickConnector::Socks(UpstreamSocks::plain(*addr)),
            Outbound::IsolatingProxy(addr) => NickConnector::Socks(UpstreamSocks::isolated(*addr)),
            #[cfg(feature = "tor")]
            Outbound::Tor(base) => NickConnector::Tor(crate::tor::TorConnector::isolated(base)),
        }
    }

    /// A path for one nick. Keep it for as long as the nick is connected.
    pub async fn path(&self) -> io::Result<NickPath> {
        Ok(match self {
            Outbound::Direct => NickPath {
                proxy: None,
                shim: None,
            },
            Outbound::Proxy(addr) => NickPath {
                proxy: Some(*addr),
                shim: None,
            },
            Outbound::IsolatingProxy(addr) => {
                NickPath::through(SocksShim::start(UpstreamSocks::isolated(*addr)).await?)
            }
            #[cfg(feature = "tor")]
            Outbound::Tor(base) => NickPath::through(crate::tor::nick_proxy(base).await?),
        })
    }
}

/// One nick's way out: the SOCKS5 address its relay connections use, if any, and the local shim behind it.
#[derive(Debug)]
pub struct NickPath {
    proxy: Option<SocketAddr>,
    shim: Option<SocksShim>,
}

impl NickPath {
    fn through(shim: SocksShim) -> NickPath {
        NickPath {
            proxy: Some(shim.addr()),
            shim: Some(shim),
        }
    }

    /// The SOCKS5 address to connect through; `None` for a direct connection.
    pub fn proxy(&self) -> Option<SocketAddr> {
        self.proxy
    }

    /// Whether this path is a shim of the nick's own.
    pub fn is_own(&self) -> bool {
        self.shim.is_some()
    }
}

/// A running shim; stops accepting when dropped.
#[derive(Debug)]
pub struct SocksShim {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl SocksShim {
    /// Listen on `127.0.0.1:<ephemeral>` in front of `connector`.
    pub async fn start<C: Connector>(connector: C) -> io::Result<SocksShim> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let connector = Arc::new(connector);
        let task = tokio::spawn(async move {
            while let Ok((conn, _)) = listener.accept().await {
                let connector = Arc::clone(&connector);
                tokio::spawn(async move {
                    let _ = serve(conn, connector).await;
                });
            }
        });
        Ok(SocksShim { addr, task })
    }

    /// The address to give as the proxy.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for SocksShim {
    fn drop(&mut self) {
        self.task.abort();
    }
}

const VERSION: u8 = 5;
const NO_AUTH: u8 = 0;
const NO_METHOD: u8 = 0xff;
const CONNECT: u8 = 1;
const REPLY_OK: u8 = 0;
const REPLY_FAILURE: u8 = 1;
const REPLY_UNREACHABLE: u8 = 4;
const REPLY_COMMAND: u8 = 7;
const REPLY_ADDRESS: u8 = 8;

async fn reply(conn: &mut TcpStream, code: u8) -> io::Result<()> {
    conn.write_all(&[VERSION, code, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
}

fn bad(why: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why)
}

async fn serve<C: Connector>(mut conn: TcpStream, connector: Arc<C>) -> io::Result<()> {
    // Greeting: VER NMETHODS METHODS...
    let mut head = [0u8; 2];
    conn.read_exact(&mut head).await?;
    if head[0] != VERSION || head[1] == 0 {
        return Err(bad("not SOCKS5"));
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    conn.read_exact(&mut methods).await?;
    if !methods.contains(&NO_AUTH) {
        conn.write_all(&[VERSION, NO_METHOD]).await?;
        return Err(bad("no acceptable method"));
    }
    conn.write_all(&[VERSION, NO_AUTH]).await?;

    // Request: VER CMD RSV ATYP ADDR PORT
    let mut req = [0u8; 4];
    conn.read_exact(&mut req).await?;
    if req[0] != VERSION {
        return Err(bad("not SOCKS5"));
    }
    if req[1] != CONNECT {
        reply(&mut conn, REPLY_COMMAND).await?;
        return Err(bad("only CONNECT"));
    }
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            conn.read_exact(&mut a).await?;
            Ipv4Addr::from(a).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            conn.read_exact(&mut len).await?;
            let mut name = vec![0u8; usize::from(len[0])];
            conn.read_exact(&mut name).await?;
            match String::from_utf8(name) {
                Ok(n) if !n.is_empty() && n.is_ascii() => n,
                _ => {
                    reply(&mut conn, REPLY_ADDRESS).await?;
                    return Err(bad("bad host name"));
                }
            }
        }
        4 => {
            let mut a = [0u8; 16];
            conn.read_exact(&mut a).await?;
            Ipv6Addr::from(a).to_string()
        }
        _ => {
            reply(&mut conn, REPLY_ADDRESS).await?;
            return Err(bad("address type"));
        }
    };
    let mut port = [0u8; 2];
    conn.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);

    let mut upstream = match connector.connect(host, port).await {
        Ok(s) => s,
        Err(e) => {
            let code = if e.kind() == io::ErrorKind::ConnectionRefused {
                REPLY_UNREACHABLE
            } else {
                REPLY_FAILURE
            };
            reply(&mut conn, code).await?;
            return Err(e);
        }
    };
    reply(&mut conn, REPLY_OK).await?;
    copy_bidirectional(&mut conn, &mut upstream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_onion_name_never_reaches_the_system_resolver() {
        for host in ["abcdef.onion", "ABCDEF.ONION", "abcdef.onion."] {
            let refused = DirectConnector.connect(host.to_string(), 80).await;
            assert_eq!(
                refused.err().map(|e| e.kind()),
                Some(io::ErrorKind::InvalidInput),
                "{host}"
            );
        }
        assert!(!is_onion("onion.example.org"));
    }

    async fn echo_server() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut c, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = c.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn connects_by_name_and_relays_bytes() {
        let echo = echo_server().await;
        let shim = SocksShim::start(DirectConnector).await.unwrap();
        let mut c = TcpStream::connect(shim.addr()).await.unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut m = [0u8; 2];
        c.read_exact(&mut m).await.unwrap();
        assert_eq!(m, [5, 0]);
        let name = b"localhost";
        let mut req = vec![5, 1, 0, 3, name.len() as u8];
        req.extend_from_slice(name);
        req.extend_from_slice(&echo.port().to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], REPLY_OK);
        c.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        c.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"ping");
    }

    #[tokio::test]
    async fn an_upstream_proxy_sees_each_connector_under_its_own_name() {
        use crate::testing::AuthSocks;

        let echo = echo_server().await;
        let proxy = AuthSocks::start().await.unwrap();
        let (one, two) = (
            UpstreamSocks::isolated(proxy.addr()),
            UpstreamSocks::isolated(proxy.addr()),
        );
        assert_ne!(one.username(), two.username());
        assert!(one.username().is_some());
        assert_eq!(one.username().map(str::len), Some(32));
        assert!(!format!("{one:?}").contains(one.username().unwrap_or_default()));
        // Bytes pass both ways; an address goes as an address, a name as a name (resolved at the proxy).
        for (connector, host) in [
            (&one, "127.0.0.1"),
            (&two, "localhost"),
            (&one, "echo.test"),
        ] {
            let mut stream = connector
                .connect(host.to_string(), echo.port())
                .await
                .unwrap();
            stream.write_all(b"ping").await.unwrap();
            let mut back = [0u8; 4];
            stream.read_exact(&mut back).await.unwrap();
            assert_eq!(&back, b"ping");
        }
        let port = echo.port();
        assert_eq!(
            proxy.seen(),
            vec![
                (
                    one.username().unwrap_or_default().to_string(),
                    format!("127.0.0.1:{port}")
                ),
                (
                    two.username().unwrap_or_default().to_string(),
                    format!("localhost:{port}")
                ),
                (
                    one.username().unwrap_or_default().to_string(),
                    format!("echo.test:{port}")
                ),
            ]
        );
        // Nothing listens there: the failure is the proxy's to report.
        let dead = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let refused = one
            .connect("127.0.0.1".into(), dead_port)
            .await
            .unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[tokio::test]
    async fn the_test_proxy_reaches_only_the_onions_it_was_given() {
        use crate::testing::AuthSocks;

        let echo = echo_server().await;
        let (here, elsewhere) = (
            format!("{}.onion", "a".repeat(56)),
            format!("{}.onion", "b".repeat(56)),
        );
        let onions = [(here.clone(), std::net::IpAddr::V4(Ipv4Addr::LOCALHOST))].into();
        let proxy = AuthSocks::start_with_onions(onions).await.unwrap();
        let connector = UpstreamSocks::isolated(proxy.addr());
        let mut stream = connector.connect(here.clone(), echo.port()).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        stream.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"ping");
        // Any other onion is unreachable, as through Tor, and never looked up.
        let refused = connector
            .connect(elsewhere.clone(), echo.port())
            .await
            .unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);
        let asked: Vec<String> = proxy.seen().into_iter().map(|(_, to)| to).collect();
        assert_eq!(
            asked,
            vec![
                format!("{here}:{}", echo.port()),
                format!("{elsewhere}:{}", echo.port())
            ]
        );
    }

    #[tokio::test]
    async fn a_proxy_that_cannot_isolate_is_refused() {
        // Our own shim speaks SOCKS5 without authentication: as an upstream it could not keep nicks apart.
        let echo = echo_server().await;
        let plain = SocksShim::start(DirectConnector).await.unwrap();
        let refused = UpstreamSocks::isolated(plain.addr())
            .connect("127.0.0.1".into(), echo.port())
            .await
            .unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::Unsupported);
    }

    #[tokio::test]
    async fn each_nick_connector_goes_the_way_its_outbound_says() {
        use crate::testing::AuthSocks;

        let echo = echo_server().await;
        let ping = |mut stream: BoxedStream| async move {
            stream.write_all(b"ping").await.unwrap();
            let mut back = [0u8; 4];
            stream.read_exact(&mut back).await.unwrap();
            assert_eq!(&back, b"ping");
        };
        // Directly.
        let direct = Outbound::Direct.connector();
        assert!(direct.is_direct());
        ping(direct.connect("127.0.0.1", echo.port()).await.unwrap()).await;
        // Through a proxy that is one nick's own: no authentication.
        let shim = SocksShim::start(DirectConnector).await.unwrap();
        let plain = Outbound::Proxy(shim.addr()).connector();
        assert!(!plain.is_direct());
        ping(plain.connect("localhost", echo.port()).await.unwrap()).await;
        // Through an isolating proxy: each connector under credentials of its own, names resolved there.
        let proxy = AuthSocks::start().await.unwrap();
        let outbound = Outbound::IsolatingProxy(proxy.addr());
        for _ in 0..2 {
            ping(
                outbound
                    .connector()
                    .connect("echo.test", echo.port())
                    .await
                    .unwrap(),
            )
            .await;
        }
        assert_eq!(proxy.usernames().len(), 2);
        assert!(
            proxy
                .seen()
                .iter()
                .all(|(_, to)| *to == format!("echo.test:{}", echo.port()))
        );
        // An isolating connector refuses a proxy that cannot isolate.
        let wrong = Outbound::IsolatingProxy(shim.addr()).connector();
        assert!(wrong.connect("127.0.0.1", echo.port()).await.is_err());
    }

    #[tokio::test]
    async fn refuses_auth_only_clients_and_other_commands() {
        let shim = SocksShim::start(DirectConnector).await.unwrap();
        // Only username/password offered.
        let mut c = TcpStream::connect(shim.addr()).await.unwrap();
        c.write_all(&[5, 1, 2]).await.unwrap();
        let mut m = [0u8; 2];
        c.read_exact(&mut m).await.unwrap();
        assert_eq!(m, [5, NO_METHOD]);
        // BIND is not supported.
        let mut c = TcpStream::connect(shim.addr()).await.unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        c.read_exact(&mut m).await.unwrap();
        c.write_all(&[5, 2, 0, 1, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], REPLY_COMMAND);
    }
}
