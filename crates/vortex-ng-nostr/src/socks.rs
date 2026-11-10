//! A minimal local SOCKS5 server (RFC 1928, `CONNECT` only, no authentication) in front of a
//! [`Connector`], so each nick's relay connections get their own outbound path.
//!
//! nostr-sdk's proxy support has no SOCKS credentials, so Tor cannot isolate nicks by SOCKS auth. Instead
//! each nick gets its own shim on `127.0.0.1:<ephemeral>` backed by its own isolated Tor client
//! (`crate::tor`, feature `tor`): one nick, one circuit. Host names are passed through unresolved, so DNS
//! happens at the far end (inside Tor). The shim listens on loopback only.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional};
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
        TcpStream::connect((host.as_str(), port)).await
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
    use std::time::Duration;

    use nostr_sdk::prelude::MockRelay;

    use super::*;
    use crate::client::{Incoming, NickClient, unix_now};
    use crate::event::public_event;
    use crate::keys::NickKeys;
    use vortex_ng_core::command::Command;

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

    #[tokio::test(flavor = "multi_thread")]
    async fn a_nick_client_reaches_its_relay_through_the_shim() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let shim = SocksShim::start(DirectConnector).await.unwrap();
        let wait = Duration::from_secs(10);
        let relays = vec![url.clone()];
        let mut maker = NickClient::connect(
            NickKeys::generate(),
            "regtest",
            &relays,
            Some(shim.addr()),
            wait,
        )
        .await
        .unwrap();
        let taker = NickClient::connect(NickKeys::generate(), "regtest", &relays, None, wait)
            .await
            .unwrap();
        maker.subscribe(unix_now() - 60, false, true).await.unwrap();
        let event = public_event(
            taker.keys(),
            "regtest",
            "!orderbook",
            &[url.as_str()],
            unix_now(),
        )
        .unwrap();
        taker.publish(&event).await.unwrap();
        let Some(Incoming::Public(_, commands)) = maker.next(wait).await else {
            panic!("nothing through the proxy")
        };
        assert_eq!(commands, vec![Command::Orderbook]);
    }
}
