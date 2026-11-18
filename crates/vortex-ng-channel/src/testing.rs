//! Helpers for tests, this crate's and (with feature `test-util`) other crates'. Nothing here is needed to
//! run vortex-ng.

use std::collections::BTreeSet;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// A SOCKS5 proxy on loopback that behaves, as far as a client can tell, like a Tor daemon's SOCKS port:
/// it insists on a username and password, takes any, and connects on the client's behalf, resolving names
/// itself. It remembers which username asked for which destination, so a test can see whether two nicks
/// came in under different credentials (which Tor would give circuits of their own).
///
/// Any host name ending in `.test` is taken to be this machine: a relay named so can only be reached
/// through the proxy, which shows that nothing connected to it directly.
#[derive(Debug)]
pub struct AuthSocks {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<(String, String)>>>,
    task: JoinHandle<()>,
}

impl AuthSocks {
    /// Listen on `127.0.0.1:<ephemeral>`.
    pub async fn start() -> io::Result<AuthSocks> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let task = tokio::spawn(async move {
            while let Ok((conn, _)) = listener.accept().await {
                let record = Arc::clone(&record);
                tokio::spawn(async move {
                    let _ = serve(conn, record).await;
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

async fn serve(mut conn: TcpStream, seen: Arc<Mutex<Vec<(String, String)>>>) -> io::Result<()> {
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
    let target = if host.ends_with(".test") {
        "127.0.0.1"
    } else {
        host.as_str()
    };
    let mut upstream = match TcpStream::connect((target, port)).await {
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
