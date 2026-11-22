//! Just enough of Tor's control protocol (control-spec.txt) to publish an ephemeral onion service: a maker's
//! address for direct connections (issue #46).
//!
//! `PROTOCOLINFO`, then `AUTHENTICATE` with the configured cookie file (method `COOKIE`) or with nothing
//! (method `NULL`), then `ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port=<virtual>,127.0.0.1:<local>`. The service
//! lives as long as the control connection: [`OnionService`] keeps it open, and dropping it removes the
//! service. The key is discarded: a new address each time, which is what a nick that changes each run wants.
//! A path the port itself names is never read: whatever answered on that port could otherwise have any
//! 32-byte file sent to it. `COOKIE` still shows the cookie to whatever listens on the port, so this must move
//! to `SAFECOOKIE` before the commands use it. `SAFECOOKIE` and password authentication are not supported yet;
//! configure Tor with `CookieAuthentication 1` (offers `COOKIE`) and make the cookie readable.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use vortex_ng_core::bitcoin::hex::DisplayHex;

use crate::wire::is_v3_onion;

/// The port an onion service is published on (joinmarket-clientserver's `ONION_VIRTUAL_PORT`).
pub const ONION_PORT: u16 = 5222;
/// The longest reply line read from the control port.
const MAX_REPLY_LINE: u64 = 4_096;
/// The most reply lines read for one command.
const MAX_REPLY_LINES: usize = 64;
/// How long the control port may take to answer.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(60);

/// Where Tor's control port is, and how to authenticate to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TorControl {
    /// The control port, normally `127.0.0.1:9051`.
    pub addr: SocketAddr,
    /// The authentication cookie file, needed for method `COOKIE`.
    pub cookie: Option<PathBuf>,
}

/// An onion service published through the control port. Dropping it removes the service.
#[derive(Debug)]
pub struct OnionService {
    /// The service's host name, `<56 characters>.onion`.
    pub host: String,
    keeper: JoinHandle<()>,
}

impl Drop for OnionService {
    fn drop(&mut self) {
        self.keeper.abort();
    }
}

type Control = BufReader<TcpStream>;

/// Send a command and read its reply: the lines, without status codes, if it ended in `250 OK`.
async fn command(control: &mut Control, line: &str) -> Result<Vec<String>, String> {
    control
        .get_mut()
        .write_all(format!("{line}\r\n").as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut lines = Vec::new();
    loop {
        let mut buf = Vec::new();
        let read = (&mut *control)
            .take(MAX_REPLY_LINE)
            .read_until(b'\n', &mut buf)
            .await
            .map_err(|e| e.to_string())?;
        if read == 0 || buf.last() != Some(&b'\n') {
            return Err("the control port closed or sent too long a line".into());
        }
        let text = String::from_utf8_lossy(&buf).trim_end().to_string();
        if !text.is_ascii() || text.len() < 4 || lines.len() >= MAX_REPLY_LINES {
            return Err("a malformed control reply".into());
        }
        let (code, rest) = text.split_at(3);
        let (separator, rest) = rest.split_at(1);
        if code != "250" {
            return Err(format!("the control port refused: {text}"));
        }
        lines.push(rest.to_string());
        if separator == " " {
            return Ok(lines);
        }
    }
}

/// Authenticate, the way the control port offers.
async fn authenticate(control: &mut Control, config: &TorControl) -> Result<(), String> {
    let info = command(control, "PROTOCOLINFO 1").await?;
    let auth = info
        .iter()
        .find_map(|line| line.strip_prefix("AUTH "))
        .ok_or("no AUTH line in PROTOCOLINFO")?;
    let methods: Vec<&str> = auth
        .split(' ')
        .find_map(|field| field.strip_prefix("METHODS="))
        .map(|m| m.split(',').collect())
        .unwrap_or_default();
    if methods.contains(&"NULL") {
        command(control, "AUTHENTICATE").await?;
        return Ok(());
    }
    if methods.contains(&"COOKIE") {
        let path = config
            .cookie
            .clone()
            .ok_or("no cookie file is configured")?;
        // 32 bytes, read once.
        let cookie =
            std::fs::read(&path).map_err(|e| format!("the cookie {}: {e}", path.display()))?;
        if cookie.len() != 32 {
            return Err("the cookie is not 32 bytes".into());
        }
        command(
            control,
            &format!("AUTHENTICATE {}", cookie.to_lower_hex_string()),
        )
        .await?;
        return Ok(());
    }
    Err(format!(
        "the control port offers {methods:?}; this needs COOKIE (CookieAuthentication 1) or NULL"
    ))
}

/// Publish `127.0.0.1:<local_port>` as a new onion service on port [`ONION_PORT`].
pub async fn publish(config: &TorControl, local_port: u16) -> Result<OnionService, String> {
    let setup = async {
        let stream = TcpStream::connect(config.addr)
            .await
            .map_err(|e| format!("the control port: {e}"))?;
        let mut control = BufReader::new(stream);
        authenticate(&mut control, config).await?;
        let reply = command(
            &mut control,
            &format!(
                "ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port={ONION_PORT},127.0.0.1:{local_port}"
            ),
        )
        .await?;
        let id = reply
            .iter()
            .find_map(|line| line.strip_prefix("ServiceID="))
            .ok_or("no ServiceID in the ADD_ONION reply")?;
        let host = format!("{id}.onion");
        if !is_v3_onion(&host) {
            return Err("the ServiceID is not a v3 onion".to_string());
        }
        Ok((control, host))
    };
    let (mut control, host) = tokio::time::timeout(CONTROL_TIMEOUT, setup)
        .await
        .map_err(|_| "the control port did not answer in time".to_string())??;
    // The service lives while this connection does: read (and ignore) until it closes or is dropped.
    let keeper = tokio::spawn(async move {
        let mut sink = Vec::new();
        while let Ok(read) = (&mut control)
            .take(MAX_REPLY_LINE)
            .read_until(b'\n', &mut sink)
            .await
        {
            if read == 0 {
                break;
            }
            sink.clear();
        }
    });
    Ok(OnionService { host, keeper })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    use tokio::net::TcpListener;

    use super::*;

    /// A control port that offers `methods`, names `cookie`, and records what it was sent.
    async fn fake_control(
        methods: &str,
        cookie: Option<String>,
    ) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (methods, record) = (methods.to_string(), Arc::clone(&seen));
        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            let mut conn = BufReader::new(conn);
            loop {
                let mut line = String::new();
                if conn.read_line(&mut line).await.unwrap_or(0) == 0 {
                    break;
                }
                let line = line.trim_end().to_string();
                record.lock().unwrap().push(line.clone());
                let reply = if line.starts_with("PROTOCOLINFO") {
                    let named = cookie
                        .as_ref()
                        .map(|c| format!(" COOKIEFILE=\"{c}\""))
                        .unwrap_or_default();
                    format!(
                        "250-PROTOCOLINFO 1\r\n250-AUTH METHODS={methods}{named}\r\n250-VERSION Tor=\"0.4.8\"\r\n250 OK\r\n"
                    )
                } else if line.starts_with("AUTHENTICATE") {
                    "250 OK\r\n".to_string()
                } else if line.starts_with("ADD_ONION") {
                    format!("250-ServiceID={}\r\n250 OK\r\n", "b".repeat(56))
                } else {
                    "510 Unrecognized command\r\n".to_string()
                };
                conn.get_mut().write_all(reply.as_bytes()).await.unwrap();
            }
        });
        (addr, seen)
    }

    #[tokio::test]
    async fn a_reply_that_is_not_ascii_is_an_error() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let _ = conn.read(&mut buf).await;
            conn.write_all(b"ab\xc3\xa9 reply\r\n").await.unwrap();
        });
        let config = TorControl { addr, cookie: None };
        assert!(publish(&config, 1).await.is_err());
    }

    #[tokio::test]
    async fn an_onion_is_published_with_null_or_cookie_authentication() {
        let (addr, seen) = fake_control("NULL", None).await;
        let service = publish(&TorControl { addr, cookie: None }, 18_082)
            .await
            .unwrap();
        assert_eq!(service.host, format!("{}.onion", "b".repeat(56)));
        let sent = seen.lock().unwrap().clone();
        assert_eq!(sent[1], "AUTHENTICATE");
        assert_eq!(
            sent[2],
            "ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port=5222,127.0.0.1:18082"
        );

        let dir = std::env::temp_dir().join(format!("vortex-ng-control-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cookie = dir.join("control.authcookie");
        std::fs::write(&cookie, [7u8; 32]).unwrap();
        // The configured file is what is read.
        let (addr, seen) = fake_control("COOKIE,SAFECOOKIE", None).await;
        let config = TorControl {
            addr,
            cookie: Some(cookie.clone()),
        };
        publish(&config, 1).await.unwrap();
        assert_eq!(
            seen.lock().unwrap()[1],
            format!("AUTHENTICATE {}", "07".repeat(32))
        );
        // A path the port names is not: nothing of that file goes back to it.
        let (addr, seen) =
            fake_control("COOKIE,SAFECOOKIE", Some(cookie.display().to_string())).await;
        assert!(
            publish(&TorControl { addr, cookie: None }, 1)
                .await
                .is_err()
        );
        assert!(
            !seen
                .lock()
                .unwrap()
                .iter()
                .any(|line| line.starts_with("AUTHENTICATE"))
        );
        std::fs::remove_dir_all(&dir).unwrap();

        // Only what is supported.
        let (addr, _) = fake_control("SAFECOOKIE,HASHEDPASSWORD", None).await;
        assert!(
            publish(&TorControl { addr, cookie: None }, 1)
                .await
                .is_err()
        );
    }
}
