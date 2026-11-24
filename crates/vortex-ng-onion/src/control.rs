//! Just enough of Tor's control protocol (control-spec.txt) to publish an ephemeral onion service: a maker's
//! address for direct connections (issue #46).
//!
//! `PROTOCOLINFO`, then authentication with nothing (method `NULL`) or with the configured cookie file (method
//! `SAFECOOKIE`), then `ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port=<virtual>,127.0.0.1:<local>`. The
//! service lives as long as the control connection: [`OnionService`] keeps it open, and dropping it removes the
//! service. The key is discarded: a new address each time, which is what a nick that changes each run wants.
//!
//! The cookie itself never goes to the port. With `SAFECOOKIE` the port first proves it holds the cookie
//! (`AUTHCHALLENGE`: an HMAC of the cookie and both sides' nonces), and only then is it sent our HMAC, which is
//! good for that one connection. So something else listening on the port learns nothing, and plain `COOKIE`,
//! which would send the cookie to it, is refused. A path the port names is never read either: only the
//! configured file is. Password authentication is not supported; configure Tor with `CookieAuthentication 1`
//! (it offers `COOKIE,SAFECOOKIE`) and make the cookie readable.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use vortex_ng_core::bitcoin::hashes::{Hash, HashEngine, hmac, sha256};
use vortex_ng_core::bitcoin::hex::{DisplayHex, FromHex};
use vortex_ng_core::tx::random_bytes;

use crate::wire::is_v3_onion;

/// The HMAC key of the hash the port proves itself with (control-spec, `AUTHCHALLENGE`).
const SERVER_TO_CONTROLLER: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
/// The HMAC key of the hash we authenticate with.
const CONTROLLER_TO_SERVER: &[u8] = b"Tor safe cookie authentication controller-to-server hash";

/// A `SAFECOOKIE` hash: HMAC-SHA256 under `key` of the cookie, our nonce and the port's.
fn safecookie(key: &[u8], cookie: &[u8], ours: &[u8; 32], theirs: &[u8; 32]) -> [u8; 32] {
    let mut engine = hmac::HmacEngine::<sha256::Hash>::new(key);
    engine.input(cookie);
    engine.input(ours);
    engine.input(theirs);
    hmac::Hmac::<sha256::Hash>::from_engine(engine).to_byte_array()
}

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
    if methods.contains(&"SAFECOOKIE") {
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
        let ours: [u8; 32] = random_bytes();
        let reply = command(
            control,
            &format!("AUTHCHALLENGE SAFECOOKIE {}", ours.to_lower_hex_string()),
        )
        .await?;
        let challenge = reply
            .iter()
            .find_map(|line| line.strip_prefix("AUTHCHALLENGE "))
            .ok_or("no AUTHCHALLENGE reply")?;
        let field = |name: &str| -> Result<[u8; 32], String> {
            challenge
                .split(' ')
                .find_map(|field| field.strip_prefix(name))
                .and_then(|hex| <[u8; 32]>::from_hex(hex).ok())
                .ok_or_else(|| format!("no {name} of 32 bytes in the AUTHCHALLENGE reply"))
        };
        let (proof, theirs) = (field("SERVERHASH=")?, field("SERVERNONCE=")?);
        // The port shows it holds the cookie before we show we do.
        if safecookie(SERVER_TO_CONTROLLER, &cookie, &ours, &theirs) != proof {
            return Err(
                "the control port does not hold the cookie: not Tor's, or not this Tor's".into(),
            );
        }
        let answer = safecookie(CONTROLLER_TO_SERVER, &cookie, &ours, &theirs);
        command(
            control,
            &format!("AUTHENTICATE {}", answer.to_lower_hex_string()),
        )
        .await?;
        return Ok(());
    }
    Err(format!(
        "the control port offers {methods:?}; this needs SAFECOOKIE (CookieAuthentication 1) or NULL"
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

    /// The port's nonce in [`fake_control`].
    const THEIRS: [u8; 32] = [9; 32];

    /// A control port that offers `methods`, names `named` as its cookie file, holds the cookie `holds` (or
    /// none it could prove), and records what it was sent. It checks a `SAFECOOKIE` answer as Tor does.
    async fn fake_control(
        methods: &str,
        named: Option<String>,
        holds: Option<[u8; 32]>,
    ) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (methods, record) = (methods.to_string(), Arc::clone(&seen));
        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            let mut conn = BufReader::new(conn);
            let cookie = holds.unwrap_or([0; 32]);
            let mut ours = None;
            loop {
                let mut line = String::new();
                if conn.read_line(&mut line).await.unwrap_or(0) == 0 {
                    break;
                }
                let line = line.trim_end().to_string();
                record.lock().unwrap().push(line.clone());
                let reply = if line.starts_with("PROTOCOLINFO") {
                    let named = named
                        .as_ref()
                        .map(|c| format!(" COOKIEFILE=\"{c}\""))
                        .unwrap_or_default();
                    format!(
                        "250-PROTOCOLINFO 1\r\n250-AUTH METHODS={methods}{named}\r\n250-VERSION Tor=\"0.4.8\"\r\n250 OK\r\n"
                    )
                } else if let Some(nonce) = line.strip_prefix("AUTHCHALLENGE SAFECOOKIE ") {
                    let nonce = <[u8; 32]>::from_hex(nonce).unwrap();
                    ours = Some(nonce);
                    // Tor writes its hex in capitals.
                    let proof = safecookie(SERVER_TO_CONTROLLER, &cookie, &nonce, &THEIRS);
                    format!(
                        "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                        proof.to_upper_hex_string(),
                        THEIRS.to_upper_hex_string()
                    )
                } else if line == "AUTHENTICATE" {
                    if methods.split(',').any(|m| m == "NULL") {
                        "250 OK\r\n".to_string()
                    } else {
                        "515 Authentication failed\r\n".to_string()
                    }
                } else if let Some(answer) = line.strip_prefix("AUTHENTICATE ") {
                    let expected = ours.map(|ours| {
                        safecookie(CONTROLLER_TO_SERVER, &cookie, &ours, &THEIRS)
                            .to_lower_hex_string()
                    });
                    if expected.as_deref() == Some(answer) {
                        "250 OK\r\n".to_string()
                    } else {
                        "515 Authentication failed\r\n".to_string()
                    }
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
    async fn an_onion_is_published_with_null_authentication() {
        let (addr, seen) = fake_control("NULL", None, None).await;
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
    }

    #[tokio::test]
    async fn the_cookie_is_proved_never_sent() {
        let dir = std::env::temp_dir().join(format!("vortex-ng-control-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("control.authcookie");
        let cookie = [7u8; 32];
        std::fs::write(&path, cookie).unwrap();
        let configured = |addr| TorControl {
            addr,
            cookie: Some(path.clone()),
        };
        let sent_the_cookie = |seen: &Arc<Mutex<Vec<String>>>| {
            seen.lock()
                .unwrap()
                .iter()
                .any(|line| line.contains(&cookie.to_lower_hex_string()))
        };

        // Tor offers both: SAFECOOKIE, with a nonce of our own, and an answer the port accepts.
        let (addr, seen) = fake_control("COOKIE,SAFECOOKIE", None, Some(cookie)).await;
        let service = publish(&configured(addr), 18_082).await.unwrap();
        assert_eq!(service.host, format!("{}.onion", "b".repeat(56)));
        let sent = seen.lock().unwrap().clone();
        let nonce = sent[1].strip_prefix("AUTHCHALLENGE SAFECOOKIE ").unwrap();
        assert_eq!(nonce.len(), 64);
        assert!(
            sent[2].starts_with("AUTHENTICATE ") && sent[2].len() == "AUTHENTICATE ".len() + 64
        );
        assert!(sent[3].starts_with("ADD_ONION "));
        assert!(!sent_the_cookie(&seen));
        // A new nonce each time, so an answer is good for one connection only.
        let (addr, again) = fake_control("COOKIE,SAFECOOKIE", None, Some(cookie)).await;
        publish(&configured(addr), 1).await.unwrap();
        assert_ne!(again.lock().unwrap()[1], sent[1]);

        // A port that does not hold the cookie cannot prove it does, and gets no answer.
        let (addr, seen) = fake_control("COOKIE,SAFECOOKIE", None, Some([8; 32])).await;
        assert!(publish(&configured(addr), 1).await.is_err());
        assert!(
            !seen
                .lock()
                .unwrap()
                .iter()
                .any(|line| line.starts_with("AUTHENTICATE"))
        );

        // Plain COOKIE would send the cookie itself: refused, and nothing is sent.
        let (addr, seen) = fake_control("COOKIE", None, Some(cookie)).await;
        assert!(publish(&configured(addr), 1).await.is_err());
        assert_eq!(seen.lock().unwrap().len(), 1);

        // A path the port names is not read: only the configured one.
        let (addr, seen) = fake_control(
            "COOKIE,SAFECOOKIE",
            Some(path.display().to_string()),
            Some(cookie),
        )
        .await;
        assert!(
            publish(&TorControl { addr, cookie: None }, 1)
                .await
                .is_err()
        );
        assert_eq!(seen.lock().unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();

        // Only what is supported.
        let (addr, _) = fake_control("HASHEDPASSWORD", None, None).await;
        assert!(
            publish(&TorControl { addr, cookie: None }, 1)
                .await
                .is_err()
        );
    }

    #[test]
    fn safecookie_hashes_are_hmac_sha256_of_cookie_and_nonces() {
        // As control-spec defines them: HMAC-SHA256, keyed with the constant, of the cookie, then the
        // controller's nonce, then the server's. Expected values from Python's `hmac` module.
        let (cookie, ours, theirs) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        assert_eq!(
            safecookie(CONTROLLER_TO_SERVER, &cookie, &ours, &theirs).to_lower_hex_string(),
            "8d81b806c8314911da68057896783b1f28f640a588c9a2cfe902d371806bbf1a"
        );
        assert_eq!(
            safecookie(SERVER_TO_CONTROLLER, &cookie, &ours, &theirs).to_lower_hex_string(),
            "1830d2de6e061e60adfa2c0c2a9257b7126e51b074f39bd4519d89229df08827"
        );
    }
}
