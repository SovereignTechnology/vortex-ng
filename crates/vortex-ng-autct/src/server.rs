//! Starting an aut-ct server for the pools in use.
//!
//! The server loads its `context:keyset` pairs when it starts and cannot be given more later, and a pool's
//! context is unique to it. So a client that joins or creates pools runs its own server, started with every
//! active pool's pair, and restarts it when a pool is added, as the joinstr Electrum plugin does. The
//! server keeps its key images on disk, which is what stops a UTXO proving twice across a restart; they are
//! never cleared here.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crate::rpc::Client;
use crate::{AutctError, is_context};

/// The arguments that start `autct` as a server for `pairs` (`context`, keyset file) on loopback `port`
/// for the Bitcoin network `network`. Every value is checked before it becomes an argument: contexts are
/// hex, keyset files have canonical names and no separator in their path.
pub fn serve_args(
    pairs: &[(String, PathBuf)],
    port: u16,
    network: &str,
) -> Result<Vec<String>, AutctError> {
    if pairs.is_empty() {
        return Err(AutctError::Invalid("no context to serve"));
    }
    if !matches!(network, "mainnet" | "signet" | "regtest") {
        return Err(AutctError::Invalid(
            "the network is not mainnet, signet or regtest",
        ));
    }
    let mut keysets = Vec::with_capacity(pairs.len());
    for (context, keyset) in pairs {
        if !is_context(context) {
            return Err(AutctError::Invalid("the context is not hex"));
        }
        let name = keyset
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let path = keyset
            .to_str()
            .ok_or(AutctError::Invalid("the keyset path is not UTF-8"))?;
        if !vortex_ng_joinstr::pool::is_keyset_name(name)
            || path.contains([':', ','])
            || path.starts_with('-')
        {
            return Err(AutctError::Invalid(
                "the keyset is not a canonical keyset file",
            ));
        }
        keysets.push(format!("{context}:{path}"));
    }
    Ok([
        "-M",
        "serve",
        "-k",
        &keysets.join(","),
        "-H",
        "127.0.0.1",
        "-p",
        &port.to_string(),
        "-n",
        network,
    ]
    .iter()
    .map(ToString::to_string)
    .collect())
}

/// An `autct` server we started; stopped when dropped.
#[derive(Debug)]
pub struct Server {
    child: Child,
    client: Client,
}

impl Server {
    /// Start `binary` serving `pairs` and wait up to `ready` for it to accept connections.
    pub async fn start(
        binary: &Path,
        pairs: &[(String, PathBuf)],
        port: u16,
        network: &str,
        ready: Duration,
    ) -> Result<Server, AutctError> {
        let args = serve_args(pairs, port, network)?;
        let child = Command::new(binary)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                AutctError::Transport(format!("cannot start {}: {e}", binary.display()))
            })?;
        let server = Server {
            child,
            client: Client::new("127.0.0.1", port)?,
        };
        let deadline = tokio::time::Instant::now() + ready;
        while tokio::time::Instant::now() < deadline {
            if server.client.is_up().await {
                return Ok(server);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(AutctError::Transport(
            "the server did not become ready".into(),
        ))
    }

    /// The client for this server.
    pub fn client(&self) -> &Client {
        &self.client
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // The child is ours: we spawned it and hold its handle.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(context: &str, keyset: &str) -> (String, PathBuf) {
        (context.to_string(), PathBuf::from(keyset))
    }

    #[test]
    fn the_server_is_started_as_the_plugin_starts_it() {
        let pairs = [
            pair("aa11", "/k/autct-830000-100000-0-2-1024.aks"),
            pair("bb22", "/k/autct-1-2-3-4-5.aks"),
        ];
        assert_eq!(
            serve_args(&pairs, 23333, "signet").unwrap(),
            [
                "-M",
                "serve",
                "-k",
                "aa11:/k/autct-830000-100000-0-2-1024.aks,bb22:/k/autct-1-2-3-4-5.aks",
                "-H",
                "127.0.0.1",
                "-p",
                "23333",
                "-n",
                "signet"
            ]
        );
    }

    #[test]
    fn nothing_unsafe_becomes_an_argument() {
        let good = "/k/autct-1-2-3-4-5.aks";
        assert!(serve_args(&[], 1, "signet").is_err());
        assert!(serve_args(&[pair("aa", good)], 1, "testnet").is_err());
        assert!(serve_args(&[pair("-M", good)], 1, "signet").is_err());
        assert!(serve_args(&[pair("AA", good)], 1, "signet").is_err());
        assert!(serve_args(&[pair("aa", "/k/passwd")], 1, "signet").is_err());
        assert!(serve_args(&[pair("aa", "/k,x/autct-1-2-3-4-5.aks")], 1, "signet").is_err());
        assert!(serve_args(&[pair("aa", "-k/autct-1-2-3-4-5.aks")], 1, "signet").is_err());
    }

    #[tokio::test]
    async fn a_missing_binary_is_reported() {
        let missing = Path::new("/nonexistent/autct");
        let pairs = [pair("aa", "/k/autct-1-2-3-4-5.aks")];
        let err = Server::start(missing, &pairs, 1, "regtest", Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(matches!(err, AutctError::Transport(_)));
    }
}
