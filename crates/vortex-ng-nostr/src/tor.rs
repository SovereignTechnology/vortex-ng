//! Per-nick Tor through arti (feature `tor`).
//!
//! One bootstrapped [`TorClient`] per process; each nick gets [`TorClient::isolated_client`], so its streams
//! never share a circuit with another nick's, behind its own [`crate::socks::SocksShim`]. Host names go to
//! arti unresolved: DNS happens at the exit.

use std::io;
use std::path::Path;
use std::sync::Arc;

use arti_client::config::TorClientConfigBuilder;
use arti_client::{DataStream, TorClient};
use tor_rtcompat::PreferredRuntime;

use crate::socks::{Connector, SocksShim};

/// Bootstrap a Tor client keeping its state and cache in the given directories.
pub async fn bootstrap(
    state_dir: &Path,
    cache_dir: &Path,
) -> io::Result<Arc<TorClient<PreferredRuntime>>> {
    let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
        .build()
        .map_err(|e| io::Error::other(format!("tor config: {e}")))?;
    TorClient::create_bootstrapped(config)
        .await
        .map_err(|e| io::Error::other(format!("tor bootstrap: {e}")))
}

/// A nick's isolated Tor client as a SOCKS-shim connector.
pub struct TorConnector {
    client: Arc<TorClient<PreferredRuntime>>,
}

impl std::fmt::Debug for TorConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TorConnector")
    }
}

impl TorConnector {
    /// A connector whose streams are isolated from every other connector made from `base`.
    pub fn isolated(base: &TorClient<PreferredRuntime>) -> TorConnector {
        TorConnector {
            client: base.isolated_client(),
        }
    }
}

impl Connector for TorConnector {
    type Stream = DataStream;
    async fn connect(&self, host: String, port: u16) -> io::Result<DataStream> {
        self.client
            .connect((host.as_str(), port))
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, format!("tor: {e}")))
    }
}

/// A SOCKS shim for one nick on its own isolated Tor circuits; give its address to `NickClient::connect`.
pub async fn nick_proxy(base: &TorClient<PreferredRuntime>) -> io::Result<SocksShim> {
    SocksShim::start(TorConnector::isolated(base)).await
}
