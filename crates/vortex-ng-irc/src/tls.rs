//! TLS to an IRC server: the certificate is checked against the server's host name, with no way to turn that
//! off, and no fallback to plain text when it fails.

use std::sync::Arc;

use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use vortex_ng_channel::socks::BoxedStream;

/// The Mozilla root store.
pub(crate) fn web_roots() -> RootCertStore {
    RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
}

/// Client settings trusting `roots`. The provider is named here, so nothing depends on which crypto provider
/// another crate in the process installed.
pub(crate) fn client_config(roots: RootCertStore) -> Result<Arc<ClientConfig>, String> {
    let config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Run the TLS handshake over `stream`, which fails unless the server proves it is `host`.
pub(crate) async fn secure(
    stream: BoxedStream,
    host: &str,
    config: &Arc<ClientConfig>,
) -> Result<BoxedStream, String> {
    let name = ServerName::try_from(host.to_string())
        .map_err(|_| "the host name cannot be checked against a certificate".to_string())?;
    let stream = TlsConnector::from(Arc::clone(config))
        .connect(name, stream)
        .await
        .map_err(|e| format!("TLS: {e}"))?;
    Ok(Box::new(stream))
}
