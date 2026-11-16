//! A client for a local aut-ct server (github.com/AdamISZ/aut-ct), for joinstr pools that ask for sybil
//! resistance (joinstr `NIP.md` "Sybil Resistance with aut-ct"; ADR 0006).
//!
//! aut-ct proves, in zero knowledge, that the prover owns some UTXO in a published snapshot of the UTXO
//! set (a keyset), without showing which, and derives a key image that is the same every time that UTXO is
//! used in one context. A pool creator verifies the proof and admits each key image once.
//!
//! The proving and verifying are done by the `autct` server, a separate program, over its WebSocket RPC on
//! loopback. This crate holds what a client needs: the proof context of a pool ([`context`]), the encrypted
//! key file the server reads a proving key from ([`keyfile`]), the RPC ([`rpc`]), and starting a server for
//! the pools in use ([`server`]), since it loads its contexts only at startup. It follows aut-ct's own
//! types at the revision in `docs/upstream-pins.md`, as the joinstr Electrum plugin does.

pub mod keyfile;
pub mod rpc;
pub mod server;

use vortex_ng_core::bitcoin::hashes::{Hash, sha256};

/// The port an aut-ct server listens on by default.
pub const DEFAULT_PORT: u16 = 23333;

/// The proof context of a pool: `SHA256(id || public_key)`, hex. The pool key is part of it so a proof
/// published for one pool cannot be reused in an announcement that copies its id.
pub fn context(pool_id: &str, pool_public_key: &str) -> String {
    sha256::Hash::hash(format!("{pool_id}{pool_public_key}").as_bytes())
        .to_byte_array()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Whether `context` may reach a server's arguments: lowercase hex, at most 64 digits.
pub fn is_context(context: &str) -> bool {
    (1..=64).contains(&context.len())
        && context
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Why an aut-ct step failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AutctError {
    /// The server address is not loopback, or an argument is not safe to pass on.
    Invalid(&'static str),
    /// The server could not be reached or did not answer as the protocol says.
    Transport(String),
    /// The server refused the request, with its code (aut-ct's `accepted` field).
    Refused(i64),
    /// The key file could not be written or encrypted.
    KeyFile(String),
}

impl std::fmt::Display for AutctError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AutctError::Invalid(why) => write!(f, "aut-ct: {why}"),
            AutctError::Transport(e) => write!(f, "aut-ct server: {e}"),
            AutctError::Refused(code) => {
                write!(f, "aut-ct server refused the request (code {code})")
            }
            AutctError::KeyFile(e) => write!(f, "aut-ct key file: {e}"),
        }
    }
}

impl std::error::Error for AutctError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_context_binds_the_pool_id_and_key() {
        // python3: hashlib.sha256(b"pool1" + b"ab" * 32).hexdigest()
        let key = "ab".repeat(32);
        let ctx = context("pool1", &key);
        assert_eq!(ctx.len(), 64);
        assert!(is_context(&ctx));
        assert_ne!(ctx, context("pool1", &"cd".repeat(32)));
        assert_ne!(ctx, context("pool2", &key));
        assert!(
            !is_context("")
                && !is_context("ABCD")
                && !is_context("a:b")
                && !is_context(&"a".repeat(65))
        );
    }
}
