//! The aut-ct server's RPC, as its own types define it (`RPCProver.prove`, `RPCProofVerifier.verify`).
//!
//! The transport is the server's WebSocket endpoint: two binary frames per request (a header naming the
//! method, then the JSON body) and two per answer (an acknowledgement, then the JSON body). A request
//! carries a file path and that file's password, and the connection is unencrypted, so only a loopback
//! server is ever spoken to.

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

use crate::keyfile::KeyFile;
use crate::{AutctError, is_context};

/// How long one RPC may take; proving walks a curve tree and takes seconds.
pub const RPC_TIMEOUT: Duration = Duration::from_secs(150);
/// The most proof text accepted from a stranger before it is handed to the server (base64).
pub const MAX_PROOF_LEN: usize = 64 * 1024;

/// A proof for a join request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// The proof, base64, as `autct_proof` carries it.
    pub proof: String,
    /// Its key image, sent as the advisory `autct_token`.
    pub key_image: String,
}

/// A local aut-ct server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Client {
    host: String,
    port: u16,
}

fn transport<E: std::fmt::Display>(e: E) -> AutctError {
    AutctError::Transport(e.to_string())
}

/// `<context>:<keyset file>`, the pair a request names. Both parts end up in the server's own lookups, so
/// the context must be hex and the keyset path free of the separators the server splits on.
fn keyset_arg(context: &str, keyset: &Path) -> Result<String, AutctError> {
    if !is_context(context) {
        return Err(AutctError::Invalid("the context is not hex"));
    }
    let name = keyset
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if !vortex_ng_joinstr::pool::is_keyset_name(name) {
        return Err(AutctError::Invalid(
            "the keyset is not a canonical keyset file name",
        ));
    }
    let path = keyset
        .to_str()
        .ok_or(AutctError::Invalid("the keyset path is not UTF-8"))?;
    if path.contains([':', ',']) {
        return Err(AutctError::Invalid("the keyset path contains a separator"));
    }
    Ok(format!("{context}:{path}"))
}

impl Client {
    /// A client for the server at `host:port`, which must be a loopback address.
    pub fn new(host: &str, port: u16) -> Result<Client, AutctError> {
        let loopback =
            host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
        if !loopback {
            return Err(AutctError::Invalid("the aut-ct server must be on loopback"));
        }
        Ok(Client {
            host: host.to_string(),
            port,
        })
    }

    fn url(&self) -> String {
        match self.host.parse::<IpAddr>() {
            Ok(IpAddr::V6(ip)) => format!("ws://[{ip}]:{}", self.port),
            _ => format!("ws://{}:{}", self.host, self.port),
        }
    }

    /// Whether the server accepts connections.
    pub async fn is_up(&self) -> bool {
        let connect = tokio_tungstenite::connect_async(self.url());
        matches!(
            tokio::time::timeout(Duration::from_secs(5), connect).await,
            Ok(Ok(_))
        )
    }

    async fn call(&self, method: &str, body: &Value) -> Result<Value, AutctError> {
        let exchange = async {
            let (mut socket, _) = tokio_tungstenite::connect_async(self.url())
                .await
                .map_err(transport)?;
            // toy-rpc's framing: the header, then the body, without waiting in between.
            let header = format!(
                "{{\"Request\": {{\"id\": 0, \"service_method\": \"{method}\",\"timeout\": {{\"secs\": 120,\"nanos\": 0}}}}}}\n"
            );
            socket
                .send(Message::Binary(header.into_bytes().into()))
                .await
                .map_err(transport)?;
            socket
                .send(Message::Binary(body.to_string().into_bytes().into()))
                .await
                .map_err(transport)?;
            // The acknowledgement, then the answer.
            let mut frames = Vec::new();
            while frames.len() < 2 {
                match socket.next().await {
                    Some(Ok(Message::Binary(data))) => frames.push(data.to_vec()),
                    Some(Ok(Message::Text(text))) => frames.push(text.as_bytes().to_vec()),
                    Some(Ok(Message::Close(_))) | None => {
                        return Err(AutctError::Transport(
                            "the server closed the connection".into(),
                        ));
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(transport(e)),
                }
            }
            let _ = socket.close(None).await;
            serde_json::from_slice::<Value>(&frames[1]).map_err(transport)
        };
        tokio::time::timeout(RPC_TIMEOUT, exchange)
            .await
            .map_err(|_| AutctError::Transport("timed out".into()))?
    }

    /// Prove ownership of the UTXO whose key is in `key_file`, for `context` against `keyset`, on the
    /// Bitcoin network `network` (`mainnet`, `signet` or `regtest`). The server must already serve that
    /// context and keyset ([`crate::server`]).
    pub async fn prove(
        &self,
        context: &str,
        keyset: &Path,
        key_file: &KeyFile,
        network: &str,
    ) -> Result<Proof, AutctError> {
        let path = key_file
            .path()
            .to_str()
            .ok_or(AutctError::Invalid("the key file path is not UTF-8"))?;
        let body = json!({
            "keyset": keyset_arg(context, keyset)?,
            "depth": 2,
            "generators_length_log_2": 11,
            "user_label": "name-goes-here",
            "privkey_file_loc": path,
            "bc_network": network,
            "encryption_password": key_file.password(),
        });
        let answer = self.call("RPCProver.prove", &body).await?;
        match answer["accepted"].as_i64() {
            Some(0) => {}
            Some(code) => return Err(AutctError::Refused(code)),
            None => return Err(AutctError::Transport("the answer has no `accepted`".into())),
        }
        let field = |name: &str| {
            answer[name]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .ok_or_else(|| AutctError::Transport(format!("the answer has no `{name}`")))
        };
        Ok(Proof {
            proof: field("proof")?,
            key_image: field("key_image")?,
        })
    }

    /// Verify a joiner's `proof` for `context` against `keyset` and return its key image. The image comes
    /// from the verifier, never from the joiner: the caller admits each image once.
    pub async fn verify(
        &self,
        context: &str,
        keyset: &Path,
        proof: &str,
    ) -> Result<String, AutctError> {
        if proof.len() > MAX_PROOF_LEN {
            return Err(AutctError::Invalid("the proof is too long"));
        }
        let body = json!({
            "keyset": keyset_arg(context, keyset)?,
            "user_label": "name-goes-here",
            "context_label": context,
            "application_label": "autct-v1.0",
            "proof": proof,
        });
        let answer = self.call("RPCProofVerifier.verify", &body).await?;
        match answer["accepted"].as_i64() {
            Some(1) => {}
            Some(code) => return Err(AutctError::Refused(code)),
            None => return Err(AutctError::Transport("the answer has no `accepted`".into())),
        }
        answer["key_image"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| AutctError::Transport("accepted without a key image".into()))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tokio::net::TcpListener;

    use super::*;

    const CONTEXT: &str = "5f2c9a";

    fn keyset() -> PathBuf {
        PathBuf::from("/keysets/autct-830000-100000-0-2-1024.aks")
    }

    /// A stand-in server: reads the two request frames, answers with an acknowledgement and `reply(method,
    /// body)`. Returns its port.
    async fn fake_server(reply: fn(&str, &Value) -> Value) -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let Ok(mut socket) = tokio_tungstenite::accept_async(stream).await else {
                        return;
                    };
                    let Some(Ok(Message::Binary(header))) = socket.next().await else {
                        return;
                    };
                    let Some(Ok(Message::Binary(body))) = socket.next().await else {
                        return;
                    };
                    let header: Value = serde_json::from_slice(&header).unwrap();
                    let method = header["Request"]["service_method"]
                        .as_str()
                        .unwrap()
                        .to_string();
                    assert_eq!(header["Request"]["timeout"]["secs"], 120);
                    let body: Value = serde_json::from_slice(&body).unwrap();
                    let ack = br#"{"Response":{"id":0,"is_ok":true}}"#.to_vec();
                    socket.send(Message::Binary(ack.into())).await.unwrap();
                    let answer = reply(&method, &body).to_string().into_bytes();
                    socket.send(Message::Binary(answer.into())).await.unwrap();
                });
            }
        });
        port
    }

    fn honest(method: &str, body: &Value) -> Value {
        assert_eq!(
            body["keyset"],
            format!("{CONTEXT}:/keysets/autct-830000-100000-0-2-1024.aks")
        );
        match method {
            "RPCProver.prove" => {
                assert_eq!(body["bc_network"], "regtest");
                assert_eq!(body["encryption_password"].as_str().unwrap().len(), 32);
                assert!(std::path::Path::new(body["privkey_file_loc"].as_str().unwrap()).exists());
                json!({"accepted": 0, "proof": "cHJvb2Y=", "key_image": "02aa"})
            }
            "RPCProofVerifier.verify" => {
                assert_eq!(
                    (&body["context_label"], &body["application_label"]),
                    (&json!(CONTEXT), &json!("autct-v1.0"))
                );
                match body["proof"].as_str() {
                    Some("cHJvb2Y=") => json!({"accepted": 1, "key_image": "02aa"}),
                    Some("reused") => json!({"accepted": -3, "key_image": null}),
                    _ => json!({"accepted": -2}),
                }
            }
            other => panic!("unexpected method {other}"),
        }
    }

    #[tokio::test]
    async fn prove_and_verify_speak_the_servers_framing() {
        let client = Client::new("127.0.0.1", fake_server(honest).await).unwrap();
        assert!(client.is_up().await);
        let key_file = KeyFile::create(
            &std::env::temp_dir(),
            "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy",
        )
        .unwrap();
        let proof = client
            .prove(CONTEXT, &keyset(), &key_file, "regtest")
            .await
            .unwrap();
        assert_eq!(
            proof,
            Proof {
                proof: "cHJvb2Y=".into(),
                key_image: "02aa".into()
            }
        );
        assert_eq!(
            client
                .verify(CONTEXT, &keyset(), &proof.proof)
                .await
                .unwrap(),
            "02aa"
        );
        // A reused key image and an invalid proof are refusals with the server's code.
        assert_eq!(
            client.verify(CONTEXT, &keyset(), "reused").await,
            Err(AutctError::Refused(-3))
        );
        assert_eq!(
            client.verify(CONTEXT, &keyset(), "junk").await,
            Err(AutctError::Refused(-2))
        );
    }

    #[tokio::test]
    async fn answers_that_break_the_protocol_are_errors_not_acceptance() {
        fn accepted_without_image(_: &str, _: &Value) -> Value {
            json!({"accepted": 1})
        }
        fn no_code(_: &str, _: &Value) -> Value {
            json!({"proof": "x", "key_image": "y"})
        }
        let client = Client::new("127.0.0.1", fake_server(accepted_without_image).await).unwrap();
        assert!(matches!(
            client.verify(CONTEXT, &keyset(), "p").await,
            Err(AutctError::Transport(_))
        ));
        let client = Client::new("127.0.0.1", fake_server(no_code).await).unwrap();
        assert!(matches!(
            client.verify(CONTEXT, &keyset(), "p").await,
            Err(AutctError::Transport(_))
        ));
        // Nothing listening.
        let dead = Client::new("127.0.0.1", 1).unwrap();
        assert!(!dead.is_up().await);
        assert!(matches!(
            dead.verify(CONTEXT, &keyset(), "p").await,
            Err(AutctError::Transport(_))
        ));
    }

    #[test]
    fn only_loopback_servers_and_safe_arguments() {
        assert!(Client::new("127.0.0.1", 23333).is_ok() && Client::new("::1", 23333).is_ok());
        assert!(Client::new("localhost", 23333).is_ok());
        assert_eq!(
            Client::new("192.168.1.5", 23333),
            Err(AutctError::Invalid("the aut-ct server must be on loopback"))
        );
        assert_eq!(
            Client::new("autct.example", 23333),
            Err(AutctError::Invalid("the aut-ct server must be on loopback"))
        );
        assert_eq!(Client::new("::1", 5).unwrap().url(), "ws://[::1]:5");
        assert!(keyset_arg("zz", &keyset()).is_err());
        assert!(keyset_arg(CONTEXT, Path::new("/keysets/evil.aks")).is_err());
        assert!(keyset_arg(CONTEXT, Path::new("/key,sets/autct-1-2-3-4-5.aks")).is_err());
        assert_eq!(
            keyset_arg(CONTEXT, &keyset()).unwrap(),
            "5f2c9a:/keysets/autct-830000-100000-0-2-1024.aks"
        );
    }
}
