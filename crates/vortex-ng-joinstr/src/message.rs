//! The messages of a pool (RULES.md R2, R4, R8.1): a join request to the pool key, then, inside the pool's
//! channel, outputs, inputs and the recovery round's `reregister` and `resign`.
//!
//! Messages are recognised by parsing their JSON and reading `type`; key order, spacing and extra keys such
//! as `version` do not matter. A message that cannot be used is `None` here and is skipped by the caller:
//! it never ends a round. What we send keeps the key order and `json.dumps` spacing of the Electrum plugin,
//! which older plugins match on.

use serde_json::{Value, json};

use crate::pyjson;

/// A message to or inside a pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PoolMessage {
    /// A request to join, sent from a fresh key to the pool key; with a proof for aut-ct pools.
    JoinPool {
        /// The aut-ct proof (base64), for pools that require one.
        autct_proof: Option<String>,
        /// The joiner's usage token: advisory, never trusted by the creator.
        autct_token: Option<String>,
    },
    /// The creator refusing a join request.
    Reject {
        /// Why (`invalid_proof`, `missing_proof`, `duplicate_token`).
        reason: String,
    },
    /// An output registration: the address a peer wants paid.
    Output {
        /// The address as sent; [`crate::rules::collect_outputs`] decides whether it counts.
        address: String,
    },
    /// An input registration: a peer's signed registration PSBT, base64.
    Input {
        /// The PSBT, base64.
        psbt: String,
    },
    /// Recovery phase 3: an output registered again under a ring signature.
    Reregister {
        /// The address to pay.
        address: String,
        /// Base64 of the signature's JSON object.
        sig: String,
        /// The key image, hex: one per input owner.
        key_image: String,
        /// The pool's id, which the signed message binds.
        pool_id: String,
    },
    /// Recovery phase 4: a peer's input signed again over the new transaction.
    Resign {
        /// The signed PSBT, base64.
        psbt: String,
    },
}

impl PoolMessage {
    /// Read a decrypted message, or `None` if it is not one we can use.
    pub fn parse(plaintext: &str) -> Option<PoolMessage> {
        let Ok(Value::Object(msg)) = serde_json::from_str::<Value>(plaintext) else {
            return None;
        };
        let text = |name: &str| {
            msg.get(name)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        match msg.get("type").and_then(Value::as_str)? {
            "join_pool" => Some(PoolMessage::JoinPool {
                autct_proof: text("autct_proof"),
                autct_token: text("autct_token"),
            }),
            "reject" => Some(PoolMessage::Reject {
                reason: text("reason").unwrap_or_else(|| "Unknown".to_string()),
            }),
            "output" => Some(PoolMessage::Output {
                address: text("address")?,
            }),
            "input" => Some(PoolMessage::Input {
                psbt: text("psbt")?,
            }),
            "reregister" => Some(PoolMessage::Reregister {
                address: text("address")?,
                sig: text("sig")?,
                key_image: text("key_image")?,
                pool_id: text("pool_id")?,
            }),
            "resign" => Some(PoolMessage::Resign {
                psbt: text("psbt")?,
            }),
            _ => None,
        }
    }

    /// The plaintext to encrypt and publish.
    pub fn to_plaintext(&self) -> String {
        match self {
            PoolMessage::JoinPool {
                autct_proof: Some(proof),
                autct_token,
            } => pyjson::object(&[
                ("type", json!("join_pool")),
                ("autct_proof", json!(proof)),
                (
                    "autct_token",
                    json!(autct_token.clone().unwrap_or_default()),
                ),
            ]),
            PoolMessage::JoinPool { .. } => pyjson::object(&[("type", json!("join_pool"))]),
            PoolMessage::Reject { reason } => {
                pyjson::object(&[("type", json!("reject")), ("reason", json!(reason))])
            }
            PoolMessage::Output { address } => {
                pyjson::object(&[("address", json!(address)), ("type", json!("output"))])
            }
            PoolMessage::Input { psbt } => {
                pyjson::object(&[("psbt", json!(psbt)), ("type", json!("input"))])
            }
            PoolMessage::Reregister {
                address,
                sig,
                key_image,
                pool_id,
            } => pyjson::object(&[
                ("type", json!("reregister")),
                ("address", json!(address)),
                ("sig", json!(sig)),
                ("key_image", json!(key_image)),
                ("pool_id", json!(pool_id)),
            ]),
            PoolMessage::Resign { psbt } => {
                pyjson::object(&[("type", json!("resign")), ("psbt", json!(psbt))])
            }
        }
    }
}

/// R2.2: whether the creator answers a decrypted message as a join request: a JSON object with `type`
/// `join_pool`, from a key other than the pool key, and only the first from each joiner key (`seen` holds
/// the keys already answered).
pub fn admit_join(
    plaintext: &str,
    sender: &str,
    pool_public_key: &str,
    seen: &[String],
) -> Option<PoolMessage> {
    if sender == pool_public_key || seen.iter().any(|s| s == sender) {
        return None;
    }
    match PoolMessage::parse(plaintext)? {
        join @ PoolMessage::JoinPool { .. } => Some(join),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_we_send_is_what_the_plugin_sends() {
        let join = PoolMessage::JoinPool {
            autct_proof: None,
            autct_token: None,
        };
        assert_eq!(join.to_plaintext(), r#"{"type": "join_pool"}"#);
        let output = PoolMessage::Output {
            address: "bcrt1qxyz".into(),
        };
        assert_eq!(
            output.to_plaintext(),
            r#"{"address": "bcrt1qxyz", "type": "output"}"#
        );
        let input = PoolMessage::Input {
            psbt: "cHNidP8=".into(),
        };
        assert_eq!(
            input.to_plaintext(),
            r#"{"psbt": "cHNidP8=", "type": "input"}"#
        );
        let resign = PoolMessage::Resign {
            psbt: "cHNidP8=".into(),
        };
        assert_eq!(
            resign.to_plaintext(),
            r#"{"type": "resign", "psbt": "cHNidP8="}"#
        );
        let reject = PoolMessage::Reject {
            reason: "invalid_proof".into(),
        };
        assert_eq!(
            reject.to_plaintext(),
            r#"{"type": "reject", "reason": "invalid_proof"}"#
        );
        for msg in [join, output, input, resign, reject] {
            assert_eq!(PoolMessage::parse(&msg.to_plaintext()), Some(msg));
        }
    }

    #[test]
    fn messages_are_read_whatever_their_spacing_and_extras() {
        let compact = r#"{"version":"1","type":"output","address":"bcrt1qxyz","more":[1,2]}"#;
        assert_eq!(
            PoolMessage::parse(compact),
            Some(PoolMessage::Output {
                address: "bcrt1qxyz".into()
            })
        );
        let rereg = r#"{"pool_id": "p", "key_image": "02ab", "sig": "e30=", "address": "bcrt1qxyz", "type": "reregister"}"#;
        assert!(matches!(
            PoolMessage::parse(rereg),
            Some(PoolMessage::Reregister { .. })
        ));
        // Unusable messages are skipped, never an error.
        for bad in [
            "",
            "nope",
            "[]",
            "5",
            r#"{"type": 7}"#,
            r#"{"type": "output"}"#,
            r#"{"type": "output", "address": ""}"#,
            r#"{"type": "output", "address": 5}"#,
            r#"{"type": "mystery"}"#,
            r#"{"address": "bcrt1qxyz"}"#,
        ] {
            assert_eq!(PoolMessage::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_creator_answers_each_joiner_once_and_never_itself() {
        let join = r#"{"type":"join_pool"}"#;
        assert!(admit_join(join, "alice", "pool", &[]).is_some());
        assert!(admit_join(join, "pool", "pool", &[]).is_none());
        assert!(admit_join(join, "alice", "pool", &["alice".to_string()]).is_none());
        assert!(
            admit_join(
                r#"{"type": "output", "address": "x"}"#,
                "alice",
                "pool",
                &[]
            )
            .is_none()
        );
        assert!(admit_join("join_pool", "alice", "pool", &[]).is_none());
    }
}
