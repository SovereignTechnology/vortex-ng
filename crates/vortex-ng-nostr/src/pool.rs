//! The transport of a joinstr pool (joinstr `NIP.md`; ADR 0006): pool announcements are kind 2022 events,
//! and everything else is NIP-04 (kind 4), first from a joiner's fresh key to the pool key, then, inside
//! the pool, from the pool key to itself by every peer that was given it.
//!
//! This is separate from the JoinMarket channel in [`crate::client`]: other kinds, other encryption, and
//! one relay per pool (the announced one). NIP-04 hides content only: the relay sees which keys talk and
//! when, and a pool message proves nothing about who wrote it, since every peer holds the pool key. What
//! arrives here is plaintext from strangers for `vortex-ng-joinstr` to judge.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::{Duration, Instant};

use futures::{Stream, StreamExt};
use nostr::key::{Keys, PublicKey, SecretKey};
use nostr::nips::nip04;
use nostr::prelude::{Event, EventBuilder, EventId, Filter, FinalizeEvent, Kind, Tag, Timestamp};
use nostr_sdk::prelude::{Client, ClientNotification, Proxy};

use crate::ChannelError;

/// Kind of a joinstr pool announcement.
pub const KIND_POOL: u16 = 2022;
/// The largest encrypted message read, bytes: a registration PSBT is a few hundred bytes, a ring
/// signature a few kilobytes.
pub const MAX_CONTENT: usize = 64 * 1024;
/// Most event ids remembered for deduplication.
const SEEN_CAP: usize = 100_000;

/// Something a pool connection received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PoolIncoming {
    /// A kind 2022 event: its author (hex), content and timestamp. The event's signature was checked by
    /// the relay client; whether the author is the pool's key is `Pool::from_announcement`'s check.
    Announcement {
        /// The event's pubkey, hex.
        author: String,
        /// The event's content.
        content: String,
        /// The event's `created_at`.
        created_at: u64,
    },
    /// A decrypted NIP-04 message addressed to our key.
    Direct {
        /// The event's pubkey, hex.
        sender: String,
        /// The decrypted content.
        plaintext: String,
        /// The event's `created_at`.
        created_at: u64,
    },
}

/// One key's connection to one pool relay.
pub struct PoolClient {
    keys: Keys,
    relay: String,
    client: Client,
    // As in `NickClient`: only `next(&mut self)` touches the stream; the Mutex makes the client `Sync`.
    notifications: std::sync::Mutex<Pin<Box<dyn Stream<Item = ClientNotification> + Send>>>,
    seen: HashSet<EventId>,
}

impl std::fmt::Debug for PoolClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolClient")
            .field("relay", &self.relay)
            .finish_non_exhaustive()
    }
}

fn io<E: std::fmt::Display>(e: E) -> ChannelError {
    ChannelError::Crypto(format!("relay: {e}"))
}

/// Nostr keys for a 32-byte secret (a pool's private key, or a fresh join key).
pub fn keys_from_secret(secret: &[u8; 32]) -> Result<Keys, ChannelError> {
    SecretKey::from_slice(secret)
        .map(Keys::new)
        .map_err(|e| ChannelError::Crypto(e.to_string()))
}

impl PoolClient {
    /// Connect `keys` to the pool's `relay` (through `proxy`, a SOCKS5 address, when given). joinstr asks
    /// for a new Tor circuit per identity: give each key its own proxy (`crate::tor::nick_proxy`).
    pub async fn connect(
        keys: Keys,
        relay: &str,
        proxy: Option<SocketAddr>,
        timeout: Duration,
    ) -> Result<PoolClient, ChannelError> {
        if !(relay.starts_with("ws://") || relay.starts_with("wss://")) {
            return Err(ChannelError::Invalid(
                "a pool relay is a ws:// or wss:// URL",
            ));
        }
        let client = match proxy {
            Some(addr) => Client::builder().proxy(Proxy::all(addr)).build(),
            None => Client::builder().build(),
        };
        // Take the notification stream before subscribing, so no event is missed.
        let notifications = client.notifications();
        client.add_relay(relay).await.map_err(io)?;
        client.connect().and_wait(timeout).await;
        Ok(PoolClient {
            keys,
            relay: relay.to_string(),
            client,
            notifications: std::sync::Mutex::new(notifications),
            seen: HashSet::new(),
        })
    }

    /// Our public key, hex (x-only), as pool announcements and message senders are named.
    pub fn public_key(&self) -> String {
        self.keys.public_key().to_hex()
    }

    /// The relay this connection is on.
    pub fn relay(&self) -> &str {
        &self.relay
    }

    /// Subscribe to pool announcements made since `since`.
    pub async fn subscribe_pools(&self, since: u64) -> Result<(), ChannelError> {
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_POOL))
            .since(Timestamp::from_secs(since));
        self.client.subscribe(filter).await.map_err(io)?;
        Ok(())
    }

    /// Subscribe to NIP-04 messages addressed to our key since `since`: the answer to a join request for a
    /// fresh key, join requests and the pool's own channel for a pool key.
    pub async fn subscribe_direct(&self, since: u64) -> Result<(), ChannelError> {
        let filter = Filter::new()
            .kind(Kind::EncryptedDirectMessage)
            .pubkey(self.keys.public_key())
            .since(Timestamp::from_secs(since));
        self.client.subscribe(filter).await.map_err(io)?;
        Ok(())
    }

    async fn publish(&self, builder: EventBuilder) -> Result<(), ChannelError> {
        let event = builder.finalize(&self.keys)?;
        let out = self.client.send_event(&event).await.map_err(io)?;
        if out.success.is_empty() {
            return Err(ChannelError::Crypto(
                "the pool relay did not accept the event".into(),
            ));
        }
        Ok(())
    }

    /// Announce a pool: a kind 2022 event with `content`, signed by our key, which must be the pool's.
    pub async fn announce(&self, content: &str) -> Result<(), ChannelError> {
        self.publish(EventBuilder::new(Kind::Custom(KIND_POOL), content))
            .await
    }

    /// Send `plaintext` to `to` (a public key, hex) as a NIP-04 message. Inside a pool `to` is our own key.
    pub async fn send(&self, to: &str, plaintext: &str) -> Result<(), ChannelError> {
        let to = PublicKey::from_hex(to).map_err(|e| ChannelError::Crypto(e.to_string()))?;
        let content = nip04::encrypt(self.keys.secret_key(), &to, plaintext)
            .map_err(|e| ChannelError::Crypto(e.to_string()))?;
        self.publish(
            EventBuilder::new(Kind::EncryptedDirectMessage, content).tag(Tag::public_key(to)),
        )
        .await
    }

    /// Wait up to `wait` for the next announcement or message to us. `None` on timeout or shutdown.
    pub async fn next(&mut self, wait: Duration) -> Option<PoolIncoming> {
        let deadline = Instant::now() + wait;
        loop {
            let left = deadline.checked_duration_since(Instant::now())?;
            let notification =
                tokio::time::timeout(left, self.notifications.get_mut().ok()?.next())
                    .await
                    .ok()??;
            let event = match notification {
                ClientNotification::Event { event, .. } => event,
                ClientNotification::Shutdown => return None,
                ClientNotification::Message { .. } => continue,
            };
            if self.seen.len() >= SEEN_CAP {
                self.seen.clear();
            }
            if !self.seen.insert(event.id) {
                continue;
            }
            if let Some(incoming) = self.read(&event) {
                return Some(incoming);
            }
        }
    }

    fn read(&self, event: &Event) -> Option<PoolIncoming> {
        if event.content.len() > MAX_CONTENT {
            return None;
        }
        let created_at = event.created_at.as_secs();
        if event.kind == Kind::Custom(KIND_POOL) {
            return Some(PoolIncoming::Announcement {
                author: event.pubkey.to_hex(),
                content: event.content.clone(),
                created_at,
            });
        }
        if event.kind == Kind::EncryptedDirectMessage {
            let ours = self.keys.public_key();
            if !event.tags.public_keys().any(|p| p == ours) {
                return None;
            }
            let plaintext = nip04::decrypt(
                self.keys.secret_key(),
                &event.pubkey,
                event.content.as_str(),
            )
            .ok()?;
            return Some(PoolIncoming::Direct {
                sender: event.pubkey.to_hex(),
                plaintext,
                created_at,
            });
        }
        None
    }

    /// Disconnect from the relay.
    pub async fn shutdown(&self) {
        self.client.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use nostr_sdk::prelude::MockRelay;

    use super::*;
    use crate::client::unix_now;

    const WAIT: Duration = Duration::from_secs(10);

    async fn connect(keys: Keys, url: &str) -> PoolClient {
        PoolClient::connect(keys, url, None, WAIT).await.unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_pool_is_announced_joined_and_talks_to_itself() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let pool_keys = keys_from_secret(&[9; 32]).unwrap();
        let since = unix_now() - 60;

        // The creator announces and listens for join requests.
        let mut creator = connect(pool_keys.clone(), &url).await;
        creator.subscribe_direct(since).await.unwrap();
        creator.announce(r#"{"type": "new_pool"}"#).await.unwrap();

        // A joiner with a fresh key finds the pool and asks to join.
        let mut joiner = connect(Keys::generate(), &url).await;
        joiner.subscribe_pools(since).await.unwrap();
        joiner.subscribe_direct(since).await.unwrap();
        let Some(PoolIncoming::Announcement {
            author, content, ..
        }) = joiner.next(WAIT).await
        else {
            panic!("no announcement")
        };
        assert_eq!(
            (author.as_str(), content.as_str()),
            (creator.public_key().as_str(), r#"{"type": "new_pool"}"#)
        );
        joiner
            .send(&author, r#"{"type": "join_pool"}"#)
            .await
            .unwrap();

        let Some(PoolIncoming::Direct {
            sender, plaintext, ..
        }) = creator.next(WAIT).await
        else {
            panic!("no join request")
        };
        assert_eq!(
            (sender.as_str(), plaintext.as_str()),
            (joiner.public_key().as_str(), r#"{"type": "join_pool"}"#)
        );
        creator.send(&sender, "credentials").await.unwrap();
        let Some(PoolIncoming::Direct {
            sender, plaintext, ..
        }) = joiner.next(WAIT).await
        else {
            panic!("no credentials")
        };
        assert_eq!(
            (sender, plaintext.as_str()),
            (creator.public_key(), "credentials")
        );

        // Inside the pool the joiner holds the pool key too, and posts as the pool, to the pool.
        let peer = connect(pool_keys, &url).await;
        peer.subscribe_direct(unix_now() - 1).await.unwrap();
        let pool_key = peer.public_key();
        peer.send(&pool_key, r#"{"address": "bcrt1q", "type": "output"}"#)
            .await
            .unwrap();
        loop {
            let Some(PoolIncoming::Direct {
                sender, plaintext, ..
            }) = creator.next(WAIT).await
            else {
                panic!("no pool message")
            };
            if plaintext.contains("output") {
                assert_eq!(sender, pool_key);
                break;
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn messages_for_other_keys_are_not_read() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let alice = connect(Keys::generate(), &url).await;
        let mut eve = connect(Keys::generate(), &url).await;
        let bob = Keys::generate();
        // Eve subscribes to every kind 4 event she can get, not only her own.
        eve.client
            .subscribe(Filter::new().kind(Kind::EncryptedDirectMessage))
            .await
            .unwrap();
        alice
            .send(&bob.public_key().to_hex(), "for bob")
            .await
            .unwrap();
        assert_eq!(eve.next(Duration::from_secs(2)).await, None);
        assert!(
            PoolClient::connect(Keys::generate(), "https://relay.example", None, WAIT)
                .await
                .is_err()
        );
    }
}
