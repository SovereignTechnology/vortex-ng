//! Relay I/O for one nick (`docs/jmp/jmp-draft-nostr-message-channel.md`).
//!
//! One [`NickClient`] per nick, so a relay connection serves exactly one nick; a per-nick SOCKS proxy (an
//! isolated Tor circuit) can be given. It subscribes to the nick's gift wraps and, as asked, to offers and
//! public messages (filtering on single-letter tags only, as relays index no others), publishes, and sends
//! private lines to the recipient's advertised relays. [`NickClient::next`] yields only events that passed
//! every check of the draft, deduplicated by event id.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::{Stream, StreamExt};
use nostr::prelude::{Event, EventId, Filter, Kind, Timestamp};
use nostr_sdk::prelude::{Client, ClientNotification, Proxy};
use vortex_ng_core::command::Command;
use vortex_ng_core::line::PrivMsg;
use vortex_ng_core::offer::Offer;

use crate::event::{Author, network_hashtag, read_offer_event, read_public_event};
use crate::keys::NickKeys;
use crate::private::{Reassembler, open_line, unwrap, wrap_line};
use crate::{ChannelError, KIND_OFFER, KIND_PUBLIC};

/// Most relays a private message is sent to.
pub const MAX_SEND_RELAYS: usize = 4;
/// Incomplete split messages kept, in total.
const REASSEMBLY_CAP: usize = 256;
/// Event ids remembered for deduplication before the set is reset.
const SEEN_CAP: usize = 100_000;

/// The current Unix time, seconds.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Something that arrived for this nick and passed the draft's checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Incoming {
    /// A verified JMP-0001 private message, and the relays its sender reads replies on.
    Private(PrivMsg, Vec<String>),
    /// A maker's offer event.
    Offers(Author, Vec<Offer>),
    /// A public message (`!orderbook`, `!hp2`, `!cancel`).
    Public(Author, Vec<Command>),
}

/// A nick's connection to its relays.
pub struct NickClient {
    keys: NickKeys,
    network: String,
    relays: Vec<String>,
    client: Client,
    // Only `next(&mut self)` touches the stream; the Mutex (reached via `get_mut`, never locked) makes the
    // client `Sync`, so futures holding `&NickClient` can be spawned.
    notifications: std::sync::Mutex<Pin<Box<dyn Stream<Item = ClientNotification> + Send>>>,
    seen: HashSet<EventId>,
    reassembler: Reassembler,
}

impl std::fmt::Debug for NickClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NickClient")
            .field("nick", &self.keys.nick())
            .field("network", &self.network)
            .finish()
    }
}

fn io<E: std::fmt::Display>(e: E) -> ChannelError {
    ChannelError::Crypto(format!("relay: {e}"))
}

impl NickClient {
    /// Connect `keys`' nick to `relays` (through `proxy`, a SOCKS5 address, when given), waiting up to
    /// `timeout` for the connections.
    pub async fn connect(
        keys: NickKeys,
        network: &str,
        relays: &[String],
        proxy: Option<SocketAddr>,
        timeout: Duration,
    ) -> Result<NickClient, ChannelError> {
        if relays.is_empty() {
            return Err(ChannelError::Invalid("at least one relay"));
        }
        let client = match proxy {
            Some(addr) => Client::builder().proxy(Proxy::all(addr)).build(),
            None => Client::builder().build(),
        };
        // Take the notification stream before subscribing, so no event is missed.
        let notifications = client.notifications();
        for relay in relays {
            client.add_relay(relay.as_str()).await.map_err(io)?;
        }
        client.connect().and_wait(timeout).await;
        Ok(NickClient {
            keys,
            network: network.to_string(),
            relays: relays
                .iter()
                .take(crate::private::MAX_REPLY_RELAYS)
                .cloned()
                .collect(),
            client,
            notifications: std::sync::Mutex::new(notifications),
            seen: HashSet::new(),
            reassembler: Reassembler::new(REASSEMBLY_CAP),
        })
    }

    /// The nick's keys.
    pub fn keys(&self) -> &NickKeys {
        &self.keys
    }

    /// The relays this nick reads on (advertised in its events and rumors).
    pub fn relays(&self) -> &[String] {
        &self.relays
    }

    /// Subscribe to this nick's private messages since `since`, and optionally to offers and public messages.
    pub async fn subscribe(
        &self,
        since: u64,
        offers: bool,
        public: bool,
    ) -> Result<(), ChannelError> {
        let since = Timestamp::from_secs(since);
        let tag = network_hashtag(&self.network);
        let mut filters = vec![
            Filter::new()
                .kind(Kind::GiftWrap)
                .pubkey(self.keys.nostr().public_key())
                .since(since),
        ];
        if offers {
            filters.push(
                Filter::new()
                    .kind(Kind::Custom(KIND_OFFER))
                    .hashtag(tag.clone()),
            );
        }
        if public {
            filters.push(
                Filter::new()
                    .kind(Kind::Custom(KIND_PUBLIC))
                    .hashtag(tag)
                    .since(since),
            );
        }
        self.client.subscribe(filters).await.map_err(io)?;
        Ok(())
    }

    /// Publish an event to our relays; at least one must accept it.
    pub async fn publish(&self, event: &Event) -> Result<(), ChannelError> {
        let out = self.client.send_event(event).await.map_err(io)?;
        if out.success.is_empty() {
            return Err(ChannelError::Crypto("no relay accepted the event".into()));
        }
        Ok(())
    }

    /// Send a JMP-0001 private-message line to `to` (its Nostr key) on up to [`MAX_SEND_RELAYS`] of its
    /// advertised relays. Every part must be accepted by at least one of them.
    pub async fn send_line(
        &self,
        to: &nostr::key::PublicKey,
        to_relays: &[String],
        line: &str,
    ) -> Result<(), ChannelError> {
        let targets: Vec<&String> = to_relays.iter().take(MAX_SEND_RELAYS).collect();
        if targets.is_empty() {
            return Err(ChannelError::Invalid("recipient advertises no relay"));
        }
        for relay in &targets {
            self.client
                .add_relay(relay.as_str())
                .and_connect()
                .await
                .map_err(io)?;
        }
        for wrap in wrap_line(&self.keys, to, line, &self.relays, unix_now())? {
            let out = self
                .client
                .send_event(&wrap)
                .to(targets.iter().map(|r| r.as_str()))
                .await
                .map_err(io)?;
            if out.success.is_empty() {
                return Err(ChannelError::Crypto(
                    "no recipient relay accepted the message".into(),
                ));
            }
        }
        Ok(())
    }

    /// Wait up to `wait` for the next event that passes every check. `None` on timeout or shutdown.
    pub async fn next(&mut self, wait: Duration) -> Option<Incoming> {
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
            if let Some(incoming) = self.check(&event) {
                return Some(incoming);
            }
        }
    }

    fn check(&mut self, event: &Event) -> Option<Incoming> {
        let now = unix_now();
        if event.kind == Kind::GiftWrap {
            let received = unwrap(&self.keys, event).ok()?;
            let delivered = self.reassembler.push(received, now)?;
            let msg = open_line(&self.keys, &delivered.sender, &delivered.line).ok()?;
            return Some(Incoming::Private(msg, delivered.relays));
        }
        if event.kind == Kind::Custom(KIND_OFFER) {
            let (author, offers) = read_offer_event(event, &self.network, now).ok()?;
            return (author.nick != self.keys.nick()).then_some(Incoming::Offers(author, offers));
        }
        if event.kind == Kind::Custom(KIND_PUBLIC) {
            let (author, commands) = read_public_event(event, &self.network).ok()?;
            return (author.nick != self.keys.nick()).then_some(Incoming::Public(author, commands));
        }
        None
    }

    /// Disconnect from every relay.
    pub async fn shutdown(&self) {
        self.client.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use nostr_sdk::prelude::MockRelay;
    use vortex_ng_core::bitcoin::secp256k1::Secp256k1;
    use vortex_ng_core::line::sign_line;
    use vortex_ng_core::offer::Pit;
    use vortex_ng_core::protocol::NOSTR_HOSTID;

    use super::*;
    use crate::event::{offer_event, public_event};

    const WAIT: Duration = Duration::from_secs(10);

    async fn pair(relay: &str) -> (NickClient, NickClient) {
        let relays = vec![relay.to_string()];
        let maker = NickClient::connect(NickKeys::generate(), "regtest", &relays, None, WAIT)
            .await
            .unwrap();
        let taker = NickClient::connect(NickKeys::generate(), "regtest", &relays, None, WAIT)
            .await
            .unwrap();
        let since = unix_now() - 60;
        maker.subscribe(since, false, true).await.unwrap();
        taker.subscribe(since, true, false).await.unwrap();
        (maker, taker)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn offers_private_lines_and_public_messages_flow_through_a_relay() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let (mut maker, mut taker) = pair(&url).await;
        let relays = [url.as_str()];

        // A maker's offer reaches the taker.
        let offer = Offer::parse("sw0reloffer", "0 50000 10000000 0 0.00025").unwrap();
        let event = offer_event(
            maker.keys(),
            "regtest",
            Pit::Sw0,
            std::slice::from_ref(&offer),
            &[],
            &relays,
            unix_now(),
            600,
        )
        .unwrap();
        maker.publish(&event).await.unwrap();
        let Some(Incoming::Offers(author, offers)) = taker.next(WAIT).await else {
            panic!("no offer")
        };
        assert_eq!(
            (author.nick.as_str(), offers),
            (maker.keys().nick(), vec![offer])
        );

        // The taker's !orderbook reaches the maker.
        let orderbook =
            public_event(taker.keys(), "regtest", "!orderbook", &relays, unix_now()).unwrap();
        taker.publish(&orderbook).await.unwrap();
        let Some(Incoming::Public(author, commands)) = maker.next(WAIT).await else {
            panic!("no orderbook")
        };
        assert_eq!(
            (author.nick.as_str(), commands),
            (taker.keys().nick(), vec![Command::Orderbook])
        );

        // A gift-wrapped !fill reaches the maker as a verified line, on the relays the maker advertised.
        let secp = Secp256k1::new();
        let line = sign_line(
            &secp,
            taker.keys().secret(),
            maker.keys().nick(),
            "fill",
            "0 1000000 ab P00",
            NOSTR_HOSTID,
        )
        .unwrap();
        taker
            .send_line(
                &maker.keys().nostr().public_key(),
                &author_relays(&url),
                &line,
            )
            .await
            .unwrap();
        let Some(Incoming::Private(msg, _)) = maker.next(WAIT).await else {
            panic!("no private message")
        };
        assert_eq!(
            (msg.from.as_str(), msg.command.as_str()),
            (taker.keys().nick(), "fill")
        );

        // A 40 KB line is split, delivered and reassembled.
        let body = "A".repeat(40_000);
        let line = sign_line(
            &secp,
            maker.keys().secret(),
            taker.keys().nick(),
            "tx",
            &body,
            NOSTR_HOSTID,
        )
        .unwrap();
        maker
            .send_line(
                &taker.keys().nostr().public_key(),
                &author_relays(&url),
                &line,
            )
            .await
            .unwrap();
        let Some(Incoming::Private(msg, _)) = taker.next(WAIT).await else {
            panic!("no split message")
        };
        assert_eq!((msg.command.as_str(), msg.body.len()), ("tx", 40_000));

        maker.shutdown().await;
        taker.shutdown().await;
    }

    fn author_relays(url: &str) -> Vec<String> {
        vec![url.to_string()]
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn someone_elses_mail_and_other_networks_are_ignored() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let (mut maker, taker) = pair(&url).await;
        let eve = NickClient::connect(
            NickKeys::generate(),
            "mainnet",
            std::slice::from_ref(&url),
            None,
            WAIT,
        )
        .await
        .unwrap();
        // A mainnet orderbook request is not seen by a regtest maker.
        let other_net = public_event(
            eve.keys(),
            "mainnet",
            "!orderbook",
            &[url.as_str()],
            unix_now(),
        )
        .unwrap();
        eve.publish(&other_net).await.unwrap();
        // A line addressed to someone else (but wrapped for the maker) is refused at the line check.
        let secp = Secp256k1::new();
        let wrong = sign_line(
            &secp,
            taker.keys().secret(),
            eve.keys().nick(),
            "fill",
            "0 1",
            NOSTR_HOSTID,
        )
        .unwrap();
        taker
            .send_line(
                &maker.keys().nostr().public_key(),
                std::slice::from_ref(&url),
                &wrong,
            )
            .await
            .unwrap();
        assert_eq!(maker.next(Duration::from_secs(3)).await, None);
    }
}
