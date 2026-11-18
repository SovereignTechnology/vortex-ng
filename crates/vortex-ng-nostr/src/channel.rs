//! [`NickClient`] as a [`Channel`]: the Nostr message channel (`docs/jmp/jmp-draft-nostr-message-channel.md`).
//!
//! Private lines are signed with `hostid` `nostr-network` and travel in gift wraps to the recipient's
//! advertised relays; offers are kind 31402 events with a lifetime of [`OFFER_TTL`]; public messages are
//! kind 21402 events; `!hp2` goes out from a throwaway nick on a path of its own.

use std::time::{Duration, Instant};

use vortex_ng_channel::{Channel, ChannelError, Incoming, Next};
use vortex_ng_core::bitcoin::secp256k1::Secp256k1;
use vortex_ng_core::line::sign_line;
use vortex_ng_core::offer::{Offer, Pit};
use vortex_ng_core::protocol::NOSTR_HOSTID;

use crate::client::{self, NickClient, unix_now};
use crate::event::{offer_deletion, offer_event, public_event};
use crate::keys::{NickKeys, nostr_public};

/// Lifetime of a maker's offer event, seconds.
pub const OFFER_TTL: u64 = 1800;
/// How long a relay connection may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Where a nick reads its private messages: its Nostr key and its relays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NostrRoute {
    key: nostr::key::PublicKey,
    relays: Vec<String>,
}

impl NostrRoute {
    fn of(
        key: &vortex_ng_core::bitcoin::secp256k1::PublicKey,
        relays: Vec<String>,
    ) -> Option<NostrRoute> {
        Some(NostrRoute {
            key: nostr_public(key).ok()?,
            relays,
        })
    }
}

impl From<crate::ChannelError> for ChannelError {
    fn from(e: crate::ChannelError) -> Self {
        match e {
            crate::ChannelError::Line(e) => ChannelError::Line(e),
            other => ChannelError::Transport(other.to_string()),
        }
    }
}

impl NickClient {
    fn relay_refs(&self) -> Vec<&str> {
        self.relays().iter().map(String::as_str).collect()
    }
}

impl Channel for NickClient {
    type Route = NostrRoute;

    fn nick(&self) -> &str {
        self.keys().nick()
    }

    fn hostid(&self) -> &str {
        NOSTR_HOSTID
    }

    async fn listen(&self, offers: bool, public: bool) -> Result<(), ChannelError> {
        self.subscribe(unix_now().saturating_sub(60), offers, public)
            .await?;
        Ok(())
    }

    async fn send_private(
        &self,
        route: &NostrRoute,
        to: &str,
        command: &str,
        body: &str,
    ) -> Result<(), ChannelError> {
        let line = sign_line(
            &Secp256k1::signing_only(),
            self.keys().secret(),
            to,
            command,
            body,
            NOSTR_HOSTID,
        )
        .map_err(ChannelError::Line)?;
        self.send_line(&route.key, &route.relays, &line).await?;
        Ok(())
    }

    async fn ask_orderbook(&self) -> Result<(), ChannelError> {
        let event = public_event(
            self.keys(),
            self.network(),
            "!orderbook",
            &self.relay_refs(),
            unix_now(),
        )?;
        self.publish(&event).await?;
        Ok(())
    }

    async fn announce_offers(&self, pit: Pit, offers: &[Offer]) -> Result<(), ChannelError> {
        let event = offer_event(
            self.keys(),
            self.network(),
            pit,
            offers,
            &[],
            &self.relay_refs(),
            unix_now(),
            OFFER_TTL,
        )?;
        self.publish(&event).await?;
        Ok(())
    }

    async fn withdraw_offers(&self, pit: Pit) -> Result<(), ChannelError> {
        let event = offer_deletion(self.keys(), self.network(), pit, unix_now())?;
        self.publish(&event).await?;
        Ok(())
    }

    async fn publish_unlinked(&self, line: &str) -> Result<(), ChannelError> {
        // A fresh nick on its own connection, closed afterwards (the draft's !hp2 rule), reaching the relays
        // the way ours does but on a path of its own: never directly when we are behind a proxy.
        let throwaway = self.sibling(NickKeys::generate(), CONNECT_TIMEOUT).await?;
        let event = public_event(
            throwaway.keys(),
            self.network(),
            line,
            &self.relay_refs(),
            unix_now(),
        )?;
        let result = throwaway.publish(&event).await;
        throwaway.shutdown().await;
        result?;
        Ok(())
    }

    async fn receive(&mut self, wait: Duration) -> Next<NostrRoute> {
        let started = Instant::now();
        loop {
            let left = wait.saturating_sub(started.elapsed());
            let Some(incoming) = NickClient::next(self, left).await else {
                return if started.elapsed() >= wait {
                    Next::Timeout
                } else {
                    Next::Closed
                };
            };
            // A key that is not a Nostr key cannot be answered; the event checks make this unreachable.
            let message = match incoming {
                client::Incoming::Private(msg, relays) => {
                    NostrRoute::of(&msg.key, relays).map(|route| Incoming::Private { msg, route })
                }
                client::Incoming::Offers(author, offers) => {
                    NostrRoute::of(&author.key, author.relays).map(|route| Incoming::Offers {
                        nick: author.nick,
                        offers,
                        route,
                    })
                }
                client::Incoming::Public(author, commands) => {
                    NostrRoute::of(&author.key, author.relays).map(|route| Incoming::Public {
                        nick: author.nick,
                        commands,
                        route,
                    })
                }
            };
            if let Some(message) = message {
                return Next::Message(message);
            }
        }
    }

    async fn shutdown(&self) {
        NickClient::shutdown(self).await;
    }
}
