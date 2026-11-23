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

    // A gift wrap is encrypted to its recipient, and its seal is signed by the sender's nick key.
    fn authenticates(&self, _route: &NostrRoute) -> bool {
        true
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
        // On the side: a relay that stalls it must not hold up the driver's loop.
        let connecting = self.sibling_later(NickKeys::generate(), CONNECT_TIMEOUT);
        let (network, relays) = (self.network().to_string(), self.relays().to_vec());
        let line = line.to_string();
        self.unlinked().spawn(async move {
            let Ok(throwaway) = connecting.await else {
                return;
            };
            let refs: Vec<&str> = relays.iter().map(String::as_str).collect();
            if let Ok(event) = public_event(throwaway.keys(), &network, &line, &refs, unix_now()) {
                let _ = throwaway.publish(&event).await;
            }
            throwaway.shutdown().await;
        })
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use nostr_sdk::prelude::MockRelay;
    use vortex_ng_core::command::Command;

    use crate::client::{Incoming, NickClient, unix_now};
    use crate::event::public_event;
    use crate::keys::NickKeys;
    use crate::socks::{DirectConnector, Outbound, SocksShim};

    #[tokio::test(flavor = "multi_thread")]
    async fn every_nick_and_its_sibling_has_a_path_of_its_own() {
        use crate::testing::AuthSocks;

        let relay = MockRelay::run().await.unwrap();
        // A name only the proxy can resolve: nothing reaches this relay directly.
        let port = relay
            .url()
            .await
            .to_string()
            .rsplit(':')
            .next()
            .unwrap()
            .trim_end_matches('/')
            .to_string();
        let relays = vec![format!("ws://relay.test:{port}")];
        let proxy = AuthSocks::start().await.unwrap();
        let outbound = Outbound::IsolatingProxy(proxy.addr());
        assert!(!outbound.is_direct() && Outbound::default().is_direct());
        let wait = Duration::from_secs(10);

        let mut maker =
            NickClient::connect_via(NickKeys::generate(), "regtest", &relays, &outbound, wait)
                .await
                .unwrap();
        let taker =
            NickClient::connect_via(NickKeys::generate(), "regtest", &relays, &outbound, wait)
                .await
                .unwrap();
        // The nick a maker sends `!hp2` from.
        let throwaway = maker.sibling(NickKeys::generate(), wait).await.unwrap();
        maker.subscribe(unix_now() - 60, false, true).await.unwrap();
        let deadline = std::time::Instant::now() + wait;
        let mut heard = Vec::new();
        while heard.len() < 2 {
            for from in [&taker, &throwaway] {
                let event = public_event(
                    from.keys(),
                    "regtest",
                    "!orderbook",
                    &[relays[0].as_str()],
                    unix_now(),
                )
                .unwrap();
                from.publish(&event).await.unwrap();
            }
            while let Some(Incoming::Public(author, _)) =
                maker.next(Duration::from_millis(1100)).await
            {
                if !heard.contains(&author.nick) {
                    heard.push(author.nick);
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "nothing through the proxy"
            );
        }
        // Three nicks, three sets of credentials; every connection was for the relay, by its name.
        assert_eq!(proxy.usernames().len(), 3);
        assert!(
            proxy
                .seen()
                .iter()
                .all(|(_, to)| *to == format!("relay.test:{port}"))
        );

        // The other ways out: a direct path has no proxy; a given address is used as it is.
        let direct = Outbound::Direct.path().await.unwrap();
        assert!(direct.proxy().is_none() && !direct.is_own());
        let fixed = Outbound::Proxy(proxy.addr()).path().await.unwrap();
        assert!(fixed.proxy() == Some(proxy.addr()) && !fixed.is_own());
        let own = outbound.path().await.unwrap();
        assert!(own.is_own() && own.proxy() != Some(proxy.addr()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_nick_client_reaches_its_relay_through_the_shim() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let shim = SocksShim::start(DirectConnector).await.unwrap();
        let wait = Duration::from_secs(10);
        let relays = vec![url.clone()];
        let mut maker = NickClient::connect(
            NickKeys::generate(),
            "regtest",
            &relays,
            Some(shim.addr()),
            wait,
        )
        .await
        .unwrap();
        let taker = NickClient::connect(NickKeys::generate(), "regtest", &relays, None, wait)
            .await
            .unwrap();
        maker.subscribe(unix_now() - 60, false, true).await.unwrap();
        // An ephemeral event reaches only the subscriptions the relay already has, and `subscribe` returns
        // once the request is sent, not once the relay has it. So ask until it arrives: a new second each
        // time, hence a new event.
        let deadline = std::time::Instant::now() + wait;
        let commands = loop {
            let event = public_event(
                taker.keys(),
                "regtest",
                "!orderbook",
                &[url.as_str()],
                unix_now(),
            )
            .unwrap();
            taker.publish(&event).await.unwrap();
            if let Some(Incoming::Public(_, commands)) =
                maker.next(Duration::from_millis(1100)).await
            {
                break commands;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "nothing through the proxy"
            );
        };
        assert_eq!(commands, vec![Command::Orderbook]);
    }
}
