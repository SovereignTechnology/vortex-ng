//! Several channels run as one ([`ChannelSet`]), and the type erasure that allows it ([`DynChannel`]).
//!
//! The rules (ADR 0007) are this project's, not a copy of joinmarket-clientserver's message channel
//! collection:
//!
//! - A peer nick is tied to the channel a round with it runs on: where its `!fill` arrived (a maker) or where
//!   we sent it ours (a taker). Only a `!fill` ties, because any other signed line can be delivered onto a
//!   channel by someone who saw it, and a tie made that way would steer the peer's round there. While the tie
//!   lasts ([`PIN_TTL`] since its last private line) the nick's private lines on any other channel are
//!   dropped, so a session never crosses channels. Public lines pass from every channel.
//! - Each channel signs and verifies with its own `hostid`; the set never moves a line between channels.
//! - A maker gives every channel the same nick; a taker gives each channel a nick of its own
//!   ([`Channel::nick_on`] tells which one a peer knows).
//! - Asking for the orderbook, announcing and withdrawing offers, and unlinked publishing go to every open
//!   channel and succeed when one does.

use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};

use vortex_ng_core::offer::{Offer, Pit};

use crate::{Channel, ChannelError, Incoming, Next};

/// How long a peer nick stays tied to its channel after its last private line (JoinMarket-NG's
/// session timeout).
pub const PIN_TTL: Duration = Duration::from_secs(300);
/// Most peer nicks tied at once. Beyond that, new peers are served without a tie until old ties expire.
pub const MAX_PINS: usize = 10_000;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A channel's route with its type erased.
#[derive(Clone)]
pub struct AnyRoute(Arc<dyn Any + Send + Sync>);

impl std::fmt::Debug for AnyRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AnyRoute")
    }
}

fn erase<R: Send + Sync + 'static>(incoming: Incoming<R>) -> Incoming<AnyRoute> {
    let wrap = |route: R| AnyRoute(Arc::new(route));
    match incoming {
        Incoming::Private { msg, route } => Incoming::Private {
            msg,
            route: wrap(route),
        },
        Incoming::Offers {
            nick,
            offers,
            route,
        } => Incoming::Offers {
            nick,
            offers,
            route: wrap(route),
        },
        Incoming::Public {
            nick,
            commands,
            route,
        } => Incoming::Public {
            nick,
            commands,
            route: wrap(route),
        },
    }
}

/// [`Channel`] with its route type erased, so channels of different kinds can be held together. Every
/// [`Channel`] is one.
pub trait DynChannel: Send + Sync {
    /// [`Channel::nick`].
    fn erased_nick(&self) -> &str;
    /// [`Channel::nick_on`]; `None` for a route of another channel.
    fn erased_nick_on(&self, route: &AnyRoute) -> Option<&str>;
    /// [`Channel::authenticates`]; `false` for a route of another channel.
    fn erased_authenticates(&self, route: &AnyRoute) -> bool;
    /// [`Channel::listen`].
    fn erased_listen(&self, offers: bool, public: bool) -> BoxFuture<'_, Result<(), ChannelError>>;
    /// [`Channel::send_private`].
    fn erased_send_private<'a>(
        &'a self,
        route: &'a AnyRoute,
        to: &'a str,
        command: &'a str,
        body: &'a str,
    ) -> BoxFuture<'a, Result<(), ChannelError>>;
    /// [`Channel::ask_orderbook`].
    fn erased_ask_orderbook(&self) -> BoxFuture<'_, Result<(), ChannelError>>;
    /// [`Channel::announce_offers`].
    fn erased_announce_offers<'a>(
        &'a self,
        pit: Pit,
        offers: &'a [Offer],
    ) -> BoxFuture<'a, Result<(), ChannelError>>;
    /// [`Channel::withdraw_offers`].
    fn erased_withdraw_offers(&self, pit: Pit) -> BoxFuture<'_, Result<(), ChannelError>>;
    /// [`Channel::publish_unlinked`].
    fn erased_publish_unlinked<'a>(
        &'a self,
        line: &'a str,
    ) -> BoxFuture<'a, Result<(), ChannelError>>;
    /// [`Channel::prepare`], for the peers whose routes are this channel's.
    fn erased_prepare<'a>(&'a self, peers: &'a [(String, AnyRoute)]) -> BoxFuture<'a, ()>;
    /// [`Channel::receive`].
    fn erased_receive(&mut self, wait: Duration) -> BoxFuture<'_, Next<AnyRoute>>;
    /// [`Channel::shutdown`].
    fn erased_shutdown(&self) -> BoxFuture<'_, ()>;
}

impl<C: Channel> DynChannel for C {
    fn erased_nick(&self) -> &str {
        Channel::nick(self)
    }

    fn erased_nick_on(&self, route: &AnyRoute) -> Option<&str> {
        let route = route.0.downcast_ref::<C::Route>()?;
        Some(Channel::nick_on(self, route))
    }

    fn erased_authenticates(&self, route: &AnyRoute) -> bool {
        route
            .0
            .downcast_ref::<C::Route>()
            .is_some_and(|route| Channel::authenticates(self, route))
    }

    fn erased_listen(&self, offers: bool, public: bool) -> BoxFuture<'_, Result<(), ChannelError>> {
        Box::pin(Channel::listen(self, offers, public))
    }

    fn erased_send_private<'a>(
        &'a self,
        route: &'a AnyRoute,
        to: &'a str,
        command: &'a str,
        body: &'a str,
    ) -> BoxFuture<'a, Result<(), ChannelError>> {
        Box::pin(async move {
            let route = route
                .0
                .downcast_ref::<C::Route>()
                .ok_or(ChannelError::Invalid("a route of another channel"))?;
            Channel::send_private(self, route, to, command, body).await
        })
    }

    fn erased_ask_orderbook(&self) -> BoxFuture<'_, Result<(), ChannelError>> {
        Box::pin(Channel::ask_orderbook(self))
    }

    fn erased_announce_offers<'a>(
        &'a self,
        pit: Pit,
        offers: &'a [Offer],
    ) -> BoxFuture<'a, Result<(), ChannelError>> {
        Box::pin(Channel::announce_offers(self, pit, offers))
    }

    fn erased_withdraw_offers(&self, pit: Pit) -> BoxFuture<'_, Result<(), ChannelError>> {
        Box::pin(Channel::withdraw_offers(self, pit))
    }

    fn erased_publish_unlinked<'a>(
        &'a self,
        line: &'a str,
    ) -> BoxFuture<'a, Result<(), ChannelError>> {
        Box::pin(Channel::publish_unlinked(self, line))
    }

    fn erased_prepare<'a>(&'a self, peers: &'a [(String, AnyRoute)]) -> BoxFuture<'a, ()> {
        let ours: Vec<(String, C::Route)> = peers
            .iter()
            .filter_map(|(nick, route)| {
                let route = route.0.downcast_ref::<C::Route>()?;
                Some((nick.clone(), route.clone()))
            })
            .collect();
        Box::pin(async move { Channel::prepare(self, &ours).await })
    }

    fn erased_receive(&mut self, wait: Duration) -> BoxFuture<'_, Next<AnyRoute>> {
        Box::pin(async move {
            match Channel::receive(self, wait).await {
                Next::Message(incoming) => Next::Message(erase(incoming)),
                Next::Timeout => Next::Timeout,
                Next::Closed => Next::Closed,
            }
        })
    }

    fn erased_shutdown(&self) -> BoxFuture<'_, ()> {
        Box::pin(Channel::shutdown(self))
    }
}

/// A route through one channel of a [`ChannelSet`].
#[derive(Clone, Debug)]
pub struct SetRoute {
    channel: usize,
    route: AnyRoute,
}

/// Several channels run as one (see the module documentation for the rules).
pub struct ChannelSet {
    channels: Vec<Box<dyn DynChannel>>,
    closed: Vec<bool>,
    /// Peer nick -> (channel, last private line).
    pins: Mutex<HashMap<String, (usize, Instant)>>,
    pin_ttl: Duration,
}

impl std::fmt::Debug for ChannelSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelSet")
            .field("channels", &self.channels.len())
            .field("pins", &self.pins.lock().map_or(0, |pins| pins.len()))
            .finish()
    }
}

impl ChannelSet {
    /// A set of `channels`, at least one. Their order is their index in [`Channel::channel_of`].
    pub fn new(channels: Vec<Box<dyn DynChannel>>) -> Result<ChannelSet, ChannelError> {
        if channels.is_empty() {
            return Err(ChannelError::Invalid("a set of no channels"));
        }
        Ok(ChannelSet {
            closed: vec![false; channels.len()],
            channels,
            pins: Mutex::new(HashMap::new()),
            pin_ttl: PIN_TTL,
        })
    }

    /// The same set with another tie duration (tests).
    pub fn with_pin_ttl(mut self, ttl: Duration) -> ChannelSet {
        self.pin_ttl = ttl;
        self
    }

    /// How many channels.
    pub fn len(&self) -> usize {
        self.channels.len()
    }

    /// Whether the set is empty (never, by construction).
    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }

    /// Whether a private line with `command` from `nick` on `channel` belongs there: it does unless the nick
    /// is tied to another channel. A line on the nick's channel keeps the tie fresh; a `!fill` makes one.
    fn admit(&self, nick: &str, channel: usize, command: &str) -> bool {
        let now = Instant::now();
        let Ok(mut pins) = self.pins.lock() else {
            return true;
        };
        if let Some((pinned, at)) = pins.get_mut(nick)
            && now.duration_since(*at) < self.pin_ttl
        {
            if *pinned != channel {
                return false;
            }
            *at = now;
            return true;
        }
        if command == "fill" {
            self.tie(&mut pins, nick, channel, now);
        }
        true
    }

    /// Tie `nick` to `channel`. When the table is full of live ties, the nick goes untied.
    fn tie(
        &self,
        pins: &mut HashMap<String, (usize, Instant)>,
        nick: &str,
        channel: usize,
        now: Instant,
    ) {
        if pins.len() >= MAX_PINS && !pins.contains_key(nick) {
            let ttl = self.pin_ttl;
            pins.retain(|_, (_, at)| now.duration_since(*at) < ttl);
            if pins.len() >= MAX_PINS {
                return;
            }
        }
        pins.insert(nick.to_string(), (channel, now));
    }

    /// Run `op` on every open channel; `Ok` if one succeeded, else the last error.
    async fn on_all<'a, F>(&'a self, op: F) -> Result<(), ChannelError>
    where
        F: Fn(&'a dyn DynChannel) -> BoxFuture<'a, Result<(), ChannelError>>,
    {
        let mut result = Err(ChannelError::Invalid("every channel is closed"));
        for (channel, closed) in self.channels.iter().zip(&self.closed) {
            if *closed {
                continue;
            }
            match op(channel.as_ref()).await {
                Ok(()) => result = Ok(()),
                Err(e) if result.is_err() => result = Err(e),
                Err(_) => {}
            }
        }
        result
    }
}

impl Channel for ChannelSet {
    type Route = SetRoute;

    fn nick(&self) -> &str {
        self.channels[0].erased_nick()
    }

    fn nick_on(&self, route: &SetRoute) -> &str {
        self.channels
            .get(route.channel)
            .and_then(|c| c.erased_nick_on(&route.route))
            .unwrap_or_else(|| self.nick())
    }

    fn channel_of(&self, route: &SetRoute) -> usize {
        route.channel
    }

    fn authenticates(&self, route: &SetRoute) -> bool {
        self.channels
            .get(route.channel)
            .is_some_and(|c| c.erased_authenticates(&route.route))
    }

    async fn listen(&self, offers: bool, public: bool) -> Result<(), ChannelError> {
        self.on_all(|c| c.erased_listen(offers, public)).await
    }

    async fn send_private(
        &self,
        route: &SetRoute,
        to: &str,
        command: &str,
        body: &str,
    ) -> Result<(), ChannelError> {
        let channel = self
            .channels
            .get(route.channel)
            .ok_or(ChannelError::Invalid("no such channel"))?;
        // Our `!fill` starts a round with this peer on this channel.
        if command == "fill"
            && let Ok(mut pins) = self.pins.lock()
        {
            self.tie(&mut pins, to, route.channel, Instant::now());
        }
        channel
            .erased_send_private(&route.route, to, command, body)
            .await
    }

    async fn ask_orderbook(&self) -> Result<(), ChannelError> {
        self.on_all(|c| c.erased_ask_orderbook()).await
    }

    async fn announce_offers(&self, pit: Pit, offers: &[Offer]) -> Result<(), ChannelError> {
        self.on_all(|c| c.erased_announce_offers(pit, offers)).await
    }

    async fn withdraw_offers(&self, pit: Pit) -> Result<(), ChannelError> {
        self.on_all(|c| c.erased_withdraw_offers(pit)).await
    }

    async fn publish_unlinked(&self, line: &str) -> Result<(), ChannelError> {
        self.on_all(|c| c.erased_publish_unlinked(line)).await
    }

    async fn prepare(&self, peers: &[(String, SetRoute)]) {
        for (index, channel) in self.channels.iter().enumerate() {
            let here: Vec<(String, AnyRoute)> = peers
                .iter()
                .filter(|(_, route)| route.channel == index)
                .map(|(nick, route)| (nick.clone(), route.route.clone()))
                .collect();
            if !here.is_empty() {
                channel.erased_prepare(&here).await;
            }
        }
    }

    async fn receive(&mut self, wait: Duration) -> Next<SetRoute> {
        let deadline = Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let closed = &self.closed;
            let mut waiting: Vec<(usize, BoxFuture<'_, Next<AnyRoute>>)> = self
                .channels
                .iter_mut()
                .enumerate()
                .filter(|(i, _)| !closed[*i])
                .map(|(i, c)| (i, c.erased_receive(left)))
                .collect();
            if waiting.is_empty() {
                return Next::Closed;
            }
            // The first channel with something to say; the others' waits are dropped (receive is
            // cancel-safe).
            let (channel, next) = std::future::poll_fn(|cx| {
                for (i, future) in &mut waiting {
                    if let Poll::Ready(next) = future.as_mut().poll(cx) {
                        return Poll::Ready((*i, next));
                    }
                }
                Poll::Pending
            })
            .await;
            drop(waiting);
            let incoming = match next {
                Next::Closed => {
                    self.closed[channel] = true;
                    continue;
                }
                Next::Timeout => return Next::Timeout,
                Next::Message(incoming) => incoming,
            };
            let set_route = |route: AnyRoute| SetRoute { channel, route };
            let message = match incoming {
                Incoming::Private { msg, route } => {
                    if !self.admit(&msg.from, channel, &msg.command) {
                        continue;
                    }
                    Incoming::Private {
                        msg,
                        route: set_route(route),
                    }
                }
                Incoming::Offers {
                    nick,
                    offers,
                    route,
                } => Incoming::Offers {
                    nick,
                    offers,
                    route: set_route(route),
                },
                Incoming::Public {
                    nick,
                    commands,
                    route,
                } => Incoming::Public {
                    nick,
                    commands,
                    route: set_route(route),
                },
            };
            return Next::Message(message);
        }
    }

    async fn shutdown(&self) {
        for channel in &self.channels {
            channel.erased_shutdown().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use vortex_ng_core::nick::NickIdentity;

    use super::*;
    use crate::testing::{MockHandle, MockRoute, Sent, mock_channel};

    const WAIT: Duration = Duration::from_millis(150);

    fn two(nicks: [&str; 2], authenticated: [bool; 2]) -> (ChannelSet, [MockHandle; 2]) {
        let (a, ha) = mock_channel(nicks[0], authenticated[0]);
        let (b, hb) = mock_channel(nicks[1], authenticated[1]);
        let set = ChannelSet::new(vec![Box::new(a), Box::new(b)]).unwrap();
        (set, [ha, hb])
    }

    async fn private_from(set: &mut ChannelSet) -> Option<(String, usize)> {
        match set.receive(WAIT).await {
            Next::Message(Incoming::Private { msg, route }) => {
                Some((msg.from, set.channel_of(&route)))
            }
            _ => None,
        }
    }

    #[tokio::test]
    async fn a_peer_stays_on_the_channel_it_first_spoke_on() {
        let (set, [h0, h1]) = two(["J5maker", "J5maker"], [true, false]);
        let mut set = set.with_pin_ttl(Duration::from_millis(400));
        let taker = NickIdentity::generate();
        let me = taker.nick().to_string();
        h1.deliver_private(&taker, "J5maker", "fill", "0 1000 key commitment", "b");
        assert_eq!(private_from(&mut set).await, Some((me.clone(), 1)));
        // The same nick on the other channel: dropped while it is tied to channel 1.
        h0.deliver_private(&taker, "J5maker", "fill", "0 1000 key commitment", "a");
        assert_eq!(private_from(&mut set).await, None);
        // On its own channel it still comes through, and keeps the tie fresh.
        h1.deliver_private(&taker, "J5maker", "auth", "AAAA", "b");
        assert_eq!(private_from(&mut set).await, Some((me.clone(), 1)));
        // Public lines come from every channel.
        h0.deliver(Incoming::Public {
            nick: me.clone(),
            commands: Vec::new(),
            route: MockRoute("a".into()),
        });
        assert!(matches!(
            set.receive(WAIT).await,
            Next::Message(Incoming::Public { .. })
        ));
        // Once the tie has lapsed, the other channel may take the nick.
        tokio::time::sleep(Duration::from_millis(450)).await;
        h0.deliver_private(&taker, "J5maker", "fill", "0 1000 key other", "a");
        assert_eq!(private_from(&mut set).await, Some((me.clone(), 0)));
        h1.deliver_private(&taker, "J5maker", "fill", "0 1000 key third", "b");
        assert_eq!(private_from(&mut set).await, None);
    }

    #[tokio::test]
    async fn only_a_fill_ties_a_peer_to_a_channel() {
        let (mut set, [h0, h1]) = two(["J5takerA", "J5takerB"], [false, false]);
        let maker = NickIdentity::generate();
        let me = maker.nick().to_string();
        // A maker's signed answer delivered on one channel does not take it off the other.
        h0.deliver_private(&maker, "J5takerA", "sw0absoffer", "0 1 2 3 4", "a");
        assert_eq!(private_from(&mut set).await, Some((me.clone(), 0)));
        h1.deliver_private(&maker, "J5takerB", "sw0absoffer", "0 1 2 3 4", "b");
        let Next::Message(Incoming::Private { route, .. }) = set.receive(WAIT).await else {
            panic!("the answer on the other channel")
        };
        assert_eq!(set.channel_of(&route), 1);
        // Our `!fill` there ties it there.
        set.send_private(&route, &me, "fill", "0 1 k c")
            .await
            .unwrap();
        h0.deliver_private(&maker, "J5takerA", "pubkey", "aa", "a");
        assert_eq!(private_from(&mut set).await, None);
        h1.deliver_private(&maker, "J5takerB", "pubkey", "bb", "b");
        assert_eq!(private_from(&mut set).await, Some((me, 1)));
    }

    #[tokio::test]
    async fn answers_go_back_the_way_they_came_and_requests_go_everywhere() {
        let (mut set, [h0, h1]) = two(["J5takerA", "J5takerB"], [true, false]);
        let maker = NickIdentity::generate();
        h1.deliver_private(&maker, "J5takerB", "sw0absoffer", "0 1 2 3 4", "b-route");
        let Next::Message(Incoming::Private { route, .. }) = set.receive(WAIT).await else {
            panic!("the offer")
        };
        // The nick the maker knows us by, and whether that channel vouches for its senders.
        assert_eq!(set.nick_on(&route), "J5takerB");
        assert!(!set.authenticates(&route));
        set.send_private(&route, maker.nick(), "fill", "0 1 k c")
            .await
            .unwrap();
        assert!(h0.sent().is_empty());
        assert_eq!(
            h1.sent(),
            vec![Sent::Private {
                route: MockRoute("b-route".into()),
                to: maker.nick().to_string(),
                command: "fill".into(),
                body: "0 1 k c".into(),
            }]
        );
        set.ask_orderbook().await.unwrap();
        set.publish_unlinked("!hp2 00").await.unwrap();
        for h in [&h0, &h1] {
            assert!(h.sent().contains(&Sent::AskOrderbook));
            assert!(h.sent().contains(&Sent::Unlinked("!hp2 00".into())));
        }
        // One channel failing does not fail a request to all; every channel failing does.
        h0.fail_sends(true);
        set.ask_orderbook().await.unwrap();
        h1.fail_sends(true);
        assert!(set.ask_orderbook().await.is_err());
    }

    #[tokio::test]
    async fn a_closed_channel_leaves_the_others_running() {
        let (mut set, [h0, h1]) = two(["J5maker", "J5maker"], [true, true]);
        assert!(matches!(set.receive(WAIT).await, Next::Timeout));
        h0.close();
        let taker = NickIdentity::generate();
        h1.deliver_private(&taker, "J5maker", "fill", "x", "b");
        assert!(private_from(&mut set).await.is_some());
        set.ask_orderbook().await.unwrap();
        assert!(!h0.sent().contains(&Sent::AskOrderbook));
        h1.close();
        assert!(matches!(set.receive(WAIT).await, Next::Closed));
        assert!(ChannelSet::new(Vec::new()).is_err());
    }

    #[tokio::test]
    async fn a_route_from_another_channel_is_refused() {
        let (channel, _handle) = mock_channel("J5x", true);
        let wrong = AnyRoute(Arc::new(42u8));
        let refused = DynChannel::erased_send_private(&channel, &wrong, "J5y", "fill", "x").await;
        assert_eq!(
            refused,
            Err(ChannelError::Invalid("a route of another channel"))
        );
        assert!(!DynChannel::erased_authenticates(&channel, &wrong));
        assert_eq!(DynChannel::erased_nick_on(&channel, &wrong), None);
    }
}
