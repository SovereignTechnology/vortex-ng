//! The message channel a vortex-ng maker or taker runs over.
//!
//! JoinMarket separates its protocol (commands, NaCl sessions, PoDLE, fidelity bonds) from the message
//! channel that carries it: public messages to everyone, private messages to a nick, offers, and the
//! `!hp2` broadcast (JMP-0001). vortex-ng's maker and taker are state machines that speak the protocol; the
//! drivers in `vortex-ng-node` connect them to a [`Channel`]. Nostr (`vortex-ng-nostr`) is one; JoinMarket's
//! onion directories and IRC are others (ADR 0007).
//!
//! A channel signs the private lines it sends with its own nick key and `hostid`, and hands the driver only
//! lines it has verified. How a peer is reached on the channel is the channel's business: it hands the
//! driver an opaque [`Channel::Route`] with each message, and the driver gives the route back to answer.

pub mod set;
pub mod socks;
#[cfg(any(test, feature = "test-util"))]
pub mod testing;
#[cfg(feature = "tor")]
pub mod tor;

use std::future::Future;
use std::time::Duration;

use vortex_ng_core::command::Command;
use vortex_ng_core::line::{LineError, PrivMsg};
use vortex_ng_core::offer::{Offer, Pit};

/// Why a channel operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// An argument breaks the channel's rules, or a peer cannot be reached on it.
    Invalid(&'static str),
    /// A private-message line could not be signed or did not verify (JMP-0001 nick signature).
    Line(LineError),
    /// Sending or receiving failed; the text says how.
    Transport(String),
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelError::Invalid(why) => f.write_str(why),
            ChannelError::Line(e) => write!(f, "{e}"),
            ChannelError::Transport(e) => f.write_str(e),
        }
    }
}

impl std::error::Error for ChannelError {}

/// A message that arrived on a channel and passed all of its checks, with the way back to its sender.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Incoming<R> {
    /// A verified JMP-0001 private message.
    Private {
        /// The line, its signature checked against the sender's nick and the channel's `hostid`.
        msg: PrivMsg,
        /// How to answer the sender.
        route: R,
    },
    /// A maker's offers as the channel announces them publicly. Not authoritative: a taker acts on the
    /// offers a maker sends privately in answer to `!orderbook` (JMP-0001); public offers only tell it who
    /// is there.
    Offers {
        /// The maker's nick.
        nick: String,
        /// Its offers.
        offers: Vec<Offer>,
        /// How to reach it.
        route: R,
    },
    /// A public message: `!orderbook`, `!hp2` or `!cancel`.
    Public {
        /// The sender's nick.
        nick: String,
        /// The commands.
        commands: Vec<Command>,
        /// How to answer it.
        route: R,
    },
}

/// What [`Channel::receive`] came back with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Next<R> {
    /// A message.
    Message(Incoming<R>),
    /// Nothing arrived in time.
    Timeout,
    /// The channel has stopped and nothing more will arrive.
    Closed,
}

/// A message channel for one nick.
pub trait Channel: Send + Sync {
    /// How a peer is reached on this channel; kept by the driver per nick and handed back to answer.
    type Route: Clone + std::fmt::Debug + Send + Sync + 'static;

    /// This channel's nick.
    fn nick(&self) -> &str;

    /// The nick this channel uses toward the peer reached by `route` (what a fidelity-bond proof from that
    /// peer is made out to). One nick per channel, so normally [`Channel::nick`]; a set of channels can use
    /// a different nick on each.
    fn nick_on(&self, route: &Self::Route) -> &str {
        let _ = route;
        self.nick()
    }

    /// Which channel `route` leads through, for keeping per-channel state (a rate limit) apart. `0` for a
    /// single channel.
    fn channel_of(&self, route: &Self::Route) -> usize {
        let _ = route;
        0
    }

    /// Whether a private line that came by `route` had its sender and recipient authenticated by the
    /// channel itself, beyond the line's own signature (which covers neither the command nor the
    /// recipient). Where they are not, a line seen once can be delivered again to anyone, so a driver must
    /// not act on a lone `!error`.
    fn authenticates(&self, route: &Self::Route) -> bool;

    /// Start receiving private messages, and also offers and public messages as asked.
    fn listen(
        &self,
        offers: bool,
        public: bool,
    ) -> impl Future<Output = Result<(), ChannelError>> + Send;

    /// Sign and send a private message `!command body` to `to`, reached by `route`.
    fn send_private(
        &self,
        route: &Self::Route,
        to: &str,
        command: &str,
        body: &str,
    ) -> impl Future<Output = Result<(), ChannelError>> + Send;

    /// Ask every maker for its offers (public `!orderbook`).
    fn ask_orderbook(&self) -> impl Future<Output = Result<(), ChannelError>> + Send;

    /// Announce this nick's offers in `pit` publicly, replacing what it announced before.
    fn announce_offers(
        &self,
        pit: Pit,
        offers: &[Offer],
    ) -> impl Future<Output = Result<(), ChannelError>> + Send;

    /// Withdraw this nick's public offers in `pit`.
    fn withdraw_offers(&self, pit: Pit) -> impl Future<Output = Result<(), ChannelError>> + Send;

    /// Make a public line known without linking it to this nick: what a maker does with a taker's PoDLE
    /// commitment (`!hp2`). Each channel has its own way.
    fn publish_unlinked(&self, line: &str)
    -> impl Future<Output = Result<(), ChannelError>> + Send;

    /// Wait up to `wait` for the next message.
    fn receive(&mut self, wait: Duration) -> impl Future<Output = Next<Self::Route>> + Send;

    /// Stop.
    fn shutdown(&self) -> impl Future<Output = ()> + Send;
}
