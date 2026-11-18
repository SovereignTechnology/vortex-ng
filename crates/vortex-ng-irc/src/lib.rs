//! JoinMarket's IRC message channel, as joinmarket-clientserver (`jmdaemon/irc.py`) speaks it (ADR 0007).
//!
//! [`codec`] is the part without I/O: IRC lines, JoinMarket's chunking of private messages and its
//! reassembly, the pit channel's name, the server's signature domain, and the line rate servers tolerate.
//! [`channel::IrcChannel`] is one nick on one server's pit channel.

pub mod channel;
pub mod codec;
#[cfg(any(test, feature = "test-util"))]
pub mod testing;

pub use channel::{IrcChannel, IrcConfig, IrcRoute, IrcServer};

#[cfg(test)]
mod tests;
