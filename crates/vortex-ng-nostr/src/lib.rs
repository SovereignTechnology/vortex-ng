//! The Nostr message channel for the JoinMarket protocol (`docs/jmp/jmp-draft-nostr-message-channel.md`).
//!
//! This crate builds and checks the channel's events; relay I/O comes on top. Offers are kind 31402
//! addressable events, public messages kind 21402 ephemeral events, and private messages NIP-59 gift wraps
//! (kind 1059, seal kind 13) whose rumor (kind 21403) carries the unchanged JMP-0001 private-message line.
//! The nick key is the Nostr key. Seal and wrap timestamps are the current time (not randomized), since
//! these messages are read live by subscriptions filtered with `since`.

pub mod event;
pub mod keys;
pub mod private;

pub use nostr;

/// Kind of an offer event (addressable; the joinmarket-ng proof of concept's kind).
pub const KIND_OFFER: u16 = 31402;
/// Kind of a public JoinMarket message (ephemeral). Provisional until agreed with joinmarket-ng.
pub const KIND_PUBLIC: u16 = 21402;
/// Kind of the rumor that carries a private message line. Provisional until agreed with joinmarket-ng.
pub const KIND_PRIVATE: u16 = 21403;

/// Why an event was not built or not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// An argument or event field breaks the draft's rules.
    Invalid(&'static str),
    /// A signature, id or decryption failed.
    Crypto(String),
    /// The private-message line did not verify (JMP-0001 nick signature).
    Line(vortex_ng_core::line::LineError),
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelError::Invalid(why) => write!(f, "invalid Nostr channel event: {why}"),
            ChannelError::Crypto(e) => write!(f, "Nostr crypto: {e}"),
            ChannelError::Line(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ChannelError {}

impl From<nostr::error::Error> for ChannelError {
    fn from(e: nostr::error::Error) -> Self {
        ChannelError::Crypto(e.to_string())
    }
}
