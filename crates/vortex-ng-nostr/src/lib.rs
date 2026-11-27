//! The Nostr message channel for the JoinMarket protocol (`docs/jmp/jmp-draft-nostr-message-channel.md`).
//!
//! This crate builds and checks the channel's events; relay I/O comes on top. Offers are kind 31402
//! addressable events, public messages kind 21402 ephemeral events, and private messages NIP-59 gift wraps
//! (kind 1059, seal kind 13) whose rumor (kind 21403) carries the unchanged JMP-0001 private-message line.
//! The nick key is the Nostr key. Seal and wrap timestamps are the current time (not randomized), since
//! these messages are read live by subscriptions filtered with `since`.

pub mod channel;
pub mod client;
pub mod event;
pub mod keys;
pub mod pool;
pub mod private;
pub use vortex_ng_channel::socks;
#[cfg(any(test, feature = "test-util"))]
pub use vortex_ng_channel::testing;
#[cfg(feature = "tor")]
pub use vortex_ng_channel::tor;

pub use nostr;

/// Kind of an offer event (addressable; the joinmarket-ng proof of concept's kind).
pub const KIND_OFFER: u16 = 31402;
/// Kind of a public JoinMarket message (ephemeral). Provisional until agreed with joinmarket-ng.
pub const KIND_PUBLIC: u16 = 21402;
/// Kind of the rumor that carries a private message line. Provisional until agreed with joinmarket-ng.
pub const KIND_PRIVATE: u16 = 21403;

/// Most `relay` tags an event or rumor carries (the draft's common tags: one to eight).
pub const MAX_RELAY_TAGS: usize = 8;
/// Longest URL a `relay` tag may hold, bytes.
pub const MAX_RELAY_URL: usize = 256;

/// Whether `url` may stand in a `relay` tag: a `ws://` or `wss://` URL of at most [`MAX_RELAY_URL`] bytes,
/// printable ASCII without spaces. The draft's size limits assume no longer tag.
pub fn valid_relay_url(url: &str) -> bool {
    url.len() <= MAX_RELAY_URL
        && (url.starts_with("wss://") || url.starts_with("ws://"))
        && url.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// One to [`MAX_RELAY_TAGS`] relay URLs, each one [`valid_relay_url`].
fn check_relays<S: AsRef<str>>(relays: &[S]) -> Result<(), ChannelError> {
    if relays.is_empty()
        || relays.len() > MAX_RELAY_TAGS
        || !relays.iter().all(|r| valid_relay_url(r.as_ref()))
    {
        return Err(ChannelError::Invalid(
            "one to eight ws:// or wss:// relay URLs of at most 256 bytes",
        ));
    }
    Ok(())
}

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
