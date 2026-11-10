//! Protocol constants (JMP-0001 "Nick Format", "Phase 1", and the Nostr channel draft).

/// JoinMarket protocol version, carried in every nick.
pub const JM_VERSION: u8 = 5;

/// First character of every JoinMarket nick.
pub const NICK_HEADER: char = 'J';

/// Bytes of `SHA256(hex(pubkey))` kept in a nick before base58 encoding.
pub const NICK_HASH_LENGTH: usize = 10;

/// Characters of the encoded hash portion of a nick, after right padding.
pub const NICK_MAX_ENCODED: usize = 14;

/// Right-padding character of the nick hash portion. It is not in the base58 alphabet.
pub const NICK_PADDING: char = 'O';

/// Prefix of every JoinMarket command, and the separator of concatenated commands.
pub const COMMAND_PREFIX: char = '!';

/// The `hostid` appended to the signed plaintext of every message on the Nostr channel.
///
/// It differs from the onion transports' `onion-network`, so a signature made for one transport
/// never verifies on the other.
pub const NOSTR_HOSTID: &str = "nostr-network";

/// JMP-0001's fixed maker-change coordination threshold, in satoshis.
pub const MAKER_CHANGE_THRESHOLD_SAT: u64 = 27_300;
