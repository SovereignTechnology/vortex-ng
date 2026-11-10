//! Private messages: NIP-59 gift wraps carrying JMP-0001 private-message lines.
//!
//! rumor (kind 21403, the line or one part of it) → seal (kind 13, signed by the sender's nick key,
//! NIP-44 to the recipient) → wrap (kind 1059, one-time key, NIP-44 to the recipient, `p` and a 600 s
//! `expiration`). All three carry the current time. Lines above 16,000 bytes are split into up to four
//! parts, so every wrap stays within NIP-44 v2's 65,535-byte plaintext limit.

use std::collections::HashMap;

use nostr::nips::nip44::{self, Version};
use nostr::nips::nip59::UnwrappedGift;
use nostr::prelude::{
    Event, EventBuilder, FinalizeEvent, FinalizeUnsignedEvent, Keys, Kind, Tag, Timestamp,
};
use vortex_ng_core::bitcoin::hex::DisplayHex;
use vortex_ng_core::bitcoin::secp256k1::Secp256k1;
use vortex_ng_core::line::{PrivMsg, verify_line};
use vortex_ng_core::protocol::NOSTR_HOSTID;

use crate::keys::{NickKeys, nostr_public};
use crate::{ChannelError, KIND_PRIVATE};

/// Largest part of a line, bytes.
pub const MAX_PART: usize = 16_000;
/// Most parts a line may be split into.
pub const MAX_PARTS: usize = 4;
/// Lifetime of a wrap on relays, seconds (NIP-40 expiration).
pub const WRAP_TTL: u64 = 600;
/// How long a receiver keeps an incomplete message, seconds.
pub const REASSEMBLY_WINDOW: u64 = 60;
/// Incomplete messages kept per sender.
pub const MAX_PENDING_PER_SENDER: usize = 4;

fn crypto<E: std::fmt::Display>(e: E) -> ChannelError {
    ChannelError::Crypto(e.to_string())
}

/// Wrap a JMP-0001 private-message line from `sender` to `recipient` (the recipient's Nostr key, which is
/// its nick key in x-only form). Returns one wrap per part.
pub fn wrap_line(
    sender: &NickKeys,
    recipient: &nostr::key::PublicKey,
    line: &str,
    now: u64,
) -> Result<Vec<Event>, ChannelError> {
    if line.is_empty() || !line.is_ascii() {
        return Err(ChannelError::Invalid("line must be non-empty ASCII"));
    }
    let parts: Vec<&str> = line
        .as_bytes()
        .chunks(MAX_PART)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect();
    if parts.len() > MAX_PARTS {
        return Err(ChannelError::Invalid("line too long"));
    }
    let id = if parts.len() > 1 {
        Keys::generate().public_key().to_bytes()[..16].to_lower_hex_string()
    } else {
        String::new()
    };
    let ts = Timestamp::from_secs(now);
    let mut wraps = Vec::with_capacity(parts.len());
    for (i, part) in parts.iter().enumerate() {
        let mut tags = vec![Tag::public_key(*recipient)];
        if parts.len() > 1 {
            let (index, total) = ((i + 1).to_string(), parts.len().to_string());
            tags.push(
                Tag::parse(["part", index.as_str(), total.as_str(), id.as_str()])
                    .map_err(crypto)?,
            );
        }
        let rumor = EventBuilder::new(Kind::Custom(KIND_PRIVATE), *part)
            .tags(tags)
            .custom_created_at(ts)
            .finalize_unsigned(sender.nostr().public_key());
        let sealed = nip44::encrypt(
            sender.nostr().secret_key(),
            recipient,
            rumor.as_json(),
            Version::V2,
        )
        .map_err(crypto)?;
        let seal = EventBuilder::new(Kind::Seal, sealed)
            .custom_created_at(ts)
            .finalize(sender.nostr())?;
        let one_time = Keys::generate();
        let wrapped = nip44::encrypt(
            one_time.secret_key(),
            recipient,
            seal.as_json(),
            Version::V2,
        )
        .map_err(crypto)?;
        let wrap = EventBuilder::new(Kind::GiftWrap, wrapped)
            .tags([
                Tag::public_key(*recipient),
                Tag::expiration(Timestamp::from_secs(now + WRAP_TTL)),
            ])
            .custom_created_at(ts)
            .finalize(&one_time)?;
        wraps.push(wrap);
    }
    Ok(wraps)
}

/// Which part of a split line a wrap carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    /// 1-based index.
    pub index: usize,
    /// Number of parts.
    pub total: usize,
    /// Message id shared by the parts (32 hex characters).
    pub id: String,
}

/// An unwrapped private message part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Received {
    /// The seal's signer: the sender's nick key, x-only.
    pub sender: nostr::key::PublicKey,
    /// The line, or this part of it.
    pub content: String,
    /// Set when the line was split.
    pub part: Option<Part>,
}

/// Unwrap a gift wrap addressed to `recipient`: the wrap's and the seal's signatures and the rumor's author
/// are checked by rust-nostr; this checks the rumor's kind, recipient, content and part tag.
pub fn unwrap(recipient: &NickKeys, wrap: &Event) -> Result<Received, ChannelError> {
    let gift = UnwrappedGift::from_gift_wrap(recipient.nostr(), wrap).map_err(crypto)?;
    let rumor = gift.rumor;
    if rumor.kind != Kind::Custom(KIND_PRIVATE) {
        return Err(ChannelError::Invalid("rumor kind"));
    }
    let me = recipient.nostr().public_key().to_hex();
    let to: Vec<&str> = rumor
        .tags
        .iter()
        .filter(|t| t.kind() == "p")
        .filter_map(|t| t.content())
        .collect();
    if to != [me.as_str()] {
        return Err(ChannelError::Invalid("rumor recipient"));
    }
    if rumor.content.is_empty() || !rumor.content.is_ascii() || rumor.content.len() > MAX_PART {
        return Err(ChannelError::Invalid("rumor content"));
    }
    let parts: Vec<&[String]> = rumor
        .tags
        .iter()
        .filter(|t| t.kind() == "part")
        .map(|t| t.as_slice())
        .collect();
    let part = match parts.as_slice() {
        [] => None,
        [[_, index, total, id]] => {
            let (index, total): (usize, usize) = (
                index.parse().map_err(|_| ChannelError::Invalid("part"))?,
                total.parse().map_err(|_| ChannelError::Invalid("part"))?,
            );
            let id_ok = id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit());
            if !(2..=MAX_PARTS).contains(&total) || index == 0 || index > total || !id_ok {
                return Err(ChannelError::Invalid("part"));
            }
            Some(Part {
                index,
                total,
                id: id.clone(),
            })
        }
        _ => return Err(ChannelError::Invalid("part")),
    };
    Ok(Received {
        sender: gift.sender,
        content: rumor.content,
        part,
    })
}

struct Pending {
    parts: Vec<Option<String>>,
    first_seen: u64,
}

/// Reassembles split lines with bounded memory.
pub struct Reassembler {
    pending: HashMap<(nostr::key::PublicKey, String), Pending>,
    global_cap: usize,
}

impl Reassembler {
    /// A reassembler keeping at most `global_cap` incomplete messages in total.
    pub fn new(global_cap: usize) -> Reassembler {
        Reassembler {
            pending: HashMap::new(),
            global_cap,
        }
    }

    /// Feed a received part; returns `(sender, line)` once a line is complete.
    pub fn push(
        &mut self,
        received: Received,
        now: u64,
    ) -> Option<(nostr::key::PublicKey, String)> {
        self.pending
            .retain(|_, p| now.saturating_sub(p.first_seen) <= REASSEMBLY_WINDOW);
        let Some(part) = received.part else {
            return Some((received.sender, received.content));
        };
        let key = (received.sender, part.id.clone());
        if !self.pending.contains_key(&key) {
            let from_sender = self
                .pending
                .keys()
                .filter(|(s, _)| *s == received.sender)
                .count();
            if from_sender >= MAX_PENDING_PER_SENDER || self.pending.len() >= self.global_cap {
                return None;
            }
            self.pending.insert(
                key.clone(),
                Pending {
                    parts: vec![None; part.total],
                    first_seen: now,
                },
            );
        }
        let entry = self.pending.get_mut(&key)?;
        if entry.parts.len() != part.total {
            return None;
        }
        entry.parts[part.index - 1] = Some(received.content);
        if entry.parts.iter().all(Option::is_some) {
            let done = self.pending.remove(&key)?;
            return Some((received.sender, done.parts.into_iter().flatten().collect()));
        }
        None
    }
}

/// Verify a complete line from `sender` as a JMP-0001 private message to `recipient` on this channel, and
/// that the line's key is the seal's signer.
pub fn open_line(
    recipient: &NickKeys,
    sender: &nostr::key::PublicKey,
    line: &str,
) -> Result<PrivMsg, ChannelError> {
    let msg = verify_line(
        &Secp256k1::verification_only(),
        line,
        NOSTR_HOSTID,
        recipient.nick(),
    )
    .map_err(ChannelError::Line)?;
    if nostr_public(&msg.key)? != *sender {
        return Err(ChannelError::Invalid("line key is not the seal's signer"));
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use vortex_ng_core::bitcoin::secp256k1::SecretKey;
    use vortex_ng_core::line::sign_line;

    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn keys(b: u8) -> NickKeys {
        NickKeys::from_secret(SecretKey::from_slice(&[b; 32]).unwrap()).unwrap()
    }

    fn line(from: &NickKeys, to: &NickKeys, command: &str, body: &str) -> String {
        sign_line(
            &Secp256k1::new(),
            from.secret(),
            to.nick(),
            command,
            body,
            NOSTR_HOSTID,
        )
        .unwrap()
    }

    #[test]
    fn single_part_round_trip() {
        let (taker, maker) = (keys(1), keys(2));
        let text = line(
            &taker,
            &maker,
            "fill",
            &format!("0 1000000 {} P{}", "ab".repeat(32), "cd".repeat(32)),
        );
        let wraps = wrap_line(&taker, &maker.nostr().public_key(), &text, NOW).unwrap();
        assert_eq!(wraps.len(), 1);
        let wrap = &wraps[0];
        assert_eq!(
            wrap.created_at.as_secs(),
            NOW,
            "timestamps are not randomized"
        );
        assert_ne!(
            wrap.pubkey,
            taker.nostr().public_key(),
            "the wrap hides the sender"
        );
        let received = unwrap(&maker, wrap).unwrap();
        assert_eq!(received.sender, taker.nostr().public_key());
        let (sender, full) = Reassembler::new(16).push(received, NOW).unwrap();
        let msg = open_line(&maker, &sender, &full).unwrap();
        assert_eq!(
            (msg.from.as_str(), msg.command.as_str()),
            (taker.nick(), "fill")
        );
        // Only the recipient can open it.
        assert!(unwrap(&keys(3), wrap).is_err());
    }

    #[test]
    fn long_lines_split_and_reassemble() {
        let (taker, maker) = (keys(1), keys(2));
        let text = line(&taker, &maker, "tx", &"A".repeat(40_000));
        let wraps = wrap_line(&taker, &maker.nostr().public_key(), &text, NOW).unwrap();
        assert_eq!(wraps.len(), 3);
        for wrap in &wraps {
            assert!(
                wrap.as_json().len() < 65_536,
                "wrap fits common relay limits"
            );
        }
        let mut r = Reassembler::new(16);
        let mut out = None;
        for wrap in wraps.iter().rev() {
            out = r.push(unwrap(&maker, wrap).unwrap(), NOW + 1).or(out);
        }
        let (sender, full) = out.unwrap();
        assert_eq!(full, text);
        open_line(&maker, &sender, &full).unwrap();
        assert!(
            wrap_line(
                &taker,
                &maker.nostr().public_key(),
                &"x".repeat(MAX_PART * MAX_PARTS + 1),
                NOW
            )
            .is_err()
        );
    }

    #[test]
    fn reassembly_is_bounded() {
        let sender = keys(1).nostr().public_key();
        let part = |id: u8, index: usize| Received {
            sender,
            content: "x".into(),
            part: Some(Part {
                index,
                total: 2,
                id: format!("{id:032x}"),
            }),
        };
        let mut r = Reassembler::new(100);
        for id in 0..MAX_PENDING_PER_SENDER as u8 {
            assert!(r.push(part(id, 1), NOW).is_none());
        }
        // A fifth concurrent message from the same sender is dropped...
        assert!(r.push(part(9, 1), NOW).is_none());
        assert!(r.push(part(9, 2), NOW).is_none());
        // ...while a pending one still completes.
        assert_eq!(r.push(part(0, 2), NOW).unwrap().1, "xx");
        // Stale parts expire.
        assert!(r.push(part(1, 2), NOW + REASSEMBLY_WINDOW + 1).is_none());
    }

    #[test]
    fn line_must_match_the_seal_signer() {
        let (taker, maker, mallory) = (keys(1), keys(2), keys(4));
        // Mallory forwards a line Taker signed, inside her own seal.
        let text = line(&taker, &maker, "fill", "0 1");
        let wraps = wrap_line(&mallory, &maker.nostr().public_key(), &text, NOW).unwrap();
        let received = unwrap(&maker, &wraps[0]).unwrap();
        assert_eq!(
            open_line(&maker, &received.sender, &received.content),
            Err(ChannelError::Invalid("line key is not the seal's signer"))
        );
        // A line for someone else is refused.
        let other = line(&taker, &mallory, "fill", "0 1");
        assert!(matches!(
            open_line(&maker, &taker.nostr().public_key(), &other),
            Err(ChannelError::Line(_))
        ));
    }
}
