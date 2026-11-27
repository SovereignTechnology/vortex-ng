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
use crate::{ChannelError, KIND_PRIVATE, check_relays, valid_relay_url};

/// Largest part of a line, bytes.
pub const MAX_PART: usize = 16_000;
/// Most parts a line may be split into.
pub const MAX_PARTS: usize = 4;
/// Lifetime of a wrap on relays, seconds (NIP-40 expiration).
pub const WRAP_TTL: u64 = 600;
/// How long a receiver keeps an incomplete message, seconds.
pub const REASSEMBLY_WINDOW: u64 = 60;
/// Most `relay` tags a rumor carries (where the sender reads its private messages).
pub const MAX_REPLY_RELAYS: usize = crate::MAX_RELAY_TAGS;
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
    reply_relays: &[String],
    now: u64,
) -> Result<Vec<Event>, ChannelError> {
    check_relays(reply_relays)?;
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
    let mut wraps = Vec::with_capacity(parts.len());
    for (i, part) in parts.iter().enumerate() {
        let mut tags = vec![Tag::public_key(*recipient)];
        for relay in reply_relays {
            tags.push(Tag::parse(["relay", relay.as_str()]).map_err(crypto)?);
        }
        if parts.len() > 1 {
            let (index, total) = ((i + 1).to_string(), parts.len().to_string());
            tags.push(
                Tag::parse(["part", index.as_str(), total.as_str(), id.as_str()])
                    .map_err(crypto)?,
            );
        }
        wraps.push(seal_and_wrap(sender, recipient, part, tags, now)?);
    }
    Ok(wraps)
}

/// A rumor of `content` and `tags` from `sender`, sealed and gift-wrapped for `recipient` (NIP-59).
fn seal_and_wrap(
    sender: &NickKeys,
    recipient: &nostr::key::PublicKey,
    content: &str,
    tags: Vec<Tag>,
    now: u64,
) -> Result<Event, ChannelError> {
    let ts = Timestamp::from_secs(now);
    let rumor = EventBuilder::new(Kind::Custom(KIND_PRIVATE), content)
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
    Ok(EventBuilder::new(Kind::GiftWrap, wrapped)
        .tags([
            Tag::public_key(*recipient),
            Tag::expiration(Timestamp::from_secs(now + WRAP_TTL)),
        ])
        .custom_created_at(ts)
        .finalize(&one_time)?)
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
    /// Relays where the sender reads its private messages (from the rumor; at most eight, `ws://`/`wss://`).
    pub relays: Vec<String>,
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
        [[_, index, total, id]] => Some(parse_part(index, total, id)?),
        _ => return Err(ChannelError::Invalid("part")),
    };
    let relays: Vec<String> = rumor
        .tags
        .iter()
        .filter(|t| t.kind() == "relay")
        .filter_map(|t| t.content())
        .filter(|r| valid_relay_url(r))
        .take(MAX_REPLY_RELAYS)
        .map(str::to_string)
        .collect();
    if relays.is_empty() {
        return Err(ChannelError::Invalid("rumor names no reply relay"));
    }
    Ok(Received {
        sender: gift.sender,
        content: rumor.content,
        part,
        relays,
    })
}

struct Pending {
    parts: Vec<Option<String>>,
    first_seen: u64,
}

/// A complete line from a sender, with the relays it reads its private messages on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivered {
    /// The seal's signer.
    pub sender: nostr::key::PublicKey,
    /// The whole line.
    pub line: String,
    /// The sender's reply relays.
    pub relays: Vec<String>,
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

    /// Feed a received part; returns the whole line once it is complete.
    pub fn push(&mut self, received: Received, now: u64) -> Option<Delivered> {
        self.pending
            .retain(|_, p| now.saturating_sub(p.first_seen) <= REASSEMBLY_WINDOW);
        let Some(part) = received.part else {
            return Some(Delivered {
                sender: received.sender,
                line: received.content,
                relays: received.relays,
            });
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
            return Some(Delivered {
                sender: received.sender,
                line: done.parts.into_iter().flatten().collect(),
                relays: received.relays,
            });
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

/// The values of a `["part", "<i>", "<n>", "<id>"]` tag: `i` and `n` in decimal digits only (`str::parse`
/// alone would also take a leading `+`), `id` 32 lowercase hex characters. Another implementation keys its
/// reassembly on the id as sent, so an id we accepted in another case would not be the same message there.
fn parse_part(index: &str, total: &str, id: &str) -> Result<Part, ChannelError> {
    // Leading zeros are read as joinmarket-ng reads them (`int("02")`); a value too long to parse is out of
    // range anyway.
    let number = |text: &str| -> Option<usize> {
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let digits = text.trim_start_matches('0');
        if digits.is_empty() {
            Some(0)
        } else {
            digits.parse().ok()
        }
    };
    let (Some(index), Some(total)) = (number(index), number(total)) else {
        return Err(ChannelError::Invalid("part"));
    };
    let id_ok = id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !(2..=MAX_PARTS).contains(&total) || index == 0 || index > total || !id_ok {
        return Err(ChannelError::Invalid("part"));
    }
    Ok(Part {
        index,
        total,
        id: id.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use vortex_ng_core::bitcoin::secp256k1::SecretKey;
    use vortex_ng_core::line::sign_line;

    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn relays() -> Vec<String> {
        vec!["wss://relay.example".to_string()]
    }

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
    fn part_tags_are_strict() {
        let id = "0123456789abcdef".repeat(2);
        let part = parse_part("2", "4", &id).unwrap();
        assert_eq!(
            (part.index, part.total, part.id.as_str()),
            (2, 4, id.as_str())
        );
        // As joinmarket-ng reads them: decimal digits, leading zeros allowed.
        assert_eq!(parse_part("02", "0004", &id).unwrap().total, 4);
        for (index, total, id) in [
            ("+2", "4", id.as_str()),
            ("2", "+4", id.as_str()),
            ("0", "4", id.as_str()),
            ("5", "4", id.as_str()),
            ("1", "1", id.as_str()),
            ("1", "5", id.as_str()),
            ("", "4", id.as_str()),
            ("2", "99999999999999999999999999", id.as_str()),
            ("2", " 4", id.as_str()),
            ("٢", "4", id.as_str()),
            ("2", "4", &id.to_uppercase()),
            ("2", "4", &id[..30]),
            ("2", "4", &format!("{}zz", &id[..30])),
        ] {
            assert!(
                parse_part(index, total, id).is_err(),
                "{index} {total} {id}"
            );
        }
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
        let wraps = wrap_line(&taker, &maker.nostr().public_key(), &text, &relays(), NOW).unwrap();
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
        let Delivered {
            sender,
            line: full,
            relays: reply,
        } = Reassembler::new(16).push(received, NOW).unwrap();
        assert_eq!(reply, relays());
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
        let wraps = wrap_line(&taker, &maker.nostr().public_key(), &text, &relays(), NOW).unwrap();
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
        let Delivered {
            sender, line: full, ..
        } = out.unwrap();
        assert_eq!(full, text);
        open_line(&maker, &sender, &full).unwrap();
        assert!(
            wrap_line(
                &taker,
                &maker.nostr().public_key(),
                &"x".repeat(MAX_PART * MAX_PARTS + 1),
                &relays(),
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
            relays: relays(),
        };
        let mut r = Reassembler::new(100);
        for id in 0..MAX_PENDING_PER_SENDER as u8 {
            assert!(r.push(part(id, 1), NOW).is_none());
        }
        // A fifth concurrent message from the same sender is dropped...
        assert!(r.push(part(9, 1), NOW).is_none());
        assert!(r.push(part(9, 2), NOW).is_none());
        // ...while a pending one still completes.
        assert_eq!(r.push(part(0, 2), NOW).unwrap().line, "xx");
        // Stale parts expire.
        assert!(r.push(part(1, 2), NOW + REASSEMBLY_WINDOW + 1).is_none());
    }

    #[test]
    fn line_must_match_the_seal_signer() {
        let (taker, maker, mallory) = (keys(1), keys(2), keys(4));
        // Mallory forwards a line Taker signed, inside her own seal.
        let text = line(&taker, &maker, "fill", "0 1");
        let wraps =
            wrap_line(&mallory, &maker.nostr().public_key(), &text, &relays(), NOW).unwrap();
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

    /// Eight relay URLs of the longest length a `relay` tag may hold.
    fn longest_relays() -> Vec<String> {
        (0..8)
            .map(|i| format!("wss://{i}{}", "r".repeat(249)))
            .collect()
    }

    #[test]
    fn reply_relays_follow_the_relay_tag_rules() {
        let (taker, maker) = (keys(1), keys(2));
        let text = line(&taker, &maker, "fill", "0 1");
        let to = maker.nostr().public_key();
        let wraps = wrap_line(&taker, &to, &text, &longest_relays(), NOW).unwrap();
        assert_eq!(unwrap(&maker, &wraps[0]).unwrap().relays, longest_relays());
        let mut nine = longest_relays();
        nine.push("wss://ninth.example".to_string());
        for bad in [
            vec![],
            nine,
            vec![format!("wss://{}", "r".repeat(251))],
            vec!["https://relay.example".to_string()],
        ] {
            assert!(wrap_line(&taker, &to, &text, &bad, NOW).is_err(), "{bad:?}");
        }
        // A sender breaking the rules: its unusable relay tags are passed over, the first eight usable kept.
        let mut tags = vec![Tag::public_key(to)];
        for relay in [
            format!("wss://{}", "r".repeat(251)),
            "https://relay.example".to_string(),
            "wss://relay.example/a b".to_string(),
        ]
        .into_iter()
        .chain(longest_relays())
        .chain(["wss://ninth.example".to_string()])
        {
            tags.push(Tag::parse(["relay", relay.as_str()]).unwrap());
        }
        let wrap = seal_and_wrap(&taker, &to, &text, tags, NOW).unwrap();
        assert_eq!(unwrap(&maker, &wrap).unwrap().relays, longest_relays());
        // With none usable the message is dropped.
        let tags = vec![
            Tag::public_key(to),
            Tag::parse(["relay", "https://relay.example"]).unwrap(),
        ];
        let wrap = seal_and_wrap(&taker, &to, &text, tags, NOW).unwrap();
        assert_eq!(
            unwrap(&maker, &wrap),
            Err(ChannelError::Invalid("rumor names no reply relay"))
        );
    }

    #[test]
    fn the_largest_wrap_fits_the_draft_size_floor() {
        // The draft's worst case: a full 16,000-byte part of a split line, with eight 256-byte relay tags.
        let (taker, maker) = (keys(1), keys(2));
        // A one-byte body gives the length of everything else in the line.
        let rest = line(&taker, &maker, "tx", "A").len() - 1;
        let text = line(
            &taker,
            &maker,
            "tx",
            &"A".repeat(MAX_PART * MAX_PARTS - rest),
        );
        assert_eq!(text.len(), MAX_PART * MAX_PARTS);
        let wraps = wrap_line(
            &taker,
            &maker.nostr().public_key(),
            &text,
            &longest_relays(),
            NOW,
        )
        .unwrap();
        assert_eq!(wraps.len(), MAX_PARTS);
        let first = &wraps[0];
        assert_eq!(unwrap(&maker, first).unwrap().content.len(), MAX_PART);
        let message = format!(r#"["EVENT",{}]"#, first.as_json());
        // What the draft states, and what it asks every relay to accept (40,000 and 39,000).
        assert_eq!((message.len(), first.content.len()), (38_775, 38_320));
        assert!(message.len() <= 40_000 && first.content.len() <= 39_000);
    }
}
