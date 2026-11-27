//! Offer events (kind 31402) and public messages (kind 21402), and the checks a receiver applies.

use nostr::prelude::{Event, EventBuilder, FinalizeEvent, Kind, Tag, Timestamp};
use vortex_ng_core::bitcoin::hex::FromHex;
use vortex_ng_core::bitcoin::secp256k1::PublicKey;
use vortex_ng_core::command::{Command, parse_plaintext};
use vortex_ng_core::nick::nick_from_pubkey;
use vortex_ng_core::offer::{Offer, Pit};

use crate::keys::{NickKeys, nostr_public};
use crate::{ChannelError, KIND_OFFER, KIND_PUBLIC, check_relays};

/// Longest an offer event may live, seconds.
pub const MAX_OFFER_TTL: u64 = 3600;

/// Who authored a channel event, as its tags state and the checks confirmed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Author {
    /// The author's nick.
    pub nick: String,
    /// The author's compressed nick key.
    pub key: PublicKey,
    /// Relays where the author reads its private messages.
    pub relays: Vec<String>,
    /// Advertised feature identifiers.
    pub features: Vec<String>,
}

/// The indexable network tag value: `joinmarket-<network>` (relays index only single-letter tags).
pub fn network_hashtag(network: &str) -> String {
    format!("joinmarket-{network}")
}

fn tag(values: &[&str]) -> Result<Tag, ChannelError> {
    Tag::parse(values.iter().copied()).map_err(|e| ChannelError::Crypto(e.to_string()))
}

fn common_tags(keys: &NickKeys, network: &str, relays: &[&str]) -> Result<Vec<Tag>, ChannelError> {
    check_relays(relays)?;
    let mut tags = vec![
        tag(&["n", keys.nick()])?,
        tag(&["jmpk", &keys.jmpk_hex()])?,
        tag(&["network", network])?,
        tag(&["t", &network_hashtag(network)])?,
    ];
    for relay in relays {
        tags.push(tag(&["relay", relay])?);
    }
    Ok(tags)
}

/// Build a maker's offer event for one pit: all `offers` must be of `pit`.
#[allow(clippy::too_many_arguments)]
pub fn offer_event(
    keys: &NickKeys,
    network: &str,
    pit: Pit,
    offers: &[Offer],
    features: &[&str],
    relays: &[&str],
    now: u64,
    ttl: u64,
) -> Result<Event, ChannelError> {
    if offers.is_empty() || offers.iter().any(|o| o.offer_type.pit != pit) {
        return Err(ChannelError::Invalid(
            "offers must be non-empty and of one pit",
        ));
    }
    if ttl == 0 || ttl > MAX_OFFER_TTL {
        return Err(ChannelError::Invalid("offer ttl"));
    }
    let content: String = offers.iter().map(Offer::to_command).collect();
    let mut tags = vec![
        tag(&["d", &format!("{network}:{}", pit.prefix())])?,
        tag(&["t", "joinmarket-offer"])?,
    ];
    let mut kinds: Vec<String> = offers.iter().map(|o| o.offer_type.command()).collect();
    kinds.sort();
    kinds.dedup();
    for kind in &kinds {
        tags.push(tag(&["f", kind])?);
    }
    tags.extend(common_tags(keys, network, relays)?);
    tags.push(tag(&["F", &features.join("+")])?);
    tags.push(Tag::expiration(Timestamp::from_secs(now + ttl)));
    Ok(EventBuilder::new(Kind::Custom(KIND_OFFER), content)
        .tags(tags)
        .custom_created_at(Timestamp::from_secs(now))
        .finalize(keys.nostr())?)
}

/// Withdraw a maker's offer event for one pit: a NIP-09 deletion naming the event's `a` coordinate
/// (`31402:<author>:<network>:<pit>`), as the draft requires when the offers are cancelled.
pub fn offer_deletion(
    keys: &NickKeys,
    network: &str,
    pit: Pit,
    now: u64,
) -> Result<Event, ChannelError> {
    let coordinate = format!(
        "{KIND_OFFER}:{}:{network}:{}",
        keys.nostr().public_key().to_hex(),
        pit.prefix()
    );
    Ok(EventBuilder::new(Kind::EventDeletion, "")
        .tags(vec![
            tag(&["a", &coordinate])?,
            tag(&["k", &KIND_OFFER.to_string()])?,
        ])
        .custom_created_at(Timestamp::from_secs(now))
        .finalize(keys.nostr())?)
}

/// Build a public message (`!orderbook`, `!hp2 <c>`, `!cancel <oid>`).
pub fn public_event(
    keys: &NickKeys,
    network: &str,
    content: &str,
    relays: &[&str],
    now: u64,
) -> Result<Event, ChannelError> {
    let commands = parse_plaintext(content).ok_or(ChannelError::Invalid("public message"))?;
    if !commands
        .iter()
        .all(|c| matches!(c, Command::Orderbook | Command::Hp2(_) | Command::Cancel(_)))
    {
        return Err(ChannelError::Invalid(
            "only !orderbook, !hp2 and !cancel are public",
        ));
    }
    Ok(EventBuilder::new(Kind::Custom(KIND_PUBLIC), content)
        .tags(common_tags(keys, network, relays)?)
        .custom_created_at(Timestamp::from_secs(now))
        .finalize(keys.nostr())?)
}

fn values<'a>(event: &'a Event, name: &str) -> Vec<&'a str> {
    event
        .tags
        .iter()
        .filter(|t| t.kind() == name)
        .filter_map(|t| t.content())
        .collect()
}

fn single<'a>(event: &'a Event, name: &'static str) -> Result<&'a str, ChannelError> {
    match values(event, name).as_slice() {
        [one] => Ok(one),
        _ => Err(ChannelError::Invalid(name)),
    }
}

/// Check an event's id and signature, kind and network, and that its `jmpk` and `n` tags name its author.
pub fn verify_author(event: &Event, kind: u16, network: &str) -> Result<Author, ChannelError> {
    event
        .verify()
        .map_err(|e| ChannelError::Crypto(e.to_string()))?;
    if event.kind != Kind::Custom(kind) {
        return Err(ChannelError::Invalid("kind"));
    }
    if single(event, "network")? != network
        || !values(event, "t").contains(&network_hashtag(network).as_str())
    {
        return Err(ChannelError::Invalid("network"));
    }
    let jmpk = single(event, "jmpk")?;
    let bytes = Vec::<u8>::from_hex(jmpk).map_err(|_| ChannelError::Invalid("jmpk"))?;
    if bytes.len() != 33 {
        return Err(ChannelError::Invalid("jmpk"));
    }
    let key = PublicKey::from_slice(&bytes).map_err(|_| ChannelError::Invalid("jmpk"))?;
    if nostr_public(&key)? != event.pubkey {
        return Err(ChannelError::Invalid("jmpk is not the event author"));
    }
    let nick = single(event, "n")?;
    if nick != nick_from_pubkey(&key) {
        return Err(ChannelError::Invalid("nick is not the jmpk's nick"));
    }
    let relays: Vec<String> = values(event, "relay")
        .into_iter()
        .map(str::to_string)
        .collect();
    check_relays(&relays)?;
    let features = values(event, "F")
        .first()
        .map(|f| {
            f.split('+')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Ok(Author {
        nick: nick.to_string(),
        key,
        relays,
        features,
    })
}

/// Check an offer event and return its author and offers. Expired events, events living longer than
/// [`MAX_OFFER_TTL`], offers of several pits, a `d` tag that does not match, or any `!tbond` are rejected.
pub fn read_offer_event(
    event: &Event,
    network: &str,
    now: u64,
) -> Result<(Author, Vec<Offer>), ChannelError> {
    let author = verify_author(event, KIND_OFFER, network)?;
    let created = event.created_at.as_secs();
    let expiration: u64 = single(event, "expiration")?
        .parse()
        .map_err(|_| ChannelError::Invalid("expiration"))?;
    if expiration <= now || expiration > created.saturating_add(MAX_OFFER_TTL) {
        return Err(ChannelError::Invalid("expired or too long-lived"));
    }
    let commands = parse_plaintext(&event.content).ok_or(ChannelError::Invalid("offer content"))?;
    let mut offers = Vec::with_capacity(commands.len());
    for command in commands {
        match command {
            Command::Offer(offer) => offers.push(offer),
            _ => return Err(ChannelError::Invalid("only offers in an offer event")),
        }
    }
    let pit = offers
        .first()
        .map(|o| o.offer_type.pit)
        .ok_or(ChannelError::Invalid("no offers"))?;
    if offers.iter().any(|o| o.offer_type.pit != pit) {
        return Err(ChannelError::Invalid("offers of several pits"));
    }
    if single(event, "d")? != format!("{network}:{}", pit.prefix()) {
        return Err(ChannelError::Invalid("d tag"));
    }
    Ok((author, offers))
}

/// Check a public message and return its author and commands.
pub fn read_public_event(
    event: &Event,
    network: &str,
) -> Result<(Author, Vec<Command>), ChannelError> {
    let author = verify_author(event, KIND_PUBLIC, network)?;
    let commands =
        parse_plaintext(&event.content).ok_or(ChannelError::Invalid("public content"))?;
    if !commands
        .iter()
        .all(|c| matches!(c, Command::Orderbook | Command::Hp2(_) | Command::Cancel(_)))
    {
        return Err(ChannelError::Invalid(
            "only !orderbook, !hp2 and !cancel are public",
        ));
    }
    Ok((author, commands))
}

#[cfg(test)]
mod tests {
    use vortex_ng_core::bitcoin::secp256k1::SecretKey;

    use super::*;

    const NOW: u64 = 1_800_000_000;
    const RELAYS: [&str; 2] = ["wss://relay.example", "wss://relay2.example"];

    fn keys(b: u8) -> NickKeys {
        NickKeys::from_secret(SecretKey::from_slice(&[b; 32]).unwrap()).unwrap()
    }

    fn offers() -> Vec<Offer> {
        vec![
            Offer::parse("sw0reloffer", "0 50000 10000000 0 0.00025").unwrap(),
            Offer::parse("sw0absoffer", "1 50000 10000000 0 250").unwrap(),
        ]
    }

    #[test]
    fn an_offer_event_is_withdrawn_by_its_coordinate() {
        let k = keys(1);
        let event = offer_deletion(&k, "regtest", Pit::Tr0, NOW).unwrap();
        event.verify().unwrap();
        assert_eq!(event.kind, Kind::EventDeletion);
        assert_eq!(event.pubkey, k.nostr().public_key());
        assert_eq!(event.created_at.as_secs(), NOW);
        assert_eq!(event.content, "");
        // The coordinate of the offer event it deletes: kind, author, `d` tag.
        let offer = offer_event(
            &k,
            "regtest",
            Pit::Tr0,
            &tr0_offers(),
            &[],
            &RELAYS,
            NOW,
            1800,
        )
        .unwrap();
        assert_eq!(values(&offer, "d"), vec!["regtest:tr0"]);
        assert_eq!(
            values(&event, "a"),
            vec![format!("31402:{}:regtest:tr0", offer.pubkey.to_hex())]
        );
        assert_eq!(values(&event, "k"), vec!["31402"]);
    }

    fn tr0_offers() -> Vec<Offer> {
        vec![Offer::parse("tr0reloffer", "0 50000 10000000 0 0.00025").unwrap()]
    }

    #[test]
    fn offer_round_trip() {
        let k = keys(1);
        let event = offer_event(
            &k,
            "regtest",
            Pit::Sw0,
            &offers(),
            &["neutrino_compat"],
            &RELAYS,
            NOW,
            1800,
        )
        .unwrap();
        assert_eq!(
            event.content,
            "!sw0reloffer 0 50000 10000000 0 0.00025!sw0absoffer 1 50000 10000000 0 250"
        );
        let (author, parsed) = read_offer_event(&event, "regtest", NOW + 10).unwrap();
        assert_eq!(parsed, offers());
        assert_eq!(author.nick, k.nick());
        assert_eq!(author.relays, RELAYS);
        assert_eq!(author.features, ["neutrino_compat"]);
        // Expired, wrong network.
        assert!(read_offer_event(&event, "regtest", NOW + 1800).is_err());
        assert!(read_offer_event(&event, "mainnet", NOW).is_err());
    }

    #[test]
    fn offer_build_rules() {
        let k = keys(1);
        let mixed = vec![
            offers()[0].clone(),
            Offer::parse("tr0absoffer", "2 50000 60000 0 1").unwrap(),
        ];
        assert!(offer_event(&k, "regtest", Pit::Sw0, &mixed, &[], &RELAYS, NOW, 60).is_err());
        assert!(offer_event(&k, "regtest", Pit::Sw0, &[], &[], &RELAYS, NOW, 60).is_err());
        assert!(offer_event(&k, "regtest", Pit::Sw0, &offers(), &[], &[], NOW, 60).is_err());
        assert!(offer_event(&k, "regtest", Pit::Sw0, &offers(), &[], &RELAYS, NOW, 3601).is_err());
    }

    /// An offer event signed by `k` with exactly these `relay` tags, built past the builder's checks.
    fn offer_with_relays(k: &NickKeys, relays: &[String]) -> Event {
        let mut tags = vec![
            tag(&["d", "regtest:sw0"]).unwrap(),
            tag(&["n", k.nick()]).unwrap(),
            tag(&["jmpk", &k.jmpk_hex()]).unwrap(),
            tag(&["network", "regtest"]).unwrap(),
            tag(&["t", "joinmarket-regtest"]).unwrap(),
            Tag::expiration(Timestamp::from_secs(NOW + 60)),
        ];
        tags.extend(relays.iter().map(|r| tag(&["relay", r]).unwrap()));
        EventBuilder::new(Kind::Custom(KIND_OFFER), "!sw0absoffer 1 50000 60000 0 1")
            .tags(tags)
            .custom_created_at(Timestamp::from_secs(NOW))
            .finalize(k.nostr())
            .unwrap()
    }

    #[test]
    fn relay_tags_are_one_to_eight_short_websocket_urls() {
        let k = keys(1);
        // 256 bytes is the longest allowed, 257 one too many.
        let longest = format!("wss://{}", "r".repeat(250));
        let eight: Vec<String> = (0..8)
            .map(|i| format!("wss://{i}{}", "r".repeat(249)))
            .collect();
        assert!(eight.iter().all(|r| r.len() == 256));
        fn refs(v: &[String]) -> Vec<&str> {
            v.iter().map(String::as_str).collect()
        }
        let build = |relays: &[String]| {
            offer_event(
                &k,
                "regtest",
                Pit::Sw0,
                &offers(),
                &[],
                &refs(relays),
                NOW,
                60,
            )
        };
        let (author, _) = read_offer_event(&build(&eight).unwrap(), "regtest", NOW).unwrap();
        assert_eq!(author.relays, eight);
        read_public_event(
            &public_event(&k, "regtest", "!orderbook", &[longest.as_str()], NOW).unwrap(),
            "regtest",
        )
        .unwrap();

        let mut nine = eight.clone();
        nine.push("wss://ninth.example".to_string());
        let bad: Vec<Vec<String>> = vec![
            vec![],
            nine,
            vec![format!("{longest}r")],
            vec!["https://relay.example".to_string()],
            vec!["wss://relay.example/a b".to_string()],
            vec!["wss://relä.example".to_string()],
            vec![
                "wss://relay.example".to_string(),
                "relay2.example".to_string(),
            ],
        ];
        for relays in &bad {
            // Neither built nor accepted from someone else.
            assert!(build(relays).is_err(), "{relays:?}");
            assert_eq!(
                read_offer_event(&offer_with_relays(&k, relays), "regtest", NOW).map(|_| ()),
                Err(ChannelError::Invalid(
                    "one to eight ws:// or wss:// relay URLs of at most 256 bytes"
                )),
                "{relays:?}"
            );
        }
        read_offer_event(&offer_with_relays(&k, &eight), "regtest", NOW).unwrap();
    }

    #[test]
    fn forged_authorship_is_rejected() {
        let (alice, mallory) = (keys(1), keys(2));
        // Mallory signs an event claiming Alice's nick and key.
        let tags = vec![
            tag(&["d", "regtest:sw0"]).unwrap(),
            tag(&["n", alice.nick()]).unwrap(),
            tag(&["jmpk", &alice.jmpk_hex()]).unwrap(),
            tag(&["network", "regtest"]).unwrap(),
            tag(&["t", "joinmarket-regtest"]).unwrap(),
            tag(&["relay", RELAYS[0]]).unwrap(),
            Tag::expiration(Timestamp::from_secs(NOW + 60)),
        ];
        let forged = EventBuilder::new(Kind::Custom(KIND_OFFER), "!sw0absoffer 1 50000 60000 0 1")
            .tags(tags)
            .custom_created_at(Timestamp::from_secs(NOW))
            .finalize(mallory.nostr())
            .unwrap();
        assert_eq!(
            read_offer_event(&forged, "regtest", NOW),
            Err(ChannelError::Invalid("jmpk is not the event author"))
        );
        // A tampered event fails its signature.
        let good = offer_event(
            &alice,
            "regtest",
            Pit::Sw0,
            &offers(),
            &[],
            &RELAYS,
            NOW,
            60,
        )
        .unwrap();
        let tampered = Event::from_json(good.as_json().replace("0.00025", "0.00001")).unwrap();
        assert!(matches!(
            read_offer_event(&tampered, "regtest", NOW),
            Err(ChannelError::Crypto(_))
        ));
    }

    #[test]
    fn bond_never_in_offer_event_and_public_messages() {
        let k = keys(3);
        let with_bond = EventBuilder::new(
            Kind::Custom(KIND_OFFER),
            "!sw0absoffer 1 50000 60000 0 1!tbond AAAA",
        )
        .tags(vec![
            tag(&["d", "regtest:sw0"]).unwrap(),
            tag(&["n", k.nick()]).unwrap(),
            tag(&["jmpk", &k.jmpk_hex()]).unwrap(),
            tag(&["network", "regtest"]).unwrap(),
            tag(&["t", "joinmarket-regtest"]).unwrap(),
            tag(&["relay", RELAYS[0]]).unwrap(),
            Tag::expiration(Timestamp::from_secs(NOW + 60)),
        ])
        .custom_created_at(Timestamp::from_secs(NOW))
        .finalize(k.nostr())
        .unwrap();
        assert!(read_offer_event(&with_bond, "regtest", NOW).is_err());

        let orderbook = public_event(&k, "regtest", "!orderbook", &RELAYS, NOW).unwrap();
        let (author, commands) = read_public_event(&orderbook, "regtest").unwrap();
        assert_eq!(
            (author.nick.as_str(), commands),
            (k.nick(), vec![Command::Orderbook])
        );
        assert!(public_event(&k, "regtest", "!fill 0 1 aa P00", &RELAYS, NOW).is_err());
        assert!(
            public_event(
                &k,
                "regtest",
                "!sw0absoffer 1 50000 60000 0 1",
                &RELAYS,
                NOW
            )
            .is_err()
        );
    }
}
