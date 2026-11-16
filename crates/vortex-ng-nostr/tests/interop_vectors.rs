//! Cross-implementation vectors for the Nostr message channel (docs/jmp/jmp-draft-nostr-message-channel.md).
//!
//! - `export_vectors` (ignored; run on purpose) prints events made by vortex-ng (an offer event, a public
//!   message, a private line in one wrap and a long one in two), for another implementation to read and
//!   verify. joinmarket-ng's `jmcore/tests/test_nostr.py` reads them.
//! - `import_vectors` reads the same shape made by another implementation and verifies it with vortex-ng's
//!   own readers. By default it reads `tests/data/jmcore_nostr_vectors.tsv`: events made by the Python
//!   `jmcore.nostr` (joinmarket-ng branch `nostr/118-message-channel`, `scripts/nostr_interop_vectors.py`,
//!   run 2026-11-16 in a Kata VM, Python 3.11.2). `VORTEX_NG_INTEROP_VECTORS` names another file.
//!
//! The format is one `label<TAB>value` per line, so no JSON library is needed on either side beyond the
//! event JSON itself. The keys are fixed test keys, never used for anything else.

// A harness: a failed step should panic with its error.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use nostr::prelude::Event;
use vortex_ng_core::bitcoin::secp256k1::{Secp256k1, SecretKey};
use vortex_ng_core::command::Command;
use vortex_ng_core::line::sign_line;
use vortex_ng_core::offer::{Offer, Pit};
use vortex_ng_core::protocol::NOSTR_HOSTID;
use vortex_ng_nostr::event::{offer_event, public_event, read_offer_event, read_public_event};
use vortex_ng_nostr::keys::NickKeys;
use vortex_ng_nostr::private::{Reassembler, open_line, unwrap, wrap_line};

const NETWORK: &str = "regtest";
const NOW: u64 = 1_800_000_000;
const RELAYS: [&str; 2] = ["wss://relay.example", "ws://127.0.0.1:7777"];
/// The long line's body: 16,100 bytes, so the signed line needs two parts.
const LONG_BODY_LEN: usize = 16_100;

fn keys(byte: u8) -> NickKeys {
    NickKeys::from_secret(SecretKey::from_slice(&[byte; 32]).unwrap()).unwrap()
}

fn maker() -> NickKeys {
    keys(0x11)
}

fn taker() -> NickKeys {
    keys(0x22)
}

fn long_body() -> String {
    (0..LONG_BODY_LEN)
        .map(|i| char::from(b'a' + (i % 26) as u8))
        .collect()
}

#[test]
#[ignore = "prints vectors; run with --ignored --nocapture"]
fn export_vectors() {
    let (maker, taker) = (maker(), taker());
    let secp = Secp256k1::signing_only();
    let offers = [
        Offer::parse("sw0reloffer", "0 50000 10000000 0 0.00025").unwrap(),
        Offer::parse("sw0absoffer", "1 50000 10000000 0 250").unwrap(),
    ];
    let offer = offer_event(
        &maker,
        NETWORK,
        Pit::Sw0,
        &offers,
        &["neutrino_compat"],
        &RELAYS,
        NOW,
        1800,
    )
    .unwrap();
    let public = public_event(&taker, NETWORK, "!orderbook", &RELAYS, NOW).unwrap();
    let relays: Vec<String> = RELAYS.iter().map(|r| (*r).to_string()).collect();
    let short = sign_line(
        &secp,
        maker.secret(),
        taker.nick(),
        "pubkey",
        "abcdef0123",
        NOSTR_HOSTID,
    )
    .unwrap();
    let long = sign_line(
        &secp,
        maker.secret(),
        taker.nick(),
        "tx",
        &long_body(),
        NOSTR_HOSTID,
    )
    .unwrap();
    let recipient = taker.nostr().public_key();
    let short_wraps = wrap_line(&maker, &recipient, &short, &relays, NOW).unwrap();
    let long_wraps = wrap_line(&maker, &recipient, &long, &relays, NOW).unwrap();
    assert_eq!((short_wraps.len(), long_wraps.len()), (1, 2));

    println!("VECTORS-BEGIN");
    println!("network\t{NETWORK}");
    println!("now\t{NOW}");
    println!("maker_secret\t{}", "11".repeat(32));
    println!("taker_secret\t{}", "22".repeat(32));
    println!("maker_nick\t{}", maker.nick());
    println!("taker_nick\t{}", taker.nick());
    println!("maker_jmpk\t{}", maker.jmpk_hex());
    println!("taker_jmpk\t{}", taker.jmpk_hex());
    println!("offer_event\t{}", offer.as_json());
    println!("public_event\t{}", public.as_json());
    println!("short_line\t{short}");
    println!("long_line\t{long}");
    for wrap in &short_wraps {
        println!("short_wrap\t{}", wrap.as_json());
    }
    for wrap in &long_wraps {
        println!("long_wrap\t{}", wrap.as_json());
    }
    println!("VECTORS-END");
}

/// The values of every `label` line in the vectors file.
fn values<'a>(text: &'a str, label: &str) -> Vec<&'a str> {
    text.lines()
        .filter_map(|l| l.split_once('\t'))
        .filter(|(k, _)| *k == label)
        .map(|(_, v)| v)
        .collect()
}

fn one<'a>(text: &'a str, label: &str) -> &'a str {
    match values(text, label).as_slice() {
        [v] => v,
        other => panic!("{label}: expected one line, found {}", other.len()),
    }
}

#[test]
fn import_vectors() {
    let path = std::env::var("VORTEX_NG_INTEROP_VECTORS").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/jmcore_nostr_vectors.tsv"
        )
        .to_string()
    });
    let text = std::fs::read_to_string(path).unwrap();
    let (maker, taker) = (maker(), taker());
    assert_eq!(one(&text, "network"), NETWORK);
    let now: u64 = one(&text, "now").parse().unwrap();
    assert_eq!(one(&text, "maker_nick"), maker.nick());
    assert_eq!(one(&text, "taker_nick"), taker.nick());
    assert_eq!(one(&text, "maker_jmpk"), maker.jmpk_hex());

    // The offer event: signature, author checks, offers.
    let offer = Event::from_json(one(&text, "offer_event")).unwrap();
    offer.verify().unwrap();
    let (author, offers) = read_offer_event(&offer, NETWORK, now).unwrap();
    assert_eq!(author.nick, maker.nick());
    assert_eq!(author.key, *maker.public());
    assert!(!author.relays.is_empty());
    assert!(!offers.is_empty());
    assert!(offers.iter().all(|o| o.offer_type.pit == Pit::Sw0));

    // The public message.
    let public = Event::from_json(one(&text, "public_event")).unwrap();
    public.verify().unwrap();
    let (author, commands) = read_public_event(&public, NETWORK).unwrap();
    assert_eq!(author.nick, taker.nick());
    assert_eq!(commands, vec![Command::Orderbook]);

    // Private lines from the maker to the taker: one wrap, then a split one.
    for (wraps_label, line_label, parts) in [
        ("short_wrap", "short_line", 1),
        ("long_wrap", "long_line", 2),
    ] {
        let wraps = values(&text, wraps_label);
        assert_eq!(wraps.len(), parts, "{wraps_label}");
        let mut reassembler = Reassembler::new(16);
        let mut delivered = None;
        for json in wraps {
            let wrap = Event::from_json(json).unwrap();
            wrap.verify().unwrap();
            let received = unwrap(&taker, &wrap).unwrap();
            assert_eq!(received.sender, maker.nostr().public_key());
            delivered = reassembler.push(received, now);
        }
        let delivered =
            delivered.unwrap_or_else(|| panic!("{wraps_label}: the line never completed"));
        assert_eq!(delivered.line, one(&text, line_label));
        assert!(!delivered.relays.is_empty());
        let msg = open_line(&taker, &delivered.sender, &delivered.line).unwrap();
        assert_eq!(msg.from, maker.nick());
    }
    println!("imported: offer event, public message, 1-part and 2-part private lines all verify");
}
