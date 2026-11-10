//! The Nostr message channel for the JoinMarket protocol.
//!
//! Implements `docs/jmp/jmp-draft-nostr-message-channel.md`: offers as kind 31402 addressable
//! events, public messages as kind 21402, private messages as NIP-59 gift wraps whose rumor (kind
//! 21403) carries the unchanged JMP-0001 private-message line, relays reached over Tor (arti) with
//! one circuit and one connection per nick. Built in M2.
