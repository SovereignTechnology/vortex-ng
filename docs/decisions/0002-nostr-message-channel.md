# 2. The Nostr message channel

Date: 2026-11-09

## Status

Accepted (the wire format itself is the draft `docs/jmp/jmp-draft-nostr-message-channel.md`)

## Context

JoinMarket-NG has no Nostr transport. Its only Nostr work is a proof of concept on branch `nostr`
(2025-12-06) that publishes maker offers as kind 31402 addressable events; issue #118 ("Research Nostr relay
protocol for offer broadcasting (and joinstr!)") is open and empty. JMP-0001 assumes a directory that relays
public messages to connected peers, routes private messages by nick, and hands out peer lists.

Facts that shape a Nostr mapping:

- Fidelity-bond proofs sign `<taker_nick>|<maker_nick>` (JMP-0001 "Fidelity Bonds"), so they are per taker
  and must stay private; offers alone can be public.
- Private messages are signed by the nick key over `body + hostid`; the nick is derived from that key.
- NIP-44 v2 encrypts at most 65,535 bytes, while JMP-0001 lines may reach 40,000 bytes, and a NIP-59 gift
  wrap encrypts twice.

## Decision

- The nick key is the Nostr key: an event's `pubkey` is the x-only form of the nick's compressed key, and
  events carry the compressed key so the nick can be re-derived.
- Kind 31402 (addressable, from the joinmarket-ng PoC) caches offers for discovery. Kind 21402 (ephemeral)
  carries JoinMarket public messages (`!orderbook`, `!hp2`, `!cancel`). Private messages are NIP-59 gift
  wraps (kind 1059, seal kind 13) whose rumor (kind 21403) holds the unchanged JMP-0001 private-message line,
  with `hostid` `nostr-network`. Lines are split into parts of at most 16,000 bytes.
- The taker still sends `!orderbook` and makers still answer privately with their offers and `!tbond`, as in
  JMP-0001; the public offer events are a discovery cache, not the authoritative offer.
- Relays are reached over Tor with arti-client: one relay connection and one Tor circuit per nick.
- Kind numbers are provisional until agreed with joinmarket-ng.

## Consequences

- Relays see neither message content nor senders of private messages, only the recipient nick's key and
  timing.
- Ephemeral public messages reach only online peers, as on JoinMarket's directories.
- vortex-ng is all-Rust (no C tor, no onion service), since there are no inbound connections.
