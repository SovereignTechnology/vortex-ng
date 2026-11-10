---
jmp: TBD
title: Nostr Message Channel
author: sovtech
status: Draft
type: Standards Track
layer: Extension
created: 2026-11-09
requires: 0001
---

## Abstract

This specification defines a JoinMarket message channel carried by Nostr relays. It replaces JMP-0001's
transport, handshake, peer discovery and message routing for peers that use it, and leaves JMP-0001's CoinJoin
protocol, PoDLE algorithm, fidelity bonds and encryption unchanged. Offers are addressable Nostr events,
public messages are ephemeral events, and private messages are NIP-59 gift wraps whose innermost event carries
the unchanged JMP-0001 private-message line.

## Motivation

JoinMarket's directory servers are a small set of long-lived onion services that every peer depends on for
discovery and, without a direct connection, for message relay. Nostr offers many independent relays, a
standard signed-event format, standard end-to-end encryption (NIP-44) and a standard way to hide a message's
sender from relays (NIP-59). Mapping JoinMarket's message channel onto Nostr gives peers a decentralized
transport without changing any CoinJoin semantics, so existing taker and maker logic is reused unchanged and
only a new message channel is implemented. joinmarket-ng issue #118 asks for this research; its `nostr`
branch publishes offers as kind 31402 events, which this specification keeps.

## Specification

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119.

### Overview

| JMP-0001 concept | On this channel |
|---|---|
| Directory server | Any set of Nostr relays |
| Nick key | The Nostr key. An event's `pubkey` is the x-only form of the nick's compressed key |
| PUBMSG | Kind 21402 ephemeral event (`!orderbook`, `!hp2`, `!cancel`) |
| Offer announcement | Kind 31402 addressable event (discovery cache) |
| PRIVMSG | NIP-59 gift wrap (kind 1059, seal kind 13) of a kind 21403 rumor holding the PRIVMSG line |
| `hostid` | `nostr-network` |
| HANDSHAKE features | `F` tag (JMP-0003 string form) |
| PING/PONG, PEERLIST, GETPEERLIST, DISCONNECT | Not used: offer expiry, subscriptions and phase timeouts replace them |

Kind numbers 21402 and 21403 are provisional until agreed with joinmarket-ng; 31402 is the kind joinmarket-ng's
proof of concept uses.

### Identity

A peer's nick key is a secp256k1 key pair, ephemeral as in JMP-0001. Its nick is derived from the 33-byte
compressed public key exactly as JMP-0001 "Nick Format" specifies. On this channel the same key signs Nostr
events: an event authored by a nick has `pubkey` = the 32-byte x-only encoding of the nick's public key.

Because the x-only encoding drops the key's parity, every event a nick authors that is not a private message
MUST carry the tag `["jmpk", "<hex of the 33-byte compressed key>"]`. A receiver MUST drop the event unless the
x-only form of `jmpk` equals the event's `pubkey` and the nick re-derived from `jmpk` equals the event's `n` tag.

A taker SHOULD use a fresh nick for each CoinJoin. A maker keeps its nick for the life of its process, as on
other channels.

### Common tags

| Tag | Value | On |
|---|---|---|
| `n` | the author's nick | 31402, 21402 |
| `jmpk` | hex of the author's 33-byte compressed nick key | 31402, 21402 |
| `network` | `mainnet`, `testnet4`, `signet` or `regtest` | 31402, 21402 |
| `t` | `joinmarket-<network>` (an indexable copy of `network`; relays only index single-letter tags) | 31402, 21402 |
| `relay` | a relay URL where the author reads its private messages; one tag per relay, at least one | 31402, 21402 |
| `F` | feature identifiers joined with `+` (JMP-0003); MAY be empty | 31402 |
| `expiration` | NIP-40 unix time | 31402, 1059 |

Receivers MUST ignore events whose `network` differs from their own. Relays index only single-letter tags
(NIP-01), so subscriptions filter on `t`, `f`, `p` and `d`, never on `network`, `jmpk` or `relay`.

### Offers (kind 31402)

A maker publishes its live offers for one pit as one addressable event:

```json
{
  "kind": 31402,
  "content": "!sw0reloffer 0 50000 10000000 0 0.00025!sw0absoffer 1 50000 10000000 0 250",
  "tags": [
    ["d", "mainnet:sw0"],
    ["t", "joinmarket-offer"], ["t", "joinmarket-mainnet"],
    ["f", "sw0reloffer"], ["f", "sw0absoffer"],
    ["n", "J5Ckon1LuuapPSBM"],
    ["jmpk", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"],
    ["network", "mainnet"],
    ["F", "neutrino_compat"],
    ["relay", "wss://relay.example"], ["relay", "wss://relay2.example"],
    ["expiration", "1793000000"]
  ]
}
```

- `content` is one or more offer commands of a single pit, concatenated with `!` exactly as JMP-0001 "Phase 1"
  allows, with the grammar of JMP-0001 and of the pit's specification (`sw0` JMP-0001, `tr0` JMP-0010, `wsh0`
  its draft). It MUST NOT contain `!tbond`: fidelity-bond proofs are per taker (JMP-0001 "Fidelity Bonds").
- `d` is `<network>:<pit>`. One `f` tag is present for each offer type in `content`.
- `expiration` MUST be at most 3600 seconds after `created_at`. A maker SHOULD republish at least every 1800
  seconds while its offers are live, and MUST republish, or delete with a NIP-09 kind 5 event naming the
  event's `a` coordinate, when an offer changes or is cancelled.
- A taker MUST treat these events as a discovery cache only. The offers it acts on are those the maker sends
  privately in answer to `!orderbook`.

### Public messages (kind 21402)

A JMP-0001 public message is an ephemeral event whose `content` is the message's command text, without the
JMP-0001 `<from_nick>!PUBLIC` prefix:

```json
{ "kind": 21402, "content": "!orderbook", "tags": [["n", "..."], ["jmpk", "..."], ["network", "mainnet"], ["t", "joinmarket-mainnet"], ["relay", "wss://..."]] }
```

- `!orderbook`: a taker requests offers. A maker that sees it SHOULD answer with a private message to the
  requesting nick containing its offers for the pits it serves, each followed by its `!tbond` proof for that
  taker, exactly as JMP-0001 "Phase 1" and "Fidelity Bonds" specify. A maker MAY answer only for pits that
  appear in the request's `f` tags when present. Makers SHOULD apply per-nick and aggregate rate limits.
- `!hp2 <commitment>`: the PoDLE commitment broadcast of JMP-0001 "Phase 3". It MUST be published from a fresh
  throwaway nick, over a connection and Tor circuit used for nothing else, which is closed afterwards.
- `!cancel <oid>`: as JMP-0001.

Ephemeral events reach only peers subscribed at the time, as on JoinMarket's directories.

### Private messages (NIP-59 gift wrap)

A JMP-0001 private message is sent as follows.

1. **Line.** Form the JMP-0001 PRIVMSG `line` exactly as on other channels:
   `<from_nick>!<to_nick>!<command> <body> <hex_pubkey> <base64_signature>`, where the signature covers
   `<body> + "nostr-network"` (JMP-0001 "Nick Signature Verification"), and encrypted commands carry the
   JMP-0001 NaCl ciphertext as their body. The line MUST be ASCII.
2. **Rumor.** An unsigned event of kind 21403 with `pubkey` = the sender's x-only nick key, `content` = the
   line (or one part of it, below), and tags `["p", "<recipient x-only nick key>"]`, one to eight
   `["relay", "<url>"]` naming where the sender reads its private messages (so the recipient can answer a
   sender it has seen no public event from; inside the encryption, only the recipient learns them), and, when
   split, `["part", "<i>", "<n>", "<id>"]`.
3. **Seal.** Kind 13, signed by the sender's nick key, `content` = NIP-44 v2 encryption of the rumor for the
   recipient, no tags (NIP-59).
4. **Wrap.** Kind 1059, signed by a one-time random key, `content` = NIP-44 v2 encryption of the seal for the
   recipient, tags `["p", "<recipient x-only nick key>"]` and `["expiration", "<created_at + 600>"]`.

`created_at` of the rumor, seal and wrap MUST be the current time. This deviates from NIP-59's suggestion to
randomize timestamps into the past: these messages are consumed live by subscriptions filtered with `since`.

**Splitting.** A line longer than 16,000 bytes MUST be split into consecutive byte ranges of at most 16,000
bytes, at most 4 parts, each sent in its own wrap with `["part", "<i>", "<n>", "<id>"]`, where `i` runs from 1
to `n` and `id` is 16 random bytes in lowercase hex shared by all parts. The receiver concatenates the parts in
order once all `n` with the same sender and `id` have arrived, and drops parts it cannot complete within 60
seconds. The sender is the seal's authenticated `pubkey`, so no one can inject parts into another sender's
message. A receiver MUST bound the memory reassembly can take: at most 4 incomplete messages per sender and a
global cap it chooses; parts beyond a cap are dropped. This keeps each wrap inside NIP-44 v2's 65,535-byte
plaintext limit and common relay event limits.

**Receiving.** The receiver MUST unwrap and unseal per NIP-59, verify the seal's signature, and drop the message
unless all of the following hold: the rumor's `pubkey` equals the seal's `pubkey`; the line's `to_nick` is the
receiver's nick; the line verifies per JMP-0001 "Nick Signature Verification" with `hostid` = `nostr-network`;
the x-only form of the line's `hex_pubkey` equals the seal's `pubkey`; and the nick derived from `hex_pubkey`
equals the line's `from_nick`. It then processes the line as a JMP-0001 private message.

**Where to send.** A sender publishes each wrap to at least two of the recipient's `relay`s (all of them if
there are fewer), learned from the recipient's latest 31402 or 21402 event or from the `relay` tags of the
recipient's last private message.

**Deduplication.** Receivers MUST drop events whose id they have already processed, and SHOULD apply
joinmarket-ng's message deduplication (`from_nick:command:first_arg` within 30 seconds), since a message
published to several relays arrives several times.

### Subscriptions

- A maker subscribes to kind 1059 with `#p` = its key, and to kind 21402 with `#t` = `joinmarket-<network>`.
- A taker subscribes to kind 31402 with `#t` = `joinmarket-<network>` (and `#f` for the pits it wants), and to
  kind 1059 with `#p` = its key.
- Subscriptions for private messages SHOULD use `since` = the time the nick was created.
- If a relay requires NIP-42 authentication to deliver kind 1059 events, the client authenticates with the nick
  key on that nick's connection.

### Network privacy

- Implementations MUST be able to reach relays over Tor and SHOULD do so by default.
- A relay connection MUST serve exactly one nick, and each nick's connections SHOULD use their own Tor circuit
  (stream isolation). A throwaway nick (for `!hp2`) gets its own connection and circuit and closes them after
  publishing.

### Sessions and timeouts

A session's messages all carry `hostid` `nostr-network`, so a session started on this channel cannot continue
on an onion channel, and a signature made for one channel never verifies on the other. Implementations apply
their usual JMP-0001 phase timeouts; there is no heartbeat, since a maker's liveness is its unexpired offer
event and its answers.

## Backward Compatibility

Peers that do not implement this channel are unaffected: the channel is additive, uses its own `hostid`, and
changes nothing in the CoinJoin protocol. A peer MAY run this channel beside onion channels with the same nick,
as JoinMarket's message channel collection allows; a session stays on the channel it started on.

The offer event keeps the joinmarket-ng proof of concept's kind 31402 and its `t=joinmarket-offer` tag, but
`content` is the JoinMarket offer line rather than an implementation's JSON model, `d` is per pit rather than
per offer, and the `c` and `v` tags are dropped (a fidelity-bond value is only verifiable from a per-taker
`!tbond` proof).

## Rationale

- **The unchanged line inside the rumor** lets an implementation reuse its JMP-0001 parsing, signature
  verification and session handling as they are; Nostr adds transport, not semantics.
- **Gift wraps** hide the sender and the content from relays. The inner NaCl session and nick signature are
  kept, so the CoinJoin protocol's security does not depend on the Nostr layer.
- **Public offers without bonds** keep JMP-0001's rule that bond proofs are per taker; takers still ask with
  `!orderbook`, so a maker's authoritative answer and bond are private.
- **Ephemeral public messages** match the directory model (seen by online peers) and leave nothing stored.
- **The nick key as the Nostr key** makes every event attributable to a nick without new key material.

## Security Considerations

- Relays learn which nick keys receive private messages and when, and can censor. Use several relays and Tor;
  takers use fresh nicks.
- A maker's 31402 event can differ from its private answer. Takers act only on private answers.
- Replay across channels is prevented by the `hostid`; replay within a session by NaCl's nonces and event-id
  deduplication.
- Ephemeral `!orderbook` events can be spammed. Makers rate-limit answers; relays may demand NIP-13
  proof-of-work.
- Fidelity bonds remain the sybil defense; nothing here weakens their verification.

## Test Vectors

To be added with the reference implementation: fixed nick keys, ephemeral wrap keys and NIP-44 nonces, with the
resulting rumor, seal and wrap events.

## Reference Implementation

- vortex-ng, crate `vortex-ng-nostr` (in development).
- A joinmarket-ng message channel implementing this draft (planned, offered upstream).
