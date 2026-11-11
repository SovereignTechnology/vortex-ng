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

JoinMarket's message channel was built on IRC: peers met in a channel such as `#joinmarket-pit` on a few IRC
servers. It now runs mostly on directory nodes, a small set of long-lived onion services (joinmarket-ng ships
eight for mainnet) that every peer depends on for discovery and, without a direct connection, for message
relay. Whoever runs a server or directory sees which nicks talk, when, and every unencrypted command, and taking
a handful of them down stops discovery. Nostr offers many independent relays that anyone can run, a standard
signed-event format, standard end-to-end encryption (NIP-44) and a standard way to hide a message's sender from
relays (NIP-59). Mapping JoinMarket's message channel onto Nostr gives peers a decentralized
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

### From IRC to Nostr

This channel keeps the IRC design: the same commands in the same order, with Nostr relays where the IRC servers
were. Only the transport changes, and it hides more. The left column is reference JoinMarket's IRC channel
(`jmdaemon/irc.py`, joinmarket-clientserver 0.9.11, whose default configuration still runs two IRC servers
beside the onion directories).

| On IRC | On this channel |
|---|---|
| A few IRC servers, reached over Tor | Any set of Nostr relays, reached over Tor (onion relays preferred) |
| Channel `#joinmarket-pit` (`-test`, `-sig` suffixes per network) | Subscriptions filtered on `#t` = `joinmarket-<network>` |
| Online = joined to the channel; the server stores nothing | Online = subscribed, plus an unexpired offer event; relays store only events that expire within an hour |
| IRC nick = JoinMarket nick from an ephemeral key | Nostr `pubkey` = the same ephemeral nick key; nick derived exactly as JMP-0001 |
| Maker announces its offers in the channel on joining and whenever they change | Maker publishes a kind 31402 offer event, expiring within 1 h and republished at least every 30 min |
| Taker says `!orderbook` in the channel; makers answer by PRIVMSG with offers and `!tbond` | Same command as a kind 21402 event; answers come as gift-wrapped private messages |
| Taker collects answers for `order_wait_time` | Same |
| PRIVMSG: the server sees sender nick, recipient nick, time, and the plaintext commands (`!fill`, `!pubkey`, `!error`, `!push`, offers, `!hp2`); only `!auth`, `!ioauth`, `!tx`, `!sig` are NaCl-encrypted | NIP-59 gift wrap: the relay sees only the recipient key, the time and the size; the sender and every command are encrypted (NIP-44), and the NaCl layer is kept inside |
| PRIVMSG split into 450-byte chunks ending ` ;` (more) and ` ~` (last) | Lines over 16,000 bytes split into at most 4 parts with a `part` tag |
| `!hp2` sent privately to a random maker, which re-broadcasts it in the channel | `!hp2` published as kind 21402 from a throwaway nick on its own connection and Tor circuit |
| Nick leaves (QUIT/PART, `on_nick_leave`): its offers are dropped | The offer event's `expiration` passes, or the maker deletes it (NIP-09); its offers are dropped |
| `!cancel` in the channel | `!cancel` as kind 21402, plus a republished or deleted offer event |
| `hostid` = the server's host and port (`onion-network` on onion directories) | `hostid` = `nostr-network` |
| Several servers at once (the message channel collection) | Several relays at once |

### Identity

A peer's nick key is a secp256k1 key pair, ephemeral as in JMP-0001. Its nick is derived from the 33-byte
compressed public key exactly as JMP-0001 "Nick Format" specifies. On this channel the same key signs Nostr
events: an event authored by a nick has `pubkey` = the 32-byte x-only encoding of the nick's public key.

Because the x-only encoding drops the key's parity, every event a nick authors that is not a private message
MUST carry the tag `["jmpk", "<hex of the 33-byte compressed key>"]`. A receiver MUST drop the event unless the
x-only form of `jmpk` equals the event's `pubkey` and the nick re-derived from `jmpk` equals the event's `n` tag.

Every key used on this channel is new and used for nothing else:

- A taker MUST use a fresh nick for each CoinJoin, and a fresh throwaway nick for each `!hp2`.
- A maker generates a new nick each time its process starts and keeps it for the life of the process, as on
  other channels. It SHOULD NOT store the nick key across restarts. Its fidelity bond, not its nick, is its
  long-lived identity.
- Each gift wrap is signed by its own one-time random key (NIP-59), never reused.
- A nick key MUST NOT be the user's own Nostr identity, MUST NOT be derived from wallet keys, and MUST NOT be
  used anywhere else.
- A nick key MUST NOT publish any event this specification does not define: no kind 0 profile, no kind 3
  follows, no kind 10002 relay list, no NIP-05 name. Where a nick reads its private messages travels only in
  `relay` tags.

### Common tags

| Tag | Value | On |
|---|---|---|
| `n` | the author's nick | 31402, 21402 |
| `jmpk` | hex of the author's 33-byte compressed nick key | 31402, 21402 |
| `network` | `mainnet`, `testnet4`, `signet` or `regtest` | 31402, 21402 |
| `t` | `joinmarket-<network>` (an indexable copy of `network`; relays only index single-letter tags) | 31402, 21402 |
| `relay` | a relay URL (at most 256 bytes) where the author reads its private messages; one tag per relay, one to eight | 31402, 21402 |
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
  Ephemeral events reach only peers subscribed at the time, so a taker MAY repeat `!orderbook` while it
  gathers, at most once a second, when an offer event reveals a maker that has not answered yet.
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

- Implementations MUST reach relays over Tor by default. A direct connection is an explicit opt-in.
- Implementations SHOULD prefer a relay's onion address when it has one.
- A relay connection MUST serve exactly one nick, and each nick's connections MUST use their own Tor circuits
  (stream isolation).
- A throwaway nick (for `!hp2`) gets its own connection and circuit and closes them after publishing.
- A relay links everything sent over one connection. An implementation SHOULD therefore publish gift wraps over
  a separate connection and circuit from the one on which that nick subscribes to its own private messages.
  Otherwise the relay can tie each wrap to its sender, despite NIP-59.
- An implementation MUST NOT perform NIP-42 AUTH on a connection it publishes gift wraps over. AUTH there would
  name the sender. AUTH is used only on a nick's subscribe connection, with that nick's key, and only where the
  relay requires it to deliver the nick's kind 1059 events.
- NIP-11 documents are fetched over Tor on a circuit no nick uses.

### Relay requirements

A relay that carries this channel needs to hold very little, and only for a short time. These are the
requirements a relay meets to conform to this specification; the conformance check below tests them.

| Kind | Carries | The relay | Holds it |
|---|---|---|---|
| 31402 (addressable) | offers | keeps the latest per `pubkey` and `d`; serves `#t`, `#f`, `#d` filters | until its `expiration` (at most 1 h) |
| 21402 (ephemeral) | `!orderbook`, `!hp2`, `!cancel` | forwards to matching live subscriptions only | never |
| 1059 (gift wrap) | private messages | stores; serves `#p` with `since` | until its `expiration` (10 min) |
| 5 (deletion) | a maker withdrawing an offer event by its `a` coordinate | applies it to the author's own events (NIP-09) | as long as the offer it deletes could live |
| 22242 (AUTH) | only where the relay limits kind 1059 reads to the recipient | accepts AUTH from any key | never |

Kinds 13 and 21403 are encrypted inside the wrap and never reach a relay. A conforming relay:

- **Retention.** MUST keep kind 31402 and 1059 events until they expire, unless replaced or deleted. MUST NOT
  serve an expired event, and SHOULD delete it at expiry: a store of old gift wraps is a record of who received
  messages and when, and nothing in the protocol reads it. Nothing on this channel needs to be kept longer than
  one hour. NIP-11 has no field that advertises retention, so clients test it.
- **Ephemeral events.** MUST forward kind 21402 to matching live subscriptions and MUST NOT return it to a later
  query.
- **Size.** MUST accept an `EVENT` message of 40,000 bytes whose `content` is 39,000 characters, and SHOULD
  advertise `max_message_length` of at least 65,536. The largest event on this channel is a gift wrap carrying a
  16,000-byte part with eight 256-byte `relay` tags. Wrapped twice with NIP-44 v2 padding and base64, its `EVENT`
  message is 38,775 bytes and its `content` 38,320 characters. Relays limited to 16 KiB cannot carry this
  channel.
- **Filters and tags.** MUST support `kinds`, `#t`, `#f`, `#d`, `#p`, `since` and `limit`. MUST allow at least
  4 subscriptions per connection and 32 tags per event.
- **Open writes.** MUST accept these kinds from any key, without payment, an allowlist, NIP-05 or AUTH: every key
  here is ephemeral, and AUTH on publish would tie a wrap to its sender. MAY rate-limit. MAY require NIP-13
  proof of work only at a difficulty this specification fixes; none is fixed yet.
- **Gift-wrap reads.** MAY require NIP-42 AUTH by the `p`-tagged key to deliver kind 1059 events, and SHOULD NOT
  deliver them to anyone else.
- **Bursts and Tor.** SHOULD accept at least 60 events in 10 seconds from one connection. A taker's `!tx` to ten makers,
  each split into up to four parts, is 40 events at once. SHOULD NOT limit connections or events per source address in a way
  that blocks Tor exits, where many nicks share one address. SHOULD offer an onion service.
- **Clock.** SHOULD accept `created_at` up to 60 seconds in the future and 600 seconds in the past.

A conforming relay's NIP-11 document includes at least:

```json
{
  "supported_nips": [1, 9, 11, 40, 42],
  "limitation": {
    "max_message_length": 65536,
    "max_content_length": 65536,
    "max_subscriptions": 4,
    "max_event_tags": 32,
    "auth_required": false,
    "payment_required": false,
    "restricted_writes": false
  }
}
```

(42 only where the relay uses AUTH. Larger limits are fine.)

Clients SHOULD read a relay's NIP-11 document before using it. They SHOULD NOT send events with `expiration` to a
relay whose `supported_nips` lacks 40 (NIP-40), and SHOULD skip relays whose limits are below the ones above.
Clients SHOULD use at least three relays run by different operators.

### Relay conformance check

An operator or client checks a relay by doing the following from fresh keys over Tor, each step on its own
connection:

1. Fetch NIP-11 and compare it with the profile above.
2. Publish a kind 31402 offer event with `expiration` 120 seconds ahead. Read it back by `#t`, `#f` and `#d`.
   Publish a newer one with the same `d` and confirm it replaces the first. Delete it with kind 5 by `a`
   coordinate and confirm it is gone. Confirm that another key's kind 5 does not delete it.
3. Publish a kind 21402 event while a second connection is subscribed. Confirm the subscriber receives it, and
   that a later query does not return it.
4. Publish a worst-case kind 1059 wrap (the size above) with `expiration` 120 seconds ahead. Read it by `#p` and
   `since`. Note whether reading requires AUTH, and whether another key can read it.
5. After the expirations pass, confirm that neither event is served.
6. Publish 60 events within 10 seconds on one connection and confirm all are accepted. Open several
   connections from one address and confirm none is refused.

### Sessions and timeouts

A session's messages all carry `hostid` `nostr-network`, so a session started on this channel cannot continue
on an onion channel, and a signature made for one channel never verifies on the other. Implementations apply
their usual JMP-0001 phase timeouts; there is no heartbeat, since a maker's liveness is its unexpired offer
event and its answers.

## Backward Compatibility

Peers that do not implement this channel are unaffected: the channel is additive, uses its own `hostid`, and
changes nothing in the CoinJoin protocol. A peer MAY run this channel beside onion channels with the same nick,
as JoinMarket's message channel collection allows; a session stays on the channel it started on.

This is how JoinMarket moved from IRC to onion directories: for a while both ran side by side, and reference
JoinMarket's default configuration still runs both. The same path works here. During the transition, makers
SHOULD run this channel beside their onion channel, so takers on either channel see the same liquidity.

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
- **Expiry instead of presence.** IRC and directories know when a nick leaves; Nostr relays don't. An offer event's
  expiry, and the maker's republishing, do what leaving the channel did, so relays only ever hold events that
  expire within an hour.

## Security Considerations

- Relays learn which nick keys receive private messages, when, and how large they are, and they can censor.
  This is less than an IRC server or directory learns: those see sender, recipient and every plaintext command.
  Use several relays run by different operators, use Tor, and use fresh nicks.
- A relay can link a gift wrap to its sender through the connection that published it. Publishing wraps over a
  separate connection and circuit, without AUTH (Network privacy), removes that link. Timing correlation by a
  relay that sees both sides remains.
- A relay that keeps expired gift wraps builds a long-term record of who received messages and when. Conforming
  relays delete them, but clients cannot verify deletion, so the fresh nicks are what limit the damage.
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
