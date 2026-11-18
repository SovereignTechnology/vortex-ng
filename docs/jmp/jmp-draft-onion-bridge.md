---
jmp: TBD
title: Onion Channel Bridge over Nostr
author: sovtech
status: Draft
type: Standards Track
layer: Extension
created: 2026-11-18
requires: 0001, 0005
---

## Abstract

This specification lets a JoinMarket peer that cannot reach Tor use the onion directory channel. The peer runs
the ordinary onion channel, with its own handshake, its own nick authentication and lines signed for
`onion-network`, but instead of a TCP connection through Tor to a directory node it sends each wire message,
unchanged, inside a Nostr gift wrap to a **bridge**. The bridge holds one directory connection per bridged nick
and passes the messages through. It is a transport for the existing channel, not a new channel: directory
nodes and other peers see an ordinary peer that does not serve an onion (`NOT-SERVING-ONION`), and nothing in
JMP-0001 or JMP-0005 changes.

## Motivation

The onion directory channel is where JoinMarket's makers are: both joinmarket-clientserver and joinmarket-ng
meet on the same directory nodes, and they are onion services, reachable only through Tor. A peer in a browser,
on a phone without a Tor client, or in a deployment that only speaks Nostr cannot reach them. The Nostr message
channel does not help such a peer reach those makers until they run it too.

A bridge that translated between channels cannot exist: a private line is signed over its body and the
channel's signature domain (`hostid`), so a line signed for `nostr-network` is not valid on the onion channel
and the bridge cannot re-sign it without the sender's nick key. What a bridge can do is carry a peer's own
onion-channel traffic. The peer keeps its nick key, signs for `onion-network`, and runs the onion channel's
handshake and nick authentication itself; the bridge only moves bytes between Nostr and a directory
connection.

## Specification

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119.

### Roles

- **Client**: a JoinMarket peer that implements this transport. It holds its nick key.
- **Bridge**: a service with a long-term Nostr key (the bridge key) and a way to reach the directory nodes it
  serves (normally a Tor daemon). It never holds a client's nick key.
- **Directory node**: an unmodified onion directory node (JMP-0001, JMP-0005).

### Bridge announcement (kind 31404)

A bridge publishes one addressable event per network it serves, signed by the bridge key:

```json
{
  "kind": 31404,
  "content": "",
  "tags": [
    ["d", "mainnet"],
    ["directory", "<v3 onion>:5222", "<directory id for JMP-0005, if the node uses one>"],
    ["relay", "wss://relay.example"],
    ["admission", "pow", "24"],
    ["limits", "sessions=200", "per_client=4", "lines_per_min=120", "bytes_per_min=200000"],
    ["expiration", "<unix time, at most 7 days ahead>"]
  ]
}
```

- `d` is the network name as the directories expect it in the handshake.
- Each `directory` tag names one directory node by its location string, exactly as the client will name it, and
  the identity it uses for nick authentication, if any. A bridge MUST NOT connect anywhere else.
- `relay` tags name where the bridge reads gift wraps addressed to it (at least one, at most five).
- `admission` gives the cost of opening a session (see Admission). `limits` states the limits the bridge
  enforces, so a client can stay inside them.
- The kind numbers in this document are provisional, in the 21402/31402 range of the Nostr message channel.

### Tunnel frames

Every frame is a JSON object in the `content` of an unsigned rumor of kind 21404, sealed and gift-wrapped as in
NIP-59: the seal (kind 13) is signed by the sender's tunnel key and NIP-44 v2 encrypted for the recipient, and
the wrap (kind 1059) is signed by a one-time key, carries a `p` tag for the recipient and a NIP-40 `expiration`
at most 10 minutes ahead.

- The client's **tunnel key** is a fresh Nostr key per session. It MUST NOT be the nick key, and MUST NOT be
  reused for another session, so relays and the bridge cannot link a client's sessions through it.
- Frames from the client go to the bridge key on the bridge's relays; frames from the bridge go to the tunnel
  key on the relays the client named in `hello`.
- Each frame carries `"s"`, the session id (16 random bytes, hex, chosen by the client), and `"n"`, a sequence
  number per session and direction starting at 0. A receiver MUST drop a frame whose seal is not signed by the
  session's tunnel key (after `hello`) or by the bridge key, MUST drop duplicates (a gift wrap may arrive from
  several relays), SHOULD put frames back in order holding at most 64 or 30 seconds' worth, and MUST close the
  session if a gap outlasts that.

| frame | direction | fields | meaning |
|---|---|---|---|
| `hello` | client → bridge | `relays` (1 to 5 URLs), `directory` (one location string from the announcement), `network` | ask for a session |
| `challenge` | bridge → client | `nonce` (32 random bytes, hex), `admission` (as announced) | the price and the nonce to prove the nick against |
| `open` | client → bridge | `nick`, `pubkey`, `proof`, `admission` | prove the nick, pay, and start |
| `opened` | bridge → client | | the bridge has connected to the directory |
| `wire` | both | `type` (integer), `line` (string) | one onion-channel message, unchanged |
| `keepalive` | client → bridge | | the session is alive |
| `close` | both | `code` | the session ends; `code` is one of `done`, `refused`, `limit`, `admission`, `idle`, `gap`, `directory`, `invalid` |

A frame that is not JSON, has unknown fields of the wrong type, or arrives in the wrong state closes the session
with `invalid`.

### Opening a session

1. The client sends `hello`. The bridge answers `challenge`, or `close` with `refused` (unknown directory, other
   network, the bridge is full).
2. The client proves it holds the nick key: `proof` is a Bitcoin signed-message signature (as JMP-0005 uses) by
   the nick key over `jm-bridge-open-v1|<nonce>|<bridge key hex>|<directory>|<network>|<nick>|<pubkey>`. The
   bridge MUST check the signature and that `nick` is the nick JMP-0001 derives from `pubkey`, and MUST refuse a
   nick that already has a session to that directory through it.
3. The bridge checks the admission (below), connects to the directory, and answers `opened`.
4. The client then sends its handshake as the first `wire` frame, written by the client itself. The bridge MUST
   check, without changing a byte of it, that it is a client handshake (`directory` false) for `nick` on the
   announced network with `location-string` equal to `NOT-SERVING-ONION`, and otherwise close the session with
   `invalid`. It forwards it, and forwards the directory's answer. If the directory asks for nick
   authentication (JMP-0005), the challenge goes to the client and the client's proof to the directory; the
   transcript hashes the handshake line the client wrote, so it verifies unchanged.

### Passing messages through

The bridge forwards only these wire messages, and drops any other:

| from the client | from the directory |
|---|---|
| `PRIVMSG` (685), `PUBMSG` (687), `HANDSHAKE` (793, once, first), `NICK_AUTH_PROOF` (805, once, after a challenge) | `PRIVMSG` (685), `PUBMSG` (687), `DN_HANDSHAKE` (795), `NICK_AUTH_CHALLENGE` (803), `NICK_AUTH_RESULT` (807) |

- A `PRIVMSG` from the client MUST have the session's nick as its sender field, and a `PUBMSG` MUST start with
  `<nick>!PUBLIC`. The bridge drops anything else; it never carries a line in another nick's name.
- `GETPEERLIST` (791) and `PEERLIST` (789) are not forwarded: a bridged client cannot connect to peers directly,
  and a peer list would only tell it where others are.
- The bridge answers the directory's `PING` (798) with `PONG` (799) itself while the session is alive, so pings
  never cross Nostr.
- A line longer than 40,000 bytes is dropped in either direction.
- When the directory connection closes, the bridge sends `close` with `directory`; when the client sends `close`
  or stays silent, the bridge closes the directory connection.

### Keeping a session alive

The client MUST send a frame at least every 60 seconds (`keepalive` if it has nothing else) and the bridge MUST
close a session that has been silent for 180 seconds (`idle`). A session lasts at most 24 hours; a client that
wants to stay longer opens a new one, with a new tunnel key.

### Limits

A bridge MUST enforce, and state in its announcement:

- a total number of sessions, and a number of sessions per client relay set and per directory;
- per session, a token bucket on lines and on bytes from the client (suggested: 120 lines and 200,000 bytes per
  minute, a burst of twice that), closing the session with `limit` when it is exceeded;
- one session per nick per directory.

It SHOULD keep its connections to one directory few enough that the directory does not see it as abuse, and
spread sessions over the directories it announces.

### Admission

A bridge charges for a session so that opening sessions costs the opener more than it costs the bridge.
`admission` in the announcement and the `challenge` names the method:

- `pow <bits>`: the `open` rumor's id MUST have at least `<bits>` leading zero bits (NIP-13). Its content holds
  the nick proof, which signs the challenge nonce, so the work cannot be reused for another session. Every
  bridge MUST support it.
- `token`: `admission` in `open` carries a bearer token the operator issued out of band (for example a Cashu
  token). A bridge MAY offer it, alone or as an alternative to proof of work.
- `none`: only for a private bridge whose relays and key are not published.

### Choosing bridges

A client SHOULD use more than one bridge, and SHOULD use the Nostr message channel as well where it can: a
single bridge, like a single directory, decides what its clients see.

## Backward Compatibility

Nothing changes for directory nodes or for peers that do not use a bridge. A bridged peer looks like any peer
that does not serve an onion: its handshake says `NOT-SERVING-ONION`, the directory relays its private messages,
and its lines are signed for `onion-network`. joinmarket-clientserver and joinmarket-ng need no change to trade
with it.

Only clients that implement this transport can be bridged. A joinmarket-ng peer on its Nostr message channel, or
any peer speaking only the Nostr channel, cannot reach the onion directories through a bridge, because its lines
are signed for `nostr-network` (see Motivation).

## Rationale

- **A transport, not a translation.** Re-signing lines would need the nick key. Carrying the client's own
  handshake, nick authentication and lines keeps the bridge unable to speak for the client.
- **One directory connection per nick.** joinmarket-ng's directory accepts a private line only from the nick
  that opened the connection it came on, so nicks cannot share a connection.
- **The bridge checks the sender.** JMP-0001 does not require a directory node to check that a private line's
  sender is the nick of the connection it came on. Checking it at the bridge keeps a bridge from becoming a way
  to send lines under other nicks, whatever the directory does.
- **A separate tunnel key.** The nick key stays a JoinMarket key only, used on Nostr only inside the seal of the
  Nostr message channel; the tunnel key is a throwaway transport key. The nick proof in `open` binds the two for
  the bridge, which sees the nick anyway.
- **Pings answered at the bridge.** A directory that pings its peers does so often enough that relaying pings
  over Nostr would cost more than the rest of an idle session; the tunnel's own keepalive tells the bridge the
  client is there.
- **Proof of work as the baseline.** It needs no account and no payment system, and every implementation can
  check it.

## Security Considerations

**What the bridge learns:** what a directory node learns about each bridged nick: every private line's sender,
recipient, size and timing, and the contents of the plain-text steps (`!fill`'s order id, amount and
commitment, `!pubkey`); public messages; the nick's presence. In addition it learns the client's relay set and
the timing of its Nostr traffic. It does not learn the client's IP address, which only the client's relays see,
and it cannot read the encrypted steps of a round, which are encrypted end to end between taker and maker.

**What the bridge cannot do:** sign a line as the client, change a line without breaking its signature, or
complete nick authentication without the client.

**What the bridge can do:** drop, delay or reorder the client's traffic; replay lines it has seen (as a
directory can; peers treat a line that does not fit their state as stray and ignore it); and show the client a
false view of the channel: offers and public messages from nicks it controls, since public messages on the onion
channel carry no signature. Fidelity bonds limit what such nicks can win; using several bridges and the Nostr
channel limits what one bridge can hide.

**Relays** see that a tunnel key and the bridge key exchange gift wraps, their sizes and their timing, and the
client's IP address. Per-session tunnel keys keep sessions apart; the relays the client chooses decide who sees
its address.

**Abuse of the bridge:** without the limits above a bridge is a free way into the onion network for anyone;
the fixed directory list, the fixed message types, the sender check, `NOT-SERVING-ONION` in every handshake,
the limits and the admission cost are each required.

**Directories** see many nicks from the bridge's Tor exit points. A directory that limits connections per source
cannot tell bridged peers apart; bridge operators SHOULD stay well inside what directories tolerate.

## Test Vectors

To be added with the reference implementation: a `hello`/`challenge`/`open` exchange with keys and the expected
proof, and the frames of a handshake with nick authentication.

## Reference Implementation

vortex-ng, issue #48 (not yet written): the tunnel as one more way for its onion channel to reach a directory,
and a `vortex-ng-bridge` service.
