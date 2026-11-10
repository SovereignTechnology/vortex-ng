# 1. JoinMarket semantics, Nostr transport

Date: 2026-11-09

## Status

Accepted

## Context

vortex-ng starts as a Rust rewrite of LnVortex, a channel-open coinjoin by benthecarman (Scala on bitcoin-s).
LnVortex is archived (last functional commit 2022-11), relied on a central coordinator, only ever opened
classic P2WSH channels (taproot channel opens are a `// todo` in `core/.../api/TransactionType.scala`), and
derives coordinator nonces as `max(nonce_index) + 1` over a table it deletes rows from
(`AliceDAO.nextNonceIndexAction`), which can reuse a Schnorr nonce and leak the coordinator key.

The project owner's requirements: regular coinjoins and Lightning channel opens (regular and taproot) for
every Lightning implementation whose API allows it; a maker/taker market like JoinMarket-NG; decentralized;
coordinated over Nostr only; and "all coinjoin methods and systems need to be compatible with how joinmarket
would do it but for nostr only".

JoinMarket separates a protocol layer (commands, NaCl sessions, PoDLE, fidelity bonds, per-pit transaction
rules, maker and taker checks) from a message-channel layer (public and private messages to nicks, peer
discovery, handshake features, nick signatures over a `hostid`). JMP-0001 documents both.

## Decision

- vortex-ng implements JoinMarket's protocol layer exactly as JMP-0001 and the JMP extensions specify it, at
  the revisions in `docs/upstream-pins.md`, and replaces only the message-channel layer, with Nostr.
- No IRC, no onion directories, no direct peer sockets, no central coordinator. WabiSabi/Wasabi-style rounds
  are out of scope: they need a coordinator.
- Where JoinMarket(-NG) has a spec (JMP-0010 `tr0`, JMP-0014 channel rings, JMP-0012/13 credential market),
  vortex-ng follows it as written. Where it has none (the Nostr channel, a regular-channel pit,
  channel-funding outputs), vortex-ng writes one in JMP format (`docs/jmp/`), in the same pattern, so
  joinmarket-ng can adopt it. A Python implementation for joinmarket-ng accompanies each draft and serves as
  the interop counterpart in tests.
- LnVortex's code is not ported. Its idea is kept: a coinjoin output that is a Lightning funding output.

## Consequences

- JoinMarket-NG's taker and maker logic maps one to one onto vortex-ng's; an implementation only needs a new
  message channel to interoperate.
- Until joinmarket-ng ships the Nostr channel, the live JoinMarket market (onion directories) and vortex-ng's
  market do not share liquidity.
- Every new protocol choice is reviewed against "is this how JoinMarket would do it?".
