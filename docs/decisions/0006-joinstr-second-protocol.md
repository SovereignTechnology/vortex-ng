# 6. joinstr as a second protocol

Date: 2026-11-15

## Status

Accepted

## Context

joinstr (gitlab.com/invincible-privacy) is the other coinjoin protocol coordinated over Nostr. Cameron wants
vortex-ng compatible with it. It is not JoinMarket over another transport:

| | JoinMarket (ADR 0001) | joinstr v1 |
|---|---|---|
| shape | a market: makers post offers, a taker pays them | a pool: one creator, N peers, one denomination, nobody is paid |
| discovery | offers (kind 31402), `!orderbook` | `new_pool` (kind 2022), signed by the pool's own key |
| messages | NIP-59 wraps of signed JMP-0001 lines, NaCl inside | NIP-04 to the pool key; once admitted, every peer holds the pool's private key and posts as it |
| inputs | any size, with change | one coin worth the denomination plus 500 to 5000 sats, no change |
| signing | `SIGHASH_ALL`, after seeing the whole transaction | one registration each, `SIGHASH_ALL \| SIGHASH_ANYONECANPAY` over the agreed outputs; anyone combines |
| sybil defence | fidelity bonds, PoDLE | optional aut-ct proof of an unrelated UTXO |
| failure | maker replacement | a recovery round: outputs re-registered under a linkable ring signature, inputs re-signed |

A JoinMarket maker cannot fill a joinstr pool and a joinstr peer cannot take a JoinMarket offer: the messages,
the trust model and the signatures differ. There is nothing to bridge.

## Decision

- vortex-ng speaks joinstr v1 as a **second protocol**, beside JoinMarket and sharing its wallet, chain backend,
  Nostr client and Tor. ADR 0001's rule is untouched: JoinMarket code paths do not change, and nothing of
  joinstr leaks into a JoinMarket round.
- The protocol lives in `vortex-ng-joinstr`, with no I/O, as `vortex-ng-core` does for JoinMarket. It is written
  to joinstr's `NIP.md` "Wire rules" and to `joinstr-difffuzz`'s `findings/RULES.md` (R1 to R8), at the
  revisions in `docs/upstream-pins.md`. Where those leave a detail open the Electrum plugin decides, as
  RULES.md says.
- rust-joinstr is read as a second reference and not linked: it brings its own wallet, Electrum client and
  Nostr client, and older pins.
- Conformance is shown the way joinstr's own clients show it: vortex-ng becomes an adapter in
  `joinstr-difffuzz`, the differential fuzzer that holds seven implementations to the same behaviour.
- The reference clients are Python and every client must derive the same numbers, so Python's arithmetic is
  reproduced exactly (`round` to even, `int` truncation, floor division, `==` across number types,
  `json.dumps` text): `vortex-ng-joinstr::pyjson` and `::rules`.
- Both roles are supported (joining and creating pools), the recovery round, and aut-ct through a local
  `autct-api` daemon. Pools whose transport is `vpn` are listed and not joined: vortex-ng reaches relays over
  Tor only, as joinstr-kmp and floresta do.

## Consequences

- joinstr's privacy properties are joinstr's, and users must be told where they differ from a JoinMarket round:
  - NIP-04 hides message content only; relays see who writes to which pool key and when.
  - Every admitted peer holds the pool's private key, so any peer can read every pool message and can forge
    messages from "the pool". The protocol's checks (credentials bound to the announcement, registrations
    that must sign identical outputs, the peer's own refusal to overpay) are what protect a coin, not the
    channel.
  - There is no change output: a wallet needs a coin of the right size first, and making one is an on-chain
    step of its own.
  - Without aut-ct a pool has no sybil defence at all.
- vortex-ng follows joinstr's wire rules even where it would choose differently, and reports disagreements
  upstream (after Cameron has read them) instead of diverging.
- joinstr and its fuzzer are MIT; test vectors derived from them are used under that licence.
