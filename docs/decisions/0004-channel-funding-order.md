# 4. Channel funding: the taker opens, and signs last

Date: 2026-11-09

## Status

Accepted (normative text: `docs/jmp/jmp-draft-channel-funding-outputs.md`)

## Context

A Lightning funder must not let its funding transaction confirm before it holds the peer's `funding_signed`:
otherwise its coins sit in a 2-of-2 with no refund path. In a coinjoin, the funding txid is only fixed once the
transaction's inputs and outputs are fixed, and all participants sign the same transaction.

In JoinMarket the taker builds the transaction, collects every maker's `!sig`, then signs its own inputs and
broadcasts. All inputs are segwit, so the txid is known from the unsigned transaction.

External funding support (checked 2026-11-09): LND (psbt_shim with `no_publish`, `psbt_verify` with
`skip_finalize`, `TAPROOT=7` channels, private only), Core Lightning (`fundchannel_start/complete/cancel`, no
taproot), LDK (`unsafe_manual_funding_transaction_generated`, no taproot). Eclair and ldk-node have no API for
it. A remote LND drops a stalled open after 10 minutes and accepts one pending channel per peer by default.

## Decision

- Only the taker's equal-amount output can be a channel funding output. Makers need no change: they see an
  output of the pit's script type.
- Order: open the pending channel and learn the funding script; run the JoinMarket round; after every
  maker's `!sig`, hand the unsigned transaction to the Lightning node; receive `funding_signed`; only then
  sign the taker's inputs and broadcast (or `!push`).
- Taproot channels go in `tr0`; regular channels go in `wsh0`. Channels are unannounced by default.
- One `ChannelFunder` trait with LND, Core Lightning and LDK backends. Eclair and ldk-node get upstream PRs
  for external funding; both can already be the remote peer.

## Consequences

- Only the taker can strand a pending channel, and only by aborting after `funding_signed`; it then cancels its
  own pending open.
- The round has a deadline: from the Lightning node's `accept_channel` to `funding_signed` must fit the
  peer's reservation timeout.
