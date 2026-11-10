---
jmp: TBD
title: Lightning Channel Funding Outputs in CoinJoins
author: sovtech
status: Draft
type: Standards Track
layer: Extension
created: 2026-11-09
requires: 0001, 0010
---

## Abstract

This specification lets a taker make its equal-amount CoinJoin output the funding output of a Lightning channel
it opens: a taproot channel in the `tr0` pit (JMP-0010) or a regular channel in the `wsh0` pit (wsh0 draft).
Makers need no change and cannot tell. The specification fixes the order in which the taker obtains the
channel peer's commitment signature and signs its own inputs, the time bound this implies, and how an
interrupted open is cancelled.

## Motivation

Opening a channel from a CoinJoin output in a second transaction links the two on chain and costs a second fee.
Funding the channel inside the CoinJoin removes that link, provided the funding output looks like every other
equal output. JMP-0010 already names taproot channel funding outputs as something `tr0`'s uniformity hides;
the `wsh0` draft does the same for regular channels. What remains is the taker's procedure, since a funder that
lets its funding transaction confirm before holding the peer's `funding_signed` locks its coins in a 2-of-2 with
no refund path.

## Specification

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119.

### Applicability

- Only the taker's equal-amount output MAY be a channel funding output. Makers' outputs are their own.
- In `tr0` the channel MUST be a simple taproot channel (`option_simple_taproot`, feature bits 80/81), whose
  funding output is a P2TR key-path output, satisfying JMP-0010's output policy.
- In `wsh0` the channel MUST use the BOLT 3 funding script, which is a `wsh0` script, satisfying the `wsh0`
  output policy.
- A taker MUST NOT use a channel funding output in `sw0`, where it would be the only P2WSH output.
- The channel capacity is the CoinJoin amount.

### Procedure

1. **Open.** Before sending `!fill`, the taker starts a channel open whose funding transaction will be supplied
   externally, and obtains the funding scriptPubKey from its Lightning node. It MUST verify that the script has
   the pit's output type.
2. **Round.** The taker runs JMP-0001 phases 1 to 4 with the funding scriptPubKey as its equal output. Nothing
   in any message reveals that the output is a channel.
3. **Commitment.** After receiving every maker's `!sig`, and before signing any of its own inputs, the taker
   gives its Lightning node the unsigned transaction with every input's prevout amount and scriptPubKey. The
   node sends `funding_created` and receives `funding_signed`. The taker MUST first verify that every input
   spends a segwit output (both pits require it), since only then is the funding txid fixed by the unsigned
   transaction; a non-segwit input would let the final txid differ from the one the peer signed for.
4. **Sign and broadcast.** Only after its node reports that `funding_signed` was received does the taker sign its
   own inputs, assemble the transaction and broadcast it, itself or by `!push` (JMP-0001 "Phase 5").

A taker MUST NOT sign any of its inputs before step 3 completes.

### Time bound

A channel peer drops a pending open it has accepted if `funding_created` does not arrive in time (LND: 10
minutes). The taker MUST complete steps 2 and 3 within 8 minutes of its node receiving `accept_channel`, and
otherwise cancel the open and start again with a new one.

### Cancellation

- Before step 3, the taker cancels the pending open on its node and MUST NOT use that funding scriptPubKey
  again.
- After step 3 and before broadcast (for example, a broadcast failure or a maker's input spent elsewhere), the
  taker MUST NOT broadcast a different transaction paying the same funding output; it abandons the pending
  channel on its node. The peer may keep the pending channel until its own timeout (2016 blocks in deployed
  implementations), and a peer that accepts one pending channel per node will refuse a new open until then.
- A taker MUST NOT replace the transaction (RBF): a new txid invalidates the channel. To raise the fee it uses
  CPFP from its change output.

### Announcement

Channels opened this way SHOULD be unannounced. Announcing a channel publishes its funding outpoint with both
node identities and so marks the taker's equal output; an implementation MUST warn before opening an announced
channel. Deployed simple taproot channels are unannounced.

### Implementation notes (informative, checked 2026-11-09)

| implementation | step 1 | step 3 | cancel | taproot |
|---|---|---|---|---|
| LND 0.21 | `OpenChannel` with `funding_shim.psbt_shim{pending_chan_id, no_publish=true}` | `FundingStateStep.psbt_verify{funded_psbt, skip_finalize=true}` | `FundingStateStep.shim_cancel`; after step 3 `AbandonChannel{pending_funding_shim_only=true}` | `commitment_type=TAPROOT` (7), private only |
| Core Lightning 26.06 | `fundchannel_start` | `fundchannel_complete{id, psbt}` (unsigned PSBT accepted) | `fundchannel_cancel` | no |
| LDK 0.2 | `create_channel`, `Event::FundingGenerationReady` | `unsafe_manual_funding_transaction_generated` with the exact funding outpoint (LDK checks nothing and will not broadcast; the taker MUST verify the outpoint's script and amount itself) | force-close the unfunded channel | no |
| Eclair 0.14, ldk-node 0.7 | no external funding API | — | — | Eclair as peer only |

Any implementation can be the remote peer of a regular channel; LND and Eclair can be the remote peer of a
taproot channel.

## Backward Compatibility

Makers are unaffected and need no support: the funding output satisfies the pit's output policy and is
indistinguishable from any other participant's output. No message changes.

## Rationale

JoinMarket's taker already collects every maker's signature before signing its own inputs, so the only extra
step is to obtain the peer's commitment signature in between. Because the taker signs last, only the taker can
leave a pending channel behind, and it controls its own cancellation.

## Security Considerations

- Signing before `funding_signed` can lock the taker's coins in a 2-of-2 with no refund; the procedure forbids
  it.
- The channel peer learns which output is the taker's and that it came from a CoinJoin. Choose peers
  accordingly.
- The channel capacity equals the round amount, which is public; this reveals nothing beyond the round itself.

## Reference Implementation

- vortex-ng, crate `vortex-ng-ln` (in development).
- A joinmarket-ng taker implementation (planned, offered upstream).
