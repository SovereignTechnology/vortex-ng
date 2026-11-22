# 8. CoinJoin from channel closes

Date: 2026-11-19

## Status

Accepted. Slice 1 (wallets that hold their own keys) is built; slice 2 (a Lightning node's wallet) is designed
here and not built.

## Context

When a Lightning channel closes, the funds come back on chain as ordinary coins, and the close is the one
moment they are most easily linked to a node: a public channel's funding output is in gossip, the closing
transaction spends it, and the output that pays the node's wallet is the next thing anyone sees. A CoinJoin
straight after breaks that link, so a closed channel is the best time to mix, and nothing in Lightning stops
it: after the close (and for a force close, the delay) the output is a coin like any other.

What is missing is the tooling. A user has to know which of their coins came from a close, keep them apart
from coins with another history (merging them in one transaction links both), and get them into a wallet
that can run a round. Cameron asked (2026-11-19) for vortex-ng to detect a channel-close coin and
CoinJoin from it, from Lightning nodes' wallets as well as from JoinMarket / joinmarket-ng wallets.

Facts that shape it:

- **Recognition needs no node.** A close's creating transaction has BOLT 3's shapes: one input spending
  `2 <K1> <K2> 2 CHECKMULTISIG` with sorted keys (a mutual close if it pays at most two outputs, a force close
  if `nSequence` is `0x80……` and `nLockTime` `0x20……`); a force close's leftovers are swept with witnesses that
  end in `to_local`'s delayed script, an anchor channel's `to_remote` (`1 CSV`) script, or the anchor script.
  BDK keeps the full creating transaction of every coin it finds.
- **The `wsh0` pit's script is BOLT 3's funding script byte for byte** (`script::wsh0_witness_script` says so).
  Every input of a `wsh0` CoinJoin has the funding-spend witness. A close spends exactly one output, so the
  one-input rule is what keeps a CoinJoin from reading as a close, and it is tested.
- **A taker needs a coin's private key**, twice: to sign its inputs, and to build the PoDLE commitment
  (`podle_for` takes the key of the committed coin; the proof is a DLEQ over `x·G` and `x·J`). A Lightning
  node's wallet signs inputs when asked (LND's `signrpc.ComputeInputScript`, `walletrpc.SignPsbt`) and never
  hands out a key, and nothing it exposes computes a PoDLE proof. LND's `DeriveSharedKey` is documented to
  return a hash of `x·Q`, which could serve as the commitment hash but not the proof. **These LND calls are
  from its documentation as remembered, not from a source tree: slice 2 starts by checking each against the
  LND release it pins, and this ADR is amended if one differs.**
- **joinmarket-ng's maker does not require the PoDLE coin to be a transaction input.** It binds the revealed
  key to the coin's scriptPubKey, then checks the coin's age (5 confirmations) and size (20 % of the amount)
  (`maker/coinjoin.py`, c3312cb). `Taker::new` already takes the commitment apart from the inputs.
- A taker's inputs come from one mixdepth of one wallet, and its outputs go to the next mixdepth: a close
  coin that is spent from where it landed ends in the same wallet's next mixdepth.

## Decision

1. **Recognise a close from the creating transaction, as evidence.** `vortex_ng_core::lnclose::classify`
   returns `Cooperative`, `Unilateral` or `Sweep` (and whether it is a simple taproot channel's) from a
   transaction alone. It is labelled "evidence": a single-input 2-of-2 spend by someone who is not a node
   looks like a mutual close. A taproot channel's mutual close is a lone key-path spend and is not recognised.
   A node's own records are stronger and slice 2 uses them where it has them.
2. **Slice 1: the wallet's own coins.** `PitWallet::close_origin` / `utxos_with_origin` label coins. The CLI
   gets `vortex-ng coins [--closes-only] [--outpoints]` and `vortex-ng coinjoin --from-closes`, which spends
   only close coins, so they are not merged with others. A joinmarket-ng wallet is the same BIP39 seed (the
   derivations match, `vortex_ng_wallet`'s header), so restoring it here gives its coins. To receive a close,
   the user passes the node one of the wallet's addresses as the close's delivery address. This covers a
   mutual close, the common and recommended case. It does NOT cover a force close: the node sweeps that into
   its own wallet, and a coin sent on from there is created by an ordinary payment, two hops from the close.
   Walking ancestors through the node was considered and left out: it needs a transaction index on the
   node, and the send that moves the coin usually merges other coins of the node's wallet, which is the
   linkage this feature exists to avoid. Force closes are slice 2's job.
3. **Slice 2: a Lightning node as a coin source, built on a signing seam.** The taker's `finish` calls a
   `PitWallet`; slice 2 puts an `InputSigner` trait there, implemented by `PitWallet` (as now) and by an LND
   client over its REST API (macaroon + pinned TLS certificate, both read from owner-only files, never from
   the command line). The node supplies the coin list (`ListUnspent`) and close history (`ClosedChannels`,
   `PendingChannels`, transaction labels) and signs the inputs (`ComputeInputScript`); the CoinJoin's outputs
   go to a vortex-ng wallet's mixdepths. Because the node cannot prove a PoDLE, the commitment comes from a
   coin of a vortex-ng wallet (any mixdepth, five confirmations, a fifth of the amount), which joinmarket-ng's
   maker accepts: the user keeps a small coin there for it. Real-LND regtest is the proof, not a fake.
4. **Other nodes (LDK, CLN, Eclair, Phoenix) use slice 1's route**: the mutual close's delivery address is
   a vortex-ng address. None exposes the signing slice 2 needs (ldk-server has no PSBT signing). A force
   close there is mixed as an unlabelled coin, with plain `coinjoin`, after the node has swept it.
5. **No unattended spending.** Nothing here watches for closes and CoinJoins by itself. A daemon policy that
   spends money without a person is a separate decision, and mainnet wallets stay refused in the CLI.

## Consequences

- `vortex-ng-core` gains a pure module with BOLT 3's script shapes. Real captures from an LND regtest close
  (mutual, force, swept) replace the hand-built vectors when slice 2's harness exists: hand-built shapes can
  agree with the author's reading of the spec and with nothing else.
- The commands print amounts, depths and kinds. Outpoints are shown only with `--outpoints`: a closing
  transaction's id names the channel's funding output, and the same data on a live node is key material.
- A mixed-history wallet is the user's to tidy: `--from-closes` never touches other coins, and says so.
- `Sweep` and a commitment's `to_remote` reach a vortex-ng wallet only when something pays them there
  directly. They are in slice 1 because the detector is shared with slice 2, where an LND wallet's own
  coins are created by exactly these transactions, and because it keeps the labels honest if they do.
- Slice 2 adds an HTTPS client and the LND REST types to `vortex-ng-ln`, so new crates and a `cargo deny`
  pass; that is the reason it is its own change.
