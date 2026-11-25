# 8. CoinJoin from channel closes

Date: 2026-11-19

## Status

Accepted. Slice 1 (wallets that hold their own keys) and slice 2 (an LND node's wallet) are built. Both run on
regtest only: mainnet stays refused.

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
  node's wallet signs inputs when asked (LND's `signrpc.ComputeInputScript`) and never hands out a key, and
  nothing it exposes computes a PoDLE proof: `DeriveSharedKey` returns only a hash of `x·Q`. Checked against
  LND v0.21.8-beta's protos and server source.
- **LND keeps a reserve that only its own sends respect.** It refuses to spend below what it needs to fee-bump
  the force close of its open anchor channels (`CheckReservedValue`). A spend it merely signs is not checked,
  and without those funds a commitment transaction may not confirm before its HTLCs expire.
- **LND pays its closes and sweeps to P2TR** (seen on v0.21.8 regtest, both kinds), so its close coins can only
  join the `tr0` pit, whose makers today are vortex-ng and joinmarket-ng's Taproot branch (PR #643). The
  deployed `sw0` market is reached by a mutual close with a `sw0` delivery address (decision 2).
- **joinmarket-ng's maker does not require the PoDLE coin to be a transaction input.** It binds the revealed
  key to the coin's scriptPubKey, then checks the coin's age (5 confirmations) and size (20 % of the amount)
  (`maker/coinjoin.py`, c3312cb), and a round with real joinmarket-ng makers confirms this way
  (`tools/jmng-interop`, `VORTEX_NG_INTEROP_COMMIT_ELSEWHERE=1`). `Taker::new` takes the commitment apart from
  the inputs.
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
3. **Slice 2: an LND node as a coin source, built on a signing seam.** `Taker::finish` takes an `InputSigner`,
   implemented by `PitWallet` and by an LND client over its REST API (`vortex_ng_ln::lnd`: TLS pinned to the
   node's own certificate, no new crates). `vortex-ng lnd-coins` lists the node's coins and marks closes by its
   own records (`ClosedChannels`, counting only sweeps this node made), which also sees force closes and taproot
   channels. `coinjoin --from-lnd --mixdepth <n>` spends them with the node signing. Its rules, each because the
   obvious version loses money or privacy:
   - **The anchor reserve is enforced here**, before the prompt and again once the coins are leased.
   - **One coin per round**, the smallest that covers it. Merging links different channels: `--merge-closes`.
   - **Change goes back to the node**, so it carries no channel's history into a mixdepth and a small round
     does not move a whole coin out of it. The amount goes to the wallet's next mixdepth.
   - **The commitment coin is shown to makers**, so it comes from the mixdepth the user names, is never a
     CoinJoin's output, and serves one round: a maker in two rounds could otherwise link two channels.
   - **Nothing reaches a maker until the node has shown it will sign**, on a throwaway transaction that states
     each amount one satoshi too high, so its signatures can never be valid.
   - **After a broadcast the coins are not given back**: held until the spend has six confirmations, or for a
     day if the call failed without saying whether the transaction got out.
   - **The macaroon** must be mode 600 and baked by `uri:` for exactly the calls used. `signer:generate` is
     not enough of a limit: it also reaches channel and identity keys through `SignOutputRaw`.
4. **Other nodes (LDK, CLN, Eclair, Phoenix) use slice 1's route**: the mutual close's delivery address is
   a vortex-ng address. None exposes the signing slice 2 needs (ldk-server has no PSBT signing). A force
   close there is mixed as an unlabelled coin, with plain `coinjoin`, after the node has swept it.
5. **No unattended spending.** Nothing here watches for closes and CoinJoins by itself. A daemon policy that
   spends money without a person is a separate decision, and mainnet wallets stay refused in the CLI.
6. **An address is never handed out twice.** The wallet lives in memory and learns what is used from the chain,
   so a failed or unconfirmed round's addresses used to come back in the next one, linking the two for good.
   Every address is now written to `<wallet>.claims` (the highest index per pit, mixdepth and chain) before it
   leaves the process, by `coinjoin`, a maker and a joinstr pool alike, and every command starts past them
   (the file is shared with the coin holds of ADR 0006's addendum).

## Consequences

- `vortex-ng-core` gains a pure module with BOLT 3's script shapes. Its vectors are hand-built and spent on
  Core, so Core validates them; they are not yet captures of what LND broadcasts. `--from-lnd` does not depend
  on them (it uses the node's records). Capturing LND's transactions into the tests is still owed.
- The commands print amounts, depths and kinds. Outpoints are shown only with `--outpoints`: a closing
  transaction's id names the channel's funding output, and the same data on a live node is key material.
- A mixed-history wallet is the user's to tidy: `--from-closes` never touches other coins, and says so.
- `Sweep` and a commitment's `to_remote` reach a vortex-ng wallet only when something pays them there
  directly. They are in slice 1 because the detector is shared with slice 2, where an LND wallet's own
  coins are created by exactly these transactions, and because it keeps the labels honest if they do.
- `tools/lnd-itest` runs all of it against a real LND v0.21.8 on regtest: a mutual close, a swept force close,
  one channel left open, and macaroons baked as the README says.
