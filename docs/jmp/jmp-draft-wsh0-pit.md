---
jmp: TBD
title: P2WSH 2-of-2 CoinJoin Pit (wsh0)
author: sovtech
status: Draft
type: Standards Track
layer: Extension
created: 2026-11-09
requires: 0001
---

## Abstract

This specification defines the `wsh0` CoinJoin pit, following the pattern of JMP-0010 (`tr0`). Every input and
output of a `wsh0` transaction is a P2WSH output whose witness script is a sorted 2-of-2 multisig, the script
BOLT 3 uses for Lightning channel funding. Wallet coins in this pit are 2-of-2s whose two keys both belong to the
wallet, so a regular (non-taproot) Lightning channel funding output is indistinguishable from every other
output of the round, both when created and when later spent with two signatures.

## Motivation

A regular Lightning channel is funded by a P2WSH `2 <key1> <key2> 2 OP_CHECKMULTISIG` output. Inside an `sw0`
round it is the only P2WSH among P2WPKH outputs and marks its owner. JMP-0010 gives taproot channels a pit where
they blend; Core Lightning, LDK and most deployed channels are not taproot. LnVortex made every output in its
Lightning rounds P2WSH for this reason. `wsh0` does the same within JoinMarket's market, and goes further: by
making wallet coins 2-of-2s too, the funding output and the wallet outputs share one witness script template,
so they also look alike when spent.

## Specification

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119.

### The wsh0 script

A `wsh0` script is exactly:

```text
OP_2 <33-byte key K1> <33-byte key K2> OP_2 OP_CHECKMULTISIG
```

with `K1` and `K2` compressed public keys and `K1` lexicographically less than `K2` (BOLT 3 funding script; a
descriptor `sortedmulti(2, …)`). Its output is P2WSH: `OP_0 <SHA256(script)>`. Its 71-byte length is fixed.

### Offer Types

The following JMP-0001 public offer grammars are added:

```text
wsh0reloffer = "!wsh0reloffer" SP oid SP minsize SP maxsize SP txfee SP relfee
wsh0absoffer = "!wsh0absoffer" SP oid SP minsize SP maxsize SP txfee SP absfee
```

Fields have the JMP-0001 grammar and meaning, as in JMP-0010 "Offer Types". A taker selects only `wsh0` offers
for a `wsh0` CoinJoin. A maker MUST NOT accept a `!fill` for a `wsh0` offer unless it can meet every requirement
here.

### Output Policy

Every participant MUST provide its equal output and, when it has change, its change output as a P2WSH output
(`OP_0 <32-byte program>`). A participant's own outputs MUST be P2WSH of a `wsh0` script. Every participant MUST
verify that every output of the transaction is P2WSH before signing and MUST reject a transaction with any other
output script type. (Other participants' witness scripts are hidden until spent, so only the P2WSH form is
checkable.)

### Input Policy

Every input MUST spend a P2WSH output whose witness script is a `wsh0` script, with the witness of "Transaction
Signing" below. Before signing, every participant MUST verify that every input's prevout scriptPubKey is P2WSH
and MUST reject a transaction otherwise. The taker MUST verify each maker's witness script and signatures
before assembling the transaction, and MUST spend its own inputs the same way. `wsh0` never mixes with `sw0` or
`tr0` inputs.

### Wallet Derivation

A `wsh0` wallet coin is a `wsh0` script of two keys the wallet holds, derived from the wallet's seed on BIP48
script type 2 (native segwit multisig), using two accounts per mixdepth `m`:

```text
K_a = m/48'/coin'/(2m)'/2'/chain/index
K_b = m/48'/coin'/(2m+1)'/2'/chain/index
descriptor: wsh(sortedmulti(2, [fp/48'/coin'/(2m)'/2']xpub_a/<0;1>/*, [fp/48'/coin'/(2m+1)'/2']xpub_b/<0;1>/*))
```

`chain` is 0 for external and 1 for internal addresses, as in BIP84. Both keys come from the one seed, so no
extra backup is needed, and the descriptor restores in any descriptor wallet. The paths are a proposal open for
review.

### Fidelity Bonds

As JMP-0010 "Fidelity Bonds": `wsh0` defines no new bond. A `wsh0` maker proves its bond with the existing
P2WSH timelocked bond and `!tbond`, on the `sw0` bond path, so one bond weights its offers in every pit.

### PoDLE Binding

The taker's PoDLE commitment (JMP-0001 "PoDLE Algorithm") MAY use either a P2WPKH UTXO, with the unchanged
five-field revelation, or a `wsh0` UTXO. For a `wsh0` UTXO the secret is the private key of one of its two keys,
`P`, and the revelation has six pipe-separated fields:

```text
<utxo>|<P>|<P2>|<sig>|<e>|<C>
```

where `C` is the other key, 33-byte compressed hex. The maker verifies the proof as JMP-0001 specifies and, for
the UTXO binding, that the UTXO's scriptPubKey equals P2WSH of the `wsh0` script of `{P, C}`. The commitment
format, `!fill` and `!hp2` are unchanged. A maker in a `wsh0` round MUST accept both revelation forms and MUST
apply JMP-0001's age and amount requirements to either.

### Authentication (`!ioauth`)

The `!ioauth` fields are unchanged except `auth_pubkey`, which in a `wsh0` round is the 132-character lowercase
hex concatenation of two compressed keys `K_auth || K_cosigner`. `btc_signature` is made with `K_auth` exactly
as in JMP-0001. The taker MUST verify the signature with `K_auth` and that P2WSH of the `wsh0` script of
`{K_auth, K_cosigner}` equals the scriptPubKey of one of the declared UTXOs. `cj_address` and `change_address`
MUST be P2WSH addresses.

### Transaction Signing

Before signing, a participant MUST have the prevout amount and scriptPubKey of each of its own inputs, and MUST
verify the outputs, its amounts and the fee as JMP-0001 and joinmarket-ng's maker checklist require. Signatures
are BIP143 ECDSA with `SIGHASH_ALL`, strict DER and low-S (relay policy rejects high-S signatures, and a
participant could otherwise stall the round with a valid but non-standard signature).

After JMP-0001 encryption is removed, the `!sig` plaintext for one input is:

```text
!sig <base64(push(sig_1) || push(sig_2) || push(witness_script))>
```

each item a minimal script push as in the `sw0` encoding (`CScript([sig]) + CScript(pub)` in the reference
implementation), where `sig_1` and `sig_2` are DER signatures with the sighash byte by the keys `K1` and `K2` in
script order. The taker MUST check that `witness_script` is a `wsh0` script whose P2WSH equals the input's
scriptPubKey and that both signatures verify. The final witness is exactly:

```text
[<empty>, <sig_1>, <sig_2>, <witness_script>]
```

A `wsh0` implementation MUST reject any other witness shape, sighash type, or witness script.

### Fee Sizing

Fee calculation MUST use the actual serialization. A P2WSH output weighs 172 weight units (43 vbytes). A `wsh0`
input weighs 164 weight units of non-witness data plus a witness of at most 222 weight units (item count, empty
item, two signatures of at most 73 bytes with their length bytes, and the 72-byte script push), at most 386
weight units (96.5 vbytes). Implementations MUST NOT apply a P2WPKH estimate to a `wsh0` transaction.

### Liquidity Pools

As JMP-0010 "Liquidity Pools": a maker accounts for `wsh0` liquidity separately, from `wsh0` coins only.

## Backward Compatibility

Implementations that do not recognize `wsh0reloffer` or `wsh0absoffer` ignore them (JMP-0001 implementations
match only known offer names) and never receive a `wsh0` `!fill`, so the six-field revelation, the two-key
`auth_pubkey` and the three-item `!sig` never reach them. Nothing else in JMP-0001 changes.

## Rationale

- **2-of-2 wallet coins** make the pit's own coins share the funding output's script template, so neither
  creation nor a later two-signature spend separates channel outputs from wallet outputs. A 1-of-1 P2WSH would
  match only until spent.
- **BIP48 accounts** give a standard, descriptor-restorable derivation for a 2-of-2 held by one seed.
- **Explicit cosigner keys** in the revelation and `!ioauth` are the minimum extra data needed to bind a key to
  a P2WSH UTXO, since the script is not on chain until spent.

## Security Considerations

- The two keys of a wallet coin are held together; the 2-of-2 adds no security, only uniformity. Losing the
  seed loses both.
- A participant must verify every input's prevout and every output's type before signing; one divergent script
  tags the round.
- Transaction-level patterns still differ between Lightning spends (cooperative closes, commitment
  transactions with their obscured locktime and sequence) and CoinJoin spends; `wsh0` hides which output is a
  channel, not that a round is a JoinMarket round.

## Reference Implementation

- vortex-ng (in development).
- A joinmarket-ng implementation of this pit (planned, offered upstream).
