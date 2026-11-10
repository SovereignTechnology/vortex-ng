# vortex-ng

JoinMarket's coinjoin protocol, over Nostr only, with Lightning channel opens, in Rust.

vortex-ng is the successor to [LnVortex](https://github.com/ln-vortex/ln-vortex) (archived 2022), rebuilt
around JoinMarket's maker/taker market instead of a central coordinator:

- **JoinMarket semantics, Nostr transport.** The protocol layer (commands, NaCl sessions, PoDLE, fidelity
  bonds, per-pit transaction rules, maker and taker checks) follows JMP-0001 and the JMP extensions exactly.
  Only the message channel changes: Nostr relays instead of IRC or onion directories. No coordinator.
- **Three pits.** `sw0` (P2WPKH, JMP-0001), `tr0` (taproot, JMP-0010), and `wsh0` (P2WSH 2-of-2, shaped
  exactly like a Lightning funding output; draft in this repo).
- **Lightning channel opens inside the coinjoin.** A taker's equal-amount output can be the funding output of
  a taproot channel (in `tr0`) or a regular channel (in `wsh0`); makers see an ordinary output of the pit's
  type. LND, Core Lightning and LDK can open; any implementation can be the peer.
- **Upstreamable by construction.** Every protocol piece JoinMarket lacks is written as a JMP draft
  (`docs/jmp/`) for [joinmarket-ng](https://github.com/joinmarket-ng/joinmarket-ng) to adopt.

**Status: milestone M0 (bootstrap and specifications). Nothing here moves coins yet. Do not use it on mainnet.**

## Documents

| | |
|---|---|
| `docs/decisions/` | Architecture decision records |
| `docs/jmp/jmp-draft-nostr-message-channel.md` | JoinMarket over Nostr: offers, public and private messages, relays, Tor |
| `docs/jmp/jmp-draft-wsh0-pit.md` | The `wsh0` pit for regular Lightning channel opens |
| `docs/jmp/jmp-draft-channel-funding-outputs.md` | A taker's coinjoin output as a Lightning funding output |
| `docs/upstream-pins.md` | The JoinMarket revisions vortex-ng is compatible with |

## Crates

| crate | role |
|---|---|
| `vortex-ng-core` | Protocol logic with no I/O: codec, nicks, offers, PoDLE, bonds, per-pit rules |
| `vortex-ng-nostr` | The Nostr message channel |
| `vortex-ng-wallet` | JoinMarket-compatible wallet (mixdepths per pit, fidelity bonds) |
| `vortex-ng-chain` | Chain backend over Core-compatible JSON-RPC (Bitcoin Core or rbitcoin) |
| `vortex-ng-ln` | Lightning channel funding (LND, Core Lightning, LDK) |
| `vortex-ng-maker`, `vortex-ng-taker` | The two roles |
| `vortex-ngd`, `vortex-ng-cli` (binary `vortex-ng`) | Daemon and command line |

## Roadmap

M0 bootstrap + specs · M1 core (all pits, PoDLE, bonds, codec, test vectors) · M2 `sw0` over Nostr, interop
with joinmarket-ng · M3 `tr0` · M4 Lightning backends, `wsh0`, channel-funding outputs · M5 tumbler, channel
rings (JMP-0014), credential market (JMP-0012/13) · M6 external funding for Eclair and ldk-node upstream.

## Building

Rust 1.98 (pinned in `rust-toolchain.toml`). `cargo test --workspace`.

## Acknowledgements

vortex-ng exists because of the work it builds on:

- **Ben Carman (benthecarman)** and the [LnVortex](https://github.com/ln-vortex/ln-vortex) contributors, for
  showing that a coinjoin output can be a Lightning channel's funding output, and for the protocol and code
  that made the idea concrete.
- **[JoinMarket-NG](https://github.com/joinmarket-ng/joinmarket-ng)** and its contributors, for a clean,
  well-documented implementation of the JoinMarket protocol, the JMP specifications, and the taproot pit and
  channel-ring designs that vortex-ng follows; and the original
  [JoinMarket](https://github.com/JoinMarket-Org/joinmarket-clientserver) project they build on.

Thank you.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your
option. Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this
work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or
conditions.
