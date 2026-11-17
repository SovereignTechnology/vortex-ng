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

## Command line

`vortex-ng` has the wallet commands, `orderbook`, `maker`, `coinjoin` and `balance`.

```
vortex-ng wallet new          --wallet <file> --network <network> [--words 12|24] [--birthday <height>]
vortex-ng wallet restore      --wallet <file> --network <network> [--mnemonic-file <file>]
                              [--bip39-passphrase | --bip39-passphrase-file <file>] [--birthday <height>]
vortex-ng wallet info         --wallet <file>
vortex-ng wallet addresses    --wallet <file> [--pit sw0|tr0|wsh0] [--mixdepth 0-4] [--count <n>] [--change]
vortex-ng wallet bond-address --wallet <file> --locktime <YYYY-MM>
vortex-ng orderbook --network <network> --relays <url[,url...]> [--pit sw0|tr0|wsh0] [--wait <seconds>] [node]
vortex-ng maker     --wallet <file> --relays <url[,url...]> node (--fee-rel <fraction> | --fee-abs <sats>)
                    [--pit sw0|tr0|wsh0] [--txfee <sats>] [--min-size <sats>] [--max-size <sats>]
                    [--upkeep <seconds>]
vortex-ng coinjoin  --wallet <file> --relays <url[,url...]> node --amount <sats> [--makers <n>]
                    [--mixdepth 0-4] [--destination <address>] [--pit sw0|tr0|wsh0]
                    [--fee-rate <sat/vB>] [--max-maker-fee <sats>] [--wait <seconds>]
                    [--allow-bondless-fees] [--yes]
vortex-ng balance   --wallet <file> node [--pit sw0|tr0|wsh0]
```

`node` is `--rpc-url <url>` with `--rpc-cookie-file <file>` (or `--rpc-user <name>` and
`--rpc-password-file <file>`): a Bitcoin Core compatible node on the wallet's network.

- The wallet file holds the seed words encrypted under a password (Argon2id, AES-256-GCM-SIV; the format is
  in `crates/vortex-ng-wallet/src/file.rs`). It is created with mode 0600 and never overwritten.
- Passwords and seed words are asked on the terminal without echo, or read from a file only its owner can
  read (`--password-file`, `--mnemonic-file`). They are never taken from the command line or the environment.
- Networks: `regtest`, `signet`, `testnet4`, `testnet`. Mainnet wallets are refused in this pre-release.
- The words restore in joinmarket-ng too: same derivation paths (see `vortex-ng-wallet`).
- `maker` runs until stopped. Every `--upkeep` seconds (30 by default) it brings the wallet up to the chain's
  tip and sizes its one offer to what the wallet can put into a round; it renews its announcement before it
  expires and withdraws it when there is too little to offer. Coins the node already shows as spent are
  never put into a round.
- `coinjoin` does one CoinJoin as the taker, from one mixdepth to the next mixdepth of the same wallet or to
  `--destination`. It merges no more coins than the round needs, bounds each maker's fee (0.1 % of the amount
  and at least 2,000 sat unless `--max-maker-fee` says otherwise), takes makers without a fidelity bond only
  at a zero fee unless `--allow-bondless-fees`, shows what it is about to do and asks before sending anything
  (`--yes` skips the question). The transaction is checked with the node before it is broadcast.
- Every PoDLE commitment sent is first written to `<wallet>.podle` (the public value makers broadcast, one
  per line): a commitment is spent even by a round that fails, and each coin has three.
- `orderbook` lists what the makers on the relays answer, and verifies their fidelity bonds when given a node.
- **No Tor yet in `orderbook`, `maker` and `coinjoin`**: they connect to the relays directly, so the relays see the machine's
  address, and they say so when they start. The Tor transport exists in `vortex-ng-nostr` and is wired in next.

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
