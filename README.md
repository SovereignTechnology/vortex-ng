# vortex-ng

JoinMarket's coinjoin protocol over Nostr, beside JoinMarket's own onion directories and IRC, with Lightning
channel opens, in Rust.

vortex-ng is the successor to [LnVortex](https://github.com/ln-vortex/ln-vortex) (archived 2022), rebuilt
around JoinMarket's maker/taker market instead of a central coordinator:

- **JoinMarket semantics, Nostr transport.** The protocol layer (commands, NaCl sessions, PoDLE, fidelity
  bonds, per-pit transaction rules, maker and taker checks) follows JMP-0001 and the JMP extensions exactly.
  The message channel is Nostr relays. No coordinator.
- **Beside JoinMarket's own channels (in progress, ADR 0007).** The onion directory nodes and IRC that
  joinmarket-clientserver and JoinMarket-NG use, at the same time as Nostr, so vortex-ng shares their market;
  then a bridge for clients without Tor. Tracked in issue #33.
- **Three pits.** `sw0` (P2WPKH, JMP-0001), `tr0` (taproot, JMP-0010), and `wsh0` (P2WSH 2-of-2, shaped
  exactly like a Lightning funding output; draft in this repo).
- **Lightning channel opens inside the coinjoin.** A taker's equal-amount output can be the funding output of
  a taproot channel (in `tr0`) or a regular channel (in `wsh0`); makers see an ordinary output of the pit's
  type. LND, Core Lightning and LDK can open; any implementation can be the peer.
- **Upstreamable by construction.** Every protocol piece JoinMarket lacks is written as a JMP draft
  (`docs/jmp/`) for [joinmarket-ng](https://github.com/joinmarket-ng/joinmarket-ng) to adopt.

**Status: pre-release. CoinJoins work on regtest, over Nostr, and interoperate there with JoinMarket-NG. It is
unaudited: mainnet wallets are refused. Do not use it with real funds.**

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
| `vortex-ng-channel` | The message-channel trait the drivers run over (Nostr today; onion directories and IRC next) |
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
vortex-ng orderbook --network <network> where [--pit sw0|tr0|wsh0] [--wait <seconds>] [node]
vortex-ng maker     --wallet <file> where node (--fee-rel <fraction> | --fee-abs <sats>)
                    [--pit sw0|tr0|wsh0] [--txfee <sats>] [--min-size <sats>] [--max-size <sats>]
                    [--upkeep <seconds>]
vortex-ng coinjoin  --wallet <file> where node --amount <sats> [--makers <n>]
                    [--min-makers <n>] [--mixdepth 0-4] [--destination <address>] [--pit sw0|tr0|wsh0]
                    [--fee-rate <sat/vB>] [--max-maker-fee <sats>] [--wait <seconds>]
                    [--allow-bondless-fees] [--yes]
vortex-ng balance   --wallet <file> node [--pit sw0|tr0|wsh0]
```

`where` is any of `--relays <url[,url...]>` (Nostr relays), `--directories <host:port[,...]>` (JoinMarket's
onion directory nodes) and `--irc <host:port[,...]>` (JoinMarket's IRC pit, as joinmarket-clientserver uses it);
the last two are regtest only in this pre-release (ADR 0007). On several channels at once a maker uses one nick on
all of them and a taker a different nick on each; a peer stays on the channel it first spoke on. An IRC server
whose signature domain (its `NETWORK` name) could be mistaken for another channel's is refused.

What each channel shows, and to whom (ADR 0007 has the reasons):

| channel | its operator sees | others on it see |
|---|---|---|
| Nostr relays | the recipient key and timing of private messages; public messages | offers, `!orderbook`, `!hp2` |
| onion directory nodes (vortex-ng never serves an onion yet, so they relay its private messages) | every private line's sender, recipient, size and timing; the encrypted steps stay encrypted, but `!fill` (order id, amount, commitment) and `!pubkey` are plain text | offers, `!orderbook`, `!hp2`; a nick's presence |
| an IRC server | everything a directory node sees, in its own logs | the same as on the directories |

A maker's single nick, and the nick key its private lines carry, link its presence on all its channels, as in
JoinMarket. A taker's nicks differ per channel. Outside regtest the onion directories and IRC will need a Tor
daemon's SOCKS port (`--proxy`).

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
- By default `coinjoin` needs every maker it asked for. With `--min-makers <n>` it leaves out a maker that fails
  or does not answer within 60 seconds and goes on with at least `n`, up to the moment the transaction goes out;
  after that every maker in it has to sign. Fewer makers is a smaller anonymity set, and another maker in the
  round, or whoever carries the lines, can get an honest maker left out, so `n` is also how far they could thin
  out a round.
- Every PoDLE commitment sent is first written to `<wallet>.podle` (the public value makers broadcast, one
  per line): a commitment is spent even by a round that fails, and each coin has three.
- `orderbook` lists what the makers answer, with the channel each answered on, and verifies their fidelity
  bonds when given a node.
- `orderbook`, `maker` and `coinjoin` take `--proxy <address>`: a SOCKS5 proxy that isolates streams by
  username and password, such as a Tor daemon's SOCKS port (`127.0.0.1:9050`). Every nick then reaches the
  relays under credentials of its own, so Tor gives it circuits of its own: a maker and the throwaway nick it
  sends `!hp2` from share nothing. Relay names are resolved by the proxy, never on this machine. A proxy that
  takes no credentials could not keep nicks apart and is refused. **Without `--proxy` the relays see this
  machine's address**, and the command says so when it starts. In-process Tor (arti, feature `tor` of
  `vortex-ng-nostr`) is not wired into the commands yet.

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
