# 5. Chain backend: Core-compatible JSON-RPC

Date: 2026-11-09

## Status

Accepted

## Context

Makers and takers must look up counterparties' UTXOs (`gettxout`), broadcast, estimate fees and sync their
wallets. JoinMarket uses Bitcoin Core (joinmarket-ng also Neutrino). rbitcoin, an all-Rust node maintained by
the same people as vortex-ng, is meant to serve Core's RPC.

## Decision

- `vortex-ng-chain` speaks Core-compatible JSON-RPC: `getblockchaininfo`, `gettxout`, `getrawtransaction`,
  `sendrawtransaction`, `estimatesmartfee`, `getblockhash`, `getblock`, and `testmempoolaccept`.
- Bitcoin Core and rbitcoin are both supported targets; integration tests run against both on regtest.
- rust-bitcoin is pinned to rbitcoin's `bitcoin = "=0.32.102"` so types and behaviour match.
- Esplora/Electrum backends are later and optional.

## Consequences

- M0 checked rbitcoin's RPC coverage of that list (2026-11-09, rbitcoin `06bc71404`): every method is present
  in `crates/rbitcoin-rpc`, plus `getblockfilter` for later compact-filter sync. That is a source check; M2's
  regtest integration tests are the behavioural proof. Gaps found then become issues or PRs on rbitcoin, not
  workarounds here.
