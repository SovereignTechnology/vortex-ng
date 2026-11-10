# Upstream pins

vortex-ng implements JoinMarket's protocol as these revisions specify and implement it. Interop tests run
against exactly these. Moving a pin is a deliberate change: read the upstream diff, update the affected spec
references and test vectors, and record the reason below.

| what | revision | date | why it is pinned |
|---|---|---|---|
| `joinmarket-ng/jmp` main (JMP-0001 base protocol, JMP-0002…0005) | `9b9483ef4bb90b66fcacd269325d8120256eab27` | 2026-08-28 | the base protocol (`sw0`) |
| `joinmarket-ng/jmp` branch `jmp-taproot-ring-market` (JMP-0010…0014, draft, JMP PR #8) | `2f20ac5d97fb2f054efd66819c06b56d659daf10` | 2026-09-26 | `tr0`, channel rings, credential market |
| `joinmarket-ng/joinmarket-ng` main | `c3312cb4ede6de89bd36a1d5b26786905ffc210f` (release 0.43.0) | 2026-11-05 | `sw0` behaviour and test vectors |
| `joinmarket-ng/joinmarket-ng` PR #643 head (`feat/taproot-pit-ring-market`, draft) | `606765ba3efa3bcda9f3c5b271da684ac48a3c8a` | 2026-10-27 | `tr0` and rings as implemented; where code and JMP drafts differ, both are noted in our specs |
| `joinmarket-ng/joinmarket-ng` branch `nostr` (offer PoC) | `f9a99b342e6011b594c7a6c152ea1cf05fd6bc0d` | 2025-12-06 | kind 31402 offer events |
| `JoinMarket-Org/joinmarket-clientserver` release | `v0.9.12` | 2026-04-21 | the reference implementation's behaviour |

## Lightning implementations (external-funding behaviour checked 2026-11-09)

| implementation | version | notes |
|---|---|---|
| LND | 0.21.x (latest 0.21.6-beta) | psbt_shim + `psbt_verify{skip_finalize}`; `TAPROOT=7` channels (private only) |
| Core Lightning | 26.06.x | `fundchannel_start/complete/cancel`; no taproot channels |
| LDK | 0.2.x | `unsafe_manual_funding_transaction_generated`; no taproot channels |
| Eclair | 0.14.x | no external funding API; taproot channels as the remote peer |
| ldk-node | 0.7.x | no external funding API |

## History

- 2026-11-09: initial pins (M0).
