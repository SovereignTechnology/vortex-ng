# 7. JoinMarket's onion directories and IRC beside Nostr

Date: 2026-11-18

## Status

Accepted. Supersedes ADR 0001's "No IRC, no onion directories, no direct peer sockets" and ADR 0002's
"vortex-ng is all-Rust (no C tor, no onion service), since there are no inbound connections". Everything else
in ADR 0001 and ADR 0002 stands. Work is tracked in GitHub issue #33 (milestone "Legacy channels").

## Context

ADR 0001 chose Nostr as the only message channel and named the cost: until joinmarket-ng ships the Nostr
channel, vortex-ng's market and the live JoinMarket market do not share liquidity. The project owner has now
asked for vortex-ng to work as legacy JoinMarket does, meaning joinmarket-clientserver, with its IRC and onion
directory channels, at the same time as Nostr, and to be able to bridge those channels to Nostr. His
statement of the situation: people still use joinmarket-clientserver.

What the two Python implementations run (code and release notes, not live measurements; nothing in this
project has connected to the live network):

- **joinmarket-clientserver v0.9.12** (2026-04-20, our pin), described in its release notes as "probably the
  final release of this implementation"; the repository is to be archived. Its default configuration runs
  the onion channel with five directory nodes **and** one IRC server, hackint, reached over Tor (`#joinmarket-pit`).
  All configured channels are used at once. Its message-channel code is the same as 0.9.11's, except that a
  received `!hp2` commitment must now be canonical hex before it is stored or announced.
- **JoinMarket-NG** (0.43.0, our pin): onion directories and direct onion connections only; it never
  implemented IRC. Its eight default mainnet directory nodes include the five above, so both implementations
  meet on the same directories.

So a joinmarket-clientserver user on defaults is on the onion directories and on IRC together, and a
JoinMarket-NG user is on the onion directories. No source read gives numbers of makers or volume.

Message channels share JMP-0001's private-message line, `from!to!command body pubkey signature`, signed by
the nick key over `body + hostid`. The `hostid` is `nostr-network` on Nostr, `onion-network` on the onion
directories, and on IRC a value the server announces. The signature covers neither the command nor the
recipient. On Nostr the gift wrap's seal authenticates the sender as well; on the other channels a sender is
only as trustworthy as the directory or server that forwarded the line.

## Decision

1. vortex-ng implements JoinMarket's onion-directory channel and IRC channel, wire-compatible with
   joinmarket-clientserver v0.9.12 and, for the onion channel, with JoinMarket-NG, and runs any combination
   of Nostr, onion directories and IRC at once. Onion directories come first (they reach both
   implementations' users), IRC directly after.
2. **Several channels at once** follows rules of its own rather than joinmarket-clientserver's collection:
   - A maker keeps one nick on every channel, as JoinMarket does. A session belongs to the channel its
     `!fill` arrived on; that nick's lines on other channels are ignored while the session lives.
   - A taker uses a different nick on each channel, so a maker never has to choose which channel to answer on,
     and the taker's channels cannot be linked through its nick.
   - A line is verified against the `hostid` of the channel it arrived on. Routes are learned only from
     verified private lines, never from unsigned public ones. The strict nick check is used everywhere.
3. **No legacy channel is switched on before the maker and taker tolerate stray lines.** A line that verifies
   but does not fit the round (a duplicate, a line re-sent from another exchange) is ignored, never a reason to
   end the round. On channels without sender authentication, a received `!error` is logged, not acted on.
4. **Tor.** The legacy channels reach `.onion` hosts through a Tor daemon's SOCKS port (`--proxy`), each nick
   under its own SOCKS credentials, since the in-process Tor client is built without onion support. Whether
   arti's onion support can replace the daemon is investigated separately (issue #49). A taker connects
   directly to the makers it chose that serve an onion, each connection on a circuit of its own, and falls back
   to directory relay for a maker it cannot reach or whose connection drops (issue #45). A maker can serve
   an onion of its own, the project's first inbound listener (issue #46): published through Tor's control
   port with `SAFECOOKIE` authentication, or one the operator's Tor already forwards to it. Takers of both
   reference implementations reach such a maker directly on regtest. The commands' makers still advertise
   `NOT-SERVING-ONION` and rely on directory relay until a peer on a direct connection can be made to prove
   its nick (issue #52).
5. **IRC's signature domain** comes from the server. vortex-ng takes it once per connection, checks its length
   and characters, compares it with the value configured for that server, and freezes it; a channel whose
   domain could be confused with another active channel's does not start. TLS certificates are checked for
   ordinary host names; onion hosts are reached through Tor. IRC reassembly is bounded in size and time.
6. **Bridge**, after the above: a relay that lets a client without Tor use the onion directories, defined as a
   transport for the unchanged onion channel carried in Nostr gift wraps, specified as a draft in `docs/jmp/`
   and read by the owner before any code is written. Clients that do not implement the transport cannot be
   bridged.
7. **Live networks.** All of this is built and tested on regtest in throwaway VMs, against
   joinmarket-clientserver v0.9.12, JoinMarket-NG and a local IRC server. The public directory nodes, the public
   IRC servers, signet and mainnet are used only on the owner's explicit go. Mainnet wallets stay refused.
8. **Choosing channels.** `orderbook`, `maker` and `coinjoin` take `--relays`, `--directories` and `--irc` side
   by side and need at least one; none is on by default. `--directories` and `--irc` are refused on every
   network but regtest in this pre-release. Outside regtest they also need `--proxy`, a rule the commands
   already check, so it stands when the regtest limit is lifted. `orderbook` shows the channel each offer came
   from. The command help and the README state the table below.

## Consequences

What each channel shows, and to whom:

| channel | the operator sees | others on the channel see |
|---|---|---|
| Nostr (ADR 0002) | the recipient's key and timing of private messages; public messages | offers, `!orderbook`, `!hp2` |
| onion directories, relayed (`NOT-SERVING-ONION`) | every private line's sender, recipient, size and timing; the encrypted steps stay encrypted, but `!fill` (order id, amount, commitment) and `!pubkey` are in clear text | public offers, `!orderbook`, `!hp2`; a nick's presence |
| onion directories, a taker connected directly | that two nicks are in contact (the maker's offer to the taker), none of the taker's round lines; a maker that answers through the directories anyway, as some do, also shows them its answers, `!pubkey` in clear text | the same |
| IRC | everything a directory sees, plus the server's own logs | the same as on onion |

- A maker's single nick, and the nick key's public key that every private line carries, link its presence on
  all its channels. That is JoinMarket's existing behaviour; vortex-ng documents it rather than changing it.
- The legacy channels add a dependency on a Tor daemon for anything beyond regtest, which ADR 0002 avoided.
- The drivers in `vortex-ng-node` become generic over a message channel; Nostr keeps its behaviour and its
  tests.
- The Nostr channel draft's rule that a nick key is used nowhere else now reads: nowhere outside JoinMarket's
  message channels; a maker may use its nick on other JoinMarket channels, a taker should use a different
  nick on each.
