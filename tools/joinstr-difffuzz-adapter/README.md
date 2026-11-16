# joinstr-difffuzz adapter

`joinstr-difffuzz` (gitlab.com/invincible-privacy/joinstr-difffuzz) feeds the same pool announcements,
credentials, registrations and coins to every joinstr implementation and records where they disagree. This
binary makes vortex-ng one of them. It speaks the harness's adapter protocol (`driver/PROTOCOL.md` at the
revision in `docs/upstream-pins.md`): one JSON request per line on stdin, one JSON reply per line on stdout,
after a first line `{"ready": [ops]}`.

Every op of the protocol (20) calls `vortex-ng-joinstr` directly; nothing is re-implemented here, and no
network is used.

To add it to a checkout of the harness, build this binary and register it in `driver/run.py` beside the
others, with the command `path/to/vortex-ng-joinstr-difffuzz`:

```sh
cargo build --release -p vortex-ng-joinstr-difffuzz
python3 -m driver.run --impls plugin,pycli,pyweb,kmp,floresta,rust,sparrow,vortex --replay corpus/regress
```

vortex-ng reaches relays over Tor only, so it refuses `vpn` pools: a documented difference it shares with
joinstr-kmp and floresta.
