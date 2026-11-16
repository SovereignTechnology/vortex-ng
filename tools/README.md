# tools

- `ref-vectors/ref.py`: an independent, stdlib-only Python implementation used to produce the test vectors
  pinned in `vortex-ng-core` (PoDLE with joinmarket-ng's deterministic nonces, Bitcoin Signed Message ECDSA,
  the JMP-0010 taproot PoDLE secret). It reads nothing from joinmarket-ng; it re-implements the algorithms.
  Run: `python3 -I tools/ref-vectors/ref.py`.
- `jmng-vectors/`: the same vectors produced by joinmarket-ng's own `jmcore` at the pinned commit, in a
  throwaway VM (it downloads and runs upstream code). **Run 2026-11-10** (Kata, agentrun, jmcore at
  `c3312cb`, Python 3.11.2): its 4 PoDLE proofs and 3 signatures are byte-identical to `ref-vectors` and to the
  vectors pinned in `vortex-ng-core`; its J_2 NUMS point is pinned too.
- `itest/run.sh`: whole CoinJoins against a real regtest node, so consensus code judges what vortex-ng signs
  (`crates/vortex-ng-node/tests/regtest.rs`; without its two environment variables that test skips itself).
  For `sw0`, `tr0` and `wsh0`: two bonded makers and a taker are funded by mined coinbases, sync from the node's
  blocks, run a round over an in-process relay with the node as chain backend; the transaction must pass
  `testmempoolaccept`, confirm, and appear in every wallet, and a copy with one signature byte flipped must be
  refused. The script downloads Bitcoin Core 32.1 and checks the tarball's SHA256 against the value pinned in
  the script (from the release's `SHA256SUMS`; the builders' signatures over that file are not checked), then
  runs bitcoind on loopback with no wallet and no P2P in a throwaway directory.
  Run: `kata-run --net --cwd ~/Projects/vortex-ng -- bash tools/itest/run.sh`.
  **Run 2026-11-15** (Kata, agentrun, Bitcoin Core v32.1.0): all three pits confirmed on the first run, and the
  node refused each flipped-signature copy.
- `ref-vectors/joinstr_lsag.py`: an independent, stdlib-only Python implementation of joinstr's linkable ring
  signature (the recovery round, ADR 0006), written from the algorithm and reading nothing from joinstr. It
  produces the vectors pinned in `vortex-ng-joinstr::lsag`; with vortex-ng's derived nonces the two give the
  same bytes. Run: `python3 -I tools/ref-vectors/joinstr_lsag.py`.
- `joinstr-difffuzz-adapter/`: vortex-ng as an implementation in joinstr's differential fuzzer (its README).
- `joinstr-difffuzz/run.sh`: runs joinstr-difffuzz, the joinstr v1 differential fuzzer, with vortex-ng as one
  more implementation, in a throwaway VM (it installs packages and runs upstream code: py-joinstr, the joinstr
  web GUI and rust-joinstr at the revisions the harness pins, and a regtest Bitcoin Core 32.1). The harness is
  checked out at the commit in `docs/upstream-pins.md` and is not patched: `drive.py` adds vortex-ng's adapter
  (`joinstr-difffuzz-adapter/`) to its implementation table in memory, replays `corpus/regress` and prints every
  group's result where vortex-ng stands alone or crashes. `CASES=300 SEED=1` adds a fresh campaign. The Electrum
  plugin, joinstr-kmp, Sparrow and floresta are not installed, so cases that need them are skipped.
  Run: `kata-run --net --cwd ~/Projects/vortex-ng -- bash tools/joinstr-difffuzz/run.sh`.
  **Run 2026-11-16** (Kata, agentrun; harness `e44b7647`, joinstr `d1290d6c`, rust-joinstr `b3a41fca`; pycli,
  pyweb, rust, vortex): of the 200 recorded cases 149 apply; 88 agree, 61 diverge (the reference clients'
  documented differences), no crash. vortex-ng stood alone in 5: three refuse the old `"type": "create"`
  announcement (as joinstr-kmp and floresta do), one accepts a nine-decimal denomination with the Python
  clients' value (it differs only in printing the fee rate as `1.0`), and one refused `"vpn_gateway": null`,
  which vortex-ng now reads as unused, as the reference clients do.
  A fresh campaign the same day (`CASES=200 SEED=20261116`): 16 distinct divergences, no crash. vortex-ng stood
  alone in two, both documented differences: the old `"type": "create"` again, and a join request sent from the
  pool's own key, which the harness's rules say a creator does not answer (joinstr-kmp and floresta refuse it too).
  In the other 14 it sides with rust-joinstr (10) or the Python clients (4).
- `jmng-interop/run.sh`: a CoinJoin between a vortex-ng taker and joinmarket-ng's makers over the Nostr message
  channel, on regtest, run from a joinmarket-ng checkout that has the channel (its header says how). It starts
  Bitcoin Core 32.1 with a wallet, funds and starts joinmarket-ng's two test makers with the relay as their only
  message channel, and runs `crates/vortex-ng-node/tests/jmng_interop.rs` (the relay and the taker) at a pinned
  vortex-ng commit.
  **Run 2026-11-16, first attempt** (vortex-ng `ac2064b`): offers, the private orderbook answers, `!fill`,
  `!pubkey`, `!auth` (joinmarket-ng verified vortex-ng's PoDLE) and `!ioauth` crossed the relay; vortex-ng then
  refused the makers' `!ioauth` signature. That was a vortex-ng bug (it expected the signature over the taker's
  NaCl key; JoinMarket signs the maker's own), fixed in the commit that added this note.
