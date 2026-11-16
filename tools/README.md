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
