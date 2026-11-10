# tools

- `ref-vectors/ref.py`: an independent, stdlib-only Python implementation used to produce the test vectors
  pinned in `vortex-ng-core` (PoDLE with joinmarket-ng's deterministic nonces, Bitcoin Signed Message ECDSA,
  the JMP-0010 taproot PoDLE secret). It reads nothing from joinmarket-ng; it re-implements the algorithms.
  Run: `python3 -I tools/ref-vectors/ref.py`.
- `jmng-vectors/`: the same vectors produced by joinmarket-ng's own `jmcore` at the pinned commit, in a
  throwaway VM (it downloads and runs upstream code). **Run 2026-11-10** (Kata, agentrun, jmcore at
  `c3312cb`, Python 3.11.2): its 4 PoDLE proofs and 3 signatures are byte-identical to `ref-vectors` and to the
  vectors pinned in `vortex-ng-core`; its J_2 NUMS point is pinned too.
