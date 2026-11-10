# tools

- `ref-vectors/ref.py`: an independent, stdlib-only Python implementation used to produce the test vectors
  pinned in `vortex-ng-core` (PoDLE with joinmarket-ng's deterministic nonces, Bitcoin Signed Message ECDSA,
  the JMP-0010 taproot PoDLE secret). It reads nothing from joinmarket-ng; it re-implements the algorithms.
  Run: `python3 -I tools/ref-vectors/ref.py`.
- `jmng-vectors/`: the same vectors produced by joinmarket-ng's own `jmcore` at the pinned commit, in a
  throwaway VM (it downloads and runs upstream code). **Not run yet**; when run, its output must equal the
  vectors pinned in the tests.
