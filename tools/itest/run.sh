#!/usr/bin/env bash
# Run the regtest tests (crates/vortex-ng-node/tests/regtest.rs for JoinMarket rounds, regtest_joinstr.rs
# for joinstr pools) against a pinned Bitcoin Core.
#
#   kata-run --net --cwd ~/Projects/vortex-ng -- bash tools/itest/run.sh
#
# Downloads the release tarball, checks it against the SHA256 pinned below (taken from the release's
# SHA256SUMS on bitcoincore.org; the builders' signatures over that file are NOT checked here), starts
# bitcoind on regtest bound to loopback with no wallet and no P2P, runs the test, and stops the node.
# Never point this at anything but a throwaway regtest node: the test mines blocks.
set -euo pipefail

VERSION=32.1
SHA256=61545c17c3120fb7412f896d248b11993af04ec8817aad3649c55b2afb044963
TARBALL="bitcoin-${VERSION}-x86_64-linux-gnu.tar.gz"
PORT=${VORTEX_NG_REGTEST_PORT:-18443}

repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
pid=
cleanup() {
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then kill "$pid"; wait "$pid" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

curl -fsSL -o "$work/$TARBALL" "https://bitcoincore.org/bin/bitcoin-core-${VERSION}/${TARBALL}"
echo "${SHA256}  ${work}/${TARBALL}" | sha256sum -c - >/dev/null
tar -xzf "$work/$TARBALL" -C "$work"
bitcoind=$(find "$work/bitcoin-${VERSION}" -type f -name bitcoind | head -1)
[ -x "$bitcoind" ] || { echo "no bitcoind in the tarball" >&2; exit 97; }
echo "bitcoind: $("$bitcoind" -version | head -1) (sha256 of the tarball verified)"

mkdir "$work/data"
"$bitcoind" -regtest -datadir="$work/data" -listen=0 -dnsseed=0 -disablewallet \
  -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcport="$PORT" -printtoconsole=0 &
pid=$!
cookie="$work/data/regtest/.cookie"
for _ in $(seq 1 60); do [ -s "$cookie" ] && break; sleep 1; done
[ -s "$cookie" ] || { echo "bitcoind did not start" >&2; exit 97; }

cd "$repo"
VORTEX_NG_REGTEST_RPC="http://127.0.0.1:${PORT}" VORTEX_NG_REGTEST_COOKIE="$cookie" \
  cargo test --locked -p vortex-ng-node --test regtest --test regtest_joinstr -- --nocapture
