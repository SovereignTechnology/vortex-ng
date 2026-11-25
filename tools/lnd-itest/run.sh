#!/usr/bin/env bash
# A CoinJoin spending what real channel closes left in a real LND node's wallet, on regtest
# (crates/vortex-ng-cli/tests/regtest_lnd.rs, set up by drive.py).
#
#   kata-run --net --cwd ~/Projects/vortex-ng -- bash tools/lnd-itest/run.sh
#
# Downloads Bitcoin Core and LND release tarballs and checks each against the SHA256 pinned below. Core's is
# tools/itest/run.sh's; LND's is the one sovtech/lnd-rbitcoin-lab pins, whose fetch verified the release manifest's
# signatures. Those signatures are NOT checked again here. Everything binds to loopback and is thrown away.
# Never point this at a node holding anything: it mines blocks and spends coins.
set -euo pipefail

CORE_VERSION=32.1
CORE_SHA256=61545c17c3120fb7412f896d248b11993af04ec8817aad3649c55b2afb044963
LND_VERSION=v0.21.8-beta
LND_SHA256=4910a14801e10164ca2ea67f5935e2486874331d56bbd0638a68c6158a8e82c9

repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

core="bitcoin-${CORE_VERSION}-x86_64-linux-gnu.tar.gz"
lnd="lnd-linux-amd64-${LND_VERSION}.tar.gz"
curl -fsSL --proto '=https' -o "$work/$core" "https://bitcoincore.org/bin/bitcoin-core-${CORE_VERSION}/${core}"
curl -fsSL --proto '=https' -o "$work/$lnd" \
  "https://github.com/lightningnetwork/lnd/releases/download/${LND_VERSION}/${lnd}"
echo "${CORE_SHA256}  ${work}/${core}" | sha256sum -c - >/dev/null
echo "${LND_SHA256}  ${work}/${lnd}" | sha256sum -c - >/dev/null
tar -xzf "$work/$core" -C "$work"
tar -xzf "$work/$lnd" -C "$work"
mkdir "$work/bin"
for program in bitcoind; do
  found=$(find "$work/bitcoin-${CORE_VERSION}" -type f -name "$program" | head -1)
  [ -x "$found" ] || { echo "no $program in the tarball" >&2; exit 97; }
  cp "$found" "$work/bin/"
done
for program in lnd lncli; do
  found=$(find "$work/lnd-linux-amd64-${LND_VERSION}" -type f -name "$program" | head -1)
  [ -x "$found" ] || { echo "no $program in the tarball" >&2; exit 97; }
  cp "$found" "$work/bin/"
done
"$work/bin/bitcoind" -version | head -1
"$work/bin/lnd" --version

cd "$repo"
status=0
PATH="$work/bin:$PATH" python3 -I tools/lnd-itest/drive.py "$work/run" || status=$?
exit "$status"
