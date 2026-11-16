#!/usr/bin/env bash
# Run joinstr-difffuzz (the joinstr v1 differential fuzzer) with vortex-ng as one more implementation.
#
#   kata-run --net --cwd ~/Projects/vortex-ng -- bash tools/joinstr-difffuzz/run.sh
#   IMPLS=pycli,pyweb,rust,vortex CASES=300 SEED=1 ... run.sh     # also a fresh campaign
#
# In a throwaway VM only: it installs packages and runs upstream code (py-joinstr, the joinstr web GUI,
# rust-joinstr, at the revisions the harness pins as submodules) and a regtest Bitcoin Core. The harness
# is checked out at the commit in docs/upstream-pins.md and is not patched: drive.py adds vortex-ng to
# its implementation table in memory. Electrum, joinstr-kmp, Sparrow and floresta are not installed, so
# those four implementations are left out by default.
set -euo pipefail

DIFFFUZZ=e44b7647f823fbf5e40f18461f0ecf464720d782
CORE_VERSION=32.1
CORE_SHA256=61545c17c3120fb7412f896d248b11993af04ec8817aad3649c55b2afb044963
IMPLS=${IMPLS:-pycli,pyweb,rust,vortex}
CASES=${CASES:-0}
SEED=${SEED:-1}

repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
cleanup() {
  if [ -d "$work/difffuzz" ]; then (cd "$work/difffuzz" && sh e2e/core.sh stop >/dev/null 2>&1) || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends python3 python3-venv python3-dev git ca-certificates curl \
  build-essential pkg-config libssl-dev >/dev/null 2>&1

cd "$repo"
cargo build --release --locked -p vortex-ng-joinstr-difffuzz >"$work/build-vortex.log" 2>&1 \
  || { tail -30 "$work/build-vortex.log"; exit 12; }
adapter="$repo/target/release/vortex-ng-joinstr-difffuzz"
[ -x "$adapter" ] || { echo "no adapter binary" >&2; exit 12; }

git clone -q https://gitlab.com/invincible-privacy/joinstr-difffuzz.git "$work/difffuzz"
cd "$work/difffuzz"
git -c advice.detachedHead=false checkout -q "$DIFFFUZZ"
[ "$(git rev-parse HEAD)" = "$DIFFFUZZ" ] || { echo "harness is not at the pin" >&2; exit 97; }
git submodule update -q --init targets/joinstr targets/rust-joinstr
echo "harness $DIFFFUZZ; targets: $(git submodule status targets/joinstr targets/rust-joinstr | awk '{print $2"@"substr($1,1,12)}' | tr '\n' ' ')"

python3 -m venv "$work/venv"
# shellcheck disable=SC1091
. "$work/venv/bin/activate"
pip install -q --disable-pip-version-check embit -r targets/joinstr/cli/requirements.txt \
  -r targets/joinstr/gui/requirements.txt >"$work/pip.log" 2>&1 || { tail -20 "$work/pip.log"; exit 21; }

tarball="bitcoin-${CORE_VERSION}-x86_64-linux-gnu.tar.gz"
curl -fsSL -o "$work/$tarball" "https://bitcoincore.org/bin/bitcoin-core-${CORE_VERSION}/${tarball}"
echo "${CORE_SHA256}  ${work}/${tarball}" | sha256sum -c - >/dev/null
tar -xzf "$work/$tarball" -C "$work"
PATH="$(dirname "$(find "$work/bitcoin-${CORE_VERSION}" -type f -name bitcoind | head -1)"):$PATH"
export PATH
sh e2e/core.sh start

case ",$IMPLS," in *,rust,*)
  (cd adapters/rust && cargo build --release -q >"$work/build-rust.log" 2>&1) \
    || { tail -30 "$work/build-rust.log"; exit 13; } ;;
esac

echo "python=$(python3 --version) impls=$IMPLS"
echo "== replay corpus/regress"
rc=0
python3 "$repo/tools/joinstr-difffuzz/drive.py" "$adapter" "$IMPLS" replay corpus/regress || rc=$?
if [ "$CASES" -gt 0 ]; then
  echo "== fresh campaign: $CASES cases, seed $SEED"
  python3 "$repo/tools/joinstr-difffuzz/drive.py" "$adapter" "$IMPLS" campaign "$CASES" "$SEED" || rc=$?
  for f in findings/*.json; do
    git ls-files --error-unmatch "$f" >/dev/null 2>&1 && continue
    echo "== new finding $f"; head -c 3000 "$f"; echo
  done
fi
echo "== adapter logs (last lines)"
for l in .run/logs/*.log; do echo "-- $l"; tail -5 "$l" | cut -c1-300; done
exit "$rc"
