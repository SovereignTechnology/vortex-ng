#!/usr/bin/env bash
# Generate cross-implementation test vectors with joinmarket-ng's own jmcore, at the pinned commit
# (docs/upstream-pins.md). Run it in a throwaway VM, never on a workstation: it installs packages.
#   kata-run --net --cwd <vortex-ng> -- bash tools/jmng-vectors/run.sh
set -euo pipefail
SHA=c3312cb4ede6de89bd36a1d5b26786905ffc210f
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends python3 python3-venv libsecp256k1-1 git ca-certificates >/dev/null
python3 -m venv "$work/venv"
# shellcheck disable=SC1091
. "$work/venv/bin/activate"
git clone -q --filter=blob:none https://github.com/joinmarket-ng/joinmarket-ng "$work/jmng"
git -C "$work/jmng" -c advice.detachedHead=false checkout -q "$SHA"
pip install -q --disable-pip-version-check --require-hashes -r "$work/jmng/jmcore/requirements.txt"
pip install -q --disable-pip-version-check --no-deps "$work/jmng/jmcore"
echo "jmng=$(git -C "$work/jmng" rev-parse HEAD) python=$(python3 --version)"
python3 -I "$here/vectors.py"
