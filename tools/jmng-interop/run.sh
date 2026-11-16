#!/usr/bin/env bash
# A CoinJoin between vortex-ng and joinmarket-ng over the Nostr message channel, on regtest.
#
# Run from a joinmarket-ng checkout that has the Nostr channel (jmcore.nostr), in a throwaway VM: it
# installs packages, runs joinmarket-ng and a regtest Bitcoin Core, and builds vortex-ng at the given commit.
#
#   cp -r ~/Projects/vortex-ng/tools/jmng-interop <joinmarket-ng checkout>/.interop
#   VORTEX_NG_COMMIT=<sha> kata-run --net --cwd <joinmarket-ng checkout> -- bash .interop/run.sh
#
# What happens: Bitcoin Core 32.1 (tarball checked against the pinned SHA256) on regtest with a wallet;
# joinmarket-ng's test wallets are funded at the addresses its own scripts/fund-test-wallets.sh uses. Then two
# rounds, each on a relay run by vortex-ng's test crates/vortex-ng-node/tests/jmng_interop.rs:
#   A. joinmarket-ng's two test makers (`jm-maker start`, Core's wallet backend, the relay as their only
#      message channel) and a vortex-ng taker, which does a sw0 round with them and checks it on the node;
#   B. two vortex-ng makers and joinmarket-ng's taker (jmng_taker.py, through joinmarket-ng's own API),
#      which does a sw0 round with them; vortex-ng then checks the transaction and its makers' wallets.
set -euo pipefail

VORTEX_NG_REPO=https://github.com/SovereignTechnology/vortex-ng.git
VORTEX_NG_COMMIT=${VORTEX_NG_COMMIT:?set VORTEX_NG_COMMIT to the vortex-ng commit to test}
CORE_VERSION=32.1
CORE_SHA256=61545c17c3120fb7412f896d248b11993af04ec8817aad3649c55b2afb044963
PORT=18443
# joinmarket-ng's own regtest test wallets (docker-compose.yml maker1, maker2; scripts/fund-test-wallets.sh).
MAKER_MNEMONICS=(
  "avoid whisper mesh corn already blur sudden fine planet chicken hover sniff"
  "minute faint grape plate stock mercy tent world space opera apple rocket"
)
MAKER_ADDRESSES=(
  bcrt1q6x4xurtda3szpc54knp6qpuh0jxgcjajmnmy89
  bcrt1qfuzpvnf2lgg8z54p3xcjp8xf8x5ydla63tgud2
)
TAKER_ADDRESS=bcrt1q84l5vscg3pvjn6se8jp4ruymtyh393ed5v2d9e

jmng=$(pwd)
here=$(cd "$(dirname "$0")" && pwd)
[ -d "$jmng/jmcore/src/jmcore/nostr" ] || { echo "run from a joinmarket-ng checkout with jmcore.nostr" >&2; exit 97; }
work=$(mktemp -d)
logs=$work/logs
mkdir -p "$logs" "$work/a" "$work/b" "$work/core"
pids=()
bin=
cleanup() {
  # Stop the node before its directory goes: a bitcoind that is still flushing keeps writing into it.
  if [ -n "$bin" ]; then "$bin/bitcoin-cli" -regtest -datadir="$work/core" -rpcport="$PORT" stop >/dev/null 2>&1 || true; fi
  for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$work" 2>/dev/null || true
}
trap cleanup EXIT
show() { echo "-- $1 (last $2 lines)"; tail -n "$2" "$1" 2>/dev/null | cut -c1-400 || true; }

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends python3 python3-venv libsecp256k1-1 git curl ca-certificates \
  build-essential >/dev/null 2>&1

# joinmarket-ng, from this checkout, with its hash-pinned requirements.
python3 -m venv "$work/venv"
# shellcheck disable=SC1091
. "$work/venv/bin/activate"
for c in jmcore jmwallet maker taker; do
  pip install -q --disable-pip-version-check --require-hashes -r "$jmng/$c/requirements.txt"
done
pip install -q --disable-pip-version-check --no-deps -e "$jmng/jmcore" -e "$jmng/jmwallet" -e "$jmng/maker" -e "$jmng/taker"
echo "joinmarket-ng $(git -C "$jmng" rev-parse --short=12 HEAD 2>/dev/null || echo snapshot), $(python3 --version)"

# vortex-ng at the given commit; the test is built before anything starts.
git clone -q "$VORTEX_NG_REPO" "$work/vortex-ng"
git -C "$work/vortex-ng" -c advice.detachedHead=false checkout -q "$VORTEX_NG_COMMIT"
[ "$(git -C "$work/vortex-ng" rev-parse HEAD)" = "$VORTEX_NG_COMMIT" ] || { echo "vortex-ng is not at the pin" >&2; exit 97; }
(cd "$work/vortex-ng" && cargo test --locked -p vortex-ng-node --test jmng_interop --no-run >"$logs/build.log" 2>&1) \
  || { show "$logs/build.log" 30; exit 12; }
echo "vortex-ng $VORTEX_NG_COMMIT built"

# Bitcoin Core on regtest, loopback only, with a wallet (joinmarket-ng's descriptor_wallet backend needs it).
tarball="bitcoin-${CORE_VERSION}-x86_64-linux-gnu.tar.gz"
curl -fsSL -o "$work/$tarball" "https://bitcoincore.org/bin/bitcoin-core-${CORE_VERSION}/${tarball}"
echo "${CORE_SHA256}  ${work}/${tarball}" | sha256sum -c - >/dev/null
tar -xzf "$work/$tarball" -C "$work"
bin=$(dirname "$(find "$work/bitcoin-${CORE_VERSION}" -type f -name bitcoind | head -1)")
"$bin/bitcoind" -regtest -datadir="$work/core" -listen=0 -dnsseed=0 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 \
  -rpcport="$PORT" -fallbackfee=0.0002 -txindex=1 -printtoconsole=0 &
pids+=($!)
cookie=$work/core/regtest/.cookie
cli() { "$bin/bitcoin-cli" -regtest -datadir="$work/core" -rpcport="$PORT" "$@"; }
for _ in $(seq 1 60); do cli getblockcount >/dev/null 2>&1 && break; sleep 1; done
cli getblockcount >/dev/null || { echo "bitcoind did not start" >&2; exit 21; }
cli createwallet funder >/dev/null
funder=$(cli -rpcwallet=funder getnewaddress "" bech32)
cli generatetoaddress 110 "$funder" >/dev/null
for address in "${MAKER_ADDRESSES[@]}" "$TAKER_ADDRESS"; do
  for _ in 1 2 3; do cli -rpcwallet=funder sendtoaddress "$address" 1.0 >/dev/null; done
done
cli generatetoaddress 6 "$funder" >/dev/null
echo "bitcoind $("$bin/bitcoind" -version | head -1) at height $(cli getblockcount); joinmarket-ng wallets funded"

# The vortex-ng side of a round: the relay plus the taker or the makers. Prints the relay URL once it is up.
vortex_pid=
start_vortex() {  # $1 = role, $2 = its directory
  (cd "$work/vortex-ng" && VORTEX_NG_INTEROP_ROLE="$1" VORTEX_NG_INTEROP_DIR="$2" \
    VORTEX_NG_INTEROP_MAKERS=${#MAKER_ADDRESSES[@]} VORTEX_NG_REGTEST_RPC="http://127.0.0.1:$PORT" \
    VORTEX_NG_REGTEST_COOKIE="$cookie" \
    cargo test --locked -p vortex-ng-node --test jmng_interop -- --nocapture >"$logs/vortex-$1.log" 2>&1) &
  vortex_pid=$!
  pids+=("$vortex_pid")
  for _ in $(seq 1 300); do [ -s "$2/relay.url" ] && break; kill -0 "$vortex_pid" 2>/dev/null || break; sleep 1; done
  [ -s "$2/relay.url" ] || { echo "vortex-ng ($1) did not start its relay"; show "$logs/vortex-$1.log" 40; return 1; }
}
report() { grep -E 'relay at|maker .* (announced|nick)|taker nick|CoinJoin .* confirmed|panicked|failed|test result|refuses' "$1" | cut -c1-400 || true; }

# ---- A: joinmarket-ng makers, vortex-ng taker ------------------------------------------------------------
rc_a=0
start_vortex taker "$work/a" || rc_a=22
maker_pids=()
if [ "$rc_a" -eq 0 ]; then
  relay=$(cat "$work/a/relay.url")
  i=0
  for mnemonic in "${MAKER_MNEMONICS[@]}"; do
    i=$((i + 1))
    home=$work/maker$i
    mkdir -p "$home"
    HOME="$home" JOINMARKET_DATA_DIR="$home/.joinmarket-ng" MNEMONIC="$mnemonic" \
      NETWORK_CONFIG__NETWORK=regtest NETWORK_CONFIG__BITCOIN_NETWORK=regtest \
      NETWORK_CONFIG__ALLOW_CLEARNET_CONNECTIONS=true DIRECTORY_SERVERS="nostr:$relay" \
      BITCOIN__BACKEND_TYPE=descriptor_wallet BITCOIN__RPC_URL="http://127.0.0.1:$PORT" \
      BITCOIN__RPC_COOKIE_FILE="$cookie" TOR__CONTROL_ENABLED=false LOGGING__LEVEL=DEBUG \
      MAKER__MIN_SIZE=10000 MAKER__TX_FEE_CONTRIBUTION=500 MAKER__CJ_FEE_RELATIVE=0.001 \
      jm-maker start >"$logs/maker$i.log" 2>&1 &
    maker_pids+=($!)
    pids+=($!)
  done
  wait "$vortex_pid" || rc_a=$?
fi
echo "== A: vortex-ng taker with joinmarket-ng makers (exit $rc_a)"
report "$logs/vortex-taker.log"
if [ "$rc_a" -ne 0 ]; then
  show "$logs/vortex-taker.log" 40
  for n in 1 2; do show "$logs/maker$n.log" 60; done
else
  echo "txid $(cat "$work/a/taker.txid") at height $(cli getblockcount)"
fi
for p in "${maker_pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done

# ---- B: vortex-ng makers, joinmarket-ng taker ------------------------------------------------------------
rc_b=0
start_vortex makers "$work/b" || rc_b=22
if [ "$rc_b" -eq 0 ]; then
  relay=$(cat "$work/b/relay.url")
  sleep 5  # the makers publish their offers right after the relay URL is written
  HOME="$work/taker" python3 "$here/jmng_taker.py" "$relay" "http://127.0.0.1:$PORT" "$cookie" \
    "$work/taker/.joinmarket-ng" >"$logs/jmng-taker.log" 2>&1 || rc_b=$?
  txid=$(sed -n 's/^JMNG_TXID=//p' "$logs/jmng-taker.log" | tail -1)
  if [ "$rc_b" -eq 0 ] && [ -n "$txid" ] && [ "$txid" != None ]; then
    cli generatetoaddress 1 "$funder" >/dev/null
    printf '%s' "$txid" >"$work/b/jmng.txid.tmp" && mv "$work/b/jmng.txid.tmp" "$work/b/jmng.txid"
    wait "$vortex_pid" || rc_b=$?
  else
    [ "$rc_b" -ne 0 ] || rc_b=23
    kill "$vortex_pid" 2>/dev/null || true
  fi
fi
echo "== B: joinmarket-ng taker with vortex-ng makers (exit $rc_b)"
report "$logs/vortex-makers.log"
if [ "$rc_b" -ne 0 ]; then
  grep -v -E 'utxo_metadata|wallet\.sync|history_reconstruction' "$logs/jmng-taker.log" | tail -n 70 | cut -c1-400 || true
  show "$logs/vortex-makers.log" 30
else
  echo "txid $txid at height $(cli getblockcount)"
fi

[ "$rc_a" -eq 0 ] && [ "$rc_b" -eq 0 ] && { echo "== both directions passed"; exit 0; }
exit 1
