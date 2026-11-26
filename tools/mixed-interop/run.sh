#!/usr/bin/env bash
# One JoinMarket round with makers of three implementations (issue #51): joinmarket-clientserver, JoinMarket-NG
# and vortex-ng, on regtest, over one onion directory node. Each implementation's taker does a round with all
# three makers in turn.
#
# Run from a vortex-ng checkout in a throwaway VM with the network: it installs packages, fetches both other
# implementations at their pins (docs/upstream-pins.md), runs them and a regtest Bitcoin Core, and builds
# vortex-ng from this tree.
#
#   kata-run --net --cwd <vortex-ng checkout> -- bash tools/mixed-interop/run.sh
#
# Where they meet: joinmarket-clientserver's directory node (one of its bots that never offers anything), in
# its testing mode: plain TCP on loopback, no Tor. joinmarket-clientserver runs regtest as `testnet` and its
# directory refuses another network's peers, so everyone says `testnet` in the handshake: JoinMarket-NG with
# NETWORK_CONFIG__NETWORK=testnet on a regtest node (as its own docker-compose does to meet
# joinmarket-clientserver), vortex-ng with VORTEX_NG_INTEROP_ONION_NETWORK=testnet. Every maker serves on
# loopback, so each taker can connect to each maker directly. JoinMarket-NG's directory server is not used:
# it refuses the loopback locations joinmarket-clientserver's makers say in testing mode. Nick
# authentication (JMP-0005) is therefore not exercised here; tools/jmng-interop/run.sh does that.
#
# The makers, one of each, all without fidelity bonds, with fees on JoinMarket-NG's fee grid:
#   joinmarket-clientserver: YieldGeneratorBasic, sw0reloffer 0.0002 (tools/ref-interop/ref_bot.py);
#   JoinMarket-NG: `jm-maker`, sw0reloffer 0.001, its regtest test wallet;
#   vortex-ng: crates/vortex-ng-node/tests/jmng_interop.rs, role makers, one maker, sw0absoffer 500 sat.
# The rounds, each of 1,000,000 sat with three makers:
#   1. joinmarket-clientserver's taker (ref_bot.py; it broadcasts itself);
#   2. JoinMarket-NG's taker (tools/jmng-interop/jmng_taker.py; a random maker broadcasts, `random-peer`);
#   3. vortex-ng's taker (jmng_interop.rs, role taker), which then has a commitment announced and checks
#      that every maker refuses it.
# Each transaction must confirm with four equal outputs (three makers and the taker); with only these three
# makers on the directory, that is one of each. vortex-ng's maker checks the transaction and its own wallet.
set -euo pipefail

REF_REPO=https://github.com/JoinMarket-Org/joinmarket-clientserver.git
REF_COMMIT=77a426c504cbf6fa56ba0316dfd8da63a76d2bbf  # v0.9.12
SECP_VERSION=0.5.0
SECP_SHA256=07934fde88c677abbc4d42c36ef7ef8d3850cd0c065e4f976f66f4f97502c95a
JMNG_REPO=https://github.com/joinmarket-ng/joinmarket-ng.git
JMNG_COMMIT=3dc893bc5a9bb30ae63ffd42c40d7c3456313183  # 0.44.1
CORE_VERSION=32.1
CORE_SHA256=61545c17c3120fb7412f896d248b11993af04ec8817aad3649c55b2afb044963
PORT=18443
DIRECTORY_PORT=18081
JMNG_SERVE_PORT=18091
AMOUNT=1000000  # crates/vortex-ng-node/tests/jmng_interop.rs AMOUNT
# joinmarket-ng's own regtest test wallets (its docker-compose.yml maker1; its e2e taker).
JMNG_MAKER_MNEMONIC="avoid whisper mesh corn already blur sudden fine planet chicken hover sniff"
JMNG_TAKER_MNEMONIC="burden notable love elephant orbit couch message galaxy elevator exile drop toilet"

here=$(cd "$(dirname "$0")" && pwd)
tree=$(cd "$here/../.." && pwd)
[ -f "$tree/crates/vortex-ng-node/tests/jmng_interop.rs" ] || { echo "run from a vortex-ng checkout" >&2; exit 97; }
ref_tools=$tree/tools/ref-interop
jmng_tools=$tree/tools/jmng-interop
work=$(mktemp -d)
logs=$work/logs
mkdir -p "$logs" "$work/core" "$work/bots"
pids=()
bin=
cleanup() {
  if [ -n "$bin" ]; then "$bin/bitcoin-cli" -regtest -datadir="$work/core" -rpcport="$PORT" stop >/dev/null 2>&1 || true; fi
  for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$work" 2>/dev/null || true
}
trap cleanup EXIT
show() { echo "-- $1 (last $2 lines)"; tail -n "$2" "$1" 2>/dev/null | cut -c1-400 || true; }
fetch() {  # url, sha256, destination
  curl -fsSL -o "$3" "$1"
  echo "$2  $3" | sha256sum -c - >/dev/null || { echo "$1: SHA256 differs from the pin" >&2; exit 98; }
}
wait_for_line() {  # file, pattern, seconds: whether the pattern appeared in time
  for _ in $(seq 1 "$3"); do grep -q -E "$2" "$1" 2>/dev/null && return 0; sleep 1; done
  return 1
}

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends python3 python3-venv python3-dev build-essential autoconf automake \
  libtool pkg-config libffi-dev libssl-dev libsodium23 libsecp256k1-1 git curl ca-certificates jq >/dev/null 2>&1

# joinmarket-clientserver at the pin, in a venv of its own, with libsecp256k1 where its jmbitcoin looks for it.
git clone -q "$REF_REPO" "$work/ref"
git -C "$work/ref" -c advice.detachedHead=false checkout -q "$REF_COMMIT"
[ "$(git -C "$work/ref" rev-parse HEAD)" = "$REF_COMMIT" ] || { echo "joinmarket-clientserver is not at the pin" >&2; exit 97; }
python3 -m venv "$work/ref-venv"
fetch "https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v$SECP_VERSION.tar.gz" "$SECP_SHA256" "$work/secp.tar.gz"
tar -xzf "$work/secp.tar.gz" -C "$work"
(cd "$work/secp256k1-$SECP_VERSION" && ./autogen.sh && ./configure --enable-module-recovery --prefix "$work/ref-venv" \
  --enable-experimental --enable-module-ecdh --enable-benchmark=no && make -j"$(nproc)" && make install) \
  >"$logs/secp.log" 2>&1 || { show "$logs/secp.log" 30; exit 11; }
"$work/ref-venv/bin/pip" install -q --disable-pip-version-check "$work/ref[services]" >"$logs/ref-pip.log" 2>&1 \
  || { show "$logs/ref-pip.log" 30; exit 11; }
ref_py=$work/ref-venv/bin/python3
echo "joinmarket-clientserver $(git -C "$work/ref" describe --tags 2>/dev/null || true) ($REF_COMMIT)"

# JoinMarket-NG at the pin, in a venv of its own, with its hash-pinned requirements.
git clone -q "$JMNG_REPO" "$work/jmng"
git -C "$work/jmng" -c advice.detachedHead=false checkout -q "$JMNG_COMMIT"
[ "$(git -C "$work/jmng" rev-parse HEAD)" = "$JMNG_COMMIT" ] || { echo "joinmarket-ng is not at the pin" >&2; exit 97; }
python3 -m venv "$work/jmng-venv"
editable=()
for c in jmcore jmwallet maker taker; do
  "$work/jmng-venv/bin/pip" install -q --disable-pip-version-check --require-hashes -r "$work/jmng/$c/requirements.txt" \
    >>"$logs/jmng-pip.log" 2>&1 || { show "$logs/jmng-pip.log" 30; exit 11; }
  editable+=(-e "$work/jmng/$c")
done
"$work/jmng-venv/bin/pip" install -q --disable-pip-version-check --no-deps "${editable[@]}" >>"$logs/jmng-pip.log" 2>&1 \
  || { show "$logs/jmng-pip.log" 30; exit 11; }
jmng_py=$work/jmng-venv/bin/python3
echo "joinmarket-ng $(git -C "$work/jmng" describe --tags 2>/dev/null || true) ($JMNG_COMMIT), $(python3 --version)"

# vortex-ng from this tree; the test is built before anything starts.
(cd "$tree" && cargo test --locked -p vortex-ng-node --test jmng_interop --no-run >"$logs/build.log" 2>&1) \
  || { show "$logs/build.log" 30; exit 12; }
echo "vortex-ng $(git -C "$tree" rev-parse --short=12 HEAD 2>/dev/null || echo tree) built"

# Bitcoin Core on regtest, loopback only, with a funding wallet and one watch-only wallet per
# joinmarket-clientserver bot.
tarball="bitcoin-${CORE_VERSION}-x86_64-linux-gnu.tar.gz"
fetch "https://bitcoincore.org/bin/bitcoin-core-${CORE_VERSION}/${tarball}" "$CORE_SHA256" "$work/$tarball"
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
for bot in directory refmaker reftaker; do
  cli -named createwallet wallet_name="jm-$bot" disable_private_keys=true blank=true descriptors=true >/dev/null
done
# JoinMarket-NG's wallets, funded at the first address it derives for each: three coins each.
for mnemonic in "$JMNG_MAKER_MNEMONIC" "$JMNG_TAKER_MNEMONIC"; do
  address=$("$jmng_py" "$jmng_tools/jmng_address.py" p2wpkh "$mnemonic" "http://127.0.0.1:$PORT" "$cookie" "$work/derive")
  case "$address" in bcrt1*) ;; *) echo "joinmarket-ng derived no regtest address" >&2; exit 24 ;; esac
  for _ in 1 2 3; do cli -rpcwallet=funder sendtoaddress "$address" 1.0 >/dev/null; done
done
cli generatetoaddress 6 "$funder" >/dev/null
echo "bitcoind $("$bin/bitcoind" -version | head -1) at height $(cli getblockcount)"

# A joinmarket-clientserver bot (tools/ref-interop/ref_bot.py): role, name, index (its daemon and serving
# ports), extra env.
bot_pid=
start_bot() {
  local role=$1 name=$2 index=$3 seed
  shift 3
  seed=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
  env "$@" REF_RPC_PORT="$PORT" REF_COOKIE="$cookie" REF_WALLET="jm-$name" REF_MINE_TO="$funder" REF_SEED="$seed" \
    REF_CHANNEL=onion REF_DIRECTORY="127.0.0.1:$DIRECTORY_PORT" REF_SERVE_PORT=$((DIRECTORY_PORT + index)) \
    REF_INDEX="$index" "$ref_py" "$ref_tools/ref_bot.py" "$role" "$name" "$work/bots/$name" "$work/bots" \
    >"$logs/$name.log" 2>&1 &
  bot_pid=$!
  pids+=("$bot_pid")
}
fund_bot() {  # name, coins of 1 BTC; six confirmations after
  local name=$1 coins=$2 address
  for _ in $(seq 1 180); do [ -s "$work/bots/$name.address" ] && break; sleep 1; done
  address=$(head -1 "$work/bots/$name.address" 2>/dev/null || true)
  case "$address" in bcrt1*) ;; *) echo "$name named no regtest address"; show "$logs/$name.log" 40; return 1 ;; esac
  for _ in $(seq 1 "$coins"); do cli -rpcwallet=funder sendtoaddress "$address" 1.0 >/dev/null; done
  cli generatetoaddress 6 "$funder" >/dev/null
  touch "$work/bots/$name.funded"
}

# ---- The directory and the two long-running makers ----------------------------------------------------------
start_bot directory directory 0
for _ in $(seq 1 120); do (exec 3<>/dev/tcp/127.0.0.1/$DIRECTORY_PORT) 2>/dev/null && break; sleep 1; done
(exec 3<>/dev/tcp/127.0.0.1/$DIRECTORY_PORT) 2>/dev/null || { show "$logs/directory.log" 40; exit 26; }
echo "joinmarket-clientserver's directory node on 127.0.0.1:$DIRECTORY_PORT (network testnet)"

start_bot maker refmaker 1
refmaker_pid=$bot_pid
fund_bot refmaker 3 || exit 24

mkdir -p "$work/jmng-maker"
env HOME="$work/jmng-maker" JOINMARKET_DATA_DIR="$work/jmng-maker/.joinmarket-ng" MNEMONIC="$JMNG_MAKER_MNEMONIC" \
  NETWORK_CONFIG__NETWORK=testnet NETWORK_CONFIG__BITCOIN_NETWORK=regtest NETWORK_CONFIG__ALLOW_CLEARNET_CONNECTIONS=true \
  DIRECTORY_SERVERS="127.0.0.1:$DIRECTORY_PORT" TOR__CONTROL_ENABLED=false \
  MAKER__ONION_HOST=127.0.0.1 MAKER__ONION_SERVING_HOST=127.0.0.1 MAKER__ONION_SERVING_PORT="$JMNG_SERVE_PORT" \
  BITCOIN__BACKEND_TYPE=descriptor_wallet BITCOIN__RPC_URL="http://127.0.0.1:$PORT" BITCOIN__RPC_COOKIE_FILE="$cookie" \
  LOGGING__LEVEL=DEBUG MAKER__MIN_SIZE=10000 MAKER__TX_FEE_CONTRIBUTION=500 MAKER__CJ_FEE_RELATIVE=0.001 \
  "$work/jmng-venv/bin/jm-maker" start >"$logs/jmng-maker.log" 2>&1 &
jmng_maker_pid=$!
pids+=("$jmng_maker_pid")

wait_for_line "$logs/jmng-maker.log" 'Created offer' 300 || { echo "joinmarket-ng's maker made no offer"; show "$logs/jmng-maker.log" 60; exit 25; }
echo "joinmarket-ng's maker: $(grep -E 'Created offer' "$logs/jmng-maker.log" | tail -1 | grep -o 'type=[a-z0-9]*' || true)"
wait_for_line "$logs/refmaker.log" 'offerlist=' 300 || echo "WARNING: joinmarket-clientserver's maker logged no offer list yet"
echo "joinmarket-clientserver's maker: $(grep -o -E "'ordertype': '[a-z0-9]*'" "$logs/refmaker.log" | tail -1 || true)"

# The vortex-ng side of a round: one maker (role makers) or the taker (role taker), meeting on the directory.
vortex_pid=
start_vortex() {  # role, its directory, then NAME=value settings of its own
  local role=$1 dir=$2
  shift 2
  mkdir -p "$dir"
  (cd "$tree" && env "$@" VORTEX_NG_INTEROP_ROLE="$role" VORTEX_NG_INTEROP_DIR="$dir" VORTEX_NG_INTEROP_BONDS=0 \
    VORTEX_NG_INTEROP_PIT=sw0 VORTEX_NG_INTEROP_DIRECTORY="127.0.0.1:$DIRECTORY_PORT" \
    VORTEX_NG_INTEROP_ONION_NETWORK=testnet VORTEX_NG_INTEROP_SERVE=loopback \
    VORTEX_NG_REGTEST_RPC="http://127.0.0.1:$PORT" VORTEX_NG_REGTEST_COOKIE="$cookie" \
    cargo test --locked -p vortex-ng-node --test jmng_interop -- --nocapture >"$logs/vortex-$(basename "$dir").log" 2>&1) &
  vortex_pid=$!
  pids+=("$vortex_pid")
  for _ in $(seq 1 600); do [ -s "$dir/relay.url" ] && break; kill -0 "$vortex_pid" 2>/dev/null || break; sleep 1; done
  [ -s "$dir/relay.url" ] || { echo "vortex-ng ($role) did not get ready"; show "$logs/vortex-$(basename "$dir").log" 40; return 1; }
}
report() { grep -E 'directory at|maker .* nick|taker nick|CoinJoin .* confirmed|Commitment announced|answered !error|refuses|panicked|failed|test result' "$1" | cut -c1-400 || true; }
# The round's transaction on the node: its inputs, and its outputs of the round's amount.
describe() {
  cli getrawtransaction "$1" 1 | jq -r --argjson amount "$AMOUNT" \
    '"\(.vin | length) inputs, \([.vout[] | select((.value * 1e8 | round) == $amount)] | length) outputs of \($amount) sat, \(.vout | length) outputs in all"'
}
# Whether the long-running makers are still up.
makers_up() {
  kill -0 "$refmaker_pid" 2>/dev/null || { echo "joinmarket-clientserver's maker exited"; show "$logs/refmaker.log" 40; return 1; }
  kill -0 "$jmng_maker_pid" 2>/dev/null || { echo "joinmarket-ng's maker exited"; show "$logs/jmng-maker.log" 40; return 1; }
}
# GRACE_SECS: our maker takes a commitment it has heard announced for 2 seconds, not 5 minutes, so that the
# taker's check that every maker refuses one, 5 seconds after the announcement, holds for it too.
our_maker=(VORTEX_NG_INTEROP_MAKERS=1 VORTEX_NG_INTEROP_ROUND_MAKERS=3 VORTEX_NG_INTEROP_GRACE_SECS=2)
# Hand the round's txid to vortex-ng's maker, which checks the transaction and its wallet, and wait for it.
our_maker_checks() {  # its directory, txid
  printf '%s' "$2" >"$1/jmng.txid.tmp" && mv "$1/jmng.txid.tmp" "$1/jmng.txid"
  wait "$vortex_pid"
}

# ---- 1: joinmarket-clientserver's taker ---------------------------------------------------------------------
rc_1=0
txid_1=
makers_up || rc_1=25
[ "$rc_1" -ne 0 ] || start_vortex makers "$work/r1" "${our_maker[@]}" || rc_1=22
if [ "$rc_1" -eq 0 ]; then
  sleep 10  # our maker announces its offer right after relay.url is written
  start_bot taker reftaker 4 REF_AMOUNT="$AMOUNT" REF_MAKERS=3 REF_BROADCAST=self
  reftaker_pid=$bot_pid
  fund_bot reftaker 1 || rc_1=24
  if [ "$rc_1" -eq 0 ]; then
    for _ in $(seq 1 900); do kill -0 "$reftaker_pid" 2>/dev/null || break; sleep 1; done
    kill "$reftaker_pid" 2>/dev/null || true
    wait "$reftaker_pid" 2>/dev/null || true
    txid_1=$(sed -n 's/^REF_TXID=//p' "$logs/reftaker.log" | tail -1)
  fi
  if [ "$rc_1" -eq 0 ] && [ -n "$txid_1" ] && [ "$txid_1" != None ]; then
    for _ in $(seq 1 60); do cli getmempoolentry "$txid_1" >/dev/null 2>&1 && break; sleep 1; done
    cli generatetoaddress 1 "$funder" >/dev/null
    our_maker_checks "$work/r1" "$txid_1" || rc_1=$?
  else
    [ "$rc_1" -ne 0 ] || rc_1=23
    kill "$vortex_pid" 2>/dev/null || true
  fi
fi
echo "== 1: joinmarket-clientserver's taker with makers of all three (exit $rc_1)"
report "$logs/vortex-r1.log"
if [ "$rc_1" -eq 0 ]; then
  echo "txid $txid_1: $(describe "$txid_1")"
else
  show "$logs/reftaker.log" 80; show "$logs/vortex-r1.log" 30
fi
cli generatetoaddress 6 "$funder" >/dev/null  # everyone's change and outputs confirmed for the next round

# ---- 2: JoinMarket-NG's taker -------------------------------------------------------------------------------
rc_2=0
txid_2=
makers_up || rc_2=25
[ "$rc_2" -ne 0 ] || start_vortex makers "$work/r2" "${our_maker[@]}" || rc_2=22
if [ "$rc_2" -eq 0 ]; then
  sleep 10
  env HOME="$work/jmng-taker" JMNG_TAKER_MNEMONIC="$JMNG_TAKER_MNEMONIC" JMNG_NETWORK=testnet JMNG_MAKERS=3 \
    JMNG_BROADCAST=random-peer "$jmng_py" "$jmng_tools/jmng_taker.py" "127.0.0.1:$DIRECTORY_PORT" \
    "http://127.0.0.1:$PORT" "$cookie" "$work/jmng-taker/.joinmarket-ng" 0 sw0 >"$logs/jmng-taker.log" 2>&1 || rc_2=$?
  txid_2=$(sed -n 's/^JMNG_TXID=//p' "$logs/jmng-taker.log" | tail -1)
  if [ "$rc_2" -eq 0 ] && [ -n "$txid_2" ] && [ "$txid_2" != None ]; then
    for _ in $(seq 1 60); do cli getmempoolentry "$txid_2" >/dev/null 2>&1 && break; sleep 1; done
    cli getmempoolentry "$txid_2" >/dev/null 2>&1 || echo "WARNING: $txid_2 is not in the mempool"
    cli generatetoaddress 1 "$funder" >/dev/null
    our_maker_checks "$work/r2" "$txid_2" || rc_2=$?
  else
    [ "$rc_2" -ne 0 ] || rc_2=23
    kill "$vortex_pid" 2>/dev/null || true
  fi
fi
echo "== 2: joinmarket-ng's taker with makers of all three (exit $rc_2)"
report "$logs/vortex-r2.log"
if [ "$rc_2" -eq 0 ]; then
  echo "txid $txid_2: $(describe "$txid_2")"
else
  grep -v -E 'utxo_metadata|wallet\.sync|history_reconstruction' "$logs/jmng-taker.log" | tail -n 70 | cut -c1-400 || true
  show "$logs/vortex-r2.log" 30
fi
cli generatetoaddress 6 "$funder" >/dev/null

# ---- 3: vortex-ng's taker -----------------------------------------------------------------------------------
rc_3=0
txid_3=
makers_up || rc_3=25
[ "$rc_3" -ne 0 ] || start_vortex makers "$work/r3" "${our_maker[@]}" || rc_3=22
maker_3=$vortex_pid
if [ "$rc_3" -eq 0 ]; then
  sleep 10
  # It waits for three answering makers, runs the round, then checks that a commitment one of its makers
  # announces is refused by every maker in the round.
  start_vortex taker "$work/r3t" VORTEX_NG_INTEROP_MAKERS=3 || rc_3=22
  taker_3=$vortex_pid
  if [ "$rc_3" -eq 0 ]; then
    while kill -0 "$taker_3" 2>/dev/null; do makers_up || { kill "$taker_3" 2>/dev/null || true; rc_3=25; }; sleep 2; done
    wait "$taker_3" || { rc=$?; [ "$rc_3" -ne 0 ] || rc_3=$rc; }
  fi
  txid_3=$(cat "$work/r3t/taker.txid" 2>/dev/null || true)
  if [ -n "$txid_3" ]; then
    vortex_pid=$maker_3
    our_maker_checks "$work/r3" "$txid_3" || { rc=$?; [ "$rc_3" -ne 0 ] || rc_3=$rc; }
  else
    [ "$rc_3" -ne 0 ] || rc_3=23
    kill "$maker_3" 2>/dev/null || true
  fi
fi
echo "== 3: vortex-ng's taker with makers of all three (exit $rc_3)"
report "$logs/vortex-r3t.log"
report "$logs/vortex-r3.log"
if [ "$rc_3" -eq 0 ]; then
  echo "txid $txid_3: $(describe "$txid_3")"
else
  show "$logs/vortex-r3t.log" 40; show "$logs/vortex-r3.log" 30
fi

# What each long-running maker said about the rounds.
echo "-- joinmarket-clientserver's maker"
grep -E -i 'txid|hp2|rejected|refus|Traceback|Error' "$logs/refmaker.log" | grep -v -E 'DEBUG.*(tick|sync)' | tail -n 12 | cut -c1-300 || true
echo "-- joinmarket-ng's maker"
grep -E -i 'coinjoin|broadcast|hp2|refus|reject|Traceback|ERROR' "$logs/jmng-maker.log" | grep -v -E 'utxo_metadata|wallet\.sync' | tail -n 16 | cut -c1-300 || true
if [ "$rc_1" -ne 0 ] || [ "$rc_2" -ne 0 ] || [ "$rc_3" -ne 0 ]; then
  show "$logs/refmaker.log" 50; show "$logs/jmng-maker.log" 60; show "$logs/directory.log" 30
  exit 1
fi
echo "== all three takers completed a round with makers of all three implementations"
