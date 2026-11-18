#!/usr/bin/env bash
# A CoinJoin between vortex-ng and joinmarket-clientserver (the reference implementation) on regtest, over
# JoinMarket's onion directory channel (CHANNEL=onion, the default) or over IRC (CHANNEL=irc).
#
# Run from a vortex-ng checkout in a throwaway VM with the network: it installs packages, fetches
# joinmarket-clientserver at the pinned commit, runs it and a regtest Bitcoin Core, and builds vortex-ng from
# this tree.
#
#   kata-run --net --cwd <vortex-ng checkout> -- bash tools/ref-interop/run.sh
#   CHANNEL=irc IRCD=ngircd kata-run --net --cwd <vortex-ng checkout> -- bash tools/ref-interop/run.sh
#
# The reference runs as its own regtest tests run it (ref_bot.py): network `testnet` on a regtest node, and on
# the onion channel its testing mode, where its bots serve and connect over plain TCP on loopback (no Tor). Its
# directory node is one of its bots that never offers anything; vortex-ng meets it there, with `testnet` in the
# handshake. With CHANNEL=irc everyone meets in #joinmarket-pit-test on a local IRC server: IRCD=miniircd (the
# default; the reference's own test server, which announces no NETWORK, so the signature domain is host and
# port) or IRCD=ngircd (Debian's, announcing NETWORK=VortexRefTest).
#
# Two rounds:
#   A. two reference makers (YieldGeneratorBasic, sw0reloffer) and a vortex-ng taker, which does a sw0 round
#      with them and checks it on the node (crates/vortex-ng-node/tests/jmng_interop.rs, role taker);
#   B. two vortex-ng makers and the reference's taker, which does a round with them and asks them to broadcast
#      it (`!push`, tx_broadcast = not-self); vortex-ng then checks the transaction and its makers' wallets.
# Fidelity bonds are not used yet (BONDS=0 on the vortex-ng side).
set -euo pipefail

REF_REPO=https://github.com/JoinMarket-Org/joinmarket-clientserver.git
REF_COMMIT=77a426c504cbf6fa56ba0316dfd8da63a76d2bbf  # v0.9.12, docs/upstream-pins.md
# What the reference's install.sh builds (v0.9.12 install.sh: libsecp256k1_install).
SECP_VERSION=0.5.0
SECP_SHA256=07934fde88c677abbc4d42c36ef7ef8d3850cd0c065e4f976f66f4f97502c95a
# The reference's own IRC test server (v0.9.12 test/run_tests.sh).
MINIIRCD_SHA256=ce3a4ddc777343645ccd06ca36233b5777e218ee89d887ef529ece86a917fc33
CORE_VERSION=32.1
CORE_SHA256=61545c17c3120fb7412f896d248b11993af04ec8817aad3649c55b2afb044963
PORT=18443
CHANNEL=${CHANNEL:-onion}
IRCD=${IRCD:-miniircd}
DIRECTORY_PORT=18081
IRC_PORT=16667
IRC_NETWORK=VortexRefTest
AMOUNT=1000000  # crates/vortex-ng-node/tests/jmng_interop.rs AMOUNT
case "$CHANNEL" in onion|irc) ;; *) echo "CHANNEL=$CHANNEL: onion or irc" >&2; exit 97 ;; esac
case "$IRCD" in miniircd|ngircd) ;; *) echo "IRCD=$IRCD: miniircd or ngircd" >&2; exit 97 ;; esac
label=$CHANNEL
[ "$CHANNEL" = irc ] && label="irc, $IRCD"

here=$(cd "$(dirname "$0")" && pwd)
tree=$(cd "$here/../.." && pwd)
[ -f "$tree/crates/vortex-ng-node/tests/jmng_interop.rs" ] || { echo "run from a vortex-ng checkout" >&2; exit 97; }
work=$(mktemp -d)
logs=$work/logs
mkdir -p "$logs" "$work/a" "$work/b" "$work/core" "$work/bots"
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

export DEBIAN_FRONTEND=noninteractive
packages=(python3 python3-venv python3-dev build-essential autoconf automake libtool pkg-config libffi-dev
  libssl-dev libsodium23 git curl ca-certificates)
[ "$CHANNEL" = irc ] && [ "$IRCD" = ngircd ] && packages+=(ngircd)
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends "${packages[@]}" >/dev/null 2>&1

# joinmarket-clientserver at the pin, in a venv, with libsecp256k1 where its jmbitcoin looks for it.
git clone -q "$REF_REPO" "$work/ref"
git -C "$work/ref" -c advice.detachedHead=false checkout -q "$REF_COMMIT"
[ "$(git -C "$work/ref" rev-parse HEAD)" = "$REF_COMMIT" ] || { echo "the reference is not at the pin" >&2; exit 97; }
python3 -m venv "$work/venv"
fetch "https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v$SECP_VERSION.tar.gz" "$SECP_SHA256" "$work/secp.tar.gz"
tar -xzf "$work/secp.tar.gz" -C "$work"
(cd "$work/secp256k1-$SECP_VERSION" && ./autogen.sh && ./configure --enable-module-recovery --prefix "$work/venv" \
  --enable-experimental --enable-module-ecdh --enable-benchmark=no && make -j"$(nproc)" && make install) \
  >"$logs/secp.log" 2>&1 || { show "$logs/secp.log" 30; exit 11; }
# shellcheck disable=SC1091
. "$work/venv/bin/activate"
# The reference pins its direct dependencies exactly (pyproject.toml); it ships no hashes.
pip install -q --disable-pip-version-check "$work/ref[services]" >"$logs/pip.log" 2>&1 || { show "$logs/pip.log" 30; exit 11; }
echo "joinmarket-clientserver $(git -C "$work/ref" describe --tags 2>/dev/null || true) ($REF_COMMIT), $(python3 --version)"

# vortex-ng from this tree; the test is built before anything starts.
(cd "$tree" && cargo test --locked -p vortex-ng-node --test jmng_interop --no-run >"$logs/build.log" 2>&1) \
  || { show "$logs/build.log" 30; exit 12; }
echo "vortex-ng $(git -C "$tree" rev-parse --short=12 HEAD 2>/dev/null || echo "${VORTEX_NG_COMMIT:-tree}") built"

# Bitcoin Core on regtest, loopback only, with a funding wallet and one watch-only wallet per reference bot.
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
for bot in directory maker1 maker2 taker; do
  cli -named createwallet wallet_name="jm-$bot" disable_private_keys=true blank=true descriptors=true >/dev/null
done
echo "bitcoind $("$bin/bitcoind" -version | head -1) at height $(cli getblockcount)"

# A reference bot: role, name, index (its daemon port and, on onion, its serving port), extra env.
bot_pid=
start_bot() {
  local role=$1 name=$2 index=$3; shift 3
  local seed
  seed=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
  env "$@" REF_RPC_PORT="$PORT" REF_COOKIE="$cookie" REF_WALLET="jm-$name" REF_SEED="$seed" REF_CHANNEL="$CHANNEL" \
    REF_DIRECTORY="127.0.0.1:$DIRECTORY_PORT" REF_SERVE_PORT=$((DIRECTORY_PORT + index)) REF_INDEX="$index" \
    REF_IRC="127.0.0.1:$IRC_PORT" \
    python3 "$here/ref_bot.py" "$role" "$name" "$work/bots/$name" "$work/bots" >"$logs/$name.log" 2>&1 &
  bot_pid=$!
  pids+=("$bot_pid")
}
# Fund a bot once it has named its address: one coin of 1 BTC, two confirmations.
fund_bot() {
  local name=$1 address
  for _ in $(seq 1 180); do [ -s "$work/bots/$name.address" ] && break; sleep 1; done
  address=$(head -1 "$work/bots/$name.address" 2>/dev/null || true)
  case "$address" in bcrt1*) ;; *) echo "$name named no regtest address"; show "$logs/$name.log" 40; return 1 ;; esac
  cli -rpcwallet=funder sendtoaddress "$address" 1.0 >/dev/null
  cli generatetoaddress 2 "$funder" >/dev/null
  touch "$work/bots/$name.funded"
}

# Where everyone meets.
meet_env=()
if [ "$CHANNEL" = onion ]; then
  start_bot directory directory 0
  for _ in $(seq 1 120); do (exec 3<>/dev/tcp/127.0.0.1/$DIRECTORY_PORT) 2>/dev/null && break; sleep 1; done
  (exec 3<>/dev/tcp/127.0.0.1/$DIRECTORY_PORT) 2>/dev/null || { show "$logs/directory.log" 40; exit 26; }
  echo "the reference's directory node on 127.0.0.1:$DIRECTORY_PORT"
  meet_env=("VORTEX_NG_INTEROP_DIRECTORY=127.0.0.1:$DIRECTORY_PORT" VORTEX_NG_INTEROP_ONION_NETWORK=testnet)
else
  if [ "$IRCD" = ngircd ]; then
    cat >"$work/ngircd.conf" <<EOF
[Global]
Name = irc.vortex.test
Info = vortex-ng reference interop
Network = $IRC_NETWORK
Listen = 127.0.0.1
Ports = $IRC_PORT
ServerUID = 65534
ServerGID = 65534
[Limits]
MaxNickLength = 30
[Options]
PAM = no
Ident = no
DNS = no
EOF
    ngircd -n -f "$work/ngircd.conf" >"$logs/ircd.log" 2>&1 &
    meet_env=("VORTEX_NG_INTEROP_IRC=127.0.0.1:$IRC_PORT" "VORTEX_NG_INTEROP_IRC_NETWORK=$IRC_NETWORK")
  else
    fetch https://github.com/JoinMarket-Org/miniircd/archive/master.tar.gz "$MINIIRCD_SHA256" "$work/miniircd.tar.gz"
    mkdir -p "$work/miniircd"
    tar -xzf "$work/miniircd.tar.gz" -C "$work/miniircd" --strip-components=1
    python3 "$work/miniircd/miniircd" --listen=127.0.0.1 --ports="$IRC_PORT" >"$logs/ircd.log" 2>&1 &
    meet_env=("VORTEX_NG_INTEROP_IRC=127.0.0.1:$IRC_PORT")
  fi
  pids+=($!)
  for _ in $(seq 1 60); do (exec 3<>/dev/tcp/127.0.0.1/$IRC_PORT) 2>/dev/null && break; sleep 1; done
  (exec 3<>/dev/tcp/127.0.0.1/$IRC_PORT) 2>/dev/null || { show "$logs/ircd.log" 30; exit 26; }
  echo "$IRCD on 127.0.0.1:$IRC_PORT"
fi

# The vortex-ng side of a round. Returns once its chain work is done (it writes relay.url).
vortex_pid=
start_vortex() {  # $1 = role, $2 = its directory
  (cd "$tree" && env "${meet_env[@]}" VORTEX_NG_INTEROP_ROLE="$1" VORTEX_NG_INTEROP_DIR="$2" VORTEX_NG_INTEROP_BONDS=0 \
    VORTEX_NG_INTEROP_PIT=sw0 VORTEX_NG_INTEROP_MAKERS=2 VORTEX_NG_REGTEST_RPC="http://127.0.0.1:$PORT" \
    VORTEX_NG_REGTEST_COOKIE="$cookie" \
    cargo test --locked -p vortex-ng-node --test jmng_interop -- --nocapture >"$logs/vortex-$1.log" 2>&1) &
  vortex_pid=$!
  pids+=("$vortex_pid")
  for _ in $(seq 1 600); do [ -s "$2/relay.url" ] && break; kill -0 "$vortex_pid" 2>/dev/null || break; sleep 1; done
  [ -s "$2/relay.url" ] || { echo "vortex-ng ($1) did not get ready"; show "$logs/vortex-$1.log" 40; return 1; }
}
report() { grep -E 'IRC server at|directory at|IRC signature domain|answered on the|maker .* nick|taker nick|CoinJoin .* confirmed|panicked|failed|test result' "$1" | cut -c1-400 || true; }
bot_report() {  # what a reference bot said that matters
  grep -E -i 'offerlist=|txid|hp2|rejected|refus|invalid|Traceback|Error|giving up|Signature|Handshake' "$logs/$1.log" \
    | grep -v -E 'DEBUG.*(tick|sync)' | tail -n "$2" | cut -c1-300 || true
}

# ---- A: reference makers, vortex-ng taker ------------------------------------------------------------------
rc_a=0
start_vortex taker "$work/a" || rc_a=22
maker_pids=()
if [ "$rc_a" -eq 0 ]; then
  for i in 1 2; do
    start_bot maker "maker$i" "$i"
    maker_pids+=("$bot_pid")
    fund_bot "maker$i" || rc_a=24
  done
  while [ "$rc_a" -eq 0 ] && kill -0 "$vortex_pid" 2>/dev/null; do
    for p in "${maker_pids[@]}"; do
      kill -0 "$p" 2>/dev/null || { echo "a reference maker exited before the round"; kill "$vortex_pid" 2>/dev/null || true; rc_a=25; }
    done
    sleep 2
  done
  wait "$vortex_pid" || { rc=$?; [ "$rc_a" -ne 0 ] || rc_a=$rc; }
fi
echo "== A ($label): vortex-ng taker with reference makers (exit $rc_a)"
report "$logs/vortex-taker.log"
for n in 1 2; do echo "-- maker$n"; bot_report "maker$n" 12; done
if [ "$rc_a" -ne 0 ]; then
  show "$logs/vortex-taker.log" 40
  for n in 1 2; do show "$logs/maker$n.log" 60; done
else
  echo "txid $(cat "$work/a/taker.txid") at height $(cli getblockcount)"
fi
for p in "${maker_pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done

# ---- B: vortex-ng makers, reference taker ------------------------------------------------------------------
rc_b=0
start_vortex makers "$work/b" || rc_b=22
txid=
if [ "$rc_b" -eq 0 ]; then
  sleep 10  # the makers join and announce their offers right after relay.url is written
  start_bot taker taker 3 REF_AMOUNT="$AMOUNT" REF_MAKERS=2 REF_BROADCAST=not-self
  taker_pid=$bot_pid
  fund_bot taker || rc_b=24
  if [ "$rc_b" -eq 0 ]; then
    # The reference's taker stops once it sees the transaction on the node.
    for _ in $(seq 1 900); do kill -0 "$taker_pid" 2>/dev/null || break; sleep 1; done
    kill "$taker_pid" 2>/dev/null || true
    wait "$taker_pid" 2>/dev/null || true
    txid=$(sed -n 's/^REF_TXID=//p' "$logs/taker.log" | tail -1)
  fi
  if [ "$rc_b" -eq 0 ] && [ -n "$txid" ] && [ "$txid" != None ]; then
    for _ in $(seq 1 60); do cli getmempoolentry "$txid" >/dev/null 2>&1 && break; sleep 1; done
    cli getmempoolentry "$txid" >/dev/null 2>&1 || echo "WARNING: $txid is not in the mempool"
    cli generatetoaddress 1 "$funder" >/dev/null
    printf '%s' "$txid" >"$work/b/jmng.txid.tmp" && mv "$work/b/jmng.txid.tmp" "$work/b/jmng.txid"
    wait "$vortex_pid" || rc_b=$?
  else
    [ "$rc_b" -ne 0 ] || rc_b=23
    kill "$vortex_pid" 2>/dev/null || true
  fi
fi
echo "== B ($label): reference taker with vortex-ng makers (exit $rc_b)"
report "$logs/vortex-makers.log"
echo "-- taker"; bot_report taker 20
if [ "$rc_b" -ne 0 ]; then
  show "$logs/taker.log" 80
  show "$logs/vortex-makers.log" 30
else
  echo "txid $txid at height $(cli getblockcount)"
fi

if [ "$CHANNEL" = onion ]; then
  echo "-- directory"; bot_report directory 10
  [ "$rc_a" -eq 0 ] && [ "$rc_b" -eq 0 ] || show "$logs/directory.log" 40
else
  [ "$rc_a" -eq 0 ] && [ "$rc_b" -eq 0 ] || show "$logs/ircd.log" 20
fi
[ "$rc_a" -eq 0 ] && [ "$rc_b" -eq 0 ] && { echo "== both directions passed"; exit 0; }
exit 1
