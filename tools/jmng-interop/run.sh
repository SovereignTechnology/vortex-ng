#!/usr/bin/env bash
# A CoinJoin between vortex-ng and joinmarket-ng on regtest, over the Nostr message channel (CHANNEL=nostr, the
# default) or over JoinMarket's onion directory channel (CHANNEL=onion).
#
# Run from a joinmarket-ng checkout in a throwaway VM: it installs packages, runs joinmarket-ng and a regtest
# Bitcoin Core, and builds vortex-ng at the given commit. CHANNEL=nostr needs a checkout with the Nostr channel
# (jmcore.nostr); CHANNEL=onion works with any, and runs joinmarket-ng's own directory server
# (`jm-directory-server`, on loopback, with a JMP-0005 identity so nick authentication is exercised): both sides
# meet there instead of on a relay.
#
#   cp -r ~/Projects/vortex-ng/tools/jmng-interop <joinmarket-ng checkout>/.interop
#   VORTEX_NG_COMMIT=<sha> kata-run --net --cwd <joinmarket-ng checkout> -- bash .interop/run.sh
#
# What happens: Bitcoin Core 32.1 (tarball checked against the pinned SHA256) on regtest with a wallet;
# joinmarket-ng's test wallets are funded at the addresses its own scripts/fund-test-wallets.sh uses. Then two
# rounds, each on a relay run by vortex-ng's test crates/vortex-ng-node/tests/jmng_interop.rs:
#   A. joinmarket-ng's two test makers (`jm-maker start`, Core's wallet backend, the relay as their only
#      message channel) and a vortex-ng taker, which does a sw0 round with them and checks it on the node;
#      then a vortex-ng maker announces a commitment, and both joinmarket-ng makers must refuse it;
# PIT=sw0 (the default) or PIT=tr0 picks the pit both sides trade in; tr0 needs a joinmarket-ng checkout that
# has the Taproot pit (its PR #643) under the Nostr channel.
# With BONDS=1 (the default) every maker holds a fidelity bond and each taker runs joinmarket-ng's default
# policy (a maker that charges a fee is chosen only if its bond verifies), so each side must verify the other's
# `!tbond` proofs; BONDS=0 turns bonds and that rule off.
#   B. two vortex-ng makers and joinmarket-ng's taker (jmng_taker.py, through joinmarket-ng's own API),
#      which does a sw0 round with them and asks them to broadcast it (`!push`, never itself); vortex-ng
#      then checks the transaction and its makers' wallets.
# With CHANNEL=onion, round A's makers also serve, as makers do behind Tor: each says an onion name of its own
# and listens on loopback. The vortex-ng taker reaches the directory through a test SOCKS proxy standing in for
# Tor, which knows maker 1's onion is on this machine and refuses maker 2's. So the taker must reach maker 1
# directly and fall back to the directory for maker 2. The directory's log (its privacy-sensitive lines on)
# must show it relayed none of the taker's `!fill`, `!auth`, `!tx` to maker 1, and relayed maker 2's.
# Round B's vortex-ng makers serve the same way (onion names of their own, loopback ports), and joinmarket-ng's
# taker reaches them through the same kind of proxy, run by vortex-ng's test, which knows maker 1's onion and
# refuses maker 2's. The directory must have relayed none of the taker's round lines to maker 1 and none of
# maker 1's answers, and relayed maker 2's both ways.
set -euo pipefail

VORTEX_NG_REPO=https://github.com/SovereignTechnology/vortex-ng.git
VORTEX_NG_COMMIT=${VORTEX_NG_COMMIT:?set VORTEX_NG_COMMIT to the vortex-ng commit to test}
CORE_VERSION=32.1
CORE_SHA256=61545c17c3120fb7412f896d248b11993af04ec8817aad3649c55b2afb044963
PORT=18443
BONDS=${BONDS:-1}
PIT=${PIT:-sw0}
CHANNEL=${CHANNEL:-nostr}
DIRECTORY_PORT=15222
DIRECTORY_ID=test:jm-directory-$DIRECTORY_PORT
case "$CHANNEL" in nostr|onion) ;; *) echo "CHANNEL=$CHANNEL: nostr or onion" >&2; exit 97 ;; esac
case "$PIT" in
  sw0) address_type=p2wpkh ;;
  tr0) address_type=p2tr ;;
  *) echo "PIT=$PIT: sw0 or tr0" >&2; exit 97 ;;
esac
# joinmarket-ng's test bond locktime (2099-12-01, timenumber 959). The bond addresses are derived by the
# vortex-ng test from the makers' mnemonics: the address in joinmarket-ng's scripts/fund-test-wallets.sh is
# the pre-timenumber derivation (child index 0) and is not what its maker derives today.
BOND_LOCKTIME=4099766400
# joinmarket-ng's own regtest test wallets (docker-compose.yml maker1, maker2; scripts/fund-test-wallets.sh).
MAKER_MNEMONICS=(
  "avoid whisper mesh corn already blur sudden fine planet chicken hover sniff"
  "minute faint grape plate stock mercy tent world space opera apple rocket"
)
TAKER_MNEMONIC="burden notable love elephant orbit couch message galaxy elevator exile drop toilet"
# With CHANNEL=onion: where round A's makers listen, and round B's (ours). Their onion names are made up below.
MAKER_SERVE_PORTS=(15231 15232)
OUR_SERVE_PORTS=(15241 15242)

jmng=$(pwd)
here=$(cd "$(dirname "$0")" && pwd)
if [ "$CHANNEL" = nostr ] && [ ! -d "$jmng/jmcore/src/jmcore/nostr" ]; then
  echo "CHANNEL=nostr: run from a joinmarket-ng checkout with jmcore.nostr" >&2; exit 97
fi
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
# jmswap exists only in a checkout with the Taproot pit; its maker and taker import it.
editable=()
for c in jmcore jmwallet jmswap maker taker directory_server; do
  [ -d "$jmng/$c" ] || continue
  pip install -q --disable-pip-version-check --require-hashes -r "$jmng/$c/requirements.txt"
  editable+=(-e "$jmng/$c")
done
pip install -q --disable-pip-version-check --no-deps "${editable[@]}"
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
# Each joinmarket-ng wallet is funded at the first address joinmarket-ng itself derives for it in this pit.
for mnemonic in "${MAKER_MNEMONICS[@]}" "$TAKER_MNEMONIC"; do
  address=$(python3 "$here/jmng_address.py" "$address_type" "$mnemonic" "http://127.0.0.1:$PORT" "$cookie" "$work/derive")
  case "$address" in bcrt1*) ;; *) echo "joinmarket-ng derived no regtest address" >&2; exit 24 ;; esac
  for _ in 1 2 3; do cli -rpcwallet=funder sendtoaddress "$address" 1.0 >/dev/null; done
done
cli generatetoaddress 6 "$funder" >/dev/null
echo "bitcoind $("$bin/bitcoind" -version | head -1) at height $(cli getblockcount); joinmarket-ng wallets funded"

# With CHANNEL=onion: joinmarket-ng's directory server, for both rounds. Its privacy-sensitive lines name
# who it relays what to, which is what shows a direct connection carried a line instead.
if [ "$CHANNEL" = onion ]; then
  HOME="$work/directory" NETWORK_CONFIG__NETWORK=regtest DIRECTORY_SERVER__HOST=127.0.0.1 \
    DIRECTORY_SERVER__PORT=$DIRECTORY_PORT DIRECTORY_SERVER__NICK_AUTH_DIRECTORY_ID=$DIRECTORY_ID \
    LOGGING__LEVEL=DEBUG LOGGING__SENSITIVE=true jm-directory-server >"$logs/directory.log" 2>&1 &
  pids+=($!)
  for _ in $(seq 1 60); do (exec 3<>/dev/tcp/127.0.0.1/$DIRECTORY_PORT) 2>/dev/null && break; sleep 1; done
  (exec 3<>/dev/tcp/127.0.0.1/$DIRECTORY_PORT) 2>/dev/null || { show "$logs/directory.log" 30; exit 26; }
  echo "joinmarket-ng's directory server on 127.0.0.1:$DIRECTORY_PORT ($DIRECTORY_ID)"
fi
# A v3 onion name, well formed (key, checksum, version) though no key behind it is anyone's.
new_onion() {
  python3 -I -c 'import base64, hashlib, os
key = os.urandom(32)
check = hashlib.sha3_256(b".onion checksum" + key + b"\x03").digest()[:2]
print(base64.b32encode(key + check + b"\x03").decode().lower() + ".onion")'
}
# What tells vortex-ng's test to meet on the directory, and which onion is on this machine.
onion_env=()
maker_onions=()
our_onions=()
if [ "$CHANNEL" = onion ]; then
  maker_onions=("$(new_onion)" "$(new_onion)")
  our_onions=("$(new_onion)" "$(new_onion)")
  onion_env=("VORTEX_NG_INTEROP_DIRECTORY=127.0.0.1:$DIRECTORY_PORT" "VORTEX_NG_INTEROP_DIRECTORY_ID=$DIRECTORY_ID"
    "VORTEX_NG_INTEROP_ONIONS=${maker_onions[0]}")
fi
# Where joinmarket-ng's side meets ours: the relay vortex-ng's test runs, or the directory.
meeting() { if [ "$CHANNEL" = onion ]; then echo "127.0.0.1:$DIRECTORY_PORT"; else echo "nostr:$1"; fi; }

# The vortex-ng side of a round: the relay plus the taker or the makers. Prints the relay URL once it is up.
vortex_pid=
start_vortex() {  # $1 = role, $2 = its directory, then settings of its own (NAME=value) over onion_env's
  local role=$1 dir=$2
  shift 2
  (cd "$work/vortex-ng" && env "${onion_env[@]}" "$@" VORTEX_NG_INTEROP_ROLE="$role" VORTEX_NG_INTEROP_DIR="$dir" VORTEX_NG_INTEROP_BONDS="$BONDS" \
    VORTEX_NG_INTEROP_PIT="$PIT" \
    VORTEX_NG_INTEROP_BOND_MNEMONICS="${MAKER_MNEMONICS[0]}|${MAKER_MNEMONICS[1]}" \
    VORTEX_NG_INTEROP_MAKERS=${#MAKER_MNEMONICS[@]} VORTEX_NG_REGTEST_RPC="http://127.0.0.1:$PORT" \
    VORTEX_NG_REGTEST_COOKIE="$cookie" \
    cargo test --locked -p vortex-ng-node --test jmng_interop -- --nocapture >"$logs/vortex-$role.log" 2>&1) &
  vortex_pid=$!
  pids+=("$vortex_pid")
  for _ in $(seq 1 600); do [ -s "$dir/relay.url" ] && break; kill -0 "$vortex_pid" 2>/dev/null || break; sleep 1; done
  [ -s "$dir/relay.url" ] || { echo "vortex-ng ($role) did not start its relay"; show "$logs/vortex-$role.log" 40; return 1; }
}
report() { grep -E 'relay at|directory at|answered on the directory|maker .* (announced|nick)|taker nick|CoinJoin .* confirmed|Commitment announced|answered !error|panicked|failed|test result|refuses' "$1" | cut -c1-400 || true; }

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
    bond_args=()
    bond_env=()
    if [ "$BONDS" = 1 ]; then  # as joinmarket-ng's compose runs its bonded maker: locktime given, no registry
      bond_args=(--fidelity-bond-locktime "$BOND_LOCKTIME")
      bond_env=("MAKER__FIDELITY_BOND_LOCKTIMES=$BOND_LOCKTIME" FIDELITY_BOND_INDEX=0)
    fi
    if [ "$PIT" = tr0 ]; then bond_env+=(WALLET__ADDRESS_TYPE=p2tr); fi  # the pit switch; offers follow it
    serve_env=()
    if [ "$CHANNEL" = onion ]; then  # a static onion: no Tor control port, the listener on loopback
      serve_env=("MAKER__ONION_HOST=${maker_onions[$((i - 1))]}" MAKER__ONION_SERVING_HOST=127.0.0.1
        "MAKER__ONION_SERVING_PORT=${MAKER_SERVE_PORTS[$((i - 1))]}")
    fi
    env "${bond_env[@]}" "${serve_env[@]}" \
    HOME="$home" JOINMARKET_DATA_DIR="$home/.joinmarket-ng" MNEMONIC="$mnemonic" \
      NETWORK_CONFIG__NETWORK=regtest NETWORK_CONFIG__BITCOIN_NETWORK=regtest \
      NETWORK_CONFIG__ALLOW_CLEARNET_CONNECTIONS=true DIRECTORY_SERVERS="$(meeting "$relay")" \
      BITCOIN__BACKEND_TYPE=descriptor_wallet BITCOIN__RPC_URL="http://127.0.0.1:$PORT" \
      BITCOIN__RPC_COOKIE_FILE="$cookie" TOR__CONTROL_ENABLED=false LOGGING__LEVEL=DEBUG \
      MAKER__MIN_SIZE=10000 MAKER__TX_FEE_CONTRIBUTION=500 MAKER__CJ_FEE_RELATIVE=0.001 \
      jm-maker start "${bond_args[@]}" >"$logs/maker$i.log" 2>&1 &
    maker_pids+=($!)
    pids+=($!)
  done
  # A maker that has died will never announce an offer: stop instead of waiting out the taker's patience.
  while kill -0 "$vortex_pid" 2>/dev/null; do
    for p in "${maker_pids[@]}"; do
      if ! kill -0 "$p" 2>/dev/null; then
        echo "a joinmarket-ng maker exited before the round"
        kill "$vortex_pid" 2>/dev/null || true
        rc_a=25
      fi
    done
    [ "$rc_a" -eq 0 ] || break
    sleep 2
  done
  wait "$vortex_pid" || { rc=$?; [ "$rc_a" -ne 0 ] || rc_a=$rc; }
fi
echo "== A ($CHANNEL, $PIT, bonds $BONDS): vortex-ng taker with joinmarket-ng makers (exit $rc_a)"
report "$logs/vortex-taker.log"
if [ "$rc_a" -ne 0 ]; then
  show "$logs/vortex-taker.log" 40
  for n in 1 2; do show "$logs/maker$n.log" 60; done
else
  echo "txid $(cat "$work/a/taker.txid") at height $(cli getblockcount)"
  # joinmarket-ng's makers publish the taker's PoDLE commitment (!hp2) from a throwaway nick after !ioauth.
  for n in 1 2; do
    grep -E 'Created offer' "$logs/maker$n.log" | tail -1 | grep -o 'type=[a-z0-9]*' || true
    grep -E 'bond_value=|No fidelity bond found|fidelity bond.*(found|loaded)' "$logs/maker$n.log" | tail -2 | cut -c1-260 || true
    echo "maker$n !hp2: $(grep -c 'CoinJoin message sent: command=!hp2' "$logs/maker$n.log") sent," \
      "$(grep -c 'Could not connect to any directory for ephemeral hp2 broadcast' "$logs/maker$n.log") could not connect"
  done
  if [ "$CHANNEL" = onion ]; then
    # Which of the taker's round lines the directory relayed to each maker: none to maker 1, reached directly.
    grep -E '^direct connection asked for' "$logs/vortex-taker.log" | cut -c1-200 || true
    taker=$(sed -n 's/^taker nick \(J[0-9A-Za-z]*\)$/\1/p' "$logs/vortex-taker.log" | head -1)
    relayed=()
    for n in 1 2; do
      nick=$(grep -o "Handshake accepted: J[0-9A-Za-z]* from [a-z]* at ${maker_onions[$((n - 1))]}:" "$logs/directory.log" \
        | tail -1 | cut -d' ' -f3 || true)
      if [ -z "$taker" ] || [ -z "$nick" ]; then
        echo "maker$n: its nick or the taker's is not in the logs"; rc_a=27; continue
      fi
      relayed[n]=$(grep -c -E "PRIVMSG routing: $taker -> $nick \(rest: (fill|auth|tx) " "$logs/directory.log" || true)
      echo "maker$n $nick at ${maker_onions[$((n - 1))]}: the directory relayed ${relayed[n]} of the taker's" \
        "!fill/!auth/!tx to it, and $(grep -c -E "PRIVMSG routing: $nick -> $taker " "$logs/directory.log" || true)" \
        "of its lines to the taker"
    done
    if [ "$rc_a" -eq 0 ]; then
      if [ "${relayed[1]}" -eq 0 ] && [ "${relayed[2]}" -ge 3 ]; then
        echo "Direct connection: maker 1 reached directly, maker 2 through the directory after its onion was refused"
      else
        echo "Direct connection: expected 0 relayed lines for maker 1 and at least 3 for maker 2"; rc_a=28
      fi
    fi
  fi
fi
for p in "${maker_pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done

# ---- B: vortex-ng makers, joinmarket-ng taker ------------------------------------------------------------
rc_b=0
# With CHANNEL=onion our makers serve as onions of their own; the test's proxy, which joinmarket-ng's taker
# then uses as its Tor, knows maker 1's and refuses maker 2's.
serve_b=()
if [ "$CHANNEL" = onion ]; then
  serve_b=("VORTEX_NG_INTEROP_SERVE=${our_onions[0]}:${OUR_SERVE_PORTS[0]},${our_onions[1]}:${OUR_SERVE_PORTS[1]}"
    "VORTEX_NG_INTEROP_ONIONS=${our_onions[0]}")
fi
start_vortex makers "$work/b" "${serve_b[@]}" || rc_b=22
if [ "$rc_b" -eq 0 ]; then
  relay=$(cat "$work/b/relay.url")
  socks_b=()
  [ ! -s "$work/b/socks.addr" ] || socks_b=("JMNG_SOCKS=$(cat "$work/b/socks.addr")")
  sleep 5  # the makers publish their offers right after the relay URL is written
  env "${socks_b[@]}" HOME="$work/taker" JMNG_TAKER_MNEMONIC="$TAKER_MNEMONIC" python3 "$here/jmng_taker.py" "$(meeting "$relay")" "http://127.0.0.1:$PORT" "$cookie" \
    "$work/taker/.joinmarket-ng" "$BONDS" "$PIT" >"$logs/jmng-taker.log" 2>&1 || rc_b=$?
  txid=$(sed -n 's/^JMNG_TXID=//p' "$logs/jmng-taker.log" | tail -1)
  if [ "$rc_b" -eq 0 ] && [ -n "$txid" ] && [ "$txid" != None ]; then
    # The makers broadcast it: it must be in the node's mempool before a block can take it.
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
echo "== B ($CHANNEL, $PIT, bonds $BONDS): joinmarket-ng taker with vortex-ng makers (exit $rc_b)"
report "$logs/vortex-makers.log"
if [ "$rc_b" -ne 0 ]; then
  grep -v -E 'utxo_metadata|wallet\.sync|history_reconstruction' "$logs/jmng-taker.log" | tail -n 70 | cut -c1-400 || true
  show "$logs/vortex-makers.log" 30
else
  echo "txid $txid at height $(cli getblockcount)"
  grep -E -i 'bond' "$logs/jmng-taker.log" | grep -v -E 'utxo_metadata|registry' | tail -6 | cut -c1-260 || true
  if [ "$CHANNEL" = onion ]; then
    # Which of the round's lines the directory relayed between joinmarket-ng's taker and each of our makers.
    grep -E '^direct connection asked for' "$logs/vortex-makers.log" | cut -c1-200 || true
    taker=$(sed -n 's/^JMNG_TAKER_NICK=\(J[0-9A-Za-z]*\)$/\1/p' "$logs/jmng-taker.log" | head -1)
    to=()
    from=()
    for n in 1 2; do
      nick=$(sed -n "s/^maker $((n - 1)) nick \(J[0-9A-Za-z]*\)\$/\1/p" "$logs/vortex-makers.log" | head -1)
      if [ -z "$taker" ] || [ -z "$nick" ]; then
        echo "maker$n: its nick or the taker's is not in the logs"; rc_b=27; continue
      fi
      to[n]=$(grep -c -E "PRIVMSG routing: $taker -> $nick \(rest: (fill|auth|tx) " "$logs/directory.log" || true)
      from[n]=$(grep -c -E "PRIVMSG routing: $nick -> $taker \(rest: (pubkey|ioauth|sig) " "$logs/directory.log" || true)
      echo "maker$n $nick at ${our_onions[$((n - 1))]}: the directory relayed ${to[n]} of the taker's" \
        "!fill/!auth/!tx to it and ${from[n]} of its !pubkey/!ioauth/!sig to the taker"
    done
    if [ "$rc_b" -eq 0 ]; then
      if [ "${to[1]}" -eq 0 ] && [ "${from[1]}" -eq 0 ] && [ "${to[2]}" -ge 3 ] && [ "${from[2]}" -ge 3 ]; then
        echo "Direct connection: joinmarket-ng's taker reached maker 1 directly both ways, maker 2 through the" \
          "directory after its onion was refused"
      else
        echo "Direct connection: expected nothing relayed with maker 1 and at least 3 lines each way with maker 2"
        rc_b=28
      fi
    fi
  fi
fi

if [ "$CHANNEL" = onion ]; then
  # What the directory saw: connections, nick authentication (ours authenticates; joinmarket-ng's makers,
  # connecting by address, do not), relayed private messages.
  echo "directory: $(grep -c -i 'handshake' "$logs/directory.log") handshake lines," \
    "$(grep -c -i 'nick.auth.*\(verified\|ok\)' "$logs/directory.log") nick-authentication successes"
  grep -i 'nick.auth' "$logs/directory.log" | tail -4 | cut -c1-240 || true
  [ "$rc_a" -eq 0 ] && [ "$rc_b" -eq 0 ] || show "$logs/directory.log" 40
fi
[ "$rc_a" -eq 0 ] && [ "$rc_b" -eq 0 ] && { echo "== both directions passed"; exit 0; }
exit 1
