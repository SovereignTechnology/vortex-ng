#!/usr/bin/env python3
"""Real channel closes in a real LND wallet, then the Rust test that CoinJoins from them.

Starts Bitcoin Core on regtest and two LND nodes A and B on loopback, opens two channels from A to B, closes one
cooperatively and force-closes the other, and mines until A has swept it. A's wallet then holds one coin from each
close and the change of its channel opens (the coins that must NOT be spent). Bakes the two macaroons a user would
bake, and runs crates/vortex-ng-cli/tests/regtest_lnd.rs against A.

Usage (tools/lnd-itest/run.sh): drive.py <empty work directory>, with bitcoind, lnd and lncli on PATH.
"""
import base64
import http.server
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

CORE_RPC = 18643
FEE_PORT = 18644
CHANNEL_SATS = 4_000_000
PUSH_SATS = 500_000
READ_PERMISSIONS = ["info:read", "onchain:read", "offchain:read"]
ROUND_PERMISSIONS = READ_PERMISSIONS + ["onchain:write", "signer:generate"]
# BIP173's regtest example: a valid address no key here spends.
NOBODY = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"


def wait_for(what, check, limit=120, every=0.5):
    until = time.monotonic() + limit
    while True:
        try:
            value = check()
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            value = None
        if value:
            return value
        if time.monotonic() > until:
            raise RuntimeError(f"timed out waiting for {what}")
        time.sleep(every)


class FeeHandler(http.server.BaseHTTPRequestHandler):
    """A flat fee estimate: regtest has no fee history for LND to read."""

    def do_GET(self):  # noqa: N802
        body = json.dumps({"fee_by_block_target": {str(n): 12500 for n in (1, 2, 3, 6, 12, 25, 144)},
                           "min_relay_feerate": 1000}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class Core:
    def __init__(self, root):
        self.dir = f"{root}/core"
        self.cookie = f"{self.dir}/regtest/.cookie"
        os.makedirs(self.dir, mode=0o700)
        self.log = open(f"{root}/core.log", "wb")
        self.proc = subprocess.Popen(
            ["bitcoind", "-regtest", f"-datadir={self.dir}", f"-rpcport={CORE_RPC}", "-rpcbind=127.0.0.1",
             "-rpcallowip=127.0.0.1", "-listen=0", "-dnsseed=0", "-txindex=1", "-disablewallet=1",
             "-fallbackfee=0.0001", "-server=1", "-printtoconsole=0"],
            stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log)
        wait_for("Core's cookie", lambda: os.path.exists(self.cookie))
        wait_for("Core's RPC", lambda: self.call("getblockcount") is not None)

    def call(self, method, *params):
        with open(self.cookie, "rb") as f:
            auth = base64.b64encode(f.read().strip()).decode()
        body = json.dumps({"jsonrpc": "1.0", "id": "drive", "method": method, "params": list(params)}).encode()
        request = urllib.request.Request(f"http://127.0.0.1:{CORE_RPC}/", body, {
            "content-type": "application/json", "authorization": f"Basic {auth}"})
        try:
            answer = json.load(urllib.request.urlopen(request, timeout=120))
        except urllib.error.HTTPError as e:
            answer = json.loads(e.read())
        if answer.get("error"):
            raise RuntimeError(f"{method}: {answer['error'].get('message')}")
        return answer["result"]


class Lnd:
    def __init__(self, root, name, core, offset):
        self.name = name
        self.dir = f"{root}/lnd-{name}"
        self.p2p = 19735 + offset
        self.rpc = 11009 + offset
        self.rest = 18080 + offset
        self.log_path = f"{root}/lnd-{name}.out"
        os.makedirs(self.dir, mode=0o700)
        self.log = open(self.log_path, "wb")
        self.proc = subprocess.Popen(
            ["lnd", f"--lnddir={self.dir}", "--bitcoin.regtest", "--bitcoin.node=bitcoind",
             f"--bitcoind.rpchost=127.0.0.1:{CORE_RPC}", f"--bitcoind.rpccookie={core.cookie}",
             "--bitcoind.rpcpolling", "--bitcoind.blockpollinginterval=1s", "--bitcoind.txpollinginterval=1s",
             "--noseedbackup", "--nobootstrap", f"--listen=127.0.0.1:{self.p2p}",
             f"--rpclisten=127.0.0.1:{self.rpc}", f"--restlisten=127.0.0.1:{self.rest}", "--tlsdisableautofill",
             f"--fee.url=http://127.0.0.1:{FEE_PORT}/fee.json", "--debuglevel=info", "--maxpendingchannels=5"],
            stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log)
        wait_for(f"{name} active", lambda: self.cli("state").get("state") == "SERVER_ACTIVE", 180, 1)
        self.pub = wait_for(f"{name} info", lambda: self.cli("getinfo").get("identity_pubkey"))

    def command(self, *args):
        return ["lncli", f"--lnddir={self.dir}", f"--rpcserver=127.0.0.1:{self.rpc}", "--network=regtest", *args]

    def cli(self, *args, timeout=60):
        done = subprocess.run(self.command(*args), stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              timeout=timeout, check=False)
        if done.returncode != 0:
            raise RuntimeError(f"lncli {args[0]}: {done.stderr.strip()[:300]}")
        return json.loads(done.stdout) if done.stdout.strip() else {}

    def synced(self, height):
        info = self.cli("getinfo")
        return info.get("synced_to_chain") and int(info.get("block_height", 0)) >= height

    def bake(self, path, permissions):
        # Not JSON, and it may print the macaroon: nothing of the answer is kept.
        done = subprocess.run(self.command("bakemacaroon", "--save_to", path, *permissions),
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=60, check=False)
        if done.returncode != 0 or not os.path.exists(path):
            raise RuntimeError("lncli bakemacaroon failed")
        os.chmod(path, 0o600)


class Lab:
    def __init__(self, core, a, b):
        self.core, self.a, self.b = core, a, b
        self.sink = b.cli("newaddress", "p2wkh")["address"]

    def mine(self, blocks, to=None):
        while blocks > 0:
            n = min(blocks, 20)
            self.core.call("generatetoaddress", n, to or self.sink)
            blocks -= n
        tip = self.core.call("getblockcount")
        for node in (self.a, self.b):
            wait_for(f"{node.name} at {tip}", lambda: node.synced(tip), 180, 0.5)

    def open_channel(self):
        before = len(self.a.cli("listchannels").get("channels", []))
        self.a.cli("openchannel", "--node_key", self.b.pub, "--local_amt", str(CHANNEL_SATS),
                   "--push_amt", str(PUSH_SATS), "--sat_per_vbyte", "3")
        self.mine(6)

        def active():
            channels = [c for c in self.a.cli("listchannels").get("channels", []) if c.get("active")]
            return channels if len(channels) == before + 1 else None
        wait_for("the channel active", active)

    def channels(self):
        return [c["channel_point"].split(":") for c in self.a.cli("listchannels")["channels"]]

    def close(self, point, force):
        args = ["closechannel", "--funding_txid", point[0], "--output_index", point[1]]
        args += ["--force"] if force else ["--sat_per_vbyte", "3"]
        closing = subprocess.Popen(self.a.command(*args), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        time.sleep(4)
        self.mine(6)
        try:
            closing.wait(timeout=60)
        except subprocess.TimeoutExpired:
            closing.kill()
            closing.wait()

    def pending(self):
        p = self.a.cli("pendingchannels")
        return any(p.get(k) for k in ("pending_open_channels", "pending_closing_channels",
                                      "pending_force_closing_channels", "waiting_close_channels"))


def build(root):
    """The chain state the test starts from. Returns the processes and the test's environment."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", FEE_PORT), FeeHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    procs = []
    core = Core(root)
    procs.append(core.proc)
    # LND waits for its backend to look current, and a chain of the genesis block alone never does.
    core.call("generatetoaddress", 1, NOBODY)
    a = Lnd(root, "a", core, 0)
    procs.append(a.proc)
    b = Lnd(root, "b", core, 1)
    procs.append(b.proc)
    lab = Lab(core, a, b)
    return procs, core, a, b, lab


def scenario(root, core, a, b, lab):
    lab.mine(4, a.cli("newaddress", "p2wkh")["address"])
    lab.mine(101)
    wait_for("A's balance", lambda: int(a.cli("walletbalance").get("confirmed_balance", 0)) > 0)
    a.cli("connect", f"{b.pub}@127.0.0.1:{b.p2p}")
    lab.open_channel()
    lab.open_channel()
    mutual, force = lab.channels()
    lab.close(mutual, force=False)
    lab.close(force, force=True)
    for _ in range(80):
        if not lab.pending():
            break
        lab.mine(10)
    if lab.pending():
        raise RuntimeError("A never finished resolving its force close")
    lab.mine(2)
    closed = sorted(c.get("close_type", "COOPERATIVE_CLOSE") for c in a.cli("closedchannels").get("channels", []))
    print(f"A's closed channels: {closed}; tip {core.call('getblockcount')}", flush=True)
    if closed != ["COOPERATIVE_CLOSE", "LOCAL_FORCE_CLOSE"]:
        raise RuntimeError(f"unexpected closes: {closed}")

    read = f"{root}/read.macaroon"
    full = f"{root}/round.macaroon"
    a.bake(read, READ_PERMISSIONS)
    a.bake(full, ROUND_PERMISSIONS)
    return {
        "VORTEX_NG_REGTEST_RPC": f"http://127.0.0.1:{CORE_RPC}",
        "VORTEX_NG_REGTEST_COOKIE": core.cookie,
        "VORTEX_NG_LND_REST": f"127.0.0.1:{a.rest}",
        "VORTEX_NG_LND_CERT": f"{a.dir}/tls.cert",
        "VORTEX_NG_LND_MACAROON": full,
        "VORTEX_NG_LND_READ_MACAROON": read,
        "VORTEX_NG_LND_OTHER_CERT": f"{b.dir}/tls.cert",
    }


def main():
    root = os.path.abspath(sys.argv[1])
    os.makedirs(root, mode=0o700)
    procs = []
    try:
        procs, core, a, b, lab = build(root)
        env = scenario(root, core, a, b, lab)
        test = subprocess.run(
            ["cargo", "test", "--locked", "-p", "vortex-ng-cli", "--test", "regtest_lnd", "--", "--nocapture"],
            env={**os.environ, **env}, stdin=subprocess.DEVNULL, check=False)
        return test.returncode
    except Exception as e:  # pylint: disable=broad-except
        print(f"drive: {e}", file=sys.stderr)
        for name in ("a", "b"):
            log = f"{root}/lnd-{name}.out"
            if os.path.exists(log):
                with open(log, errors="replace") as f:
                    print(f"--- last lines of LND {name}:", *f.readlines()[-25:], sep="", file=sys.stderr)
        return 1
    finally:
        for proc in reversed(procs):
            proc.terminate()
        for proc in reversed(procs):
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    sys.exit(main())
