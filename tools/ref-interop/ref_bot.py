"""One of joinmarket-clientserver's bots on regtest, for run.sh: a maker, a taker, or a directory node.

    python3 ref_bot.py <role> <name> <data dir> <work dir>

Everything else comes from the environment run.sh sets:

    REF_RPC_PORT, REF_COOKIE    Bitcoin Core's RPC port and cookie file
    REF_WALLET                  the Core watch-only wallet this bot imports its addresses into (created by run.sh)
    REF_MINE_TO                 where the reference's regtest interface would mine to (see the shim below)
    REF_SEED                    the bot's wallet entropy (32 hex characters); not used by the directory
    REF_CHANNEL                 onion or irc
    REF_DIRECTORY               onion: the directory node, 127.0.0.1:<port>
    REF_SERVE_PORT              onion, maker and directory: the port this bot serves on
    REF_IRC                     irc: the server, <host>:<port>
    REF_AMOUNT, REF_MAKERS      taker: the CoinJoin amount (sats) and how many makers
    REF_BROADCAST               taker: self or not-self (ask a maker to broadcast: `!push`)

It runs joinmarket-clientserver as its own regtest tests do (test/unified/test_e2e_coinjoin.py,
test/regtest_joinmarket.cfg): network `testnet` on a regtest node, and on the onion channel its testing mode
(`regtest_count` set), where bots serve and connect over plain TCP on loopback and Tor is never used. The
directory node is a maker that never syncs its wallet, so it never offers anything: the "crippled maker" the
reference's documentation describes for directory nodes. Its own address is its only `directory_nodes` entry.

A maker or taker writes its funding address to <work dir>/<name>.address, waits for <work dir>/<name>.funded,
then syncs and runs. The taker prints REF_TXID=<txid> once the transaction is on the node, and exits 0.
"""

import os
import sys
import time
from pathlib import Path

ROLE, NAME, DATA, WORK = sys.argv[1:5]
CHANNEL = os.environ["REF_CHANNEL"]


def config_text() -> str:
    """The bot's joinmarket.cfg: only what differs from the reference's defaults."""
    rpc_port = os.environ["REF_RPC_PORT"]
    # The daemon runs in this process (no_daemon = 1); each bot needs its own port for it.
    daemon_port = 27183 + int(os.environ.get("REF_INDEX", "0"))
    lines = [
        "[DAEMON]",
        "no_daemon = 1",
        f"daemon_port = {daemon_port}",
        "daemon_host = localhost",
        "use_ssl = false",
        "[BLOCKCHAIN]",
        "blockchain_source = regtest",
        "network = testnet",
        "rpc_host = 127.0.0.1",
        f"rpc_port = {rpc_port}",
        f"rpc_cookie_file = {os.environ['REF_COOKIE']}",
        f"rpc_wallet_file = {os.environ['REF_WALLET']}",
    ]
    if CHANNEL == "onion":
        serve = os.environ.get("REF_SERVE_PORT", "0")
        lines += [
            "[MESSAGING:onion]",
            "type = onion",
            "socks5_host = localhost",
            "socks5_port = 9050",
            "tor_control_host = localhost",
            "tor_control_port = 9051",
            "onion_serving_host = 127.0.0.1",
            f"onion_serving_port = {serve}",
            'hidden_service_dir = ""',
            f"directory_nodes = {os.environ['REF_DIRECTORY']}",
            "regtest_count = 1,5",
        ]
    else:
        host, port = os.environ["REF_IRC"].rsplit(":", 1)
        lines += [
            "[MESSAGING:server1]",
            "type = irc",
            f"host = {host}",
            f"port = {port}",
            "channel = joinmarket-pit",
            "usessl = false",
            "socks5 = false",
            "socks5_host = localhost",
            "socks5_port = 9150",
        ]
    lines += [
        "[TIMEOUT]",
        "maker_timeout_sec = 60",
        "[LOGGING]",
        "console_log_level = DEBUG",
        "[POLICY]",
        "tx_fees = 3",
        "taker_utxo_retries = 3",
        "taker_utxo_age = 1",
        "taker_utxo_amtpercent = 20",
        "accept_commitment_broadcasts = 1",
        f"minimum_makers = {os.environ.get('REF_MAKERS', '2')}",
        "max_cj_fee_abs = 200000",
        "max_cj_fee_rel = 0.2",
        f"tx_broadcast = {os.environ.get('REF_BROADCAST', 'self')}",
        "[YIELDGENERATOR]",
        "ordertype = reloffer",
        "cjfee_r = 0.0002",
        "txfee_contribution = 0",
        "minsize = 100000",
        "size_factor = 0",
        "cjfee_factor = 0",
        "txfee_contribution_factor = 0",
    ]
    return "\n".join(lines) + "\n"


def regtest_without_mining_wallet() -> None:
    """A harness shim. The reference's regtest interface asks its Core wallet for a new address when it starts,
    to mine to when it ticks the chain forward itself (`tick_forward_chain`). Its own tests run it with a legacy
    Core wallet; Core 32 has none, and a watch-only descriptor wallet (which its address imports need) has no keys
    to give an address from. This bot never ticks the chain (`tick_forward_chain_interval` stays -1), so the
    constructor is the reference's own minus that call, with the address the harness mines to instead.
    """
    import jmclient.blockchaininterface as interfaces

    def init(self, jsonRpc, wallet_name):
        interfaces.BitcoinCoreInterface.__init__(self, jsonRpc, "regtest", wallet_name)
        self.pushtx_failure_prob = 0
        self.tick_forward_chain_interval = -1
        self.absurd_fees = False
        self.simulating = False
        self.shutdown_signal = False
        self.destn_addr = os.environ["REF_MINE_TO"]

    interfaces.RegtestBitcoinCoreInterface.__init__ = init


def wait_for(path: Path, seconds: int) -> None:
    for _ in range(seconds):
        if path.exists():
            return
        time.sleep(1)
    raise SystemExit(f"{path} never appeared")


def main() -> int:
    data = Path(DATA)
    data.mkdir(parents=True, exist_ok=True)
    (data / "joinmarket.cfg").write_text(config_text())

    from twisted.internet import reactor

    from jmbase import bintohex, get_log
    from jmclient import (
        JMClientProtocolFactory,
        SegwitWallet,
        Taker,
        WalletService,
        YieldGeneratorBasic,
        jm_single,
        load_program_config,
        open_test_wallet_maybe,
        start_reactor,
    )
    from jmclient.support import random_under_max_order_choose

    log = get_log()
    regtest_without_mining_wallet()
    load_program_config(config_path=str(data), bs="regtest")
    host = jm_single().config.get("DAEMON", "daemon_host")
    port = jm_single().config.getint("DAEMON", "daemon_port")

    seed = os.environ.get("REF_SEED", "00" * 16)
    wallet = open_test_wallet_maybe(seed, seed, 4, test_wallet_cls=SegwitWallet)
    service = WalletService(wallet)

    if ROLE == "directory":
        # Never synced, so it never computes offers: it only serves the channel.
        directory = YieldGeneratorBasic(service, [0, None, "0.0002", "sw0reloffer", 100000, 0, 0, 0])
        start_reactor(host, port, JMClientProtocolFactory(directory, proto_type="MAKER"), daemon=True)
        return 0

    # Imported into Core's watch-only wallet before it is funded, so no rescan is needed.
    address = service.get_internal_addr(0)
    (Path(WORK) / f"{NAME}.address").write_text(f"{address}\n")
    wait_for(Path(WORK) / f"{NAME}.funded", 600)
    # A first sync imports the rest of the gap and may ask for another pass (the regtest interface never
    # exits for a rescan, unlike the mainnet one).
    for _ in range(10):
        if service.sync_wallet(fast=True):
            break
        time.sleep(1)
    else:
        raise SystemExit(f"{NAME}: the wallet did not sync")
    log.info(f"{NAME}: balance by mixdepth {service.get_balance_by_mixdepth()}")

    if ROLE == "maker":
        service.startService()
        options = jm_single().config
        maker = YieldGeneratorBasic(
            service,
            [
                int(options.get("YIELDGENERATOR", "txfee_contribution")),
                None,
                options.get("YIELDGENERATOR", "cjfee_r"),
                "sw0reloffer",
                int(options.get("YIELDGENERATOR", "minsize")),
                0.0,
                0.0,
                0.0,
            ],
        )
        start_reactor(host, port, JMClientProtocolFactory(maker, proto_type="MAKER"), daemon=True)
        return 0

    # The taker: one CoinJoin from mixdepth 0 to a fresh address in mixdepth 1.
    amount = int(os.environ["REF_AMOUNT"])
    makers = int(os.environ["REF_MAKERS"])
    destination = service.get_internal_addr(1)
    schedule = [(0, amount, makers, destination, 0.0, 16, 0)]
    result = {}

    def finished(res, fromtx=False, waittime=0.0, txdetails=None):
        if fromtx == "unconfirmed" or (fromtx and res):
            tx = taker.latest_tx
            result["txid"] = bintohex(tx.GetTxid()[::-1]) if tx is not None else None
            if reactor.running:
                reactor.stop()
        elif not res:
            log.error("the round failed")
            if reactor.running:
                reactor.stop()

    def no_filter(orders_fees, cjamount):
        return True

    service.startService()
    taker = Taker(
        service,
        schedule,
        max_cj_fee=(200000, 0.2),
        order_chooser=random_under_max_order_choose,
        callbacks=(no_filter, None, finished),
    )
    start_reactor(host, port, JMClientProtocolFactory(taker), daemon=True)
    txid = result.get("txid")
    print(f"REF_TXID={txid}", flush=True)
    return 0 if txid else 1


if __name__ == "__main__":
    sys.exit(main())
