"""joinmarket-ng's taker, through its own API, doing one CoinJoin with the makers on a Nostr relay.

Run by run.sh inside the VM, with joinmarket-ng installed:

    python3 jmng_taker.py <relay url> <rpc url> <cookie file> <data dir>

It uses joinmarket-ng's own regtest test wallet for the taker, Bitcoin Core's wallet backend, and the
relay as the only message channel. Like joinmarket-ng's own end-to-end tests it lets makers without a
fidelity bond charge a fee. It broadcasts the transaction itself. Prints `JMNG_TXID=<txid>`.
"""

import asyncio
import sys
from pathlib import Path

# joinmarket-ng's own regtest taker wallet (tests/e2e; funded by run.sh at its first address).
TAKER_MNEMONIC = "burden notable love elephant orbit couch message galaxy elevator exile drop toilet"
AMOUNT = 1_000_000


async def main() -> int:
    relay, rpc_url, cookie_file, data = sys.argv[1:5]
    user, password = Path(cookie_file).read_text().strip().split(":", 1)

    from jmcore.models import NetworkType
    from jmwallet.backends.descriptor_wallet import DescriptorWalletBackend
    from jmwallet.wallet.service import WalletService
    from taker.config import BroadcastPolicy, MaxCjFee, TakerConfig
    from taker.podle_manager import initialize_commitment_history
    from taker.taker import Taker

    data_dir = Path(data)
    data_dir.mkdir(parents=True, exist_ok=True)
    initialize_commitment_history(data_dir)  # a brand-new taker: a new, unused history
    backend = DescriptorWalletBackend(rpc_url=rpc_url, rpc_user=user, rpc_password=password)
    wallet = WalletService(
        mnemonic=TAKER_MNEMONIC, backend=backend, network="regtest", mixdepth_count=5, data_dir=data_dir
    )
    await wallet.sync_all()
    config = TakerConfig(
        mnemonic=TAKER_MNEMONIC,
        network=NetworkType.REGTEST,
        bitcoin_network=NetworkType.REGTEST,
        backend_type="descriptor_wallet",
        backend_config={"rpc_url": rpc_url, "rpc_user": user, "rpc_password": password},
        directory_servers=[f"nostr:{relay}"],
        allow_clearnet_connections=True,
        counterparty_count=2,
        minimum_makers=2,
        maker_timeout_sec=60,
        order_wait_time=20.0,
        bondless_makers_allowance_require_zero_fee=False,
        max_cj_fee=MaxCjFee(abs_fee=10_000, rel_fee="0.01"),
        tx_broadcast=BroadcastPolicy.SELF,
        data_dir=data_dir,
    )
    taker = Taker(wallet, backend, config)
    await taker.start()
    try:
        destination = wallet.get_receive_address(1, 0)
        txid = await asyncio.wait_for(
            taker.do_coinjoin(amount=AMOUNT, destination=destination, mixdepth=0), 600
        )
    finally:
        await taker.stop()
        await wallet.close()
    print(f"JMNG_TXID={txid}")
    return 0 if txid else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
