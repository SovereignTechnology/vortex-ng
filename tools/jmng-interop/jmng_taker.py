"""joinmarket-ng's taker, through its own API, doing one CoinJoin with the makers on a Nostr relay.

Run by run.sh inside the VM, with joinmarket-ng installed:

    python3 jmng_taker.py <relay url> <rpc url> <cookie file> <data dir> [bonds: 1|0] [pit: sw0|tr0]

It uses joinmarket-ng's own regtest test wallet for the taker, Bitcoin Core's wallet backend, and the
relay as the only message channel. With bonds (1) it keeps joinmarket-ng's default policy: a maker that
charges a fee is chosen only if its fidelity bond verifies, so the makers' `!tbond` proofs must pass
joinmarket-ng's own checks. Without (0), like joinmarket-ng's own end-to-end tests, it lets makers without a
bond charge a fee. It never broadcasts the transaction itself (`not-self`): it sends `!push` to
the makers, so the round reaches the node only if one of them broadcasts it. Prints `JMNG_TXID=<txid>`.
"""

import asyncio
import os
import sys
from pathlib import Path

# joinmarket-ng's own regtest taker wallet (tests/e2e), named and funded by run.sh at its first address.
TAKER_MNEMONIC = os.environ["JMNG_TAKER_MNEMONIC"]
AMOUNT = 1_000_000


async def main() -> int:
    relay, rpc_url, cookie_file, data = sys.argv[1:5]
    bonds = len(sys.argv) > 5 and sys.argv[5] == "1"
    taproot = len(sys.argv) > 6 and sys.argv[6] == "tr0"
    user, password = Path(cookie_file).read_text().strip().split(":", 1)

    from jmcore.models import NetworkType
    from jmwallet.backends.descriptor_wallet import DescriptorWalletBackend
    from jmwallet.wallet.service import WalletService
    from taker.config import BroadcastPolicy, MaxCjFee, TakerConfig
    from taker.taker import Taker

    data_dir = Path(data)
    data_dir.mkdir(parents=True, exist_ok=True)
    try:  # a brand-new taker: a new, unused history (a step older checkouts do not have)
        from taker.podle_manager import initialize_commitment_history

        initialize_commitment_history(data_dir)
    except ImportError:
        pass
    backend = DescriptorWalletBackend(rpc_url=rpc_url, rpc_user=user, rpc_password=password)
    # The Taproot pit: a BIP86 wallet and tr0 offers (keywords a checkout without the pit does not have).
    wallet_pit, config_pit = {}, {}
    if taproot:
        from jmcore.models import OfferType

        wallet_pit = {"address_type": "p2tr"}
        config_pit = {"address_type": "p2tr", "preferred_offer_type": OfferType.TR0_RELATIVE}
    wallet = WalletService(
        mnemonic=TAKER_MNEMONIC,
        backend=backend,
        network="regtest",
        mixdepth_count=5,
        data_dir=data_dir,
        **wallet_pit,
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
        bondless_makers_allowance_require_zero_fee=bonds,
        max_cj_fee=MaxCjFee(abs_fee=10_000, rel_fee="0.01"),
        tx_broadcast=BroadcastPolicy.NOT_SELF,
        data_dir=data_dir,
        **config_pit,
    )
    taker = Taker(wallet, backend, config)
    await taker.start()
    try:
        destination = wallet.get_receive_address(1, 0)
        txid = await asyncio.wait_for(
            taker.do_coinjoin(amount=AMOUNT, destination=destination, mixdepth=0), 600
        )
        for offer in getattr(taker.orderbook_manager, "offers", []) or []:
            print(f"offer from {offer.counterparty}: bond value {getattr(offer, 'fidelity_bond_value', 0)}")
    finally:
        await taker.stop()
        await wallet.close()
    print(f"JMNG_TXID={txid}")
    return 0 if txid else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
