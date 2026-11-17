"""The first receive address (mixdepth 0, index 0) joinmarket-ng derives for a wallet.

Run by run.sh inside the VM, with joinmarket-ng installed:

    python3 jmng_address.py <p2wpkh|p2tr> "<mnemonic>" <rpc url> <cookie file> <scratch dir>

Derivation only: nothing is asked of the node. run.sh funds the wallet at the address printed.
"""

import sys
from pathlib import Path


def main() -> int:
    address_type, mnemonic, rpc_url, cookie_file, scratch = sys.argv[1:6]
    user, password = Path(cookie_file).read_text().strip().split(":", 1)

    from jmwallet.backends.descriptor_wallet import DescriptorWalletBackend
    from jmwallet.wallet.service import WalletService

    data_dir = Path(scratch)
    data_dir.mkdir(parents=True, exist_ok=True)
    backend = DescriptorWalletBackend(rpc_url=rpc_url, rpc_user=user, rpc_password=password)
    # `address_type` exists only in a checkout that has the Taproot pit.
    pit = {"address_type": address_type} if address_type != "p2wpkh" else {}
    wallet = WalletService(
        mnemonic=mnemonic, backend=backend, network="regtest", mixdepth_count=5, data_dir=data_dir, **pit
    )
    print(wallet.get_receive_address(0, 0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
