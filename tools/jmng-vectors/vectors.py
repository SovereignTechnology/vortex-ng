"""Print test vectors from joinmarket-ng's jmcore (see run.sh). Inputs are fixed; outputs are deterministic."""

import json

from jmcore.crypto import ecdsa_sign
from jmcore.podle import generate_podle, get_nums_point

PODLE_CASES = [(1, "a" * 64 + ":0", 0), (4, "d" * 64 + ":3", 4), (5, "f" * 64 + ":5", 5), (2, "b" * 64 + ":1", 1)]
SIGN_CASES = [(1, "hello nostr-network"), (7, "0 1000000 abcd Pdeadbeefnostr-network"), (3, "")]

for key_byte, utxo, index in PODLE_CASES:
    c = generate_podle(bytes([key_byte] * 32), utxo, index=index)
    print(json.dumps({"podle": {"key_byte": key_byte, "utxo": utxo, "index": index, "p": c.p.hex(),
                                "p2": c.p2.hex(), "s": c.sig.hex(), "e": c.e.hex(),
                                "commitment": c.commitment.hex()}}))
for key_byte, message in SIGN_CASES:
    print(json.dumps({"sign": {"key_byte": key_byte, "message": message,
                               "signature": ecdsa_sign(message, bytes([key_byte] * 32))}}))
print(json.dumps({"nums_2": bytes(get_nums_point(2)).hex()}))
