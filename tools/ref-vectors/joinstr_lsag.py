#!/usr/bin/env python3
"""An independent, stdlib-only reference for joinstr's linkable ring signature (LSAG).

It re-implements the algorithm of the Electrum plugin's `lrs.py` (joinstr at the revision in
docs/upstream-pins.md) from its description, reading nothing from joinstr: the ring is compressed
secp256k1 keys sorted by hex, the key image is x * Hp(P), and each challenge is
sha256(str(L) || Y0 || message || L' || R') mod n, where L = sha256(ring keys) mod n is hashed as its
DECIMAL text. Scalars are written as Python hex().

joinstr draws its nonces from os.urandom. vortex-ng derives them from the key, message and ring
(`nonce` below), so a signature is reproducible and this script and vortex-ng-joinstr produce the same
bytes. Any verifier accepts either.

Run: python3 -I tools/ref-vectors/joinstr_lsag.py
"""
import base64
import hashlib
import json

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0]:
        if (a[1] + b[1]) % P == 0:
            return None
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def mul(k, pt):
    out = None
    while k:
        if k & 1:
            out = add(out, pt)
        pt = add(pt, pt)
        k >>= 1
    return out


def ser(pt):
    assert pt is not None, "point at infinity"
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def deser(b):
    assert len(b) == 33 and b[0] in (2, 3)
    x = int.from_bytes(b[1:], "big")
    assert x < P
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    assert y * y % P == (x * x * x + 7) % P, "not on the curve"
    return (x, y if (y & 1) == (b[0] & 1) else P - y)


def sha(b):
    return hashlib.sha256(b).digest()


def hash_to_point(data):
    nonce = 0
    while True:
        try:
            return deser(b"\x02" + sha(data + nonce.to_bytes(4, "big")))
        except AssertionError:
            nonce += 1


def challenge(l_digest, y0, message, l, r):
    # The ring digest enters as the decimal text of the integer, as lrs.py's hash_points does.
    return int.from_bytes(sha(str(l_digest).encode() + y0 + message + ser(l) + ser(r)), "big") % N


def nonce(x, message, l_digest, identity, slot):
    counter = 0
    while True:
        k = int.from_bytes(sha(b"vortex-ng/joinstr/lsag" + x.to_bytes(32, "big") + message
                               + str(l_digest).encode() + identity.to_bytes(4, "big")
                               + slot.to_bytes(4, "big") + counter.to_bytes(4, "big")), "big")
        if 0 < k < N:
            return k
        counter += 1


def sign(message, ring, x):
    ring = sorted(ring, key=lambda p: ser(p).hex())
    mine = mul(x, G)
    identity = ring.index(mine)
    n = len(ring)
    hp = hash_to_point(ser(mine))
    y0_point = mul(x, hp)
    y0 = ser(y0_point)
    l_digest = int.from_bytes(sha(b"".join(ser(p) for p in ring)), "big") % N
    u = nonce(x, message, l_digest, identity, identity)
    c, s = [0] * n, [0] * n
    l, r = mul(u, G), mul(u, hp)
    idx = (identity + 1) % n
    c[idx] = challenge(l_digest, y0, message, l, r)
    while idx != identity:
        s[idx] = nonce(x, message, l_digest, identity, idx)
        l = add(mul(s[idx], G), mul(c[idx], ring[idx]))
        r = add(mul(s[idx], hash_to_point(ser(ring[idx]))), mul(c[idx], y0_point))
        idx = (idx + 1) % n
        c[idx] = challenge(l_digest, y0, message, l, r)
    s[identity] = (u - c[identity] * x) % N
    return {"Y0": y0.hex(), "S": [hex(v) for v in s], "C": [hex(v) for v in c]}


def verify(message, sig, ring):
    ring = sorted(ring, key=lambda p: ser(p).hex())
    n = len(ring)
    if n == 0 or len(sig["S"]) != n or len(sig["C"]) != n:
        return False
    try:
        y0_point = deser(bytes.fromhex(sig["Y0"]))
    except (AssertionError, ValueError):
        return False
    if ser(y0_point).hex() != sig["Y0"]:
        return False
    s, c = [int(v, 16) for v in sig["S"]], [int(v, 16) for v in sig["C"]]
    if not all(0 < v < N for v in s + c):
        return False
    l_digest = int.from_bytes(sha(b"".join(ser(p) for p in ring)), "big") % N
    for i in range(n):
        l = add(mul(s[i], G), mul(c[i], ring[i]))
        r = add(mul(s[i], hash_to_point(ser(ring[i]))), mul(c[i], y0_point))
        if l is None or r is None:
            return False
        if challenge(l_digest, bytes.fromhex(sig["Y0"]), message, l, r) != c[(i + 1) % n]:
            return False
    return True


def main():
    keys = [int.from_bytes(bytes([b]) * 32, "big") for b in (1, 2, 3)]
    ring = [mul(k, G) for k in keys]
    address, pool_id = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "pool1"
    message = sha((address + pool_id).encode())
    out = {"ring_sorted": sorted(ser(p).hex() for p in ring), "message": message.hex(),
           "hash_to_point_of_key_1": ser(hash_to_point(ser(ring[0]))).hex(), "signatures": {}}
    for byte, x in zip((1, 2, 3), keys):
        sig = sign(message, ring, x)
        assert verify(message, sig, ring)
        assert not verify(sha(b"other"), sig, ring)
        out["signatures"][str(byte)] = sig
        out.setdefault("sig_fields", {})[str(byte)] = base64.b64encode(json.dumps(sig).encode()).decode()
    # One key signing twice links: the key image is the same whatever the message.
    assert sign(sha(b"m1"), ring, keys[0])["Y0"] == sign(sha(b"m2"), ring, keys[0])["Y0"]
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
