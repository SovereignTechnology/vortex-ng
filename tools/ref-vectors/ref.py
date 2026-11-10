"""Independent reference for vortex-ng-core test vectors: Python stdlib only, pure big-integer secp256k1.

It re-implements, from the specifications and joinmarket-ng's source as read (not imported):
JMP-0001 NUMS generators and PoDLE (with joinmarket-ng's deterministic RFC 6979 nonces), Bitcoin Signed
Message ECDSA as libsecp256k1 signs it (RFC 6979, low-S, strict DER), and the JMP-0010 taproot PoDLE secret.
Run: python3 -I tools/ref-vectors/ref.py
"""

import base64
import hashlib
import hmac
import json

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
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
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def deser(b):
    x = int.from_bytes(b[1:], "big")
    if x >= P:
        return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return None
    if (y & 1) != (b[0] & 1):
        y = P - y
    return (x, y)


def sha(b):
    return hashlib.sha256(b).digest()


def nums(i):
    for seed in (ser(G), b"\x04" + GX.to_bytes(32, "big") + GY.to_bytes(32, "big")):
        for c in range(256):
            pt = deser(b"\x02" + sha(seed + bytes([i, c])))
            if pt is not None:
                return pt
    raise ValueError


def rfc6979(key32, h32):
    h1 = (int.from_bytes(h32, "big") % N).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + key32 + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + key32 + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < N:
            yield cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def podle(key_int, utxo, index):
    key32 = key_int.to_bytes(32, "big")
    p, j = mul(key_int, G), nums(index)
    p2 = mul(key_int, j)
    pb, p2b = ser(p), ser(p2)
    u = utxo.encode()
    transcript = b"JoinMarket/PoDLE/nonce/v1" + len(u).to_bytes(4, "big") + u + bytes([index]) + pb + p2b
    for kn in rfc6979(key32, sha(transcript)):
        e = sha(ser(mul(kn, G)) + ser(mul(kn, j)) + pb + p2b)
        ei = int.from_bytes(e, "big") % N
        s = (kn + ei * key_int) % N
        if ei and s:
            return {"p": pb.hex(), "p2": p2b.hex(), "s": s.to_bytes(32, "big").hex(), "e": e.hex(),
                    "commitment": sha(p2b).hex()}
    raise ValueError


def compact_size(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


def der_int(x):
    b = x.to_bytes(32, "big").lstrip(b"\x00") or b"\x00"
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def sign_message(key_int, message):
    m = message.encode()
    z = hashlib.sha256(sha(b"\x18Bitcoin Signed Message:\n" + compact_size(len(m)) + m)).digest()
    zi = int.from_bytes(z, "big")
    for k in rfc6979(key_int.to_bytes(32, "big"), z):
        r = mul(k, G)[0] % N
        s = pow(k, N - 2, N) * (zi + r * key_int) % N
        if r and s:
            s = min(s, N - s)
            body = der_int(r) + der_int(s)
            return base64.b64encode(b"\x30" + bytes([len(body)]) + body).decode()
    raise ValueError


def tagged(tag, msg):
    t = sha(tag.encode())
    return sha(t + t + msg)


def taproot_output_secret(s):
    pt = mul(s, G)
    d = s if pt[1] % 2 == 0 else N - s
    t = int.from_bytes(tagged("TapTweak", mul(d, G)[0].to_bytes(32, "big")), "big") % N
    q = (d + t) % N
    return q if mul(q, G)[1] % 2 == 0 else N - q


def key(byte):
    return int.from_bytes(bytes([byte] * 32), "big")


assert ser(nums(0)).hex() == "0296f47ec8e6d6a9c3379c2ce983a6752bcfa88d46f2a6ffe0dd12c9ae76d01a1f"
assert ser(nums(255)).hex() == "02a0a8694820c794852110e5939a2c03f8482f81ed57396042c6b34557f6eb430a"

for kb, utxo, index in [(1, "a" * 64 + ":0", 0), (4, "d" * 64 + ":3", 4), (5, "f" * 64 + ":5", 5), (2, "b" * 64 + ":1", 1)]:
    print(json.dumps({"podle": {"key_byte": kb, "utxo": utxo, "index": index, **podle(key(kb), utxo, index)}}))
for kb, message in [(1, "hello nostr-network"), (7, "0 1000000 abcd Pdeadbeefnostr-network"), (3, "")]:
    print(json.dumps({"sign": {"key_byte": kb, "message": message, "signature": sign_message(key(kb), message)}}))
for kb in [3, 8]:
    e = taproot_output_secret(key(kb))
    print(json.dumps({"taproot": {"key_byte": kb, "output_secret": e.to_bytes(32, "big").hex(),
                                  "output_key": ser(mul(e, G)).hex()}}))


def sign_der(key_int, m):
    z = hashlib.sha256(sha(b"\x18Bitcoin Signed Message:\n" + compact_size(len(m)) + m)).digest()
    zi = int.from_bytes(z, "big")
    for k in rfc6979(key_int.to_bytes(32, "big"), z):
        r = mul(k, G)[0] % N
        s = pow(k, N - 2, N) * (zi + r * key_int) % N
        if r and s:
            s = min(s, N - s)
            body = der_int(r) + der_int(s)
            return b"\x30" + bytes([len(body)]) + body
    raise ValueError


# Fidelity-bond proof (JMP-0001 "Fidelity Bonds"): 252 bytes, '<72s72s33sH33s32sII', DER left-padded with 0xff.
cert_key, utxo_key = key(9), key(10)
cert_pub, utxo_pub = ser(mul(cert_key, G)), ser(mul(utxo_key, G))
expiry, locktime, txid_display, vout = 52, 1767225600, bytes.fromhex("ab" * 32), 1
nick_sig = sign_der(cert_key, b"J5TestTaker|J52TestMaker")
cert_sig = sign_der(utxo_key, b"fidelity-bond-cert|" + cert_pub + b"|" + str(expiry).encode())
proof = (nick_sig.rjust(72, b"\xff") + cert_sig.rjust(72, b"\xff") + cert_pub + expiry.to_bytes(2, "little")
         + utxo_pub + txid_display + vout.to_bytes(4, "little") + locktime.to_bytes(4, "little"))
assert len(proof) == 252
print(json.dumps({"bond": {"cert_key_byte": 9, "utxo_key_byte": 10, "expiry": expiry, "locktime": locktime,
                           "txid": txid_display.hex(), "vout": vout, "taker": "J5TestTaker", "maker": "J52TestMaker",
                           "proof": base64.b64encode(proof).decode()}}))
