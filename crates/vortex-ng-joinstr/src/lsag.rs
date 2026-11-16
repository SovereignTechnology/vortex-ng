//! joinstr's linkable ring signature (LSAG), as the Electrum plugin's `lrs.py` computes it (RULES.md R8.2).
//!
//! In the recovery round each owner of a registered input signs its new output address under the ring of
//! every input's key: the signature shows that one of those keys signed without showing which, and its key
//! image `Y0 = x * Hp(P)` is the same for every signature by one key, so nobody registers two outputs.
//!
//! The encoding is fixed by the Python reference and reproduced exactly: the ring is compressed keys sorted
//! by hex, the ring digest `L = sha256(keys) mod n` enters each challenge as its DECIMAL text, and scalars
//! are written as Python `hex()` strings. joinstr draws its nonces from the OS; here they are derived from
//! the key, the message and the ring, so signing needs no randomness and is reproducible. Checked against
//! `tools/ref-vectors/joinstr_lsag.py`, an independent implementation.

use bitcoin::base64::Engine;
use bitcoin::base64::engine::general_purpose::STANDARD;
use bitcoin::hashes::{Hash, HashEngine, sha256};
use bitcoin::secp256k1::constants::CURVE_ORDER;
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use serde_json::{Value, json};

use crate::pyjson;

type Bytes32 = [u8; 32];

/// Why a signature could not be made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LsagError {
    /// The signing key's public key is not in the ring.
    NotInRing,
    /// The ring is empty.
    EmptyRing,
    /// A point or scalar degenerated (probability negligible for honest inputs).
    Degenerate,
}

impl std::fmt::Display for LsagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LsagError::NotInRing => f.write_str("the signing key is not in the ring"),
            LsagError::EmptyRing => f.write_str("the ring is empty"),
            LsagError::Degenerate => f.write_str("degenerate ring signature"),
        }
    }
}

impl std::error::Error for LsagError {}

/// A linkable ring signature as joinstr carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// The key image: a compressed point, lowercase hex.
    pub y0: String,
    /// One response per ring member, Python `hex()` strings.
    pub s: Vec<String>,
    /// One challenge per ring member, Python `hex()` strings.
    pub c: Vec<String>,
}

impl Signature {
    /// The `sig` field of a `reregister` message: base64 of `json.dumps({"Y0": .., "S": [..], "C": [..]})`.
    pub fn to_field(&self) -> String {
        let text = pyjson::object(&[
            ("Y0", json!(self.y0)),
            ("S", json!(self.s)),
            ("C", json!(self.c)),
        ]);
        STANDARD.encode(text)
    }

    /// Read a `sig` field. `None` unless it is base64 of a JSON object with a string `Y0` and string lists
    /// `S` and `C`.
    pub fn from_field(field: &str) -> Option<Signature> {
        let bytes = STANDARD.decode(field.trim()).ok()?;
        let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(&bytes) else {
            return None;
        };
        let list = |name: &str| -> Option<Vec<String>> {
            map.get(name)?
                .as_array()?
                .iter()
                .map(|v| v.as_str().map(str::to_string))
                .collect()
        };
        Some(Signature {
            y0: map.get("Y0")?.as_str()?.to_string(),
            s: list("S")?,
            c: list("C")?,
        })
    }
}

/// The ring in the order every client uses: compressed keys sorted by hex, each key once.
pub fn sorted_ring(keys: &[PublicKey]) -> Vec<PublicKey> {
    let mut ring = keys.to_vec();
    ring.sort_by_key(PublicKey::serialize);
    ring.dedup();
    ring
}

fn sha(parts: &[&[u8]]) -> Bytes32 {
    let mut engine = sha256::Hash::engine();
    for part in parts {
        engine.input(part);
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// `value mod n` for a 256-bit value: one subtraction at most, since `n > 2^255`.
fn reduce(value: Bytes32) -> Bytes32 {
    if value < CURVE_ORDER {
        return value;
    }
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let diff = i16::from(value[i]) - i16::from(CURVE_ORDER[i]) - borrow;
        borrow = i16::from(diff < 0);
        out[i] = (diff + 256 * borrow) as u8;
    }
    out
}

/// Python's `str(int)` of a 256-bit value.
fn decimal(value: &Bytes32) -> String {
    let mut n = *value;
    let mut digits = Vec::new();
    loop {
        let mut rem = 0u32;
        for byte in &mut n {
            let cur = (rem << 8) | u32::from(*byte);
            *byte = (cur / 10) as u8;
            rem = cur % 10;
        }
        digits.push(b'0' + rem as u8);
        if n.iter().all(|b| *b == 0) {
            break;
        }
    }
    digits.iter().rev().map(|d| *d as char).collect()
}

/// Python's `hex(int)` of a 256-bit value: `0x` and the digits without leading zeros.
fn py_hex(value: &Bytes32) -> String {
    let digits: String = value.iter().map(|b| format!("{b:02x}")).collect();
    let trimmed = digits.trim_start_matches('0');
    format!("0x{}", if trimmed.is_empty() { "0" } else { trimmed })
}

/// A scalar from text as Python's `int(text, 16)` reads the forms a client writes (optional `0x`, either
/// case, surrounding whitespace), accepted only when `0 < value < n`.
fn parse_scalar(text: &str) -> Option<Bytes32> {
    let text = text.trim();
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() || digits.len() > 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let padded = format!("{digits:0>64}");
    let mut out = [0u8; 32];
    for (i, pair) in padded.as_bytes().chunks(2).enumerate() {
        out[i] = ((pair[0] as char).to_digit(16)? * 16 + (pair[1] as char).to_digit(16)?) as u8;
    }
    (out < CURVE_ORDER).then_some(out)
}

/// `lrs.py`'s `hash_to_point`: the first `sha256(data || nonce)` that is the x coordinate of a point, taken
/// with even y.
fn hash_to_point(data: &[u8]) -> Option<PublicKey> {
    (0u32..=u32::MAX).find_map(|nonce| {
        let mut candidate = [2u8; 33];
        candidate[1..].copy_from_slice(&sha(&[data, &nonce.to_be_bytes()]));
        PublicKey::from_slice(&candidate).ok()
    })
}

struct Ctx {
    secp: Secp256k1<bitcoin::secp256k1::All>,
}

impl Ctx {
    fn base(&self, scalar: &Bytes32) -> Option<PublicKey> {
        Some(SecretKey::from_slice(scalar).ok()?.public_key(&self.secp))
    }

    fn mul(&self, point: &PublicKey, scalar: &Bytes32) -> Option<PublicKey> {
        point
            .mul_tweak(&self.secp, &Scalar::from_be_bytes(*scalar).ok()?)
            .ok()
    }

    /// One ring step for member `p` with response `s` and challenge `c`:
    /// `L' = s*G + c*P` and `R' = s*Hp(P) + c*Y0`. `None` if either is the point at infinity.
    fn step(
        &self,
        p: &PublicKey,
        s: &Bytes32,
        c: &Bytes32,
        y0: &PublicKey,
    ) -> Option<(PublicKey, PublicKey)> {
        let l = self.base(s)?.combine(&self.mul(p, c)?).ok()?;
        let hp = hash_to_point(&p.serialize())?;
        let r = self.mul(&hp, s)?.combine(&self.mul(y0, c)?).ok()?;
        Some((l, r))
    }
}

/// The ring digest's decimal text and the challenge hash over it.
fn ring_digest(ring: &[PublicKey]) -> String {
    let keys: Vec<[u8; 33]> = ring.iter().map(PublicKey::serialize).collect();
    let parts: Vec<&[u8]> = keys.iter().map(<[u8; 33]>::as_slice).collect();
    decimal(&reduce(sha(&parts)))
}

fn challenge(digest: &str, y0: &[u8; 33], message: &[u8], l: &PublicKey, r: &PublicKey) -> Bytes32 {
    reduce(sha(&[
        digest.as_bytes(),
        y0,
        message,
        &l.serialize(),
        &r.serialize(),
    ]))
}

/// A nonce derived from the key, the message and the ring; `slot` separates the signer's commitment from
/// each decoy response.
fn nonce(key: &SecretKey, message: &[u8], digest: &str, identity: u32, slot: u32) -> Bytes32 {
    let mut counter = 0u32;
    loop {
        let k = sha(&[
            b"vortex-ng/joinstr/lsag",
            &key.secret_bytes(),
            message,
            digest.as_bytes(),
            &identity.to_be_bytes(),
            &slot.to_be_bytes(),
            &counter.to_be_bytes(),
        ]);
        if SecretKey::from_slice(&k).is_ok() {
            return k;
        }
        counter = counter.wrapping_add(1);
    }
}

/// Sign `message` as one member of the ring `keys` (any order; sorted here).
pub fn sign(message: &[u8], keys: &[PublicKey], key: &SecretKey) -> Result<Signature, LsagError> {
    let ctx = Ctx {
        secp: Secp256k1::new(),
    };
    let ring = sorted_ring(keys);
    let n = ring.len();
    if n == 0 {
        return Err(LsagError::EmptyRing);
    }
    let mine = key.public_key(&ctx.secp);
    let identity = ring
        .iter()
        .position(|p| *p == mine)
        .ok_or(LsagError::NotInRing)?;
    let x = key.secret_bytes();
    let hp = hash_to_point(&mine.serialize()).ok_or(LsagError::Degenerate)?;
    let y0_point = ctx.mul(&hp, &x).ok_or(LsagError::Degenerate)?;
    let y0 = y0_point.serialize();
    let digest = ring_digest(&ring);

    let u = nonce(key, message, &digest, identity as u32, identity as u32);
    let mut c = vec![[0u8; 32]; n];
    let mut s = vec![[0u8; 32]; n];
    let mut l = ctx.base(&u).ok_or(LsagError::Degenerate)?;
    let mut r = ctx.mul(&hp, &u).ok_or(LsagError::Degenerate)?;
    let mut idx = (identity + 1) % n;
    c[idx] = challenge(&digest, &y0, message, &l, &r);
    while idx != identity {
        s[idx] = nonce(key, message, &digest, identity as u32, idx as u32);
        (l, r) = ctx
            .step(&ring[idx], &s[idx], &c[idx], &y0_point)
            .ok_or(LsagError::Degenerate)?;
        idx = (idx + 1) % n;
        c[idx] = challenge(&digest, &y0, message, &l, &r);
    }
    // s = u - c * x (mod n)
    let c_scalar = Scalar::from_be_bytes(c[identity]).map_err(|_| LsagError::Degenerate)?;
    let u_scalar = Scalar::from_be_bytes(u).map_err(|_| LsagError::Degenerate)?;
    s[identity] = key
        .mul_tweak(&c_scalar)
        .map(SecretKey::negate)
        .and_then(|neg| neg.add_tweak(&u_scalar))
        .map_err(|_| LsagError::Degenerate)?
        .secret_bytes();

    Ok(Signature {
        y0: y0.iter().map(|b| format!("{b:02x}")).collect(),
        s: s.iter().map(py_hex).collect(),
        c: c.iter().map(py_hex).collect(),
    })
}

/// The key image of a signature in its one accepted spelling (a compressed point, lowercase hex), or
/// `None`. Signatures are linked by comparing this text, so no other spelling of the same point may pass.
pub fn canonical_key_image(y0: &str) -> Option<[u8; 33]> {
    if y0.len() != 66
        || !y0
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut bytes = [0u8; 33];
    for (i, pair) in y0.as_bytes().chunks(2).enumerate() {
        bytes[i] = ((pair[0] as char).to_digit(16)? * 16 + (pair[1] as char).to_digit(16)?) as u8;
    }
    PublicKey::from_slice(&bytes).ok().map(|p| p.serialize())
}

/// Whether `signature` is a valid ring signature of `message` under the ring `keys` (any order).
pub fn verify(message: &[u8], signature: &Signature, keys: &[PublicKey]) -> bool {
    let ctx = Ctx {
        secp: Secp256k1::new(),
    };
    let ring = sorted_ring(keys);
    let n = ring.len();
    if n == 0 || signature.s.len() != n || signature.c.len() != n {
        return false;
    }
    let Some(y0) = canonical_key_image(&signature.y0) else {
        return false;
    };
    let Ok(y0_point) = PublicKey::from_slice(&y0) else {
        return false;
    };
    let scalars = |texts: &[String]| {
        texts
            .iter()
            .map(|t| parse_scalar(t))
            .collect::<Option<Vec<_>>>()
    };
    let (Some(s), Some(c)) = (scalars(&signature.s), scalars(&signature.c)) else {
        return false;
    };
    let digest = ring_digest(&ring);
    (0..n).all(|i| {
        ctx.step(&ring[i], &s[i], &c[i], &y0_point)
            .is_some_and(|(l, r)| challenge(&digest, &y0, message, &l, &r) == c[(i + 1) % n])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn ring() -> Vec<PublicKey> {
        let secp = Secp256k1::new();
        [1, 2, 3]
            .iter()
            .map(|b| key(*b).public_key(&secp))
            .collect()
    }

    // From tools/ref-vectors/joinstr_lsag.py (independent, stdlib only).
    const MESSAGE_HEX: &str = "dd728d4d45b3a725745db6014a450f9c12c345c12d1ba6534b8fd3779f1ed4cd";
    const RING_SORTED: [&str; 3] = [
        "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766",
        "02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337",
        "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
    ];
    const HP_OF_KEY_1: &str = "0239d7af226da230c2a624c11be2c91a477d87f623008cd9152e2ad5efd0599cc6";
    const Y0: &str = "03e8f245289b5ae9138a2d25bc4a3812ac7f0562c10e34bc28e1a6364b2c87e747";
    const S: [&str; 3] = [
        "0x5023a329ef0ad5a0a883335a3e3877d8e870263eb62ce9d9889c36b6c6c4ed53",
        "0x69dfb4fb99ca635be0d87b1f577703dc1f59bbcab462c5250413c12a0ed2c1c4",
        "0x5ac93e608c28910145ad7e19fdb00b2d3b3e0686556f01593434a889a015d7c4",
    ];
    const C: [&str; 3] = [
        "0xa47ed5a0ea0fda39b1b91f4f0fbe1979e6621f51f34e2ef1c2b75d039d8a6fed",
        "0xbb0f85e369d4ef2d0e8703bcc04471b36b6dd9753c4b3ce54a7c609efb4dc9c4",
        "0x3f06f1e722f647f46a630ef54a256ca971606d88350d3a5b688ab5b655283430",
    ];
    const SIG_FIELD: &str = "eyJZMCI6ICIwM2U4ZjI0NTI4OWI1YWU5MTM4YTJkMjViYzRhMzgxMmFjN2YwNTYyYzEwZTM0YmMyOGUxYTYzNjRiMmM4N2U3NDciLCAiUyI6IFsiMHg1MDIzYTMyOWVmMGFkNWEwYTg4MzMzNWEzZTM4NzdkOGU4NzAyNjNlYjYyY2U5ZDk4ODljMzZiNmM2YzRlZDUzIiwgIjB4NjlkZmI0ZmI5OWNhNjM1YmUwZDg3YjFmNTc3NzAzZGMxZjU5YmJjYWI0NjJjNTI1MDQxM2MxMmEwZWQyYzFjNCIsICIweDVhYzkzZTYwOGMyODkxMDE0NWFkN2UxOWZkYjAwYjJkM2IzZTA2ODY1NTZmMDE1OTM0MzRhODg5YTAxNWQ3YzQiXSwgIkMiOiBbIjB4YTQ3ZWQ1YTBlYTBmZGEzOWIxYjkxZjRmMGZiZTE5NzllNjYyMWY1MWYzNGUyZWYxYzJiNzVkMDM5ZDhhNmZlZCIsICIweGJiMGY4NWUzNjlkNGVmMmQwZTg3MDNiY2MwNDQ3MWIzNmI2ZGQ5NzUzYzRiM2NlNTRhN2M2MDllZmI0ZGM5YzQiLCAiMHgzZjA2ZjFlNzIyZjY0N2Y0NmE2MzBlZjU0YTI1NmNhOTcxNjA2ZDg4MzUwZDNhNWI2ODhhYjViNjU1MjgzNDMwIl19";

    fn message() -> Vec<u8> {
        sha(&[b"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", b"pool1"]).to_vec()
    }

    fn hexs(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn the_pieces_match_the_reference() {
        assert_eq!(hexs(&message()), MESSAGE_HEX);
        let sorted: Vec<String> = sorted_ring(&ring())
            .iter()
            .map(|p| hexs(&p.serialize()))
            .collect();
        assert_eq!(sorted, RING_SORTED);
        let secp = Secp256k1::new();
        let hp = hash_to_point(&key(1).public_key(&secp).serialize()).unwrap();
        assert_eq!(hexs(&hp.serialize()), HP_OF_KEY_1);
    }

    #[test]
    fn a_signature_is_byte_identical_to_the_reference() {
        let sig = sign(&message(), &ring(), &key(2)).unwrap();
        assert_eq!(sig.y0, Y0);
        assert_eq!(sig.s, S);
        assert_eq!(sig.c, C);
        assert_eq!(sig.to_field(), SIG_FIELD);
        assert_eq!(Signature::from_field(SIG_FIELD), Some(sig.clone()));
        assert!(verify(&message(), &sig, &ring()));
        // The ring's order as given does not matter.
        let mut reversed = ring();
        reversed.reverse();
        assert!(verify(&message(), &sig, &reversed));
        assert_eq!(sign(&message(), &reversed, &key(2)).unwrap(), sig);
    }

    #[test]
    fn every_member_can_sign_and_one_key_links() {
        for byte in [1, 2, 3] {
            let sig = sign(&message(), &ring(), &key(byte)).unwrap();
            assert!(verify(&message(), &sig, &ring()), "{byte}");
            // Same key, another message: the same key image.
            assert_eq!(
                sign(b"another message", &ring(), &key(byte)).unwrap().y0,
                sig.y0
            );
        }
        let images: std::collections::HashSet<String> = [1, 2, 3]
            .iter()
            .map(|b| sign(&message(), &ring(), &key(*b)).unwrap().y0)
            .collect();
        assert_eq!(images.len(), 3);
        assert_eq!(
            sign(&message(), &ring(), &key(9)),
            Err(LsagError::NotInRing)
        );
        assert_eq!(sign(&message(), &[], &key(1)), Err(LsagError::EmptyRing));
    }

    #[test]
    fn forgeries_and_other_spellings_are_refused() {
        let sig = sign(&message(), &ring(), &key(2)).unwrap();
        assert!(!verify(b"other", &sig, &ring()));
        // Another ring.
        let secp = Secp256k1::new();
        let mut other = ring();
        other[0] = key(7).public_key(&secp);
        assert!(!verify(&message(), &sig, &other));
        // A tampered response, as the fuzzer's `tamper_s` does.
        let mut bad = sig.clone();
        bad.s[0] = format!("{}0", bad.s[0]);
        assert!(!verify(&message(), &bad, &ring()));
        let mut bad = sig.clone();
        bad.c.swap(0, 1);
        assert!(!verify(&message(), &bad, &ring()));
        // The key image in another spelling of the same point must not pass: it would link to nothing.
        let mut upper = sig.clone();
        upper.y0 = upper.y0.to_uppercase();
        assert!(!verify(&message(), &upper, &ring()));
        let mut spaced = sig.clone();
        spaced.y0 = format!(" {}", spaced.y0);
        assert!(!verify(&message(), &spaced, &ring()));
        // Scalars: zero, the order itself, and junk.
        for junk in [
            "0x0",
            "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            "zz",
            "",
        ] {
            let mut bad = sig.clone();
            bad.s[1] = junk.to_string();
            assert!(!verify(&message(), &bad, &ring()), "{junk}");
        }
        // Lengths.
        let mut short = sig.clone();
        short.s.pop();
        assert!(!verify(&message(), &short, &ring()));
        assert_eq!(Signature::from_field("not base64!"), None);
        assert_eq!(Signature::from_field(&STANDARD.encode("[1]")), None);
    }

    #[test]
    fn python_number_forms() {
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(py_hex(&one), "0x1");
        assert_eq!(py_hex(&[0u8; 32]), "0x0");
        assert_eq!(decimal(&one), "1");
        assert_eq!(decimal(&[0u8; 32]), "0");
        let mut big = [0u8; 32];
        big[30] = 1; // 256
        assert_eq!(decimal(&big), "256");
        assert_eq!(
            decimal(&[0xff; 32]),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
        // 2^256 - 1 mod n
        assert_eq!(
            hexs(&reduce([0xff; 32])),
            "000000000000000000000000000000014551231950b75fc4402da1732fc9bebe"
        );
        assert_eq!(parse_scalar(" 0X0A "), parse_scalar("a"));
        assert_eq!(parse_scalar("0x"), None);
    }
}
