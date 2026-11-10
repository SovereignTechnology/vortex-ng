//! PoDLE: proof of discrete-log equivalence (JMP-0001 "PoDLE Algorithm").
//!
//! A taker commits at `!fill` to `SHA256(P2)` where `P = k·G` controls a UTXO and `P2 = k·J_i` for a
//! NUMS generator `J_i`, then reveals `utxo|P|P2|s|e` at `!auth`. For a `wsh0` UTXO the revelation has a
//! sixth field, the cosigner key (`docs/jmp/jmp-draft-wsh0-pit.md`). For a `tr0` UTXO the secret is the
//! parity-normalised BIP86 output secret ([`crate::script::taproot_output_secret`], JMP-0010).
//!
//! Proof nonces are deterministic, derived exactly as joinmarket-ng does (RFC 6979 with HMAC-SHA256 over
//! `SHA256("JoinMarket/PoDLE/nonce/v1" || len(utxo) || utxo || index || P || P2)`), so both produce
//! byte-identical proofs. The nonce is not part of the wire format; verification does not depend on it.

use std::sync::OnceLock;

use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::{Hash, HashEngine, sha256};
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::constants::{CURVE_ORDER, GENERATOR_X, GENERATOR_Y};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, Signing, Verification};
use bitcoin::{OutPoint, Script};

use crate::script::{Binding, binding_of};

/// The NUMS indices the deployed implementations permit by default, on both sides.
pub const DEFAULT_INDICES: [u8; 3] = [0, 1, 2];

/// Prefix of a PoDLE commitment in `!fill`.
pub const COMMITMENT_PREFIX: char = 'P';

const NONCE_DOMAIN: &[u8] = b"JoinMarket/PoDLE/nonce/v1";

/// Why a PoDLE could not be produced or did not verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PodleError {
    /// The revelation or commitment is not in the wire format.
    Malformed(&'static str),
    /// `SHA256(P2)` is not the commitment.
    CommitmentMismatch,
    /// The proof does not verify for any permitted index.
    InvalidProof,
    /// `P` (with the cosigner, if any) does not control the UTXO's scriptPubKey.
    BindingMismatch,
    /// No valid NUMS point for the index (never happens for 0..=255).
    NoNumsPoint,
    /// Deterministic nonce candidates were exhausted (negligible probability).
    NoncesExhausted,
}

impl std::fmt::Display for PodleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PodleError::Malformed(why) => write!(f, "malformed PoDLE: {why}"),
            PodleError::CommitmentMismatch => f.write_str("PoDLE commitment mismatch"),
            PodleError::InvalidProof => f.write_str("PoDLE proof invalid"),
            PodleError::BindingMismatch => f.write_str("PoDLE key does not control the UTXO"),
            PodleError::NoNumsPoint => f.write_str("no NUMS point for index"),
            PodleError::NoncesExhausted => f.write_str("PoDLE nonce candidates exhausted"),
        }
    }
}

impl std::error::Error for PodleError {}

fn sha256(data: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(data).to_byte_array()
}

/// `J_i`: for the seeds `ser_P(G)` then the uncompressed `G`, and counters 0..=255, the first
/// `0x02 || SHA256(seed || i || c)` that is a valid point.
fn derive_nums(index: u8) -> Option<PublicKey> {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02; // G has even Y
    compressed[1..].copy_from_slice(&GENERATOR_X);
    let mut uncompressed = [0u8; 65];
    uncompressed[0] = 0x04;
    uncompressed[1..33].copy_from_slice(&GENERATOR_X);
    uncompressed[33..].copy_from_slice(&GENERATOR_Y);
    for seed in [&compressed[..], &uncompressed[..]] {
        for counter in 0..=255u8 {
            let mut data = seed.to_vec();
            data.push(index);
            data.push(counter);
            let mut claimed = [0u8; 33];
            claimed[0] = 0x02;
            claimed[1..].copy_from_slice(&sha256(&data));
            if let Ok(point) = PublicKey::from_slice(&claimed) {
                return Some(point);
            }
        }
    }
    None
}

/// The NUMS generator `J_index`.
pub fn nums_point(index: u8) -> Result<PublicKey, PodleError> {
    static TABLE: OnceLock<Vec<Option<PublicKey>>> = OnceLock::new();
    TABLE.get_or_init(|| (0..=255u8).map(derive_nums).collect())[usize::from(index)]
        .ok_or(PodleError::NoNumsPoint)
}

/// `x mod n` for a 32-byte big-endian `x` (`x < 2^256 < 2n`, so one subtraction suffices).
fn reduce_mod_n(x: [u8; 32]) -> [u8; 32] {
    if x < CURVE_ORDER {
        return x;
    }
    let mut out = [0u8; 32];
    let mut borrow = 0u16;
    for ((o, &a), &b) in out.iter_mut().zip(x.iter()).zip(CURVE_ORDER.iter()).rev() {
        let d = 256 + u16::from(a) - u16::from(b) - borrow;
        *o = (d & 0xff) as u8;
        borrow = u16::from(d < 256);
    }
    out
}

/// Decode exactly `N` bytes of hex.
fn hex_array<const N: usize>(hex: &str) -> Option<[u8; N]> {
    Vec::<u8>::from_hex(hex).ok()?.try_into().ok()
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut engine = HmacEngine::<sha256::Hash>::new(key);
    for part in parts {
        engine.input(part);
    }
    Hmac::<sha256::Hash>::from_engine(engine).to_byte_array()
}

/// RFC 6979 nonce candidates (HMAC-SHA256, qlen 256) for `key` and a 32-byte message hash.
struct Rfc6979 {
    k: [u8; 32],
    v: [u8; 32],
    first: bool,
}

impl Rfc6979 {
    fn new(key: &[u8; 32], message_hash: &[u8; 32]) -> Self {
        let h1 = reduce_mod_n(*message_hash);
        let mut v = [0x01u8; 32];
        let mut k = [0x00u8; 32];
        k = hmac(&k, &[&v, &[0x00], key, &h1]);
        v = hmac(&k, &[&v]);
        k = hmac(&k, &[&v, &[0x01], key, &h1]);
        v = hmac(&k, &[&v]);
        Rfc6979 { k, v, first: true }
    }
}

impl Iterator for Rfc6979 {
    type Item = SecretKey;

    fn next(&mut self) -> Option<SecretKey> {
        loop {
            if !self.first {
                self.k = hmac(&self.k, &[&self.v, &[0x00]]);
                self.v = hmac(&self.k, &[&self.v]);
            }
            self.first = false;
            self.v = hmac(&self.k, &[&self.v]);
            // `from_slice` accepts exactly 1 <= candidate < n.
            if let Ok(candidate) = SecretKey::from_slice(&self.v) {
                return Some(candidate);
            }
        }
    }
}

/// A PoDLE proof: what `!auth` reveals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Podle {
    /// The committed UTXO as sent: `txid:vout`, or the `neutrino_compat` extended form.
    pub utxo: String,
    /// `P = k·G`.
    pub p: PublicKey,
    /// `P2 = k·J_i`.
    pub p2: PublicKey,
    /// The response `s`.
    pub s: [u8; 32],
    /// The challenge `e` as transmitted (a 32-byte hash).
    pub e: [u8; 32],
    /// For a `wsh0` UTXO, the other key of its 2-of-2.
    pub cosigner: Option<PublicKey>,
}

impl Podle {
    /// `SHA256(ser_P(P2))`.
    pub fn commitment(&self) -> [u8; 32] {
        sha256(&self.p2.serialize())
    }

    /// The `!fill` commitment: `P` followed by the lowercase hex commitment.
    pub fn commitment_string(&self) -> String {
        format!(
            "{COMMITMENT_PREFIX}{}",
            self.commitment().to_lower_hex_string()
        )
    }

    /// The `!auth` revelation: `utxo|P|P2|s|e`, plus `|C` for a `wsh0` UTXO.
    pub fn revelation(&self) -> String {
        let mut out = format!(
            "{}|{}|{}|{}|{}",
            self.utxo,
            self.p.serialize().to_lower_hex_string(),
            self.p2.serialize().to_lower_hex_string(),
            self.s.to_lower_hex_string(),
            self.e.to_lower_hex_string(),
        );
        if let Some(c) = &self.cosigner {
            out.push('|');
            out.push_str(&c.serialize().to_lower_hex_string());
        }
        out
    }

    /// Parse a five- or six-field revelation. Keys must be 33-byte compressed points.
    pub fn parse_revelation(revelation: &str) -> Result<Podle, PodleError> {
        let fields: Vec<&str> = revelation.split('|').collect();
        if fields.len() != 5 && fields.len() != 6 {
            return Err(PodleError::Malformed("revelation needs 5 or 6 fields"));
        }
        parse_utxo(fields[0])?;
        let key = |hex: &str| -> Result<PublicKey, PodleError> {
            let bytes: [u8; 33] = hex_array(hex).ok_or(PodleError::Malformed("key"))?;
            PublicKey::from_slice(&bytes).map_err(|_| PodleError::Malformed("key"))
        };
        let scalar = |hex: &str| -> Result<[u8; 32], PodleError> {
            hex_array(hex).ok_or(PodleError::Malformed("32-byte field"))
        };
        Ok(Podle {
            utxo: fields[0].to_string(),
            p: key(fields[1])?,
            p2: key(fields[2])?,
            s: scalar(fields[3])?,
            e: scalar(fields[4])?,
            cosigner: fields.get(5).map(|c| key(c)).transpose()?,
        })
    }

    /// The committed outpoint (the first two fields of the UTXO reference).
    pub fn outpoint(&self) -> Result<OutPoint, PodleError> {
        parse_utxo(&self.utxo)
    }

    /// Verify the proof against a `!fill` commitment for any index in `indices` (JMP-0001
    /// "Verification" steps 1 and 2). The UTXO binding is [`Podle::check_binding`].
    pub fn verify<C: Signing + Verification>(
        &self,
        secp: &Secp256k1<C>,
        commitment: &[u8; 32],
        indices: &[u8],
    ) -> Result<(), PodleError> {
        if &self.commitment() != commitment {
            return Err(PodleError::CommitmentMismatch);
        }
        // s must be in [1, n).
        let s = SecretKey::from_slice(&self.s).map_err(|_| PodleError::InvalidProof)?;
        let s_scalar = Scalar::from(s);
        let e =
            Scalar::from_be_bytes(reduce_mod_n(self.e)).map_err(|_| PodleError::InvalidProof)?;
        // Kg' = s·G - e·P; a zero e or an infinite result fails here.
        let kg = PublicKey::from_secret_key(secp, &s)
            .combine(
                &self
                    .p
                    .mul_tweak(secp, &e)
                    .map_err(|_| PodleError::InvalidProof)?
                    .negate(secp),
            )
            .map_err(|_| PodleError::InvalidProof)?;
        let minus_e_p2 = self
            .p2
            .mul_tweak(secp, &e)
            .map_err(|_| PodleError::InvalidProof)?
            .negate(secp);
        for &index in indices {
            let j = nums_point(index)?;
            let Ok(sj) = j.mul_tweak(secp, &s_scalar) else {
                continue;
            };
            let Ok(kj) = sj.combine(&minus_e_p2) else {
                continue;
            };
            let mut transcript = Vec::with_capacity(132);
            transcript.extend_from_slice(&kg.serialize());
            transcript.extend_from_slice(&kj.serialize());
            transcript.extend_from_slice(&self.p.serialize());
            transcript.extend_from_slice(&self.p2.serialize());
            if sha256(&transcript) == self.e {
                return Ok(());
            }
        }
        Err(PodleError::InvalidProof)
    }

    /// Check that `P` (with the cosigner for `wsh0`) controls the UTXO whose scriptPubKey is `spk`,
    /// returning how (JMP-0001 "Verification" step 3, JMP-0010, the `wsh0` draft). Which bindings a
    /// pit accepts is the maker's policy.
    pub fn check_binding(&self, spk: &Script) -> Result<Binding, PodleError> {
        binding_of(&self.p, self.cosigner.as_ref(), spk).ok_or(PodleError::BindingMismatch)
    }
}

/// Parse `txid:vout` or the extended `txid:vout:scriptpubkey:blockheight` (JMP-0002) into an outpoint.
pub fn parse_utxo(utxo: &str) -> Result<OutPoint, PodleError> {
    let mut parts = utxo.split(':');
    let (Some(txid), Some(vout)) = (parts.next(), parts.next()) else {
        return Err(PodleError::Malformed("utxo"));
    };
    let extra: Vec<&str> = parts.collect();
    match extra.as_slice() {
        [] => {}
        // JMP-0002 extended form: scriptPubKey hex and block height.
        [spk, height]
            if !spk.is_empty()
                && Vec::<u8>::from_hex(spk).is_ok()
                && !height.is_empty()
                && height.bytes().all(|b| b.is_ascii_digit())
                && height.parse::<u32>().is_ok() => {}
        _ => return Err(PodleError::Malformed("utxo")),
    }
    if txid.len() != 64 || !vout.bytes().all(|b| b.is_ascii_digit()) || vout.is_empty() {
        return Err(PodleError::Malformed("utxo"));
    }
    let txid = txid
        .parse()
        .map_err(|_| PodleError::Malformed("utxo txid"))?;
    let vout = vout
        .parse()
        .map_err(|_| PodleError::Malformed("utxo vout"))?;
    Ok(OutPoint { txid, vout })
}

/// Parse a `!fill` commitment (`P` + 64 hex) into its 32 bytes.
pub fn parse_commitment(commitment: &str) -> Result<[u8; 32], PodleError> {
    let hex = commitment
        .strip_prefix(COMMITMENT_PREFIX)
        .ok_or(PodleError::Malformed("commitment prefix"))?;
    hex_array(hex).ok_or(PodleError::Malformed("commitment"))
}

/// Generate a PoDLE for the UTXO `utxo` controlled by `key` (for `tr0`, pass the output secret from
/// [`crate::script::taproot_output_secret`]), at NUMS `index`; `cosigner` is set for a `wsh0` UTXO.
pub fn generate<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    key: &SecretKey,
    utxo: &str,
    index: u8,
    cosigner: Option<PublicKey>,
) -> Result<Podle, PodleError> {
    parse_utxo(utxo)?;
    let k = Scalar::from(*key);
    let p = PublicKey::from_secret_key(secp, key);
    let j = nums_point(index)?;
    let p2 = j
        .mul_tweak(secp, &k)
        .map_err(|_| PodleError::InvalidProof)?;
    let (p_ser, p2_ser) = (p.serialize(), p2.serialize());

    let utxo_bytes = utxo.as_bytes();
    let mut transcript = NONCE_DOMAIN.to_vec();
    transcript.extend_from_slice(&(utxo_bytes.len() as u32).to_be_bytes());
    transcript.extend_from_slice(utxo_bytes);
    transcript.push(index);
    transcript.extend_from_slice(&p_ser);
    transcript.extend_from_slice(&p2_ser);
    let nonces = Rfc6979::new(&key.secret_bytes(), &sha256(&transcript));

    // Retry on a zero challenge or zero response, as joinmarket-ng does; both have negligible probability.
    for nonce in nonces.take(1024) {
        let kg = PublicKey::from_secret_key(secp, &nonce);
        let Ok(kj) = j.mul_tweak(secp, &Scalar::from(nonce)) else {
            continue;
        };
        let mut data = Vec::with_capacity(132);
        data.extend_from_slice(&kg.serialize());
        data.extend_from_slice(&kj.serialize());
        data.extend_from_slice(&p_ser);
        data.extend_from_slice(&p2_ser);
        let e = sha256(&data);
        let Ok(e_scalar) = Scalar::from_be_bytes(reduce_mod_n(e)) else {
            continue;
        };
        // s = nonce + e·k (mod n); libsecp256k1 rejects a zero product or sum.
        let Ok(ek) = key.mul_tweak(&e_scalar) else {
            continue;
        };
        let Ok(s) = ek.add_tweak(&Scalar::from(nonce)) else {
            continue;
        };
        return Ok(Podle {
            utxo: utxo.to_string(),
            p,
            p2,
            s: s.secret_bytes(),
            e,
            cosigner,
        });
    }
    Err(PodleError::NoncesExhausted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::{taproot_output_secret, wsh0_script_pubkey};

    // JMP-0001 "NUMS Generators" and joinmarket-ng `jmcore/podle.py` NUMS_TEST_VECTORS.
    const NUMS_VECTORS: &[(u8, &str)] = &[
        (
            0,
            "0296f47ec8e6d6a9c3379c2ce983a6752bcfa88d46f2a6ffe0dd12c9ae76d01a1f",
        ),
        (
            1,
            "023f9976b86d3f1426638da600348d96dc1f1eb0bd5614cc50db9e9a067c0464a2",
        ),
        (
            5,
            "02bbc5c4393395a38446e2bd4d638b7bfd864afb5ffaf4bed4caf797df0e657434",
        ),
        (
            9,
            "021b739f21b981c2dcbaf9af4d89223a282939a92aee079e94a46c273759e5b42e",
        ),
        (
            100,
            "02aacc3145d04972d0527c4458629d328219feda92bef6ef6025878e3a252e105a",
        ),
        (
            255,
            "02a0a8694820c794852110e5939a2c03f8482f81ed57396042c6b34557f6eb430a",
        ),
    ];

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn utxo(c: char, vout: u32) -> String {
        format!("{}:{vout}", c.to_string().repeat(64))
    }

    /// (key byte, utxo char, vout, index, P, P2, s, e, commitment) from `tools/ref-vectors/ref.py`, an
    /// independent stdlib-only implementation of joinmarket-ng's deterministic PoDLE.
    /// (key byte, utxo char, vout, index, P, P2, s, e, commitment).
    type PodleVector = (
        u8,
        char,
        u32,
        u8,
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        &'static str,
    );

    const PODLE_VECTORS: &[PodleVector] = &[
        (
            1,
            'a',
            0,
            0,
            "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
            "0263c89959c452d2310684bc07b9f39d9f4d08a641e28e7ee0e6f69a27bc75dcbd",
            "5f797bca5efd07117e92be82d812dac9209b5971a5488ec6a4bb2d3406ff4e26",
            "2b155a1a8f0e1ac40c05f54f54de0ae2a1e17760fdf4c72f03d083ee1f5c96f6",
            "0699ef3695ee2050f6d0cfcdb8ef0b49d118d6b0b0bc9f56c8621639ad05bec6",
        ),
        (
            4,
            'd',
            3,
            4,
            "03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b",
            "02a69c446a98feeb0903026231d20e874939ca23c161939f31a21d67b3fa480d2a",
            "f3ce5a4c7a1420acee6d0eea54c0d1cea104f8d74969ec4aebc73d467f0e29b1",
            "2e56aa75033da9cb1141f8741a038a790b6d99fdb4ada8803156895f00e2b25b",
            "acbbe441935d9dc7a52fa198a0c5fb5a38be5ed4daf66767f4f98377ef7262e3",
        ),
        (
            5,
            'f',
            5,
            5,
            "0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7",
            "03354e3da299d46b8fc3b02d0f14a6eaf6d6e573ea7a5326a5bb4c00ed1ab8acfa",
            "1c58e2388907ff693d89d1000691b84286c43d0edcdaedaaa38c3948659a06ce",
            "6f11f2523f9cd2e113303bede15f3686b9700ee1e46627b66c05dbb3df9a0419",
            "716bec1415cf4b30562b25b4b8bce14a44f27a743e11bfacba6bdbe40cba7ac8",
        ),
        (
            2,
            'b',
            1,
            1,
            "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766",
            "03d8ae01483473cc3ec52904d8cfc22ff3046542d3073b56b658736af74ab5c44a",
            "f91fe8499525c262f08caade6d7f904a5a0e5cc6d118eefe857824f7a043b71c",
            "3d400b8efaad4a6c785559e8d11c400165dcb5c7d7726806729cb7d22b0f741d",
            "9efef58194b07d7f3e8b4bfdb3e5352825365f323e9e3fdca3541e7c33e00c1d",
        ),
    ];

    #[test]
    fn podle_matches_independent_reference() {
        let secp = Secp256k1::new();
        for (kb, c, vout, index, p, p2, s, e, commitment) in PODLE_VECTORS {
            let proof = generate(&secp, &key(*kb), &utxo(*c, *vout), *index, None).unwrap();
            assert_eq!(proof.p.serialize().to_lower_hex_string(), *p);
            assert_eq!(proof.p2.serialize().to_lower_hex_string(), *p2);
            assert_eq!(proof.s.to_lower_hex_string(), *s, "s for key {kb}");
            assert_eq!(proof.e.to_lower_hex_string(), *e, "e for key {kb}");
            assert_eq!(proof.commitment().to_lower_hex_string(), *commitment);
            proof.verify(&secp, &proof.commitment(), &[*index]).unwrap();
        }
    }

    #[test]
    fn nums_vectors() {
        for (index, hex) in NUMS_VECTORS {
            assert_eq!(
                nums_point(*index)
                    .unwrap()
                    .serialize()
                    .to_lower_hex_string(),
                *hex,
                "J_{index}"
            );
        }
        for index in 0..=255u8 {
            assert!(nums_point(index).is_ok());
        }
    }

    #[test]
    fn reduce_mod_n_works() {
        assert_eq!(reduce_mod_n([0u8; 32]), [0u8; 32]);
        assert_eq!(reduce_mod_n(CURVE_ORDER), [0u8; 32]);
        let mut n_plus_5 = CURVE_ORDER;
        n_plus_5[31] += 5;
        let mut five = [0u8; 32];
        five[31] = 5;
        assert_eq!(reduce_mod_n(n_plus_5), five);
        assert_eq!(reduce_mod_n([0xff; 32]).len(), 32);
        assert!(reduce_mod_n([0xff; 32]) < CURVE_ORDER);
    }

    #[test]
    fn generate_verify_round_trip_and_binding() {
        let secp = Secp256k1::new();
        let sk = key(1);
        for index in DEFAULT_INDICES {
            let proof = generate(&secp, &sk, &utxo('a', 0), index, None).unwrap();
            let commitment = parse_commitment(&proof.commitment_string()).unwrap();
            let parsed = Podle::parse_revelation(&proof.revelation()).unwrap();
            assert_eq!(parsed, proof);
            parsed.verify(&secp, &commitment, &DEFAULT_INDICES).unwrap();
            let wpkh = bitcoin::ScriptBuf::new_p2wpkh(
                &bitcoin::CompressedPublicKey(proof.p).wpubkey_hash(),
            );
            assert_eq!(parsed.check_binding(&wpkh), Ok(Binding::P2wpkh));
        }
    }

    #[test]
    fn deterministic_and_bound_to_utxo() {
        let secp = Secp256k1::new();
        let a = generate(&secp, &key(4), &utxo('d', 3), 4, None).unwrap();
        assert_eq!(a, generate(&secp, &key(4), &utxo('d', 3), 4, None).unwrap());
        let b = generate(&secp, &key(4), &utxo('e', 3), 4, None).unwrap();
        assert_eq!((a.p, a.p2, a.commitment()), (b.p, b.p2, b.commitment()));
        assert_ne!((a.s, a.e), (b.s, b.e));
    }

    #[test]
    fn verification_failures() {
        let secp = Secp256k1::new();
        let proof = generate(&secp, &key(2), &utxo('b', 1), 1, None).unwrap();
        let commitment = proof.commitment();
        // Wrong commitment.
        assert_eq!(
            proof.verify(&secp, &[0u8; 32], &DEFAULT_INDICES),
            Err(PodleError::CommitmentMismatch)
        );
        // Index not permitted.
        assert_eq!(
            proof.verify(&secp, &commitment, &[0, 2]),
            Err(PodleError::InvalidProof)
        );
        // Tampered s and e.
        let mut bad = proof.clone();
        bad.s[31] ^= 1;
        assert_eq!(
            bad.verify(&secp, &commitment, &DEFAULT_INDICES),
            Err(PodleError::InvalidProof)
        );
        let mut bad = proof.clone();
        bad.e[0] ^= 1;
        assert_eq!(
            bad.verify(&secp, &commitment, &DEFAULT_INDICES),
            Err(PodleError::InvalidProof)
        );
        // s = 0 and s >= n.
        let mut bad = proof.clone();
        bad.s = [0u8; 32];
        assert_eq!(
            bad.verify(&secp, &commitment, &DEFAULT_INDICES),
            Err(PodleError::InvalidProof)
        );
        let mut bad = proof.clone();
        bad.s = CURVE_ORDER;
        assert_eq!(
            bad.verify(&secp, &commitment, &DEFAULT_INDICES),
            Err(PodleError::InvalidProof)
        );
        // A P that is not k·G for the same k (another key's P with this P2).
        let mut bad = proof.clone();
        bad.p = PublicKey::from_secret_key(&secp, &key(9));
        assert_eq!(
            bad.verify(&secp, &commitment, &DEFAULT_INDICES),
            Err(PodleError::InvalidProof)
        );
    }

    #[test]
    fn taproot_podle_binds_bip86_output() {
        let secp = Secp256k1::new();
        let internal = key(3);
        let e = taproot_output_secret(&secp, &internal);
        let proof = generate(&secp, &e, &utxo('c', 2), 0, None).unwrap();
        proof
            .verify(&secp, &proof.commitment(), &DEFAULT_INDICES)
            .unwrap();
        let (xonly, _) = internal.x_only_public_key(&secp);
        let spk =
            bitcoin::Address::p2tr(&secp, xonly, None, bitcoin::KnownHrp::Mainnet).script_pubkey();
        assert_eq!(proof.check_binding(&spk), Ok(Binding::P2trOutputKey));
        // The untweaked internal key does not bind.
        let raw = generate(&secp, &internal, &utxo('c', 2), 0, None).unwrap();
        assert_eq!(raw.check_binding(&spk), Err(PodleError::BindingMismatch));
    }

    #[test]
    fn wsh0_podle_six_fields() {
        let secp = Secp256k1::new();
        let cosigner = PublicKey::from_secret_key(&secp, &key(6));
        let proof = generate(&secp, &key(5), &utxo('f', 5), 2, Some(cosigner)).unwrap();
        let revelation = proof.revelation();
        assert_eq!(revelation.split('|').count(), 6);
        let parsed = Podle::parse_revelation(&revelation).unwrap();
        parsed
            .verify(&secp, &proof.commitment(), &DEFAULT_INDICES)
            .unwrap();
        let spk = wsh0_script_pubkey(&parsed.p, &cosigner).unwrap();
        assert_eq!(parsed.check_binding(&spk), Ok(Binding::Wsh0));
        let other =
            wsh0_script_pubkey(&parsed.p, &PublicKey::from_secret_key(&secp, &key(7))).unwrap();
        assert_eq!(
            parsed.check_binding(&other),
            Err(PodleError::BindingMismatch)
        );
    }

    #[test]
    fn malformed_inputs() {
        let secp = Secp256k1::new();
        let good = generate(&secp, &key(1), &utxo('a', 0), 0, None)
            .unwrap()
            .revelation();
        let fields: Vec<&str> = good.split('|').collect();
        for bad in [
            String::new(),
            fields[..4].join("|"),
            format!("{good}|{}|x", fields[1]),
            good.replacen(fields[0], "zz:0", 1),
            good.replacen(fields[0], &format!("{}:", "a".repeat(64)), 1),
            good.replacen(fields[1], &fields[1][..64], 1),
            good.replacen(fields[3], "00", 1),
        ] {
            assert!(Podle::parse_revelation(&bad).is_err(), "{bad}");
        }
        assert!(parse_utxo(&format!("{}:0:0014aa:100", "a".repeat(64))).is_ok());
        assert!(parse_utxo(&format!("{}:0:extra", "a".repeat(64))).is_err());
        assert!(parse_utxo(&format!("{}:0:zz:100", "a".repeat(64))).is_err());
        assert!(parse_utxo(&format!("{}:0:0014aa:-1", "a".repeat(64))).is_err());
        assert!(parse_utxo(&format!("{}:0:0014aa:", "a".repeat(64))).is_err());
        assert!(parse_utxo(&format!("{}:4294967296", "a".repeat(64))).is_err());
        assert!(parse_commitment("Q00").is_err());
        assert!(parse_commitment(&format!("P{}", "ab".repeat(32))).is_ok());
    }
}
