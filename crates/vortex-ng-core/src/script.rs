//! Output scripts the pits use, and the key ↔ scriptPubKey bindings PoDLE and `!ioauth` check.

use bitcoin::key::TapTweak;
use bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_1, OP_PUSHNUM_2};
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey, Signing, Verification};
use bitcoin::{CompressedPublicKey, Script, ScriptBuf};

/// The `wsh0` witness script for two keys: `OP_2 <K1> <K2> OP_2 OP_CHECKMULTISIG` with `K1 < K2`
/// lexicographically, which is also BOLT 3's channel funding script. `None` if the keys are equal.
pub fn wsh0_witness_script(a: &PublicKey, b: &PublicKey) -> Option<ScriptBuf> {
    let (first, second) = match a.serialize().cmp(&b.serialize()) {
        std::cmp::Ordering::Less => (a, b),
        std::cmp::Ordering::Greater => (b, a),
        std::cmp::Ordering::Equal => return None,
    };
    Some(
        Builder::new()
            .push_opcode(OP_PUSHNUM_2)
            .push_key(&bitcoin::PublicKey::new(*first))
            .push_key(&bitcoin::PublicKey::new(*second))
            .push_opcode(OP_PUSHNUM_2)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script(),
    )
}

/// The P2WSH scriptPubKey of the `wsh0` script of two keys.
pub fn wsh0_script_pubkey(a: &PublicKey, b: &PublicKey) -> Option<ScriptBuf> {
    wsh0_witness_script(a, b).map(|ws| ScriptBuf::new_p2wsh(&ws.wscript_hash()))
}

/// The parity-normalised BIP86 output secret `e` for an internal secret key (JMP-0010 "Taproot PoDLE
/// Binding"): normalise the internal key to even Y, add the BIP341 TapTweak (no Merkle root), then
/// normalise the output key to even Y. `e·G` is the output key with an even Y coordinate.
pub fn taproot_output_secret<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    internal: &SecretKey,
) -> SecretKey {
    // `tap_tweak` negates the internal secret when its key has odd Y (libsecp256k1's
    // keypair_xonly_tweak_add), then adds the tweak.
    let tweaked = Keypair::from_secret_key(secp, internal)
        .tap_tweak(secp, None)
        .to_keypair();
    let (_, parity) = tweaked.x_only_public_key();
    let q = tweaked.secret_key();
    match parity {
        bitcoin::secp256k1::Parity::Even => q,
        bitcoin::secp256k1::Parity::Odd => q.negate(),
    }
}

/// How a public key `P` controls an output, as a PoDLE or `!ioauth` binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    /// P2WPKH of `P` (`sw0`).
    P2wpkh,
    /// P2SH-wrapped P2WPKH of `P` (accepted by JMP-0001 for PoDLE).
    P2shP2wpkh,
    /// P2PKH of `P` (accepted by JMP-0001 for PoDLE).
    P2pkh,
    /// P2TR whose output key is `P`, which must have even Y (JMP-0010).
    P2trOutputKey,
    /// P2WSH of the `wsh0` script of `P` and a cosigner key (`wsh0` draft).
    Wsh0,
}

/// Which binding, if any, makes `spk` controlled by `p` (and, for `wsh0`, the `cosigner`).
pub fn binding_of(p: &PublicKey, cosigner: Option<&PublicKey>, spk: &Script) -> Option<Binding> {
    if let Some(c) = cosigner {
        return (wsh0_script_pubkey(p, c).as_deref() == Some(spk)).then_some(Binding::Wsh0);
    }
    let compressed = CompressedPublicKey(*p);
    let p2wpkh = ScriptBuf::new_p2wpkh(&compressed.wpubkey_hash());
    if spk == p2wpkh.as_script() {
        return Some(Binding::P2wpkh);
    }
    if spk == ScriptBuf::new_p2sh(&p2wpkh.script_hash()).as_script() {
        return Some(Binding::P2shP2wpkh);
    }
    if spk == ScriptBuf::new_p2pkh(&compressed.pubkey_hash()).as_script() {
        return Some(Binding::P2pkh);
    }
    let ser = p.serialize();
    if ser[0] == 0x02 {
        let mut p2tr = vec![OP_PUSHNUM_1.to_u8(), 0x20];
        p2tr.extend_from_slice(&ser[1..]);
        if spk.as_bytes() == p2tr.as_slice() {
            return Some(Binding::P2trOutputKey);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use bitcoin::hex::DisplayHex;
    use bitcoin::{Address, KnownHrp};

    use super::*;

    fn pk(secp: &Secp256k1<bitcoin::secp256k1::All>, byte: u8) -> PublicKey {
        PublicKey::from_secret_key(secp, &SecretKey::from_slice(&[byte; 32]).unwrap())
    }

    #[test]
    fn wsh0_script_is_sorted_and_symmetric() {
        let secp = Secp256k1::new();
        let (a, b) = (pk(&secp, 1), pk(&secp, 2));
        let ab = wsh0_witness_script(&a, &b).unwrap();
        assert_eq!(Some(ab.clone()), wsh0_witness_script(&b, &a));
        let bytes = ab.as_bytes();
        assert_eq!(bytes.len(), 71);
        assert_eq!((bytes[0], bytes[69], bytes[70]), (0x52, 0x52, 0xae));
        assert!(bytes[2..35] < bytes[36..69]);
        assert!(wsh0_witness_script(&a, &a).is_none());
    }

    #[test]
    fn bindings() {
        let secp = Secp256k1::new();
        let (p, c) = (pk(&secp, 1), pk(&secp, 2));
        let cp = CompressedPublicKey(p);
        let wpkh = ScriptBuf::new_p2wpkh(&cp.wpubkey_hash());
        assert_eq!(binding_of(&p, None, &wpkh), Some(Binding::P2wpkh));
        assert_eq!(
            binding_of(&p, None, &ScriptBuf::new_p2sh(&wpkh.script_hash())),
            Some(Binding::P2shP2wpkh)
        );
        assert_eq!(
            binding_of(&p, None, &ScriptBuf::new_p2pkh(&cp.pubkey_hash())),
            Some(Binding::P2pkh)
        );
        let wsh = wsh0_script_pubkey(&p, &c).unwrap();
        assert_eq!(binding_of(&p, Some(&c), &wsh), Some(Binding::Wsh0));
        assert_eq!(binding_of(&c, Some(&p), &wsh), Some(Binding::Wsh0));
        assert_eq!(binding_of(&p, None, &wsh), None);
        assert_eq!(binding_of(&p, Some(&c), &wpkh), None);
        assert_eq!(binding_of(&pk(&secp, 3), None, &wpkh), None);
    }

    #[test]
    fn taproot_output_secret_matches_independent_reference() {
        // From `tools/ref-vectors/ref.py` (JMP-0010's two normalisations in pure Python).
        let secp = Secp256k1::new();
        for (kb, secret, output_key) in [
            (
                3u8,
                "1826eb18dfdd68e63028666b8d3ae430edc0eb5e155eb265d93feb2c1ab27784",
                "02d3a0d82bbfae272329e54e3b3410efc98646eaf06b7b6bf7cadceee05ba1447e",
            ),
            (
                8u8,
                "2f6481402b8512ce448a4eb69b9e7b8ff804717dee7e34dcee2e7d43361a2834",
                "02268fcfbdc8529b6d6d540fe8ee57aa60f0b90684c594eb5ce582a0f2d6f77a50",
            ),
        ] {
            let e = taproot_output_secret(&secp, &SecretKey::from_slice(&[kb; 32]).unwrap());
            assert_eq!(e.secret_bytes().to_lower_hex_string(), secret);
            assert_eq!(
                PublicKey::from_secret_key(&secp, &e)
                    .serialize()
                    .to_lower_hex_string(),
                output_key
            );
        }
    }

    #[test]
    fn taproot_output_secret_matches_bip86_address() {
        let secp = Secp256k1::new();
        for byte in 1..=8u8 {
            let internal = SecretKey::from_slice(&[byte; 32]).unwrap();
            let e = taproot_output_secret(&secp, &internal);
            let q = PublicKey::from_secret_key(&secp, &e);
            assert_eq!(q.serialize()[0], 0x02, "output key must have even Y");
            let (xonly, _) = internal.x_only_public_key(&secp);
            let bip86 = Address::p2tr(&secp, xonly, None, KnownHrp::Mainnet).script_pubkey();
            assert_eq!(binding_of(&q, None, &bip86), Some(Binding::P2trOutputKey));
            assert_eq!(
                &bip86.as_bytes()[2..],
                &q.serialize()[1..],
                "{}",
                q.serialize().to_lower_hex_string()
            );
        }
    }
}
