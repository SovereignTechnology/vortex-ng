//! The transactions of a pool (RULES.md R6, R7): each peer's registration PSBT and the combined coinjoin.
//!
//! A registration is one input, the peer's coin, signed `SIGHASH_ALL | SIGHASH_ANYONECANPAY` over the
//! pool's outputs. That signature stays valid whatever inputs are added beside it, so anyone holding every
//! registration can assemble the transaction, and a registration is public to the whole pool. Two
//! consequences shape this module: every registration must sign exactly the same outputs in the same order
//! (the template), and a peer never signs a registration its own coin could pay for alone, since anyone who
//! read it could broadcast it and keep the difference.

use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, CompressedPublicKey, EcdsaSighashType, OutPoint, Psbt, Script, ScriptBuf, Sequence,
    TapSighashType, Transaction, TxIn, TxOut, Witness, ecdsa, taproot,
};

use crate::message::PoolMessage;
use crate::rules;

/// R6.2: the nSequence of a registration's input.
pub const REGISTRATION_SEQUENCE: Sequence = Sequence(0xffff_fffe);
/// The sighash byte of a registration signature, `SIGHASH_ALL | SIGHASH_ANYONECANPAY`.
pub const REGISTRATION_SIGHASH: u8 = 0x81;

/// Why a registration or a combined transaction is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxError {
    /// Our own output is not among the pool's outputs, or the outputs are not `peers` equal amounts.
    Template(&'static str),
    /// Our coin would pay for every output by itself: the registration could be broadcast alone (R6.6).
    Solvent,
    /// The key does not control the coin, or the coin's script type cannot be registered.
    Key(&'static str),
    /// The PSBT cannot be read, or is not a registration (R6.1, R6.2, R6.4).
    Registration(&'static str),
    /// The registration signs other outputs than the pool's template (R7.2).
    Outputs,
    /// The registration's signature does not verify.
    Signature,
    /// The combined transaction breaks a rule (R7): what.
    Combine(&'static str),
}

impl std::fmt::Display for TxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxError::Template(why) => write!(f, "pool outputs refused: {why}"),
            TxError::Solvent => f.write_str("our coin alone would pay for every output"),
            TxError::Key(why) => write!(f, "cannot sign the coin: {why}"),
            TxError::Registration(why) => write!(f, "not a registration: {why}"),
            TxError::Outputs => f.write_str("registration signs different outputs"),
            TxError::Signature => f.write_str("registration signature does not verify"),
            TxError::Combine(why) => write!(f, "combined transaction refused: {why}"),
        }
    }
}

impl std::error::Error for TxError {}

/// R6.3: the pool's outputs in BIP69 order, by value and then by scriptPubKey bytes (not by address text:
/// the bech32 alphabet is not in byte order). Every output pays `output_sats`.
pub fn template(scripts: &[ScriptBuf], output_sats: u64) -> Vec<TxOut> {
    let mut outputs: Vec<TxOut> = scripts
        .iter()
        .map(|script| TxOut {
            value: Amount::from_sat(output_sats),
            script_pubkey: script.clone(),
        })
        .collect();
    outputs.sort_by(|a, b| {
        (a.value, a.script_pubkey.as_bytes()).cmp(&(b.value, b.script_pubkey.as_bytes()))
    });
    outputs
}

fn registration_tx(coin: OutPoint, sequence: Sequence, outputs: &[TxOut]) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: coin,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        }],
        output: outputs.to_vec(),
    }
}

fn p2tr_key(script: &Script) -> Option<XOnlyPublicKey> {
    if !script.is_p2tr() {
        return None;
    }
    XOnlyPublicKey::from_slice(script.as_bytes().get(2..34)?).ok()
}

fn ecdsa_digest(tx: &Transaction, coin: &TxOut) -> Option<Message> {
    let hash = SighashCache::new(tx)
        .p2wpkh_signature_hash(
            0,
            &coin.script_pubkey,
            coin.value,
            EcdsaSighashType::AllPlusAnyoneCanPay,
        )
        .ok()?;
    Some(Message::from_digest(hash.to_byte_array()))
}

fn taproot_digest(tx: &Transaction, coin: &TxOut) -> Option<Message> {
    let hash = SighashCache::new(tx)
        .taproot_key_spend_signature_hash(
            0,
            &Prevouts::One(0, coin),
            TapSighashType::AllPlusAnyoneCanPay,
        )
        .ok()?;
    Some(Message::from_digest(hash.to_byte_array()))
}

/// R6: our registration for the pool's `template` (from [`template`]), spending `coin` (`coin_txout`) with
/// `key`: the coin's private key for P2WPKH, the taproot output key's secret for a P2TR key spend.
///
/// Refused unless `my_script` is one of `peers` equal outputs, and unless the outputs cost more than our
/// coin holds (R6.6). The result is finalized: `witness_utxo`, the final witness and an empty final
/// scriptSig, with no derivation paths, partial signatures or sighash field for peers to fingerprint.
pub fn build_registration(
    coin: OutPoint,
    coin_txout: &TxOut,
    template: &[TxOut],
    my_script: &Script,
    peers: u32,
    key: &SecretKey,
) -> Result<Psbt, TxError> {
    let Some(first) = template.first() else {
        return Err(TxError::Template("no outputs"));
    };
    if template.len() != peers as usize {
        return Err(TxError::Template("not one output per peer"));
    }
    if template.iter().any(|o| o.value != first.value) {
        return Err(TxError::Template("outputs are not equal"));
    }
    if !template
        .iter()
        .any(|o| o.script_pubkey.as_script() == my_script)
    {
        return Err(TxError::Template("our output is missing"));
    }
    let total: Amount = template.iter().map(|o| o.value).sum();
    if total < coin_txout.value {
        return Err(TxError::Solvent);
    }

    let secp = Secp256k1::new();
    let tx = registration_tx(coin, REGISTRATION_SEQUENCE, template);
    let script = &coin_txout.script_pubkey;
    let witness = if script.is_p2wpkh() {
        let public = key.public_key(&secp);
        if ScriptBuf::new_p2wpkh(&CompressedPublicKey(public).wpubkey_hash()) != *script {
            return Err(TxError::Key("not the coin's key"));
        }
        let digest = ecdsa_digest(&tx, coin_txout).ok_or(TxError::Key("sighash"))?;
        let signature = ecdsa::Signature {
            signature: secp.sign_ecdsa(&digest, key),
            sighash_type: EcdsaSighashType::AllPlusAnyoneCanPay,
        };
        Witness::p2wpkh(&signature, &public)
    } else if let Some(output_key) = p2tr_key(script) {
        let pair = Keypair::from_secret_key(&secp, key);
        if pair.x_only_public_key().0 != output_key {
            return Err(TxError::Key("not the coin's output key"));
        }
        let digest = taproot_digest(&tx, coin_txout).ok_or(TxError::Key("sighash"))?;
        let signature = taproot::Signature {
            signature: secp.sign_schnorr_no_aux_rand(&digest, &pair),
            sighash_type: TapSighashType::AllPlusAnyoneCanPay,
        };
        Witness::p2tr_key_spend(&signature)
    } else {
        return Err(TxError::Key("only P2WPKH and P2TR coins can be registered"));
    };

    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|_| TxError::Key("psbt"))?;
    psbt.inputs[0].witness_utxo = Some(coin_txout.clone());
    psbt.inputs[0].final_script_witness = Some(witness);
    // R6.5: Electrum releases without spesmilo/electrum#10987 count the input as signed only with this.
    psbt.inputs[0].final_script_sig = Some(ScriptBuf::new());
    Ok(psbt)
}

/// A registration a combiner has read and checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    /// The coin it spends.
    pub outpoint: OutPoint,
    /// The nSequence it was signed with, which the combined input must keep.
    pub sequence: Sequence,
    /// The coin's output (`witness_utxo`).
    pub coin: TxOut,
    /// The final witness.
    pub witness: Witness,
    /// The outputs it signs.
    pub outputs: Vec<TxOut>,
}

/// R6, R7.2: read a registration PSBT (base64). It must be one input with `witness_utxo` and a final
/// witness, version 2, locktime 0; a final scriptSig may be absent or empty (R6.5). With the pool's
/// `template` it must sign exactly those outputs in order; without one (inputs seen before the outputs are
/// settled) its own outputs are taken, and [`combine`] holds every registration to one template later.
/// P2WPKH and P2TR key-spend signatures are verified and must carry the `ALL | ANYONECANPAY` byte; other
/// script types are passed through for the node to judge.
pub fn read_registration(
    psbt_base64: &str,
    template: Option<&[TxOut]>,
) -> Result<Registration, TxError> {
    let psbt =
        Psbt::from_str(psbt_base64.trim()).map_err(|_| TxError::Registration("unreadable PSBT"))?;
    let tx = &psbt.unsigned_tx;
    let (Some(txin), Some(input), 1) = (tx.input.first(), psbt.inputs.first(), tx.input.len())
    else {
        return Err(TxError::Registration("not exactly one input"));
    };
    if tx.version != Version::TWO || tx.lock_time != LockTime::ZERO {
        return Err(TxError::Registration("not version 2 with locktime 0"));
    }
    if template.is_some_and(|t| tx.output != t) {
        return Err(TxError::Outputs);
    }
    let outputs = tx.output.as_slice();
    let coin = input
        .witness_utxo
        .clone()
        .ok_or(TxError::Registration("no witness_utxo"))?;
    let witness = input
        .final_script_witness
        .clone()
        .filter(|w| !w.is_empty())
        .ok_or(TxError::Registration("not finalized"))?;
    if input
        .final_script_sig
        .as_ref()
        .is_some_and(|s| !s.is_empty())
    {
        return Err(TxError::Registration("a scriptSig on a segwit coin"));
    }

    let secp = Secp256k1::verification_only();
    let signed = registration_tx(txin.previous_output, txin.sequence, outputs);
    let script = &coin.script_pubkey;
    if script.is_p2wpkh() {
        let (Some(sig), Some(public), 2) = (witness.nth(0), witness.nth(1), witness.len()) else {
            return Err(TxError::Signature);
        };
        let public = CompressedPublicKey::from_slice(public).map_err(|_| TxError::Signature)?;
        let signature = ecdsa::Signature::from_slice(sig).map_err(|_| TxError::Signature)?;
        if ScriptBuf::new_p2wpkh(&public.wpubkey_hash()) != *script
            || signature.sighash_type != EcdsaSighashType::AllPlusAnyoneCanPay
        {
            return Err(TxError::Signature);
        }
        let digest = ecdsa_digest(&signed, &coin).ok_or(TxError::Signature)?;
        secp.verify_ecdsa(&digest, &signature.signature, &public.0)
            .map_err(|_| TxError::Signature)?;
    } else if let Some(output_key) = p2tr_key(script) {
        // A key spend: one element, 65 bytes with the sighash byte. Script-path spends are passed through.
        if let (Some(sig), 1) = (witness.nth(0), witness.len()) {
            let signature = taproot::Signature::from_slice(sig).map_err(|_| TxError::Signature)?;
            if signature.sighash_type != TapSighashType::AllPlusAnyoneCanPay {
                return Err(TxError::Signature);
            }
            let digest = taproot_digest(&signed, &coin).ok_or(TxError::Signature)?;
            secp.verify_schnorr(&signature.signature, &digest, &output_key)
                .map_err(|_| TxError::Signature)?;
        }
    }
    Ok(Registration {
        outpoint: txin.previous_output,
        sequence: txin.sequence,
        coin,
        witness,
        outputs: outputs.to_vec(),
    })
}

/// The pool's terms a combiner checks registrations against.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Terms {
    /// The denomination in BTC, as announced.
    pub denomination: f64,
    /// How many peers the pool takes.
    pub peers: u32,
}

/// R4, R5.4: the registrations a pool accepts from its decrypted channel messages, in arrival order, each
/// with the PSBT text as sent: `input` messages whose PSBT [`read_registration`] accepts (for `template`
/// when the outputs are settled), whose coin is in the input window and within the cost cap, each coin
/// once, the first `peers`. Anything else is skipped.
pub fn collect_inputs<'a>(
    plaintexts: impl IntoIterator<Item = &'a str>,
    template: Option<&[TxOut]>,
    terms: Terms,
) -> Vec<(String, Registration)> {
    let mut accepted: Vec<(String, Registration)> = Vec::new();
    for text in plaintexts {
        if accepted.len() >= terms.peers as usize {
            break;
        }
        let Some(PoolMessage::Input { psbt }) = PoolMessage::parse(text) else {
            continue;
        };
        let Ok(registration) = read_registration(&psbt, template) else {
            continue;
        };
        let output_sats = registration.outputs.first().map_or(0, |o| o.value.to_sat());
        let coin_sats = registration.coin.value.to_sat();
        if rules::check_input(coin_sats, terms.denomination, output_sats).is_err()
            || accepted
                .iter()
                .any(|(_, r)| r.outpoint == registration.outpoint)
        {
            continue;
        }
        accepted.push((psbt, registration));
    }
    accepted
}

/// R7: the coinjoin from the pool's registrations. Inputs go in BIP69 order (txid as displayed, then vout),
/// each with the nSequence and witness it was registered with; outputs are the template, untouched. Refused
/// when there are fewer inputs than outputs, when a scriptPubKey is spent twice or is also paid (address
/// reuse undoes the coinjoin), when the inputs do not cover the outputs, and, with `fee_bounds`, when the
/// fee is outside 100 to 10,000 sats per input (R7.4; regtest pools skip it, as the reference does).
pub fn combine(
    registrations: &[Registration],
    template: &[TxOut],
    fee_bounds: bool,
) -> Result<Transaction, TxError> {
    let mut inputs: Vec<&Registration> = Vec::new();
    for registration in registrations {
        if registration.outputs != template {
            return Err(TxError::Outputs);
        }
        if !inputs.iter().any(|r| r.outpoint == registration.outpoint) {
            inputs.push(registration);
        }
    }
    if template.is_empty() || inputs.len() < template.len() {
        return Err(TxError::Combine("fewer inputs than outputs"));
    }
    for (i, a) in inputs.iter().enumerate() {
        if inputs[..i]
            .iter()
            .any(|b| b.coin.script_pubkey == a.coin.script_pubkey)
        {
            return Err(TxError::Combine("two inputs spend the same scriptPubKey"));
        }
        if template
            .iter()
            .any(|o| o.script_pubkey == a.coin.script_pubkey)
        {
            return Err(TxError::Combine("an output pays a spent scriptPubKey"));
        }
    }
    for (i, a) in template.iter().enumerate() {
        if template[..i]
            .iter()
            .any(|b| b.script_pubkey == a.script_pubkey)
        {
            return Err(TxError::Combine("two outputs pay the same scriptPubKey"));
        }
    }
    let paid_in: u64 = inputs.iter().map(|r| r.coin.value.to_sat()).sum();
    let paid_out: u64 = template.iter().map(|o| o.value.to_sat()).sum();
    if paid_in <= paid_out {
        return Err(TxError::Combine("inputs do not exceed outputs"));
    }
    if fee_bounds && !rules::fee_in_bounds(paid_in - paid_out, inputs.len()) {
        return Err(TxError::Combine("fee outside 100 to 10000 sats per input"));
    }
    inputs.sort_by_key(|r| (r.outpoint.txid.to_string(), r.outpoint.vout));
    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs
            .iter()
            .map(|r| TxIn {
                previous_output: r.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: r.sequence,
                witness: r.witness.clone(),
            })
            .collect(),
        output: template.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use bitcoin::key::TapTweak;
    use bitcoin::{Address, Network, Txid};

    use super::*;

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn p2wpkh(k: &SecretKey) -> ScriptBuf {
        let public = CompressedPublicKey(k.public_key(&Secp256k1::new()));
        Address::p2wpkh(&public, Network::Regtest).script_pubkey()
    }

    /// A BIP86-style coin: its scriptPubKey and the output key's secret.
    fn p2tr(k: &SecretKey) -> (ScriptBuf, SecretKey) {
        let secp = Secp256k1::new();
        let tweaked = Keypair::from_secret_key(&secp, k)
            .tap_tweak(&secp, None)
            .to_keypair();
        (
            ScriptBuf::new_p2tr_tweaked(tweaked.x_only_public_key().0.dangerous_assume_tweaked()),
            tweaked.secret_key(),
        )
    }

    fn outpoint(byte: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([byte; 32]),
            vout,
        }
    }

    const DENOM: f64 = 0.001;
    const OUT: u64 = 99_750; // 0.001 BTC at 2.5 sat/vB with 3 peers
    const TERMS: Terms = Terms {
        denomination: DENOM,
        peers: 3,
    };

    /// Three peers: two P2WPKH coins and one P2TR coin, each paying to a fresh P2WPKH output.
    struct Pool {
        template: Vec<TxOut>,
        coins: Vec<(OutPoint, TxOut, SecretKey)>,
        mine: Vec<ScriptBuf>,
    }

    fn pool() -> Pool {
        let mine: Vec<ScriptBuf> = (1..=3).map(|i| p2wpkh(&key(100 + i))).collect();
        let (tr_script, tr_secret) = p2tr(&key(3));
        let coins = vec![
            (
                outpoint(0xbb, 1),
                TxOut {
                    value: Amount::from_sat(100_500),
                    script_pubkey: p2wpkh(&key(1)),
                },
                key(1),
            ),
            (
                outpoint(0xaa, 7),
                TxOut {
                    value: Amount::from_sat(105_000),
                    script_pubkey: p2wpkh(&key(2)),
                },
                key(2),
            ),
            (
                outpoint(0xaa, 2),
                TxOut {
                    value: Amount::from_sat(101_000),
                    script_pubkey: tr_script,
                },
                tr_secret,
            ),
        ];
        Pool {
            template: template(&mine, OUT),
            coins,
            mine,
        }
    }

    fn registrations(pool: &Pool) -> Vec<String> {
        pool.coins
            .iter()
            .zip(&pool.mine)
            .map(|((op, txout, k), script)| {
                build_registration(*op, txout, &pool.template, script, 3, k)
                    .unwrap()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn the_template_is_in_bip69_order_by_script_bytes() {
        let pool = pool();
        let scripts: Vec<&[u8]> = pool
            .template
            .iter()
            .map(|o| o.script_pubkey.as_bytes())
            .collect();
        let mut sorted = scripts.clone();
        sorted.sort();
        assert_eq!(scripts, sorted);
        assert!(pool.template.iter().all(|o| o.value.to_sat() == OUT));
        // Whatever order the outputs were registered in, every peer builds the same template.
        let mut shuffled = pool.mine.clone();
        shuffled.reverse();
        assert_eq!(template(&shuffled, OUT), pool.template);
    }

    #[test]
    fn a_registration_has_the_shape_the_rules_fix() {
        let pool = pool();
        for text in registrations(&pool) {
            let psbt = Psbt::from_str(&text).unwrap();
            let tx = &psbt.unsigned_tx;
            assert_eq!(
                (tx.version, tx.lock_time, tx.input.len()),
                (Version::TWO, LockTime::ZERO, 1)
            );
            assert_eq!(tx.input[0].sequence, Sequence(0xffff_fffe));
            assert_eq!(tx.output, pool.template);
            let input = &psbt.inputs[0];
            assert!(input.witness_utxo.is_some());
            assert_eq!(
                input.final_script_sig,
                Some(ScriptBuf::new()),
                "empty final scriptSig, key 0x07"
            );
            assert!(input.partial_sigs.is_empty() && input.sighash_type.is_none());
            assert!(input.bip32_derivation.is_empty() && input.tap_key_origins.is_empty());
            let sig = input.final_script_witness.as_ref().unwrap().nth(0).unwrap();
            assert_eq!(*sig.last().unwrap(), REGISTRATION_SIGHASH);
        }
    }

    #[test]
    fn a_peer_refuses_registrations_that_would_lose_its_coin() {
        let pool = pool();
        let (op, txout, k) = pool.coins[0].clone();
        let build = |template: &[TxOut], script: &ScriptBuf, peers, coin: &TxOut, k: &SecretKey| {
            build_registration(op, coin, template, script, peers, k).unwrap_err()
        };
        // Our output missing, unequal outputs, or not one per peer.
        assert_eq!(
            build(&pool.template, &p2wpkh(&key(50)), 3, &txout, &k),
            TxError::Template("our output is missing")
        );
        let mut unequal = pool.template.clone();
        unequal[0].value = Amount::from_sat(OUT - 1);
        assert_eq!(
            build(&unequal, &pool.mine[0], 3, &txout, &k),
            TxError::Template("outputs are not equal")
        );
        assert_eq!(
            build(&pool.template, &pool.mine[0], 4, &txout, &k),
            TxError::Template("not one output per peer")
        );
        // A coin that covers every output alone: anyone could broadcast the registration by itself.
        let rich = TxOut {
            value: Amount::from_sat(3 * OUT + 1),
            script_pubkey: txout.script_pubkey.clone(),
        };
        assert_eq!(
            build(&pool.template, &pool.mine[0], 3, &rich, &k),
            TxError::Solvent
        );
        // Somebody else's key.
        assert_eq!(
            build(&pool.template, &pool.mine[0], 3, &txout, &key(77)),
            TxError::Key("not the coin's key")
        );
    }

    #[test]
    fn registrations_combine_into_one_transaction_in_bip69_order() {
        let pool = pool();
        let texts = registrations(&pool);
        let messages: Vec<String> = texts
            .iter()
            .map(|p| PoolMessage::Input { psbt: p.clone() }.to_plaintext())
            .collect();
        let collected = collect_inputs(
            messages.iter().map(String::as_str),
            Some(&pool.template),
            TERMS,
        );
        assert_eq!(collected.len(), 3);
        // The PSBT text comes back as it was sent.
        assert!(
            collected
                .iter()
                .zip(&texts)
                .all(|((sent, _), text)| sent == text)
        );
        let accepted: Vec<Registration> = collected.into_iter().map(|(_, r)| r).collect();
        // Before the outputs are settled the same registrations are collected without a template.
        assert_eq!(
            collect_inputs(messages.iter().map(String::as_str), None, TERMS).len(),
            3
        );
        let tx = combine(&accepted, &pool.template, true).unwrap();
        // Displayed txid then vout: aa..:2, aa..:7, bb..:1.
        let order: Vec<OutPoint> = tx.input.iter().map(|i| i.previous_output).collect();
        assert_eq!(
            order,
            [outpoint(0xaa, 2), outpoint(0xaa, 7), outpoint(0xbb, 1)]
        );
        assert_eq!(tx.output, pool.template);
        assert!(
            tx.input
                .iter()
                .all(|i| i.sequence == REGISTRATION_SEQUENCE && !i.witness.is_empty())
        );
        // Any arrival order gives the same transaction.
        let mut reversed = accepted.clone();
        reversed.reverse();
        assert_eq!(
            combine(&reversed, &pool.template, true)
                .unwrap()
                .compute_txid(),
            tx.compute_txid()
        );
        // Each signature still verifies inside the combined transaction: ANYONECANPAY does not commit to
        // the other inputs or to the input's position.
        for (i, input) in tx.input.iter().enumerate() {
            let reg = accepted
                .iter()
                .find(|r| r.outpoint == input.previous_output)
                .unwrap();
            let mut cache = SighashCache::new(&tx);
            if reg.coin.script_pubkey.is_p2wpkh() {
                let hash = cache
                    .p2wpkh_signature_hash(
                        i,
                        &reg.coin.script_pubkey,
                        reg.coin.value,
                        EcdsaSighashType::AllPlusAnyoneCanPay,
                    )
                    .unwrap();
                let sig = ecdsa::Signature::from_slice(input.witness.nth(0).unwrap()).unwrap();
                let public =
                    CompressedPublicKey::from_slice(input.witness.nth(1).unwrap()).unwrap();
                Secp256k1::new()
                    .verify_ecdsa(
                        &Message::from_digest(hash.to_byte_array()),
                        &sig.signature,
                        &public.0,
                    )
                    .unwrap();
            } else {
                let hash = cache
                    .taproot_key_spend_signature_hash(
                        i,
                        &Prevouts::One(i, &reg.coin),
                        TapSighashType::AllPlusAnyoneCanPay,
                    )
                    .unwrap();
                let sig = taproot::Signature::from_slice(input.witness.nth(0).unwrap()).unwrap();
                Secp256k1::new()
                    .verify_schnorr(
                        &sig.signature,
                        &Message::from_digest(hash.to_byte_array()),
                        &p2tr_key(&reg.coin.script_pubkey).unwrap(),
                    )
                    .unwrap();
            }
        }
    }

    #[test]
    fn a_combiner_refuses_what_cannot_make_a_valid_coinjoin() {
        let pool = pool();
        let texts = registrations(&pool);
        // Signed over other outputs: refused, never merged.
        let other = template(
            &[pool.mine[0].clone(), pool.mine[1].clone(), p2wpkh(&key(60))],
            OUT,
        );
        assert_eq!(
            read_registration(&texts[0], Some(&other)),
            Err(TxError::Outputs)
        );
        // A flipped signature byte, and a plain SIGHASH_ALL signature.
        let mut psbt = Psbt::from_str(&texts[0]).unwrap();
        let mut items: Vec<Vec<u8>> = psbt.inputs[0]
            .final_script_witness
            .as_ref()
            .unwrap()
            .iter()
            .map(<[u8]>::to_vec)
            .collect();
        items[0][10] ^= 1;
        psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&items));
        assert_eq!(
            read_registration(&psbt.to_string(), Some(&pool.template)),
            Err(TxError::Signature)
        );
        items[0][10] ^= 1;
        *items[0].last_mut().unwrap() = 0x01;
        psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&items));
        assert_eq!(
            read_registration(&psbt.to_string(), Some(&pool.template)),
            Err(TxError::Signature)
        );
        // Not finalized, and not a PSBT.
        psbt.inputs[0].final_script_witness = None;
        assert_eq!(
            read_registration(&psbt.to_string(), Some(&pool.template)),
            Err(TxError::Registration("not finalized"))
        );
        assert_eq!(
            read_registration("cHNidP8=", Some(&pool.template)),
            Err(TxError::Registration("unreadable PSBT"))
        );
        // A registration without the empty final scriptSig is accepted too (R6.5).
        let mut bare = Psbt::from_str(&texts[1]).unwrap();
        bare.inputs[0].final_script_sig = None;
        assert!(read_registration(&bare.to_string(), Some(&pool.template)).is_ok());

        // Collected without a template, a registration over other outputs is still refused at combine.
        let stray = read_registration(&texts[0], None).unwrap();
        assert_eq!(
            combine(std::slice::from_ref(&stray), &other, true),
            Err(TxError::Outputs)
        );
        let regs: Vec<Registration> = texts
            .iter()
            .map(|t| read_registration(t, Some(&pool.template)).unwrap())
            .collect();
        assert_eq!(
            combine(&regs[..2], &pool.template, true),
            Err(TxError::Combine("fewer inputs than outputs"))
        );
        // The same coin twice is one input.
        let twice = [regs[0].clone(), regs[0].clone(), regs[1].clone()];
        assert_eq!(
            combine(&twice, &pool.template, true),
            Err(TxError::Combine("fewer inputs than outputs"))
        );
        // The fee bound: 6,000 sats over three inputs is fine; a pool paying 40,000 is not.
        let mut costly = regs.clone();
        costly[0].coin.value = Amount::from_sat(140_000);
        assert_eq!(
            combine(&costly, &pool.template, true),
            Err(TxError::Combine("fee outside 100 to 10000 sats per input"))
        );
        assert!(combine(&costly, &pool.template, false).is_ok());
    }

    #[test]
    fn inputs_outside_the_window_and_reused_addresses_are_refused() {
        let pool = pool();
        let (op, _, k) = pool.coins[0].clone();
        // A coin worth less than the denomination plus 500 is not collected.
        let small = TxOut {
            value: Amount::from_sat(100_499),
            script_pubkey: p2wpkh(&k),
        };
        let psbt = build_registration(op, &small, &pool.template, &pool.mine[0], 3, &k)
            .unwrap()
            .to_string();
        let msg = PoolMessage::Input { psbt }.to_plaintext();
        assert!(collect_inputs([msg.as_str()], Some(&pool.template), TERMS).is_empty());
        // Junk between good messages is skipped; only `peers` are taken.
        let good: Vec<String> = registrations(&pool)
            .into_iter()
            .map(|p| PoolMessage::Input { psbt: p }.to_plaintext())
            .collect();
        let stream = [
            "junk",
            good[0].as_str(),
            r#"{"type": "input", "psbt": "AAAA"}"#,
            good[0].as_str(),
            good[1].as_str(),
            good[2].as_str(),
        ];
        assert_eq!(collect_inputs(stream, Some(&pool.template), TERMS).len(), 3);
        // An input spending the script one of the outputs pays: address reuse.
        let reuse_coin = TxOut {
            value: Amount::from_sat(100_500),
            script_pubkey: pool.mine[1].clone(),
        };
        let reuse = build_registration(
            outpoint(0xcc, 0),
            &reuse_coin,
            &pool.template,
            &pool.mine[1],
            3,
            &key(102),
        )
        .unwrap();
        let mut regs: Vec<Registration> = registrations(&pool)
            .iter()
            .map(|t| read_registration(t, Some(&pool.template)).unwrap())
            .collect();
        regs[2] = read_registration(&reuse.to_string(), Some(&pool.template)).unwrap();
        assert_eq!(
            combine(&regs, &pool.template, true),
            Err(TxError::Combine("an output pays a spent scriptPubKey"))
        );
    }
}
