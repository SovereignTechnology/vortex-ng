//! Spotting coins that came out of a Lightning channel close, from chain data alone.
//!
//! A wallet coin has a creating transaction. When that transaction spent a channel's funding output, or
//! swept one of the outputs a force close leaves behind, it carries BOLT 3's shapes in its inputs'
//! witnesses, and no node is needed to see them:
//!
//! | shape | where | what it says |
//! |---|---|---|
//! | one input spending `2 <K1> <K2> 2 CHECKMULTISIG` with `K1 < K2`, at most two outputs | mutual close | [`CloseKind::Cooperative`] |
//! | the same input, `nSequence` `0x80……` and `nLockTime` `0x20……` | commitment transaction | [`CloseKind::Unilateral`] |
//! | a witness whose last item is `to_local`'s delayed script, `to_remote`'s `1 CSV` script (anchor channels) or the anchor script | the sweep of a force close | [`CloseKind::Sweep`] |
//!
//! Simple taproot channels are seen where they are as plain as a script path (the sweeps) or carry the
//! commitment markers (a single Schnorr signature spending the funding output, `0x80`/`0x20`). A taproot
//! channel's mutual close is a lone key-path spend like any other and is NOT recognised here.
//!
//! This is evidence, not proof: a single-input 2-of-2 multisig spend by someone who is not a Lightning
//! node looks like a mutual close, and a node's own records (an LND `ClosedChannels` list) say more. The
//! wallet uses it to label coins and to let the user pick them, which cannot hurt: every such coin is
//! still the wallet's own.
//!
//! **The `wsh0` pit's script is BOLT 3's funding script byte for byte** (`script::wsh0_witness_script`), so
//! every input of a `wsh0` CoinJoin has the funding-spend witness. What keeps a CoinJoin from reading as a
//! close is the one-input rule: a close spends exactly one output, the funding output.

use bitcoin::Transaction;

/// What kind of channel close a transaction is, or sweeps the leftovers of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseKind {
    /// A mutual close: the funding output spent by one transaction that pays at most two outputs.
    Cooperative,
    /// A force close: the commitment transaction.
    Unilateral,
    /// The sweep of an output a force close left behind: the delayed `to_local`, an anchor channel's
    /// `to_remote`, an anchor, or the delayed output of an HTLC transaction.
    Sweep,
}

impl CloseKind {
    /// The kind in a sentence: "mutual close", "force close", "force-close sweep".
    pub fn describe(self) -> &'static str {
        match self {
            CloseKind::Cooperative => "mutual close",
            CloseKind::Unilateral => "force close",
            CloseKind::Sweep => "force-close sweep",
        }
    }
}

/// What [`classify`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloseEvidence {
    /// Which kind of close.
    pub kind: CloseKind,
    /// Whether it is a simple taproot channel's (script-path sweeps and commitment transactions only).
    pub taproot: bool,
}

impl std::fmt::Display for CloseEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}",
            self.kind.describe(),
            if self.taproot {
                " (taproot channel)"
            } else {
                ""
            }
        )
    }
}

/// A compressed public key: 33 bytes, `02` or `03` first. (Not checked to be on the curve: the shapes are
/// what is looked for, and a script that is not a real channel's gains nothing by faking one.)
fn is_key(bytes: &[u8]) -> bool {
    bytes.len() == 33 && matches!(bytes[0], 0x02 | 0x03)
}

/// The end of the minimal script-number push that starts at `at`: `OP_1`..`OP_16`, or a direct push of one
/// to three bytes (a `to_self_delay` of up to 2^23 blocks).
fn number_push_end(script: &[u8], at: usize) -> Option<usize> {
    let end = match *script.get(at)? {
        0x51..=0x60 => at + 1,
        n @ 1..=3 => at + 1 + usize::from(n),
        _ => return None,
    };
    (end <= script.len()).then_some(end)
}

/// BOLT 3's funding script, `OP_2 <K1> <K2> OP_2 OP_CHECKMULTISIG` with the keys in lexicographic order.
fn is_funding_script(script: &[u8]) -> bool {
    script.len() == 71
        && script[0] == 0x52
        && script[1] == 0x21
        && script[35] == 0x21
        && script[69] == 0x52
        && script[70] == 0xae
        && is_key(&script[2..35])
        && is_key(&script[36..69])
        && script[2..35] < script[36..69]
}

/// `to_local`: `OP_IF <revocationpubkey> OP_ELSE <to_self_delay> OP_CSV OP_DROP <delayedpubkey> OP_ENDIF
/// OP_CHECKSIG`.
fn is_delayed_script(script: &[u8]) -> bool {
    let Some(delay_end) = script
        .get(..36)
        .filter(|head| {
            head[0] == 0x63 && head[1] == 0x21 && is_key(&head[2..35]) && head[35] == 0x67
        })
        .and_then(|_| number_push_end(script, 36))
    else {
        return false;
    };
    let tail = &script[delay_end..];
    tail.len() == 38
        && tail[0] == 0xb2
        && tail[1] == 0x75
        && tail[2] == 0x21
        && is_key(&tail[3..36])
        && tail[36] == 0x68
        && tail[37] == 0xac
}

/// An anchor channel's `to_remote`: `<remotepubkey> OP_CHECKSIGVERIFY 1 OP_CSV`.
fn is_remote_anchor_script(script: &[u8]) -> bool {
    script.len() == 37
        && script[0] == 0x21
        && is_key(&script[1..34])
        && script[34..] == [0xad, 0x51, 0xb2]
}

/// An anchor output: `<funding_pubkey> OP_CHECKSIG OP_IFDUP OP_NOTIF OP_16 OP_CSV OP_ENDIF`.
fn is_anchor_script(script: &[u8]) -> bool {
    script.len() == 40
        && script[0] == 0x21
        && is_key(&script[1..34])
        && script[34..] == [0xac, 0x73, 0x64, 0x60, 0xb2, 0x68]
}

/// A simple taproot channel's delayed leaf: `<delayedpubkey> OP_CHECKSIG <to_self_delay> OP_CSV OP_DROP`,
/// which is also its `to_remote` leaf with a delay of one.
fn is_taproot_delayed_script(script: &[u8]) -> bool {
    script.len() > 33
        && script[0] == 0x20
        && script[33] == 0xac
        && number_push_end(script, 34).is_some_and(|end| script[end..] == [0xb2, 0x75])
}

/// A taproot control block: the leaf version `0xc0` (parity bit aside), the internal key, then hashes.
fn is_control_block(bytes: &[u8]) -> bool {
    bytes.len() >= 33 && (bytes.len() - 33) % 32 == 0 && bytes[0] & 0xfe == 0xc0
}

/// Whether one input's witness sweeps an output a force close left behind: `Some(taproot)` if it does.
fn sweep(witness: &bitcoin::Witness) -> Option<bool> {
    let items: Vec<&[u8]> = witness.iter().collect();
    match items.as_slice() {
        // `<sig> <> <to_local script>` (the delayed path) or `<sig> 1 <script>` (the revocation path).
        [_, selector, script] if selector.is_empty() || *selector == [1] => {
            is_delayed_script(script).then_some(false)
        }
        // `<sig> <to_remote script>` or `<sig> <anchor script>`.
        [_, script] => {
            (is_remote_anchor_script(script) || is_anchor_script(script)).then_some(false)
        }
        // A taproot leaf: `<sig> <leaf script> <control block>`.
        [_, script, control] => {
            (is_control_block(control) && is_taproot_delayed_script(script)).then_some(true)
        }
        _ => None,
    }
}

/// The funding output of a channel as a segwit v0 witness: `<> <sig> <sig> <funding script>`; or a simple
/// taproot channel's: one Schnorr signature. Returns whether the witness is a taproot one.
fn funding_witness(witness: &bitcoin::Witness) -> Option<bool> {
    let items: Vec<&[u8]> = witness.iter().collect();
    match items.as_slice() {
        [dummy, _, _, script] if dummy.is_empty() && is_funding_script(script) => Some(false),
        [sig] if matches!(sig.len(), 64 | 65) => Some(true),
        _ => None,
    }
}

/// BOLT 3's commitment-number obfuscation: `nSequence` has `0x80` in its top byte and `nLockTime` `0x20`.
fn has_commitment_markers(tx: &Transaction) -> bool {
    tx.lock_time.to_consensus_u32() >> 24 == 0x20
        && tx
            .input
            .first()
            .is_some_and(|input| input.sequence.to_consensus_u32() >> 24 == 0x80)
}

/// Whether `tx` is a channel close, or sweeps what one left behind. See the module documentation for what
/// is and is not recognised.
pub fn classify(tx: &Transaction) -> Option<CloseEvidence> {
    // A close spends exactly one output, the funding output: this is what keeps a `wsh0` CoinJoin (whose
    // inputs all have the funding witness) from being taken for one.
    if let [input] = tx.input.as_slice()
        && let Some(taproot) = funding_witness(&input.witness)
    {
        if has_commitment_markers(tx) {
            return Some(CloseEvidence {
                kind: CloseKind::Unilateral,
                taproot,
            });
        }
        // A taproot channel's mutual close is a lone key-path spend like any other: not recognised.
        if !taproot && (1..=2).contains(&tx.output.len()) {
            return Some(CloseEvidence {
                kind: CloseKind::Cooperative,
                taproot,
            });
        }
        return None;
    }
    let sweeps: Vec<bool> = tx
        .input
        .iter()
        .filter_map(|input| sweep(&input.witness))
        .collect();
    (!sweeps.is_empty()).then(|| CloseEvidence {
        kind: CloseKind::Sweep,
        taproot: sweeps.contains(&true),
    })
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid, Witness, absolute};

    use super::*;

    fn key(seed: u8) -> [u8; 33] {
        let secret = SecretKey::from_slice(&[seed; 32]).unwrap();
        PublicKey::from_secret_key(&Secp256k1::new(), &secret).serialize()
    }

    /// BOLT 3, "Funding Transaction Output": `2 <pubkey1> <pubkey2> 2 OP_CHECKMULTISIG`, sorted.
    fn funding_script(a: [u8; 33], b: [u8; 33]) -> Vec<u8> {
        let (first, second) = if a < b { (a, b) } else { (b, a) };
        let mut script = vec![0x52, 0x21];
        script.extend_from_slice(&first);
        script.push(0x21);
        script.extend_from_slice(&second);
        script.extend_from_slice(&[0x52, 0xae]);
        script
    }

    /// BOLT 3, `to_local`, with the delay as a minimal script number (`144` is `0x90 0x00`).
    fn to_local_script(delay: &[u8]) -> Vec<u8> {
        let mut script = vec![0x63, 0x21];
        script.extend_from_slice(&key(3));
        script.push(0x67);
        script.extend_from_slice(delay);
        script.extend_from_slice(&[0xb2, 0x75, 0x21]);
        script.extend_from_slice(&key(4));
        script.extend_from_slice(&[0x68, 0xac]);
        script
    }

    fn witness(items: &[&[u8]]) -> Witness {
        let mut w = Witness::new();
        for item in items {
            w.push(item);
        }
        w
    }

    fn tx(inputs: Vec<(Witness, u32)>, outputs: usize, lock_time: u32) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::from_consensus(lock_time),
            input: inputs
                .into_iter()
                .enumerate()
                .map(|(i, (witness, sequence))| TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([i as u8 + 1; 32]),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::from_consensus(sequence),
                    witness,
                })
                .collect(),
            output: (0..outputs)
                .map(|_| TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: ScriptBuf::new(),
                })
                .collect(),
        }
    }

    fn funding_input() -> Witness {
        let script = funding_script(key(1), key(2));
        witness(&[&[], &[0x30; 72], &[0x30; 71], &script])
    }

    fn kind(tx: &Transaction) -> Option<(CloseKind, bool)> {
        classify(tx).map(|e| (e.kind, e.taproot))
    }

    #[test]
    fn a_mutual_close_spends_the_funding_output_alone() {
        for outputs in [1, 2] {
            assert_eq!(
                kind(&tx(vec![(funding_input(), 0xffff_fffd)], outputs, 0)),
                Some((CloseKind::Cooperative, false)),
                "{outputs} outputs"
            );
        }
        // The same witness with three outputs is not a close, and with none either.
        for outputs in [0, 3] {
            assert_eq!(
                kind(&tx(vec![(funding_input(), 0xffff_fffd)], outputs, 0)),
                None
            );
        }
    }

    #[test]
    fn a_commitment_transaction_is_a_force_close() {
        // BOLT 3: nSequence = 0x80 << 24 | upper 24 bits of the obscured commitment number,
        // nLockTime = 0x20 << 24 | lower 24 bits.
        let force = tx(vec![(funding_input(), 0x8000_1234)], 4, 0x2000_5678);
        assert_eq!(kind(&force), Some((CloseKind::Unilateral, false)));
        // Half a marker is a mutual close shape, not a force close.
        let half = tx(vec![(funding_input(), 0x8000_1234)], 2, 0);
        assert_eq!(kind(&half), Some((CloseKind::Cooperative, false)));
        let half = tx(vec![(funding_input(), 0xffff_fffd)], 2, 0x2000_5678);
        assert_eq!(kind(&half), Some((CloseKind::Cooperative, false)));
    }

    #[test]
    fn a_taproot_commitment_is_a_force_close_and_nothing_else_is_seen() {
        let sig = [0x42u8; 64];
        let force = tx(vec![(witness(&[&sig]), 0x8000_0001)], 3, 0x2000_0002);
        assert_eq!(kind(&force), Some((CloseKind::Unilateral, true)));
        // A lone key-path spend without the markers is any taproot payment.
        assert_eq!(kind(&tx(vec![(witness(&[&sig]), 0xffff_fffd)], 2, 0)), None);
    }

    #[test]
    fn the_funding_script_must_be_bolt_3s() {
        // Keys out of order, a 2-of-3, a 1-of-2: ordinary multisigs, not a channel.
        let mut unsorted = funding_script(key(1), key(2));
        let (a, b) = (unsorted[2..35].to_vec(), unsorted[36..69].to_vec());
        unsorted[2..35].copy_from_slice(&b);
        unsorted[36..69].copy_from_slice(&a);
        let mut one_of_two = funding_script(key(1), key(2));
        one_of_two[0] = 0x51;
        for script in [unsorted, one_of_two] {
            let w = witness(&[&[], &[0x30; 72], &[0x30; 71], &script]);
            assert_eq!(kind(&tx(vec![(w, 0xffff_fffd)], 2, 0)), None);
        }
        // A first item that is not the empty dummy.
        let script = funding_script(key(1), key(2));
        let w = witness(&[&[0u8], &[0x30; 72], &[0x30; 71], &script]);
        assert_eq!(kind(&tx(vec![(w, 0xffff_fffd)], 2, 0)), None);
    }

    /// The `wsh0` pit's inputs have the funding witness, and a CoinJoin has many of them.
    #[test]
    fn a_wsh0_coinjoin_is_not_a_close() {
        let inputs = (0..4).map(|_| (funding_input(), 0xffff_ffff)).collect();
        assert_eq!(kind(&tx(inputs, 2, 0)), None);
        // Not even with the commitment markers on its first input.
        let inputs = (0..2).map(|_| (funding_input(), 0x8000_0000)).collect();
        assert_eq!(kind(&tx(inputs, 2, 0x2000_0000)), None);
    }

    #[test]
    fn sweeps_of_a_force_close() {
        // to_local, delay 144 (`0x90 0x00`), 2016, 6 (OP_6), and the revocation path (`1`).
        for (delay, label) in [
            (&[0x02, 0x90, 0x00][..], "144"),
            (&[0x02, 0xe0, 0x07][..], "2016"),
            (&[0x56][..], "OP_6"),
        ] {
            let script = to_local_script(delay);
            for selector in [&[][..], &[1][..]] {
                let w = witness(&[&[0x30; 71], selector, &script]);
                assert_eq!(
                    kind(&tx(vec![(w, 144)], 1, 0)),
                    Some((CloseKind::Sweep, false)),
                    "{label}"
                );
            }
        }
        // An anchor channel's to_remote: `<key> OP_CHECKSIGVERIFY 1 OP_CSV`.
        let mut remote = vec![0x21];
        remote.extend_from_slice(&key(5));
        remote.extend_from_slice(&[0xad, 0x51, 0xb2]);
        let w = witness(&[&[0x30; 71], &remote]);
        assert_eq!(
            kind(&tx(vec![(w, 1)], 1, 0)),
            Some((CloseKind::Sweep, false))
        );
        // An anchor: `<key> OP_CHECKSIG OP_IFDUP OP_NOTIF OP_16 OP_CSV OP_ENDIF`.
        let mut anchor = vec![0x21];
        anchor.extend_from_slice(&key(6));
        anchor.extend_from_slice(&[0xac, 0x73, 0x64, 0x60, 0xb2, 0x68]);
        let w = witness(&[&[0x30; 71], &anchor]);
        assert_eq!(
            kind(&tx(vec![(w, 0xffff_fffd)], 1, 0)),
            Some((CloseKind::Sweep, false))
        );
    }

    #[test]
    fn a_batched_sweep_counts_when_one_input_is() {
        let script = to_local_script(&[0x02, 0x90, 0x00]);
        let delayed = witness(&[&[0x30; 71], &[], &script]);
        let plain = witness(&[&[0x30; 71], &[0x02; 33]]);
        let batch = tx(vec![(plain, 0xffff_fffd), (delayed, 144)], 1, 0);
        assert_eq!(kind(&batch), Some((CloseKind::Sweep, false)));
    }

    #[test]
    fn a_taproot_channels_sweep() {
        let mut leaf = vec![0x20];
        leaf.extend_from_slice(&key(7)[1..]);
        leaf.extend_from_slice(&[0xac, 0x02, 0x90, 0x00, 0xb2, 0x75]);
        let control = [&[0xc1u8][..], &[9u8; 32][..]].concat();
        let w = witness(&[&[0x42; 64], &leaf, &control]);
        assert_eq!(
            kind(&tx(vec![(w, 144)], 1, 0)),
            Some((CloseKind::Sweep, true))
        );
        // A control block with another leaf version, or a truncated one, is not it.
        for bad in [[&[0xc2u8][..], &[9u8; 32][..]].concat(), vec![0xc0; 40]] {
            let w = witness(&[&[0x42; 64], &leaf, &bad]);
            assert_eq!(kind(&tx(vec![(w, 144)], 1, 0)), None);
        }
    }

    #[test]
    fn ordinary_transactions_are_not_closes() {
        // P2WPKH spend, P2TR key spend with two outputs, coinbase-like empty witness, and a witness that
        // ends in a script that merely starts like to_local.
        let p2wpkh = witness(&[&[0x30; 71], &[0x02; 33]]);
        assert_eq!(kind(&tx(vec![(p2wpkh, 0xffff_fffd)], 2, 0)), None);
        assert_eq!(kind(&tx(vec![(Witness::new(), 0xffff_ffff)], 1, 0)), None);
        let mut truncated = to_local_script(&[0x02, 0x90, 0x00]);
        truncated.truncate(truncated.len() - 1);
        let w = witness(&[&[0x30; 71], &[], &truncated]);
        assert_eq!(kind(&tx(vec![(w, 144)], 1, 0)), None);
        // The right shape with a push opcode for a delay that is not a number push.
        let w = witness(&[&[0x30; 71], &[], &to_local_script(&[0x4c, 0x01, 0x90])]);
        assert_eq!(kind(&tx(vec![(w, 144)], 1, 0)), None);
    }

    #[test]
    fn evidence_reads_as_a_sentence() {
        let force = CloseEvidence {
            kind: CloseKind::Unilateral,
            taproot: true,
        };
        assert_eq!(force.to_string(), "force close (taproot channel)");
        let mutual = CloseEvidence {
            kind: CloseKind::Cooperative,
            taproot: false,
        };
        assert_eq!(mutual.to_string(), "mutual close");
    }
}
