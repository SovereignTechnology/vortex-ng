//! The maker's check of an unsigned CoinJoin transaction before signing.
//!
//! joinmarket-ng's `maker/tx_verification.py` (`verify_unsigned_transaction`, documented in
//! `docs/technical/maker-verification-checklist.md`) at the pinned main, plus PR #643's locktime guard,
//! plus the pit rules of JMP-0010 (`tr0`) and the `wsh0` draft: every output, and every input's prevout,
//! of the pit's script family, and a non-negative fee once every prevout is known. Two further checks a
//! correct taker never trips: no duplicate inputs, and distinct coinjoin and change scripts.
//!
//! Profit follows the code, not the checklist's wording: `cjfee - txfee` must not be negative (the code
//! accepts zero, which zero-fee offers rely on).

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::{OutPoint, Script, Transaction, TxOut};

use crate::offer::Pit;

/// nLockTime values below this are block heights; at or above, Unix times.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;
/// How far past our tip a height locktime may be (PR #643).
pub const LOCKTIME_HEIGHT_TOLERANCE: u32 = 12;
/// How far into the future a time locktime may be, seconds (PR #643).
pub const LOCKTIME_TIME_TOLERANCE: u64 = 2 * 60 * 60;

/// What the maker agreed to in this session.
#[derive(Clone, Copy, Debug)]
pub struct MakerTerms<'a> {
    /// The pit of the offer that was filled.
    pub pit: Pit,
    /// The UTXOs the maker declared in `!ioauth`, with their prevouts.
    pub our_utxos: &'a BTreeMap<OutPoint, TxOut>,
    /// The maker's coinjoin output script.
    pub cj_script: &'a Script,
    /// The maker's change output script.
    pub change_script: &'a Script,
    /// The coinjoin amount, satoshis.
    pub amount: u64,
    /// The coinjoin fee for this amount, satoshis (`Offer::fee_for`).
    pub cjfee: u64,
    /// The maker's mining-fee contribution, satoshis.
    pub txfee: u64,
}

/// The maker's view of the chain when it checks.
#[derive(Clone, Copy, Debug)]
pub struct ChainView {
    /// Our chain tip, if known. Unknown rejects any height locktime (fail closed, as PR #643).
    pub tip_height: Option<u32>,
    /// Current Unix time, seconds.
    pub now: u64,
}

/// Why the maker refuses to sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxError {
    /// Version not 1, 2 or 3.
    Version(i32),
    /// No inputs or no outputs.
    Empty,
    /// The same outpoint is spent twice.
    DuplicateInput(OutPoint),
    /// The locktime could strand our inputs.
    Locktime(u32),
    /// One of our declared UTXOs is not an input.
    MissingOurInput(OutPoint),
    /// One of our inputs already carries a signature.
    OurInputSigned(OutPoint),
    /// `cjfee < txfee`.
    NegativeProfit,
    /// Our inputs cannot pay the amount and our fee contribution.
    InsufficientInputs,
    /// Our coinjoin and change scripts are the same.
    SameScripts,
    /// Our coinjoin output appears this many times (must be once).
    CjOutputCount(usize),
    /// Our coinjoin output is below the amount.
    CjOutputTooLow,
    /// Our change output appears this many times (must be once).
    ChangeOutputCount(usize),
    /// Our change output is below what we are owed.
    ChangeTooLow,
    /// An output is not of the pit's script family.
    ForeignOutput(usize),
    /// An input's prevout is unknown, and the pit needs every prevout.
    MissingPrevout(OutPoint),
    /// An input's prevout is not of the pit's script family.
    ForeignInput(OutPoint),
    /// Outputs exceed inputs.
    NegativeFee,
    /// An amount overflowed.
    Overflow,
}

impl std::fmt::Display for TxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "refusing to sign: {self:?}")
    }
}

impl std::error::Error for TxError {}

fn in_family(pit: Pit, script: &Script) -> bool {
    match pit {
        Pit::Sw0 => true,
        Pit::Tr0 => script.is_p2tr(),
        Pit::Wsh0 => script.is_p2wsh(),
    }
}

fn check_locktime(locktime: u32, chain: &ChainView) -> Result<(), TxError> {
    if locktime == 0 {
        return Ok(());
    }
    if locktime < LOCKTIME_THRESHOLD {
        let tip = chain.tip_height.ok_or(TxError::Locktime(locktime))?;
        if locktime > tip.saturating_add(LOCKTIME_HEIGHT_TOLERANCE) {
            return Err(TxError::Locktime(locktime));
        }
        return Ok(());
    }
    if u64::from(locktime) > chain.now.saturating_add(LOCKTIME_TIME_TOLERANCE) {
        return Err(TxError::Locktime(locktime));
    }
    Ok(())
}

/// Check an unsigned CoinJoin transaction against what the maker agreed to. `prevouts` holds known
/// prevouts of other participants' inputs; `tr0` and `wsh0` need every input's prevout.
pub fn verify_unsigned(
    tx: &Transaction,
    terms: &MakerTerms<'_>,
    prevouts: &BTreeMap<OutPoint, TxOut>,
    chain: &ChainView,
) -> Result<(), TxError> {
    let version = tx.version.0;
    if !(1..=3).contains(&version) {
        return Err(TxError::Version(version));
    }
    if tx.input.is_empty() || tx.output.is_empty() {
        return Err(TxError::Empty);
    }
    let mut seen = BTreeSet::new();
    for input in &tx.input {
        if !seen.insert(input.previous_output) {
            return Err(TxError::DuplicateInput(input.previous_output));
        }
    }
    check_locktime(tx.lock_time.to_consensus_u32(), chain)?;

    for outpoint in terms.our_utxos.keys() {
        let input = tx
            .input
            .iter()
            .find(|i| i.previous_output == *outpoint)
            .ok_or(TxError::MissingOurInput(*outpoint))?;
        if !input.script_sig.is_empty() || !input.witness.is_empty() {
            return Err(TxError::OurInputSigned(*outpoint));
        }
    }

    if terms.cjfee < terms.txfee {
        return Err(TxError::NegativeProfit);
    }
    let our_total = terms
        .our_utxos
        .values()
        .try_fold(0u64, |acc, o| acc.checked_add(o.value.to_sat()))
        .ok_or(TxError::Overflow)?;
    let expected_change =
        i128::from(our_total) - i128::from(terms.amount) - i128::from(terms.txfee)
            + i128::from(terms.cjfee);
    if expected_change < 0 {
        return Err(TxError::InsufficientInputs);
    }
    if terms.cj_script == terms.change_script {
        return Err(TxError::SameScripts);
    }

    let cj: Vec<&TxOut> = tx
        .output
        .iter()
        .filter(|o| o.script_pubkey.as_script() == terms.cj_script)
        .collect();
    if cj.len() != 1 {
        return Err(TxError::CjOutputCount(cj.len()));
    }
    if cj[0].value.to_sat() < terms.amount {
        return Err(TxError::CjOutputTooLow);
    }
    let change: Vec<&TxOut> = tx
        .output
        .iter()
        .filter(|o| o.script_pubkey.as_script() == terms.change_script)
        .collect();
    if change.len() != 1 {
        return Err(TxError::ChangeOutputCount(change.len()));
    }
    if i128::from(change[0].value.to_sat()) < expected_change {
        return Err(TxError::ChangeTooLow);
    }

    if let Some(index) = tx
        .output
        .iter()
        .position(|o| !in_family(terms.pit, &o.script_pubkey))
    {
        return Err(TxError::ForeignOutput(index));
    }
    if terms.pit != Pit::Sw0 {
        let mut total_in = 0u64;
        for input in &tx.input {
            let op = input.previous_output;
            let prevout = terms
                .our_utxos
                .get(&op)
                .or_else(|| prevouts.get(&op))
                .ok_or(TxError::MissingPrevout(op))?;
            if !in_family(terms.pit, &prevout.script_pubkey) {
                return Err(TxError::ForeignInput(op));
            }
            total_in = total_in
                .checked_add(prevout.value.to_sat())
                .ok_or(TxError::Overflow)?;
        }
        let total_out = tx
            .output
            .iter()
            .try_fold(0u64, |acc, o| acc.checked_add(o.value.to_sat()))
            .ok_or(TxError::Overflow)?;
        if total_out > total_in {
            return Err(TxError::NegativeFee);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, Txid, WPubkeyHash, WScriptHash, Witness};

    use super::*;

    fn op(n: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([n; 32]),
            vout: u32::from(n),
        }
    }
    fn out(value: u64, script: &ScriptBuf) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: script.clone(),
        }
    }
    fn input(o: OutPoint) -> TxIn {
        TxIn {
            previous_output: o,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }
    fn wpkh(n: u8) -> ScriptBuf {
        ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([n; 20]))
    }
    fn wsh(n: u8) -> ScriptBuf {
        ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([n; 32]))
    }
    fn tr(n: u8) -> ScriptBuf {
        let mut b = vec![0x51, 0x20];
        b.extend_from_slice(&[n; 32]);
        ScriptBuf::from_bytes(b)
    }
    const NOW: ChainView = ChainView {
        tip_height: Some(900_000),
        now: 1_800_000_000,
    };

    struct Case {
        ours: BTreeMap<OutPoint, TxOut>,
        cj: ScriptBuf,
        change: ScriptBuf,
        tx: Transaction,
        others: BTreeMap<OutPoint, TxOut>,
    }

    /// A valid round for `pit`: maker in 1.5M, taker in 1.2M; amount 1M; cjfee 300, txfee 100.
    fn case(pit: Pit) -> Case {
        let s = |n: u8| match pit {
            Pit::Sw0 => wpkh(n),
            Pit::Tr0 => tr(n),
            Pit::Wsh0 => wsh(n),
        };
        let ours = BTreeMap::from([(op(1), out(1_500_000, &s(1)))]);
        let others = BTreeMap::from([(op(2), out(1_200_000, &s(2)))]);
        let (cj, change) = (s(10), s(11));
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![input(op(1)), input(op(2))],
            output: vec![
                out(1_000_000, &cj),
                out(500_200, &change), // 1.5M - 1M - 100 + 300
                out(1_000_000, &s(20)),
                out(199_000, &s(21)),
            ],
        };
        Case {
            ours,
            cj,
            change,
            tx,
            others,
        }
    }

    fn check(pit: Pit, c: &Case) -> Result<(), TxError> {
        let terms = MakerTerms {
            pit,
            our_utxos: &c.ours,
            cj_script: &c.cj,
            change_script: &c.change,
            amount: 1_000_000,
            cjfee: 300,
            txfee: 100,
        };
        verify_unsigned(&c.tx, &terms, &c.others, &NOW)
    }

    #[test]
    fn valid_rounds_pass_in_every_pit() {
        for pit in Pit::ALL {
            check(pit, &case(pit)).unwrap();
        }
    }

    #[test]
    fn checklist_failures() {
        let pit = Pit::Sw0;
        let mut c = case(pit);
        c.tx.input.remove(0);
        assert_eq!(check(pit, &c), Err(TxError::MissingOurInput(op(1))));

        let mut c = case(pit);
        c.tx.output[0].value = Amount::from_sat(999_999);
        assert_eq!(check(pit, &c), Err(TxError::CjOutputTooLow));

        let mut c = case(pit);
        c.tx.output[1].value = Amount::from_sat(500_199);
        assert_eq!(check(pit, &c), Err(TxError::ChangeTooLow));

        let mut c = case(pit);
        c.tx.output.push(out(1_000_000, &c.cj.clone()));
        assert_eq!(check(pit, &c), Err(TxError::CjOutputCount(2)));

        let mut c = case(pit);
        c.tx.output.remove(1);
        assert_eq!(check(pit, &c), Err(TxError::ChangeOutputCount(0)));

        let c = case(pit);
        let terms = MakerTerms {
            pit,
            our_utxos: &c.ours,
            cj_script: &c.cj,
            change_script: &c.change,
            amount: 1_000_000,
            cjfee: 99,
            txfee: 100,
        };
        assert_eq!(
            verify_unsigned(&c.tx, &terms, &c.others, &NOW),
            Err(TxError::NegativeProfit)
        );
        let terms = MakerTerms {
            amount: 2_000_000,
            cjfee: 100,
            ..terms
        };
        assert_eq!(
            verify_unsigned(&c.tx, &terms, &c.others, &NOW),
            Err(TxError::InsufficientInputs)
        );
        let terms = MakerTerms {
            cjfee: 100,
            change_script: &c.cj,
            ..terms
        };
        assert_eq!(
            verify_unsigned(
                &c.tx,
                &MakerTerms {
                    amount: 1_000_000,
                    ..terms
                },
                &c.others,
                &NOW
            ),
            Err(TxError::SameScripts)
        );
        // Zero profit is accepted (zero-fee offers).
        let mut c = case(pit);
        c.tx.output[1].value = Amount::from_sat(500_000);
        let terms = MakerTerms {
            pit,
            our_utxos: &c.ours,
            cj_script: &c.cj,
            change_script: &c.change,
            amount: 1_000_000,
            cjfee: 0,
            txfee: 0,
        };
        verify_unsigned(&c.tx, &terms, &c.others, &NOW).unwrap();
    }

    #[test]
    fn structure_failures() {
        let pit = Pit::Sw0;
        let mut c = case(pit);
        c.tx.version = Version(4);
        assert_eq!(check(pit, &c), Err(TxError::Version(4)));
        let mut c = case(pit);
        c.tx.input.push(input(op(2)));
        assert_eq!(check(pit, &c), Err(TxError::DuplicateInput(op(2))));
        let mut c = case(pit);
        c.tx.input[0].witness = Witness::from_slice(&[vec![1u8; 71]]);
        assert_eq!(check(pit, &c), Err(TxError::OurInputSigned(op(1))));
    }

    #[test]
    fn locktime_guard() {
        let pit = Pit::Sw0;
        let lock = |l: u32| {
            let mut c = case(pit);
            c.tx.lock_time = LockTime::from_consensus(l);
            c
        };
        check(pit, &lock(900_000)).unwrap(); // anti-fee-sniping at tip
        check(pit, &lock(900_012)).unwrap();
        assert_eq!(check(pit, &lock(900_013)), Err(TxError::Locktime(900_013)));
        check(pit, &lock(1_800_000_000 + 7200)).unwrap();
        assert_eq!(
            check(pit, &lock(1_800_007_201)),
            Err(TxError::Locktime(1_800_007_201))
        );
        let c = lock(899_000);
        let terms = MakerTerms {
            pit,
            our_utxos: &c.ours,
            cj_script: &c.cj,
            change_script: &c.change,
            amount: 1_000_000,
            cjfee: 300,
            txfee: 100,
        };
        let blind = ChainView {
            tip_height: None,
            now: NOW.now,
        };
        assert_eq!(
            verify_unsigned(&c.tx, &terms, &c.others, &blind),
            Err(TxError::Locktime(899_000))
        );
    }

    #[test]
    fn pit_uniformity() {
        for pit in [Pit::Tr0, Pit::Wsh0] {
            let mut c = case(pit);
            c.tx.output[3].script_pubkey = wpkh(9);
            assert_eq!(check(pit, &c), Err(TxError::ForeignOutput(3)), "{pit:?}");

            let mut c = case(pit);
            c.others.insert(op(2), out(1_200_000, &wpkh(2)));
            assert_eq!(check(pit, &c), Err(TxError::ForeignInput(op(2))), "{pit:?}");

            let mut c = case(pit);
            c.others.clear();
            assert_eq!(
                check(pit, &c),
                Err(TxError::MissingPrevout(op(2))),
                "{pit:?}"
            );

            let mut c = case(pit);
            let first = c.others.get(&op(2)).unwrap().script_pubkey.clone();
            c.others.insert(op(2), out(1_000, &first));
            assert_eq!(check(pit, &c), Err(TxError::NegativeFee), "{pit:?}");
        }
        // sw0 does not police other participants' script types (reference behaviour).
        let mut c = case(Pit::Sw0);
        c.tx.output[3].script_pubkey = tr(9);
        check(Pit::Sw0, &c).unwrap();
    }
}
