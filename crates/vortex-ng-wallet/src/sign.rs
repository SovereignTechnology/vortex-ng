//! Maker-side signing: sign this mixdepth's inputs of a verified CoinJoin transaction and produce one
//! `!sig` payload per input, re-verified with `vortex_ng_core::sig` before it is returned.

use bdk_wallet::bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bdk_wallet::bitcoin::{OutPoint, Psbt, Transaction, TxOut};
use vortex_ng_core::offer::Pit;
use vortex_ng_core::sig::{encode_sw0, encode_tr0, encode_wsh0, verify_sig, wsh0_keys};

use crate::{PitWallet, WalletError};

impl PitWallet {
    /// Sign the inputs of `tx` that spend `declared` (the UTXOs mixdepth `m` declared in `!ioauth`), whose
    /// prevouts (every input's, in order) the caller has checked against the chain and
    /// `vortex_ng_core::tx::verify_unsigned` has accepted. Returns `(input index, !sig payload)` per
    /// declared input. Any other UTXO of ours in `tx` is refused, never signed: signing an undeclared
    /// input would hand its value to the taker.
    pub fn sign_inputs(
        &self,
        m: u32,
        tx: &Transaction,
        prevouts: &[TxOut],
        declared: &[OutPoint],
    ) -> Result<Vec<(usize, String)>, WalletError> {
        let signing = |e: &dyn std::fmt::Display| WalletError::Descriptor(format!("signing: {e}"));
        if prevouts.len() != tx.input.len() {
            return Err(WalletError::Descriptor("one prevout per input".into()));
        }
        let wallet = self.mixdepth(m)?;
        let mut psbt = Psbt::from_unsigned_tx(tx.clone()).map_err(|e| signing(&e))?;
        let mut ours = Vec::new();
        for (i, input) in tx.input.iter().enumerate() {
            if let Some(local) = wallet.get_utxo(input.previous_output) {
                if !declared.contains(&input.previous_output) {
                    return Err(WalletError::Descriptor(format!(
                        "input {i} spends an undeclared UTXO of ours"
                    )));
                }
                if local.txout != prevouts[i] {
                    return Err(WalletError::Descriptor(format!(
                        "prevout of input {i} differs from our record"
                    )));
                }
                psbt.inputs[i] = wallet
                    .get_psbt_input(local, None, true)
                    .map_err(|e| signing(&e))?;
                ours.push(i);
            }
            psbt.inputs[i].witness_utxo = Some(prevouts[i].clone());
        }
        // rust-bitcoin signs every input whose derivation data carries our master fingerprint (ours only:
        // foreign inputs have none). SIGHASH_ALL for ECDSA, SIGHASH_DEFAULT for taproot key spends.
        psbt.sign(&self.master, &Secp256k1::new())
            .map_err(|(_, errors)| signing(&format!("{errors:?}")))?;

        let secp = Secp256k1::verification_only();
        let mut out = Vec::with_capacity(ours.len());
        for i in ours {
            let input = &psbt.inputs[i];
            let payload = match self.pit {
                Pit::Sw0 => {
                    let (key, sig) = input
                        .partial_sigs
                        .iter()
                        .next()
                        .ok_or_else(|| signing(&"no signature"))?;
                    encode_sw0(sig, &key.inner)
                }
                Pit::Tr0 => {
                    let sig = input
                        .tap_key_sig
                        .ok_or_else(|| signing(&"no taproot signature"))?;
                    let program = prevouts[i]
                        .script_pubkey
                        .as_bytes()
                        .get(2..34)
                        .ok_or_else(|| signing(&"not P2TR"))?;
                    let key = XOnlyPublicKey::from_slice(program).map_err(|e| signing(&e))?;
                    encode_tr0(&sig.signature, &key)
                }
                Pit::Wsh0 => {
                    let script = input
                        .witness_script
                        .as_ref()
                        .ok_or_else(|| signing(&"no witness script"))?;
                    let (k1, k2) =
                        wsh0_keys(script).ok_or_else(|| signing(&"not a wsh0 script"))?;
                    let get = |k| {
                        input
                            .partial_sigs
                            .get(&bdk_wallet::bitcoin::PublicKey::new(k))
                            .ok_or_else(|| signing(&"missing signature"))
                    };
                    encode_wsh0(get(k1)?, get(k2)?, script)
                }
            };
            verify_sig(&secp, self.pit, &payload, tx, i, prevouts).map_err(|e| signing(&e))?;
            out.push((i, payload));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use bdk_wallet::bitcoin::block::{Header, Version as BlockVersion};
    use bdk_wallet::bitcoin::blockdata::constants::genesis_block;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::transaction::Version;
    use bdk_wallet::bitcoin::{
        Amount, Block, CompactTarget, Network, OutPoint, ScriptBuf, Sequence, TxIn, TxMerkleNode,
        Txid, Witness, absolute,
    };

    use super::*;
    use crate::Seed;

    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// Fund mixdepth 0 of `pit`, then sign a coinjoin spending it beside a foreign input.
    fn round_trip(pit: Pit) {
        let mut w = PitWallet::new(
            &Seed::from_mnemonic(WORDS, "", Network::Regtest).unwrap(),
            pit,
        )
        .unwrap();
        let addr = w.next_receive_address(0).unwrap();
        let funding = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([3; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(200_000),
                script_pubkey: addr.script_pubkey(),
            }],
        };
        let genesis = genesis_block(Network::Regtest);
        let block = Block {
            header: Header {
                version: BlockVersion::TWO,
                prev_blockhash: genesis.block_hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: genesis.header.time + 600,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![funding.clone()],
        };
        w.apply_block(&block, 1).unwrap();
        let ours = OutPoint {
            txid: funding.compute_txid(),
            vout: 0,
        };
        // A foreign input of the same pit's type (another participant's).
        let other = PitWallet::new(
            &Seed::from_mnemonic(WORDS, "other", Network::Regtest).unwrap(),
            pit,
        )
        .unwrap();
        let foreign_spk = other.peek_address(0, false, 0).unwrap().script_pubkey();
        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: [
                OutPoint {
                    txid: Txid::from_byte_array([9; 32]),
                    vout: 1,
                },
                ours,
            ]
            .map(|o| TxIn {
                previous_output: o,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .to_vec(),
            output: vec![TxOut {
                value: Amount::from_sat(290_000),
                script_pubkey: w.peek_address(0, true, 0).unwrap().script_pubkey(),
            }],
        };
        let prevouts = vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: foreign_spk,
            },
            funding.output[0].clone(),
        ];
        let sigs = w.sign_inputs(0, &tx, &prevouts, &[ours]).unwrap();
        assert_eq!(sigs.len(), 1, "{pit:?}");
        assert_eq!(sigs[0].0, 1);
        // The taker's check accepts it.
        verify_sig(
            &Secp256k1::verification_only(),
            pit,
            &sigs[0].1,
            &tx,
            1,
            &prevouts,
        )
        .unwrap();
        // Another mixdepth owns nothing here.
        assert!(w.sign_inputs(1, &tx, &prevouts, &[]).unwrap().is_empty());
        // An input of ours that was not declared is refused, not signed.
        assert!(w.sign_inputs(0, &tx, &prevouts, &[]).is_err());
        // A prevout that differs from our record is refused.
        let mut bad = prevouts.clone();
        bad[1].value = Amount::from_sat(1);
        assert!(w.sign_inputs(0, &tx, &bad, &[ours]).is_err());
    }

    #[test]
    fn sw0_signs_and_verifies() {
        round_trip(Pit::Sw0);
    }

    #[test]
    fn tr0_signs_and_verifies() {
        round_trip(Pit::Tr0);
    }

    #[test]
    fn wsh0_signs_and_verifies() {
        round_trip(Pit::Wsh0);
    }
}
