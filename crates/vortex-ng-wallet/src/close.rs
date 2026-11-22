//! Which of the wallet's coins came out of a Lightning channel close.
//!
//! The wallet keeps the full transaction that created each of its coins, so `vortex_ng_core::lnclose`
//! can read BOLT 3's shapes off it with no node and no extra request. A coin whose creating transaction is
//! not in the wallet (it cannot happen for a coin the wallet found by scanning blocks) reads as "not known
//! to be one".
//!
//! A close pays a coin to the wallet in one of two ways, and this sees both: the user hands the node one of
//! the wallet's addresses as the close's delivery address (`lncli closechannel --delivery_addr`, CLN's
//! `close <id> <unilateraltimeout> <destination>`), so the closing transaction itself pays the wallet; or the
//! node sweeps a force close into the wallet, and the sweep is the creating transaction.

use bdk_wallet::LocalOutput;
use bdk_wallet::bitcoin::OutPoint;
use vortex_ng_core::lnclose::{CloseEvidence, classify};

use crate::{PitWallet, WalletError};

impl PitWallet {
    /// Whether the transaction that created `outpoint` (a coin of mixdepth `m`) is a channel close or the
    /// sweep of one, and what is known of it.
    pub fn close_origin(
        &self,
        m: u32,
        outpoint: &OutPoint,
    ) -> Result<Option<CloseEvidence>, WalletError> {
        Ok(self
            .mixdepth(m)?
            .get_tx(outpoint.txid)
            .and_then(|created_by| classify(&created_by.tx_node.tx)))
    }

    /// Mixdepth `m`'s unspent outputs, each with its channel-close evidence if it has any.
    pub fn utxos_with_origin(
        &self,
        m: u32,
    ) -> Result<Vec<(LocalOutput, Option<CloseEvidence>)>, WalletError> {
        self.utxos(m)?
            .into_iter()
            .map(|utxo| {
                let origin = self.close_origin(m, &utxo.outpoint)?;
                Ok((utxo, origin))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use bdk_wallet::bitcoin::block::{Header, Version as BlockVersion};
    use bdk_wallet::bitcoin::blockdata::constants::genesis_block;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use bdk_wallet::bitcoin::transaction::Version;
    use bdk_wallet::bitcoin::{
        Amount, Block, CompactTarget, Network, ScriptBuf, Sequence, Transaction, TxIn,
        TxMerkleNode, TxOut, Txid, Witness, absolute,
    };
    use vortex_ng_core::lnclose::CloseKind;
    use vortex_ng_core::offer::Pit;

    use super::*;
    use crate::Seed;

    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn key(seed: u8) -> [u8; 33] {
        let secret = SecretKey::from_slice(&[seed; 32]).unwrap();
        PublicKey::from_secret_key(&Secp256k1::new(), &secret).serialize()
    }

    /// A BOLT 3 funding script and the witness that spends it (signatures are placeholders: nothing here
    /// validates them, the wallet only reads the shape).
    fn funding_witness() -> Witness {
        let (a, b) = (key(1), key(2));
        let (first, second) = if a < b { (a, b) } else { (b, a) };
        let mut script = vec![0x52, 0x21];
        script.extend_from_slice(&first);
        script.push(0x21);
        script.extend_from_slice(&second);
        script.extend_from_slice(&[0x52, 0xae]);
        let mut witness = Witness::new();
        for item in [&[][..], &[0x30; 72][..], &[0x30; 71][..], &script[..]] {
            witness.push(item);
        }
        witness
    }

    fn paying(inputs: Vec<(Txid, Witness, u32)>, to: &[(ScriptBuf, u64)]) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: inputs
                .into_iter()
                .map(|(txid, witness, sequence)| TxIn {
                    previous_output: OutPoint { txid, vout: 0 },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::from_consensus(sequence),
                    witness,
                })
                .collect(),
            output: to
                .iter()
                .map(|(script_pubkey, sats)| TxOut {
                    value: Amount::from_sat(*sats),
                    script_pubkey: script_pubkey.clone(),
                })
                .collect(),
        }
    }

    fn block_of(txs: Vec<Transaction>) -> Block {
        let genesis = genesis_block(Network::Regtest);
        Block {
            header: Header {
                version: BlockVersion::TWO,
                prev_blockhash: genesis.block_hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: genesis.header.time + 600,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: txs,
        }
    }

    #[test]
    fn a_close_that_pays_the_wallet_is_seen_and_a_payment_is_not() {
        let mut wallet = PitWallet::new(
            &Seed::from_mnemonic(WORDS, "", Network::Regtest).unwrap(),
            Pit::Sw0,
        )
        .unwrap();
        let close_to = wallet.next_receive_address(0).unwrap().script_pubkey();
        let paid_to = wallet.next_receive_address(0).unwrap().script_pubkey();
        let elsewhere = ScriptBuf::new_op_return([1u8; 4]);
        // A mutual close: the funding output alone in, the wallet and the peer out.
        let close = paying(
            vec![(
                Txid::from_byte_array([1; 32]),
                funding_witness(),
                0xffff_fffd,
            )],
            &[(close_to, 400_000), (elsewhere, 599_000)],
        );
        // An ordinary payment to the wallet.
        let payment = paying(
            vec![(Txid::from_byte_array([2; 32]), Witness::new(), 0xffff_fffd)],
            &[(paid_to, 250_000)],
        );
        let (close_id, payment_id) = (close.compute_txid(), payment.compute_txid());
        wallet
            .apply_block(&block_of(vec![close, payment]), 1)
            .unwrap();

        let coins = wallet.utxos_with_origin(0).unwrap();
        assert_eq!(coins.len(), 2);
        for (coin, origin) in coins {
            if coin.outpoint.txid == close_id {
                assert_eq!(
                    origin.map(|e| e.kind),
                    Some(CloseKind::Cooperative),
                    "the close's output"
                );
            } else {
                assert_eq!(coin.outpoint.txid, payment_id);
                assert_eq!(origin, None, "an ordinary payment");
            }
        }
        // Another mixdepth holds nothing; an outpoint of a transaction the wallet never saw reads as unknown.
        assert!(wallet.utxos_with_origin(1).unwrap().is_empty());
        let unseen = OutPoint {
            txid: Txid::from_byte_array([9; 32]),
            vout: 0,
        };
        assert_eq!(wallet.close_origin(0, &unseen), Ok(None));
        assert_eq!(
            wallet.close_origin(9, &unseen),
            Err(WalletError::Mixdepth(9))
        );
    }

    /// The `wsh0` pit spends BOLT 3's funding script in every input, so its CoinJoins carry the funding
    /// witness many times over: none of their outputs is a close.
    #[test]
    fn a_wsh0_coinjoin_output_is_not_a_close() {
        let mut wallet = PitWallet::new(
            &Seed::from_mnemonic(WORDS, "", Network::Regtest).unwrap(),
            Pit::Wsh0,
        )
        .unwrap();
        let to = wallet.next_receive_address(1).unwrap().script_pubkey();
        let coinjoin = paying(
            (1..=4)
                .map(|n| {
                    (
                        Txid::from_byte_array([n; 32]),
                        funding_witness(),
                        0xffff_ffff,
                    )
                })
                .collect(),
            &[(to, 500_000)],
        );
        wallet.apply_block(&block_of(vec![coinjoin]), 1).unwrap();
        let coins = wallet.utxos_with_origin(1).unwrap();
        assert_eq!(coins.len(), 1);
        assert_eq!(coins[0].1, None);
    }
}
