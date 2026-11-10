//! Fidelity bonds: joinmarket's timelocked P2WSH bonds at `m/84'/coin'/0'/2/timenumber` (mixdepth 0,
//! chain 2), whatever the pit (JMP-0010 "Fidelity Bonds"). Their script, `<locktime> OP_CLTV OP_DROP
//! <pubkey> OP_CHECKSIG`, is not miniscript, so the wallet indexes the 960 bond scripts itself and records
//! bond UTXOs while applying blocks.

use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;

use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv};
use bdk_wallet::bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bdk_wallet::bitcoin::{Address, Amount, Block, Network, OutPoint, ScriptBuf};
use vortex_ng_core::bond::{TIMENUMBER_COUNT, freeze_script, timenumber_locktime};

use crate::{PitWallet, WalletError, coin_type};

/// A bond UTXO the wallet holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BondUtxo {
    /// The bond output.
    pub outpoint: OutPoint,
    /// Its value.
    pub value: Amount,
    /// Its timenumber (which monthly timelock).
    pub timenumber: u32,
    /// Its absolute timelock (Unix time).
    pub locktime: u32,
    /// The height it confirmed at.
    pub height: u32,
}

/// The wallet's bond scripts, bond UTXOs, and spent bonds with their spending height (so a reorg that
/// removes the spend brings the bond back).
pub(crate) struct BondIndex {
    by_script: HashMap<ScriptBuf, u32>,
    utxos: BTreeMap<OutPoint, BondUtxo>,
    spent: BTreeMap<OutPoint, (BondUtxo, u32)>,
}

fn bond_account(master: &Xpriv, network: Network) -> Result<Xpriv, WalletError> {
    let path = DerivationPath::from_str(&format!("m/84'/{}'/0'/2", coin_type(network)))
        .map_err(|e| WalletError::Descriptor(e.to_string()))?;
    master
        .derive_priv(&Secp256k1::new(), &path)
        .map_err(|e| WalletError::Descriptor(e.to_string()))
}

fn bond_secret(account: &Xpriv, timenumber: u32) -> Result<SecretKey, WalletError> {
    let path = DerivationPath::from_str(&format!("m/{timenumber}"))
        .map_err(|e| WalletError::Descriptor(e.to_string()))?;
    Ok(account
        .derive_priv(&Secp256k1::new(), &path)
        .map_err(|e| WalletError::Descriptor(e.to_string()))?
        .private_key)
}

fn bond_script(key: &PublicKey, locktime: u32) -> ScriptBuf {
    ScriptBuf::new_p2wsh(&freeze_script(key, locktime).wscript_hash())
}

impl BondIndex {
    pub(crate) fn new(master: &Xpriv, network: Network) -> Result<BondIndex, WalletError> {
        let account = bond_account(master, network)?;
        let secp = Secp256k1::new();
        let mut by_script = HashMap::with_capacity(TIMENUMBER_COUNT as usize);
        for n in 0..TIMENUMBER_COUNT {
            let locktime =
                timenumber_locktime(n).ok_or(WalletError::Descriptor("timenumber".into()))?;
            let key = PublicKey::from_secret_key(&secp, &bond_secret(&account, n)?);
            by_script.insert(bond_script(&key, locktime), n);
        }
        Ok(BondIndex {
            by_script,
            utxos: BTreeMap::new(),
            spent: BTreeMap::new(),
        })
    }

    pub(crate) fn scan(&mut self, block: &Block, height: u32) {
        for tx in &block.txdata {
            for input in &tx.input {
                if let Some(bond) = self.utxos.remove(&input.previous_output) {
                    self.spent.insert(input.previous_output, (bond, height));
                }
            }
            let txid = tx.compute_txid();
            for (vout, out) in tx.output.iter().enumerate() {
                if let Some(&timenumber) = self.by_script.get(&out.script_pubkey) {
                    let outpoint = OutPoint {
                        txid,
                        vout: vout as u32,
                    };
                    let locktime = timenumber_locktime(timenumber).unwrap_or(0);
                    self.utxos.insert(
                        outpoint,
                        BondUtxo {
                            outpoint,
                            value: out.value,
                            timenumber,
                            locktime,
                            height,
                        },
                    );
                }
            }
        }
    }

    /// Forget blocks above `height` (a reorg): bonds confirmed above it go, spends above it are undone.
    pub(crate) fn drop_above(&mut self, height: u32) {
        let unspent: Vec<OutPoint> = self
            .spent
            .iter()
            .filter(|(_, (_, spent_at))| *spent_at > height)
            .map(|(outpoint, _)| *outpoint)
            .collect();
        for outpoint in unspent {
            if let Some((bond, _)) = self.spent.remove(&outpoint) {
                self.utxos.insert(outpoint, bond);
            }
        }
        self.utxos.retain(|_, b| b.height <= height);
        self.spent.retain(|_, (b, _)| b.height <= height);
    }
}

impl PitWallet {
    /// The address to fund a bond locked until timenumber `timenumber`'s date.
    pub fn bond_address(&self, timenumber: u32) -> Result<Address, WalletError> {
        let locktime =
            timenumber_locktime(timenumber).ok_or(WalletError::Descriptor("timenumber".into()))?;
        let key = PublicKey::from_secret_key(&Secp256k1::new(), &self.bond_key(timenumber)?);
        Address::from_script(&bond_script(&key, locktime), self.network)
            .map_err(|e| WalletError::Descriptor(e.to_string()))
    }

    /// The private key of bond timenumber `timenumber` (signs the bond's certificate). Never printed.
    pub fn bond_key(&self, timenumber: u32) -> Result<SecretKey, WalletError> {
        if timenumber >= TIMENUMBER_COUNT {
            return Err(WalletError::Descriptor("timenumber".into()));
        }
        bond_secret(&bond_account(&self.master, self.network)?, timenumber)
    }

    /// The bond UTXOs found so far.
    pub fn bonds(&self) -> Vec<BondUtxo> {
        self.bonds.utxos.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use bdk_wallet::bitcoin::block::{Header, Version as BlockVersion};
    use bdk_wallet::bitcoin::blockdata::constants::genesis_block;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::transaction::Version;
    use bdk_wallet::bitcoin::{
        CompactTarget, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Txid, Witness, absolute,
    };
    use vortex_ng_core::offer::Pit;

    use super::*;
    use crate::Seed;

    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn block(prev: bdk_wallet::bitcoin::BlockHash, txs: Vec<Transaction>, nonce: u32) -> Block {
        Block {
            header: Header {
                version: BlockVersion::TWO,
                prev_blockhash: prev,
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_700_000_000 + nonce,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce,
            },
            txdata: txs,
        }
    }

    fn tx(input: OutPoint, outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: input,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: outputs,
        }
    }

    #[test]
    fn bonds_are_found_and_spent_in_every_pit() {
        for pit in [Pit::Sw0, Pit::Tr0, Pit::Wsh0] {
            let mut w = PitWallet::new(
                &Seed::from_mnemonic(WORDS, "", Network::Regtest).unwrap(),
                pit,
            )
            .unwrap();
            let address = w.bond_address(72).unwrap();
            assert!(address.script_pubkey().is_p2wsh());
            let fund = tx(
                OutPoint {
                    txid: Txid::from_byte_array([1; 32]),
                    vout: 0,
                },
                vec![TxOut {
                    value: Amount::from_sat(1_000_000),
                    script_pubkey: address.script_pubkey(),
                }],
            );
            let b1 = block(
                genesis_block(Network::Regtest).block_hash(),
                vec![fund.clone()],
                1,
            );
            w.apply_block(&b1, 1).unwrap();
            let bonds = w.bonds();
            assert_eq!(bonds.len(), 1, "{pit:?}");
            assert_eq!(
                (bonds[0].timenumber, bonds[0].locktime, bonds[0].height),
                (72, 1_767_225_600, 1)
            );
            // Same address in every pit: the bond lives on the BIP84 path.
            assert_eq!(
                address,
                PitWallet::new(
                    &Seed::from_mnemonic(WORDS, "", Network::Regtest).unwrap(),
                    Pit::Sw0
                )
                .unwrap()
                .bond_address(72)
                .unwrap()
            );
            let spend = tx(bonds[0].outpoint, vec![TxOut::NULL]);
            w.apply_block(&block(b1.block_hash(), vec![spend], 2), 2)
                .unwrap();
            assert!(w.bonds().is_empty(), "{pit:?}: spent bond removed");
        }
    }

    #[test]
    fn a_reorg_undoes_bond_spends_and_confirmations_above_the_fork() {
        let w = PitWallet::new(
            &Seed::from_mnemonic(WORDS, "", Network::Regtest).unwrap(),
            Pit::Sw0,
        )
        .unwrap();
        let mut index = BondIndex::new(&w.master, Network::Regtest).unwrap();
        let pay = |n: u32, salt: u8| {
            tx(
                OutPoint {
                    txid: Txid::from_byte_array([salt; 32]),
                    vout: 0,
                },
                vec![TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: w.bond_address(n).unwrap().script_pubkey(),
                }],
            )
        };
        let genesis = genesis_block(Network::Regtest).block_hash();
        let (old, new) = (pay(10, 1), pay(11, 2));
        let old_bond = OutPoint {
            txid: old.compute_txid(),
            vout: 0,
        };
        index.scan(&block(genesis, vec![old], 1), 1);
        index.scan(&block(genesis, vec![tx(old_bond, vec![TxOut::NULL])], 2), 5);
        index.scan(&block(genesis, vec![new], 3), 6);
        assert_eq!(
            index.utxos.keys().map(|o| o.txid).collect::<Vec<_>>().len(),
            1
        );
        // Fork at 4: the spend at 5 and the bond confirmed at 6 never happened.
        index.drop_above(4);
        assert_eq!(
            index.utxos.keys().copied().collect::<Vec<_>>(),
            vec![old_bond]
        );
        assert!(index.spent.is_empty());
    }

    #[test]
    fn bond_key_controls_the_bond_script() {
        let w = PitWallet::new(
            &Seed::from_mnemonic(WORDS, "", Network::Regtest).unwrap(),
            Pit::Sw0,
        )
        .unwrap();
        let key = PublicKey::from_secret_key(&Secp256k1::new(), &w.bond_key(5).unwrap());
        assert_eq!(
            bond_script(&key, timenumber_locktime(5).unwrap()),
            w.bond_address(5).unwrap().script_pubkey()
        );
        assert!(w.bond_key(TIMENUMBER_COUNT).is_err());
        assert_ne!(w.bond_address(5).unwrap(), w.bond_address(6).unwrap());
    }
}
