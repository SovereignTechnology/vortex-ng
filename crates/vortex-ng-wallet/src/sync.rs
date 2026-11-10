//! Syncing a pit wallet from a block source (our chain backend), with a birthday and reorg handling.

use bdk_wallet::bitcoin::{Block, BlockHash};
use bdk_wallet::chain::BlockId;

use crate::{PitWallet, WalletError};

/// Where blocks come from. Implemented for `vortex-ng-chain`'s `CoreRpc`.
pub trait BlockSource {
    /// The best block's height.
    fn tip_height(&self) -> Result<u32, String>;
    /// The hash of the block at `height` on the best chain.
    fn block_hash(&self, height: u32) -> Result<BlockHash, String>;
    /// The block with `hash`.
    fn block(&self, hash: &BlockHash) -> Result<Block, String>;
}

impl BlockSource for vortex_ng_chain::CoreRpc {
    fn tip_height(&self) -> Result<u32, String> {
        vortex_ng_chain::CoreRpc::tip_height(self).map_err(|e| e.to_string())
    }
    fn block_hash(&self, height: u32) -> Result<BlockHash, String> {
        vortex_ng_chain::CoreRpc::block_hash(self, height).map_err(|e| e.to_string())
    }
    fn block(&self, hash: &BlockHash) -> Result<Block, String> {
        vortex_ng_chain::CoreRpc::block(self, hash).map_err(|e| e.to_string())
    }
}

impl PitWallet {
    /// The wallet's checkpoints, highest first.
    fn checkpoints(&self) -> Vec<BlockId> {
        self.mixdepths
            .first()
            .map(|w| {
                w.latest_checkpoint()
                    .iter()
                    .map(|cp| cp.block_id())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn apply_connected(
        &mut self,
        block: &Block,
        height: u32,
        connected_to: BlockId,
    ) -> Result<(), WalletError> {
        for wallet in &mut self.mixdepths {
            wallet
                .apply_block_connected_to(block, height, connected_to)
                .map_err(|e| WalletError::CannotConnect(e.to_string()))?;
        }
        Ok(())
    }

    /// Bring every mixdepth up to the source's tip. A new wallet starts at `birthday` (blocks below it
    /// are not scanned). If the source reorganised, the wallet rewinds to the highest checkpoint the
    /// source still agrees with and re-applies from there. Returns the synced height.
    pub fn sync(&mut self, source: &impl BlockSource, birthday: u32) -> Result<u32, WalletError> {
        let source_err = |e: String| WalletError::CannotConnect(format!("block source: {e}"));
        let tip = source.tip_height().map_err(source_err)?;
        // Find the highest checkpoint the source agrees with (genesis always, on the right network).
        let mut connect = None;
        for cp in self.checkpoints() {
            if cp.height > tip {
                continue;
            }
            if source.block_hash(cp.height).map_err(source_err)? == cp.hash {
                connect = Some(cp);
                break;
            }
        }
        let connect = connect.ok_or_else(|| {
            WalletError::CannotConnect("source shares no block with the wallet".into())
        })?;
        let mut height = if connect.height == 0 {
            birthday.max(1)
        } else {
            connect.height + 1
        };
        let mut connected_to = connect;
        while height <= tip {
            let hash = source.block_hash(height).map_err(source_err)?;
            let block = source.block(&hash).map_err(source_err)?;
            if block.block_hash() != hash {
                return Err(WalletError::CannotConnect(
                    "source returned another block".into(),
                ));
            }
            self.apply_connected(&block, height, connected_to)?;
            connected_to = BlockId { height, hash };
            height += 1;
        }
        Ok(self.synced_height())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use bdk_wallet::bitcoin::block::{Header, Version as BlockVersion};
    use bdk_wallet::bitcoin::blockdata::constants::genesis_block;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::transaction::Version;
    use bdk_wallet::bitcoin::{
        Amount, CompactTarget, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxMerkleNode, TxOut, Txid, Witness, absolute,
    };
    use vortex_ng_core::offer::Pit;

    use super::*;
    use crate::Seed;

    /// A chain of blocks; `fork` rebuilds it from a height with a different nonce.
    struct Chain(RefCell<Vec<Block>>);

    impl Chain {
        fn new() -> Chain {
            Chain(RefCell::new(vec![genesis_block(Network::Regtest)]))
        }
        fn mine(&self, payments: Vec<TxOut>, salt: u32) {
            let mut blocks = self.0.borrow_mut();
            let prev = blocks.last().map(|b| b.block_hash()).unwrap();
            let height = blocks.len() as u32;
            let tx = Transaction {
                version: Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([height as u8; 32]),
                        vout: salt,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: if payments.is_empty() {
                    vec![TxOut::NULL]
                } else {
                    payments
                },
            };
            blocks.push(Block {
                header: Header {
                    version: BlockVersion::TWO,
                    prev_blockhash: prev,
                    merkle_root: TxMerkleNode::all_zeros(),
                    time: 1_700_000_000 + height,
                    bits: CompactTarget::from_consensus(0x207f_ffff),
                    nonce: salt,
                },
                txdata: vec![tx],
            });
        }
        fn truncate(&self, len: usize) {
            self.0.borrow_mut().truncate(len);
        }
    }

    impl BlockSource for Chain {
        fn tip_height(&self) -> Result<u32, String> {
            Ok(self.0.borrow().len() as u32 - 1)
        }
        fn block_hash(&self, height: u32) -> Result<BlockHash, String> {
            self.0
                .borrow()
                .get(height as usize)
                .map(|b| b.block_hash())
                .ok_or_else(|| "no block".into())
        }
        fn block(&self, hash: &BlockHash) -> Result<Block, String> {
            self.0
                .borrow()
                .iter()
                .find(|b| b.block_hash() == *hash)
                .cloned()
                .ok_or_else(|| "no block".into())
        }
    }

    fn wallet() -> PitWallet {
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        PitWallet::new(
            &Seed::from_mnemonic(words, "", Network::Regtest).unwrap(),
            Pit::Sw0,
        )
        .unwrap()
    }

    #[test]
    fn syncs_from_birthday_and_follows_the_tip() {
        let mut w = wallet();
        let addr = w.next_receive_address(1).unwrap();
        let chain = Chain::new();
        chain.mine(
            vec![TxOut {
                value: Amount::from_sat(5_000),
                script_pubkey: addr.script_pubkey(),
            }],
            0,
        ); // 1: before birthday
        chain.mine(vec![], 0); // 2
        chain.mine(
            vec![TxOut {
                value: Amount::from_sat(70_000),
                script_pubkey: addr.script_pubkey(),
            }],
            0,
        ); // 3
        assert_eq!(w.sync(&chain, 2).unwrap(), 3);
        // The payment below the birthday is not seen; the one above is.
        assert_eq!(w.confirmed_balance(1).unwrap(), Amount::from_sat(70_000));
        chain.mine(
            vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: addr.script_pubkey(),
            }],
            0,
        ); // 4
        assert_eq!(w.sync(&chain, 2).unwrap(), 4);
        assert_eq!(w.confirmed_balance(1).unwrap(), Amount::from_sat(71_000));
        assert_eq!(w.sync(&chain, 2).unwrap(), 4, "idempotent at the tip");
    }

    #[test]
    fn reorg_drops_the_orphaned_payment() {
        let mut w = wallet();
        let addr = w.next_receive_address(0).unwrap();
        let chain = Chain::new();
        chain.mine(vec![], 0); // 1
        chain.mine(
            vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: addr.script_pubkey(),
            }],
            0,
        ); // 2
        assert_eq!(w.sync(&chain, 1).unwrap(), 2);
        assert_eq!(w.confirmed_balance(0).unwrap(), Amount::from_sat(40_000));
        // Block 2 is replaced by a longer branch without the payment.
        chain.truncate(2);
        chain.mine(vec![], 7); // 2'
        chain.mine(vec![], 7); // 3'
        assert_eq!(w.sync(&chain, 1).unwrap(), 3);
        assert_eq!(w.confirmed_balance(0).unwrap(), Amount::ZERO);
    }
}
