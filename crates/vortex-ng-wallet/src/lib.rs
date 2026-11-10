//! JoinMarket-compatible wallet for vortex-ng.
//!
//! One BIP39 seed (optional passphrase), five mixdepths per pit, each an account with external (0) and
//! internal (1) chains, `coin_type` 0 on mainnet and 1 elsewhere, as joinmarket-ng lays it out
//! (`docs/technical/wallet.md`), so a seed restores in either:
//!
//! | pit | descriptor per mixdepth `m` |
//! |---|---|
//! | `sw0` | `wpkh(m/84'/coin'/m'/chain/*)` (BIP84, joinmarket-ng) |
//! | `tr0` | `tr(m/86'/coin'/m'/chain/*)` (BIP86, JMP-0010) |
//! | `wsh0` | `wsh(sortedmulti(2, m/48'/coin'/(2m)'/2'/chain/*, m/48'/coin'/(2m+1)'/2'/chain/*))` (the wsh0 draft) |
//!
//! Each mixdepth is a BDK wallet held in memory with its private descriptors; blocks come from
//! `vortex-ng-chain`. Fidelity bonds (`m/84'/coin'/0'/2/timenumber`, a script miniscript cannot express)
//! are handled separately.

use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::{Address, Amount, Block, Network, Transaction};
use bdk_wallet::keys::bip39::{Language, Mnemonic};
use bdk_wallet::{KeychainKind, LocalOutput, Wallet};
use vortex_ng_core::offer::Pit;

pub use bdk_wallet;

/// Mixdepths per pit.
pub const MIXDEPTHS: u32 = 5;

/// Why a wallet operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletError {
    /// The mnemonic is not valid BIP39 English.
    Mnemonic(String),
    /// A descriptor or key could not be built.
    Descriptor(String),
    /// No such mixdepth.
    Mixdepth(u32),
    /// A block does not connect to the wallet's chain (reorg or gap).
    CannotConnect(String),
}

impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletError::Mnemonic(e) => write!(f, "invalid mnemonic: {e}"),
            WalletError::Descriptor(e) => write!(f, "descriptor: {e}"),
            WalletError::Mixdepth(m) => write!(f, "no mixdepth {m}"),
            WalletError::CannotConnect(e) => write!(f, "block does not connect: {e}"),
        }
    }
}

impl std::error::Error for WalletError {}

/// BIP44 `coin_type`: 0 on mainnet, 1 on every test network.
pub fn coin_type(network: Network) -> u32 {
    if network == Network::Bitcoin { 0 } else { 1 }
}

/// A wallet seed. Holds the master private key; never printed.
pub struct Seed {
    master: Xpriv,
    network: Network,
}

impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Seed")
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

impl Seed {
    /// From a BIP39 English mnemonic and passphrase (empty for none; not trimmed, NFKD per BIP39).
    pub fn from_mnemonic(
        words: &str,
        passphrase: &str,
        network: Network,
    ) -> Result<Seed, WalletError> {
        let mnemonic = Mnemonic::parse_in(Language::English, words)
            .map_err(|e| WalletError::Mnemonic(e.to_string()))?;
        let seed = mnemonic.to_seed(passphrase);
        let master = Xpriv::new_master(network, &seed)
            .map_err(|e| WalletError::Descriptor(e.to_string()))?;
        Ok(Seed { master, network })
    }

    /// The network the seed's keys are encoded for.
    pub fn network(&self) -> Network {
        self.network
    }

    /// The private (external, internal) descriptors of `pit`'s mixdepth `m`. They contain the master
    /// private key: keep them in memory only.
    fn descriptors(&self, pit: Pit, m: u32) -> (String, String) {
        let (x, c) = (self.master, coin_type(self.network));
        let one = |chain: u32| match pit {
            Pit::Sw0 => format!("wpkh({x}/84'/{c}'/{m}'/{chain}/*)"),
            Pit::Tr0 => format!("tr({x}/86'/{c}'/{m}'/{chain}/*)"),
            Pit::Wsh0 => format!(
                "wsh(sortedmulti(2,{x}/48'/{c}'/{a}'/2'/{chain}/*,{x}/48'/{c}'/{b}'/2'/{chain}/*))",
                a = 2 * m,
                b = 2 * m + 1
            ),
        };
        (one(0), one(1))
    }
}

/// One pit's wallet: a BDK wallet per mixdepth.
pub struct PitWallet {
    pit: Pit,
    mixdepths: Vec<Wallet>,
}

impl std::fmt::Debug for PitWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PitWallet")
            .field("pit", &self.pit)
            .finish_non_exhaustive()
    }
}

impl PitWallet {
    /// Build `pit`'s wallet from `seed`, in memory.
    pub fn new(seed: &Seed, pit: Pit) -> Result<PitWallet, WalletError> {
        let mixdepths = (0..MIXDEPTHS)
            .map(|m| {
                let (external, internal) = seed.descriptors(pit, m);
                Wallet::create(external, internal)
                    .network(seed.network)
                    .create_wallet_no_persist()
                    .map_err(|e| WalletError::Descriptor(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PitWallet { pit, mixdepths })
    }

    /// The pit.
    pub fn pit(&self) -> Pit {
        self.pit
    }

    fn mixdepth(&self, m: u32) -> Result<&Wallet, WalletError> {
        self.mixdepths
            .get(m as usize)
            .ok_or(WalletError::Mixdepth(m))
    }

    fn mixdepth_mut(&mut self, m: u32) -> Result<&mut Wallet, WalletError> {
        self.mixdepths
            .get_mut(m as usize)
            .ok_or(WalletError::Mixdepth(m))
    }

    /// The address at `index` on mixdepth `m`'s external (`internal = false`) or internal chain, without
    /// revealing it.
    pub fn peek_address(&self, m: u32, internal: bool, index: u32) -> Result<Address, WalletError> {
        let keychain = if internal {
            KeychainKind::Internal
        } else {
            KeychainKind::External
        };
        Ok(self.mixdepth(m)?.peek_address(keychain, index).address)
    }

    /// A fresh receive address on mixdepth `m`.
    pub fn next_receive_address(&mut self, m: u32) -> Result<Address, WalletError> {
        Ok(self
            .mixdepth_mut(m)?
            .reveal_next_address(KeychainKind::External)
            .address)
    }

    /// A fresh change address on mixdepth `m`.
    pub fn next_change_address(&mut self, m: u32) -> Result<Address, WalletError> {
        Ok(self
            .mixdepth_mut(m)?
            .reveal_next_address(KeychainKind::Internal)
            .address)
    }

    /// Mixdepth `m`'s unspent outputs.
    pub fn utxos(&self, m: u32) -> Result<Vec<LocalOutput>, WalletError> {
        Ok(self.mixdepth(m)?.list_unspent().collect())
    }

    /// Mixdepth `m`'s confirmed balance.
    pub fn confirmed_balance(&self, m: u32) -> Result<Amount, WalletError> {
        Ok(self.mixdepth(m)?.balance().confirmed)
    }

    /// The height of the last block applied.
    pub fn synced_height(&self) -> u32 {
        self.mixdepths
            .first()
            .map_or(0, |w| w.latest_checkpoint().height())
    }

    /// Apply a block at `height` to every mixdepth. It must connect to the last applied block.
    pub fn apply_block(&mut self, block: &Block, height: u32) -> Result<(), WalletError> {
        for wallet in &mut self.mixdepths {
            wallet
                .apply_block(block, height)
                .map_err(|e| WalletError::CannotConnect(e.to_string()))?;
        }
        Ok(())
    }

    /// Record unconfirmed transactions seen at `seen_at` (Unix seconds).
    pub fn apply_unconfirmed(&mut self, txs: &[Transaction], seen_at: u64) {
        for wallet in &mut self.mixdepths {
            wallet.apply_unconfirmed_txs(txs.iter().cloned().map(|tx| (tx, seen_at)));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bdk_wallet::bitcoin::bip32::DerivationPath;
    use bdk_wallet::bitcoin::block::{Header, Version as BlockVersion};
    use bdk_wallet::bitcoin::blockdata::constants::genesis_block;
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::secp256k1::Secp256k1;
    use bdk_wallet::bitcoin::transaction::Version;
    use bdk_wallet::bitcoin::{
        CompactTarget, OutPoint, ScriptBuf, Sequence, TxIn, TxMerkleNode, TxOut, Txid, Witness,
        absolute,
    };
    use vortex_ng_core::script::wsh0_script_pubkey;

    use super::*;

    // The BIP84 / BIP86 test mnemonic (public test vector, not anyone's wallet).
    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn seed(network: Network) -> Seed {
        Seed::from_mnemonic(WORDS, "", network).unwrap()
    }

    #[test]
    fn bip84_vectors_sw0() {
        let w = PitWallet::new(&seed(Network::Bitcoin), Pit::Sw0).unwrap();
        assert_eq!(
            w.peek_address(0, false, 0).unwrap().to_string(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        assert_eq!(
            w.peek_address(0, false, 1).unwrap().to_string(),
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
        );
        assert_eq!(
            w.peek_address(0, true, 0).unwrap().to_string(),
            "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"
        );
    }

    #[test]
    fn bip86_vectors_tr0() {
        let w = PitWallet::new(&seed(Network::Bitcoin), Pit::Tr0).unwrap();
        assert_eq!(
            w.peek_address(0, false, 0).unwrap().to_string(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
        assert_eq!(
            w.peek_address(0, false, 1).unwrap().to_string(),
            "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"
        );
        assert_eq!(
            w.peek_address(0, true, 0).unwrap().to_string(),
            "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"
        );
    }

    #[test]
    fn wsh0_matches_the_draft_derivation() {
        let s = seed(Network::Regtest);
        let w = PitWallet::new(&s, Pit::Wsh0).unwrap();
        let secp = Secp256k1::new();
        for (m, chain, index) in [(0u32, 0u32, 0u32), (1, 0, 3), (4, 1, 2)] {
            let key = |account: u32| {
                let path =
                    DerivationPath::from_str(&format!("m/48'/1'/{account}'/2'/{chain}/{index}"))
                        .unwrap();
                s.master
                    .derive_priv(&secp, &path)
                    .unwrap()
                    .private_key
                    .public_key(&secp)
            };
            let expected = wsh0_script_pubkey(&key(2 * m), &key(2 * m + 1)).unwrap();
            assert_eq!(
                w.peek_address(m, chain == 1, index)
                    .unwrap()
                    .script_pubkey(),
                expected,
                "m={m}"
            );
        }
    }

    #[test]
    fn layout_rules() {
        let regtest = PitWallet::new(&seed(Network::Regtest), Pit::Sw0).unwrap();
        assert!(
            regtest
                .peek_address(0, false, 0)
                .unwrap()
                .to_string()
                .starts_with("bcrt1q")
        );
        // Mixdepths are separate accounts; a passphrase gives another wallet.
        assert_ne!(
            regtest.peek_address(0, false, 0).unwrap(),
            regtest.peek_address(1, false, 0).unwrap()
        );
        let other = PitWallet::new(
            &Seed::from_mnemonic(WORDS, "TREZOR", Network::Regtest).unwrap(),
            Pit::Sw0,
        )
        .unwrap();
        assert_ne!(
            other.peek_address(0, false, 0).unwrap(),
            regtest.peek_address(0, false, 0).unwrap()
        );
        assert_eq!(
            regtest.peek_address(MIXDEPTHS, false, 0),
            Err(WalletError::Mixdepth(MIXDEPTHS))
        );
        assert!(Seed::from_mnemonic("abandon abandon", "", Network::Regtest).is_err());
        assert!(!format!("{:?}", seed(Network::Regtest)).contains("prv"));
    }

    #[test]
    fn applying_a_block_credits_the_mixdepth() {
        let mut w = PitWallet::new(&seed(Network::Regtest), Pit::Tr0).unwrap();
        let addr = w.next_receive_address(2).unwrap();
        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([7; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(150_000),
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
            txdata: vec![tx],
        };
        w.apply_block(&block, 1).unwrap();
        assert_eq!(w.synced_height(), 1);
        assert_eq!(w.confirmed_balance(2).unwrap(), Amount::from_sat(150_000));
        assert_eq!(w.confirmed_balance(0).unwrap(), Amount::ZERO);
        assert_eq!(w.utxos(2).unwrap().len(), 1);
        // A block that does not connect is refused.
        let mut orphan = block.clone();
        orphan.header.prev_blockhash = bdk_wallet::bitcoin::BlockHash::from_byte_array([9; 32]);
        orphan.header.time += 1;
        assert!(matches!(
            w.apply_block(&orphan, 2),
            Err(WalletError::CannotConnect(_))
        ));
    }
}
