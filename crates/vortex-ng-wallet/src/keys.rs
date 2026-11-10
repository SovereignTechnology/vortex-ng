//! Per-UTXO private keys, for the `!ioauth` authentication signature and the taker's PoDLE.
//!
//! `sw0` gives the P2WPKH key; `tr0` the BIP86 *internal* key (joinmarket-ng's `!ioauth` sends the
//! internal key and the taker tweaks it; PoDLE uses `vortex_ng_core::script::taproot_output_secret` of
//! it, JMP-0010); `wsh0` the 2-of-2's two keys (accounts `2m` and `2m+1`).

use std::str::FromStr;

use bdk_wallet::bitcoin::bip32::DerivationPath;
use bdk_wallet::bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bdk_wallet::{KeychainKind, LocalOutput};
use vortex_ng_core::offer::Pit;

use crate::{PitWallet, WalletError, coin_type};

/// The private key(s) controlling one of our UTXOs. Never printed.
pub enum UtxoKeys {
    /// `sw0` key or `tr0` internal key.
    Single(SecretKey),
    /// `wsh0`: the keys from accounts `2m` and `2m+1`.
    Pair(SecretKey, SecretKey),
}

impl std::fmt::Debug for UtxoKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            UtxoKeys::Single(_) => "UtxoKeys::Single(..)",
            UtxoKeys::Pair(..) => "UtxoKeys::Pair(..)",
        })
    }
}

impl UtxoKeys {
    /// The authentication key: the first key.
    pub fn auth(&self) -> &SecretKey {
        match self {
            UtxoKeys::Single(k) | UtxoKeys::Pair(k, _) => k,
        }
    }

    /// For `wsh0`, the other key's public key.
    pub fn cosigner_public(&self) -> Option<PublicKey> {
        match self {
            UtxoKeys::Single(_) => None,
            UtxoKeys::Pair(_, k) => Some(PublicKey::from_secret_key(&Secp256k1::signing_only(), k)),
        }
    }
}

impl PitWallet {
    /// The private key(s) of mixdepth `m`'s UTXO `utxo`. The derived script is checked against the
    /// UTXO's, so a key is never returned for an output this derivation does not control.
    pub fn utxo_keys(&self, m: u32, utxo: &LocalOutput) -> Result<UtxoKeys, WalletError> {
        let secp = Secp256k1::new();
        let chain = match utxo.keychain {
            KeychainKind::External => 0,
            KeychainKind::Internal => 1,
        };
        let (c, i) = (coin_type(self.network), utxo.derivation_index);
        let derive = |path: String| -> Result<SecretKey, WalletError> {
            let path = DerivationPath::from_str(&path)
                .map_err(|e| WalletError::Descriptor(e.to_string()))?;
            Ok(self
                .master
                .derive_priv(&secp, &path)
                .map_err(|e| WalletError::Descriptor(e.to_string()))?
                .private_key)
        };
        let keys = match self.pit {
            Pit::Sw0 => UtxoKeys::Single(derive(format!("m/84'/{c}'/{m}'/{chain}/{i}"))?),
            Pit::Tr0 => UtxoKeys::Single(derive(format!("m/86'/{c}'/{m}'/{chain}/{i}"))?),
            Pit::Wsh0 => UtxoKeys::Pair(
                derive(format!("m/48'/{c}'/{}'/2'/{chain}/{i}", 2 * m))?,
                derive(format!("m/48'/{c}'/{}'/2'/{chain}/{i}", 2 * m + 1))?,
            ),
        };
        if self.peek_address(m, chain == 1, i)?.script_pubkey() != utxo.txout.script_pubkey {
            return Err(WalletError::Descriptor(
                "derived script does not match the UTXO".into(),
            ));
        }
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{
        Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf, TxOut, Txid,
    };
    use bdk_wallet::chain::ChainPosition;
    use vortex_ng_core::script::{Binding, binding_of, taproot_output_secret};

    use super::*;
    use crate::Seed;

    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn local(w: &PitWallet, m: u32, internal: bool, index: u32) -> LocalOutput {
        LocalOutput {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([1; 32]),
                vout: 0,
            },
            txout: TxOut {
                value: Amount::from_sat(1),
                script_pubkey: w.peek_address(m, internal, index).unwrap().script_pubkey(),
            },
            keychain: if internal {
                KeychainKind::Internal
            } else {
                KeychainKind::External
            },
            is_spent: false,
            derivation_index: index,
            chain_position: ChainPosition::Unconfirmed {
                first_seen: None,
                last_seen: None,
            },
        }
    }

    #[test]
    fn keys_bind_to_their_outputs() {
        let secp = Secp256k1::new();
        for pit in [Pit::Sw0, Pit::Tr0, Pit::Wsh0] {
            let w = PitWallet::new(
                &Seed::from_mnemonic(WORDS, "", Network::Regtest).unwrap(),
                pit,
            )
            .unwrap();
            let utxo = local(&w, 2, true, 5);
            let keys = w.utxo_keys(2, &utxo).unwrap();
            let auth = PublicKey::from_secret_key(&secp, keys.auth());
            let binding = match pit {
                Pit::Tr0 => binding_of(
                    &PublicKey::from_secret_key(&secp, &taproot_output_secret(&secp, keys.auth())),
                    None,
                    &utxo.txout.script_pubkey,
                ),
                _ => binding_of(
                    &auth,
                    keys.cosigner_public().as_ref(),
                    &utxo.txout.script_pubkey,
                ),
            };
            let expected = match pit {
                Pit::Sw0 => Binding::P2wpkh,
                Pit::Tr0 => Binding::P2trOutputKey,
                Pit::Wsh0 => Binding::Wsh0,
            };
            assert_eq!(binding, Some(expected), "{pit:?}");
            assert!(!format!("{keys:?}").contains(&keys.auth().display_secret().to_string()));
        }
    }

    #[test]
    fn foreign_script_is_refused() {
        let w = PitWallet::new(
            &Seed::from_mnemonic(WORDS, "", Network::Regtest).unwrap(),
            Pit::Sw0,
        )
        .unwrap();
        let mut utxo = local(&w, 0, false, 0);
        let other = PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[9; 32]).unwrap(),
        );
        utxo.txout.script_pubkey =
            ScriptBuf::new_p2wpkh(&CompressedPublicKey(other).wpubkey_hash());
        assert!(w.utxo_keys(0, &utxo).is_err());
    }
}
