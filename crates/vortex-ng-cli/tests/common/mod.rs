//! Lightning channel closes, made by hand for the regtest tests.
//!
//! Core on regtest here has no wallet and no Lightning node beside it, so the tests act as both peers of a
//! channel: they hold the two funding keys, and a coinbase paying the funding address stands in for the
//! funding transaction. The scripts are built from opcodes the way BOLT 3 writes them, not from the byte
//! layout `vortex_ng_core::lnclose` looks for, and Core's script interpreter validates every spend.

// Each test file uses some of these.
#![allow(dead_code, clippy::unwrap_used)]

use vortex_ng_chain::CoreRpc;
use vortex_ng_core::bitcoin::hashes::Hash;
use vortex_ng_core::bitcoin::opcodes::all::{
    OP_CHECKMULTISIG, OP_CHECKSIG, OP_CSV, OP_DROP, OP_ELSE, OP_ENDIF, OP_IF, OP_PUSHNUM_2,
};
use vortex_ng_core::bitcoin::script::Builder;
use vortex_ng_core::bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use vortex_ng_core::bitcoin::sighash::{EcdsaSighashType, SighashCache};
use vortex_ng_core::bitcoin::transaction::Version;
use vortex_ng_core::bitcoin::{
    Address, Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Witness, absolute, ecdsa,
};

/// Mine one block paying `address`, and return its coinbase payout and value (the stand-in for a funding
/// transaction's output).
pub fn mine_to(rpc: &CoreRpc, address: &Address) -> (OutPoint, Amount) {
    let hashes = rpc.generate_to_address(1, address).unwrap();
    let block = rpc.block(&hashes[0]).unwrap();
    let coinbase = &block.txdata[0];
    (
        OutPoint {
            txid: coinbase.compute_txid(),
            vout: 0,
        },
        coinbase.output[0].value,
    )
}

/// A P2WPKH script paying a key made from `seed`: a peer's payout, or a script nobody here spends.
pub fn payout(seed: u8) -> ScriptBuf {
    let secp = Secp256k1::new();
    let key = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap());
    ScriptBuf::new_p2wpkh(&CompressedPublicKey(key).wpubkey_hash())
}

fn transaction(
    spending: OutPoint,
    sequence: u32,
    lock_time: u32,
    outputs: Vec<TxOut>,
) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::from_consensus(lock_time),
        input: vec![TxIn {
            previous_output: spending,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::new(),
        }],
        output: outputs,
    }
}

fn sign(tx: &Transaction, script: &ScriptBuf, value: Amount, key: &SecretKey) -> ecdsa::Signature {
    let hash = SighashCache::new(tx)
        .p2wsh_signature_hash(0, script, value, EcdsaSighashType::All)
        .unwrap();
    let message = Message::from_digest(hash.to_byte_array());
    ecdsa::Signature {
        signature: Secp256k1::new().sign_ecdsa(&message, key),
        sighash_type: EcdsaSighashType::All,
    }
}

/// A channel between two parties the test plays both of.
pub struct Channel {
    /// The two funding keys, in the order their public keys sort (BOLT 3).
    keys: [SecretKey; 2],
    /// `2 <pubkey1> <pubkey2> 2 OP_CHECKMULTISIG`.
    script: ScriptBuf,
}

impl Channel {
    /// A channel whose keys come from `seed` and `seed + 1`.
    pub fn new(seed: u8) -> Channel {
        let secp = Secp256k1::new();
        let mut keys = [
            SecretKey::from_slice(&[seed; 32]).unwrap(),
            SecretKey::from_slice(&[seed + 1; 32]).unwrap(),
        ];
        keys.sort_by_key(|key| PublicKey::from_secret_key(&secp, key).serialize());
        let [first, second] = keys.map(|key| {
            vortex_ng_core::bitcoin::PublicKey::new(PublicKey::from_secret_key(&secp, &key))
        });
        let script = Builder::new()
            .push_opcode(OP_PUSHNUM_2)
            .push_key(&first)
            .push_key(&second)
            .push_opcode(OP_PUSHNUM_2)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        Channel { keys, script }
    }

    /// The funding output's address.
    pub fn funding_address(&self) -> Address {
        Address::p2wsh(&self.script, Network::Regtest)
    }

    /// A transaction that spends the funding output `funding` (worth `value`) with both signatures:
    /// `<> <sig1> <sig2> <script>`.
    pub fn spend(
        &self,
        funding: OutPoint,
        value: Amount,
        sequence: u32,
        lock_time: u32,
        outputs: Vec<TxOut>,
    ) -> Transaction {
        let mut tx = transaction(funding, sequence, lock_time, outputs);
        let signatures = self.keys.map(|key| sign(&tx, &self.script, value, &key));
        let mut witness = Witness::new();
        witness.push([] as [u8; 0]);
        for signature in &signatures {
            witness.push_ecdsa_signature(signature);
        }
        witness.push(self.script.as_bytes());
        tx.input[0].witness = witness;
        tx
    }

    /// A force close as BOLT 3 lays it out: the commitment transaction (`nSequence` `0x80……`, `nLockTime`
    /// `0x20……`) paying `to_local` behind `delay` blocks and `to_remote` straight to `remote`.
    pub fn force_close(
        &self,
        funding: OutPoint,
        value: Amount,
        to_local: &ToLocal,
        to_local_value: Amount,
        remote: ScriptBuf,
        fee: Amount,
    ) -> Transaction {
        let to_remote = value - to_local_value - fee;
        self.spend(
            funding,
            value,
            0x8000_0001,
            0x2000_0002,
            vec![
                TxOut {
                    value: to_local_value,
                    script_pubkey: ScriptBuf::new_p2wsh(&to_local.script.wscript_hash()),
                },
                TxOut {
                    value: to_remote,
                    script_pubkey: remote,
                },
            ],
        )
    }
}

/// BOLT 3's `to_local`: `OP_IF <revocationpubkey> OP_ELSE <to_self_delay> OP_CSV OP_DROP <delayedpubkey>
/// OP_ENDIF OP_CHECKSIG`.
pub struct ToLocal {
    delayed: SecretKey,
    delay: u16,
    /// The witness script.
    pub script: ScriptBuf,
}

impl ToLocal {
    /// A `to_local` of `delay` blocks, with keys from `seed` and `seed + 1`.
    pub fn new(seed: u8, delay: u16) -> ToLocal {
        let secp = Secp256k1::new();
        let public = |seed: u8| {
            vortex_ng_core::bitcoin::PublicKey::new(PublicKey::from_secret_key(
                &secp,
                &SecretKey::from_slice(&[seed; 32]).unwrap(),
            ))
        };
        let script = Builder::new()
            .push_opcode(OP_IF)
            .push_key(&public(seed))
            .push_opcode(OP_ELSE)
            .push_int(i64::from(delay))
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_key(&public(seed + 1))
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        ToLocal {
            delayed: SecretKey::from_slice(&[seed + 1; 32]).unwrap(),
            delay,
            script,
        }
    }

    /// The transaction that sweeps `output` (the `to_local` output of a commitment transaction, worth
    /// `value`) to `to`, after the delay: `<sig> <> <script>`.
    pub fn sweep(
        &self,
        output: OutPoint,
        value: Amount,
        to: ScriptBuf,
        fee: Amount,
    ) -> Transaction {
        let mut tx = transaction(
            output,
            u32::from(self.delay),
            0,
            vec![TxOut {
                value: value - fee,
                script_pubkey: to,
            }],
        );
        let signature = sign(&tx, &self.script, value, &self.delayed);
        let mut witness = Witness::new();
        witness.push_ecdsa_signature(&signature);
        witness.push([] as [u8; 0]);
        witness.push(self.script.as_bytes());
        tx.input[0].witness = witness;
        tx
    }
}
