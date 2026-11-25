//! Drives joinstr pools over their relay (ADR 0006): listing pools, joining one, and running a peer's
//! [`Peer`] session on the pool's channel, for a joiner or for the pool's creator.
//!
//! The session (`vortex-ng-joinstr`) decides everything; this module moves messages between it and a
//! [`PoolClient`], hands out credentials when we host the pool, starts the recovery round when inputs stay
//! missing, and checks the finished transaction's coins against the chain before returning it. Broadcasting
//! is the caller's step. Pools that require aut-ct are joined and hosted through a local aut-ct server
//! (`vortex-ng-autct`): a joiner sends a proof with its join request, a creator verifies it and admits each
//! key image once.

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use vortex_ng_autct::keyfile::KeyFile;
use vortex_ng_autct::rpc::Client as AutctClient;

use vortex_ng_chain::ChainLookup;
use vortex_ng_core::bitcoin::secp256k1::SecretKey;
use vortex_ng_core::bitcoin::{OutPoint, Transaction};
use vortex_ng_joinstr::message::{PoolMessage, admit_join};
use vortex_ng_joinstr::pool::{Pool, Transport, accept_credentials};
use vortex_ng_joinstr::session::{Action, Peer};
use vortex_ng_nostr::client::unix_now;
use vortex_ng_nostr::pool::{PoolClient, PoolIncoming, keys_from_secret};

use crate::{CONNECT_TIMEOUT, NodeError, blocking};

/// Most pools kept from one listing.
pub const MAX_POOLS: usize = 500;
/// A pool's creator answers at most this many join requests per peer slot.
pub const JOINS_PER_SLOT: usize = 4;

fn now() -> i64 {
    i64::try_from(unix_now()).unwrap_or(i64::MAX)
}

/// A connection to `relay` as the pool key `secret` (the creator's, or a joiner's once it has credentials).
pub async fn pool_client(
    secret: &SecretKey,
    relay: &str,
    proxy: Option<SocketAddr>,
) -> Result<PoolClient, NodeError> {
    let keys = keys_from_secret(&secret.secret_bytes())?;
    Ok(PoolClient::connect(keys, relay, proxy, CONNECT_TIMEOUT).await?)
}

/// The pools announced on `relay` since `since` that we could join now: well-formed, signed by their own
/// key, still open and over Tor; those with an aut-ct requirement only with `with_autct` (we have a server
/// to prove with). Listens for `wait`.
pub async fn list_pools(
    relay: &str,
    proxy: Option<SocketAddr>,
    since: u64,
    wait: Duration,
    with_autct: bool,
) -> Result<Vec<Pool>, NodeError> {
    let keys = vortex_ng_nostr::nostr::key::Keys::generate();
    let mut client = PoolClient::connect(keys, relay, proxy, CONNECT_TIMEOUT).await?;
    client.subscribe_pools(since).await?;
    let until = Instant::now() + wait;
    let mut pools: Vec<Pool> = Vec::new();
    while let Some(left) = until.checked_duration_since(Instant::now()) {
        let Some(incoming) = client.next(left).await else {
            break;
        };
        let PoolIncoming::Announcement {
            author, content, ..
        } = incoming
        else {
            continue;
        };
        // One announcement we cannot read never hides the others (R1.9).
        let Ok(pool) = Pool::from_announcement(&author, &content) else {
            continue;
        };
        let joinable = pool.open_at(now())
            && pool.transport == Transport::Tor
            && (with_autct || pool.autct.is_none());
        if joinable
            && pools.len() < MAX_POOLS
            && !pools.iter().any(|p| p.public_key == pool.public_key)
        {
            pools.push(pool);
        }
    }
    client.shutdown().await;
    Ok(pools)
}

/// What a joiner proves an aut-ct pool's requirement with.
#[derive(Clone, Copy, Debug)]
pub struct AutctProver<'a> {
    /// The local aut-ct server, already serving this pool's context and keyset.
    pub server: &'a AutctClient,
    /// The directory holding keyset files; the pool names one by its canonical file name.
    pub keysets: &'a Path,
    /// A private directory for the one-call key file.
    pub scratch: &'a Path,
    /// The proving UTXO's private key, WIF. It must satisfy `Autct::accepts` and is never the coin that
    /// enters the coinjoin.
    pub wif: &'a str,
    /// The Bitcoin network as aut-ct names it: `mainnet`, `signet` or `regtest`.
    pub network: &'a str,
}

/// What a creator verifies joiners' proofs with.
#[derive(Clone, Copy, Debug)]
pub struct AutctVerifier<'a> {
    /// The local aut-ct server, already serving this pool's context and keyset.
    pub server: &'a AutctClient,
    /// The directory holding keyset files.
    pub keysets: &'a Path,
}

/// The pool we created and what we host it with.
#[derive(Clone, Copy, Debug)]
pub struct Hosting<'a> {
    /// The pool as announced.
    pub pool: &'a Pool,
    /// Its private key, handed to every admitted joiner.
    pub key: &'a SecretKey,
    /// The proof verifier, for a pool with an aut-ct requirement.
    pub autct: Option<AutctVerifier<'a>>,
}

fn autct_error(e: vortex_ng_autct::AutctError) -> NodeError {
    NodeError::Pool(e.to_string())
}

/// Ask to join `pool` from a fresh key and wait up to `wait` for its credentials. Anyone reading the relay
/// can answer a join request; only an answer carrying the announced pool's private key and unchanged terms
/// is accepted. Returns that key. A pool with an aut-ct requirement needs `prover`.
pub async fn join_pool(
    pool: &Pool,
    proxy: Option<SocketAddr>,
    wait: Duration,
    prover: Option<AutctProver<'_>>,
) -> Result<SecretKey, NodeError> {
    let join = match (&pool.autct, prover) {
        (None, _) => PoolMessage::JoinPool {
            autct_proof: None,
            autct_token: None,
        },
        (Some(_), None) => return Err(NodeError::Pool("the pool requires an aut-ct proof".into())),
        (Some(autct), Some(prover)) => {
            let context = vortex_ng_autct::context(&pool.id, &pool.public_key);
            let key_file = KeyFile::create(prover.scratch, prover.wif).map_err(autct_error)?;
            let proof = prover
                .server
                .prove(
                    &context,
                    &prover.keysets.join(&autct.keyset),
                    &key_file,
                    prover.network,
                )
                .await
                .map_err(autct_error)?;
            PoolMessage::JoinPool {
                autct_proof: Some(proof.proof),
                autct_token: Some(proof.key_image),
            }
        }
    };
    let keys = vortex_ng_nostr::nostr::key::Keys::generate();
    let mut client = PoolClient::connect(keys, &pool.relay, proxy, CONNECT_TIMEOUT).await?;
    client
        .subscribe_direct(unix_now().saturating_sub(5))
        .await?;
    client.send(&pool.public_key, &join.to_plaintext()).await?;
    let until = Instant::now() + wait;
    let mut result = Err(NodeError::Timeout);
    while let Some(left) = until.checked_duration_since(Instant::now()) {
        let plaintext = match client.next(left).await {
            Some(PoolIncoming::Direct { plaintext, .. }) => plaintext,
            Some(PoolIncoming::Announcement { .. }) => continue,
            None => break,
        };
        match accept_credentials(&plaintext, pool) {
            Ok(key) => {
                result = Ok(key);
                break;
            }
            Err(vortex_ng_joinstr::pool::CredentialsError::Rejected(why)) => {
                result = Err(NodeError::Pool(format!("join request refused: {why}")));
                break;
            }
            // Somebody else's answer, or noise: keep waiting for the pool's.
            Err(_) => {}
        }
    }
    client.shutdown().await;
    result
}

/// Whether the creator admits a join request: always in a plain pool; in an aut-ct pool only with a proof
/// that verifies for this pool's context and whose key image (as the verifier returns it, never as the
/// joiner states it) has not been admitted before. The error is the `reject` reason.
async fn admission(
    host: &Hosting<'_>,
    proof: Option<&str>,
    key_images: &mut Vec<String>,
) -> Result<(), &'static str> {
    let Some(autct) = &host.pool.autct else {
        return Ok(());
    };
    let proof = proof.ok_or("missing_proof")?;
    let verifier = host.autct.ok_or("invalid_proof")?;
    let context = vortex_ng_autct::context(&host.pool.id, &host.pool.public_key);
    let key_image = verifier
        .server
        .verify(&context, &verifier.keysets.join(&autct.keyset), proof)
        .await
        .map_err(|_| "invalid_proof")?;
    if key_images.contains(&key_image) {
        return Err("duplicate_token");
    }
    key_images.push(key_image);
    Ok(())
}

/// Whether `tx` may be returned: every coin it spends is unspent on `chain`, or `chain` already has the
/// transaction (its first output is there).
///
/// The coins are asked first and the transaction second, and the order matters. Every peer finishes the round
/// at the same moment, and any of them may broadcast it. Asked the other way round, a peer finds the
/// transaction absent, a second peer broadcasts it, and the peer then finds its coins spent and fails a round
/// that is done. Asked in this order, a coin that is seen spent was spent by something that was already on the
/// node, and the transaction is looked for after that: if it is ours, it is there.
fn coins_unspent_or_tx_known(chain: &impl ChainLookup, tx: &Transaction) -> bool {
    tx.input
        .iter()
        .all(|i| matches!(chain.utxo(&i.previous_output), Ok(Some(_))))
        || matches!(
            chain.utxo(&OutPoint {
                txid: tx.compute_txid(),
                vout: 0
            }),
            Ok(Some(_))
        )
}

/// Run `peer`'s session on the pool's channel until it yields the transaction, and return it.
///
/// `client` is connected as the pool key (see [`pool_client`]) and reads the channel from `since`, which
/// must not be later than the pool's announcement. With `hosting` we are the creator and also answer join
/// requests: with the credentials, or, in an aut-ct pool, with a `reject` when the proof is missing, does not
/// verify, or reuses a key image. If our registration has been out for
/// `input_wait` without the round completing, the recovery round starts. Every coin the finished
/// transaction spends must be an unspent output on `chain`, unless `chain` already has the transaction
/// itself: any peer may broadcast it, and the first to do so spends every coin in it.
pub async fn run_pool(
    peer: &mut Peer,
    client: &mut PoolClient,
    hosting: Option<Hosting<'_>>,
    chain: &impl ChainLookup,
    since: u64,
    input_wait: Duration,
    until: Instant,
) -> Result<Transaction, NodeError> {
    let pool_key = client.public_key();
    client.subscribe_direct(since).await?;
    let mut answered: Vec<String> = Vec::new();
    let mut key_images: Vec<String> = Vec::new();
    let mut registered_at: Option<Instant> = None;
    let mut recovering = false;
    let mut actions = peer.start()?;
    loop {
        for action in std::mem::take(&mut actions) {
            match action {
                Action::Send(text) => client.send(&pool_key, &text).await?,
                Action::Broadcast(tx) => {
                    if !blocking(|| coins_unspent_or_tx_known(chain, &tx)) {
                        return Err(NodeError::Pool(
                            "the transaction spends a coin that is not unspent".into(),
                        ));
                    }
                    return Ok(tx);
                }
            }
        }
        if peer.has_registered() && registered_at.is_none() {
            registered_at = Some(Instant::now());
        }
        let Some(mut left) = until.checked_duration_since(Instant::now()) else {
            return Err(NodeError::Timeout);
        };
        if let (Some(at), false) = (registered_at, recovering) {
            let Some(to_recovery) = (at + input_wait).checked_duration_since(Instant::now()) else {
                recovering = true;
                actions = peer.on_timeout()?;
                continue;
            };
            left = left.min(to_recovery);
        }
        match client.next(left).await {
            Some(PoolIncoming::Direct {
                sender, plaintext, ..
            }) if sender == pool_key => {
                actions = peer.on_message(&plaintext)?;
            }
            Some(PoolIncoming::Direct {
                sender, plaintext, ..
            }) => {
                let Some(host) = hosting else {
                    continue;
                };
                let room = answered.len() < JOINS_PER_SLOT * host.pool.peers as usize;
                let Some(PoolMessage::JoinPool { autct_proof, .. }) =
                    admit_join(&plaintext, &sender, &pool_key, &answered).filter(|_| room)
                else {
                    continue;
                };
                // Answered once, whatever the answer: a proof costs seconds to verify.
                answered.push(sender.clone());
                let answer = match admission(&host, autct_proof.as_deref(), &mut key_images).await {
                    Ok(()) => host.pool.credentials(host.key),
                    Err(reason) => PoolMessage::Reject {
                        reason: reason.into(),
                    }
                    .to_plaintext(),
                };
                // A failed send to one joiner must not stop the pool.
                let _ = client.send(&sender, &answer).await;
            }
            Some(PoolIncoming::Announcement { .. }) | None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use nostr_sdk::prelude::MockRelay;
    use vortex_ng_chain::Utxo;
    use vortex_ng_core::bitcoin::absolute::LockTime;
    use vortex_ng_core::bitcoin::hashes::Hash;
    use vortex_ng_core::bitcoin::secp256k1::Secp256k1;
    use vortex_ng_core::bitcoin::transaction::Version;
    use vortex_ng_core::bitcoin::{
        Address, Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf, Sequence, TxIn, TxOut,
        Txid, Witness,
    };

    use super::*;

    #[derive(Clone, Default)]
    struct Coins(Arc<HashMap<OutPoint, Utxo>>);

    impl ChainLookup for Coins {
        fn utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, String> {
            Ok(self.0.get(outpoint).cloned())
        }
        fn tip_height(&self) -> Result<u32, String> {
            Ok(300)
        }
        fn block_time(&self, height: u32) -> Result<u32, String> {
            Ok(1_700_000_000 + height * 600)
        }
    }

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn address(k: &SecretKey) -> Address {
        Address::p2wpkh(
            &CompressedPublicKey(k.public_key(&Secp256k1::new())),
            Network::Regtest,
        )
    }

    fn coin(i: u8) -> (OutPoint, TxOut) {
        let txout = TxOut {
            value: Amount::from_sat(101_000 + u64::from(i)),
            script_pubkey: address(&key(i)).script_pubkey(),
        };
        (
            OutPoint {
                txid: Txid::from_byte_array([i; 32]),
                vout: u32::from(i),
            },
            txout,
        )
    }

    fn chain() -> Coins {
        let utxos = (1..=3u8)
            .map(|i| {
                let (outpoint, txout) = coin(i);
                let utxo = Utxo {
                    value: txout.value,
                    script_pubkey: txout.script_pubkey,
                    confirmations: 6,
                    coinbase: false,
                };
                (outpoint, utxo)
            })
            .collect();
        Coins(Arc::new(utxos))
    }

    fn peer(i: u8, pool: &Pool) -> Peer {
        let (outpoint, txout) = coin(i);
        Peer::new(
            pool.clone(),
            Network::Regtest,
            address(&key(100 + i)),
            outpoint,
            txout,
            key(i),
        )
        .unwrap()
    }

    const WAIT: Duration = Duration::from_secs(20);

    /// A joiner's whole path: find the pool on the relay, get its credentials, run the round.
    async fn join_and_run(
        i: u8,
        url: String,
        since: u64,
        input_wait: Duration,
    ) -> Result<Transaction, NodeError> {
        let pools = list_pools(&url, None, since, Duration::from_secs(2), false).await?;
        let pool = pools.first().expect("the pool is listed").clone();
        let pool_key = join_pool(&pool, None, WAIT, None).await?;
        let mut client = pool_client(&pool_key, &pool.relay, None).await?;
        let mut peer = peer(i, &pool);
        run_pool(
            &mut peer,
            &mut client,
            None,
            &chain(),
            since,
            input_wait,
            Instant::now() + WAIT,
        )
        .await
    }

    async fn host(
        pool: Pool,
        pool_key: SecretKey,
        since: u64,
        input_wait: Duration,
    ) -> Result<Transaction, NodeError> {
        let mut client = pool_client(&pool_key, &pool.relay, None).await?;
        client.announce(&pool.announcement()).await?;
        let mut peer = peer(1, &pool);
        let hosting = Some(Hosting {
            pool: &pool,
            key: &pool_key,
            autct: None,
        });
        run_pool(
            &mut peer,
            &mut client,
            hosting,
            &chain(),
            since,
            input_wait,
            Instant::now() + WAIT,
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_pool_is_created_joined_and_completed_over_a_relay() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let since = unix_now() - 60;
        let pool_key = key(200);
        let pool = Pool::create(&pool_key, "pool1", 0.001, 3, now() + 3600, &url, 2.5).unwrap();
        let creator = tokio::spawn(host(pool, pool_key, since, WAIT));
        let joiners: Vec<_> = (2..=3u8)
            .map(|i| tokio::spawn(join_and_run(i, url.clone(), since, WAIT)))
            .collect();
        let tx = creator.await.unwrap().unwrap();
        for joiner in joiners {
            assert_eq!(
                joiner.await.unwrap().unwrap(),
                tx,
                "every peer builds the same transaction"
            );
        }
        assert_eq!((tx.input.len(), tx.output.len()), (3, 3));
        assert!(tx.output.iter().all(|o| o.value.to_sat() == 99_750));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_peer_that_withholds_its_input_is_recovered_from() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let since = unix_now() - 60;
        let pool_key = key(201);
        let pool = Pool::create(&pool_key, "pool2", 0.001, 3, now() + 3600, &url, 2.5).unwrap();
        let input_wait = Duration::from_secs(4);
        let creator = tokio::spawn(host(pool.clone(), pool_key, since, input_wait));
        let joiner = tokio::spawn(join_and_run(2, url.clone(), since, input_wait));
        // The third peer joins, registers an output, and goes silent.
        let ghost_key = join_pool(&pool, None, WAIT, None).await.unwrap();
        let ghost = pool_client(&ghost_key, &url, None).await.unwrap();
        let output = PoolMessage::Output {
            address: address(&key(150)).to_string(),
        };
        ghost
            .send(&pool.public_key, &output.to_plaintext())
            .await
            .unwrap();

        let tx = creator.await.unwrap().unwrap();
        assert_eq!(joiner.await.unwrap().unwrap(), tx);
        assert_eq!(
            (tx.input.len(), tx.output.len()),
            (2, 2),
            "the silent peer's output is gone"
        );
        // 100 * 2 + 68 * 2 + 100 = 436 vbytes at 2.5 sat/vB: 1090 // 2 = 545 per output.
        assert!(tx.output.iter().all(|o| o.value.to_sat() == 100_000 - 545));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_transaction_spending_a_missing_coin_is_not_returned() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let since = unix_now() - 60;
        let pool_key = key(202);
        let pool = Pool::create(&pool_key, "pool3", 0.001, 2, now() + 3600, &url, 2.5).unwrap();
        // The creator's chain does not know the joiner's coin.
        let mut known = HashMap::new();
        let (outpoint, txout) = coin(1);
        known.insert(
            outpoint,
            Utxo {
                value: txout.value,
                script_pubkey: txout.script_pubkey,
                confirmations: 6,
                coinbase: false,
            },
        );
        let partial = Coins(Arc::new(known));
        let host_pool = pool.clone();
        let creator = tokio::spawn(async move {
            let mut client = pool_client(&pool_key, &host_pool.relay, None).await?;
            client.announce(&host_pool.announcement()).await?;
            let mut peer = peer(1, &host_pool);
            let hosting = Some(Hosting {
                pool: &host_pool,
                key: &pool_key,
                autct: None,
            });
            run_pool(
                &mut peer,
                &mut client,
                hosting,
                &partial,
                since,
                WAIT,
                Instant::now() + WAIT,
            )
            .await
        });
        let joiner = tokio::spawn(join_and_run(2, url, since, WAIT));
        assert!(matches!(creator.await.unwrap(), Err(NodeError::Pool(_))));
        assert!(joiner.await.unwrap().is_ok());
    }
    /// A chain on which another peer has already broadcast the round: its coins are spent, and every other
    /// output it is asked about (the round's own) is there.
    #[derive(Clone)]
    struct AlreadyBroadcast;

    impl ChainLookup for AlreadyBroadcast {
        fn utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, String> {
            if (1..=3u8).any(|i| coin(i).0 == *outpoint) {
                return Ok(None);
            }
            Ok(Some(Utxo {
                value: vortex_ng_core::bitcoin::Amount::from_sat(99_750),
                script_pubkey: address(&key(150)).script_pubkey(),
                confirmations: 0,
                coinbase: false,
            }))
        }
        fn tip_height(&self) -> Result<u32, String> {
            Ok(300)
        }
        fn block_time(&self, height: u32) -> Result<u32, String> {
            Ok(1_700_000_000 + height * 600)
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_round_another_peer_broadcast_first_is_still_returned() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let since = unix_now() - 60;
        let pool_key = key(204);
        let pool = Pool::create(&pool_key, "pool5", 0.001, 2, now() + 3600, &url, 2.5).unwrap();
        let host_pool = pool.clone();
        let creator = tokio::spawn(async move {
            let mut client = pool_client(&pool_key, &host_pool.relay, None).await?;
            client.announce(&host_pool.announcement()).await?;
            let mut peer = peer(1, &host_pool);
            let hosting = Some(Hosting {
                pool: &host_pool,
                key: &pool_key,
                autct: None,
            });
            run_pool(
                &mut peer,
                &mut client,
                hosting,
                &AlreadyBroadcast,
                since,
                WAIT,
                Instant::now() + WAIT,
            )
            .await
        });
        let joiner = tokio::spawn(join_and_run(2, url, since, WAIT));
        let tx = creator.await.unwrap().unwrap();
        assert_eq!(joiner.await.unwrap().unwrap(), tx);
    }

    /// A chain on which another peer's broadcast of the round lands after `before` questions: until then the
    /// round's coins are unspent and its first output is absent, afterwards the coins are spent and the output
    /// is there.
    struct BroadcastAfter {
        asked: AtomicUsize,
        before: usize,
    }

    impl ChainLookup for BroadcastAfter {
        fn utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, String> {
            let broadcast = self.asked.fetch_add(1, Ordering::SeqCst) >= self.before;
            let is_coin = (1..=3u8).any(|i| coin(i).0 == *outpoint);
            Ok((is_coin != broadcast).then(|| Utxo {
                value: Amount::from_sat(99_750),
                script_pubkey: address(&key(150)).script_pubkey(),
                confirmations: 0,
                coinbase: false,
            }))
        }
        fn tip_height(&self) -> Result<u32, String> {
            Ok(300)
        }
        fn block_time(&self, height: u32) -> Result<u32, String> {
            Ok(1_700_000_000 + height * 600)
        }
    }

    /// A round of the coins `coin(1)` to `coin(3)`.
    fn round_of_three() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: (1..=3u8)
                .map(|i| TxIn {
                    previous_output: coin(i).0,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![coin(4).1],
        }
    }

    #[test]
    fn a_broadcast_landing_between_the_questions_does_not_fail_the_round() {
        let tx = round_of_three();
        // Three coins and then the transaction are asked at most: the other peer's broadcast may land before
        // any of those four, or after all of them.
        for before in 0..=4 {
            let chain = BroadcastAfter {
                asked: AtomicUsize::new(0),
                before,
            };
            assert!(
                coins_unspent_or_tx_known(&chain, &tx),
                "the broadcast landed after {before} questions"
            );
        }
    }

    #[test]
    fn coins_spent_by_another_transaction_still_fail_the_round() {
        // `Coins::default()` holds nothing: the coins are spent and the round's own output was never there.
        assert!(!coins_unspent_or_tx_known(
            &Coins::default(),
            &round_of_three()
        ));
    }

    /// A stand-in aut-ct server speaking the real framing. A proof is the proving key itself, and its key
    /// image is derived from that key, so one key gives one image as in aut-ct.
    async fn fake_autct() -> AutctClient {
        use futures::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let Ok(mut socket) = tokio_tungstenite::accept_async(stream).await else {
                        return;
                    };
                    let Some(Ok(Message::Binary(header))) = socket.next().await else {
                        return;
                    };
                    let Some(Ok(Message::Binary(body))) = socket.next().await else {
                        return;
                    };
                    let header: serde_json::Value = serde_json::from_slice(&header).unwrap();
                    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    let answer = match header["Request"]["service_method"].as_str().unwrap() {
                        "RPCProver.prove" => {
                            let file =
                                std::fs::read(body["privkey_file_loc"].as_str().unwrap()).unwrap();
                            let password = body["encryption_password"].as_str().unwrap();
                            let wif =
                                vortex_ng_autct::keyfile::open(&file, password.as_bytes()).unwrap();
                            let wif = String::from_utf8(wif).unwrap();
                            serde_json::json!({"accepted": 0, "proof": wif, "key_image": format!("image-of-{wif}")})
                        }
                        _ => match body["proof"].as_str().unwrap() {
                            "forged" => serde_json::json!({"accepted": -2}),
                            wif => {
                                serde_json::json!({"accepted": 1, "key_image": format!("image-of-{wif}")})
                            }
                        },
                    };
                    let ack = br#"{"Response":{"id":0,"is_ok":true}}"#.to_vec();
                    socket.send(Message::Binary(ack.into())).await.unwrap();
                    socket
                        .send(Message::Binary(answer.to_string().into_bytes().into()))
                        .await
                        .unwrap();
                });
            }
        });
        AutctClient::new("127.0.0.1", port).unwrap()
    }

    /// Send a join request by hand and return the creator's plaintext answer.
    async fn raw_join(pool: &Pool, request: &PoolMessage) -> String {
        let keys = vortex_ng_nostr::nostr::key::Keys::generate();
        let mut client = PoolClient::connect(keys, &pool.relay, None, CONNECT_TIMEOUT)
            .await
            .unwrap();
        client.subscribe_direct(unix_now() - 5).await.unwrap();
        client
            .send(&pool.public_key, &request.to_plaintext())
            .await
            .unwrap();
        let Some(PoolIncoming::Direct { plaintext, .. }) = client.next(WAIT).await else {
            panic!("no answer to the join request")
        };
        plaintext
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_autct_pool_admits_each_proving_coin_once() {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let since = unix_now() - 60;
        let pool_key = key(203);
        let pool = Pool::create(&pool_key, "pool4", 0.001, 3, now() + 3600, &url, 2.5)
            .unwrap()
            .require_autct("autct-1-2-3-4-5.aks", 0, 1, "")
            .unwrap();
        let server = fake_autct().await;
        let keysets = std::path::PathBuf::from("/keysets");
        let scratch = std::env::temp_dir();

        let (host_pool, host_server, host_keysets) =
            (pool.clone(), server.clone(), keysets.clone());
        let creator = tokio::spawn(async move {
            let mut client = pool_client(&pool_key, &host_pool.relay, None).await?;
            client.announce(&host_pool.announcement()).await?;
            let mut peer = peer(1, &host_pool);
            let autct = Some(AutctVerifier {
                server: &host_server,
                keysets: &host_keysets,
            });
            let hosting = Some(Hosting {
                pool: &host_pool,
                key: &pool_key,
                autct,
            });
            run_pool(
                &mut peer,
                &mut client,
                hosting,
                &chain(),
                since,
                WAIT,
                Instant::now() + WAIT,
            )
            .await
        });

        // The pool is listed only for a client that can prove.
        assert!(
            list_pools(&url, None, since, Duration::from_secs(2), false)
                .await
                .unwrap()
                .is_empty()
        );
        let listed = list_pools(&url, None, since, Duration::from_secs(2), true)
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);

        // Without a prover we do not even ask; asking without a proof is refused by the creator.
        assert!(matches!(
            join_pool(&pool, None, WAIT, None).await,
            Err(NodeError::Pool(_))
        ));
        let plain = PoolMessage::JoinPool {
            autct_proof: None,
            autct_token: None,
        };
        assert_eq!(
            raw_join(&pool, &plain).await,
            r#"{"type": "reject", "reason": "missing_proof"}"#
        );
        // A proof the verifier refuses.
        let forged = PoolMessage::JoinPool {
            autct_proof: Some("forged".into()),
            autct_token: Some("x".into()),
        };
        assert_eq!(
            raw_join(&pool, &forged).await,
            r#"{"type": "reject", "reason": "invalid_proof"}"#
        );

        // A real proof is admitted and yields the pool key.
        let prover = |wif: &'static str| AutctProver {
            server: &server,
            keysets: &keysets,
            scratch: &scratch,
            wif,
            network: "regtest",
        };
        assert_eq!(
            join_pool(&pool, None, WAIT, Some(prover("coin-a")))
                .await
                .unwrap(),
            pool_key
        );
        // The same coin again, from another key and claiming another token: one coin, one slot.
        let again = join_pool(&pool, None, WAIT, Some(prover("coin-a"))).await;
        assert_eq!(
            again,
            Err(NodeError::Pool(
                "join request refused: duplicate_token".into()
            ))
        );
        let lying = PoolMessage::JoinPool {
            autct_proof: Some("coin-a".into()),
            autct_token: Some("fresh".into()),
        };
        assert_eq!(
            raw_join(&pool, &lying).await,
            r#"{"type": "reject", "reason": "duplicate_token"}"#
        );
        // Another coin is fine.
        assert_eq!(
            join_pool(&pool, None, WAIT, Some(prover("coin-b")))
                .await
                .unwrap(),
            pool_key
        );
        creator.abort();
    }
}
