//! joinstr v1, the second coinjoin protocol vortex-ng speaks (ADR 0006).
//!
//! joinstr is not JoinMarket: a pool creator announces one denomination (kind 2022), peers join by NIP-04
//! and receive the pool's private key, register an output and one input signed
//! `SIGHASH_ALL | SIGHASH_ANYONECANPAY`, and anyone combines the registrations. This crate holds the protocol
//! with no I/O, as `vortex-ng-core` does for JoinMarket. Its rules are joinstr's `NIP.md` "Wire rules" and
//! `joinstr-difffuzz`'s `findings/RULES.md` (R1 to R8) at the revisions in `docs/upstream-pins.md`; where
//! those leave a detail open, the Electrum plugin's behaviour is followed, as RULES.md says.
//!
//! The reference clients are Python, and the numbers must come out the same, so [`pyjson`] reproduces what
//! Python's `json`, `==`, `round` and `repr` do.

pub mod lsag;
pub mod message;
pub mod pool;
pub mod pyjson;
pub mod recovery;
pub mod rules;
pub mod session;
pub mod tx;
