//! JoinMarket protocol logic for vortex-ng, with no I/O.
//!
//! vortex-ng implements JoinMarket's protocol layer as JMP-0001 and the JMP extensions specify it, and
//! carries it over Nostr only (`docs/jmp/jmp-draft-nostr-message-channel.md`). This crate holds the
//! parts that are pure functions of their inputs: protocol constants, nicks, signed messages and lines,
//! offers and commands, NaCl sessions, PoDLE, fidelity-bond proofs, and the pits' scripts; and (rest of
//! M1) the per-pit transaction rules.

pub mod bond;
pub mod command;
pub mod line;
pub mod nacl;
pub mod nick;
pub mod offer;
pub mod podle;
pub mod protocol;
pub mod script;
pub mod sigmsg;

pub use bitcoin;
