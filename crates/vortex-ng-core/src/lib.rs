//! JoinMarket protocol logic for vortex-ng, with no I/O.
//!
//! vortex-ng implements JoinMarket's protocol layer as JMP-0001 and the JMP extensions specify it, and
//! carries it over Nostr only (`docs/jmp/jmp-draft-nostr-message-channel.md`). This crate holds the
//! parts that are pure functions of their inputs: protocol constants, nicks, offer types, and (from
//! M1) the command codec, PoDLE, fidelity bonds and the per-pit transaction rules.

pub mod nick;
pub mod offer;
pub mod protocol;

pub use bitcoin;
