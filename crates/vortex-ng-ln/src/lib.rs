//! Lightning channel funding from coinjoin outputs.
//!
//! One `ChannelFunder` trait with LND (taproot and regular channels), Core Lightning and LDK
//! backends, following `docs/jmp/jmp-draft-channel-funding-outputs.md`: the taker never signs its
//! inputs before the peer's `funding_signed`. Built in M4.
