//! Pits and offer types.
//!
//! A pit is a coinjoin pool for one script family; pits never mix (JMP-0010). vortex-ng speaks the
//! native-segwit `sw0` pit (JMP-0001), the taproot `tr0` pit (JMP-0010) and the regular-channel
//! `wsh0` pit (`docs/jmp/jmp-draft-wsh0-pit.md`). The legacy and wrapped-segwit offer types are not
//! supported.

/// A coinjoin pool for one script family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Pit {
    /// Native segwit v0 P2WPKH (JMP-0001).
    Sw0,
    /// Taproot P2TR key-path (JMP-0010).
    Tr0,
    /// P2WSH 2-of-2, shaped like a Lightning funding output (vortex-ng draft).
    Wsh0,
}

impl Pit {
    /// Every pit vortex-ng speaks.
    pub const ALL: [Pit; 3] = [Pit::Sw0, Pit::Tr0, Pit::Wsh0];

    /// The pit's prefix in offer command names.
    pub const fn prefix(self) -> &'static str {
        match self {
            Pit::Sw0 => "sw0",
            Pit::Tr0 => "tr0",
            Pit::Wsh0 => "wsh0",
        }
    }
}

/// How an offer states its coinjoin fee.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FeeKind {
    /// A fraction of the coinjoin amount (`…reloffer`).
    Relative,
    /// A fixed number of satoshis (`…absoffer`).
    Absolute,
}

/// An offer type: its pit and fee kind, named by its command (for example `sw0reloffer`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OfferType {
    /// The pit the offer is for.
    pub pit: Pit,
    /// How the offer states its fee.
    pub fee: FeeKind,
}

impl OfferType {
    /// The offer's command name, without the `!` prefix.
    pub fn command(self) -> String {
        let suffix = match self.fee {
            FeeKind::Relative => "reloffer",
            FeeKind::Absolute => "absoffer",
        };
        format!("{}{suffix}", self.pit.prefix())
    }

    /// Parse an offer command name (without the `!` prefix). Unknown names, including the legacy
    /// `reloffer`/`absoffer` and wrapped-segwit `swreloffer`/`swabsoffer`, return `None`, which is
    /// how JoinMarket implementations treat offer types they do not speak.
    pub fn from_command(name: &str) -> Option<Self> {
        Pit::ALL.into_iter().find_map(|pit| {
            let rest = name.strip_prefix(pit.prefix())?;
            let fee = match rest {
                "reloffer" => FeeKind::Relative,
                "absoffer" => FeeKind::Absolute,
                _ => return None,
            };
            Some(OfferType { pit, fee })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_offer_type_round_trips() {
        for pit in Pit::ALL {
            for fee in [FeeKind::Relative, FeeKind::Absolute] {
                let offer = OfferType { pit, fee };
                assert_eq!(OfferType::from_command(&offer.command()), Some(offer));
            }
        }
    }

    #[test]
    fn known_names() {
        let names: Vec<String> = Pit::ALL
            .into_iter()
            .flat_map(|pit| {
                [FeeKind::Relative, FeeKind::Absolute].map(|fee| OfferType { pit, fee }.command())
            })
            .collect();
        assert_eq!(
            names,
            [
                "sw0reloffer",
                "sw0absoffer",
                "tr0reloffer",
                "tr0absoffer",
                "wsh0reloffer",
                "wsh0absoffer"
            ]
        );
    }

    #[test]
    fn unsupported_names_are_ignored() {
        for name in [
            "reloffer",
            "absoffer",
            "swreloffer",
            "swabsoffer",
            "sw0",
            "tr0offer",
            "!sw0reloffer",
            "",
        ] {
            assert_eq!(OfferType::from_command(name), None, "{name}");
        }
    }
}
