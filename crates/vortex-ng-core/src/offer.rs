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

/// A relative fee: an exact decimal `mantissa / 10^scale`, kept with its original text so it is sent
/// back exactly as the maker wrote it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelativeFee {
    mantissa: u128,
    scale: u32,
    text: String,
}

const MAX_SCALE: u32 = 30;

impl RelativeFee {
    /// Parse a non-negative decimal such as `0.00025`, `2.5e-05` or `1E-4` (Python's `str(float)`
    /// output, which makers may send). Signs, NaN and infinities are rejected.
    pub fn parse(text: &str) -> Option<RelativeFee> {
        let (number, exponent) = match text.find(['e', 'E']) {
            Some(i) => (&text[..i], text[i + 1..].parse::<i32>().ok()?),
            None => (text, 0),
        };
        let (int_part, frac_part) = number.split_once('.').unwrap_or((number, ""));
        if int_part.is_empty() && frac_part.is_empty() {
            return None;
        }
        if !int_part
            .bytes()
            .chain(frac_part.bytes())
            .all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let digits = format!("{int_part}{frac_part}");
        let digits = digits.trim_start_matches('0');
        let mut mantissa: u128 = if digits.is_empty() {
            0
        } else {
            digits.parse().ok()?
        };
        let mut scale = i64::try_from(frac_part.len()).ok()? - i64::from(exponent);
        while scale < 0 {
            mantissa = mantissa.checked_mul(10)?;
            scale += 1;
        }
        let scale = u32::try_from(scale).ok().filter(|s| *s <= MAX_SCALE)?;
        Some(RelativeFee {
            mantissa,
            scale,
            text: text.to_string(),
        })
    }

    /// The fee in satoshis on `amount`: `ROUND_HALF_EVEN(Decimal(cjfee) * amount)` (JMP-0001).
    pub fn fee_for(&self, amount: u64) -> Option<u64> {
        let numerator = self.mantissa.checked_mul(u128::from(amount))?;
        let denominator = 10u128.checked_pow(self.scale)?;
        let (quotient, remainder) = (numerator / denominator, numerator % denominator);
        let twice = remainder.checked_mul(2)?;
        let rounded = match twice.cmp(&denominator) {
            std::cmp::Ordering::Less => quotient,
            std::cmp::Ordering::Greater => quotient + 1,
            std::cmp::Ordering::Equal => quotient + (quotient & 1),
        };
        u64::try_from(rounded).ok()
    }

    /// The text as the maker sent it.
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

/// A coinjoin fee as offered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CjFee {
    /// A fraction of the coinjoin amount.
    Relative(RelativeFee),
    /// Satoshis.
    Absolute(u64),
}

/// An offer: `!<type> <oid> <minsize> <maxsize> <txfee> <cjfee>` (JMP-0001 "Phase 1", JMP-0010).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    /// Pit and fee kind.
    pub offer_type: OfferType,
    /// The maker's order id.
    pub oid: u64,
    /// Minimum coinjoin amount, satoshis.
    pub minsize: u64,
    /// Maximum coinjoin amount, satoshis.
    pub maxsize: u64,
    /// The maker's contribution to the mining fee, satoshis.
    pub txfee: u64,
    /// The coinjoin fee.
    pub cjfee: CjFee,
}

impl Offer {
    /// Parse an offer from its command name (without `!`) and its arguments.
    pub fn parse(command: &str, args: &str) -> Option<Offer> {
        let offer_type = OfferType::from_command(command)?;
        let fields: Vec<&str> = args.split(' ').collect();
        let [oid, minsize, maxsize, txfee, cjfee] = fields.as_slice() else {
            return None;
        };
        let int = |s: &str| -> Option<u64> {
            (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                .then(|| s.parse().ok())
                .flatten()
        };
        let (oid, minsize, maxsize, txfee) = (int(oid)?, int(minsize)?, int(maxsize)?, int(txfee)?);
        if minsize > maxsize {
            return None;
        }
        let cjfee = match offer_type.fee {
            FeeKind::Relative => CjFee::Relative(RelativeFee::parse(cjfee)?),
            FeeKind::Absolute => CjFee::Absolute(int(cjfee)?),
        };
        Some(Offer {
            offer_type,
            oid,
            minsize,
            maxsize,
            txfee,
            cjfee,
        })
    }

    /// The offer as a command line, with the `!` prefix.
    pub fn to_command(&self) -> String {
        let cjfee = match &self.cjfee {
            CjFee::Relative(r) => r.as_str().to_string(),
            CjFee::Absolute(a) => a.to_string(),
        };
        format!(
            "!{} {} {} {} {} {cjfee}",
            self.offer_type.command(),
            self.oid,
            self.minsize,
            self.maxsize,
            self.txfee
        )
    }

    /// The coinjoin fee in satoshis for `amount`, or `None` if out of range or overflowing.
    pub fn fee_for(&self, amount: u64) -> Option<u64> {
        if amount < self.minsize || amount > self.maxsize {
            return None;
        }
        match &self.cjfee {
            CjFee::Relative(r) => r.fee_for(amount),
            CjFee::Absolute(a) => Some(*a),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_fee_parsing_and_rounding() {
        let fee = |t: &str, amount: u64| RelativeFee::parse(t).unwrap().fee_for(amount).unwrap();
        assert_eq!(fee("0.00025", 1_000_000), 250);
        assert_eq!(fee("2.5e-05", 1_000_000), 25);
        assert_eq!(fee("1E-4", 1_000_000), 100);
        assert_eq!(fee("0", 1_000_000), 0);
        assert_eq!(fee(".5", 3), 2); // 1.5 -> 2 (half to even)
        assert_eq!(fee("0.5", 5), 2); // 2.5 -> 2 (half to even)
        assert_eq!(fee("0.5", 7), 4); // 3.5 -> 4
        assert_eq!(fee("0.0001", 12_345), 1); // 1.2345 -> 1
        assert_eq!(fee("0.00015", 10_000), 2); // 1.5 -> 2
        assert_eq!(fee("0.00025", 10_000), 2); // 2.5 -> 2
        assert_eq!(fee("1.2e1", 1), 12);
        for bad in [
            "", ".", "-0.1", "+0.1", "nan", "inf", "0.1.2", "1e", "0x1", "1e-40", " 0.1",
        ] {
            assert!(RelativeFee::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn offers_parse_and_serialize() {
        let rel = Offer::parse("sw0reloffer", "0 50000 10000000 0 0.00025").unwrap();
        assert_eq!(rel.to_command(), "!sw0reloffer 0 50000 10000000 0 0.00025");
        assert_eq!(rel.fee_for(1_000_000), Some(250));
        assert_eq!(rel.fee_for(10_000), None); // below minsize
        let abs = Offer::parse("tr0absoffer", "7 50000 10000000 0 250").unwrap();
        assert_eq!(
            abs.offer_type,
            OfferType {
                pit: Pit::Tr0,
                fee: FeeKind::Absolute
            }
        );
        assert_eq!(abs.fee_for(60_000), Some(250));
        let wsh = Offer::parse("wsh0reloffer", "3 100000 200000 10 2.5e-05").unwrap();
        assert_eq!(wsh.to_command(), "!wsh0reloffer 3 100000 200000 10 2.5e-05");
        for (cmd, args) in [
            ("sw0reloffer", "0 50000 10000000 0"),
            ("sw0reloffer", "0 50000 10000000 0 0.1 extra"),
            ("sw0reloffer", "0 60000 50000 0 0.1"),
            ("sw0reloffer", "-1 50000 60000 0 0.1"),
            ("sw0absoffer", "0 50000 60000 0 0.5"),
            ("sw0reloffer", "0  50000 60000 0 0.1"),
            ("reloffer", "0 50000 60000 0 0.1"),
        ] {
            assert!(Offer::parse(cmd, args).is_none(), "{cmd} {args}");
        }
    }

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
