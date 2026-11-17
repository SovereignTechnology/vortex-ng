//! Command-line options: `--name value`, `--name=value` and bare `--flag`s, nothing positional.

use std::collections::HashMap;

/// The options of one command, as given.
#[derive(Debug, Default)]
pub(crate) struct Args {
    values: HashMap<&'static str, String>,
    flags: Vec<&'static str>,
}

impl Args {
    /// Parse `given` against the options a command takes: `valued` ones take a value, `flags` do not.
    /// Anything else, a repeated option or a missing value is an error.
    pub(crate) fn parse(
        given: &[String],
        valued: &[&'static str],
        flags: &[&'static str],
    ) -> Result<Args, String> {
        let mut args = Args::default();
        let mut rest = given.iter();
        while let Some(arg) = rest.next() {
            let Some(body) = arg.strip_prefix("--") else {
                return Err(format!("unexpected argument `{arg}`"));
            };
            let (name, inline) = match body.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (body, None),
            };
            if let Some(&flag) = flags.iter().find(|f| **f == name) {
                if inline.is_some() {
                    return Err(format!("`--{flag}` takes no value"));
                }
                if args.flags.contains(&flag) {
                    return Err(format!("`--{flag}` given twice"));
                }
                args.flags.push(flag);
            } else if let Some(&option) = valued.iter().find(|v| **v == name) {
                let value = match inline {
                    Some(value) => value.to_string(),
                    None => rest
                        .next()
                        .ok_or_else(|| format!("`--{option}` needs a value"))?
                        .clone(),
                };
                if args.values.insert(option, value).is_some() {
                    return Err(format!("`--{option}` given twice"));
                }
            } else {
                return Err(format!("unknown option `--{name}`"));
            }
        }
        Ok(args)
    }

    /// The value of `--name`, if given.
    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    /// The value of `--name`, which the command cannot do without.
    pub(crate) fn required(&self, name: &str) -> Result<&str, String> {
        self.get(name)
            .ok_or_else(|| format!("`--{name}` is required"))
    }

    /// The value of `--name` as a number within `range`, or `default` when not given.
    pub(crate) fn number(
        &self,
        name: &str,
        default: u32,
        range: std::ops::RangeInclusive<u32>,
    ) -> Result<u32, String> {
        let Some(text) = self.get(name) else {
            return Ok(default);
        };
        let wrong = || {
            format!(
                "`--{name}` must be a number from {} to {}",
                range.start(),
                range.end()
            )
        };
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(wrong());
        }
        text.parse()
            .ok()
            .filter(|n| range.contains(n))
            .ok_or_else(wrong)
    }

    /// The value of `--name` as an amount in satoshis (at most 21 million coins), if given.
    pub(crate) fn sats(&self, name: &str) -> Result<Option<u64>, String> {
        const MAX: u64 = 21_000_000 * 100_000_000;
        let Some(text) = self.get(name) else {
            return Ok(None);
        };
        let wrong = || format!("`--{name}` is an amount in satoshis");
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(wrong());
        }
        text.parse()
            .ok()
            .filter(|sats| *sats <= MAX)
            .map(Some)
            .ok_or_else(wrong)
    }

    /// Whether `--name` was given.
    pub(crate) fn flag(&self, name: &str) -> bool {
        self.flags.contains(&name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| a.to_string()).collect()
    }

    #[test]
    fn options_and_flags() {
        let args = Args::parse(
            &strings(&["--wallet", "w.json", "--count=3", "--change"]),
            &["wallet", "count"],
            &["change"],
        )
        .unwrap();
        assert_eq!(args.get("wallet"), Some("w.json"));
        assert_eq!(args.number("count", 10, 1..=100), Ok(3));
        assert_eq!(args.number("mixdepth", 0, 0..=4), Ok(0));
        assert!(args.flag("change"));
        assert!(args.required("pit").is_err());
        // A value may look like an option: it is still the value.
        let args = Args::parse(&strings(&["--wallet", "--odd"]), &["wallet"], &[]).unwrap();
        assert_eq!(args.get("wallet"), Some("--odd"));
    }

    #[test]
    fn mistakes_are_errors() {
        let parse =
            |given: &[&str]| Args::parse(&strings(given), &["wallet", "count"], &["change"]);
        let cases: [&[&str]; 6] = [
            &["wallet.json"],
            &["--walet", "w"],
            &["--wallet"],
            &["--wallet", "a", "--wallet", "b"],
            &["--change", "--change"],
            &["--change=yes"],
        ];
        for given in cases {
            assert!(parse(given).is_err(), "{given:?}");
        }
        for count in ["0", "101", "+3", "3.0", "", "99999999999"] {
            let args = parse(&["--count", count]).unwrap();
            assert!(args.number("count", 10, 1..=100).is_err(), "{count}");
        }
        // Amounts go beyond 32 bits, and no further than there are coins.
        let args = parse(&["--count", "2100000000000000"]).unwrap();
        assert_eq!(args.sats("count"), Ok(Some(2_100_000_000_000_000)));
        assert_eq!(args.sats("wallet"), Ok(None));
        for sats in ["2100000000000001", "-1", "1.5", "1e8", ""] {
            let args = parse(&["--count", sats]).unwrap();
            assert!(args.sats("count").is_err(), "{sats}");
        }
    }
}
