//! The numbers every joinstr client must derive identically (RULES.md R4, R5, R7.4, R8.3).
//!
//! The reference arithmetic is Python's: IEEE doubles, `round` to even, `int` truncation, floor division.
//! A client that truncates where the others round builds a different transaction, and its signature cannot
//! sit in theirs.

use std::str::FromStr;

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Network, Script, ScriptBuf};
use serde_json::Value;

/// A peer's coin is worth the denomination plus this much at least.
pub const INPUT_SLACK_MIN: i64 = 500;
/// A peer's coin is worth the denomination plus this much at most.
pub const INPUT_SLACK_MAX: i64 = 5_000;
/// The most a coinjoin may cost one peer (its input minus its output), satoshis.
pub const MAX_PERSONAL_COST: i64 = 15_000;
/// The combined transaction pays at least this much fee per input.
pub const MIN_FEE_PER_INPUT: u64 = 100;
/// The combined transaction pays at most this much fee per input.
pub const MAX_FEE_PER_INPUT: u64 = 10_000;

/// Python's `round(x)` for a float: nearest integer, ties to even, saturating where Python would return an
/// integer too large to be an amount.
fn py_round(x: f64) -> i64 {
    x.round_ties_even() as i64
}

/// Python's `int(x)` for a float: truncation toward zero (saturating).
fn py_int(x: f64) -> i64 {
    x.trunc() as i64
}

/// R5.1: the denomination in satoshis, `round(denomination * 1e8)`. Truncating is wrong: 0.29 BTC is
/// 28999999.999999996 as a double.
pub fn denom_sats(denomination_btc: f64) -> i64 {
    py_round(denomination_btc * 100_000_000.0)
}

/// R5.2: each output's share of the fee, `int(fee_rate * (100 * n)) // n`. The integer `100 * n` is formed
/// first: `fee_rate * 100 * n` rounds differently for some rates (1.15 with 3 outputs).
pub fn per_output_fee(fee_rate: f64, outputs: u32) -> i64 {
    let n = i64::from(outputs.max(1));
    py_int(fee_rate * (100 * n) as f64).div_euclid(n)
}

/// R5.3: what every output pays, `denom_sats - per_output_fee`. May be zero or negative for absurd terms;
/// [`check_amounts`] refuses those.
pub fn output_amount(denomination_btc: f64, fee_rate: f64, outputs: u32) -> i64 {
    denom_sats(denomination_btc).saturating_sub(per_output_fee(fee_rate, outputs))
}

/// R8.3: the output amount of the recovery round, with the fee sized as
/// `100 * outputs + 68 * inputs + 100` vbytes and the denomination rounded as in [`denom_sats`].
pub fn recovery_output_amount(
    denomination_btc: f64,
    fee_rate: f64,
    outputs: u32,
    inputs: u32,
) -> i64 {
    let n = i64::from(outputs.max(1));
    let vbytes = 100 * i64::from(outputs) + 68 * i64::from(inputs) + 100;
    denom_sats(denomination_btc).saturating_sub(py_int(fee_rate * vbytes as f64).div_euclid(n))
}

/// R5.3: the dust threshold of an output script, as bitcoind computes it: 294 (P2WPKH), 330 (P2TR, P2WSH),
/// 540 (P2SH), 546 (P2PKH and anything else).
pub fn dust_limit(script_pubkey: &Script) -> i64 {
    if script_pubkey.is_p2wpkh() {
        294
    } else if script_pubkey.is_p2tr() || script_pubkey.is_p2wsh() {
        330
    } else if script_pubkey.is_p2sh() {
        540
    } else {
        546
    }
}

/// Why a pool's amounts are refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AmountError {
    /// An output would be below the dust limit of one of the pool's output types.
    Dust {
        /// What each output would pay.
        output: i64,
        /// The limit it must reach.
        limit: i64,
    },
    /// The round would cost a peer more than [`MAX_PERSONAL_COST`], or the coin is outside the window.
    Cost(i64),
    /// The coin is not worth `denom_sats + 500` to `denom_sats + 5000`.
    InputWindow,
}

impl std::fmt::Display for AmountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AmountError::Dust { output, limit } => {
                write!(
                    f,
                    "outputs of {output} sats are below the dust limit of {limit}"
                )
            }
            AmountError::Cost(cost) => {
                write!(
                    f,
                    "the round would cost {cost} sats, above {MAX_PERSONAL_COST}"
                )
            }
            AmountError::InputWindow => {
                f.write_str("the coin is not the denomination plus 500 to 5000 sats")
            }
        }
    }
}

impl std::error::Error for AmountError {}

/// R5.3: the amount each of `outputs` is paid, refused when it does not clear the dust limit of every
/// output type present (546 when no output is known yet).
pub fn check_amounts(
    denomination_btc: f64,
    fee_rate: f64,
    peers: u32,
    outputs: &[ScriptBuf],
) -> Result<u64, AmountError> {
    let output = output_amount(denomination_btc, fee_rate, peers);
    let limit = outputs.iter().map(|s| dust_limit(s)).max().unwrap_or(546);
    if output < limit {
        return Err(AmountError::Dust { output, limit });
    }
    let cost = denom_sats(denomination_btc) - output;
    if cost > MAX_PERSONAL_COST {
        return Err(AmountError::Cost(cost));
    }
    u64::try_from(output).map_err(|_| AmountError::Dust { output, limit })
}

/// R5.4: a peer's coin is worth `denom_sats + 500` to `denom_sats + 5000`, and the coinjoin may cost it at
/// most 15,000 sats (`coin - output`).
pub fn check_input(
    coin_sats: u64,
    denomination_btc: f64,
    output_sats: u64,
) -> Result<(), AmountError> {
    let (coin, denom) = (
        i64::try_from(coin_sats).unwrap_or(i64::MAX),
        denom_sats(denomination_btc),
    );
    if coin < denom.saturating_add(INPUT_SLACK_MIN) || coin > denom.saturating_add(INPUT_SLACK_MAX)
    {
        return Err(AmountError::InputWindow);
    }
    let cost = coin.saturating_sub(i64::try_from(output_sats).unwrap_or(i64::MAX));
    if cost > MAX_PERSONAL_COST {
        return Err(AmountError::Cost(cost));
    }
    Ok(())
}

/// R7.4: whether a combined transaction's fee is within `100 * n_inputs ..= 10000 * n_inputs` sats.
pub fn fee_in_bounds(fee_sats: u64, inputs: usize) -> bool {
    let n = inputs as u64;
    (MIN_FEE_PER_INPUT * n..=MAX_FEE_PER_INPUT * n).contains(&fee_sats)
}

/// An address string a pool message carried, as an address on `network`, or `None` (R4.2: addresses of
/// another network, or not addresses at all, are ignored).
pub fn output_address(address: &str, network: Network) -> Option<Address> {
    Address::<NetworkUnchecked>::from_str(address)
        .ok()?
        .require_network(network)
        .ok()
}

/// R4: the outputs a pool registers from its decrypted channel messages, in arrival order: JSON objects
/// with `type` `output` and a usable `address` for `network`, counted by scriptPubKey (an address and its
/// upper-case bech32 form are one output), the first `peers` distinct ones. Anything else is skipped and
/// never ends the round.
pub fn collect_outputs<'a>(
    plaintexts: impl IntoIterator<Item = &'a str>,
    peers: u32,
    network: Network,
) -> Vec<Address> {
    let mut outputs: Vec<Address> = Vec::new();
    for text in plaintexts {
        let Ok(Value::Object(msg)) = serde_json::from_str::<Value>(text) else {
            continue;
        };
        if msg.get("type").and_then(Value::as_str) != Some("output") {
            continue;
        }
        let Some(address) = msg.get("address").and_then(Value::as_str) else {
            continue;
        };
        let Some(address) = output_address(address, network) else {
            continue;
        };
        let script = address.script_pubkey();
        if outputs.iter().any(|a| a.script_pubkey() == script) || outputs.len() >= peers as usize {
            continue;
        }
        outputs.push(address);
    }
    outputs
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every expected number below was computed with Python 3 (`round(float(d) * 100000000)`,
    // `int(f * (100 * n)) // n`), the arithmetic the reference clients run.

    #[test]
    fn denominations_round_as_python_rounds() {
        for (btc, sats) in [
            (0.29, 29_000_000),
            (0.001, 100_000),
            (0.0003, 30_000),
            (0.2719403, 27_194_030),
            (1.0, 100_000_000),
            (0.123456785, 12_345_678),
            (0.000000005, 0),
            (0.000000015, 1),
            (2.5e-08, 2),
            (21_000_000.0, 2_100_000_000_000_000),
        ] {
            assert_eq!(denom_sats(btc), sats, "{btc}");
        }
        // The trap the rule exists for: truncation gives one satoshi less.
        assert_eq!((0.29f64 * 100_000_000.0) as i64, 28_999_999);
    }

    #[test]
    fn fee_shares_multiply_by_the_integer_first() {
        for ((rate, n), fee) in [
            ((1.15, 3), 115),
            ((2.5, 3), 250),
            ((1.1, 5), 110),
            ((0.1, 7), 10),
            ((1.0, 2), 100),
            ((33.333, 9), 3333),
            ((0.57, 5), 57),
            ((1.005, 4), 100),
        ] {
            assert_eq!(per_output_fee(rate, n), fee, "{rate} x {n}");
        }
        // fee_rate * 100 * n, the wrong order, loses a satoshi here.
        assert_eq!(((1.15f64 * 100.0 * 3.0) as i64) / 3, 114);
        assert_eq!(output_amount(0.001, 2.5, 3), 99_750);
    }

    #[test]
    fn recovery_amounts() {
        assert_eq!(recovery_output_amount(0.0003, 1.5, 3, 3), 29_698);
        assert_eq!(recovery_output_amount(0.001, 2.5, 2, 3), 99_370);
        assert_eq!(recovery_output_amount(0.29, 1.15, 5, 4), 28_999_800);
    }

    fn spk(address: &str) -> ScriptBuf {
        output_address(address, Network::Regtest)
            .unwrap()
            .script_pubkey()
    }

    /// Regtest addresses of each type for one fixed key: (P2WPKH, P2TR, P2PKH).
    fn addresses() -> (String, String, String) {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[7; 32]).unwrap().public_key(&secp);
        let compressed = bitcoin::CompressedPublicKey(key);
        (
            Address::p2wpkh(&compressed, Network::Regtest).to_string(),
            Address::p2tr(&secp, key.x_only_public_key().0, None, Network::Regtest).to_string(),
            Address::p2pkh(compressed, Network::Regtest).to_string(),
        )
    }

    #[test]
    fn dust_follows_the_largest_output_type() {
        let (p2wpkh, p2tr, p2pkh) = addresses();
        assert_eq!(dust_limit(&spk(&p2wpkh)), 294);
        assert_eq!(dust_limit(&spk(&p2tr)), 330);
        assert_eq!(dust_limit(&spk(&p2pkh)), 546);
        // 0.000004 BTC at 1 sat/vB with 2 peers pays 300 per output: fine for P2WPKH, dust once a P2TR joins.
        assert_eq!(check_amounts(0.000004, 1.0, 2, &[spk(&p2wpkh)]), Ok(300));
        assert_eq!(
            check_amounts(0.000004, 1.0, 2, &[spk(&p2wpkh), spk(&p2tr)]),
            Err(AmountError::Dust {
                output: 300,
                limit: 330
            })
        );
        // A fee rate that would cost a peer more than 15,000 sats is refused.
        assert_eq!(
            check_amounts(0.01, 151.0, 2, &[]),
            Err(AmountError::Cost(15_100))
        );
        assert!(check_amounts(0.01, 150.0, 2, &[]).is_ok());
    }

    #[test]
    fn input_window_and_cost() {
        let out = 99_750;
        assert!(check_input(100_500, 0.001, out).is_ok());
        assert!(check_input(105_000, 0.001, out).is_ok());
        assert_eq!(
            check_input(100_499, 0.001, out),
            Err(AmountError::InputWindow)
        );
        assert_eq!(
            check_input(105_001, 0.001, out),
            Err(AmountError::InputWindow)
        );
        assert_eq!(
            check_input(105_000, 0.001, 89_000),
            Err(AmountError::Cost(16_000))
        );
        assert!(fee_in_bounds(300, 3) && fee_in_bounds(30_000, 3));
        assert!(!fee_in_bounds(299, 3) && !fee_in_bounds(30_001, 3));
    }

    #[test]
    fn outputs_are_counted_by_script_first_come() {
        let (p2wpkh, p2tr, p2pkh) = addresses();
        let upper = p2wpkh.to_uppercase();
        let msgs = [
            format!(r#"{{"address": "{p2wpkh}", "type": "output"}}"#),
            format!(r#"{{"type":"output","address":"{upper}","version":"1"}}"#), // same script
            "not json".to_string(),
            r#"["type", "output"]"#.to_string(),
            r#"{"type": "output", "address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}"#
                .to_string(), // mainnet
            r#"{"type": "output", "address": 5}"#.to_string(),
            r#"{"type": "input", "psbt": "x"}"#.to_string(),
            format!(r#"{{"type": "output", "address": "{p2tr}"}}"#),
            format!(r#"{{"type": "output", "address": "{p2pkh}"}}"#), // a third, beyond `peers`
        ];
        let got = collect_outputs(msgs.iter().map(String::as_str), 2, Network::Regtest);
        let got: Vec<String> = got.iter().map(ToString::to_string).collect();
        assert_eq!(got, [p2wpkh, p2tr]);
    }
}
