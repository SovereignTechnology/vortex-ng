//! What the Python clients do with JSON, reproduced: `json.dumps` text (default separators, ASCII only,
//! `repr` floats), `==` between decoded values, and the truthiness the plugin leans on.
//!
//! Receivers parse JSON, so spacing does not matter to current clients, but older Electrum plugins look for
//! the substring `"type": "join_pool"`, and RULES.md R8.1 asks senders to keep `json.dumps` spacing.

use serde_json::Value;

/// Python's `repr(float)`, which is how `json.dumps` writes a float: the shortest digits that round-trip,
/// in positional form for exponents from -4 to 15 and scientific form (two-digit exponent at least)
/// otherwise; whole numbers keep a `.0`.
pub fn float_repr(x: f64) -> String {
    if x.is_nan() {
        return "NaN".into();
    }
    if x.is_infinite() {
        return if x > 0.0 {
            "Infinity".into()
        } else {
            "-Infinity".into()
        };
    }
    if x == 0.0 {
        return if x.is_sign_negative() {
            "-0.0".into()
        } else {
            "0.0".into()
        };
    }
    // Rust's `{:e}` gives the shortest round-trip digits: "d.ddde<exp>".
    let sci = format!("{:e}", x.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap_or((sci.as_str(), "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let sign = if x < 0.0 { "-" } else { "" };
    let body = if (-4..16).contains(&exp) {
        if exp < 0 {
            format!("0.{}{digits}", "0".repeat((-exp - 1) as usize))
        } else {
            let point = exp as usize + 1;
            if digits.len() <= point {
                format!("{digits}{}.0", "0".repeat(point - digits.len()))
            } else {
                format!("{}.{}", &digits[..point], &digits[point..])
            }
        }
    } else {
        let (head, tail) = digits.split_at(1);
        let frac = if tail.is_empty() {
            String::new()
        } else {
            format!(".{tail}")
        };
        let esign = if exp < 0 { '-' } else { '+' };
        format!("{head}{frac}e{esign}{:02}", exp.abs())
    };
    format!("{sign}{body}")
}

/// A JSON string literal as `json.dumps` writes it (`ensure_ascii`: everything outside ASCII is `\uXXXX`,
/// astral characters as surrogate pairs).
pub fn string_repr(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (' '..='~').contains(&c) => out.push(c),
            c => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
    out
}

/// One value as `json.dumps` writes it. Objects nested inside keep serde_json's key order (sorted), not
/// the sender's; the messages this crate builds list their top-level keys through [`object`].
pub fn dumps(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => match (n.as_i64(), n.as_u64(), n.as_f64()) {
            (Some(i), _, _) => i.to_string(),
            (_, Some(u), _) => u.to_string(),
            (_, _, Some(f)) => float_repr(f),
            _ => n.to_string(),
        },
        Value::String(s) => string_repr(s),
        Value::Array(items) => {
            format!(
                "[{}]",
                items.iter().map(dumps).collect::<Vec<_>>().join(", ")
            )
        }
        Value::Object(map) => {
            let pairs: Vec<(&str, Value)> =
                map.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
            object(&pairs)
        }
    }
}

/// A JSON object with its keys in the order given, as `json.dumps` writes a dict.
pub fn object(pairs: &[(&str, Value)]) -> String {
    let body: Vec<String> = pairs
        .iter()
        .map(|(k, v)| format!("{}: {}", string_repr(k), dumps(v)))
        .collect();
    format!("{{{}}}", body.join(", "))
}

/// Whether a decoded value is a Python `int` or `float` and not a `bool`.
pub fn is_number(v: &Value) -> bool {
    v.is_number()
}

/// Whether a decoded value is a Python `int` (a JSON number written without fraction or exponent) and not
/// a `bool`: `2` is, `2.0` is not.
pub fn is_int(v: &Value) -> bool {
    v.is_i64() || v.is_u64()
}

fn numeric(v: &Value) -> Option<f64> {
    match v {
        Value::Bool(b) => Some(f64::from(u8::from(*b))),
        Value::Number(n) => n.as_f64(),
        _ => None,
    }
}

/// Python's `==` between two decoded JSON values: numbers compare by value whatever their type
/// (`1 == 1.0`), and a `bool` is the number 0 or 1 (`True == 1`); everything else compares by type and
/// content.
pub fn py_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) if is_int(a) && is_int(b) => {
            match (x.as_i64(), y.as_i64(), x.as_u64(), y.as_u64()) {
                (Some(p), Some(q), _, _) => p == q,
                (_, _, Some(p), Some(q)) => p == q,
                _ => false,
            }
        }
        (Value::Bool(_) | Value::Number(_), Value::Bool(_) | Value::Number(_)) => {
            numeric(a) == numeric(b)
        }
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| py_eq(p, q))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, p)| y.get(k).is_some_and(|q| py_eq(p, q)))
        }
        _ => a == b,
    }
}

/// Python truthiness of a decoded value (`None`, `False`, `0`, `""`, `[]`, `{}` are false).
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn floats_and_strings_as_python_writes_them() {
        // python3: json.dumps({"a": [...], "s": "é \"\\\n\x01😀"})
        let floats = [
            0.001,
            1e-05,
            1.0,
            1e16,
            123456789012345680.0,
            2.719403e-1,
            5e-324,
            1.5e300,
            100.0,
            1e22,
        ];
        let expect = "[0.001, 1e-05, 1.0, 1e+16, 1.2345678901234568e+17, 0.2719403, 5e-324, 1.5e+300, 100.0, 1e+22]";
        let got: Vec<String> = floats.iter().map(|f| float_repr(*f)).collect();
        assert_eq!(format!("[{}]", got.join(", ")), expect);
        assert_eq!(float_repr(-0.00012), "-0.00012");
        assert_eq!(float_repr(0.0001), "0.0001");
        assert_eq!(float_repr(123456.789), "123456.789");
        assert_eq!(float_repr(9999999999999998.0), "9999999999999998.0");
        // Python: json.dumps("é\u2028\"\\\n\x01😀")
        let text = "é\u{2028}\"\\\n\u{1}😀";
        assert_eq!(
            string_repr(text),
            "\"\\u00e9\\u2028\\\"\\\\\\n\\u0001\\ud83d\\ude00\""
        );
    }

    #[test]
    fn objects_keep_their_order_and_spacing() {
        let text = object(&[("type", json!("join_pool"))]);
        assert_eq!(text, r#"{"type": "join_pool"}"#);
        let text = object(&[("psbt", json!("cHNidP8=")), ("type", json!("input"))]);
        assert_eq!(text, r#"{"psbt": "cHNidP8=", "type": "input"}"#);
        assert_eq!(
            dumps(&json!([1, 2.5, null, true, "x"])),
            r#"[1, 2.5, null, true, "x"]"#
        );
    }

    #[test]
    fn equality_and_types_follow_python() {
        assert!(py_eq(&json!(1), &json!(1.0)));
        assert!(py_eq(&json!(true), &json!(1)));
        assert!(py_eq(&json!(0.001), &json!(0.001)));
        assert!(!py_eq(&json!("1"), &json!(1)));
        assert!(!py_eq(&json!(null), &json!(0)));
        assert!(py_eq(&json!({"a": [1, 2.0]}), &json!({"a": [1.0, 2]})));
        assert!(py_eq(
            &json!(18446744073709551615u64),
            &json!(18446744073709551615u64)
        ));
        assert!(is_int(&json!(2)) && !is_int(&json!(2.0)) && !is_int(&json!(true)));
        assert!(is_number(&json!(2.0)) && !is_number(&json!(false)) && !is_number(&json!("2")));
        assert!(!truthy(&json!({})) && !truthy(&json!("")) && truthy(&json!({"k": 1})));
    }
}
