//! RFC 8785 (JSON Canonicalization Scheme), restricted to integers.
//!
//! Canonicalization is the step where two implementations disagree silently and
//! a valid approval fails to verify. So this is written out rather than pulled
//! in, and every rule that differs from "serialize the JSON" carries the reason
//! it exists.
//!
//! # The integer restriction
//!
//! RFC 8785 serializes numbers with ECMAScript `Number::toString` — a
//! shortest-round-trip double formatter. It is well-defined, and it is a
//! reliable source of cross-language divergence, which in this layer means a
//! human turned the dial and the verifier said no.
//!
//! Every number Countersign carries is a count, a millisecond, or a version. So
//! [`canonicalize`] **rejects** any number that is not an integer in the
//! JavaScript-safe range rather than serializing it approximately. Within that
//! subset the output is byte-identical to RFC 8785, so this restricts inputs
//! without diverging from the format.

use std::cmp::Ordering;
use std::fmt::Write as _;

use serde_json::Value;

/// The largest integer representable exactly in an IEEE-754 double, and so the
/// largest one every JSON implementation agrees about.
const SAFE_INT_MAX: i128 = 9_007_199_254_740_991; // 2^53 - 1

/// Why a value could not be canonicalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JcsError {
    /// A number was not an integer, or fell outside ±(2^53 - 1).
    UnsupportedNumber(String),
    /// An object carried the same key twice.
    DuplicateKey(String),
    /// The input was not well-formed JSON.
    Malformed(String),
}

impl std::fmt::Display for JcsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JcsError::UnsupportedNumber(n) => write!(
                f,
                "number {n} is not an integer within ±(2^53-1); Countersign v1 canonicalizes integers only"
            ),
            JcsError::DuplicateKey(k) => write!(f, "duplicate object key {k:?}"),
            JcsError::Malformed(e) => write!(f, "malformed JSON: {e}"),
        }
    }
}

impl std::error::Error for JcsError {}

/// Canonicalize a parsed value.
///
/// Duplicate keys cannot be detected here — `serde_json::Value` has already
/// collapsed them. Use [`canonicalize_str`] when the input arrived as text from
/// somewhere you do not control.
pub fn canonicalize(value: &Value) -> Result<String, JcsError> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

/// Canonicalize JSON text, rejecting duplicate object keys.
///
/// RFC 8785 requires duplicate rejection, and it is not pedantry here: two
/// parsers that disagree about which of `{"ttl_ms":1,"ttl_ms":999999}` wins
/// produce different digests for the same bytes, and the disagreement is
/// attacker-chosen.
pub fn canonicalize_str(json: &str) -> Result<String, JcsError> {
    // serde_json keeps the last duplicate silently, so the check has to happen
    // during parsing rather than after it.
    let mut de = serde_json::Deserializer::from_str(json);
    let checked: DupChecked =
        serde::Deserialize::deserialize(&mut de).map_err(|e| JcsError::Malformed(e.to_string()))?;
    de.end().map_err(|e| JcsError::Malformed(e.to_string()))?;
    if let Some(k) = checked.duplicate {
        return Err(JcsError::DuplicateKey(k));
    }
    canonicalize(&checked.value)
}

/// A `Value` plus the first duplicate key seen while parsing it.
struct DupChecked {
    value: Value,
    duplicate: Option<String>,
}

impl<'de> serde::Deserialize<'de> for DupChecked {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(DupVisitor)
    }
}

struct DupVisitor;

impl<'de> serde::de::Visitor<'de> for DupVisitor {
    type Value = DupChecked;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_unit<E>(self) -> Result<DupChecked, E> {
        Ok(DupChecked {
            value: Value::Null,
            duplicate: None,
        })
    }
    fn visit_none<E>(self) -> Result<DupChecked, E> {
        Ok(DupChecked {
            value: Value::Null,
            duplicate: None,
        })
    }
    fn visit_bool<E>(self, v: bool) -> Result<DupChecked, E> {
        Ok(DupChecked {
            value: Value::Bool(v),
            duplicate: None,
        })
    }
    fn visit_i64<E>(self, v: i64) -> Result<DupChecked, E> {
        Ok(DupChecked {
            value: Value::from(v),
            duplicate: None,
        })
    }
    fn visit_u64<E>(self, v: u64) -> Result<DupChecked, E> {
        Ok(DupChecked {
            value: Value::from(v),
            duplicate: None,
        })
    }
    fn visit_f64<E>(self, v: f64) -> Result<DupChecked, E> {
        Ok(DupChecked {
            value: Value::from(v),
            duplicate: None,
        })
    }
    fn visit_str<E>(self, v: &str) -> Result<DupChecked, E> {
        Ok(DupChecked {
            value: Value::String(v.to_owned()),
            duplicate: None,
        })
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<DupChecked, A::Error> {
        let mut items = Vec::new();
        let mut duplicate = None;
        while let Some(el) = a.next_element::<DupChecked>()? {
            duplicate = duplicate.or(el.duplicate);
            items.push(el.value);
        }
        Ok(DupChecked {
            value: Value::Array(items),
            duplicate,
        })
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut a: A) -> Result<DupChecked, A::Error> {
        let mut map = serde_json::Map::new();
        let mut duplicate = None;
        while let Some(k) = a.next_key::<String>()? {
            let v = a.next_value::<DupChecked>()?;
            duplicate = duplicate.or(v.duplicate);
            if map.insert(k.clone(), v.value).is_some() && duplicate.is_none() {
                duplicate = Some(k);
            }
        }
        Ok(DupChecked {
            value: Value::Object(map),
            duplicate,
        })
    }
}

fn write_value(v: &Value, out: &mut String) -> Result<(), JcsError> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(n, out)?,
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Sorted by UTF-16 code unit, which is neither byte order nor code
            // point order — see `utf16_cmp`.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_cmp(a, b));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_value(&map[*k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_number(n: &serde_json::Number, out: &mut String) -> Result<(), JcsError> {
    let as_int: Option<i128> = n
        .as_i64()
        .map(i128::from)
        .or_else(|| n.as_u64().map(i128::from));

    match as_int {
        Some(i) if i.abs() <= SAFE_INT_MAX => {
            let _ = write!(out, "{i}");
            Ok(())
        }
        _ => Err(JcsError::UnsupportedNumber(n.to_string())),
    }
}

/// RFC 8785 string escaping: only `"`, `\` and C0 controls are escaped, the
/// five short forms are used where they exist, other controls take `\u00xx`
/// with **lowercase** hex, `/` is left alone, and non-ASCII is emitted as UTF-8
/// rather than `\u`-escaped.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Compare two strings by UTF-16 code unit, as RFC 8785 requires.
///
/// Rust's `str: Ord` compares UTF-8 bytes, which orders by code point. The two
/// disagree above the BMP: a code point at or above `U+10000` encodes in UTF-16
/// as a surrogate pair beginning in `0xD800..=0xDBFF`, so it sorts *before*
/// `U+E000..=U+FFFF` — the reverse of code-point order. Object keys are usually
/// ASCII and this rarely bites, which is exactly why it needs a test rather
/// than a comment.
fn utf16_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canon(v: Value) -> String {
        canonicalize(&v).expect("canonicalizable")
    }

    #[test]
    fn object_keys_sort_and_whitespace_vanishes() {
        assert_eq!(canon(json!({"b": 1, "a": 2})), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn keys_sort_by_utf16_code_unit_not_code_point() {
        // U+FFFD sorts *after* U+10140 in UTF-16 (the latter starts with a
        // 0xD800-range surrogate) and *before* it by code point. Byte-wise
        // sorting — Rust's default — would produce the wrong order here.
        let high = "\u{10140}"; // surrogate pair D800 DD40
        let bmp = "\u{FFFD}";
        let out = canon(json!({ bmp: 1, high: 2 }));
        let expected = format!("{{\"{high}\":2,\"{bmp}\":1}}");
        assert_eq!(out, expected, "keys must sort by UTF-16 code unit");
        assert!(bmp < high, "and that is the opposite of Rust's byte order");
    }

    #[test]
    fn strings_escape_exactly_what_rfc8785_escapes() {
        assert_eq!(canon(json!("a/b")), r#""a/b""#, "solidus is not escaped");
        assert_eq!(canon(json!("q\"s")), r#""q\"s""#);
        assert_eq!(canon(json!("back\\slash")), r#""back\\slash""#);
        assert_eq!(canon(json!("tab\there")), r#""tab\there""#);
        assert_eq!(canon(json!("nl\n")), r#""nl\n""#);
        // A control with no short form takes lowercase-hex \u00xx.
        assert_eq!(canon(json!("\u{01}")), "\"\\u0001\"");
        // Non-ASCII travels as UTF-8, not as an escape.
        assert_eq!(canon(json!("café")), "\"café\"");
    }

    #[test]
    fn non_integer_numbers_are_refused_rather_than_approximated() {
        assert!(matches!(
            canonicalize(&json!(1.5)),
            Err(JcsError::UnsupportedNumber(_))
        ));
        // 2^53 is the first integer two doubles can disagree about.
        assert!(matches!(
            canonicalize(&json!(9_007_199_254_740_992i64)),
            Err(JcsError::UnsupportedNumber(_))
        ));
        assert_eq!(canon(json!(9_007_199_254_740_991i64)), "9007199254740991");
        assert_eq!(canon(json!(-9_007_199_254_740_991i64)), "-9007199254740991");
        assert_eq!(canon(json!(0)), "0");
    }

    #[test]
    fn duplicate_keys_are_rejected_from_text() {
        // Whichever key a parser keeps, it is a different digest for the same
        // bytes — and the choice is the sender's.
        assert!(matches!(
            canonicalize_str(r#"{"ttl_ms":1,"ttl_ms":999999}"#),
            Err(JcsError::DuplicateKey(k)) if k == "ttl_ms"
        ));
        // Nested, and inside an array, too.
        assert!(matches!(
            canonicalize_str(r#"{"a":{"x":1,"x":2}}"#),
            Err(JcsError::DuplicateKey(_))
        ));
        assert!(matches!(
            canonicalize_str(r#"[{"x":1,"x":2}]"#),
            Err(JcsError::DuplicateKey(_))
        ));
        assert!(canonicalize_str(r#"{"a":1,"b":2}"#).is_ok());
    }

    #[test]
    fn nesting_and_arrays_round_trip() {
        assert_eq!(
            canon(json!({"z": [1, {"b": true, "a": null}], "y": "x"})),
            r#"{"y":"x","z":[1,{"a":null,"b":true}]}"#
        );
        assert_eq!(canon(json!([])), "[]");
        assert_eq!(canon(json!({})), "{}");
    }

    #[test]
    fn canonical_form_is_a_fixed_point() {
        let once = canonicalize_str(r#" { "b" : 1 , "a" : [ 2 , 3 ] } "#).unwrap();
        assert_eq!(once, r#"{"a":[2,3],"b":1}"#);
        assert_eq!(canonicalize_str(&once).unwrap(), once);
    }
}
