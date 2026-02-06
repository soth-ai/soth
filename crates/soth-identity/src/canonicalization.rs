//! RFC 8785 JSON Canonicalization Scheme (JCS)
//!
//! Ensures deterministic JSON serialization before signing to prevent
//! signature mismatch errors caused by key ordering or whitespace differences.

use sha2::{Digest, Sha256};
use soth_core::error::{Result, SothError};

/// Canonicalize a JSON value to bytes (RFC 8785)
pub fn canonicalize_json(data: &serde_json::Value) -> Result<Vec<u8>> {
    let canonical_str = canonicalize_value(data)?;
    Ok(canonical_str.into_bytes())
}

/// Canonicalize a JSON value to a string
pub fn canonicalize_to_string(data: &serde_json::Value) -> Result<String> {
    canonicalize_value(data)
}

/// Compute SHA-256 hash of canonical JSON
pub fn compute_hash(data: &serde_json::Value) -> Result<String> {
    let canonical = canonicalize_json(data)?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// Normalize data for signing (remove signature fields)
pub fn normalize_for_signing(
    data: &serde_json::Value,
    exclude_signature: bool,
) -> Result<serde_json::Value> {
    let mut normalized: serde_json::Value = data.clone();

    if exclude_signature {
        if let Some(obj) = normalized.as_object_mut() {
            obj.remove("signature");
            obj.remove("log_proof");
            obj.remove("proof");
        }
    }

    Ok(normalized)
}

/// Recursively canonicalize a JSON value according to RFC 8785
fn canonicalize_value(value: &serde_json::Value) -> Result<String> {
    match value {
        serde_json::Value::Null => Ok("null".to_string()),

        serde_json::Value::Bool(b) => Ok(if *b { "true" } else { "false" }.to_string()),

        serde_json::Value::Number(n) => serialize_number(n),

        serde_json::Value::String(s) => Ok(serialize_string(s)),

        serde_json::Value::Array(arr) => {
            let elements: Result<Vec<String>> = arr.iter().map(canonicalize_value).collect();
            Ok(format!("[{}]", elements?.join(",")))
        }

        serde_json::Value::Object(obj) => {
            // Sort keys by UTF-16 code units (RFC 8785)
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort_by_key(|a| utf16_sort_key(a));

            let pairs: Result<Vec<String>> = keys
                .iter()
                .map(|key| {
                    let value = &obj[*key];
                    let canonical_value = canonicalize_value(value)?;
                    Ok(format!("{}:{}", serialize_string(key), canonical_value))
                })
                .collect();

            Ok(format!("{{{}}}", pairs?.join(",")))
        }
    }
}

/// Serialize a number according to RFC 8785
fn serialize_number(n: &serde_json::Number) -> Result<String> {
    // Handle integers
    if let Some(i) = n.as_i64() {
        return Ok(i.to_string());
    }
    if let Some(u) = n.as_u64() {
        return Ok(u.to_string());
    }

    // Handle floats
    if let Some(f) = n.as_f64() {
        // Check for special values
        if f.is_nan() {
            return Err(SothError::Internal("NaN is not allowed in canonical JSON".to_string()));
        }
        if f.is_infinite() {
            return Err(SothError::Internal("Infinity is not allowed in canonical JSON".to_string()));
        }

        // Normalize negative zero
        if f == 0.0 {
            return Ok("0".to_string());
        }

        // Check if it's effectively an integer
        if f == f.trunc() && f.abs() < (1i64 << 53) as f64 {
            return Ok((f as i64).to_string());
        }

        // Use ECMAScript-style formatting
        let abs_f = f.abs();
        if !(1e-6..1e21).contains(&abs_f) {
            // Use exponential notation
            format_exponential(f)
        } else {
            // Use decimal notation
            format_decimal(f)
        }
    } else {
        Ok(n.to_string())
    }
}

/// Format a float in exponential notation
fn format_exponential(f: f64) -> Result<String> {
    let s = format!("{f:e}");
    // Normalize: remove unnecessary zeros and plus signs
    let parts: Vec<&str> = s.split('e').collect();
    if parts.len() != 2 {
        return Ok(s);
    }

    let mantissa = parts[0].trim_end_matches('0').trim_end_matches('.');
    let exp: i32 = parts[1].parse().unwrap_or(0);

    if exp >= 0 {
        Ok(format!("{mantissa}e+{exp}"))
    } else {
        Ok(format!("{mantissa}e{exp}"))
    }
}

/// Format a float in decimal notation
fn format_decimal(f: f64) -> Result<String> {
    // Use repr to get the shortest representation
    let s = format!("{f}");

    // Remove trailing zeros after decimal point
    if s.contains('.') {
        let trimmed = s.trim_end_matches('0').trim_end_matches('.');
        Ok(trimmed.to_string())
    } else {
        Ok(s)
    }
}

/// Serialize a string with proper escaping (RFC 8785)
fn serialize_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 2);
    result.push('"');

    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\x08' => result.push_str("\\b"),
            '\x0c' => result.push_str("\\f"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }

    result.push('"');
    result
}

/// Get UTF-16 sort key for a string (RFC 8785)
fn utf16_sort_key(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_canonicalize_null() {
        let result = canonicalize_value(&json!(null)).unwrap();
        assert_eq!(result, "null");
    }

    #[test]
    fn test_canonicalize_bool() {
        assert_eq!(canonicalize_value(&json!(true)).unwrap(), "true");
        assert_eq!(canonicalize_value(&json!(false)).unwrap(), "false");
    }

    #[test]
    fn test_canonicalize_integer() {
        assert_eq!(canonicalize_value(&json!(42)).unwrap(), "42");
        assert_eq!(canonicalize_value(&json!(-123)).unwrap(), "-123");
        assert_eq!(canonicalize_value(&json!(0)).unwrap(), "0");
    }

    #[test]
    fn test_canonicalize_string() {
        assert_eq!(canonicalize_value(&json!("hello")).unwrap(), "\"hello\"");
        assert_eq!(canonicalize_value(&json!("a\"b")).unwrap(), "\"a\\\"b\"");
        assert_eq!(canonicalize_value(&json!("a\nb")).unwrap(), "\"a\\nb\"");
    }

    #[test]
    fn test_canonicalize_array() {
        let arr = json!([1, 2, 3]);
        assert_eq!(canonicalize_value(&arr).unwrap(), "[1,2,3]");

        let arr2 = json!(["a", "b", "c"]);
        assert_eq!(canonicalize_value(&arr2).unwrap(), "[\"a\",\"b\",\"c\"]");
    }

    #[test]
    fn test_canonicalize_object() {
        // Keys should be sorted
        let obj = json!({"z": 1, "a": 2, "m": 3});
        assert_eq!(canonicalize_value(&obj).unwrap(), "{\"a\":2,\"m\":3,\"z\":1}");
    }

    #[test]
    fn test_canonicalize_nested() {
        let nested = json!({
            "b": [1, 2],
            "a": {"y": 1, "x": 2}
        });
        assert_eq!(
            canonicalize_value(&nested).unwrap(),
            "{\"a\":{\"x\":2,\"y\":1},\"b\":[1,2]}"
        );
    }

    #[test]
    fn test_compute_hash() {
        let data = json!({"hello": "world"});
        let hash = compute_hash(&data).unwrap();
        assert_eq!(hash.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn test_normalize_for_signing() {
        let data = json!({
            "data": "value",
            "signature": "should be removed",
            "proof": "also removed"
        });

        let normalized = normalize_for_signing(&data, true).unwrap();
        let obj = normalized.as_object().unwrap();

        assert!(obj.contains_key("data"));
        assert!(!obj.contains_key("signature"));
        assert!(!obj.contains_key("proof"));
    }

    #[test]
    fn test_serialize_string_escaping() {
        assert_eq!(serialize_string("hello"), "\"hello\"");
        assert_eq!(serialize_string("a\"b"), "\"a\\\"b\"");
        assert_eq!(serialize_string("a\\b"), "\"a\\\\b\"");
        assert_eq!(serialize_string("a\nb"), "\"a\\nb\"");
        assert_eq!(serialize_string("a\tb"), "\"a\\tb\"");
    }
}
