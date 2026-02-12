//! Helpers for stripping anti-JSON-hijacking prefixes.

const JSON_SECURITY_PREFIXES: &[&[u8]] = &[b")]}'\n", b")]}'", b"for(;;);", b"while(1);", b"{}&&"];

/// Strip common anti-JSON-hijacking prefixes used by some providers.
/// Returns the original buffer when no known prefix is present.
pub fn strip_json_security_prefix(data: &[u8]) -> &[u8] {
    let Some(non_ws_idx) = data.iter().position(|b| !b.is_ascii_whitespace()) else {
        return data;
    };
    let trimmed = &data[non_ws_idx..];
    for prefix in JSON_SECURITY_PREFIXES {
        if trimmed.starts_with(prefix) {
            return &trimmed[prefix.len()..];
        }
    }
    data
}

/// String helper for anti-JSON-hijacking prefix stripping.
pub fn strip_json_security_prefix_text(text: &str) -> &str {
    let bytes = text.as_bytes();
    let Some(non_ws_idx) = bytes.iter().position(|b| !b.is_ascii_whitespace()) else {
        return text;
    };
    let trimmed = &bytes[non_ws_idx..];
    for prefix in JSON_SECURITY_PREFIXES {
        if trimmed.starts_with(prefix) {
            let start = non_ws_idx + prefix.len();
            return &text[start..];
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::{strip_json_security_prefix, strip_json_security_prefix_text};

    #[test]
    fn strips_google_xssi_prefix() {
        let raw = b")]}'\n{\"ok\":true}";
        assert_eq!(strip_json_security_prefix(raw), br#"{"ok":true}"#);
    }

    #[test]
    fn strips_for_loop_prefix() {
        let raw = b"for(;;);{\"ok\":true}";
        assert_eq!(strip_json_security_prefix(raw), br#"{"ok":true}"#);
    }

    #[test]
    fn strips_while_loop_prefix() {
        let raw = "while(1);{\"ok\":true}";
        assert_eq!(strip_json_security_prefix_text(raw), "{\"ok\":true}");
    }

    #[test]
    fn strips_object_and_prefix() {
        let raw = "{}&&{\"ok\":true}";
        assert_eq!(strip_json_security_prefix_text(raw), "{\"ok\":true}");
    }

    #[test]
    fn keeps_non_prefixed_payload() {
        let raw = "{\"ok\":true}";
        assert_eq!(strip_json_security_prefix_text(raw), raw);
    }
}
