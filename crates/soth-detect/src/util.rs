pub use soth_parse::util::*;

/// Sampling thresholds for large-content scanning. When a string exceeds
/// `SAMPLING_THRESHOLD_BYTES`, scanners should check only the head/tail
/// slices instead of the full content.
pub const SAMPLING_THRESHOLD_BYTES: usize = 64 * 1024;
pub const SAMPLE_PREFIX_BYTES: usize = 8 * 1024;
pub const SAMPLE_SUFFIX_BYTES: usize = 4 * 1024;

/// Char-boundary-safe prefix slice: returns the longest `&str` prefix up to `max_bytes`.
pub fn safe_prefix(s: &str, max_bytes: usize) -> &str {
    if max_bytes >= s.len() {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Char-boundary-safe suffix slice: returns the longest `&str` suffix up to `max_bytes`.
pub fn safe_suffix(s: &str, max_bytes: usize) -> &str {
    if max_bytes >= s.len() {
        return s;
    }
    let mut start = s.len() - max_bytes;
    while start < s.len() && !s.is_char_boundary(start) {
        start += 1;
    }
    &s[start..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_prefix_on_ascii() {
        assert_eq!(safe_prefix("hello world", 5), "hello");
        assert_eq!(safe_prefix("hi", 10), "hi");
        assert_eq!(safe_prefix("", 5), "");
    }

    #[test]
    fn safe_prefix_on_multibyte() {
        // '€' is 3 bytes (E2 82 AC). Requesting 4 bytes from "€abc" should
        // return "€a" (3+1=4), not panic on a mid-char boundary.
        let s = "€abc";
        assert_eq!(safe_prefix(s, 4), "€a");
        // Requesting 2 bytes cannot include the full '€', so we get "".
        assert_eq!(safe_prefix(s, 2), "");
    }

    #[test]
    fn safe_suffix_on_ascii() {
        assert_eq!(safe_suffix("hello world", 5), "world");
        assert_eq!(safe_suffix("hi", 10), "hi");
        assert_eq!(safe_suffix("", 5), "");
    }

    #[test]
    fn safe_suffix_on_multibyte() {
        let s = "abc€";
        assert_eq!(safe_suffix(s, 4), "c€");
        // Requesting 2 bytes cannot include the full '€', so we skip it.
        assert_eq!(safe_suffix(s, 2), "");
    }
}
