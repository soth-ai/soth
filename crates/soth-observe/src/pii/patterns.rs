//! PII detection regex patterns

use once_cell::sync::Lazy;
use regex::Regex;
use soth_core::types::observation::PiiType;

/// Compiled PII patterns
pub struct PiiPatterns {
    pub ssn: Regex,
    pub email: Regex,
    pub credit_card: Regex,
    pub phone: Regex,
    pub ip_address: Regex,
    pub api_key: Regex,
}

impl PiiPatterns {
    /// Create compiled patterns
    /// Note: Rust regex doesn't support lookaround, so patterns use word boundaries where possible
    pub fn new() -> Self {
        Self {
            // SSN: XXX-XX-XXXX format
            // Uses word boundaries instead of lookahead/lookbehind
            ssn: Regex::new(
                r"\b(\d{3})[-\s]?(\d{2})[-\s]?(\d{4})\b"
            ).unwrap(),

            // Email: standard email pattern
            email: Regex::new(
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
            ).unwrap(),

            // Credit card: Visa, MC, Amex, Discover with optional separators
            // Uses word boundaries
            credit_card: Regex::new(
                r"\b(4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"
            ).unwrap(),

            // Phone: US format with optional country code
            // Uses word boundaries
            phone: Regex::new(
                r"(\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}\b"
            ).unwrap(),

            // IPv4 address
            ip_address: Regex::new(
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
            ).unwrap(),

            // API keys: common patterns (sk_, api_, bearer tokens, etc.)
            api_key: Regex::new(
                r"(?i)(sk[_-][a-zA-Z0-9]{20,}|api[_-]?key[_-]?[a-zA-Z0-9]{16,}|bearer\s+[a-zA-Z0-9._-]{20,}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36})"
            ).unwrap(),
        }
    }
}

impl Default for PiiPatterns {
    fn default() -> Self {
        Self::new()
    }
}

/// Global singleton for compiled patterns
pub static PATTERNS: Lazy<PiiPatterns> = Lazy::new(PiiPatterns::new);

/// Get the pattern for a PII type
#[allow(dead_code)]
pub fn pattern_for_type(pii_type: PiiType) -> &'static Regex {
    match pii_type {
        PiiType::Ssn => &PATTERNS.ssn,
        PiiType::Email => &PATTERNS.email,
        PiiType::CreditCard => &PATTERNS.credit_card,
        PiiType::Phone => &PATTERNS.phone,
        PiiType::IpAddress => &PATTERNS.ip_address,
        PiiType::ApiKey => &PATTERNS.api_key,
        PiiType::Other => &PATTERNS.email, // Fallback
    }
}

/// Luhn algorithm for credit card validation
pub fn luhn_check(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                d
            }
        })
        .sum();

    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssn_pattern() {
        let pattern = &PATTERNS.ssn;

        assert!(pattern.is_match("123-45-6789"));
        assert!(pattern.is_match("123 45 6789"));
        assert!(pattern.is_match("123456789"));

        // Pattern matches format only, validation for invalid SSNs
        // (000, 666, etc) should be done separately after matching
    }

    #[test]
    fn test_email_pattern() {
        let pattern = &PATTERNS.email;

        assert!(pattern.is_match("test@example.com"));
        assert!(pattern.is_match("user.name+tag@domain.co.uk"));
        assert!(!pattern.is_match("not-an-email"));
    }

    #[test]
    fn test_credit_card_pattern() {
        let pattern = &PATTERNS.credit_card;

        assert!(pattern.is_match("4111111111111111")); // Visa
        assert!(pattern.is_match("4111-1111-1111-1111"));
        assert!(pattern.is_match("5500 0000 0000 0004")); // MC
    }

    #[test]
    fn test_phone_pattern() {
        let pattern = &PATTERNS.phone;

        // Note: Pattern requires area code starting with 2-9
        assert!(pattern.is_match("(212) 555-1234"));
        assert!(pattern.is_match("+1 212-555-1234"));
        assert!(pattern.is_match("2125551234"));
    }

    #[test]
    fn test_luhn_check() {
        // Valid test card numbers
        assert!(luhn_check("4111111111111111")); // Visa test
        assert!(luhn_check("5500000000000004")); // MC test
        assert!(luhn_check("378282246310005")); // Amex test

        // Invalid
        assert!(!luhn_check("4111111111111112"));
        assert!(!luhn_check("1234567890"));
    }
}
