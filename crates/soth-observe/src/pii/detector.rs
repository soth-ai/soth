//! PII detection engine

use super::patterns::{luhn_check, PATTERNS};
use soth_core::types::observation::PiiType;

/// A detected PII match
#[derive(Debug, Clone)]
pub struct PiiMatch {
    /// Type of PII detected
    pub pii_type: PiiType,
    /// Start position in the text
    pub start: usize,
    /// End position in the text
    pub end: usize,
    /// The matched text
    pub text: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
}

/// PII detection engine
#[derive(Debug, Default)]
pub struct PiiDetector {
    /// Enable SSN detection
    pub detect_ssn: bool,
    /// Enable email detection
    pub detect_email: bool,
    /// Enable credit card detection
    pub detect_credit_card: bool,
    /// Enable phone detection
    pub detect_phone: bool,
    /// Enable IP address detection
    pub detect_ip: bool,
    /// Enable API key detection
    pub detect_api_key: bool,
}

impl PiiDetector {
    /// Create a new detector with all detection enabled
    pub fn new() -> Self {
        Self {
            detect_ssn: true,
            detect_email: true,
            detect_credit_card: true,
            detect_phone: true,
            detect_ip: true,
            detect_api_key: true,
        }
    }

    /// Create a detector with specific types enabled
    pub fn with_types(types: &[PiiType]) -> Self {
        let mut detector = Self::default();
        for pii_type in types {
            match pii_type {
                PiiType::Ssn => detector.detect_ssn = true,
                PiiType::Email => detector.detect_email = true,
                PiiType::CreditCard => detector.detect_credit_card = true,
                PiiType::Phone => detector.detect_phone = true,
                PiiType::IpAddress => detector.detect_ip = true,
                PiiType::ApiKey => detector.detect_api_key = true,
                PiiType::Other => {}
            }
        }
        detector
    }

    /// Detect PII in text
    pub fn detect(&self, text: &str) -> Vec<PiiMatch> {
        let mut matches = Vec::new();

        if self.detect_ssn {
            self.find_ssn(text, &mut matches);
        }

        if self.detect_email {
            self.find_email(text, &mut matches);
        }

        if self.detect_credit_card {
            self.find_credit_card(text, &mut matches);
        }

        if self.detect_phone {
            self.find_phone(text, &mut matches);
        }

        if self.detect_ip {
            self.find_ip(text, &mut matches);
        }

        if self.detect_api_key {
            self.find_api_key(text, &mut matches);
        }

        // Sort by position
        matches.sort_by_key(|m| m.start);

        // Remove overlapping matches (keep highest confidence)
        Self::remove_overlaps(&mut matches);

        matches
    }

    /// Check if text contains any PII
    pub fn contains_pii(&self, text: &str) -> bool {
        !self.detect(text).is_empty()
    }

    /// Get the types of PII found in text
    pub fn detect_types(&self, text: &str) -> Vec<PiiType> {
        let matches = self.detect(text);
        let mut types: Vec<PiiType> = matches.into_iter().map(|m| m.pii_type).collect();
        types.sort_by_key(|t| format!("{t:?}"));
        types.dedup();
        types
    }

    fn find_ssn(&self, text: &str, matches: &mut Vec<PiiMatch>) {
        for cap in PATTERNS.ssn.find_iter(text) {
            matches.push(PiiMatch {
                pii_type: PiiType::Ssn,
                start: cap.start(),
                end: cap.end(),
                text: cap.as_str().to_string(),
                confidence: 0.9,
            });
        }
    }

    fn find_email(&self, text: &str, matches: &mut Vec<PiiMatch>) {
        for cap in PATTERNS.email.find_iter(text) {
            matches.push(PiiMatch {
                pii_type: PiiType::Email,
                start: cap.start(),
                end: cap.end(),
                text: cap.as_str().to_string(),
                confidence: 0.95,
            });
        }
    }

    fn find_credit_card(&self, text: &str, matches: &mut Vec<PiiMatch>) {
        for cap in PATTERNS.credit_card.find_iter(text) {
            let matched_text = cap.as_str();
            // Additional Luhn validation
            if luhn_check(matched_text) {
                matches.push(PiiMatch {
                    pii_type: PiiType::CreditCard,
                    start: cap.start(),
                    end: cap.end(),
                    text: matched_text.to_string(),
                    confidence: 0.95,
                });
            } else {
                // Still flag it but with lower confidence
                matches.push(PiiMatch {
                    pii_type: PiiType::CreditCard,
                    start: cap.start(),
                    end: cap.end(),
                    text: matched_text.to_string(),
                    confidence: 0.6,
                });
            }
        }
    }

    fn find_phone(&self, text: &str, matches: &mut Vec<PiiMatch>) {
        for cap in PATTERNS.phone.find_iter(text) {
            matches.push(PiiMatch {
                pii_type: PiiType::Phone,
                start: cap.start(),
                end: cap.end(),
                text: cap.as_str().to_string(),
                confidence: 0.85,
            });
        }
    }

    fn find_ip(&self, text: &str, matches: &mut Vec<PiiMatch>) {
        for cap in PATTERNS.ip_address.find_iter(text) {
            // Skip common non-PII IPs
            let ip = cap.as_str();
            if ip == "127.0.0.1"
                || ip == "0.0.0.0"
                || ip.starts_with("192.168.")
                || ip.starts_with("10.")
            {
                continue;
            }

            matches.push(PiiMatch {
                pii_type: PiiType::IpAddress,
                start: cap.start(),
                end: cap.end(),
                text: ip.to_string(),
                confidence: 0.7,
            });
        }
    }

    fn find_api_key(&self, text: &str, matches: &mut Vec<PiiMatch>) {
        for cap in PATTERNS.api_key.find_iter(text) {
            matches.push(PiiMatch {
                pii_type: PiiType::ApiKey,
                start: cap.start(),
                end: cap.end(),
                text: cap.as_str().to_string(),
                confidence: 0.9,
            });
        }
    }

    /// Remove overlapping matches, keeping the one with highest confidence
    fn remove_overlaps(matches: &mut Vec<PiiMatch>) {
        if matches.len() <= 1 {
            return;
        }

        let mut i = 0;
        while i < matches.len() {
            let mut j = i + 1;
            while j < matches.len() {
                // Check for overlap
                if matches[i].end > matches[j].start && matches[i].start < matches[j].end {
                    // Keep the one with higher confidence
                    if matches[i].confidence >= matches[j].confidence {
                        matches.remove(j);
                    } else {
                        matches.remove(i);
                        j = i + 1;
                        continue;
                    }
                } else {
                    j += 1;
                }
            }
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ssn() {
        let detector = PiiDetector::new();
        let text = "My SSN is 123-45-6789";
        let matches = detector.detect(text);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pii_type, PiiType::Ssn);
        assert_eq!(matches[0].text, "123-45-6789");
    }

    #[test]
    fn test_detect_email() {
        let detector = PiiDetector::new();
        let text = "Contact me at test@example.com";
        let matches = detector.detect(text);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pii_type, PiiType::Email);
        assert_eq!(matches[0].text, "test@example.com");
    }

    #[test]
    fn test_detect_credit_card() {
        let detector = PiiDetector::new();
        let text = "Card: 4111-1111-1111-1111";
        let matches = detector.detect(text);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pii_type, PiiType::CreditCard);
        assert!(matches[0].confidence > 0.9); // Luhn valid
    }

    #[test]
    fn test_detect_multiple() {
        let detector = PiiDetector::new();
        // Note: Phone format needs [2-9] for area code and exchange
        let text = "SSN: 123-45-6789, Email: test@example.com, Phone: (212) 555-4567";
        let matches = detector.detect(text);

        assert_eq!(matches.len(), 3);
        let types: Vec<_> = matches.iter().map(|m| m.pii_type).collect();
        assert!(types.contains(&PiiType::Ssn));
        assert!(types.contains(&PiiType::Email));
        assert!(types.contains(&PiiType::Phone));
    }

    #[test]
    fn test_contains_pii() {
        let detector = PiiDetector::new();
        assert!(detector.contains_pii("SSN: 123-45-6789"));
        assert!(!detector.contains_pii("No PII here"));
    }

    #[test]
    fn test_detect_types() {
        let detector = PiiDetector::new();
        let text = "test@example.com and 123-45-6789";
        let types = detector.detect_types(text);

        assert!(types.contains(&PiiType::Email));
        assert!(types.contains(&PiiType::Ssn));
    }

    #[test]
    fn test_selective_detection() {
        let detector = PiiDetector::with_types(&[PiiType::Email]);
        let text = "Email: test@example.com, SSN: 123-45-6789";
        let matches = detector.detect(text);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pii_type, PiiType::Email);
    }

    #[test]
    fn test_api_key_detection() {
        let detector = PiiDetector::new();
        // API key pattern requires at least 20 chars after sk_ or sk-
        let text = "Key: sk_1234567890abcdefghijklmnop";
        let matches = detector.detect(text);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pii_type, PiiType::ApiKey);
    }
}
