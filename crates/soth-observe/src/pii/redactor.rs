//! PII redaction utilities

use super::detector::{PiiDetector, PiiMatch};
use soth_core::types::observation::PiiType;

/// PII redaction engine
#[derive(Debug)]
pub struct PiiRedactor {
    /// The detector to use
    detector: PiiDetector,
    /// Redaction character
    redact_char: char,
    /// Whether to preserve length
    preserve_length: bool,
    /// Custom replacement map by type
    replacements: std::collections::HashMap<PiiType, String>,
}

impl Default for PiiRedactor {
    fn default() -> Self {
        Self::new()
    }
}

impl PiiRedactor {
    /// Create a new redactor with default settings
    pub fn new() -> Self {
        Self {
            detector: PiiDetector::new(),
            redact_char: '*',
            preserve_length: true,
            replacements: std::collections::HashMap::new(),
        }
    }

    /// Set the redaction character
    pub fn with_redact_char(mut self, c: char) -> Self {
        self.redact_char = c;
        self
    }

    /// Set whether to preserve length
    pub fn with_preserve_length(mut self, preserve: bool) -> Self {
        self.preserve_length = preserve;
        self
    }

    /// Set a custom replacement for a PII type
    pub fn with_replacement(mut self, pii_type: PiiType, replacement: impl Into<String>) -> Self {
        self.replacements.insert(pii_type, replacement.into());
        self
    }

    /// Set the detector to use
    pub fn with_detector(mut self, detector: PiiDetector) -> Self {
        self.detector = detector;
        self
    }

    /// Redact PII from text
    pub fn redact(&self, text: &str) -> RedactionResult {
        let matches = self.detector.detect(text);

        if matches.is_empty() {
            return RedactionResult {
                text: text.to_string(),
                redactions: Vec::new(),
            };
        }

        let mut result = text.to_string();
        let mut offset: i64 = 0;

        let mut redactions = Vec::new();

        for m in &matches {
            let start = (m.start as i64 + offset) as usize;
            let end = (m.end as i64 + offset) as usize;

            let replacement = self.get_replacement(m);
            let length_diff = replacement.len() as i64 - (m.end - m.start) as i64;

            result.replace_range(start..end, &replacement);

            redactions.push(Redaction {
                pii_type: m.pii_type,
                original_length: m.end - m.start,
                replacement: replacement.clone(),
                position: start,
            });

            offset += length_diff;
        }

        RedactionResult {
            text: result,
            redactions,
        }
    }

    /// Redact PII in a JSON value (recursive)
    pub fn redact_json(&self, value: &serde_json::Value) -> (serde_json::Value, Vec<Redaction>) {
        let mut all_redactions = Vec::new();
        let result = self.redact_json_value(value, &mut all_redactions);
        (result, all_redactions)
    }

    fn redact_json_value(
        &self,
        value: &serde_json::Value,
        redactions: &mut Vec<Redaction>,
    ) -> serde_json::Value {
        match value {
            serde_json::Value::String(s) => {
                let result = self.redact(s);
                redactions.extend(result.redactions);
                serde_json::Value::String(result.text)
            }
            serde_json::Value::Array(arr) => {
                let redacted: Vec<_> = arr
                    .iter()
                    .map(|v| self.redact_json_value(v, redactions))
                    .collect();
                serde_json::Value::Array(redacted)
            }
            serde_json::Value::Object(obj) => {
                let mut redacted = serde_json::Map::new();
                for (k, v) in obj {
                    redacted.insert(k.clone(), self.redact_json_value(v, redactions));
                }
                serde_json::Value::Object(redacted)
            }
            _ => value.clone(),
        }
    }

    fn get_replacement(&self, m: &PiiMatch) -> String {
        // Check for custom replacement
        if let Some(replacement) = self.replacements.get(&m.pii_type) {
            return replacement.clone();
        }

        // Generate replacement
        if self.preserve_length {
            self.redact_char.to_string().repeat(m.text.len())
        } else {
            // Use type-specific placeholders
            match m.pii_type {
                PiiType::Ssn => "[SSN]".to_string(),
                PiiType::Email => "[EMAIL]".to_string(),
                PiiType::CreditCard => "[CARD]".to_string(),
                PiiType::Phone => "[PHONE]".to_string(),
                PiiType::IpAddress => "[IP]".to_string(),
                PiiType::ApiKey => "[API_KEY]".to_string(),
                PiiType::Other => "[REDACTED]".to_string(),
            }
        }
    }
}

/// Result of redaction
#[derive(Debug, Clone)]
pub struct RedactionResult {
    /// The redacted text
    pub text: String,
    /// Information about what was redacted
    pub redactions: Vec<Redaction>,
}

/// Information about a single redaction
#[derive(Debug, Clone)]
pub struct Redaction {
    /// Type of PII that was redacted
    pub pii_type: PiiType,
    /// Original length of the redacted text
    pub original_length: usize,
    /// The replacement text
    pub replacement: String,
    /// Position in the redacted text
    pub position: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_ssn() {
        let redactor = PiiRedactor::new();
        let result = redactor.redact("SSN: 123-45-6789");

        assert_eq!(result.text, "SSN: ***********");
        assert_eq!(result.redactions.len(), 1);
        assert_eq!(result.redactions[0].pii_type, PiiType::Ssn);
    }

    #[test]
    fn test_redact_email() {
        let redactor = PiiRedactor::new();
        let result = redactor.redact("Email: test@example.com");

        assert_eq!(result.text, "Email: ****************");
        assert_eq!(result.redactions.len(), 1);
    }

    #[test]
    fn test_redact_multiple() {
        let redactor = PiiRedactor::new();
        let result = redactor.redact("SSN: 123-45-6789, Email: a@b.com");

        assert_eq!(result.redactions.len(), 2);
        assert!(!result.text.contains("123-45-6789"));
        assert!(!result.text.contains("a@b.com"));
    }

    #[test]
    fn test_custom_redact_char() {
        let redactor = PiiRedactor::new().with_redact_char('X');
        let result = redactor.redact("SSN: 123-45-6789");

        assert!(result.text.contains("XXXXXXXXXXX"));
    }

    #[test]
    fn test_no_preserve_length() {
        let redactor = PiiRedactor::new().with_preserve_length(false);
        let result = redactor.redact("SSN: 123-45-6789");

        assert_eq!(result.text, "SSN: [SSN]");
    }

    #[test]
    fn test_custom_replacement() {
        let redactor = PiiRedactor::new()
            .with_preserve_length(false)
            .with_replacement(PiiType::Ssn, "<SOCIAL>");

        let result = redactor.redact("SSN: 123-45-6789");
        assert_eq!(result.text, "SSN: <SOCIAL>");
    }

    #[test]
    fn test_redact_json() {
        let redactor = PiiRedactor::new().with_preserve_length(false);

        let json = serde_json::json!({
            "name": "John Doe",
            "ssn": "123-45-6789",
            "contact": {
                "email": "john@example.com"
            }
        });

        let (redacted, redactions) = redactor.redact_json(&json);

        assert_eq!(redacted["ssn"], "[SSN]");
        assert_eq!(redacted["contact"]["email"], "[EMAIL]");
        assert_eq!(redactions.len(), 2);
    }

    #[test]
    fn test_no_pii() {
        let redactor = PiiRedactor::new();
        let result = redactor.redact("Hello, world!");

        assert_eq!(result.text, "Hello, world!");
        assert!(result.redactions.is_empty());
    }
}
