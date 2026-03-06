use crate::hash::sha256_hex;
use crate::types::{ArtifactLocation, ArtifactType, SensitiveArtifact, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

static OPENAI_KEY_RE: Lazy<Option<Regex>> =
    Lazy::new(|| Regex::new(r"\bsk-[A-Za-z0-9\-_]{16,}\b").ok());
static ANTHROPIC_KEY_RE: Lazy<Option<Regex>> =
    Lazy::new(|| Regex::new(r"\bsk-ant-[A-Za-z0-9\-_]{16,}\b").ok());
static AWS_KEY_RE: Lazy<Option<Regex>> = Lazy::new(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").ok());
static GITHUB_PAT_RE: Lazy<Option<Regex>> =
    Lazy::new(|| Regex::new(r"\bghp_[A-Za-z0-9]{20,}\b").ok());
static GITLAB_PAT_RE: Lazy<Option<Regex>> =
    Lazy::new(|| Regex::new(r"\bglpat-[A-Za-z0-9\-_]{20,}\b").ok());
static JWT_RE: Lazy<Option<Regex>> =
    Lazy::new(|| Regex::new(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b").ok());
static PRIVATE_KEY_RE: Lazy<Option<Regex>> =
    Lazy::new(|| Regex::new(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----").ok());
static CONNECTION_STRING_RE: Lazy<Option<Regex>> =
    Lazy::new(|| Regex::new(r#"\b(postgres|mysql|mongodb|redis|amqp)://[^\s"']+"#).ok());
static SLACK_TOKEN_RE: Lazy<Option<Regex>> =
    Lazy::new(|| Regex::new(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b").ok());
static STRIPE_SECRET_RE: Lazy<Option<Regex>> =
    Lazy::new(|| Regex::new(r"\bsk_live_[A-Za-z0-9]{16,}\b").ok());
static STRIPE_TEST_RE: Lazy<Option<Regex>> =
    Lazy::new(|| Regex::new(r"\bsk_test_[A-Za-z0-9]{16,}\b").ok());
static HEX_KEY_RE: Lazy<Option<Regex>> =
    Lazy::new(|| Regex::new(r"\b[0-9a-fA-F]{32,64}\b").ok());

pub fn credential_scan(body: &[u8], location: ArtifactLocation) -> Vec<SensitiveArtifact> {
    let text = String::from_utf8_lossy(body);
    let mut out = Vec::new();

    // Scan Anthropic before OpenAI to avoid sk-ant- matching sk-
    scan_pattern(
        &mut out, &text, &ANTHROPIC_KEY_RE, ArtifactType::AnthropicKey,
        Severity::Critical, location.clone(),
    );
    scan_pattern(
        &mut out, &text, &OPENAI_KEY_RE, ArtifactType::OpenAIKey,
        Severity::Critical, location.clone(),
    );
    scan_pattern(
        &mut out, &text, &AWS_KEY_RE, ArtifactType::AwsAccessKey,
        Severity::High, location.clone(),
    );
    scan_pattern(
        &mut out, &text, &GITHUB_PAT_RE, ArtifactType::GitHubPat,
        Severity::High, location.clone(),
    );
    scan_pattern(
        &mut out, &text, &GITLAB_PAT_RE, ArtifactType::GitLabToken,
        Severity::High, location.clone(),
    );
    scan_pattern(
        &mut out, &text, &SLACK_TOKEN_RE, ArtifactType::SlackToken,
        Severity::High, location.clone(),
    );
    scan_pattern(
        &mut out, &text, &STRIPE_SECRET_RE, ArtifactType::StripeSecretKey,
        Severity::Critical, location.clone(),
    );
    scan_pattern(
        &mut out, &text, &STRIPE_TEST_RE, ArtifactType::StripeSecretKey,
        Severity::Medium, location.clone(),
    );
    scan_pattern(
        &mut out, &text, &JWT_RE, ArtifactType::JwtToken,
        Severity::Medium, location.clone(),
    );
    scan_pattern(
        &mut out, &text, &PRIVATE_KEY_RE, ArtifactType::PrivateKey,
        Severity::Critical, location.clone(),
    );
    scan_pattern(
        &mut out, &text, &CONNECTION_STRING_RE, ArtifactType::ConnectionString,
        Severity::High, location.clone(),
    );

    scan_hex_keys(&mut out, &text, location);

    out
}

pub fn redact_sensitive_bytes(input: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(input);
    redact_sensitive_text(&text).into_bytes()
}

pub fn redact_sensitive_text(input: &str) -> String {
    let mut output = input.to_string();
    output = replace_all(&output, &ANTHROPIC_KEY_RE, "<REDACTED_ANTHROPIC_KEY>");
    output = replace_all(&output, &OPENAI_KEY_RE, "<REDACTED_OPENAI_KEY>");
    output = replace_all(&output, &AWS_KEY_RE, "<REDACTED_AWS_ACCESS_KEY>");
    output = replace_all(&output, &GITHUB_PAT_RE, "<REDACTED_GITHUB_PAT>");
    output = replace_all(&output, &GITLAB_PAT_RE, "<REDACTED_GITLAB_PAT>");
    output = replace_all(&output, &SLACK_TOKEN_RE, "<REDACTED_SLACK_TOKEN>");
    output = replace_all(&output, &STRIPE_SECRET_RE, "<REDACTED_STRIPE_KEY>");
    output = replace_all(&output, &STRIPE_TEST_RE, "<REDACTED_STRIPE_TEST_KEY>");
    output = replace_all(&output, &JWT_RE, "<REDACTED_JWT>");
    output = replace_all(&output, &PRIVATE_KEY_RE, "<REDACTED_PRIVATE_KEY_HEADER>");
    output = replace_all(
        &output, &CONNECTION_STRING_RE, "<REDACTED_CONNECTION_STRING>",
    );
    output
}

/// Second-pass structural scan. Detects auth and crypto logic patterns
/// without capturing any content. Only emits presence-flag artifacts.
pub fn structural_scan(body: &[u8], location: ArtifactLocation) -> Vec<SensitiveArtifact> {
    let text = String::from_utf8_lossy(body);
    let text_lc = text.to_ascii_lowercase();
    let mut out = Vec::new();

    if has_auth_logic(&text_lc) {
        out.push(SensitiveArtifact {
            artifact_type: ArtifactType::AuthLogicFlag,
            commitment: sha256_hex(format!("auth_logic:present:{:?}", location)),
            severity: Severity::Low,
            location: location.clone(),
            redacted_hint: None,
        });
    }

    if has_crypto_operations(&text_lc) {
        out.push(SensitiveArtifact {
            artifact_type: ArtifactType::CryptoFlag,
            commitment: sha256_hex(format!("crypto_op:present:{:?}", location)),
            severity: Severity::Low,
            location,
            redacted_hint: None,
        });
    }

    out
}

/// Scan body against org-configured regex patterns.
pub fn org_pattern_scan(
    body: &[u8],
    org_patterns: &[String],
    location: ArtifactLocation,
) -> Vec<SensitiveArtifact> {
    if org_patterns.is_empty() {
        return Vec::new();
    }

    let text = String::from_utf8_lossy(body);
    let mut out = Vec::new();

    for (idx, pattern_str) in org_patterns.iter().enumerate() {
        let Ok(regex) = regex::Regex::new(pattern_str) else {
            continue;
        };

        if regex.is_match(&text) {
            let pattern_id = idx as u32;
            out.push(SensitiveArtifact {
                artifact_type: ArtifactType::OrgPatternMatch { pattern_id },
                commitment: sha256_hex(format!("org_pattern:{}:detect-v1", pattern_id)),
                severity: Severity::Medium,
                location: location.clone(),
                redacted_hint: None,
            });
        }
    }

    out
}

fn has_auth_logic(text_lc: &str) -> bool {
    let auth_patterns = [
        "authenticate", "authorization", "bearer ", "api_key", "apikey",
        "access_token", "refresh_token", "oauth", "saml", "oidc",
        "verify_password", "check_password", "login(", "logout(",
        "session.set", "session.get", "is_authenticated", "require_auth",
        "password_hash", "verify_token", "decode_jwt", "validate_token",
    ];
    auth_patterns.iter().filter(|p| text_lc.contains(*p)).count() >= 2
}

fn has_crypto_operations(text_lc: &str) -> bool {
    let crypto_patterns = [
        "encrypt(", "decrypt(", "aes.new", "rsa.new", "cipher(", "decipher(",
        "hmac(", "sha256(", "sha512(", "md5(", "bcrypt.", "argon2.",
        "sign(", "verify(", "keypair", "private_key", "public_key",
        "crypto.create", "openssl", "nacl.", "sodium.",
    ];
    crypto_patterns.iter().filter(|p| text_lc.contains(*p)).count() >= 2
}

fn scan_pattern(
    out: &mut Vec<SensitiveArtifact>,
    haystack: &str,
    regex: &Option<Regex>,
    artifact_type: ArtifactType,
    severity: Severity,
    location: ArtifactLocation,
) {
    let Some(regex) = regex else {
        return;
    };

    for m in regex.find_iter(haystack) {
        let raw = m.as_str();
        let commitment = sha256_hex(format!(
            "{}:{}:{}",
            artifact_type_name(&artifact_type),
            raw,
            "detect-v1"
        ));
        out.push(SensitiveArtifact {
            artifact_type: artifact_type.clone(),
            commitment,
            severity: severity.clone(),
            location: location.clone(),
            redacted_hint: redacted_hint(raw),
        });
    }
}

fn scan_hex_keys(
    out: &mut Vec<SensitiveArtifact>,
    haystack: &str,
    location: ArtifactLocation,
) {
    let Some(regex) = &*HEX_KEY_RE else { return };

    for m in regex.find_iter(haystack) {
        let raw = m.as_str();

        if raw.len() == 32 && looks_like_uuid_hex(raw) {
            continue;
        }

        if raw.len() == 40 && raw.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) {
            continue;
        }

        let mixed_case = raw.chars().any(|c| c.is_uppercase())
            && raw.chars().any(|c| c.is_lowercase());
        if mixed_case || raw.len() >= 48 {
            let commitment = sha256_hex(format!("hex_key:{}:detect-v1", raw));
            out.push(SensitiveArtifact {
                artifact_type: ArtifactType::UnknownCredential,
                commitment,
                severity: Severity::Medium,
                location: location.clone(),
                redacted_hint: redacted_hint(raw),
            });
        }
    }
}

fn looks_like_uuid_hex(s: &str) -> bool {
    s.len() == 32 && s.chars().nth(12) == Some('4')
}

fn redacted_hint(raw: &str) -> Option<String> {
    if raw.len() < 4 {
        return None;
    }
    Some(format!("{}...XXXX", &raw[..4]))
}

fn artifact_type_name(kind: &ArtifactType) -> &'static str {
    match kind {
        ArtifactType::OpenAIKey => "openai_key",
        ArtifactType::AnthropicKey => "anthropic_key",
        ArtifactType::AwsAccessKey => "aws_access_key",
        ArtifactType::GitHubPat => "github_pat",
        ArtifactType::GitLabToken => "gitlab_token",
        ArtifactType::SlackToken => "slack_token",
        ArtifactType::StripeSecretKey => "stripe_secret_key",
        ArtifactType::JwtToken => "jwt",
        ArtifactType::PrivateKey => "private_key",
        ArtifactType::ConnectionString => "connection_string",
        ArtifactType::CodeBlock { .. } => "code_block",
        ArtifactType::UnknownCredential => "unknown_credential",
        ArtifactType::AuthLogicFlag => "auth_logic",
        ArtifactType::CryptoFlag => "crypto_operation",
        ArtifactType::OrgPatternMatch { .. } => "org_pattern",
    }
}

fn replace_all(input: &str, regex: &Option<Regex>, replacement: &str) -> String {
    let Some(regex) = regex else {
        return input.to_string();
    };
    regex.replace_all(input, replacement).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_scan_detects_multiple_artifact_types() {
        let body = br#"
openai=sk-abcdefghijklmnopqrstuvwxyz1234
anthropic=sk-ant-abcdefghijklmnopqrstuvwx1234
aws=AKIA1234567890ABCDEF
github=ghp_abcdefghijklmnopqrstuvwxyz1234
gitlab=glpat-abcdefghijklmnopqrstuvwx
jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.signaturetoken
db=postgres://user:pass@db.local:5432/app
-----BEGIN PRIVATE KEY-----
"#;

        let artifacts = credential_scan(body, ArtifactLocation::Unknown);
        assert!(artifacts.iter().any(|a| matches!(a.artifact_type, ArtifactType::OpenAIKey)));
        assert!(artifacts.iter().any(|a| matches!(a.artifact_type, ArtifactType::AnthropicKey)));
        assert!(artifacts.iter().any(|a| matches!(a.artifact_type, ArtifactType::AwsAccessKey)));
        assert!(artifacts.iter().any(|a| matches!(a.artifact_type, ArtifactType::GitHubPat)));
        assert!(artifacts.iter().any(|a| matches!(a.artifact_type, ArtifactType::GitLabToken)));
        assert!(artifacts.iter().any(|a| matches!(a.artifact_type, ArtifactType::JwtToken)));
        assert!(artifacts.iter().any(|a| matches!(a.artifact_type, ArtifactType::ConnectionString)));
        assert!(artifacts.iter().any(|a| matches!(a.artifact_type, ArtifactType::PrivateKey)));
    }

    #[test]
    fn credential_scan_detects_slack_token() {
        let body = b"token=xoxb-1234567890-abcdef";
        let artifacts = credential_scan(body, ArtifactLocation::Unknown);
        assert!(artifacts.iter().any(|a| matches!(a.artifact_type, ArtifactType::SlackToken)));
    }

    #[test]
    fn credential_scan_detects_stripe_keys() {
        let body = b"live=sk_live_abcdefghijklmnop test=sk_test_abcdefghijklmnop";
        let artifacts = credential_scan(body, ArtifactLocation::Unknown);
        assert!(artifacts.iter().any(|a| matches!(a.artifact_type, ArtifactType::StripeSecretKey)));
    }

    #[test]
    fn redact_sensitive_text_masks_known_patterns() {
        let input = concat!(
            "token=sk-abcdefghijklmnopqrstuvwxyz1234 ",
            "aws=AKIA1234567890ABCDEF ",
            "db=postgres://user:pass@db.local:5432/app ",
            "-----BEGIN PRIVATE KEY-----"
        );

        let redacted = redact_sensitive_text(input);
        assert!(redacted.contains("<REDACTED_OPENAI_KEY>"));
        assert!(redacted.contains("<REDACTED_AWS_ACCESS_KEY>"));
        assert!(redacted.contains("<REDACTED_CONNECTION_STRING>"));
        assert!(redacted.contains("<REDACTED_PRIVATE_KEY_HEADER>"));
        assert!(!redacted.contains("sk-abcdefghijklmnopqrstuvwxyz1234"));
        assert!(!redacted.contains("AKIA1234567890ABCDEF"));
        assert!(!redacted.contains("postgres://user:pass@db.local:5432/app"));
    }

    #[test]
    fn credential_scan_empty_input_is_empty() {
        let artifacts = credential_scan(b"", ArtifactLocation::Unknown);
        assert!(artifacts.is_empty());
    }

    #[test]
    fn structural_scan_detects_auth_logic() {
        let body = b"user.authenticate(password); check_password(hash); bearer token";
        let artifacts = structural_scan(body, ArtifactLocation::Unknown);
        assert!(artifacts.iter().any(|a| matches!(a.artifact_type, ArtifactType::AuthLogicFlag)));
    }

    #[test]
    fn structural_scan_detects_crypto_operations() {
        let body = b"let cipher = encrypt(data); let hash = sha256(input);";
        let artifacts = structural_scan(body, ArtifactLocation::Unknown);
        assert!(artifacts.iter().any(|a| matches!(a.artifact_type, ArtifactType::CryptoFlag)));
    }

    #[test]
    fn structural_scan_requires_two_signals() {
        let body = b"just one authenticate call";
        let artifacts = structural_scan(body, ArtifactLocation::Unknown);
        assert!(artifacts.is_empty());
    }

    #[test]
    fn org_pattern_scan_matches_configured_patterns() {
        let body = b"SSN: 123-45-6789";
        let patterns = vec![r"\d{3}-\d{2}-\d{4}".to_string()];
        let artifacts = org_pattern_scan(body, &patterns, ArtifactLocation::Unknown);
        assert_eq!(artifacts.len(), 1);
        assert!(matches!(artifacts[0].artifact_type, ArtifactType::OrgPatternMatch { pattern_id: 0 }));
        assert!(artifacts[0].redacted_hint.is_none());
    }

    #[test]
    fn org_pattern_scan_skips_invalid_regex() {
        let body = b"test data";
        let patterns = vec!["[invalid".to_string(), r"\btest\b".to_string()];
        let artifacts = org_pattern_scan(body, &patterns, ArtifactLocation::Unknown);
        assert_eq!(artifacts.len(), 1);
        assert!(matches!(artifacts[0].artifact_type, ArtifactType::OrgPatternMatch { pattern_id: 1 }));
    }

    #[test]
    fn org_pattern_scan_empty_patterns_returns_empty() {
        let body = b"test data";
        let artifacts = org_pattern_scan(body, &[], ArtifactLocation::Unknown);
        assert!(artifacts.is_empty());
    }
}
