use crate::hash::sha256_hex;
use crate::types::{ArtifactLocation, SensitiveArtifact};
use once_cell::sync::Lazy;
use regex::Regex;
use soth_core::{ArtifactKind, ArtifactSeverity, DetectedProvider};
use tracing;

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
static HEX_KEY_RE: Lazy<Option<Regex>> = Lazy::new(|| Regex::new(r"\b[0-9a-fA-F]{32,64}\b").ok());

/// Scan a pre-decoded `&str` for credentials. Prefer this over
/// [`credential_scan`] when you already hold a UTF-8 view of the body to
/// avoid a redundant `String::from_utf8_lossy` allocation.
pub fn credential_scan_str(text: &str, location: ArtifactLocation) -> Vec<SensitiveArtifact> {
    let mut out = Vec::new();

    // Scan Anthropic before OpenAI to avoid sk-ant- matching sk-
    scan_pattern(
        &mut out,
        text,
        &ANTHROPIC_KEY_RE,
        ArtifactKind::ApiKey {
            provider: Some(DetectedProvider::Anthropic),
        },
        Some("anthropic_api_key"),
        ArtifactSeverity::Critical,
        location.clone(),
    );
    scan_pattern(
        &mut out,
        text,
        &OPENAI_KEY_RE,
        ArtifactKind::ApiKey {
            provider: Some(DetectedProvider::OpenAi),
        },
        Some("openai_api_key"),
        ArtifactSeverity::Critical,
        location.clone(),
    );
    scan_pattern(
        &mut out,
        text,
        &AWS_KEY_RE,
        ArtifactKind::AwsAccessKey,
        Some("aws_access_key_id"),
        ArtifactSeverity::High,
        location.clone(),
    );
    scan_pattern(
        &mut out,
        text,
        &GITHUB_PAT_RE,
        ArtifactKind::GitHubPat,
        Some("github_pat"),
        ArtifactSeverity::High,
        location.clone(),
    );
    scan_pattern(
        &mut out,
        text,
        &GITLAB_PAT_RE,
        ArtifactKind::GitLabToken,
        Some("gitlab_token"),
        ArtifactSeverity::High,
        location.clone(),
    );
    scan_pattern(
        &mut out,
        text,
        &SLACK_TOKEN_RE,
        ArtifactKind::SlackToken,
        Some("slack_token"),
        ArtifactSeverity::High,
        location.clone(),
    );
    scan_pattern(
        &mut out,
        text,
        &STRIPE_SECRET_RE,
        ArtifactKind::StripeSecretKey,
        Some("stripe_live_secret_key"),
        ArtifactSeverity::Critical,
        location.clone(),
    );
    scan_pattern(
        &mut out,
        text,
        &STRIPE_TEST_RE,
        ArtifactKind::StripeSecretKey,
        Some("stripe_test_secret_key"),
        ArtifactSeverity::Medium,
        location.clone(),
    );
    scan_pattern(
        &mut out,
        text,
        &JWT_RE,
        ArtifactKind::Jwt,
        Some("jwt"),
        ArtifactSeverity::Medium,
        location.clone(),
    );
    scan_private_keys(&mut out, text, location.clone());
    scan_connection_strings(&mut out, text, location.clone());

    scan_hex_keys(&mut out, text, location);

    out
}

/// Scan raw bytes for credentials. Decodes `body` as UTF-8 (lossy) then
/// delegates to [`credential_scan_str`]. When the caller already has a
/// `&str` view of the same bytes, use [`credential_scan_str`] directly to
/// skip the extra allocation.
pub fn credential_scan(body: &[u8], location: ArtifactLocation) -> Vec<SensitiveArtifact> {
    let text = String::from_utf8_lossy(body);
    credential_scan_str(&text, location)
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
        &output,
        &CONNECTION_STRING_RE,
        "<REDACTED_CONNECTION_STRING>",
    );
    output
}

/// Second-pass structural scan over a pre-decoded `&str`. Detects auth and
/// crypto logic patterns without capturing any content. Only emits
/// presence-flag artifacts. Prefer this over [`structural_scan`] when you
/// already hold a UTF-8 view of the body.
pub fn structural_scan_str(text: &str, location: ArtifactLocation) -> Vec<SensitiveArtifact> {
    let text_lc = text.to_ascii_lowercase();
    let mut out = Vec::new();

    if has_auth_logic(&text_lc) {
        out.push(SensitiveArtifact {
            kind: ArtifactKind::AuthLogic,
            credential_kind: None,
            commitment: Some(sha256_hex(format!("auth_logic:present:{location:?}"))),
            severity: ArtifactSeverity::Low,
            location: location.clone(),
            redacted_hint: None,
        });
    }

    if has_crypto_operations(&text_lc) {
        out.push(SensitiveArtifact {
            kind: ArtifactKind::CryptoOperation,
            credential_kind: None,
            commitment: Some(sha256_hex(format!("crypto_op:present:{location:?}"))),
            severity: ArtifactSeverity::Low,
            location,
            redacted_hint: None,
        });
    }

    out
}

/// Second-pass structural scan. Detects auth and crypto logic patterns
/// without capturing any content. Only emits presence-flag artifacts.
/// Decodes `body` as UTF-8 (lossy) then delegates to
/// [`structural_scan_str`]. When the caller already has a `&str` view of
/// the same bytes, use [`structural_scan_str`] directly to skip the extra
/// allocation.
pub fn structural_scan(body: &[u8], location: ArtifactLocation) -> Vec<SensitiveArtifact> {
    let text = String::from_utf8_lossy(body);
    structural_scan_str(&text, location)
}

/// Maximum number of org-configured patterns accepted. Patterns beyond this
/// limit are silently dropped after a warning is emitted.
const ORG_PATTERN_MAX_COUNT: usize = 100;

/// Maximum byte length of a single org-configured pattern string. Patterns
/// exceeding this length are rejected after a warning.
const ORG_PATTERN_MAX_LEN: usize = 1_000;

/// Maximum compiled NFA size (bytes) allowed per org pattern.
const ORG_PATTERN_SIZE_LIMIT: usize = 1_000_000;

/// Maximum compiled DFA size (bytes) allowed per org pattern.
const ORG_PATTERN_DFA_SIZE_LIMIT: usize = 1_000_000;

/// Compile a single org pattern string with safety limits applied.
/// Returns `None` and logs a warning if the pattern is rejected.
fn compile_org_pattern(idx: usize, pattern_str: &str) -> Option<Regex> {
    if pattern_str.len() > ORG_PATTERN_MAX_LEN {
        tracing::warn!(
            pattern_index = idx,
            pattern_len = pattern_str.len(),
            max_len = ORG_PATTERN_MAX_LEN,
            "org pattern rejected: pattern string exceeds maximum length"
        );
        return None;
    }

    match regex::RegexBuilder::new(pattern_str)
        .size_limit(ORG_PATTERN_SIZE_LIMIT)
        .dfa_size_limit(ORG_PATTERN_DFA_SIZE_LIMIT)
        .build()
    {
        Ok(re) => Some(re),
        Err(err) => {
            tracing::warn!(
                pattern_index = idx,
                error = %err,
                "org pattern rejected: failed to compile (invalid regex or size limit exceeded)"
            );
            None
        }
    }
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

    let capped = if org_patterns.len() > ORG_PATTERN_MAX_COUNT {
        tracing::warn!(
            supplied = org_patterns.len(),
            max = ORG_PATTERN_MAX_COUNT,
            "org patterns truncated: too many patterns supplied"
        );
        &org_patterns[..ORG_PATTERN_MAX_COUNT]
    } else {
        org_patterns
    };

    let text = String::from_utf8_lossy(body);
    let mut out = Vec::new();

    for (idx, pattern_str) in capped.iter().enumerate() {
        let Some(regex) = compile_org_pattern(idx, pattern_str) else {
            continue;
        };

        if regex.is_match(&text) {
            let pattern_id = idx as u32;
            out.push(SensitiveArtifact {
                kind: ArtifactKind::OrgPattern { pattern_id },
                credential_kind: None,
                commitment: Some(sha256_hex(format!("org_pattern:{pattern_id}:detect-v1"))),
                severity: ArtifactSeverity::Medium,
                location: location.clone(),
                redacted_hint: None,
            });
        }
    }

    out
}

/// Pre-compiled org-pattern regexes. Compile once per request, scan once.
pub struct CompiledOrgPatterns {
    patterns: Vec<(u32, Regex)>,
}

impl CompiledOrgPatterns {
    pub fn compile(org_patterns: &[String]) -> Self {
        let capped = if org_patterns.len() > ORG_PATTERN_MAX_COUNT {
            tracing::warn!(
                supplied = org_patterns.len(),
                max = ORG_PATTERN_MAX_COUNT,
                "org patterns truncated: too many patterns supplied"
            );
            &org_patterns[..ORG_PATTERN_MAX_COUNT]
        } else {
            org_patterns
        };

        let patterns = capped
            .iter()
            .enumerate()
            .filter_map(|(idx, pattern_str)| {
                compile_org_pattern(idx, pattern_str).map(|re| (idx as u32, re))
            })
            .collect();
        Self { patterns }
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

/// Like `org_pattern_scan` but takes pre-compiled regexes and a pre-decoded
/// `&str`. Prefer this over [`org_pattern_scan_compiled`] when you already
/// hold a UTF-8 view of the body to avoid a redundant
/// `String::from_utf8_lossy` allocation.
pub fn org_pattern_scan_compiled_str(
    text: &str,
    compiled: &CompiledOrgPatterns,
    location: ArtifactLocation,
) -> Vec<SensitiveArtifact> {
    if compiled.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();

    for (pattern_id, regex) in &compiled.patterns {
        if regex.is_match(text) {
            out.push(SensitiveArtifact {
                kind: ArtifactKind::OrgPattern {
                    pattern_id: *pattern_id,
                },
                credential_kind: None,
                commitment: Some(sha256_hex(format!("org_pattern:{pattern_id}:detect-v1"))),
                severity: ArtifactSeverity::Medium,
                location: location.clone(),
                redacted_hint: None,
            });
        }
    }

    out
}

/// Like `org_pattern_scan` but takes pre-compiled regexes. Decodes `body`
/// as UTF-8 (lossy) then delegates to [`org_pattern_scan_compiled_str`].
/// When the caller already has a `&str` view of the same bytes, use
/// [`org_pattern_scan_compiled_str`] directly to skip the extra allocation.
pub fn org_pattern_scan_compiled(
    body: &[u8],
    compiled: &CompiledOrgPatterns,
    location: ArtifactLocation,
) -> Vec<SensitiveArtifact> {
    if compiled.is_empty() {
        return Vec::new();
    }

    let text = String::from_utf8_lossy(body);
    org_pattern_scan_compiled_str(&text, compiled, location)
}

fn has_auth_logic(text_lc: &str) -> bool {
    let auth_patterns = [
        "authenticate",
        "authorization",
        "bearer ",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "oauth",
        "saml",
        "oidc",
        "verify_password",
        "check_password",
        "login(",
        "logout(",
        "session.set",
        "session.get",
        "is_authenticated",
        "require_auth",
        "password_hash",
        "verify_token",
        "decode_jwt",
        "validate_token",
    ];
    auth_patterns
        .iter()
        .filter(|p| text_lc.contains(*p))
        .count()
        >= 2
}

fn has_crypto_operations(text_lc: &str) -> bool {
    let crypto_patterns = [
        "encrypt(",
        "decrypt(",
        "aes.new",
        "rsa.new",
        "cipher(",
        "decipher(",
        "hmac(",
        "sha256(",
        "sha512(",
        "md5(",
        "bcrypt.",
        "argon2.",
        "sign(",
        "verify(",
        "keypair",
        "private_key",
        "public_key",
        "crypto.create",
        "openssl",
        "nacl.",
        "sodium.",
    ];
    crypto_patterns
        .iter()
        .filter(|p| text_lc.contains(*p))
        .count()
        >= 2
}

fn scan_pattern(
    out: &mut Vec<SensitiveArtifact>,
    haystack: &str,
    regex: &Option<Regex>,
    kind: ArtifactKind,
    credential_kind: Option<&'static str>,
    severity: ArtifactSeverity,
    location: ArtifactLocation,
) {
    let Some(regex) = regex else {
        return;
    };

    for m in regex.find_iter(haystack) {
        let raw = m.as_str();
        let commitment = sha256_hex(format!(
            "{}:{}:{}",
            artifact_kind_name(&kind),
            raw,
            "detect-v1"
        ));
        out.push(SensitiveArtifact {
            kind: kind.clone(),
            credential_kind: credential_kind.map(str::to_string),
            commitment: Some(commitment),
            severity,
            location: location.clone(),
            redacted_hint: redacted_hint(raw),
        });
    }
}

fn scan_private_keys(out: &mut Vec<SensitiveArtifact>, haystack: &str, location: ArtifactLocation) {
    let Some(regex) = &*PRIVATE_KEY_RE else {
        return;
    };

    for m in regex.find_iter(haystack) {
        let raw = m.as_str();
        let credential_kind = private_key_credential_kind(raw);
        let commitment = sha256_hex(format!("private_key:{raw}:detect-v1"));
        out.push(SensitiveArtifact {
            kind: ArtifactKind::PrivateKey,
            credential_kind: Some(credential_kind.to_string()),
            commitment: Some(commitment),
            severity: ArtifactSeverity::Critical,
            location: location.clone(),
            redacted_hint: redacted_hint(raw),
        });
    }
}

fn private_key_credential_kind(raw: &str) -> &'static str {
    if raw.contains("RSA ") {
        "rsa_private_key"
    } else if raw.contains("EC ") {
        "ec_private_key"
    } else if raw.contains("OPENSSH ") {
        "openssh_private_key"
    } else {
        "generic_private_key"
    }
}

fn scan_connection_strings(
    out: &mut Vec<SensitiveArtifact>,
    haystack: &str,
    location: ArtifactLocation,
) {
    let Some(regex) = &*CONNECTION_STRING_RE else {
        return;
    };

    for m in regex.find_iter(haystack) {
        let raw = m.as_str();
        let credential_kind = connection_string_credential_kind(raw);
        let commitment = sha256_hex(format!("connection_string:{raw}:detect-v1"));
        out.push(SensitiveArtifact {
            kind: ArtifactKind::ConnectionString,
            credential_kind: Some(credential_kind.to_string()),
            commitment: Some(commitment),
            severity: ArtifactSeverity::High,
            location: location.clone(),
            redacted_hint: redacted_hint(raw),
        });
    }
}

fn connection_string_credential_kind(raw: &str) -> &'static str {
    match raw
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .as_deref()
    {
        Some("postgres") => "postgres_connection_string",
        Some("mysql") => "mysql_connection_string",
        Some("mongodb") => "mongodb_connection_string",
        Some("redis") => "redis_connection_string",
        Some("amqp") => "amqp_connection_string",
        _ => "connection_string",
    }
}

fn scan_hex_keys(out: &mut Vec<SensitiveArtifact>, haystack: &str, location: ArtifactLocation) {
    let Some(regex) = &*HEX_KEY_RE else { return };

    for m in regex.find_iter(haystack) {
        let raw = m.as_str();

        if raw.len() == 32 && looks_like_uuid_hex(raw) {
            continue;
        }

        if raw.len() == 40
            && raw
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        {
            continue;
        }

        let mixed_case =
            raw.chars().any(|c| c.is_uppercase()) && raw.chars().any(|c| c.is_lowercase());
        if mixed_case || raw.len() >= 48 {
            let commitment = sha256_hex(format!("hex_key:{raw}:detect-v1"));
            out.push(SensitiveArtifact {
                kind: ArtifactKind::HexKey,
                credential_kind: Some("hex_secret".to_string()),
                commitment: Some(commitment),
                severity: ArtifactSeverity::Medium,
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

fn artifact_kind_name(kind: &ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::ApiKey {
            provider: Some(DetectedProvider::OpenAi),
        } => "openai_key",
        ArtifactKind::ApiKey {
            provider: Some(DetectedProvider::Anthropic),
        } => "anthropic_key",
        ArtifactKind::ApiKey { .. } => "api_key",
        ArtifactKind::AwsAccessKey => "aws_access_key",
        ArtifactKind::GitHubPat => "github_pat",
        ArtifactKind::GitLabToken => "gitlab_token",
        ArtifactKind::SlackToken => "slack_token",
        ArtifactKind::StripeSecretKey => "stripe_secret_key",
        ArtifactKind::Jwt => "jwt",
        ArtifactKind::HexKey => "hex_key",
        ArtifactKind::PrivateKey => "private_key",
        ArtifactKind::ConnectionString => "connection_string",
        ArtifactKind::CodeBlock { .. } => "code_block",
        ArtifactKind::UnknownCredential => "unknown_credential",
        ArtifactKind::AuthLogic => "auth_logic",
        ArtifactKind::CryptoOperation => "crypto_operation",
        ArtifactKind::OrgPattern { .. } => "org_pattern",
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
        assert!(artifacts.iter().any(|a| matches!(
            &a.kind,
            ArtifactKind::ApiKey {
                provider: Some(DetectedProvider::OpenAi)
            }
        )));
        assert!(artifacts.iter().any(|a| matches!(
            &a.kind,
            ArtifactKind::ApiKey {
                provider: Some(DetectedProvider::Anthropic)
            }
        )));
        assert!(artifacts
            .iter()
            .any(|a| matches!(a.kind, ArtifactKind::AwsAccessKey)));
        assert!(artifacts
            .iter()
            .any(|a| matches!(a.kind, ArtifactKind::GitHubPat)));
        assert!(artifacts
            .iter()
            .any(|a| matches!(a.kind, ArtifactKind::GitLabToken)));
        assert!(artifacts
            .iter()
            .any(|a| matches!(a.kind, ArtifactKind::Jwt)));
        assert!(artifacts
            .iter()
            .any(|a| matches!(a.kind, ArtifactKind::ConnectionString)));
        assert!(artifacts
            .iter()
            .any(|a| matches!(a.kind, ArtifactKind::PrivateKey)));

        let credential_kinds: Vec<&str> = artifacts
            .iter()
            .filter_map(|artifact| artifact.credential_kind.as_deref())
            .collect();
        assert!(credential_kinds.contains(&"openai_api_key"));
        assert!(credential_kinds.contains(&"anthropic_api_key"));
        assert!(credential_kinds.contains(&"aws_access_key_id"));
        assert!(credential_kinds.contains(&"github_pat"));
        assert!(credential_kinds.contains(&"gitlab_token"));
        assert!(credential_kinds.contains(&"jwt"));
        assert!(credential_kinds.contains(&"postgres_connection_string"));
        assert!(credential_kinds.contains(&"generic_private_key"));
    }

    #[test]
    fn credential_scan_detects_slack_token() {
        let body = b"token=xoxb-1234567890-abcdef";
        let artifacts = credential_scan(body, ArtifactLocation::Unknown);
        assert!(artifacts
            .iter()
            .any(|a| matches!(a.kind, ArtifactKind::SlackToken)));
    }

    #[test]
    fn credential_scan_detects_stripe_keys() {
        let body = b"live=sk_live_abcdefghijklmnop test=sk_test_abcdefghijklmnop";
        let artifacts = credential_scan(body, ArtifactLocation::Unknown);
        assert!(artifacts
            .iter()
            .any(|a| matches!(a.kind, ArtifactKind::StripeSecretKey)));
        let credential_kinds: Vec<&str> = artifacts
            .iter()
            .filter_map(|artifact| artifact.credential_kind.as_deref())
            .collect();
        assert!(credential_kinds.contains(&"stripe_live_secret_key"));
        assert!(credential_kinds.contains(&"stripe_test_secret_key"));
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
        assert!(artifacts
            .iter()
            .any(|a| matches!(a.kind, ArtifactKind::AuthLogic)));
    }

    #[test]
    fn structural_scan_detects_crypto_operations() {
        let body = b"let cipher = encrypt(data); let hash = sha256(input);";
        let artifacts = structural_scan(body, ArtifactLocation::Unknown);
        assert!(artifacts
            .iter()
            .any(|a| matches!(a.kind, ArtifactKind::CryptoOperation)));
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
        assert!(matches!(
            artifacts[0].kind,
            ArtifactKind::OrgPattern { pattern_id: 0 }
        ));
        assert!(artifacts[0].redacted_hint.is_none());
    }

    #[test]
    fn org_pattern_scan_skips_invalid_regex() {
        let body = b"test data";
        let patterns = vec!["[invalid".to_string(), r"\btest\b".to_string()];
        let artifacts = org_pattern_scan(body, &patterns, ArtifactLocation::Unknown);
        assert_eq!(artifacts.len(), 1);
        assert!(matches!(
            artifacts[0].kind,
            ArtifactKind::OrgPattern { pattern_id: 1 }
        ));
    }

    #[test]
    fn org_pattern_scan_empty_patterns_returns_empty() {
        let body = b"test data";
        let artifacts = org_pattern_scan(body, &[], ArtifactLocation::Unknown);
        assert!(artifacts.is_empty());
    }
}
