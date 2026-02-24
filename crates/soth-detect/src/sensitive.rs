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

pub fn credential_scan(body: &[u8], location: ArtifactLocation) -> Vec<SensitiveArtifact> {
    let text = String::from_utf8_lossy(body);
    let mut out = Vec::new();

    scan_pattern(
        &mut out,
        &text,
        &OPENAI_KEY_RE,
        ArtifactType::OpenAIKey,
        Severity::Critical,
        location.clone(),
    );
    scan_pattern(
        &mut out,
        &text,
        &ANTHROPIC_KEY_RE,
        ArtifactType::AnthropicKey,
        Severity::Critical,
        location.clone(),
    );
    scan_pattern(
        &mut out,
        &text,
        &AWS_KEY_RE,
        ArtifactType::AwsAccessKey,
        Severity::High,
        location.clone(),
    );
    scan_pattern(
        &mut out,
        &text,
        &GITHUB_PAT_RE,
        ArtifactType::GitHubPat,
        Severity::High,
        location.clone(),
    );
    scan_pattern(
        &mut out,
        &text,
        &GITLAB_PAT_RE,
        ArtifactType::GitLabToken,
        Severity::High,
        location.clone(),
    );
    scan_pattern(
        &mut out,
        &text,
        &JWT_RE,
        ArtifactType::JwtToken,
        Severity::Medium,
        location.clone(),
    );
    scan_pattern(
        &mut out,
        &text,
        &PRIVATE_KEY_RE,
        ArtifactType::PrivateKey,
        Severity::Critical,
        location.clone(),
    );
    scan_pattern(
        &mut out,
        &text,
        &CONNECTION_STRING_RE,
        ArtifactType::ConnectionString,
        Severity::High,
        location,
    );

    out
}

pub fn redact_sensitive_bytes(input: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(input);
    redact_sensitive_text(&text).into_bytes()
}

pub fn redact_sensitive_text(input: &str) -> String {
    let mut output = input.to_string();
    output = replace_all(&output, &OPENAI_KEY_RE, "<REDACTED_OPENAI_KEY>");
    output = replace_all(&output, &ANTHROPIC_KEY_RE, "<REDACTED_ANTHROPIC_KEY>");
    output = replace_all(&output, &AWS_KEY_RE, "<REDACTED_AWS_ACCESS_KEY>");
    output = replace_all(&output, &GITHUB_PAT_RE, "<REDACTED_GITHUB_PAT>");
    output = replace_all(&output, &GITLAB_PAT_RE, "<REDACTED_GITLAB_PAT>");
    output = replace_all(&output, &JWT_RE, "<REDACTED_JWT>");
    output = replace_all(&output, &PRIVATE_KEY_RE, "<REDACTED_PRIVATE_KEY_HEADER>");
    output = replace_all(
        &output,
        &CONNECTION_STRING_RE,
        "<REDACTED_CONNECTION_STRING>",
    );
    output
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
    }
}

fn replace_all(input: &str, regex: &Option<Regex>, replacement: &str) -> String {
    let Some(regex) = regex else {
        return input.to_string();
    };
    regex.replace_all(input, replacement).to_string()
}
