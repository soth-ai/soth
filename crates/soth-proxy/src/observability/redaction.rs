//! Redaction policy applied before spans/events leave the process.
//!
//! Two layers of defense:
//!
//! 1. **Field-name deny list**: any tracing field whose name (case-insensitive)
//!    matches `is_sensitive_field_name` has its value replaced with
//!    `[REDACTED]` regardless of content.
//!
//! 2. **Value-prefix patterns**: any string value starting with a known
//!    secret-token shape (Bearer, sk-, soth_live_, AWS access keys, …) is
//!    replaced with `[REDACTED]` regardless of which field carried it.
//!
//! Both layers are pure, table-driven, and exhaustively unit tested. The
//! tracing-opentelemetry SpanProcessor (`super::honeycomb::RedactingProcessor`)
//! and the Sentry `before_send` hook (`super::sentry::scrub_event`) call into
//! these helpers to apply the same policy on every export path.

/// Field names whose values are always redacted (case-insensitive substring
/// match). The list is conservative: false positives just blank a debugging
/// breadcrumb, false negatives leak customer data, so we err on the side of
/// scrubbing aggressively.
const FIELD_NAME_DENY: &[&str] = &[
    // Auth / credentials
    "authorization",
    "auth_token",
    "api_key",
    "apikey",
    "api-key",
    "x-api-key",
    "secret",
    "client_secret",
    "bearer",
    "password",
    "passwd",
    "session",
    "cookie",
    "token",
    "otp",
    "mfa",
    "private_key",
    "privatekey",
    // SOTH-specific token shapes
    "owner_token",
    "enroll_token",
    "enrollment_token",
    "refresh_token",
    // Per-request payload that may carry prompts / tool args / responses
    "prompt",
    "messages",
    "content",
    "request_body",
    "response_body",
    "raw_body",
    "body_bytes",
    "tool_args",
    "tool_arguments",
    "tool_result",
];

/// Value-prefix patterns. If a field's value (case-sensitive — these are
/// well-known prefixes) starts with one of these, the whole value is
/// scrubbed. Use `starts_with`, not `contains`, to keep this fast and
/// false-positive-free for log lines that happen to mention the pattern.
const VALUE_PREFIX_DENY: &[&str] = &[
    "Bearer ",
    "Basic ",
    "sk-",        // OpenAI
    "sk_live_",   // Stripe live
    "sk_test_",   // Stripe test
    "rk_live_",   // Stripe restricted
    "soth_live_", // SOTH
    "soth_test_",
    "ant-",        // Anthropic
    "AKIA",        // AWS access key id
    "ASIA",        // AWS temporary access key
    "ghp_",        // GitHub personal access token
    "gho_",        // GitHub OAuth
    "ghu_",        // GitHub user-to-server
    "ghs_",        // GitHub server-to-server
    "ghr_",        // GitHub refresh
    "github_pat_", // GitHub fine-grained PAT
    "xoxb-",       // Slack bot
    "xoxp-",       // Slack user
    "xoxa-",       // Slack app
    "xoxs-",       // Slack legacy
    "ya29.",       // Google OAuth
    "AIza",        // Google API
];

pub const REDACTED: &str = "[REDACTED]";

/// Returns `true` if a tracing field name is on the deny list. Match is
/// case-insensitive **substring** so callers don't have to worry about
/// `Authorization`/`authorization`/`AUTHORIZATION` or compound names like
/// `request_authorization_header`.
pub fn is_sensitive_field_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    FIELD_NAME_DENY.iter().any(|deny| lower.contains(deny))
}

/// Returns `true` if a string value starts with a known secret-token prefix.
pub fn looks_like_secret_value(value: &str) -> bool {
    let trimmed = value.trim_start();
    VALUE_PREFIX_DENY
        .iter()
        .any(|prefix| trimmed.starts_with(prefix))
}

/// Apply both layers and return a redacted view of the value.
///
/// - If the field name is on the deny list, returns `[REDACTED]` regardless
///   of what the value contained.
/// - Otherwise, if the value matches a known secret-token prefix, returns
///   `[REDACTED]`.
/// - Otherwise, returns the original value unchanged.
pub fn redact<'a>(field_name: &'a str, value: &'a str) -> std::borrow::Cow<'a, str> {
    if is_sensitive_field_name(field_name) || looks_like_secret_value(value) {
        std::borrow::Cow::Borrowed(REDACTED)
    } else {
        std::borrow::Cow::Borrowed(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_name_deny_is_case_insensitive() {
        assert!(is_sensitive_field_name("Authorization"));
        assert!(is_sensitive_field_name("AUTHORIZATION"));
        assert!(is_sensitive_field_name("authorization"));
    }

    #[test]
    fn field_name_deny_matches_substrings() {
        // compound names should still be caught
        assert!(is_sensitive_field_name("request_authorization_header"));
        assert!(is_sensitive_field_name("user.api_key"));
        assert!(is_sensitive_field_name("X-API-Key"));
        assert!(is_sensitive_field_name("client_secret"));
    }

    #[test]
    fn field_name_deny_covers_llm_payload() {
        // Prompts and bodies are the highest-risk leak vector.
        assert!(is_sensitive_field_name("prompt"));
        assert!(is_sensitive_field_name("messages"));
        assert!(is_sensitive_field_name("response_body"));
        assert!(is_sensitive_field_name("tool_arguments"));
    }

    #[test]
    fn field_name_deny_does_not_match_unrelated_names() {
        assert!(!is_sensitive_field_name("request_id"));
        assert!(!is_sensitive_field_name("agent_id"));
        assert!(!is_sensitive_field_name("status_code"));
        assert!(!is_sensitive_field_name("latency_ms"));
        assert!(!is_sensitive_field_name("host"));
        assert!(!is_sensitive_field_name("method"));
    }

    #[test]
    fn value_prefix_catches_common_token_shapes() {
        assert!(looks_like_secret_value(
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        ));
        assert!(looks_like_secret_value("sk-proj-abc123"));
        assert!(looks_like_secret_value("soth_live_default0_abc123"));
        assert!(looks_like_secret_value(
            "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
        ));
        assert!(looks_like_secret_value("AKIAIOSFODNN7EXAMPLE"));
        assert!(looks_like_secret_value("AIzaSyD-1234567890abcdef"));
        assert!(looks_like_secret_value("xoxb-1234-abcdef"));
    }

    #[test]
    fn value_prefix_does_not_match_innocent_strings() {
        assert!(!looks_like_secret_value(""));
        assert!(!looks_like_secret_value("https://api.openai.com"));
        assert!(!looks_like_secret_value("agent-instance-1234"));
        assert!(!looks_like_secret_value("device-abc-def"));
        // "skip-" doesn't match "sk-" because of the trailing chars, but…
        // a string that just happens to start with "sk-" *will* match.
        // That's an acceptable false-positive trade-off — we err on scrubbing.
        assert!(looks_like_secret_value("sk-something"));
    }

    #[test]
    fn redact_blanks_value_when_field_name_matches() {
        let out = redact("Authorization", "Bearer xyz");
        assert_eq!(out, REDACTED);
    }

    #[test]
    fn redact_blanks_value_when_value_pattern_matches() {
        // Field name is innocent but value looks like a secret.
        let out = redact("hello_world", "ghp_thisIsNotActuallyAToken");
        assert_eq!(out, REDACTED);
    }

    #[test]
    fn redact_passes_innocent_values_through() {
        let out = redact("status_code", "200");
        assert_eq!(out, "200");
        let out = redact("agent_id", "agent-instance-1234");
        assert_eq!(out, "agent-instance-1234");
    }

    #[test]
    fn redact_handles_leading_whitespace_in_value_match() {
        // We trim_start before prefix matching to catch values that arrive
        // with stray whitespace from header parsers.
        let out = redact("hint", "   Bearer abcd");
        assert_eq!(out, REDACTED);
    }
}
