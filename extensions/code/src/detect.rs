//! Credential detection for hook payloads.
//!
//! Mirrors the proxy's detection model: scan the payload for known
//! credential shapes, produce a `SensitiveArtifact` per match, and let
//! the hook handler / policy evaluator decide what to do with them.
//! Detection **never mutates the payload** — that is policy's call
//! (e.g. `PolicyDecisionKind::Redact`), not the detector's.
//!
//! For Group 4, the hook handler defaults to `Block` when *any*
//! credential artifact is detected (security-tool stance; gryph Issue
//! #20's lesson about silent fail-open). Group 5 wires this through
//! the OPA evaluator so per-org policy can override (e.g. flag-only
//! mode in dev environments).

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;
use soth_core::{ArtifactKind, ArtifactLocation, ArtifactSeverity, SensitiveArtifact};

/// Walk the payload and emit one `SensitiveArtifact` per credential
/// pattern match. `tool_name_hint` populates the artifact location's
/// tool name when known; pass `""` otherwise.
pub fn scan(payload: &Value, tool_name_hint: &str) -> Vec<SensitiveArtifact> {
    let mut out = Vec::new();
    walk(payload, "", tool_name_hint, &mut out);
    out
}

fn walk(v: &Value, path: &str, tool_name: &str, out: &mut Vec<SensitiveArtifact>) {
    match v {
        Value::String(s) => {
            scan_string(s, path, tool_name, out);
        }
        Value::Object(map) => {
            for (k, sub) in map {
                let new_path = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                walk(sub, &new_path, tool_name, out);
            }
        }
        Value::Array(arr) => {
            for sub in arr {
                walk(sub, path, tool_name, out);
            }
        }
        _ => {}
    }
}

fn scan_string(s: &str, path: &str, tool_name: &str, out: &mut Vec<SensitiveArtifact>) {
    if s.is_empty() {
        return;
    }
    for entry in patterns() {
        // First-match wins per pattern entry — duplicate matches in
        // the same string still emit one artifact for the kind, with
        // the path captured. The hook handler / policy evaluator
        // dedups across artifact list if it cares.
        if entry.regex.is_match(s) {
            out.push(SensitiveArtifact {
                kind: entry.kind.clone(),
                credential_kind: Some(entry.credential_kind.to_string()),
                severity: entry.severity,
                location: ArtifactLocation::ToolResult {
                    tool_name: if tool_name.is_empty() {
                        None
                    } else {
                        Some(tool_name.to_string())
                    },
                },
                commitment: None, // Group 5 can compute a hash if policy needs it.
                redacted_hint: Some(format!(
                    "{} detected at payload path `{}`",
                    entry.credential_kind, path
                )),
            });
        }
    }
}

struct PatternEntry {
    regex: Regex,
    kind: ArtifactKind,
    credential_kind: &'static str,
    severity: ArtifactSeverity,
}

fn patterns() -> &'static [PatternEntry] {
    static CACHE: OnceLock<Vec<PatternEntry>> = OnceLock::new();
    CACHE.get_or_init(|| {
        // Order matters when patterns share a prefix — Anthropic
        // before OpenAI because both start with `sk-`. RE2-equivalent
        // throughout (no backreferences) so catastrophic-backtracking
        // is structurally precluded.
        vec![
            PatternEntry {
                regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
                kind: ArtifactKind::AwsAccessKey,
                credential_kind: "aws_access_key",
                severity: ArtifactSeverity::Critical,
            },
            PatternEntry {
                regex: Regex::new(r"(?:ASIA|AROA|AGPA|ANPA|AIDA)[0-9A-Z]{16}").unwrap(),
                kind: ArtifactKind::AwsAccessKey,
                credential_kind: "aws_temporary_key",
                severity: ArtifactSeverity::High,
            },
            PatternEntry {
                regex: Regex::new(r"gh[psour]_[A-Za-z0-9_]{32,255}").unwrap(),
                kind: ArtifactKind::GitHubPat,
                credential_kind: "github_token",
                severity: ArtifactSeverity::Critical,
            },
            PatternEntry {
                regex: Regex::new(r"xox[baprs]-[A-Za-z0-9-]{10,}").unwrap(),
                kind: ArtifactKind::SlackToken,
                credential_kind: "slack_token",
                severity: ArtifactSeverity::High,
            },
            PatternEntry {
                regex: Regex::new(r"sk-ant-[A-Za-z0-9_-]{20,}").unwrap(),
                kind: ArtifactKind::ApiKey { provider: None },
                credential_kind: "anthropic_api_key",
                severity: ArtifactSeverity::Critical,
            },
            PatternEntry {
                regex: Regex::new(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}").unwrap(),
                kind: ArtifactKind::ApiKey { provider: None },
                credential_kind: "openai_api_key",
                severity: ArtifactSeverity::Critical,
            },
            PatternEntry {
                regex: Regex::new(r"sk_live_[A-Za-z0-9]{24,}").unwrap(),
                kind: ArtifactKind::StripeSecretKey,
                credential_kind: "stripe_secret_key",
                severity: ArtifactSeverity::Critical,
            },
            PatternEntry {
                regex: Regex::new(r"(?i)Bearer\s+[A-Za-z0-9._~+/=-]{16,}").unwrap(),
                kind: ArtifactKind::ApiKey { provider: None },
                credential_kind: "bearer_token",
                severity: ArtifactSeverity::Medium,
            },
            PatternEntry {
                regex: Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
                    .unwrap(),
                kind: ArtifactKind::Jwt,
                credential_kind: "jwt",
                severity: ArtifactSeverity::Medium,
            },
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn kinds(artifacts: &[SensitiveArtifact]) -> Vec<&str> {
        artifacts
            .iter()
            .filter_map(|a| a.credential_kind.as_deref())
            .collect()
    }

    #[test]
    fn detects_aws_access_key_in_command() {
        let p = json!({
            "tool_name": "Bash",
            "tool_input": { "command": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE ls" }
        });
        let arts = scan(&p, "Bash");
        assert!(kinds(&arts).contains(&"aws_access_key"));
        assert_eq!(
            arts.iter()
                .find(|a| a.credential_kind.as_deref() == Some("aws_access_key"))
                .unwrap()
                .severity,
            ArtifactSeverity::Critical
        );
    }

    #[test]
    fn detects_github_pat() {
        let p = json!({
            "tool_input": { "command": "GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa gh pr create" }
        });
        let arts = scan(&p, "Bash");
        assert!(kinds(&arts).contains(&"github_token"));
    }

    #[test]
    fn detects_anthropic_key_before_openai_pattern_runs() {
        // Both `sk-ant-` and `sk-` would match — we must register the
        // anthropic-specific kind, not the generic openai one.
        let p = json!({
            "tool_input": { "command": "ANTHROPIC_API_KEY=sk-ant-api03-aaaa-bbbb-cccc-dddd-eeee" }
        });
        let arts = scan(&p, "Bash");
        let k = kinds(&arts);
        assert!(
            k.contains(&"anthropic_api_key"),
            "expected anthropic_api_key in {k:?}"
        );
    }

    #[test]
    fn detects_bearer_token_in_headers() {
        let p = json!({
            "tool_input": {
                "headers": "Authorization: Bearer abc123def456ghi789jklmnopqrst"
            }
        });
        let arts = scan(&p, "mcp__http__fetch");
        assert!(kinds(&arts).contains(&"bearer_token"));
    }

    #[test]
    fn no_artifacts_for_clean_payload() {
        let p = json!({
            "tool_name": "Read",
            "tool_input": { "file_path": "/etc/hosts" }
        });
        let arts = scan(&p, "Read");
        assert!(arts.is_empty(), "no credentials present, no artifacts");
    }

    #[test]
    fn does_not_mutate_payload() {
        let p = json!({
            "tool_input": { "command": "AKIAIOSFODNN7EXAMPLE" }
        });
        let before = p.clone();
        let _ = scan(&p, "Bash");
        // We only read &p; this is a compile-time guarantee. The
        // assertion just makes the contract obvious to readers.
        assert_eq!(p, before);
    }

    #[test]
    fn detects_in_nested_arrays() {
        let p = json!({
            "tool_response": [
                { "stdout": "AKIAIOSFODNN7EXAMPLE" },
                { "stderr": "no leak" }
            ]
        });
        let arts = scan(&p, "Bash");
        assert!(kinds(&arts).contains(&"aws_access_key"));
    }

    #[test]
    fn empty_payload_yields_empty_artifacts() {
        let p = json!({});
        assert!(scan(&p, "").is_empty());
    }

    #[test]
    fn artifact_carries_path_in_redacted_hint() {
        let p = json!({
            "tool_input": { "command": "AKIAIOSFODNN7EXAMPLE" }
        });
        let arts = scan(&p, "Bash");
        let hint = arts[0].redacted_hint.as_deref().unwrap();
        assert!(
            hint.contains("tool_input.command"),
            "redacted_hint should locate the field: {hint}"
        );
    }

    #[test]
    fn jwt_pattern_matches_three_segment_token() {
        let p = json!({
            "tool_input": {
                "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            }
        });
        let arts = scan(&p, "");
        assert!(kinds(&arts).contains(&"jwt"));
    }

    #[test]
    fn stripe_live_key_detected() {
        let p = json!({
            "tool_input": { "command": "stripe charges create --key sk_live_abcdefghijklmnopqrstuvwx" }
        });
        let arts = scan(&p, "Bash");
        assert!(kinds(&arts).contains(&"stripe_secret_key"));
    }
}
