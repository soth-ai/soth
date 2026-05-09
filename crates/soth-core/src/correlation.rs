//! Cross-layer correlation key.
//!
//! SOTH observes AI agent activity at three orthogonal layers (network /
//! action / session — see `docs/gryph/plan.md` §10). Each layer emits its
//! own event records; the dashboard joins them per-session via this
//! deterministic key.
//!
//! The key is `sha256(agent_name || ":" || native_session_id)` rendered as
//! lowercase hex. Two layers observing the same agent session compute the
//! same key, so dashboard drill-down (e.g. "show me all activity for this
//! Claude Code session") is a single lookup.

use crate::crypto::sha256_hex;

/// Derive a per-session correlation key.
///
/// `agent_name` should match the convention used elsewhere
/// (`"claude_code"`, `"cursor"`, `"codex"`, …), and `native_session_id`
/// is whatever the agent considers a session identifier — historian
/// pulls it from the JSONL filename, `soth-code` reads it from the hook
/// stdin payload.
pub fn correlation_key(agent_name: &str, native_session_id: &str) -> String {
    // Concatenation rather than separate hashes so that callers in
    // historian and soth-code produce identical keys for identical inputs.
    let mut buf = String::with_capacity(agent_name.len() + 1 + native_session_id.len());
    buf.push_str(agent_name);
    buf.push(':');
    buf.push_str(native_session_id);
    sha256_hex(buf.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_identical_inputs() {
        let a = correlation_key("claude_code", "session-abc-123");
        let b = correlation_key("claude_code", "session-abc-123");
        assert_eq!(a, b);
    }

    #[test]
    fn differs_when_agent_differs() {
        let a = correlation_key("claude_code", "shared-session-id");
        let b = correlation_key("cursor", "shared-session-id");
        assert_ne!(
            a, b,
            "agent name must contribute to the key — otherwise two different agents \
             with the same native session id would alias"
        );
    }

    #[test]
    fn differs_when_session_differs() {
        let a = correlation_key("claude_code", "session-aaa");
        let b = correlation_key("claude_code", "session-bbb");
        assert_ne!(a, b);
    }

    #[test]
    fn produces_64_char_lowercase_hex() {
        let k = correlation_key("claude_code", "session-1");
        assert_eq!(k.len(), 64, "sha256 hex is 64 chars");
        assert!(
            k.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "key must be lowercase hex"
        );
    }

    #[test]
    fn separator_prevents_concat_collisions() {
        // Without a separator, ("ab", "cd") and ("a", "bcd") would
        // hash identically. The ":" separator must prevent that.
        let a = correlation_key("ab", "cd");
        let b = correlation_key("a", "bcd");
        assert_ne!(
            a, b,
            "the ':' separator must disambiguate split points between agent and session id"
        );
    }
}
