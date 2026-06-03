//! Stub adapter for Group 3 smoke E2E.
//!
//! Accepts any agent name, parses stdin as generic JSON, maps hook_type
//! strings to a coarse `ActionType`, and returns `AdapterResponse::allow`
//! for any decision. **Not** a usable adapter for production traffic —
//! it does no redaction and no per-agent decision rendering.
//!
//! The stub exists only to prove the hook plumbing end-to-end before
//! the real Claude Code adapter (Group 4) lands. CLI flag
//! `--allow-stub-adapter` gates its use; `soth code hook` refuses to
//! run with the stub by default once a real adapter is registered for
//! the named agent.

use serde_json::Value;

use crate::decision::{AdapterResponse, HookDecision};
use crate::event::{ActionType, CodeEvent};

use super::{Adapter, ParseError};

pub struct StubAdapter {
    /// Whatever name the caller asked for. Smoke tests pass
    /// `"claude_code"` so the queue file gets a realistic agent tag.
    agent_name: String,
}

impl StubAdapter {
    pub fn new(agent_name: String) -> Self {
        Self { agent_name }
    }

    fn coerce_action_type(hook_type: &str) -> ActionType {
        // Coarse mapping shared by most hook conventions. Real
        // adapters refine this per-agent.
        match hook_type {
            "pre_tool_use" | "post_tool_use" | "tool_use" => ActionType::ToolUse,
            "user_prompt_submit" => ActionType::UserPromptSubmit,
            "stop" => ActionType::Stop,
            "session_start" => ActionType::SessionStart,
            "session_end" => ActionType::SessionEnd,
            "subagent_start" => ActionType::SubagentStart,
            "subagent_stop" => ActionType::SubagentStop,
            "notification" => ActionType::Notification,
            "file_read" => ActionType::FileRead,
            "file_write" => ActionType::FileWrite,
            "file_delete" => ActionType::FileDelete,
            "command_exec" => ActionType::CommandExec,
            // Unknown hook types collapse to Notification rather than
            // erroring — the stub is permissive by design so the smoke
            // E2E doesn't bisect on hook-name fastidiousness. Real
            // adapters return Err(UnknownHookType).
            _ => ActionType::Notification,
        }
    }

    fn extract_session_id(payload: &Value) -> String {
        // Best-effort lookup of common keys — agent payloads tend to
        // use one of these. Not authoritative; the real adapter knows.
        for key in ["session_id", "sessionId", "agent_session_id"] {
            if let Some(s) = payload.get(key).and_then(|v| v.as_str()) {
                return s.to_string();
            }
        }
        String::new()
    }
}

impl Adapter for StubAdapter {
    fn name(&self) -> &'static str {
        // Stub doesn't have a static name — it adopts the caller's. We
        // expose a placeholder here; the actual agent name is in the
        // event's `agent` field (set via parse_event).
        "stub"
    }

    fn ua_patterns(&self) -> &'static [&'static str] {
        // No UA matching — stub is invoked manually from the CLI.
        &[]
    }

    fn parse_event(&self, hook_type: &str, stdin: &[u8]) -> Result<CodeEvent, ParseError> {
        let payload: Value = if stdin.is_empty() {
            Value::Object(serde_json::Map::new())
        } else {
            serde_json::from_slice(stdin)?
        };
        let action_type = Self::coerce_action_type(hook_type);
        let session_id = Self::extract_session_id(&payload);
        Ok(CodeEvent::new(
            self.agent_name.clone(),
            hook_type.to_string(),
            action_type,
            session_id,
            payload,
        ))
    }

    fn render_decision(&self, decision: &HookDecision) -> AdapterResponse {
        // Stub: every decision lowers to Allow with empty IO. Group 4
        // / Group 5 wire real per-agent decision rendering.
        match decision {
            HookDecision::Allow => AdapterResponse::allow(),
            HookDecision::Block { .. } | HookDecision::Error(_) => AdapterResponse::allow(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_empty_stdin_as_empty_object() {
        let a = StubAdapter::new("claude_code".to_string());
        let ev = a.parse_event("pre_tool_use", b"").expect("empty parses");
        assert_eq!(ev.agent, "claude_code");
        assert_eq!(ev.hook_type, "pre_tool_use");
        assert_eq!(ev.action_type, ActionType::ToolUse);
        assert!(ev.payload.is_object());
    }

    #[test]
    fn parses_minimal_json_object() {
        let a = StubAdapter::new("claude_code".to_string());
        let ev = a
            .parse_event("user_prompt_submit", br#"{"prompt":"hi"}"#)
            .expect("valid json parses");
        assert_eq!(ev.action_type, ActionType::UserPromptSubmit);
        assert_eq!(ev.payload["prompt"], "hi");
    }

    #[test]
    fn extracts_session_id_when_present() {
        let a = StubAdapter::new("claude_code".to_string());
        let ev = a
            .parse_event("pre_tool_use", br#"{"session_id":"sess-123"}"#)
            .expect("parses");
        assert_eq!(ev.agent_native_session_id, "sess-123");
        assert!(!ev.correlation_key.is_empty());
    }

    #[test]
    fn malformed_json_errors() {
        let a = StubAdapter::new("claude_code".to_string());
        let r = a.parse_event("pre_tool_use", b"{ not json");
        assert!(matches!(r, Err(ParseError::InvalidJson(_))));
    }

    #[test]
    fn unknown_hook_type_collapses_to_notification() {
        // The stub is permissive — strict adapters produce UX that
        // bisects on hook-name typos. Stub avoids that for the smoke E2E.
        let a = StubAdapter::new("claude_code".to_string());
        let ev = a.parse_event("totally_made_up", b"{}").expect("permissive");
        assert_eq!(ev.action_type, ActionType::Notification);
    }
}
