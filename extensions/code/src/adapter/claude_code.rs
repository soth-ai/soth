//! Claude Code adapter (Anthropic's `claude` CLI).
//!
//! Hook protocol reference: Claude Code's stdin/stdout-based hooks
//! (PreToolUse / PostToolUse / UserPromptSubmit / Stop / SessionStart /
//! SessionEnd / Notification / SubagentStart / SubagentStop). Every
//! hook payload is one JSON object piped to stdin; the hook process
//! returns its decision via stdout JSON or exit code.
//!
//! Lessons baked in (from gryph forensics):
//! - PR #32: tool_response can be array / string / null despite docs;
//!   parse as `serde_json::Value` and never assume a shape at the
//!   adapter boundary.
//! - PR #38: subagent attribution detected by *presence* of
//!   `agent_id` / `agent_type`; hook event names alone do not
//!   distinguish main vs subagent.
//! - PR #35: Block decisions need guidance text routed via the JSON
//!   output, not just exit code 2.
//! - PR #21/#22: line-count helpers must special-case empty sides —
//!   handled in `crate::diff`.

use serde_json::Value;
use soth_classify::HookContentKind;

use crate::decision::{AdapterResponse, HookDecision};
use crate::event::{ActionType, CodeEvent, HookContentExtract, SubagentContext};

use super::{Adapter, ParseError};

const NAME: &str = "claude_code";

pub struct ClaudeCodeAdapter;

impl ClaudeCodeAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ClaudeCodeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Adapter for ClaudeCodeAdapter {
    fn name(&self) -> &'static str {
        NAME
    }

    fn ua_patterns(&self) -> &'static [&'static str] {
        &["claude-cli/*", "claude-code/*"]
    }

    fn parse_event(&self, hook_type: &str, stdin: &[u8]) -> Result<CodeEvent, ParseError> {
        let payload: Value = if stdin.is_empty() {
            Value::Object(serde_json::Map::new())
        } else {
            serde_json::from_slice(stdin)?
        };

        let action_type = action_type_for_hook(hook_type, &payload);
        let session_id = extract_session_id(&payload);
        let mut event = CodeEvent::new(NAME, hook_type, action_type, session_id, payload.clone());

        // Subagent attribution — gryph PR #38. Detected only by
        // *presence* of `agent_id`/`agent_type`, since main and subagent
        // calls reuse the same hook event names.
        if let Some(sub) = extract_subagent(&payload) {
            event.subagent = Some(sub);
        }

        Ok(event)
    }

    fn classify_input(&self, event: &CodeEvent) -> Option<HookContentExtract> {
        match event.hook_type.as_str() {
            "user_prompt_submit" => {
                let prompt = event.payload.get("prompt").and_then(Value::as_str)?;
                Some(HookContentExtract {
                    kind: HookContentKind::PromptText,
                    content: prompt.to_string(),
                })
            }
            "pre_tool_use" => {
                let tool = event
                    .payload
                    .get("tool_name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let input = event.payload.get("tool_input").cloned().unwrap_or(Value::Null);
                let body = serde_json::to_string(&input).ok()?;
                Some(HookContentExtract {
                    kind: HookContentKind::ToolArgs,
                    content: format!("{tool}\n{body}"),
                })
            }
            "post_tool_use" => {
                let result = event.payload.get("tool_response").cloned().unwrap_or(Value::Null);
                let body = serde_json::to_string(&result).ok()?;
                if body.is_empty() || body == "null" {
                    return None;
                }
                Some(HookContentExtract {
                    kind: HookContentKind::ToolResult,
                    content: body,
                })
            }
            "stop" => {
                // Some Claude Code variants pass an assistant turn here;
                // older variants don't. Best-effort extract.
                let turn = event.payload.get("assistant_message").and_then(Value::as_str)?;
                Some(HookContentExtract {
                    kind: HookContentKind::AssistantTurn,
                    content: turn.to_string(),
                })
            }
            // session_start / session_end / notification / subagent_*
            // are bookkeeping — no classifiable content.
            _ => None,
        }
    }

    fn render_decision(&self, decision: &HookDecision) -> AdapterResponse {
        match decision {
            HookDecision::Allow => AdapterResponse::allow(),
            HookDecision::Block { reason, guidance } => {
                // Claude Code's documented blocking contract: JSON on
                // stdout with `decision: "block"` plus a `reason`
                // surfaced to the model. The CLI also accepts exit
                // code 2 with a stderr message for older flows; we
                // emit both so all Claude Code versions in the wild
                // see *something* (gryph PR #35 found Anthropic
                // changed the documented shape mid-2025).
                let mut stdout_obj = serde_json::Map::new();
                stdout_obj.insert("decision".into(), Value::String("block".into()));
                stdout_obj.insert("reason".into(), Value::String(reason.clone()));
                if let Some(g) = guidance {
                    stdout_obj.insert("guidance".into(), Value::String(g.clone()));
                }
                let stdout = serde_json::to_vec(&Value::Object(stdout_obj)).unwrap_or_default();
                let stderr = reason.trim().as_bytes().to_vec();
                AdapterResponse {
                    stdout,
                    stderr,
                    exit_code: 2, // gryph PR #22 default: blocking exit
                }
            }
            HookDecision::Error(msg) => {
                // Tooling-side errors don't block (gryph Issue #20:
                // silent fail-open via async spawn was the bug to
                // avoid; failing-open *with a loud stderr line* is the
                // right answer for parser/io errors specifically).
                let stderr = format!("[soth-code error] {msg}").into_bytes();
                AdapterResponse {
                    stdout: Vec::new(),
                    stderr,
                    exit_code: 1,
                }
            }
        }
    }
}

/// Map `(hook_type, payload)` → `ActionType`. Tool-driven hooks
/// (`pre_tool_use`, `post_tool_use`) inspect `tool_name` in the payload
/// to refine; everything else is a fixed mapping by hook name.
fn action_type_for_hook(hook_type: &str, payload: &Value) -> ActionType {
    match hook_type {
        "pre_tool_use" | "post_tool_use" => {
            let tool_name = payload
                .get("tool_name")
                .and_then(Value::as_str)
                .unwrap_or("");
            tool_to_action(tool_name)
        }
        "user_prompt_submit" => ActionType::UserPromptSubmit,
        "stop" => ActionType::Stop,
        "session_start" => ActionType::SessionStart,
        "session_end" => ActionType::SessionEnd,
        "notification" => ActionType::Notification,
        "subagent_start" => ActionType::SubagentStart,
        "subagent_stop" => ActionType::SubagentStop,
        // Unknown — collapse rather than error so a future Claude Code
        // hook type doesn't crash the hook subprocess. Tracked via
        // `hook_type` field on the emitted event for observability.
        _ => ActionType::Notification,
    }
}

/// Tool name → action type. Matches gryph's `agent/claudecode/parser.go`
/// `ToolNameMapping` table (gryph PR #32 reference). Preserves the
/// canonical tool names Anthropic ships with `claude` 1.x; new tools
/// land here as we observe them.
fn tool_to_action(tool_name: &str) -> ActionType {
    match tool_name {
        "Read" | "NotebookRead" => ActionType::FileRead,
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => ActionType::FileWrite,
        "Bash" | "BashOutput" | "KillBash" | "KillShell" => ActionType::CommandExec,
        "Task" => ActionType::SubagentStart,
        "TodoWrite" | "ExitPlanMode" => ActionType::Notification,
        // MCP tool calls (e.g. `mcp__github__create_issue`). Anything
        // else (WebFetch, Glob, Grep, …) collapses to ToolUse — they're
        // tool-shaped operations without a more specific action category.
        _ => ActionType::ToolUse,
    }
}

/// `session_id` is universally present in Claude Code hook payloads.
/// Returns empty string if missing — the hook still runs end-to-end so
/// observability tags it as `correlation_key=sha256(claude_code:)`,
/// surfaced in dashboard "missing session id" alerts later.
fn extract_session_id(payload: &Value) -> String {
    payload
        .get("session_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// Subagent fields per gryph PR #38: presence of `agent_id` (UUID) and
/// `agent_type` (string identifier of the subagent class) is the
/// authoritative signal. Both must be present; one without the other
/// is treated as missing.
fn extract_subagent(payload: &Value) -> Option<SubagentContext> {
    let agent_id = payload.get("agent_id").and_then(Value::as_str)?;
    let agent_type = payload.get("agent_type").and_then(Value::as_str)?;
    Some(SubagentContext {
        subagent_id: agent_id.to_string(),
        subagent_type: agent_type.to_string(),
        parent_session_id: payload
            .get("parent_session_id")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_tool_use_read_maps_to_file_read() {
        let a = ClaudeCodeAdapter::new();
        let payload = br#"{
            "session_id": "sess-abc",
            "tool_name": "Read",
            "tool_input": { "file_path": "/etc/hosts" }
        }"#;
        let ev = a.parse_event("pre_tool_use", payload).unwrap();
        assert_eq!(ev.agent, "claude_code");
        assert_eq!(ev.hook_type, "pre_tool_use");
        assert_eq!(ev.action_type, ActionType::FileRead);
        assert_eq!(ev.agent_native_session_id, "sess-abc");
        assert_eq!(ev.payload["tool_input"]["file_path"], "/etc/hosts");
    }

    #[test]
    fn pre_tool_use_bash_maps_to_command_exec() {
        let a = ClaudeCodeAdapter::new();
        let payload = br#"{
            "session_id": "sess-xyz",
            "tool_name": "Bash",
            "tool_input": { "command": "ls -la" }
        }"#;
        let ev = a.parse_event("pre_tool_use", payload).unwrap();
        assert_eq!(ev.action_type, ActionType::CommandExec);
    }

    #[test]
    fn pre_tool_use_edit_maps_to_file_write() {
        let a = ClaudeCodeAdapter::new();
        let payload = br#"{
            "session_id": "s",
            "tool_name": "Edit",
            "tool_input": { "file_path": "/tmp/x.rs", "old_string": "a", "new_string": "b" }
        }"#;
        let ev = a.parse_event("pre_tool_use", payload).unwrap();
        assert_eq!(ev.action_type, ActionType::FileWrite);
    }

    #[test]
    fn pre_tool_use_mcp_collapses_to_tool_use() {
        let a = ClaudeCodeAdapter::new();
        let payload = br#"{
            "session_id": "s",
            "tool_name": "mcp__github__create_issue",
            "tool_input": { "title": "x" }
        }"#;
        let ev = a.parse_event("pre_tool_use", payload).unwrap();
        assert_eq!(ev.action_type, ActionType::ToolUse);
    }

    #[test]
    fn user_prompt_submit_maps_correctly() {
        let a = ClaudeCodeAdapter::new();
        let payload = br#"{ "session_id": "s", "prompt": "hello" }"#;
        let ev = a.parse_event("user_prompt_submit", payload).unwrap();
        assert_eq!(ev.action_type, ActionType::UserPromptSubmit);
    }

    #[test]
    fn task_tool_maps_to_subagent_start() {
        let a = ClaudeCodeAdapter::new();
        let payload = br#"{
            "session_id": "s",
            "tool_name": "Task",
            "tool_input": { "description": "research" }
        }"#;
        let ev = a.parse_event("pre_tool_use", payload).unwrap();
        assert_eq!(ev.action_type, ActionType::SubagentStart);
    }

    #[test]
    fn subagent_context_extracted_when_agent_id_and_type_present() {
        // gryph PR #38: subagent attribution requires *both* fields.
        let a = ClaudeCodeAdapter::new();
        let payload = br#"{
            "session_id": "sess-sub",
            "tool_name": "Read",
            "tool_input": {},
            "agent_id": "ag-uuid-1",
            "agent_type": "general-purpose"
        }"#;
        let ev = a.parse_event("pre_tool_use", payload).unwrap();
        let sub = ev.subagent.expect("subagent context populated");
        assert_eq!(sub.subagent_id, "ag-uuid-1");
        assert_eq!(sub.subagent_type, "general-purpose");
        assert!(sub.parent_session_id.is_none());
    }

    #[test]
    fn subagent_context_absent_when_only_agent_id_set() {
        // gryph PR #38: we explicitly require *both* fields. One alone
        // is treated as missing rather than fabricating a partial
        // context, since real Claude Code payloads always send the pair.
        let a = ClaudeCodeAdapter::new();
        let payload = br#"{
            "session_id": "s",
            "tool_name": "Read",
            "agent_id": "uuid-only"
        }"#;
        let ev = a.parse_event("pre_tool_use", payload).unwrap();
        assert!(ev.subagent.is_none());
    }

    #[test]
    fn subagent_context_carries_parent_session_id_when_present() {
        let a = ClaudeCodeAdapter::new();
        let payload = br#"{
            "session_id": "sub",
            "tool_name": "Read",
            "agent_id": "ag-1",
            "agent_type": "research",
            "parent_session_id": "parent-sess"
        }"#;
        let ev = a.parse_event("pre_tool_use", payload).unwrap();
        let sub = ev.subagent.unwrap();
        assert_eq!(sub.parent_session_id.as_deref(), Some("parent-sess"));
    }

    #[test]
    fn malformed_json_returns_parse_error() {
        let a = ClaudeCodeAdapter::new();
        let r = a.parse_event("pre_tool_use", b"{ not json");
        assert!(matches!(r, Err(ParseError::InvalidJson(_))));
    }

    #[test]
    fn empty_stdin_treated_as_empty_object() {
        let a = ClaudeCodeAdapter::new();
        let ev = a.parse_event("session_start", b"").unwrap();
        assert_eq!(ev.action_type, ActionType::SessionStart);
        assert!(ev.payload.is_object());
        assert_eq!(ev.agent_native_session_id, "");
    }

    #[test]
    fn unknown_hook_type_collapses_to_notification() {
        let a = ClaudeCodeAdapter::new();
        let ev = a
            .parse_event("totally_made_up_hook", br#"{"session_id":"s"}"#)
            .unwrap();
        assert_eq!(ev.action_type, ActionType::Notification);
    }

    #[test]
    fn tool_response_array_does_not_crash_parser() {
        // gryph PR #32: real MCP tool responses are sometimes arrays
        // even though docs say objects. Adapter must not crash.
        let a = ClaudeCodeAdapter::new();
        let payload = br#"{
            "session_id": "s",
            "tool_name": "mcp__weather__forecast",
            "tool_input": {},
            "tool_response": [{"day": 1}, {"day": 2}]
        }"#;
        let ev = a.parse_event("post_tool_use", payload).unwrap();
        assert_eq!(ev.action_type, ActionType::ToolUse);
        assert!(ev.payload["tool_response"].is_array());
    }

    #[test]
    fn render_allow_is_zero_exit() {
        let a = ClaudeCodeAdapter::new();
        let r = a.render_decision(&HookDecision::Allow);
        assert_eq!(r.exit_code, 0);
        assert!(r.stdout.is_empty());
    }

    #[test]
    fn render_block_emits_json_and_stderr_with_exit_two() {
        let a = ClaudeCodeAdapter::new();
        let r = a.render_decision(&HookDecision::Block {
            reason: "denied by rule X".into(),
            guidance: Some("avoid /etc paths".into()),
        });
        assert_eq!(r.exit_code, 2);
        let stdout: serde_json::Value = serde_json::from_slice(&r.stdout).unwrap();
        assert_eq!(stdout["decision"], "block");
        assert_eq!(stdout["reason"], "denied by rule X");
        assert_eq!(stdout["guidance"], "avoid /etc paths");
        assert_eq!(r.stderr, b"denied by rule X");
    }

    #[test]
    fn render_block_trims_stderr_whitespace() {
        // gryph PR #22 — trailing whitespace in block reasons looks
        // like a trailing newline / extra padding to the agent and
        // sometimes shows in the user-visible error.
        let a = ClaudeCodeAdapter::new();
        let r = a.render_decision(&HookDecision::Block {
            reason: "   denied   \n".into(),
            guidance: None,
        });
        assert_eq!(r.stderr, b"denied");
    }

    #[test]
    fn render_error_exits_one_not_two() {
        // Tooling errors must not look like a Block to Claude Code.
        let a = ClaudeCodeAdapter::new();
        let r = a.render_decision(&HookDecision::Error("parse failed".into()));
        assert_eq!(r.exit_code, 1);
        assert_ne!(r.exit_code, 2);
    }
}
