//! Cursor adapter (Anysphere's `cursor` IDE).
//!
//! Hook protocol reference: Cursor's `~/.cursor/hooks.json` config
//! lists per-event commands; each invocation receives a JSON payload
//! on stdin including a `hook_event_name` field that names the
//! firing hook (camelCase upstream — we normalize to snake_case at
//! install time so the hook subprocess accepts a uniform CLI shape
//! across agents).
//!
//! Cursor diverges from Claude Code in three relevant ways:
//!
//! 1. **23 hook event names vs Claude Code's 7.** In addition to the
//!    generic `preToolUse` / `postToolUse`, Cursor has dedicated
//!    pre-action hooks for shell execution, file reads, file edits,
//!    MCP calls, and prompt submission — each of which can return
//!    Block independently. We map the dedicated ones to specific
//!    `ActionType` variants (FileRead, CommandExec, FileWrite) since
//!    they carry richer per-event context than the generic
//!    `preToolUse`.
//! 2. **Different field names.** `conversation_id` instead of
//!    `session_id`; `tool_output` instead of `tool_response`.
//! 3. **Settings file.** `~/.cursor/hooks.json` (separate
//!    install path from Claude Code's `~/.claude/settings.json`).
//!    Handled by `crate::install::install_cursor`.
//!
//! Decision contract: same as Claude Code (stdout JSON
//! `{decision, reason, guidance}` + stderr trimmed reason +
//! exit 2 on Block), since Cursor implements the documented
//! Anthropic-style blocking-hook protocol.

use serde_json::Value;
use soth_classify::HookContentKind;

use crate::decision::{AdapterResponse, HookDecision};
use crate::event::{ActionType, CodeEvent, HookContentExtract, SubagentContext};

use super::{Adapter, ParseError};

const NAME: &str = "cursor";

pub struct CursorAdapter;

impl CursorAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CursorAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Adapter for CursorAdapter {
    fn name(&self) -> &'static str {
        NAME
    }

    fn ua_patterns(&self) -> &'static [&'static str] {
        &["cursor/*", "Cursor/*"]
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

        if let Some(sub) = extract_subagent(&payload) {
            event.subagent = Some(sub);
        }

        // Cursor carries `model` in the top-level hook payload on
        // every hook. Note: when a `subagent_start` event includes a
        // separate `subagent.model`, we treat the subagent's model
        // as the authoritative one for that branch.
        let model = event
            .payload
            .pointer("/subagent/model")
            .and_then(Value::as_str)
            .or_else(|| event.payload.get("model").and_then(Value::as_str))
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        event.model = model;

        Ok(event)
    }

    fn render_decision(&self, decision: &HookDecision) -> AdapterResponse {
        // Same Anthropic-style blocking contract as Claude Code:
        // stdout JSON for the structured shape, stderr for the
        // trimmed human-readable reason, exit 2 on Block. Cursor
        // honors the documented protocol consistently with Claude
        // Code, since both target the same Anthropic backend.
        match decision {
            HookDecision::Allow => AdapterResponse::allow(),
            HookDecision::Block { reason, guidance } => {
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
                    exit_code: 2,
                }
            }
            HookDecision::Error(msg) => {
                let stderr = format!("[soth-code error] {msg}").into_bytes();
                AdapterResponse {
                    stdout: Vec::new(),
                    stderr,
                    exit_code: 1,
                }
            }
        }
    }

    fn is_pre_action_hook(&self, hook_type: &str) -> bool {
        // Pre-action allow-list — every hook here can be installed
        // such that an exit-2 response halts the upcoming action.
        // Snake_case form because `soth code install --target cursor`
        // writes commands like `... --type before_shell_execution`,
        // normalizing Cursor's camelCase native event names into the
        // hook subprocess's uniform CLI shape.
        matches!(
            hook_type,
            "pre_tool_use"
                | "before_shell_execution"
                | "before_mcp_execution"
                | "before_read_file"
                | "before_tab_file_read"
                | "before_submit_prompt"
                | "subagent_start"
        )
    }

    fn classify_input(&self, event: &CodeEvent) -> Option<HookContentExtract> {
        match event.hook_type.as_str() {
            "before_submit_prompt" => {
                // Cursor's prompt-submit equivalent. Payload field
                // varies by version; try both.
                let prompt = event
                    .payload
                    .get("prompt")
                    .or_else(|| event.payload.get("agent_message"))
                    .and_then(Value::as_str)?;
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
                let input = event
                    .payload
                    .get("tool_input")
                    .cloned()
                    .unwrap_or(Value::Null);
                let body = serde_json::to_string(&input).ok()?;
                Some(HookContentExtract {
                    kind: HookContentKind::ToolArgs,
                    content: format!("{tool}\n{body}"),
                })
            }
            "before_shell_execution" => {
                let cmd = event.payload.get("command").and_then(Value::as_str)?;
                Some(HookContentExtract {
                    kind: HookContentKind::ToolArgs,
                    content: format!("Shell\n{cmd}"),
                })
            }
            "before_read_file" => {
                let path = event.payload.get("file_path").and_then(Value::as_str)?;
                Some(HookContentExtract {
                    kind: HookContentKind::ToolArgs,
                    content: format!("Read\n{path}"),
                })
            }
            "before_mcp_execution" => {
                // MCP tool args carry the credential leak surface.
                let body = serde_json::to_string(&event.payload).ok()?;
                Some(HookContentExtract {
                    kind: HookContentKind::ToolArgs,
                    content: body,
                })
            }
            "post_tool_use" => {
                let result = event
                    .payload
                    .get("tool_output")
                    .cloned()
                    .unwrap_or(Value::Null);
                let body = serde_json::to_string(&result).ok()?;
                if body.is_empty() || body == "null" {
                    return None;
                }
                Some(HookContentExtract {
                    kind: HookContentKind::ToolResult,
                    content: body,
                })
            }
            // Lifecycle / Tab-* / After* hooks: bookkeeping. Skip.
            _ => None,
        }
    }
}

/// Map `(hook_type, payload)` → `ActionType`. Cursor has dedicated
/// pre-action hooks for shell / file-read / file-edit; we map them to
/// specific action types since they carry stronger per-event context
/// than the generic `pre_tool_use` would.
fn action_type_for_hook(hook_type: &str, payload: &Value) -> ActionType {
    match hook_type {
        // Generic pre/post tool use — inspect tool_name to refine.
        "pre_tool_use" | "post_tool_use" | "post_tool_use_failure" => {
            let tool_name = payload
                .get("tool_name")
                .and_then(Value::as_str)
                .unwrap_or("");
            tool_to_action(tool_name)
        }
        // Dedicated pre-action hooks (Cursor-specific).
        "before_shell_execution" | "after_shell_execution" => ActionType::CommandExec,
        "before_read_file" | "before_tab_file_read" => ActionType::FileRead,
        "after_file_edit" | "after_tab_file_edit" => ActionType::FileWrite,
        "before_mcp_execution" | "after_mcp_execution" => ActionType::ToolUse,
        // Prompt / response.
        "before_submit_prompt" => ActionType::UserPromptSubmit,
        "after_agent_response" | "after_agent_thought" => ActionType::Stop,
        // Lifecycle.
        "session_start" => ActionType::SessionStart,
        "session_end" => ActionType::SessionEnd,
        "stop" => ActionType::Stop,
        "subagent_start" => ActionType::SubagentStart,
        "subagent_stop" => ActionType::SubagentStop,
        // Compaction, unknown — collapse to Notification.
        _ => ActionType::Notification,
    }
}

fn tool_to_action(tool_name: &str) -> ActionType {
    match tool_name {
        "Read" | "ReadFile" => ActionType::FileRead,
        "Write" | "Edit" | "MultiEdit" => ActionType::FileWrite,
        "Shell" | "Terminal" | "Bash" => ActionType::CommandExec,
        "Task" | "Agent" => ActionType::SubagentStart,
        _ => ActionType::ToolUse,
    }
}

fn extract_session_id(payload: &Value) -> String {
    // Cursor uses `conversation_id`. Fall back to `generation_id` if
    // conversation_id is absent (rare; some early-version payloads
    // omit it on session_start).
    payload
        .get("conversation_id")
        .or_else(|| payload.get("generation_id"))
        .or_else(|| payload.get("session_id"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn extract_subagent(payload: &Value) -> Option<SubagentContext> {
    let agent_id = payload.get("agent_id").and_then(Value::as_str)?;
    let agent_type = payload.get("agent_type").and_then(Value::as_str)?;
    Some(SubagentContext {
        subagent_id: agent_id.to_string(),
        subagent_type: agent_type.to_string(),
        parent_session_id: payload
            .get("parent_conversation_id")
            .or_else(|| payload.get("parent_session_id"))
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_tool_use_shell_maps_to_command_exec() {
        let a = CursorAdapter::new();
        let payload = br#"{
            "conversation_id": "conv-test-123",
            "hook_event_name": "preToolUse",
            "tool_name": "Shell",
            "tool_input": { "command": "npm install" }
        }"#;
        let ev = a.parse_event("pre_tool_use", payload).unwrap();
        assert_eq!(ev.agent, "cursor");
        assert_eq!(ev.action_type, ActionType::CommandExec);
        assert_eq!(ev.agent_native_session_id, "conv-test-123");
    }

    #[test]
    fn before_shell_execution_maps_to_command_exec() {
        let a = CursorAdapter::new();
        let payload = br#"{
            "conversation_id": "conv-x",
            "hook_event_name": "beforeShellExecution",
            "command": "ls -la",
            "cwd": "/tmp"
        }"#;
        let ev = a.parse_event("before_shell_execution", payload).unwrap();
        assert_eq!(ev.action_type, ActionType::CommandExec);
        assert_eq!(ev.payload["command"], "ls -la");
    }

    #[test]
    fn before_read_file_maps_to_file_read() {
        let a = CursorAdapter::new();
        let payload = br#"{
            "conversation_id": "conv-x",
            "hook_event_name": "beforeReadFile",
            "file_path": "/etc/hosts"
        }"#;
        let ev = a.parse_event("before_read_file", payload).unwrap();
        assert_eq!(ev.action_type, ActionType::FileRead);
        assert_eq!(ev.payload["file_path"], "/etc/hosts");
    }

    #[test]
    fn after_file_edit_maps_to_file_write() {
        let a = CursorAdapter::new();
        let payload = br#"{
            "conversation_id": "conv-x",
            "hook_event_name": "afterFileEdit",
            "file_path": "/tmp/x.rs",
            "edits": []
        }"#;
        let ev = a.parse_event("after_file_edit", payload).unwrap();
        assert_eq!(ev.action_type, ActionType::FileWrite);
    }

    #[test]
    fn conversation_id_used_as_session() {
        let a = CursorAdapter::new();
        let ev = a
            .parse_event(
                "pre_tool_use",
                br#"{"conversation_id":"conv-abc","tool_name":"Read","tool_input":{}}"#,
            )
            .unwrap();
        assert_eq!(ev.agent_native_session_id, "conv-abc");
        // generation_id alone (no conversation_id) is a fallback.
        let ev = a
            .parse_event("session_start", br#"{"generation_id":"gen-1"}"#)
            .unwrap();
        assert_eq!(ev.agent_native_session_id, "gen-1");
    }

    #[test]
    fn pre_action_hooks_classified_correctly() {
        let a = CursorAdapter::new();
        // Pre-action: enforceable.
        for h in [
            "pre_tool_use",
            "before_shell_execution",
            "before_mcp_execution",
            "before_read_file",
            "before_tab_file_read",
            "before_submit_prompt",
            "subagent_start",
        ] {
            assert!(a.is_pre_action_hook(h), "{h} should be pre-action");
        }
        // Post-action: not enforceable.
        for h in [
            "post_tool_use",
            "after_file_edit",
            "after_shell_execution",
            "after_agent_response",
            "stop",
            "session_end",
            "subagent_stop",
        ] {
            assert!(!a.is_pre_action_hook(h), "{h} must NOT be enforceable");
        }
    }

    #[test]
    fn render_block_uses_anthropic_style_contract() {
        let a = CursorAdapter::new();
        let r = a.render_decision(&HookDecision::Block {
            reason: "denied".into(),
            guidance: None,
        });
        assert_eq!(r.exit_code, 2);
        let stdout: serde_json::Value = serde_json::from_slice(&r.stdout).unwrap();
        assert_eq!(stdout["decision"], "block");
        assert_eq!(stdout["reason"], "denied");
        assert_eq!(r.stderr, b"denied");
    }

    #[test]
    fn classify_input_for_before_shell_execution() {
        let a = CursorAdapter::new();
        let ev = a
            .parse_event(
                "before_shell_execution",
                br#"{"conversation_id":"c","command":"npm test","cwd":"/tmp"}"#,
            )
            .unwrap();
        let extract = a.classify_input(&ev).unwrap();
        assert_eq!(extract.kind, HookContentKind::ToolArgs);
        assert!(extract.content.contains("npm test"));
    }

    #[test]
    fn unknown_hook_type_does_not_crash() {
        let a = CursorAdapter::new();
        let ev = a
            .parse_event("totally_made_up_event", br#"{"conversation_id":"c"}"#)
            .unwrap();
        assert_eq!(ev.action_type, ActionType::Notification);
    }

    #[test]
    fn extract_model_from_top_level_payload() {
        let a = CursorAdapter::new();
        let p = br#"{"conversation_id":"c1","hook_event_name":"pre_tool_use","model":"claude-4-sonnet"}"#;
        let ev = a.parse_event("pre_tool_use", p).unwrap();
        assert_eq!(ev.model.as_deref(), Some("claude-4-sonnet"));
    }

    #[test]
    fn extract_model_prefers_subagent_when_present() {
        // subagent.model is authoritative for subagent_start
        // branches. Pin that ordering.
        let a = CursorAdapter::new();
        let p = br#"{
            "conversation_id":"c1",
            "hook_event_name":"subagent_start",
            "model":"gpt-4o",
            "subagent":{"model":"claude-4-sonnet"}
        }"#;
        let ev = a.parse_event("subagent_start", p).unwrap();
        assert_eq!(ev.model.as_deref(), Some("claude-4-sonnet"));
    }
}
