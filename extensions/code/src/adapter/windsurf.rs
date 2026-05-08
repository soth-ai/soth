//! Windsurf adapter (Codeium's IDE).
//!
//! Windsurf's hook protocol diverges meaningfully from the
//! Anthropic-style convention shared by Claude Code / Cursor /
//! Codex: it uses `agent_action_name` instead of `hook_event_name`,
//! `trajectory_id`/`execution_id` for session/turn correlation
//! (no `session_id` field on the wire), and dedicated hook events
//! (`pre_read_code`, `post_write_code`, `pre_mcp_tool_use`,
//! `post_cascade_response`). `tool_info` arrives as `json.RawMessage`
//! upstream — defensively parsed as `serde_json::Value`.

use serde_json::Value;
use soth_classify::HookContentKind;

use crate::decision::{AdapterResponse, HookDecision};
use crate::event::{ActionType, CodeEvent, HookContentExtract};

use super::{Adapter, ParseError};

const NAME: &str = "windsurf";

pub struct WindsurfAdapter;

impl WindsurfAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindsurfAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Adapter for WindsurfAdapter {
    fn name(&self) -> &'static str {
        NAME
    }

    fn ua_patterns(&self) -> &'static [&'static str] {
        &["windsurf/*", "Windsurf/*", "codeium-windsurf/*"]
    }

    fn parse_event(&self, hook_type: &str, stdin: &[u8]) -> Result<CodeEvent, ParseError> {
        let payload: Value = if stdin.is_empty() {
            Value::Object(serde_json::Map::new())
        } else {
            serde_json::from_slice(stdin)?
        };
        let action = action_type_for(hook_type);
        // Windsurf has no `session_id`; trajectory_id is the closest
        // semantic match (tracks one user-driven coding trajectory).
        // Fall back to execution_id (per-action turn id) if absent.
        let session = payload
            .get("trajectory_id")
            .or_else(|| payload.get("execution_id"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        Ok(CodeEvent::new(NAME, hook_type, action, session, payload))
    }

    fn render_decision(&self, decision: &HookDecision) -> AdapterResponse {
        match decision {
            HookDecision::Allow => AdapterResponse::allow(),
            HookDecision::Block { reason, guidance } => {
                let mut obj = serde_json::Map::new();
                obj.insert("decision".into(), Value::String("block".into()));
                obj.insert("reason".into(), Value::String(reason.clone()));
                if let Some(g) = guidance {
                    obj.insert("guidance".into(), Value::String(g.clone()));
                }
                AdapterResponse {
                    stdout: serde_json::to_vec(&Value::Object(obj)).unwrap_or_default(),
                    stderr: reason.trim().as_bytes().to_vec(),
                    exit_code: 2,
                }
            }
            HookDecision::Error(msg) => AdapterResponse {
                stdout: Vec::new(),
                stderr: format!("[soth-code error] {msg}").into_bytes(),
                exit_code: 1,
            },
        }
    }

    fn is_pre_action_hook(&self, hook_type: &str) -> bool {
        matches!(
            hook_type,
            "pre_read_code"
                | "pre_write_code"
                | "pre_mcp_tool_use"
                | "pre_run_command"
                | "pre_cascade_request"
        )
    }

    fn classify_input(&self, event: &CodeEvent) -> Option<HookContentExtract> {
        match event.hook_type.as_str() {
            "pre_cascade_request" => {
                let p = event
                    .payload
                    .get("prompt")
                    .or_else(|| event.payload.get("user_message"))
                    .and_then(Value::as_str)?;
                Some(HookContentExtract {
                    kind: HookContentKind::PromptText,
                    content: p.to_string(),
                })
            }
            "pre_run_command" => {
                let cmd = event.payload.get("command").and_then(Value::as_str)?;
                Some(HookContentExtract {
                    kind: HookContentKind::ToolArgs,
                    content: format!("Shell\n{cmd}"),
                })
            }
            "pre_read_code" => {
                let p = event.payload.get("file_path").and_then(Value::as_str)?;
                Some(HookContentExtract {
                    kind: HookContentKind::ToolArgs,
                    content: format!("Read\n{p}"),
                })
            }
            "pre_write_code" | "post_write_code" => {
                let body = serde_json::to_string(event.payload.get("tool_info")?).ok()?;
                Some(HookContentExtract {
                    kind: HookContentKind::ToolArgs,
                    content: body,
                })
            }
            "pre_mcp_tool_use" => {
                let body = serde_json::to_string(&event.payload).ok()?;
                Some(HookContentExtract {
                    kind: HookContentKind::ToolArgs,
                    content: body,
                })
            }
            _ => None,
        }
    }
}

fn action_type_for(hook_type: &str) -> ActionType {
    match hook_type {
        "pre_read_code" | "post_read_code" => ActionType::FileRead,
        "pre_write_code" | "post_write_code" => ActionType::FileWrite,
        "pre_run_command" | "post_run_command" => ActionType::CommandExec,
        "pre_mcp_tool_use" | "post_mcp_tool_use" => ActionType::ToolUse,
        "pre_cascade_request" => ActionType::UserPromptSubmit,
        "post_cascade_response" => ActionType::Stop,
        "post_setup_worktree" => ActionType::SessionStart,
        _ => ActionType::Notification,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trajectory_id_used_as_session() {
        let a = WindsurfAdapter::new();
        let p = br#"{"agent_action_name":"pre_read_code","trajectory_id":"traj-1","execution_id":"exec-9","file_path":"/x"}"#;
        let ev = a.parse_event("pre_read_code", p).unwrap();
        assert_eq!(ev.agent_native_session_id, "traj-1");
        assert_eq!(ev.action_type, ActionType::FileRead);
    }

    #[test]
    fn execution_id_fallback_when_no_trajectory() {
        let a = WindsurfAdapter::new();
        let p = br#"{"execution_id":"exec-only"}"#;
        let ev = a.parse_event("post_setup_worktree", p).unwrap();
        assert_eq!(ev.agent_native_session_id, "exec-only");
    }

    #[test]
    fn pre_action_hooks() {
        let a = WindsurfAdapter::new();
        assert!(a.is_pre_action_hook("pre_read_code"));
        assert!(a.is_pre_action_hook("pre_run_command"));
        assert!(a.is_pre_action_hook("pre_mcp_tool_use"));
        assert!(!a.is_pre_action_hook("post_write_code"));
        assert!(!a.is_pre_action_hook("post_cascade_response"));
    }
}
