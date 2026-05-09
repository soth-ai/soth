//! Pi Agent adapter.
//!
//! Pi Agent uses Anthropic-conventional hook payloads but with a
//! flatter shape than Claude Code: tool args under `input`
//! (not `tool_input`), `tool_call_id` instead of `tool_use_id`. Pre-
//! action hooks block via exit-2 + stderr reason (gryph PR #22). Pi
//! Agent ships its hook configuration via a TS plugin file
//! (`~/.config/piagent/plugins/`); install for that surface is
//! deferred to a follow-up Phase-3 commit — the parser ships now so
//! manually-configured hooks work end-to-end.

use serde_json::Value;
use soth_classify::HookContentKind;

use crate::decision::{AdapterResponse, HookDecision};
use crate::event::{ActionType, CodeEvent, HookContentExtract};

use super::{Adapter, ParseError};

const NAME: &str = "pi_agent";

pub struct PiAgentAdapter;

impl PiAgentAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PiAgentAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Adapter for PiAgentAdapter {
    fn name(&self) -> &'static str {
        NAME
    }

    fn ua_patterns(&self) -> &'static [&'static str] {
        &["pi-agent/*", "piagent/*"]
    }

    fn parse_event(&self, hook_type: &str, stdin: &[u8]) -> Result<CodeEvent, ParseError> {
        let payload: Value = if stdin.is_empty() {
            Value::Object(serde_json::Map::new())
        } else {
            serde_json::from_slice(stdin)?
        };
        let action = action_type_for(hook_type, &payload);
        let session = payload
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        // Pi Agent's plugin can include `model` / `ctx.model` /
        // `agent_model` on the hook payload (varies by version).
        // Best-effort lookup so cloud rows show the model when
        // the plugin provides it; None otherwise.
        let model = ["model", "agent_model"]
            .iter()
            .find_map(|k| payload.get(*k).and_then(Value::as_str))
            .or_else(|| payload.pointer("/ctx/model").and_then(Value::as_str))
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let mut event = CodeEvent::new(NAME, hook_type, action, session, payload);
        event.model = model;
        Ok(event)
    }

    fn render_decision(&self, decision: &HookDecision) -> AdapterResponse {
        // Pi Agent contract per gryph PR #22: stderr trimmed reason +
        // exit 2 on Block. JSON-on-stdout shape isn't supported by
        // older Pi Agent versions, so we stay with the simple form.
        match decision {
            HookDecision::Allow => AdapterResponse::allow(),
            HookDecision::Block { reason, .. } => AdapterResponse {
                stdout: Vec::new(),
                stderr: reason.trim().as_bytes().to_vec(),
                exit_code: 2,
            },
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
            "pre_tool_use"
                | "user_prompt_submit"
                | "before_tool_call"
                | "subagent_start"
        )
    }

    fn classify_input(&self, event: &CodeEvent) -> Option<HookContentExtract> {
        match event.hook_type.as_str() {
            "user_prompt_submit" => {
                let p = event.payload.get("prompt").and_then(Value::as_str)?;
                Some(HookContentExtract {
                    kind: HookContentKind::PromptText,
                    content: p.to_string(),
                })
            }
            "pre_tool_use" | "before_tool_call" => {
                let tool = event
                    .payload
                    .get("tool_name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                // Pi Agent uses `input` (not `tool_input`).
                let input = event.payload.get("input").cloned().unwrap_or(Value::Null);
                let body = serde_json::to_string(&input).ok()?;
                Some(HookContentExtract {
                    kind: HookContentKind::ToolArgs,
                    content: format!("{tool}\n{body}"),
                })
            }
            "post_tool_use" | "after_tool_call" => {
                let r = event.payload.get("output").cloned().unwrap_or(Value::Null);
                let body = serde_json::to_string(&r).ok()?;
                if body == "null" || body.is_empty() {
                    return None;
                }
                Some(HookContentExtract {
                    kind: HookContentKind::ToolResult,
                    content: body,
                })
            }
            _ => None,
        }
    }
}

fn action_type_for(hook_type: &str, payload: &Value) -> ActionType {
    match hook_type {
        "pre_tool_use" | "post_tool_use" | "before_tool_call" | "after_tool_call" => {
            let tool = payload
                .get("tool_name")
                .and_then(Value::as_str)
                .unwrap_or("");
            tool_to_action(tool)
        }
        "user_prompt_submit" => ActionType::UserPromptSubmit,
        "stop" => ActionType::Stop,
        "session_start" => ActionType::SessionStart,
        "session_shutdown" | "session_end" => ActionType::SessionEnd,
        "subagent_start" => ActionType::SubagentStart,
        "subagent_stop" => ActionType::SubagentStop,
        _ => ActionType::Notification,
    }
}

fn tool_to_action(tool_name: &str) -> ActionType {
    match tool_name {
        "read" | "Read" => ActionType::FileRead,
        "edit" | "write" | "Edit" | "Write" => ActionType::FileWrite,
        "bash" | "Bash" | "shell" => ActionType::CommandExec,
        "task" | "Task" => ActionType::SubagentStart,
        _ => ActionType::ToolUse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pi_agent_uses_input_not_tool_input() {
        let a = PiAgentAdapter::new();
        let p = br#"{"session_id":"s","tool_name":"bash","input":{"command":"ls"}}"#;
        let ev = a.parse_event("pre_tool_use", p).unwrap();
        assert_eq!(ev.action_type, ActionType::CommandExec);
        // Field is `input` (Pi Agent convention), not `tool_input`.
        assert_eq!(ev.payload["input"]["command"], "ls");
    }

    #[test]
    fn render_block_uses_stderr_only_no_stdout_json() {
        let a = PiAgentAdapter::new();
        let r = a.render_decision(&HookDecision::Block {
            reason: "denied".into(),
            guidance: None,
        });
        assert_eq!(r.exit_code, 2);
        assert!(r.stdout.is_empty(), "Pi Agent uses stderr, not stdout JSON");
        assert_eq!(r.stderr, b"denied");
    }

    #[test]
    fn pre_action_hooks() {
        let a = PiAgentAdapter::new();
        assert!(a.is_pre_action_hook("pre_tool_use"));
        assert!(a.is_pre_action_hook("user_prompt_submit"));
        assert!(!a.is_pre_action_hook("post_tool_use"));
        assert!(!a.is_pre_action_hook("session_shutdown"));
    }
}
