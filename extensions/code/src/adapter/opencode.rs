//! OpenCode adapter.
//!
//! OpenCode's hook protocol uses snake_case event names (`hook_type`
//! field, matching our internal canonical form), `tool` instead of
//! `tool_name`, `args` instead of `tool_input`, `result` instead of
//! `tool_response`. OpenCode ships hooks via a JS plugin file at
//! `~/.config/opencode/plugins/`; install for the JS-plugin surface
//! is deferred to a follow-up — the parser ships now so manually-
//! configured hooks work end-to-end.

use serde_json::Value;
use soth_classify::HookContentKind;

use crate::decision::{AdapterResponse, HookDecision};
use crate::event::{ActionType, CodeEvent, HookContentExtract};

use super::{Adapter, ParseError};

const NAME: &str = "opencode";

pub struct OpenCodeAdapter;

impl OpenCodeAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for OpenCodeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Adapter for OpenCodeAdapter {
    fn name(&self) -> &'static str {
        NAME
    }

    fn ua_patterns(&self) -> &'static [&'static str] {
        &["opencode/*", "OpenCode/*"]
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
        // OpenCode's JS plugin can attach `model` / `ctx.model` to
        // the stdin payload — wire it through when present.
        let model = payload
            .get("model")
            .and_then(Value::as_str)
            .or_else(|| payload.pointer("/ctx/model").and_then(Value::as_str))
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let mut event = CodeEvent::new(NAME, hook_type, action, session, payload);
        event.model = model;
        Ok(event)
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
        // `tool_execute_before` is the only enforceable surface
        // OpenCode's plugin API actually exposes. The pre-LLM prompt
        // submit + `session_idle_before` hooks don't exist in the
        // upstream plugin contract (only `tool.execute.before/after`,
        // `chat.message` — which is post-action — and the four
        // `session.*` events), so claiming we could block them would
        // be a false promise that silently fails when the policy
        // gate fires. Re-add either entry only if OpenCode's plugin
        // SDK gains a synchronous pre-prompt hook upstream.
        matches!(hook_type, "tool_execute_before")
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
            "tool_execute_before" => {
                let tool = event
                    .payload
                    .get("tool")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                // OpenCode uses `args` (not `tool_input`).
                let args = event.payload.get("args").cloned().unwrap_or(Value::Null);
                Some(HookContentExtract {
                    kind: HookContentKind::ToolArgs,
                    content: format!("{tool}\n{}", serde_json::to_string(&args).ok()?),
                })
            }
            "tool_execute_after" => {
                // OpenCode uses `result` (not `tool_response`).
                let r = event.payload.get("result").cloned().unwrap_or(Value::Null);
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
        "tool_execute_before" | "tool_execute_after" => {
            let tool = payload.get("tool").and_then(Value::as_str).unwrap_or("");
            tool_to_action(tool)
        }
        "user_prompt_submit" => ActionType::UserPromptSubmit,
        "session_created" | "session_idle_before" => ActionType::SessionStart,
        "session_idle" => ActionType::Notification,
        "session_error" | "session_end" => ActionType::SessionEnd,
        _ => ActionType::Notification,
    }
}

fn tool_to_action(tool_name: &str) -> ActionType {
    match tool_name {
        "read" | "Read" => ActionType::FileRead,
        "edit" | "write" | "Edit" | "Write" => ActionType::FileWrite,
        "bash" | "Bash" | "shell" => ActionType::CommandExec,
        _ => ActionType::ToolUse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_field_used_not_tool_name() {
        let a = OpenCodeAdapter::new();
        let p = br#"{"session_id":"s","tool":"bash","args":{"command":"ls"}}"#;
        let ev = a.parse_event("tool_execute_before", p).unwrap();
        assert_eq!(ev.action_type, ActionType::CommandExec);
        // OpenCode's payload uses `args`, not `tool_input`.
        assert_eq!(ev.payload["args"]["command"], "ls");
    }

    #[test]
    fn session_lifecycle_events_recognized() {
        let a = OpenCodeAdapter::new();
        for (h, expected) in [
            ("session_created", ActionType::SessionStart),
            ("session_error", ActionType::SessionEnd),
            ("session_idle", ActionType::Notification),
        ] {
            let ev = a.parse_event(h, br#"{"session_id":"s"}"#).unwrap();
            assert_eq!(ev.action_type, expected, "hook {h}");
        }
    }

    #[test]
    fn pre_action_hooks() {
        let a = OpenCodeAdapter::new();
        assert!(a.is_pre_action_hook("tool_execute_before"));
        assert!(!a.is_pre_action_hook("tool_execute_after"));
        assert!(!a.is_pre_action_hook("session_idle"));
        // Regression guard: these were previously advertised as
        // enforceable but OpenCode's plugin API never exposes them,
        // so the policy gate would silently fail to block. Keep them
        // false until upstream adds a pre-prompt hook.
        assert!(
            !a.is_pre_action_hook("user_prompt_submit"),
            "OpenCode plugin API has no pre-prompt hook"
        );
        assert!(
            !a.is_pre_action_hook("session_idle_before"),
            "OpenCode plugin API has no session_idle_before"
        );
    }
}
