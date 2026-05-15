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
        // the stdin payload — wire it through when present. Newer
        // OpenCode versions carry `model` on the per-event `input`
        // object (chat.message / chat.params), so also probe
        // `/input/model` as a fallback before giving up.
        let model = payload
            .get("model")
            .and_then(Value::as_str)
            .or_else(|| payload.pointer("/ctx/model").and_then(Value::as_str))
            .or_else(|| payload.pointer("/input/model").and_then(Value::as_str))
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
        matches!(
            hook_type,
            "tool_execute_before" | "user_prompt_submit" | "session_idle_before"
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
            // OpenCode chat hooks: the plugin pre-extracts the user's
            // typed text into `content` (concatenating `output.parts`
            // text parts for chat.message, or `input.message.parts`
            // for chat.params). Feed that to the classifier so the
            // dashboard's use_case column gets a real ML label
            // instead of "unknown".
            "chat_message" => {
                let text = event.payload.get("content").and_then(Value::as_str)?;
                if text.is_empty() {
                    return None;
                }
                let role = event.payload.get("role").and_then(Value::as_str);
                let kind = match role {
                    Some("assistant") => HookContentKind::AssistantTurn,
                    _ => HookContentKind::PromptText,
                };
                Some(HookContentExtract {
                    kind,
                    content: text.to_string(),
                })
            }
            "chat_params" => {
                let text = event.payload.get("content").and_then(Value::as_str)?;
                if text.is_empty() {
                    return None;
                }
                Some(HookContentExtract {
                    kind: HookContentKind::PromptText,
                    content: text.to_string(),
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
        // OpenCode emits `chat.message` for both user and assistant
        // turns. The plugin tags `role` on the payload; treat the
        // user-role turn like `user_prompt_submit` so the existing
        // classify pipeline produces a real use-case label, and the
        // assistant-role turn as a generic notification (model output
        // doesn't drive policy in this codepath).
        "chat_message" => match payload.get("role").and_then(Value::as_str) {
            Some("assistant") => ActionType::Notification,
            _ => ActionType::UserPromptSubmit,
        },
        "user_prompt_submit" => ActionType::UserPromptSubmit,
        "session_created" | "session_idle_before" => ActionType::SessionStart,
        "session_idle" => ActionType::Notification,
        "session_error" | "session_end" => ActionType::SessionEnd,
        // chat_params and permission_ask are bookkeeping today —
        // surface them as notifications. Promote to a dedicated
        // ActionType variant once we want policy to gate on them.
        "chat_params" | "permission_ask" => ActionType::Notification,
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
    }

    #[test]
    fn chat_message_user_role_maps_to_user_prompt_submit() {
        let a = OpenCodeAdapter::new();
        let payload = br#"{
            "session_id": "ses_abc",
            "model": "claude-sonnet-4-5-20251022",
            "role": "user",
            "content": "refactor this function for readability"
        }"#;
        let ev = a.parse_event("chat_message", payload).unwrap();
        assert_eq!(ev.action_type, ActionType::UserPromptSubmit);
        assert_eq!(ev.model.as_deref(), Some("claude-sonnet-4-5-20251022"));
        let extract = a.classify_input(&ev).expect("user chat message classifies");
        assert_eq!(extract.kind, HookContentKind::PromptText);
        assert_eq!(extract.content, "refactor this function for readability");
    }

    #[test]
    fn chat_message_assistant_role_routes_as_assistant_turn() {
        let a = OpenCodeAdapter::new();
        let payload = br#"{
            "session_id": "ses_abc",
            "role": "assistant",
            "content": "Here's the refactored function..."
        }"#;
        let ev = a.parse_event("chat_message", payload).unwrap();
        assert_eq!(ev.action_type, ActionType::Notification);
        let extract = a.classify_input(&ev).expect("assistant turn classifies");
        assert_eq!(extract.kind, HookContentKind::AssistantTurn);
    }

    #[test]
    fn model_extracted_from_nested_input_path() {
        // Older plugin builds didn't lift model to the top level —
        // adapter should still find it on /input/model so we don't
        // regress when running against an un-updated plugin.
        let a = OpenCodeAdapter::new();
        let payload = br#"{
            "session_id": "ses_abc",
            "input": { "sessionID": "ses_abc", "model": "gpt-5-codex" }
        }"#;
        let ev = a.parse_event("chat_message", payload).unwrap();
        assert_eq!(ev.model.as_deref(), Some("gpt-5-codex"));
    }
}
