//! Gemini CLI adapter (Google's `gemini` CLI).
//!
//! Hook payloads are very close to Claude Code's (Gemini reuses the
//! Anthropic-conventional `tool_input`/`tool_response` shape) but with
//! its own pre-action hook event names (`before_tool_*`,
//! `after_tool_*`). The biggest gryph-forensics lesson here is PR #29:
//! the `details` field on some hooks was typed as `string` upstream
//! but Gemini sends a structured object — defensively typed access
//! to the few fields we narrow on, full payload preserved on the
//! event for telemetry.

use serde_json::Value;
use soth_classify::HookContentKind;

use crate::decision::{AdapterResponse, HookDecision};
use crate::event::{ActionType, CodeEvent, HookContentExtract};

use super::{Adapter, ParseError};

const NAME: &str = "gemini_cli";

pub struct GeminiCliAdapter;

impl GeminiCliAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GeminiCliAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Adapter for GeminiCliAdapter {
    fn name(&self) -> &'static str {
        NAME
    }

    fn ua_patterns(&self) -> &'static [&'static str] {
        &["gemini-cli/*", "Gemini-CLI/*", "gemini/*"]
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
        // Gemini CLI's hook payload does NOT carry a model field
        // (gryph leaves Model empty for this agent).  Best-effort
        // fallback: read `~/.gemini/settings.json`'s `model` value
        // (Gemini's CLI persists the active model there) or the
        // `GEMINI_MODEL` env var.  Best-effort — failure here keeps
        // the hook running with `model = None`.
        let model = payload
            .get("model")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(extract_model_fallback);
        let mut event = CodeEvent::new(NAME, hook_type, action, session, payload);
        event.model = model;
        Ok(event)
    }

    fn render_decision(&self, decision: &HookDecision) -> AdapterResponse {
        // Same Anthropic-style stdout-JSON + stderr-reason + exit-2
        // contract Claude Code uses. Gemini honors it.
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
            "pre_tool_use"
                | "user_prompt_submit"
                | "before_tool_read_file"
                | "before_tool_write_file"
                | "before_tool_shell"
                | "before_tool_call"
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
                let input = event
                    .payload
                    .get("tool_input")
                    .cloned()
                    .unwrap_or(Value::Null);
                Some(HookContentExtract {
                    kind: HookContentKind::ToolArgs,
                    content: format!("{tool}\n{}", serde_json::to_string(&input).ok()?),
                })
            }
            "before_tool_shell" => {
                let cmd = event
                    .payload
                    .get("tool_input")
                    .and_then(|v| v.get("command"))
                    .and_then(Value::as_str)?;
                Some(HookContentExtract {
                    kind: HookContentKind::ToolArgs,
                    content: format!("Shell\n{cmd}"),
                })
            }
            "before_tool_read_file" | "before_tool_write_file" => {
                let p = event
                    .payload
                    .get("tool_input")
                    .and_then(|v| v.get("file_path"))
                    .and_then(Value::as_str)?;
                Some(HookContentExtract {
                    kind: HookContentKind::ToolArgs,
                    content: format!("File\n{p}"),
                })
            }
            "post_tool_use" | "after_tool_call" => {
                let r = event
                    .payload
                    .get("tool_response")
                    .or_else(|| event.payload.get("tool_output"))
                    .cloned()
                    .unwrap_or(Value::Null);
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
        "before_tool_read_file" | "after_tool_read" => ActionType::FileRead,
        "before_tool_write_file" | "after_tool_write" => ActionType::FileWrite,
        "before_tool_shell" | "after_tool_shell" => ActionType::CommandExec,
        "user_prompt_submit" => ActionType::UserPromptSubmit,
        "stop" => ActionType::Stop,
        "session_start" => ActionType::SessionStart,
        "session_end" => ActionType::SessionEnd,
        "after_tool_failure" => ActionType::Notification,
        _ => ActionType::Notification,
    }
}

fn tool_to_action(tool_name: &str) -> ActionType {
    match tool_name {
        "read_file" | "Read" => ActionType::FileRead,
        "write_file" | "edit" | "Write" | "Edit" => ActionType::FileWrite,
        "shell" | "Shell" | "bash" | "Bash" => ActionType::CommandExec,
        _ => ActionType::ToolUse,
    }
}

/// Fallback model lookup for Gemini CLI when the hook payload
/// doesn't carry one.  Order:
/// 1. `GEMINI_MODEL` env var (CI/dev override).
/// 2. `~/.gemini/settings.json` `model` field — Gemini CLI's
///    persistent active-model record.
///
/// All failures swallowed; the hook just sets `model = None` and
/// the dashboard renders "unknown" for that event.
fn extract_model_fallback() -> Option<String> {
    if let Ok(env) = std::env::var("GEMINI_MODEL") {
        if !env.is_empty() {
            return Some(env);
        }
    }
    let path = dirs::home_dir()?.join(".gemini").join("settings.json");
    let bytes = std::fs::read(&path).ok()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    v.get("model")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn before_tool_shell_maps_to_command_exec() {
        let a = GeminiCliAdapter::new();
        let p = br#"{
            "session_id":"s",
            "hook_event_name":"before_tool_shell",
            "tool_name":"shell",
            "tool_input":{"command":"ls"}
        }"#;
        let ev = a.parse_event("before_tool_shell", p).unwrap();
        assert_eq!(ev.action_type, ActionType::CommandExec);
    }

    #[test]
    fn details_field_can_be_object_per_pr29() {
        // gryph PR #29: real Gemini sends `details` as an object
        // even though docs typed it as string. Defensive parsing
        // means the adapter doesn't crash on either shape.
        let a = GeminiCliAdapter::new();
        let p = br#"{
            "session_id":"s",
            "hook_event_name":"after_tool_failure",
            "details":{"error":"timeout","code":408}
        }"#;
        let ev = a.parse_event("after_tool_failure", p).unwrap();
        assert!(ev.payload["details"].is_object());
    }

    #[test]
    fn pre_action_hooks() {
        let a = GeminiCliAdapter::new();
        assert!(a.is_pre_action_hook("before_tool_shell"));
        assert!(a.is_pre_action_hook("before_tool_read_file"));
        assert!(a.is_pre_action_hook("pre_tool_use"));
        assert!(!a.is_pre_action_hook("after_tool_read"));
        assert!(!a.is_pre_action_hook("after_tool_failure"));
    }

    #[test]
    fn extract_model_from_env_fallback() {
        // Gemini hooks never include model in the payload, so
        // we lean on `GEMINI_MODEL` as the fastest fallback
        // before touching disk.
        let a = GeminiCliAdapter::new();
        std::env::set_var("GEMINI_MODEL", "gemini-2.5-pro");
        let ev = a
            .parse_event(
                "before_tool_shell",
                br#"{"session_id":"s","hook_event_name":"before_tool_shell"}"#,
            )
            .unwrap();
        assert_eq!(ev.model.as_deref(), Some("gemini-2.5-pro"));
        std::env::remove_var("GEMINI_MODEL");
    }
}
