//! Codex adapter (OpenAI's `codex` CLI).
//!
//! **Alpha-gated.** Codex hooks are very young — only 5 hook types
//! shipped as of rust-codex 0.114.0 (`session_start`,
//! `pre_tool_use`, `post_tool_use`, `user_prompt_submit`, `stop`).
//! Schema churn risk is high; gryph upstream's `agent/codex/`
//! adapter is itself still evolving. This adapter is shipped
//! parser-only — `soth code install --target codex` is deferred to
//! a follow-up commit pending stable upstream config-format
//! decisions (Codex hooks live in `~/.codex/config.toml` and the
//! TOML-format coupling is not worth threading through the CLI for
//! a v0 alpha-gated adapter).

use serde_json::Value;
use soth_classify::HookContentKind;

use crate::decision::{AdapterResponse, HookDecision};
use crate::event::{ActionType, CodeEvent, HookContentExtract};

use super::{Adapter, ParseError};

const NAME: &str = "codex";

pub struct CodexAdapter;

impl CodexAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CodexAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Adapter for CodexAdapter {
    fn name(&self) -> &'static str {
        NAME
    }

    fn ua_patterns(&self) -> &'static [&'static str] {
        &["codex/*", "Codex/*", "openai-codex/*"]
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
        Ok(CodeEvent::new(NAME, hook_type, action, session, payload))
    }

    fn render_decision(&self, decision: &HookDecision) -> AdapterResponse {
        // Anthropic-style protocol per gryph's Codex adapter.
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
        // Codex's 5 hook types: pre_tool_use + user_prompt_submit are
        // the two where blocking makes sense. session_start is
        // explicitly NOT enforced (refusing init is bad UX).
        matches!(hook_type, "pre_tool_use" | "user_prompt_submit")
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
                Some(HookContentExtract {
                    kind: HookContentKind::ToolArgs,
                    content: format!("{tool}\n{}", serde_json::to_string(&input).ok()?),
                })
            }
            "post_tool_use" => {
                let r = event
                    .payload
                    .get("tool_response")
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
        "pre_tool_use" | "post_tool_use" => {
            let tool = payload
                .get("tool_name")
                .and_then(Value::as_str)
                .unwrap_or("");
            tool_to_action(tool)
        }
        "user_prompt_submit" => ActionType::UserPromptSubmit,
        "stop" => ActionType::Stop,
        "session_start" => ActionType::SessionStart,
        _ => ActionType::Notification,
    }
}

fn tool_to_action(tool_name: &str) -> ActionType {
    match tool_name {
        "Read" | "read" => ActionType::FileRead,
        "Write" | "Edit" | "write" | "edit" => ActionType::FileWrite,
        "Bash" | "bash" | "shell" => ActionType::CommandExec,
        _ => ActionType::ToolUse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_canonical_hook_types_parse() {
        let a = CodexAdapter::new();
        for h in ["session_start", "pre_tool_use", "post_tool_use", "user_prompt_submit", "stop"] {
            let r = a.parse_event(h, br#"{"session_id":"s"}"#);
            assert!(r.is_ok(), "hook {h} must parse");
        }
    }

    #[test]
    fn pre_action_set_is_minimal() {
        let a = CodexAdapter::new();
        assert!(a.is_pre_action_hook("pre_tool_use"));
        assert!(a.is_pre_action_hook("user_prompt_submit"));
        // session_start NOT enforceable (refusing init breaks the agent).
        assert!(!a.is_pre_action_hook("session_start"));
        assert!(!a.is_pre_action_hook("stop"));
    }
}
