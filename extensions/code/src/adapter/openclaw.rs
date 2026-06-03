//! OpenClaw adapter.
//!
//! OpenClaw is a community OpenAI-CLI-style agent that records
//! sessions to `~/.openclaw/agents/main/sessions/*.jsonl` (per
//! historian's `openclaw` playbook).  Its hook protocol mirrors
//! Codex / Anthropic-style payloads — `pre_tool_use`,
//! `post_tool_use`, `user_prompt_submit`, `stop`, `session_start`
//! with the same `tool_name` / `tool_input` / `tool_response`
//! shape — and decisions are rendered Anthropic-style with a
//! JSON `{decision, reason, guidance}` object.
//!
//! **Install deferred.** Upstream OpenClaw's hook configuration
//! format is still in flux, so `soth code install --target openclaw`
//! returns a clear "format pending" message rather than writing
//! a config that may not match upstream's settled shape.  The
//! parser, classify-on-hook, policy evaluation, and decision
//! rendering paths all work end-to-end against manually
//! configured hooks; once upstream stabilizes, the install
//! surface lights up by adding one match arm in `commands/code.rs`.
//!
//! Fixtures live at `extensions/code/tests/fixtures/openclaw/`
//! and exercise all 5 hook types (parsed correctly per
//! `parser_corpus_phase3::every_fixture_parses_for_every_agent`).
//! When upstream ships a config-format spec, capture real
//! payloads and replace the synthetic fixtures.
//!
//! Identity and provider come from soth-core's `DataSource::
//! HistorianOpenClaw` mirror — historian sees the session log
//! files, soth-code sees the live hooks; both layers correlate
//! on `agent: "openclaw"` + the agent's native `session_id`.

use serde_json::Value;
use soth_classify::HookContentKind;

use crate::decision::{AdapterResponse, HookDecision};
use crate::event::{ActionType, CodeEvent, HookContentExtract};

use super::{Adapter, ParseError};

const NAME: &str = "openclaw";

pub struct OpenClawAdapter;

impl OpenClawAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for OpenClawAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Adapter for OpenClawAdapter {
    fn name(&self) -> &'static str {
        NAME
    }

    fn ua_patterns(&self) -> &'static [&'static str] {
        &["openclaw/*", "OpenClaw/*", "open-claw/*"]
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
        let model = payload
            .get("model")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let mut event = CodeEvent::new(NAME, hook_type, action, session, payload);
        event.model = model;
        Ok(event)
    }

    fn render_decision(&self, decision: &HookDecision) -> AdapterResponse {
        // Anthropic-style protocol.  stdout carries the decision JSON,
        // stderr a trimmed reason for terminal display, exit 2
        // signals "halt the action".
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
        // Same as Codex: pre_tool_use + user_prompt_submit are
        // the two where blocking actually halts execution.
        // Refusing session_start is bad UX (agent fails to
        // initialize for opaque reasons).
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
        let a = OpenClawAdapter::new();
        for ht in [
            "pre_tool_use",
            "post_tool_use",
            "user_prompt_submit",
            "stop",
            "session_start",
        ] {
            let payload =
                br#"{"session_id":"s1","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
            let ev = a.parse_event(ht, payload).expect("parse");
            assert_eq!(ev.agent, "openclaw");
            assert_eq!(ev.agent_native_session_id, "s1");
        }
    }

    #[test]
    fn ua_patterns_cover_known_spellings() {
        let a = OpenClawAdapter::new();
        let patterns: Vec<&str> = a.ua_patterns().to_vec();
        // Both case variants and the dashed form — proxy
        // matching needs all three because production traffic
        // shows all three live.
        assert!(patterns.contains(&"openclaw/*"));
        assert!(patterns.contains(&"OpenClaw/*"));
        assert!(patterns.contains(&"open-claw/*"));
    }

    #[test]
    fn pre_action_hook_gates_only_pre_tool_use_and_prompt() {
        let a = OpenClawAdapter::new();
        // Block-eligible: actually halts the action.
        assert!(a.is_pre_action_hook("pre_tool_use"));
        assert!(a.is_pre_action_hook("user_prompt_submit"));
        // Post-action: can't halt the past.  Block decisions
        // here would just produce stop-hook feedback loops.
        assert!(!a.is_pre_action_hook("post_tool_use"));
        assert!(!a.is_pre_action_hook("stop"));
        assert!(!a.is_pre_action_hook("session_start"));
    }

    #[test]
    fn classify_input_returns_prompt_text_for_user_prompt_submit() {
        let a = OpenClawAdapter::new();
        let payload = br#"{"session_id":"s1","prompt":"Refactor this auth check."}"#;
        let ev = a.parse_event("user_prompt_submit", payload).unwrap();
        let extract = a.classify_input(&ev).expect("user prompt should classify");
        assert_eq!(extract.kind, HookContentKind::PromptText);
        assert_eq!(extract.content, "Refactor this auth check.");
    }

    #[test]
    fn classify_input_returns_tool_args_for_pre_tool_use() {
        let a = OpenClawAdapter::new();
        let payload =
            br#"{"session_id":"s1","tool_name":"Bash","tool_input":{"command":"ls -la"}}"#;
        let ev = a.parse_event("pre_tool_use", payload).unwrap();
        let extract = a.classify_input(&ev).expect("pre_tool_use should classify");
        assert_eq!(extract.kind, HookContentKind::ToolArgs);
        // Tool name + serialized input — the same shape Codex
        // uses, so the classify pipeline doesn't need an
        // adapter-specific branch.
        assert!(extract.content.starts_with("Bash\n"));
        assert!(extract.content.contains("ls -la"));
    }

    #[test]
    fn classify_input_skips_session_start_and_stop() {
        let a = OpenClawAdapter::new();
        for ht in ["session_start", "stop"] {
            let payload = br#"{"session_id":"s1"}"#;
            let ev = a.parse_event(ht, payload).unwrap();
            assert!(a.classify_input(&ev).is_none(), "{ht} must not classify");
        }
    }

    #[test]
    fn render_block_emits_decision_json_and_exit_2() {
        let a = OpenClawAdapter::new();
        let resp = a.render_decision(&HookDecision::Block {
            reason: "credential detected".to_string(),
            guidance: Some("see policy bundle".to_string()),
        });
        assert_eq!(resp.exit_code, 2);
        let body: Value = serde_json::from_slice(&resp.stdout).unwrap();
        assert_eq!(body["decision"], "block");
        assert_eq!(body["reason"], "credential detected");
        assert_eq!(body["guidance"], "see policy bundle");
        // stderr trimmed for terminal display.
        assert_eq!(resp.stderr, b"credential detected");
    }

    #[test]
    fn render_allow_is_silent_exit_0() {
        let a = OpenClawAdapter::new();
        let resp = a.render_decision(&HookDecision::Allow);
        assert_eq!(resp.exit_code, 0);
        assert!(resp.stdout.is_empty());
        assert!(resp.stderr.is_empty());
    }

    #[test]
    fn tool_to_action_maps_known_tools_and_falls_back_to_tool_use() {
        assert_eq!(tool_to_action("Bash"), ActionType::CommandExec);
        assert_eq!(tool_to_action("bash"), ActionType::CommandExec);
        assert_eq!(tool_to_action("Read"), ActionType::FileRead);
        assert_eq!(tool_to_action("Edit"), ActionType::FileWrite);
        assert_eq!(tool_to_action("Write"), ActionType::FileWrite);
        // Unknown tool name → generic ToolUse so MCP-style
        // tool calls don't get silently mis-categorized.
        assert_eq!(
            tool_to_action("mcp__github__list_issues"),
            ActionType::ToolUse
        );
    }
}
