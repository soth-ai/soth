//! `CodeEvent` — internal action-layer event shape produced by adapters.
//!
//! Adapters parse hook stdin into a `CodeEvent`, the privacy walker
//! redacts sensitive fields in place, classify attaches a sidecar, and
//! the hook handler maps the result into `soth_core::GovernableEvent`
//! before enqueueing.
//!
//! The pre-classify event shape lives here (not in `soth-core`) because
//! it carries adapter-specific raw payload that callers outside this
//! crate should not manipulate. Only the `GovernableEvent` mapping is
//! the public contract.

use serde::{Deserialize, Serialize};
use soth_classify::{ClassifiedResult, HookContentKind};
use uuid::Uuid;

/// What kind of action the hook event represents. The full mapping from
/// agent-native hook types (Claude Code's `pre_tool_use`, Cursor's
/// `before_shell_execution`, etc.) to these variants is the job of each
/// adapter — see `adapter::Adapter::parse_event`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    FileRead,
    FileWrite,
    FileDelete,
    CommandExec,
    ToolUse,
    SessionStart,
    SessionEnd,
    Notification,
    SubagentStart,
    SubagentStop,
    UserPromptSubmit,
    Stop,
}

impl ActionType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FileRead => "file_read",
            Self::FileWrite => "file_write",
            Self::FileDelete => "file_delete",
            Self::CommandExec => "command_exec",
            Self::ToolUse => "tool_use",
            Self::SessionStart => "session_start",
            Self::SessionEnd => "session_end",
            Self::Notification => "notification",
            Self::SubagentStart => "subagent_start",
            Self::SubagentStop => "subagent_stop",
            Self::UserPromptSubmit => "user_prompt_submit",
            Self::Stop => "stop",
        }
    }
}

/// Subagent attribution from agent-tool / sub-agent invocations
/// (Claude Code's Agent tool, e.g.). `None` for main-agent calls.
///
/// Detected by *presence* of `agent_id` / `agent_type` in hook payload
/// — gryph PR #38 verified this is the only reliable signal; hook
/// event names alone do not distinguish main vs subagent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubagentContext {
    pub subagent_id: String,
    pub subagent_type: String,
    /// Parent session id when the agent payload supplies one. Claude
    /// Code does not currently surface this through hooks — left
    /// `None` rather than guessing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_session_id: Option<String>,
}

/// What an adapter wants to feed into classify for a given event.
///
/// Adapters return `Some(HookContentExtract)` when the payload carries
/// content the embedding/anomaly stages should see (prompt text, tool
/// args, tool result, assistant turn). They return `None` for
/// bookkeeping events (session_start/end, notifications without text)
/// — classify is then skipped and `CodeEvent::classify` stays `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookContentExtract {
    pub kind: HookContentKind,
    pub content: String,
}

/// Subset of [`ClassifiedResult`] surfaced into the queued event.
///
/// Excludes the embedding vector itself (LOCAL ONLY — never serialized)
/// and a few proxy-only fields. Mirrors what the policy evaluator's
/// `PolicyContext::semantic` consumes plus the visible anomaly score
/// the dashboard renders.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifySidecar {
    pub semantic_hash: String,
    pub use_case_label: String,
    pub use_case_confidence: f32,
    pub complexity_score: u8,
    pub anomaly_score: f32,
    pub anomaly_flags: Vec<String>,
    pub estimated_input_tokens: u32,
    pub topic_cluster_id: u32,
    pub stage_total_us: u64,
}

impl From<&ClassifiedResult> for ClassifySidecar {
    fn from(c: &ClassifiedResult) -> Self {
        Self {
            semantic_hash: c.semantic_hash.clone(),
            use_case_label: format!("{:?}", c.use_case_label),
            use_case_confidence: c.use_case_confidence,
            complexity_score: c.complexity_score,
            anomaly_score: c.anomaly_score,
            anomaly_flags: c
                .anomaly_flags
                .iter()
                .map(|f| format!("{f:?}"))
                .collect(),
            estimated_input_tokens: c.telemetry_event.estimated_input_tokens.unwrap_or(0),
            topic_cluster_id: c.topic_cluster_id,
            stage_total_us: c.stage_latencies.total_us,
        }
    }
}

/// Internal action-layer event the adapter produces and the hook handler
/// transports through detect → classify → policy → enqueue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeEvent {
    pub event_id: Uuid,
    pub timestamp_ms: i64,
    /// Adapter name (e.g. `"claude_code"`).
    pub agent: String,
    /// Native hook-type string (e.g. `"pre_tool_use"`). Adapter-specific.
    pub hook_type: String,
    /// Agent's own session id. Empty string when the hook payload doesn't
    /// supply one — the smoke-E2E stub path hits this case; real adapters
    /// extract it from agent-specific fields.
    pub agent_native_session_id: String,
    pub action_seq: Option<u32>,
    pub action_type: ActionType,
    pub subagent: Option<SubagentContext>,
    /// `sha256(agent || ":" || agent_native_session_id)` — joins this
    /// event to network/session-layer events for the same agent session
    /// in the dashboard. Computed once at event construction so consumers
    /// don't have to re-derive.
    pub correlation_key: String,
    /// Raw hook stdin payload. Keep as `Value` until we narrow on use —
    /// gryph PR #32 showed that real MCP servers return shapes the docs
    /// don't predict; defensively typed access to the few fields we need
    /// at parse time, full payload preserved here for telemetry / debug.
    pub payload: serde_json::Value,
    /// Outputs from the synchronous classify call run on the hook
    /// payload. `None` when the hook event isn't classifiable
    /// (bookkeeping events) or when classify was skipped (e.g.
    /// classify is disabled in config).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classify: Option<ClassifySidecar>,
}

impl CodeEvent {
    /// Build a minimal `CodeEvent` from a fully-parsed hook input. The
    /// stub adapter uses this; real adapters call it after extracting
    /// agent-specific fields (action_seq, native session id, subagent
    /// attribution) into the right slots.
    pub fn new(
        agent: impl Into<String>,
        hook_type: impl Into<String>,
        action_type: ActionType,
        agent_native_session_id: impl Into<String>,
        payload: serde_json::Value,
    ) -> Self {
        let agent = agent.into();
        let agent_native_session_id = agent_native_session_id.into();
        let correlation_key = soth_core::correlation_key(&agent, &agent_native_session_id);
        Self {
            event_id: Uuid::new_v4(),
            timestamp_ms: now_ms(),
            agent,
            hook_type: hook_type.into(),
            agent_native_session_id,
            action_seq: None,
            action_type,
            subagent: None,
            correlation_key,
            payload,
            classify: None,
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlation_key_deterministic_on_construct() {
        let a = CodeEvent::new(
            "claude_code",
            "pre_tool_use",
            ActionType::ToolUse,
            "session-abc",
            serde_json::json!({}),
        );
        let b = CodeEvent::new(
            "claude_code",
            "pre_tool_use",
            ActionType::ToolUse,
            "session-abc",
            serde_json::json!({}),
        );
        // event_id and timestamp differ; correlation_key matches.
        assert_eq!(a.correlation_key, b.correlation_key);
        assert_ne!(a.event_id, b.event_id);
    }

    #[test]
    fn action_type_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&ActionType::CommandExec).unwrap(),
            "\"command_exec\""
        );
        assert_eq!(
            serde_json::to_string(&ActionType::UserPromptSubmit).unwrap(),
            "\"user_prompt_submit\""
        );
        assert_eq!(
            serde_json::to_string(&ActionType::SubagentStart).unwrap(),
            "\"subagent_start\""
        );
    }

    #[test]
    fn action_type_as_str_matches_serde() {
        for a in [
            ActionType::FileRead,
            ActionType::FileWrite,
            ActionType::FileDelete,
            ActionType::CommandExec,
            ActionType::ToolUse,
            ActionType::SessionStart,
            ActionType::SessionEnd,
            ActionType::Notification,
            ActionType::SubagentStart,
            ActionType::SubagentStop,
            ActionType::UserPromptSubmit,
            ActionType::Stop,
        ] {
            let serde_form = serde_json::to_string(&a).unwrap();
            // serde_form has surrounding quotes; strip them.
            assert_eq!(
                a.as_str(),
                serde_form.trim_matches('"'),
                "as_str must match serde_json snake_case for {a:?}"
            );
        }
    }
}
