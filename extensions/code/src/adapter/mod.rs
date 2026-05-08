//! Per-agent adapters — parse hook stdin into a `CodeEvent`, redact
//! sensitive fields, render decisions back in the agent's native
//! contract.
//!
//! Group 3 ships the trait + a stub adapter that accepts any agent and
//! parses a generic JSON payload. Group 4 lands the real Claude Code
//! adapter and the per-agent fixture corpus.

use crate::decision::{AdapterResponse, HookDecision};
use crate::event::CodeEvent;

mod claude_code;
mod stub;

pub use claude_code::ClaudeCodeAdapter;
pub use stub::StubAdapter;

/// Per-agent adapter contract. Each agent's hook payload format,
/// decision-rendering convention, and install/uninstall flow lives
/// behind this trait so the hook handler treats them uniformly.
pub trait Adapter: Send + Sync {
    /// Adapter machine name (e.g. `"claude_code"`). Stable forever —
    /// surfaces in `DataSource::Code{Agent}` and `correlation_key`.
    fn name(&self) -> &'static str;

    /// User-Agent glob patterns this adapter matches. Used by the
    /// proxy gating layer to decide whether to bypass an outbound
    /// request (plan §10.11).
    fn ua_patterns(&self) -> &'static [&'static str];

    /// Parse a hook stdin payload into a `CodeEvent`. Returns
    /// `Err(ParseError)` if the payload is malformed or the hook type
    /// is unrecognized.
    fn parse_event(&self, hook_type: &str, stdin: &[u8]) -> Result<CodeEvent, ParseError>;

    /// Render a generic `HookDecision` into the agent's native
    /// stdout/stderr/exit-code contract.
    fn render_decision(&self, decision: &HookDecision) -> AdapterResponse;
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("invalid JSON in hook stdin: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("unknown hook type for {agent}: {hook_type}")]
    UnknownHookType { agent: &'static str, hook_type: String },
    #[error("missing required field {field} for {agent} hook {hook_type}")]
    MissingField {
        agent: &'static str,
        hook_type: String,
        field: &'static str,
    },
}

/// Adapter lookup by agent name. Lives behind a function (not a static
/// registry) so adapters are zero-cost to construct per hook
/// invocation — the hook subprocess is ephemeral, no shared state to
/// share across calls.
///
/// Known agents return their real adapter; unknown names fall through
/// to the permissive `StubAdapter` so the smoke E2E and integration
/// tests can exercise the pipeline without a registered adapter.
/// Production deployments only see traffic for agents in the
/// `code.agents.<name>.enabled = true` map (cli_config.rs), so the
/// stub is unreachable on the hot path.
pub fn for_agent(name: &str) -> Option<Box<dyn Adapter>> {
    if name.is_empty() {
        return None;
    }
    match name {
        "claude_code" => Some(Box::new(ClaudeCodeAdapter::new())),
        // Other adapters land in subsequent groups (Pi Agent, Cursor,
        // Codex, Gemini CLI, Windsurf, OpenCode). Until then any other
        // name lands on the stub.
        _ => Some(Box::new(StubAdapter::new(name.to_string()))),
    }
}
