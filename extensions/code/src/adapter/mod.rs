//! Per-agent adapters — parse hook stdin into a `CodeEvent`, redact
//! sensitive fields, render decisions back in the agent's native
//! contract.
//!
//! Group 3 ships the trait + a stub adapter that accepts any agent and
//! parses a generic JSON payload. Group 4 lands the real Claude Code
//! adapter and the per-agent fixture corpus.

use crate::decision::{AdapterResponse, HookDecision};
use crate::event::CodeEvent;

mod stub;

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

/// Static lookup by adapter name. Lives behind a function (not a
/// `static`) so the smoke E2E doesn't need a global registry mutex —
/// the stub adapter is zero-cost to construct.
pub fn for_agent(name: &str) -> Option<Box<dyn Adapter>> {
    // Group 3: only the stub. Group 4 adds Claude Code; Group 6 adds
    // the rest. The stub accepts any agent name so the smoke E2E
    // works without a real adapter installed.
    if name.is_empty() {
        return None;
    }
    Some(Box::new(StubAdapter::new(name.to_string())))
}
