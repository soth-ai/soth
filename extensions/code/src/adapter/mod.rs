//! Per-agent adapters — parse hook stdin into a `CodeEvent`, redact
//! sensitive fields, render decisions back in the agent's native
//! contract.
//!
//! Group 3 ships the trait + a stub adapter that accepts any agent and
//! parses a generic JSON payload. Group 4 lands the real Claude Code
//! adapter and the per-agent fixture corpus.

use crate::decision::{AdapterResponse, HookDecision};
use crate::event::{CodeEvent, HookContentExtract};

mod claude_code;
mod codex;
mod cursor;
mod gemini_cli;
mod opencode;
mod openclaw;
mod piagent;
mod stub;
mod windsurf;

pub use claude_code::ClaudeCodeAdapter;
pub use codex::CodexAdapter;
pub use cursor::CursorAdapter;
pub use gemini_cli::GeminiCliAdapter;
pub use opencode::OpenCodeAdapter;
pub use openclaw::OpenClawAdapter;
pub use piagent::PiAgentAdapter;
pub use stub::StubAdapter;
pub use windsurf::WindsurfAdapter;

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

    /// Extract the content the classify pipeline should see for this
    /// event. `None` for bookkeeping hooks (session_start, etc.).
    /// The default implementation returns `None`; adapters override
    /// per agent's hook taxonomy. See `docs/gryph/plan.md` §10.10.
    fn classify_input(&self, _event: &CodeEvent) -> Option<HookContentExtract> {
        None
    }

    /// Whether this hook type, for this agent, fires **before** the
    /// action runs. Only pre-action hooks can usefully Block — post-
    /// action hooks (Stop, PostToolUse, Notification, …) fire after
    /// the fact, where Block prevents nothing and creates feedback
    /// loops when post-event payloads echo content that triggered
    /// the original detection (gryph 2026-05-08 soak finding;
    /// hook.rs `is_enforceable_hook` regression test pins this
    /// guarantee).
    ///
    /// Default `false` (safe — adapters must opt their pre-action
    /// hooks in explicitly). Each agent's pre-action hook taxonomy
    /// differs; e.g. Claude Code uses snake_case `pre_tool_use`,
    /// Cursor uses snake_case `pre_tool_use` + a richer set
    /// (`before_shell_execution`, `before_read_file`, …).
    fn is_pre_action_hook(&self, _hook_type: &str) -> bool {
        false
    }
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
        "cursor" => Some(Box::new(CursorAdapter::new())),
        "pi_agent" | "piagent" => Some(Box::new(PiAgentAdapter::new())),
        "gemini_cli" | "gemini" => Some(Box::new(GeminiCliAdapter::new())),
        "codex" => Some(Box::new(CodexAdapter::new())),
        "windsurf" => Some(Box::new(WindsurfAdapter::new())),
        "opencode" => Some(Box::new(OpenCodeAdapter::new())),
        // OpenClaw: parser + classify + decision rendering live;
        // `soth code install --target openclaw` is the deferred
        // piece (upstream config-format unstable per gryph PR
        // #31). Manually-configured hooks pointing at
        // `soth code hook --agent openclaw --type ...` work
        // end-to-end against this adapter.
        "openclaw" | "open_claw" | "open-claw" => Some(Box::new(OpenClawAdapter::new())),
        _ => Some(Box::new(StubAdapter::new(name.to_string()))),
    }
}
