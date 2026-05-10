//! Hook decision shape and exit-code/IO contract.
//!
//! Adapters return an `AdapterResponse` from `render_decision` describing
//! exactly what to write to stdout/stderr and what exit code to use —
//! since the per-agent contract differs (Claude Code expects a JSON
//! blocking shape on stdout; Pi Agent expects exit code 2 + reason on
//! stderr; etc.). This module owns the abstraction so higher layers
//! never see raw exit codes.
//!
//! For Group 3 (smoke E2E) only `Allow` is exercised. Group 5 (E-3) wires
//! `From<&PolicyDecision>` to translate the OPA evaluator's verdict.

use std::process::ExitCode;

use serde::{Deserialize, Serialize};

/// Generic, agent-agnostic hook outcome. Adapter-agnostic so the policy
/// evaluator and the hook handler reason in one shape; per-agent
/// translation is the adapter's job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HookDecision {
    /// Allow the action. Adapters render this as exit code 0 with no
    /// blocking JSON.
    Allow,
    /// Block the action. `reason` is the human-readable message; some
    /// adapters route it via stderr, others embed it in stdout JSON.
    /// `guidance` is a longer human-readable hint (Claude Code surfaces
    /// it as a tool-output guidance message — gryph PR #35).
    Block {
        reason: String,
        guidance: Option<String>,
    },
    /// Adapter-internal error (parse failure, classify timeout, OPA
    /// bundle missing). Whether this halts the action depends on the
    /// runtime's `on_policy_error` config (`Block` vs `Allow`).
    Error(String),
}

/// What the hook subprocess writes back to the agent. Each adapter
/// returns one of these from `render_decision` so the hook handler can
/// uniformly emit it regardless of agent.
#[derive(Debug, Clone)]
pub struct AdapterResponse {
    /// Bytes to write to stdout (typically structured JSON when the
    /// agent expects it; empty for plain Allow under most adapters).
    pub stdout: Vec<u8>,
    /// Bytes to write to stderr (typically a trimmed human-readable
    /// reason on Block; empty on Allow). gryph PR #22 found that
    /// trailing whitespace in block reasons produced confusing UX —
    /// adapters should trim before rendering.
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

impl AdapterResponse {
    /// Trivial Allow response — exit 0, no output. Default response for
    /// most adapters when policy returns Allow and no redaction is
    /// needed.
    pub fn allow() -> Self {
        Self {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_code: 0,
        }
    }

    /// Convert to `std::process::ExitCode`. The hook subprocess returns
    /// this from `main` after writing `stdout` and `stderr`.
    pub fn exit_code(&self) -> ExitCode {
        // ExitCode::from accepts u8; saturate negatives to 1 for
        // safety (cargo never produces negative exit codes by design,
        // but adapters could in principle).
        let code: u8 = if self.exit_code < 0 {
            1
        } else if self.exit_code > 255 {
            255
        } else {
            self.exit_code as u8
        };
        ExitCode::from(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_default_is_exit_zero_no_output() {
        let r = AdapterResponse::allow();
        assert!(r.stdout.is_empty());
        assert!(r.stderr.is_empty());
        assert_eq!(r.exit_code, 0);
    }

    #[test]
    fn exit_code_clamps_to_byte_range() {
        let r = AdapterResponse {
            stdout: vec![],
            stderr: vec![],
            exit_code: 300,
        };
        // No panic on out-of-range — clamps to 255.
        let _ = r.exit_code();
    }

    #[test]
    fn hook_decision_serde_round_trip() {
        let d = HookDecision::Block {
            reason: "denied by rule".into(),
            guidance: Some("see policy docs".into()),
        };
        let s = serde_json::to_string(&d).unwrap();
        let back: HookDecision = serde_json::from_str(&s).unwrap();
        assert_eq!(d, back);
    }
}
