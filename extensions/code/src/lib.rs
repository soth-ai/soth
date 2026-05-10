//! `soth-code` — synchronous per-action policy gate for AI coding agents.
//!
//! See `docs/gryph/plan.md` for the architecture. In short:
//!
//! - The proxy observes the **network** layer (HTTP traffic to AI APIs).
//! - The historian observes the **session** layer (local file-watch
//!   reconstruction of agent transcripts).
//! - This extension observes the **action** layer: synchronously, at the
//!   agent's hook boundary, *before* a tool call / file edit / shell
//!   command executes. Returns Allow / Block / Redact decisions that
//!   propagate to the agent via its native blocking-hook contract.
//!
//! Subsequent groups land:
//! - Group 3: `soth code hook` CLI handler (smoke E2E with stub adapter).
//! - Group 4: Claude Code adapter (parser, install, redact, fixtures).
//! - Group 5: classify + policy integration (the synchronous decision path).
//! - Group 6: proxy bypass / cost-skim wiring; dashboard contract.

#![forbid(unsafe_code)]

pub mod adapter;
pub mod classify_daemon;
pub mod decision;
pub mod detect;
pub mod diff;
pub mod event;
pub mod hook;
pub mod install;
pub mod paths;
pub mod state;

pub use decision::{AdapterResponse, HookDecision};
pub use event::{
    ActionType, ClassifySidecar, CodeCaptureMode, CodeEvent, HookCaptureConfig, HookContentExtract,
    SubagentContext,
};
pub use hook::{read_stdin_to_end, run_hook, write_outcome, HookError, HookOutcome};

use soth_core::ExtensionSource;
use soth_extensions::{
    Capability, Extension, ExtensionArchetype, ExtensionManifest, ExtensionRuntimeContext,
    ExtensionStatus,
};

use crate::paths::CodePaths;

static CODE_MANIFEST: ExtensionManifest = ExtensionManifest {
    name: "code",
    version: env!("CARGO_PKG_VERSION"),
    source: ExtensionSource::Code,
    // CanBlock — the synchronous hook handler returns exit code 2 / blocking
    // JSON to halt the agent before the action executes.
    // CanInstall — `soth code install/uninstall/status/doctor` lives here.
    capabilities: &[Capability::CanBlock, Capability::CanInstall],
    archetype: ExtensionArchetype::Governance,
    requires_daemon: false,
    tracing_target: "soth_code",
};

/// The `soth-code` extension. The hook handler is invoked ephemerally per
/// agent action (one OS process per `soth code hook` invocation), so this
/// struct holds no long-running state — only the path resolver.
pub struct CodeExtension {
    paths: CodePaths,
}

impl CodeExtension {
    /// Construct with default `~/.soth/`-rooted paths.
    pub fn with_defaults() -> Self {
        Self {
            paths: CodePaths::from_default_root(),
        }
    }

    /// Construct with explicit paths (tests, alternate roots).
    pub fn with_paths(paths: CodePaths) -> Self {
        Self { paths }
    }

    /// Paths owned by this extension. Always resolve via this method —
    /// never call `dirs::*` from outside `paths.rs` (see `paths.rs` doc).
    pub fn paths(&self) -> &CodePaths {
        &self.paths
    }
}

#[async_trait::async_trait]
impl Extension for CodeExtension {
    fn manifest(&self) -> &ExtensionManifest {
        &CODE_MANIFEST
    }

    fn status(&self, _ctx: &ExtensionRuntimeContext) -> ExtensionStatus {
        // Group 2 ships an inert status — the hook handler isn't wired in yet,
        // so there are no events to count. Group 3 (smoke E2E) and Group 4
        // (Claude Code adapter) extend this with queue depth, last-event
        // timestamp, and per-adapter health.
        ExtensionStatus {
            name: CODE_MANIFEST.name.to_string(),
            version: CODE_MANIFEST.version.to_string(),
            archetype: CODE_MANIFEST.archetype,
            installed: self.paths.config.exists(),
            enabled: false, // toggled by YAML knob — Group 2's B-5 wires this in
            healthy: true,
            ..ExtensionStatus::default()
        }
    }

    // No `start` / `shutdown`: the hook handler is per-invocation.
    // No `migrations` (yet): SQLite store lands with adapter health in Group 4.
    // No `cli_commands` yet: hook subcommand wiring is Group 3 (C-1).
    // No `observe_telemetry_event`: this extension is Governance archetype,
    //   not PassiveObserver — it acts on its own event stream from hooks.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_identifies_extension() {
        let ext = CodeExtension::with_defaults();
        let m = ext.manifest();
        assert_eq!(m.name, "code");
        assert_eq!(m.tracing_target, "soth_code");
        assert_eq!(m.archetype, ExtensionArchetype::Governance);
        assert!(!m.requires_daemon);
        assert_eq!(m.source.name(), "code");
        assert!(m.capabilities.contains(&Capability::CanBlock));
        assert!(m.capabilities.contains(&Capability::CanInstall));
    }

    #[test]
    fn status_reports_uninstalled_when_no_config() {
        // `with_paths` lets the test point at an empty tempdir so no
        // accidental `~/.soth/code.yaml` triggers a false `installed: true`.
        let tmp = tempfile::tempdir().unwrap();
        let ext = CodeExtension::with_paths(CodePaths::from_root(tmp.path()));
        let ctx = soth_extensions::ExtensionRuntimeContext::from_defaults();
        let st = ext.status(&ctx);
        assert_eq!(st.name, "code");
        assert!(!st.installed);
        // Healthy without events is the right resting state for an extension
        // that hasn't been wired into the hook path yet.
        assert!(st.healthy);
    }
}
