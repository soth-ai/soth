//! `soth-code` — synchronous per-action policy gate for AI coding agents.
//!
//! # Status: Experimental
//!
//! This extension is under active development. Public types and the on-disk
//! hook contract may change between releases. APIs annotated as stable
//! (`HookDecision`, `HookOutcome`, `run_hook`) are unlikely to move, but the
//! parser / adapter / install surface is still in flux.
//!
//! Architecture in short:
//!
//! - The proxy observes the **network** layer (HTTP traffic to AI APIs).
//! - The historian observes the **session** layer (local file-watch
//!   reconstruction of agent transcripts).
//! - This extension observes the **action** layer: synchronously, at the
//!   agent's hook boundary, *before* a tool call / file edit / shell
//!   command executes. Returns Allow / Block / Redact decisions that
//!   propagate to the agent via its native blocking-hook contract.

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
pub mod policy_defaults;
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
        // `installed` reflects whether any agent hook is wired into
        // a coding tool — that's what makes the extension functionally
        // installed. `code.yaml` is only for tuning knobs and is
        // legitimately absent on hosts that ran `soth code install`
        // without ever customizing config; using its presence here
        // previously caused `soth code status` to report `installed:
        // false` despite `installed.json` listing 6 agents.
        let installed_agents: Vec<String> =
            state::InstalledHostState::load(&self.paths.installed_state)
                .map(|s| s.hooks.keys().cloned().collect())
                .unwrap_or_default();

        ExtensionStatus {
            name: CODE_MANIFEST.name.to_string(),
            version: CODE_MANIFEST.version.to_string(),
            archetype: CODE_MANIFEST.archetype,
            installed: !installed_agents.is_empty(),
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
    fn status_reports_uninstalled_when_no_hooks_recorded() {
        // Empty tempdir → no `installed.json` → no agent hooks
        // wired → `installed: false`. Tempdir avoids picking up the
        // host's real `~/.soth/installed.json`.
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

    #[test]
    fn status_reports_installed_when_installed_json_has_agents() {
        // Regression for the bug where `status()` only checked
        // `code.yaml`. Six agents in installed.json but no
        // `code.yaml` MUST report `installed: true`.
        use crate::state::InstalledHostState;
        use std::path::PathBuf;

        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());
        let mut state = InstalledHostState::default();
        state.record_install(
            "cursor",
            PathBuf::from("/x/.cursor/hooks.json"),
            PathBuf::from("/usr/local/bin/soth"),
        );
        state.save(&paths.installed_state).unwrap();
        // No `code.yaml` written — the bug case.
        assert!(!paths.config.exists());

        let ext = CodeExtension::with_paths(paths);
        let ctx = soth_extensions::ExtensionRuntimeContext::from_defaults();
        let st = ext.status(&ctx);
        assert!(
            st.installed,
            "any recorded agent hook should mark extension installed"
        );
    }
}
