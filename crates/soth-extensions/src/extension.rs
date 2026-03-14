use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::context::ExtensionRuntimeContext;
use crate::status::ExtensionStatus;

use soth_core::PreEmitEvent;

// ---------------------------------------------------------------------------
// Extension trait — registration + lifecycle for all extension archetypes
// ---------------------------------------------------------------------------
//
// This trait is compile-time only — used for CLI registration and `soth status`.
// It is not in any hot path. `run_hook()` in gryph is called directly without
// going through the trait. `observe_telemetry_event` is called via the broadcast
// closure (see registry.rs). The trait is the registration mechanism, not the
// dispatch mechanism for performance-critical paths.

#[async_trait]
pub trait Extension: Send + Sync + 'static {
    fn manifest(&self) -> &ExtensionManifest;

    /// SQL DDL strings this extension needs applied to soth.db.
    /// Returned in order — applied once, tracked by MigrationRunner.
    fn migrations(&self) -> &[&'static str] {
        &[]
    }

    /// clap subcommands this extension contributes to soth-cli.
    fn cli_commands(&self) -> Vec<clap::Command> {
        Vec::new()
    }

    /// Dispatch a matched subcommand. Called by soth-cli's dispatch().
    /// Returns the process exit code.
    fn dispatch(
        &self,
        _subcmd: &str,
        _matches: &clap::ArgMatches,
        _ctx: &ExtensionRuntimeContext,
    ) -> ExitCode {
        ExitCode::SUCCESS
    }

    /// Called by `soth status`. Returns current health + install state.
    fn status(&self, ctx: &ExtensionRuntimeContext) -> ExtensionStatus;

    // ── Lifecycle methods (default: no-op) ──────────────────────────────
    //
    // Called by `ExtensionRegistry::start_all` / `shutdown_all` during proxy
    // startup/shutdown. Extensions that need background tasks (historian
    // backfill + watch, etc.) implement these. Passive observers and simple
    // governance extensions leave the defaults.

    /// Start the extension's background tasks. Called once after migrations.
    /// The extension owns its own tokio tasks and shutdown signals internally.
    async fn start(&self, _ctx: Arc<ExtensionRuntimeContext>) {}

    /// Signal the extension to stop and wait for clean exit.
    async fn shutdown(&self) {}

    // ── Passive observer methods (default: no-op) ────────────────────────

    /// If Some(interval), this extension is a periodic passive observer.
    /// soth-cli spawns a flush task at this cadence when the proxy runs.
    /// Governance extensions return None (default).
    fn observation_interval(&self) -> Option<Duration> {
        None
    }

    /// Called (via the broadcast fn injected into soth-proxy) after each
    /// intercepted AI call produces a PreEmitEvent.
    ///
    /// Must return quickly — offload any heavy work to a background thread.
    /// Governance extensions leave this as the default no-op.
    fn observe_telemetry_event(
        &self,
        _event: &PreEmitEvent,
        _ctx: &ExtensionRuntimeContext,
    ) {
    }

    /// Called periodically at observation_interval() cadence by soth-cli.
    /// Drains the in-memory signal buffer, aggregates into ObservationEvents,
    /// writes to SQLite, emits to obs.queue file.
    /// Governance extensions leave this as the default no-op.
    fn flush_observations(&self, _ctx: &ExtensionRuntimeContext) {}
}

// ---------------------------------------------------------------------------
// ExtensionManifest
// ---------------------------------------------------------------------------

pub struct ExtensionManifest {
    /// Machine name used in file paths, queue files, migration tags.
    /// Snake_case, stable forever: "gryph", "mcp_reticle", "historian",
    /// "subscription_detector"
    pub name: &'static str,
    pub version: &'static str,
    pub source: soth_core::ExtensionSource,
    pub capabilities: &'static [Capability],
    pub archetype: ExtensionArchetype,
    /// Whether this extension's hot path requires the proxy daemon running.
    pub requires_daemon: bool,
    /// The `tracing` log target for this extension's crate (e.g. "soth_historian").
    /// Used by the proxy to build the tracing filter dynamically so that
    /// individual extension crate names never appear in main.rs.
    pub tracing_target: &'static str,
}

// ---------------------------------------------------------------------------
// ExtensionArchetype
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionArchetype {
    /// Invoked per user action; produces GovernableEvent + PolicyDecision.
    Governance,
    /// Reacts to proxy events; produces ObservationEvent; no PolicyDecision.
    PassiveObserver,
}

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Can return exit 2 / block an upstream action.
    CanBlock,
    /// Telemetry only, no enforcement possible.
    ObserveOnly,
    /// Has install/uninstall/hook-status CLI commands.
    CanInstall,
    /// Reacts to proxy events, not user actions.
    PassiveObserver,
}
