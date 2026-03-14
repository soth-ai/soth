use std::process::ExitCode;
use std::sync::Arc;

use soth_core::PreEmitEvent;

use crate::context::ExtensionRuntimeContext;
use crate::extension::Extension;
use crate::status::ExtensionStatus;

// ---------------------------------------------------------------------------
// ExtensionRegistry — replaces scattered #[cfg(feature)] blocks in soth-cli
// ---------------------------------------------------------------------------

pub struct ExtensionRegistry {
    extensions: Vec<Arc<dyn Extension>>,
}

impl ExtensionRegistry {
    pub fn empty() -> Self {
        Self {
            extensions: Vec::new(),
        }
    }

    pub fn register(&mut self, ext: Arc<dyn Extension>) {
        self.extensions.push(ext);
    }

    /// All clap commands from all registered extensions.
    pub fn commands(&self) -> Vec<clap::Command> {
        self.extensions
            .iter()
            .flat_map(|e| e.cli_commands())
            .collect()
    }

    /// Find the extension that owns `subcmd` and dispatch to it.
    pub fn dispatch(
        &self,
        subcmd: &str,
        matches: &clap::ArgMatches,
        ctx: &ExtensionRuntimeContext,
    ) -> Option<ExitCode> {
        for ext in &self.extensions {
            let names: Vec<String> = ext
                .cli_commands()
                .iter()
                .map(|c| c.get_name().to_owned())
                .collect();
            if names.iter().any(|n| n == subcmd) {
                return Some(ext.dispatch(subcmd, matches, ctx));
            }
        }
        None
    }

    pub fn all_status(&self, ctx: &ExtensionRuntimeContext) -> Vec<ExtensionStatus> {
        self.extensions.iter().map(|e| e.status(ctx)).collect()
    }

    pub fn all_migrations(&self) -> Vec<(&'static str, &[&'static str])> {
        self.extensions
            .iter()
            .map(|e| (e.manifest().name, e.migrations()))
            .collect()
    }

    /// Returns only extensions with observation_interval().is_some().
    /// Used by soth-cli to spawn periodic flush tasks.
    pub fn passive_observers(&self) -> Vec<Arc<dyn Extension>> {
        self.extensions
            .iter()
            .filter(|e| e.observation_interval().is_some())
            .cloned()
            .collect()
    }

    /// Build the observer broadcast closure injected into soth-proxy's config.
    ///
    /// soth-proxy calls this closure (in a spawned task) after each AI request
    /// produces a PreEmitEvent. The closure fans out to all passive observers.
    ///
    /// Returns None if no passive observer extensions are registered — soth-proxy
    /// skips the spawn entirely.
    ///
    /// Type: `Option<Arc<dyn Fn(&PreEmitEvent) + Send + Sync>>`
    /// Uses only soth-core types. soth-proxy gains zero new crate dependencies.
    pub fn build_observer_broadcast(
        &self,
        ctx: Arc<ExtensionRuntimeContext>,
    ) -> Option<Arc<dyn Fn(&PreEmitEvent) + Send + Sync>> {
        let passive = self.passive_observers();
        if passive.is_empty() {
            return None;
        }

        Some(Arc::new(move |event: &PreEmitEvent| {
            for ext in &passive {
                ext.observe_telemetry_event(event, &ctx);
            }
        }))
    }

    // ── Lifecycle management ────────────────────────────────────────────

    /// Start all registered extensions. Called once after migrations complete.
    /// Each extension manages its own background tasks internally.
    pub async fn start_all(&self, ctx: Arc<ExtensionRuntimeContext>) {
        for ext in &self.extensions {
            let name = ext.manifest().name;
            tracing::info!(extension = name, "starting extension");
            ext.start(ctx.clone()).await;
        }
    }

    /// Signal all extensions to shut down, in reverse registration order.
    pub async fn shutdown_all(&self) {
        for ext in self.extensions.iter().rev() {
            let name = ext.manifest().name;
            tracing::info!(extension = name, "shutting down extension");
            ext.shutdown().await;
        }
    }

    /// Collect tracing targets from all registered extensions.
    /// Used by the proxy to build the tracing filter dynamically.
    pub fn tracing_targets(&self) -> Vec<&'static str> {
        self.extensions
            .iter()
            .map(|e| e.manifest().tracing_target)
            .collect()
    }

    /// Number of registered extensions.
    pub fn extension_count(&self) -> usize {
        self.extensions.len()
    }
}
