use async_trait::async_trait;

use crate::capabilities::ExtensionCapabilities;
use crate::error::ExtensionError;
use crate::handle::ExtensionHandle;

/// Health status reported by an extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionHealth {
    Healthy,
    Degraded { reason: String },
    Unhealthy { reason: String },
}

/// Core trait every extension must implement.
///
/// Extensions are pluggable intake paths that produce `GovernableEvent`s
/// which flow through the standard policy → classify → telemetry pipeline.
#[async_trait]
pub trait Extension: Send + Sync + 'static {
    /// The extension type identifier.
    fn extension_type(&self) -> soth_core::ExtensionType;

    /// Human-readable name.
    fn name(&self) -> &str;

    /// Semantic version of this extension.
    fn version(&self) -> &str;

    /// Declares what pipeline stages this extension needs.
    fn capabilities(&self) -> ExtensionCapabilities;

    /// Start the extension (open connections, spawn background tasks, etc.).
    async fn start(&mut self) -> Result<(), ExtensionError>;

    /// Gracefully shut down.
    async fn stop(&mut self) -> Result<(), ExtensionError>;

    /// Report current health.
    async fn health(&self) -> ExtensionHealth;

    /// Called by the manager to hand the extension a channel for submitting events.
    fn set_handle(&mut self, handle: ExtensionHandle);
}
