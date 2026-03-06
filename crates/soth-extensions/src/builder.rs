use std::sync::Arc;

use tokio::sync::mpsc;

use crate::error::ExtensionError;
use crate::handle::ExtensionHandle;
use crate::manager::ExtensionManager;
use crate::traits::Extension;

const EVENT_CHANNEL_CAPACITY: usize = 1_024;

/// Builder for constructing an `ExtensionManager` with registered extensions.
pub struct ExtensionManagerBuilder {
    extensions: Vec<Box<dyn Extension>>,
    policy_bundle: Option<Arc<soth_policy::PolicyBundle>>,
    classify_bundle: Option<Arc<soth_classify::ClassifyBundle>>,
    classify_config: Option<Arc<soth_classify::ClassifyConfig>>,
    telemetry: Option<Arc<soth_telemetry::TelemetryPipeline>>,
}

impl ExtensionManagerBuilder {
    pub fn new() -> Self {
        Self {
            extensions: Vec::new(),
            policy_bundle: None,
            classify_bundle: None,
            classify_config: None,
            telemetry: None,
        }
    }

    /// Register an extension. Can be called multiple times.
    pub fn register(mut self, ext: impl Extension) -> Self {
        self.extensions.push(Box::new(ext));
        self
    }

    /// Set the policy bundle for evaluating extension events.
    pub fn with_policy_bundle(mut self, bundle: Arc<soth_policy::PolicyBundle>) -> Self {
        self.policy_bundle = Some(bundle);
        self
    }

    /// Set the classify bundle for semantic classification (optional).
    pub fn with_classify_bundle(
        mut self,
        bundle: Arc<soth_classify::ClassifyBundle>,
        config: Arc<soth_classify::ClassifyConfig>,
    ) -> Self {
        self.classify_bundle = Some(bundle);
        self.classify_config = Some(config);
        self
    }

    /// Set the telemetry pipeline for emitting events (optional).
    pub fn with_telemetry(mut self, pipeline: Arc<soth_telemetry::TelemetryPipeline>) -> Self {
        self.telemetry = Some(pipeline);
        self
    }

    /// Build the manager. Fails if no policy bundle is set.
    pub fn build(mut self) -> Result<ExtensionManager, ExtensionError> {
        let policy_bundle = self
            .policy_bundle
            .ok_or_else(|| ExtensionError::Other("policy_bundle is required".to_string()))?;

        // Create the shared event channel
        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);

        // Hand each extension a handle with the sender
        for ext in &mut self.extensions {
            ext.set_handle(ExtensionHandle::new(event_tx.clone()));
        }

        Ok(ExtensionManager::from_parts(
            event_rx,
            self.extensions,
            policy_bundle,
            self.classify_bundle,
            self.classify_config,
            self.telemetry,
        ))
    }
}

impl Default for ExtensionManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
