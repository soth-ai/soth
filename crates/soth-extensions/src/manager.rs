use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::traits::{Extension, ExtensionHealth};

/// Manages registered extensions and processes their events through the pipeline.
pub struct ExtensionManager {
    event_rx: mpsc::Receiver<soth_core::GovernableEvent>,
    extensions: Vec<Box<dyn Extension>>,
    policy_bundle: Arc<soth_policy::PolicyBundle>,
    classify_bundle: Option<Arc<soth_classify::ClassifyBundle>>,
    classify_config: Option<Arc<soth_classify::ClassifyConfig>>,
    telemetry: Option<Arc<soth_telemetry::TelemetryPipeline>>,
}

impl ExtensionManager {
    /// Construct from pre-built parts. Prefer `ExtensionManagerBuilder`.
    pub(crate) fn from_parts(
        event_rx: mpsc::Receiver<soth_core::GovernableEvent>,
        extensions: Vec<Box<dyn Extension>>,
        policy_bundle: Arc<soth_policy::PolicyBundle>,
        classify_bundle: Option<Arc<soth_classify::ClassifyBundle>>,
        classify_config: Option<Arc<soth_classify::ClassifyConfig>>,
        telemetry: Option<Arc<soth_telemetry::TelemetryPipeline>>,
    ) -> Self {
        Self {
            event_rx,
            extensions,
            policy_bundle,
            classify_bundle,
            classify_config,
            telemetry,
        }
    }

    /// Start all registered extensions, then run the event loop until shutdown.
    pub async fn run(&mut self) {
        for ext in &mut self.extensions {
            match ext.start().await {
                Ok(()) => info!(
                    extension = ext.name(),
                    ext_type = ?ext.extension_type(),
                    "extension started"
                ),
                Err(error) => warn!(
                    extension = ext.name(),
                    ext_type = ?ext.extension_type(),
                    %error,
                    "extension failed to start"
                ),
            }
        }

        while let Some(event) = self.event_rx.recv().await {
            self.process_event(event);
        }

        for ext in &mut self.extensions {
            if let Err(error) = ext.stop().await {
                warn!(
                    extension = ext.name(),
                    %error,
                    "extension failed to stop cleanly"
                );
            }
        }
    }

    /// Process a single GovernableEvent through policy → classify → telemetry.
    fn process_event(&self, event: soth_core::GovernableEvent) {
        let ext_type = match &event.source {
            soth_core::EventSource::Extension { ext_type } => ext_type.clone(),
            _ => {
                warn!(source = ?event.source, "received event with non-extension source; dropping");
                return;
            }
        };

        let caps = self
            .extensions
            .iter()
            .find(|ext| ext.extension_type() == ext_type)
            .map(|ext| ext.capabilities())
            .unwrap_or_default();

        let proxy_ctx = build_extension_proxy_ctx(&event);

        // Extract normalized request (or default) for policy evaluation
        let normalized = event
            .normalized
            .clone()
            .unwrap_or_default();
        let artifacts = event.artifacts.clone();

        let policy_ctx = soth_core::PolicyContext {
            process_resolution: soth_core::ProcessResolution {
                match_kind: soth_core::ProcessMatchKind::Unknown,
                app_type: soth_core::AppType::Unknown,
                capture_mode: Some(event.capture_mode),
                process_name: None,
                bundle_id: None,
            },
            capture_mode: event.capture_mode,
            traffic_classification: soth_core::TrafficClassification::Other,
            deployment: soth_core::DeploymentModel::Proxy,
            skip_org_rules: false,
            semantic: None,
            session: soth_core::SessionSnapshot::default(),
        };

        // Step 1: Policy (always)
        let policy_decision =
            soth_policy::evaluate(&normalized, &artifacts, &policy_ctx, &self.policy_bundle);

        if matches!(
            policy_decision.kind,
            soth_core::PolicyDecisionKind::Block { .. }
        ) && caps.can_block
        {
            tracing::debug!(
                ext_type = ?ext_type,
                event_id = %event.event_id,
                "policy blocked extension event"
            );
        }

        // Step 2: Optional classify
        let classify_result = if caps.needs_classify {
            if let (Some(ref bundle), Some(ref config)) =
                (&self.classify_bundle, &self.classify_config)
            {
                let detect_result = build_detect_result_from_event(&event);
                Some(soth_classify::classify(
                    &detect_result,
                    event.embed_content.as_deref(),
                    &proxy_ctx,
                    bundle.as_ref(),
                    config.as_ref(),
                ))
            } else {
                None
            }
        } else {
            None
        };

        // Step 3: Emit telemetry
        if caps.emits_telemetry {
            if let Some(pipeline) = &self.telemetry {
                let telemetry_event = if let Some(ref result) = classify_result {
                    result.telemetry_event.clone()
                } else {
                    build_minimal_telemetry_event(&event, &policy_decision)
                };
                pipeline.push(telemetry_event);
            }
        }
    }

    /// Query health of all extensions.
    pub async fn health(&self) -> Vec<(String, ExtensionHealth)> {
        let mut results = Vec::with_capacity(self.extensions.len());
        for ext in &self.extensions {
            let health = ext.health().await;
            results.push((ext.name().to_string(), health));
        }
        results
    }

    /// Number of registered extensions.
    pub fn extension_count(&self) -> usize {
        self.extensions.len()
    }
}

fn build_extension_proxy_ctx(event: &soth_core::GovernableEvent) -> soth_core::ProxyContext {
    soth_core::ProxyContext {
        org_id: String::new(),
        user_id_hmac: String::new(),
        team_id: String::new(),
        device_id_hash: String::new(),
        endpoint_hash: String::new(),
        process_resolution: soth_core::ProcessResolution {
            match_kind: soth_core::ProcessMatchKind::Unknown,
            app_type: soth_core::AppType::Unknown,
            capture_mode: Some(event.capture_mode),
            process_name: None,
            bundle_id: None,
        },
        capture_mode: event.capture_mode,
        matched_provider: Some(format!("{:?}", event.provider)),
        matched_application: Some(event.context.extension_name.clone()),
        traffic_classification: soth_core::TrafficClassification::Other,
        classification_source: soth_core::ClassificationSource::Sdk,
        session_snapshot: Some(soth_core::SessionSnapshot::default()),
        request_method: None,
        deployment_context: None,
        precomputed_commitment_nonce: None,
        precomputed_commitment_hash: None,
    }
}

fn parse_data_source(value: Option<&str>) -> soth_core::DataSource {
    match value {
        Some("HistorianClaudeCode") => soth_core::DataSource::HistorianClaudeCode,
        Some("HistorianGemini") => soth_core::DataSource::HistorianGemini,
        Some("HistorianCodex") => soth_core::DataSource::HistorianCodex,
        _ => soth_core::DataSource::LiveProxy,
    }
}

fn build_detect_result_from_event(event: &soth_core::GovernableEvent) -> soth_core::DetectResult {
    let mut result = soth_core::DetectResult::default();
    if let Some(ref normalized) = event.normalized {
        result.normalized = normalized.clone();
    }
    result.artifacts = event.artifacts.clone();
    result.capture_mode = event.capture_mode;
    result
}

fn build_minimal_telemetry_event(
    event: &soth_core::GovernableEvent,
    policy_decision: &soth_core::PolicyDecision,
) -> soth_core::TelemetryEvent {
    let policy_kind = match policy_decision.kind {
        soth_core::PolicyDecisionKind::Allow => Some(soth_core::TelemetryPolicyKind::Allow),
        soth_core::PolicyDecisionKind::Block { .. } => {
            Some(soth_core::TelemetryPolicyKind::Block)
        }
        soth_core::PolicyDecisionKind::Flag { .. } => {
            Some(soth_core::TelemetryPolicyKind::Flag)
        }
        soth_core::PolicyDecisionKind::Redact { .. } => {
            Some(soth_core::TelemetryPolicyKind::Redact)
        }
        soth_core::PolicyDecisionKind::Reroute { .. } => {
            Some(soth_core::TelemetryPolicyKind::Reroute)
        }
    };

    let mut te = soth_core::TelemetryEvent::default();
    te.event_id = event.event_id;
    te.timestamp_epoch_ms = event.timestamp_epoch_ms;
    te.provider = event.provider.clone();
    te.model = event.model.clone();
    te.endpoint_type = event.endpoint_type;
    te.capture_mode = event.capture_mode;
    te.policy_kind = policy_kind;

    // Propagate historian metadata if present
    let meta = &event.context.metadata;
    if meta.get("is_historical").map(|v| v.as_str()) == Some("true") {
        te.is_historical = true;
        te.data_source = parse_data_source(meta.get("data_source").map(|s| s.as_str()));
        te.original_timestamp = meta
            .get("original_timestamp")
            .and_then(|v| v.parse::<i64>().ok());
    } else {
        te.data_source = soth_core::DataSource::LiveProxy;
    }

    te
}
