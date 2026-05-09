//! Classify enrichment for historian events.
//!
//! Runs the soth-classify pipeline on GovernableEvents *before* they are
//! serialised to the governance queue.  The classify results are stored
//! as typed metadata keys so that `TelemetryEvent::from_governable()` can
//! read them back without requiring access to embed_content (which is
//! `#[serde(skip)]`).

use std::path::Path;
use std::sync::Arc;

use soth_classify::{ClassifyBundle, ClassifyConfig, ProxyContext};
use soth_core::classify::{
    AppType, ClassificationSource, ProcessMatchKind, ProcessResolution, SurfaceType,
    TrafficClassification,
};
use soth_core::extensions::GovernableEvent;
use soth_core::{CaptureMode, DetectResult};

use soth_extensions::ExtensionRuntimeContext;

/// Metadata keys written by the enrichment step and read by
/// `TelemetryEvent::from_governable()`.
pub mod keys {
    pub const USE_CASE: &str = "classify.use_case";
    pub const USE_CASE_CONFIDENCE: &str = "classify.use_case_confidence";
    pub const USE_CASE_LABEL_REASON: &str = "classify.use_case_label_reason";
    pub const USE_CASE_SECONDARY_LABEL: &str = "classify.use_case_secondary_label";
    pub const VOLATILITY_CLASS: &str = "classify.volatility_class";
    pub const DYNAMIC_FRACTION: &str = "classify.dynamic_fraction";
    pub const ANOMALY_SCORE: &str = "classify.anomaly_score";
    pub const ANOMALY_FLAGS: &str = "classify.anomaly_flags";
    pub const COMPLEXITY_SCORE: &str = "classify.complexity_score";
    pub const TOPIC_CLUSTER_ID: &str = "classify.topic_cluster_id";
    /// Top-level (NOT under `classify.`) — `from_governable`
    /// reads this directly off the metadata map.
    pub const SEMANTIC_HASH: &str = "semantic_hash";
    pub const ESTIMATED_INPUT_TOKENS: &str = "estimated_input_tokens";
}

/// Holds the loaded classify bundle + config for the duration of a
/// backfill / watch run.  Created once, shared across all events.
pub struct ClassifyEnricher {
    bundle: Arc<ClassifyBundle>,
    config: ClassifyConfig,
    proxy_ctx: ProxyContext,
}

impl ClassifyEnricher {
    /// Try to build an enricher from the runtime context.
    /// Returns `None` if the classify bundle cannot be loaded (e.g. bundle
    /// doesn't contain model assets).  The caller should proceed without
    /// enrichment in that case.
    pub fn try_new(ctx: &ExtensionRuntimeContext) -> Option<Self> {
        let bundle = load_classify_bundle(&ctx.bundle_path)?;
        let config = ClassifyConfig::default();
        let proxy_ctx = build_historian_proxy_ctx(ctx);
        Some(Self {
            bundle,
            config,
            proxy_ctx,
        })
    }

    /// Build from an existing bundle (useful when the proxy already has one).
    pub fn with_bundle(bundle: Arc<ClassifyBundle>, ctx: &ExtensionRuntimeContext) -> Self {
        Self {
            bundle,
            config: ClassifyConfig::default(),
            proxy_ctx: build_historian_proxy_ctx(ctx),
        }
    }

    /// Run classify on a GovernableEvent and write enrichment results
    /// into its metadata.  The event is modified in-place.
    pub fn enrich(&self, event: &mut GovernableEvent) {
        let detect_result = build_detect_result(event);
        let content = event.embed_content.as_deref();

        let result = soth_classify::classify(
            &detect_result,
            content,
            &self.proxy_ctx,
            &self.bundle,
            &self.config,
        );

        // Write classify results into metadata so they survive queue
        // serialization (embed_content is #[serde(skip)]).
        let meta = &mut event.context.metadata;
        meta.insert(
            keys::USE_CASE.to_string(),
            serde_json::to_string(&result.use_case_label).unwrap_or_default(),
        );
        meta.insert(
            keys::USE_CASE_CONFIDENCE.to_string(),
            result.use_case_confidence.to_string(),
        );
        meta.insert(
            keys::USE_CASE_LABEL_REASON.to_string(),
            serde_json::to_string(&result.use_case_label_reason).unwrap_or_default(),
        );
        meta.insert(
            keys::VOLATILITY_CLASS.to_string(),
            serde_json::to_string(&result.volatility_class).unwrap_or_default(),
        );
        meta.insert(
            keys::DYNAMIC_FRACTION.to_string(),
            result.dynamic_fraction.to_string(),
        );
        meta.insert(
            keys::ANOMALY_SCORE.to_string(),
            result.anomaly_score.to_string(),
        );
        meta.insert(
            keys::COMPLEXITY_SCORE.to_string(),
            result.complexity_score.to_string(),
        );
        meta.insert(
            keys::TOPIC_CLUSTER_ID.to_string(),
            result.topic_cluster_id.to_string(),
        );

        // Parity with soth-code's hook handler: secondary label,
        // anomaly flags, semantic hash, estimated input tokens.
        // These were previously only written by the proxy +
        // soth-code paths; historian rows ended up with NULL
        // secondary / empty flags / NULL semantic_hash on the
        // dashboard, breaking cross-source rollups.
        if let Some(secondary) = result.secondary_label.as_ref() {
            meta.insert(
                keys::USE_CASE_SECONDARY_LABEL.to_string(),
                serde_json::to_string(secondary).unwrap_or_default(),
            );
        }
        if !result.anomaly_flags.is_empty() {
            // JSON-array of snake_case enum names — same shape
            // soth-code writes, same shape `from_governable`
            // reads via `serde_json::from_str::<Vec<AnomalyFlag>>`.
            if let Ok(json) = serde_json::to_string(&result.anomaly_flags) {
                meta.insert(keys::ANOMALY_FLAGS.to_string(), json);
            }
        }
        // Top-level (NOT under `classify.`) keys.  Skip the
        // all-zero sentinel — that means the embedding stage
        // didn't run (unlikely for historian but defensive).
        if !result.semantic_hash.is_empty()
            && result.semantic_hash != "00000000000000000000000000000000"
        {
            meta.insert(
                keys::SEMANTIC_HASH.to_string(),
                result.semantic_hash.clone(),
            );
        }
        if let Some(tokens) = result.telemetry_event.estimated_input_tokens {
            if tokens > 0 {
                meta.insert(keys::ESTIMATED_INPUT_TOKENS.to_string(), tokens.to_string());
            }
        }
    }
}

/// Build a synthetic `DetectResult` from the GovernableEvent's already-parsed
/// data.  This avoids re-running the soth-detect HTTP parsing pipeline.
fn build_detect_result(event: &GovernableEvent) -> DetectResult {
    let normalized = event.normalized.clone().unwrap_or_default();

    DetectResult {
        normalized,
        artifacts: event.artifacts.clone(),
        capture_mode: event.capture_mode,
        parse_source: event
            .normalized
            .as_ref()
            .map(|n| n.parse_source)
            .unwrap_or(soth_core::ParseSource::Heuristic),
        confidence: event
            .normalized
            .as_ref()
            .map(|n| n.parse_confidence)
            .unwrap_or(soth_core::ParseConfidence::Heuristic),
        ..DetectResult::default()
    }
}

/// Build a minimal ProxyContext for historian events.
fn build_historian_proxy_ctx(ctx: &ExtensionRuntimeContext) -> ProxyContext {
    ProxyContext {
        identity: soth_core::IdentityContext {
            org_id: ctx.org_id.clone(),
            user_id_hmac: ctx.user_id_hmac.clone(),
            team_id: String::new(),
            device_id_hash: ctx.device_id.clone(),
            endpoint_hash: String::new(),
            capture_mode: CaptureMode::MetadataOnly,
            traffic_classification: TrafficClassification::ToolUsage,
            classification_source: ClassificationSource::Proxy,
            session_snapshot: None,
            declared_provider: None,
            declared_application: None,
            session_id: None,
            deployment_context: None,
            bundle_trust_level: None,
            precomputed_commitment_nonce: None,
            precomputed_commitment_hash: None,
        },
        transport: soth_core::TransportContext::default(),
        attribution: soth_core::AttributionContext {
            process_resolution: ProcessResolution {
                match_kind: ProcessMatchKind::Unknown,
                app_type: AppType::NonHost,
                capture_mode: Some(CaptureMode::MetadataOnly),
                process_name: None,
                bundle_id: None,
                matched_app_id: None,
                ..Default::default()
            },
            product_id: None,
            surface_type: SurfaceType::Unknown,
            is_shadow_it: false,
        },
    }
}

/// Attempt to load the classify bundle from the bundle directory.
fn load_classify_bundle(bundle_path: &Path) -> Option<Arc<ClassifyBundle>> {
    match soth_classify::load_bundle(bundle_path) {
        Ok(bundle) => Some(bundle),
        Err(_) => {
            // Fall back to the built-in fallback bundle (no ONNX model,
            // but heuristic stages still work).
            Some(soth_classify::fallback_bundle())
        }
    }
}
