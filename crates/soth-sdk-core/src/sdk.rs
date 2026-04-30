//! `SothSdk` facade — the surface bindings consume.
//!
//! `pre_call` is synchronous (≤5 ms p99 budget per spec §7.1):
//!   1. Build a `DetectResult` via `process_normalized` (artifact scan +
//!      session dedup; no embedding, no classification).
//!   2. Run system rules conditioned on artifacts to make a sync block
//!      decision.
//!   3. Allocate a `DecisionToken` slab slot for the post-call enrichment.
//!
//! `post_call` is the async-ish enrichment (≤300 ms p99 budget §7.2):
//!   1. Consume the slab slot.
//!   2. Run the full classify pipeline (embed → cluster → use_case →
//!      semantic anomaly).
//!   3. Apply label-conditioned org rules.
//!   4. Push a `TelemetryEvent` onto the in-memory queue.
//!
//! For v0, the post_call enrichment uses the classify fallback bundle,
//! so use_case_label is heuristic. Phase-1 wires real bundle pulls
//! and Phase-2 brings the WASM cloud-classify path online.

use std::sync::Arc;

use arc_swap::ArcSwap;
use soth_core::{
    AttributionContext, CaptureMode, ClassificationSource, IdentityContext, OwnedDetectBundle,
    ProxyContext, SessionSnapshot, TrafficClassification, TransportContext,
};

use crate::call::{LlmCall, LlmChunk, LlmResponse};
use crate::config::{BundleSource, ClassificationMode, SdkConfig};
use crate::decision::{
    BlockReason, BudgetKind, Decision, DecisionToken, FlagSeverity, MessageRedactions,
};
use crate::error::SdkError;
use crate::slab::{ArtifactsSummary, DecisionContext, DecisionSlab};
use crate::telemetry_queue::TelemetryQueue;

/// Per-call observation handle returned by `pre_call`. Currently
/// transparent over `DecisionToken`; reserved for richer state in
/// Phase 1 (e.g. carrying OTel span context across the FFI boundary).
#[derive(Debug, Clone, Copy)]
pub struct Observation {
    pub token: DecisionToken,
}

/// Streaming counterpart to `Observation`. Bindings call
/// `stream_chunk` once per chunk and `stream_end` to finalize.
pub struct StreamObservation {
    pub token: DecisionToken,
    chunks_seen: u32,
    accumulated_content: String,
    finish_reason: Option<String>,
}

impl StreamObservation {
    fn new(token: DecisionToken) -> Self {
        Self {
            token,
            chunks_seen: 0,
            accumulated_content: String::new(),
            finish_reason: None,
        }
    }
}

/// Main SDK type. `Send + Sync` — bindings stash `Arc<SothSdk>` and
/// invoke from arbitrary host threads.
pub struct SothSdk {
    config: SdkConfig,
    detect_registry: Arc<soth_detect::ParserRegistry>,
    detect_bundle: ArcSwap<OwnedDetectBundle>,
    classify_bundle: ArcSwap<soth_classify::ClassifyBundle>,
    classify_config: soth_classify::ClassifyConfig,
    slab: Arc<DecisionSlab>,
    telemetry: Arc<TelemetryQueue>,
    /// Background HTTPS shipper (when `http-telemetry` feature is on
    /// AND `telemetry_endpoint` is configured). Held in a Mutex so
    /// `shutdown` can take ownership and stop the thread cleanly; the
    /// field is read indirectly via that path.
    #[cfg(feature = "http-telemetry")]
    #[allow(dead_code)]
    shipper: std::sync::Mutex<Option<crate::shipper::TelemetryShipper>>,
}

// `SothSdk` must be `Send + Sync` for bindings to share it across host
// threads. Compile-time check — same pattern as PR 4.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SothSdk>();
    assert_send_sync::<Observation>();
};

impl SothSdk {
    /// Construct a new SDK instance from a [`SdkConfig`].
    ///
    /// Failure modes (per spec §7.4): bundle pull / verification
    /// failure logs and returns an error; the binding's wrapper SHOULD
    /// fall back to no-op mode rather than crashing the host process.
    pub fn init(config: SdkConfig) -> Result<Self, SdkError> {
        // Validate the HMAC key resolves before we accept the config.
        // Resolved bytes are dropped immediately — Phase 1 keeps them
        // for telemetry signing, v0 only validates.
        let _hmac = config.hmac_key.resolve()?;

        // ClassificationMode::Full + onnx-models feature-off would be a
        // mismatch; bindings on size-constrained targets must pick
        // Reduced or CloudOptIn.
        #[cfg(not(feature = "onnx-models"))]
        if matches!(config.local_classification, ClassificationMode::Full) {
            return Err(SdkError::OnnxUnavailable);
        }

        let detect_bundle = build_detect_bundle(&config.bundle_source)?;
        let detect_registry = Arc::new(soth_detect::ParserRegistry::default());

        let classify_bundle = match config.bundle_source {
            BundleSource::Fallback | BundleSource::Embedded => soth_classify::fallback_bundle(),
            BundleSource::Cdn { ref url } => {
                tracing::warn!(
                    target: "soth_sdk_core",
                    url,
                    "bundle CDN pull is a Phase-1 deliverable; using fallback bundle for v0"
                );
                soth_classify::fallback_bundle()
            }
        };

        let classify_config = soth_classify::ClassifyConfig::default();

        let telemetry = Arc::new(TelemetryQueue::new());
        #[cfg(feature = "http-telemetry")]
        let shipper = if let Some(endpoint) = config.telemetry_endpoint.clone() {
            Some(crate::shipper::TelemetryShipper::spawn(
                Arc::clone(&telemetry),
                endpoint,
                config.api_key.clone(),
                config.org_id.clone(),
            ))
        } else {
            None
        };

        Ok(Self {
            config,
            detect_registry,
            detect_bundle: ArcSwap::from_pointee(detect_bundle),
            classify_bundle: ArcSwap::from_pointee((*classify_bundle).clone()),
            classify_config,
            slab: Arc::new(DecisionSlab::new()),
            telemetry,
            #[cfg(feature = "http-telemetry")]
            shipper: std::sync::Mutex::new(shipper),
        })
    }

    /// Test-only constructor that bypasses [`init`]'s bundle-source dispatch.
    /// The conformance harness uses this to isolate facade-vs-direct-crate
    /// parity from bundle-source differences. Not stable; not part of the
    /// customer-facing API. Phase-1 `init` will gain an in-memory
    /// `BundleSource` variant that subsumes this constructor.
    #[doc(hidden)]
    pub fn for_test(
        config: SdkConfig,
        detect_bundle: OwnedDetectBundle,
        classify_bundle: Arc<soth_classify::ClassifyBundle>,
    ) -> Result<Self, SdkError> {
        let _hmac = config.hmac_key.resolve()?;
        Ok(Self {
            config,
            detect_registry: Arc::new(soth_detect::ParserRegistry::default()),
            detect_bundle: ArcSwap::from_pointee(detect_bundle),
            classify_bundle: ArcSwap::from_pointee((*classify_bundle).clone()),
            classify_config: soth_classify::ClassifyConfig::default(),
            slab: Arc::new(DecisionSlab::new()),
            telemetry: Arc::new(TelemetryQueue::new()),
            // Test ctor never spawns a shipper — fixtures don't have
            // a real cloud endpoint and we want CI hermetic.
            #[cfg(feature = "http-telemetry")]
            shipper: std::sync::Mutex::new(None),
        })
    }

    /// Synchronous decision path. Returns within 5 ms p99 (binding-side
    /// histograms gate this in CI).
    ///
    /// Allowed work (per spec §7.1):
    /// - artifact scan via `process_normalized`
    /// - artifact-conditioned system rules
    /// - artifact-conditioned org rules
    pub fn pre_call(&self, call: &LlmCall) -> Decision {
        let detect_bundle = self.detect_bundle.load_full();
        let detect = soth_detect::process_normalized(
            self.detect_registry.as_ref(),
            call,
            &detect_bundle.as_slice(),
            &SessionSnapshot::default(),
            self.config.capture_mode,
        );

        let summary = ArtifactsSummary::from_artifacts(&detect.artifacts);

        // Sync block path — credential / private-key artifacts are an
        // unconditional block in v0. Phase-1 expands this with full
        // org-rule evaluation on artifact-conditioned rules.
        if let Some(reason) = detect.artifacts.iter().find_map(|a| {
            artifact_block_reason(&a.kind, a.severity)
        }) {
            let ctx = DecisionContext {
                created_at: std::time::Instant::now(),
                generation: 0,
                detect: detect.clone(),
                artifacts_summary: summary.clone(),
                call_provider: call.provider.clone(),
                call_model: call.model.clone(),
                user_content: detect.normalized.user_prompt.clone(),
            };
            let token = self.slab.allocate(ctx);
            return Decision::Block { token, reason };
        }

        // Allow path — stash the partial state for post_call enrichment.
        let ctx = DecisionContext {
            created_at: std::time::Instant::now(),
            generation: 0,
            detect,
            artifacts_summary: summary,
            call_provider: call.provider.clone(),
            call_model: call.model.clone(),
            user_content: None, // populated on consume; we cloned detect so re-derive there
        };
        let token = self.slab.allocate(ctx);
        Decision::Allow { token }
    }

    /// Async-ish enrichment + telemetry emission. Bindings spawn this
    /// off the host's critical path. Idempotent on sentinel tokens
    /// (no-op).
    pub fn post_call(&self, token: DecisionToken, _resp: &LlmResponse) {
        let Some(ctx) = self.slab.consume(token) else {
            // Token is sentinel, stale, or already consumed. Emit a
            // tagged telemetry event so cluster operators can
            // distinguish "binding bug" from "slab pressure".
            self.emit_orphan_or_full(token);
            return;
        };

        let proxy_ctx = self.build_proxy_context(&ctx);
        let user_content = ctx.detect.normalized.user_prompt.clone();
        let classify_bundle = self.classify_bundle.load_full();
        let result = soth_classify::classify(
            &ctx.detect,
            user_content.as_deref(),
            &proxy_ctx,
            &classify_bundle,
            &self.classify_config,
        );

        self.telemetry.push(result.telemetry_event);
    }

    /// Streaming counterpart to `pre_call`. Returns the decision and an
    /// observation handle for `stream_chunk` / `stream_end`.
    pub fn stream_begin(&self, call: &LlmCall) -> (Decision, StreamObservation) {
        let decision = self.pre_call(call);
        let token = decision.token();
        (decision, StreamObservation::new(token))
    }

    pub fn stream_chunk(&self, obs: &mut StreamObservation, chunk: &LlmChunk) {
        obs.chunks_seen = obs.chunks_seen.saturating_add(1);
        if let Some(delta) = &chunk.delta_content {
            obs.accumulated_content.push_str(delta);
        }
        if chunk.finish_reason.is_some() {
            obs.finish_reason = chunk.finish_reason.clone();
        }
    }

    pub fn stream_end(&self, obs: StreamObservation) {
        let mut response = LlmResponse::new(soth_core::EndpointType::ChatCompletion);
        response.assistant_content = if obs.accumulated_content.is_empty() {
            None
        } else {
            Some(obs.accumulated_content)
        };
        response.finish_reason = obs.finish_reason;
        self.post_call(obs.token, &response);
    }

    /// Pull a fresh bundle from the configured CDN, verify, and hot-swap.
    /// V0 stub — Phase 1 implements the actual transport.
    pub fn refresh_bundle(&self) -> Result<(), SdkError> {
        match &self.config.bundle_source {
            BundleSource::Fallback | BundleSource::Embedded => Ok(()),
            BundleSource::Cdn { url } => {
                tracing::warn!(
                    target: "soth_sdk_core",
                    url,
                    "bundle refresh is a Phase-1 deliverable"
                );
                Ok(())
            }
        }
    }

    // ── test helpers ─────────────────────────────────────────────────

    /// Number of in-flight `DecisionToken`s. Used by the smoke test
    /// to assert pre_call/post_call balance.
    pub fn in_flight_decisions(&self) -> usize {
        self.slab.in_flight()
    }

    /// Drain the in-memory telemetry queue. Test-only — production
    /// shippers will pull batches via a different API in Phase 1.
    pub fn drain_telemetry_for_test(&self) -> Vec<soth_core::TelemetryEvent> {
        self.telemetry.drain_for_test()
    }

    fn build_proxy_context(&self, ctx: &DecisionContext) -> ProxyContext {
        ProxyContext {
            identity: IdentityContext {
                org_id: self.config.org_id.clone(),
                user_id_hmac: self
                    .config
                    .default_team_id
                    .clone()
                    .unwrap_or_else(|| String::from("sdk-anonymous")),
                team_id: self.config.default_team_id.clone().unwrap_or_default(),
                device_id_hash: self
                    .config
                    .default_device_id_hash
                    .clone()
                    .unwrap_or_default(),
                endpoint_hash: String::new(),
                capture_mode: self.config.capture_mode,
                traffic_classification: TrafficClassification::ToolUsage,
                classification_source: ClassificationSource::Sdk,
                session_snapshot: Some(SessionSnapshot::default()),
                declared_provider: Some(ctx.call_provider.clone()),
                declared_application: None,
                session_id: None,
                deployment_context: None,
                bundle_trust_level: None,
                precomputed_commitment_nonce: None,
                precomputed_commitment_hash: None,
            },
            transport: TransportContext::default(),
            attribution: AttributionContext::default(),
        }
    }

    /// Stop the background telemetry shipper (if any) and flush
    /// pending events. Bindings call this at process exit so events
    /// buffered in the last batch window aren't lost. Idempotent.
    pub fn shutdown(&self) {
        #[cfg(feature = "http-telemetry")]
        {
            let mut guard = match self.shipper.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if let Some(mut shipper) = guard.take() {
                shipper.shutdown();
            }
        }
    }

    fn emit_orphan_or_full(&self, token: DecisionToken) {
        if token == DecisionToken::SLAB_FULL {
            tracing::warn!(
                target: "soth_sdk_core",
                "post_call invoked with SLAB_FULL token — slab pressure; size up the SDK"
            );
        } else if token == DecisionToken::SENTINEL_FAIL_OPEN {
            tracing::warn!(
                target: "soth_sdk_core",
                "post_call invoked with SENTINEL_FAIL_OPEN token — pre_call panicked at FFI boundary"
            );
        } else {
            tracing::warn!(
                target: "soth_sdk_core",
                token = token.inner,
                "post_call invoked with stale/already-consumed token (binding bug)"
            );
        }
    }
}

fn artifact_block_reason(
    kind: &soth_core::ArtifactKind,
    severity: soth_core::ArtifactSeverity,
) -> Option<BlockReason> {
    use soth_core::{ArtifactKind, ArtifactSeverity};
    match kind {
        ArtifactKind::PrivateKey => Some(BlockReason::SensitiveArtifact {
            artifact: kind.clone(),
            severity,
        }),
        ArtifactKind::ApiKey { .. } if severity >= ArtifactSeverity::High => {
            Some(BlockReason::SensitiveArtifact {
                artifact: kind.clone(),
                severity,
            })
        }
        _ => None,
    }
}

fn build_detect_bundle(source: &BundleSource) -> Result<OwnedDetectBundle, SdkError> {
    // V0: every BundleSource variant resolves to the empty bundle.
    // Phase-1 wires real CDN pull + verification per
    // SDK_WASM_TRUST_BOUNDARY_SPEC.md §6.
    let _ = source;
    Ok(OwnedDetectBundle::default())
}

// Re-exports above keep these types used. Phase-1 hooks for budget /
// flag / redact / capture-mode / classification-mode are wired in
// then; v0 references them via `BlockReason::*` in artifact_block_reason
// and via the public type re-exports.
#[allow(dead_code)]
fn _typecheck_unused_for_v0() {
    let _: Option<BudgetKind> = None;
    let _: Option<FlagSeverity> = None;
    let _: Option<MessageRedactions> = None;
    let _: Option<ClassificationMode> = None;
    let _: Option<CaptureMode> = None;
}
