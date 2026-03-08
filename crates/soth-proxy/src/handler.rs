use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{
    atomic::{AtomicBool, AtomicI64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use bytes::Bytes;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::sync::oneshot::error::TryRecvError;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::classify_task;
use crate::config::PipelineConfig;
use crate::gating::GateEvaluator;
use crate::pending::{PendingCapture, PendingStore};
use crate::response;
use crate::session::SessionManager;
use crate::streaming::StreamingStore;

const EMBEDDING_RETENTION_DAYS: u32 = 90;
const EMBEDDING_CLEANUP_INTERVAL_SECS: i64 = 24 * 60 * 60;

#[derive(Clone)]
pub struct ProxyHandler {
    bundle_handle: soth_bundle::BundleHandle,
    parser_registry: Arc<ArcSwap<soth_detect::ParserRegistry>>,
    gate_evaluator: Arc<ArcSwap<GateEvaluator>>,
    session_store: Arc<SessionManager>,
    pending: Arc<PendingStore>,
    streaming: Arc<StreamingStore>,
    telemetry: Option<Arc<soth_telemetry::TelemetryPipeline>>,
    db: Arc<Mutex<rusqlite::Connection>>,
    classify_runtime: Arc<crate::classify_task::Runtime>,
    pipeline_config: Arc<PipelineConfig>,
    classify_config: Arc<soth_classify::ClassifyConfig>,
    last_embedding_cleanup_epoch: Arc<AtomicI64>,
    org_id: String,
    team_id: String,
    device_id_hash: String,
    user_hmac_secret: Arc<String>,
}

impl ProxyHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bundle_handle: soth_bundle::BundleHandle,
        telemetry: Option<Arc<soth_telemetry::TelemetryPipeline>>,
        db: Arc<Mutex<rusqlite::Connection>>,
        pipeline_config: PipelineConfig,
        classify_config: soth_classify::ClassifyConfig,
        classify_runtime_config: crate::classify_task::RuntimeConfig,
        org_id: String,
        team_id: String,
        device_id_hash: String,
        user_hmac_secret: String,
    ) -> Self {
        let initial_bundle = bundle_handle.current();
        crate::heartbeat_telemetry::record_bundle_trust_level(initial_bundle.trust_level);
        let initial_parser_registry = build_parser_registry(initial_bundle.detect.as_ref());
        let initial_gate_evaluator = GateEvaluator::new(initial_bundle.gating.clone());
        let classify_runtime =
            crate::classify_task::Runtime::new(db.clone(), classify_runtime_config);
        Self {
            bundle_handle,
            parser_registry: Arc::new(ArcSwap::from_pointee(initial_parser_registry)),
            gate_evaluator: Arc::new(ArcSwap::from_pointee(initial_gate_evaluator)),
            session_store: Arc::new(SessionManager::new(pipeline_config.session.clone())),
            pending: Arc::new(PendingStore::new()),
            streaming: Arc::new(StreamingStore::new()),
            telemetry,
            db,
            classify_runtime,
            pipeline_config: Arc::new(pipeline_config),
            classify_config: Arc::new(classify_config),
            last_embedding_cleanup_epoch: Arc::new(AtomicI64::new(0)),
            org_id,
            team_id,
            device_id_hash,
            user_hmac_secret: Arc::new(user_hmac_secret),
        }
    }

    pub fn maintenance_tick(&self) {
        self.gate_evaluator.load().maintenance_tick();
        self.pending.evict_stale(Duration::from_secs(300));
        self.streaming.evict_stale(Duration::from_secs(300));
        self.session_store.evict_stale();
        self.expire_embeddings_if_due();
    }

    fn expire_embeddings_if_due(&self) {
        let now = chrono::Utc::now().timestamp();
        let last = self.last_embedding_cleanup_epoch.load(Ordering::Relaxed);
        if now.saturating_sub(last) < EMBEDDING_CLEANUP_INTERVAL_SECS {
            return;
        }

        if self
            .last_embedding_cleanup_epoch
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        match crate::db::expire_embeddings(&self.db, EMBEDDING_RETENTION_DAYS) {
            Ok(expired_rows) => {
                if expired_rows > 0 {
                    tracing::debug!(
                        expired_rows,
                        retention_days = EMBEDDING_RETENTION_DAYS,
                        "expired old embeddings from local sqlite storage"
                    );
                }
            }
            Err(error) => {
                self.last_embedding_cleanup_epoch
                    .store(last, Ordering::Relaxed);
                warn!(
                    error = %error,
                    retention_days = EMBEDDING_RETENTION_DAYS,
                    "failed to run embedding retention cleanup"
                );
            }
        }
    }

    pub fn on_bundle_updated(&self, bundle: &soth_bundle::LoadedBundle) {
        crate::heartbeat_telemetry::record_bundle_trust_level(bundle.trust_level);
        let parser_registry = build_parser_registry(bundle.detect.as_ref());
        let gate_evaluator = GateEvaluator::new(bundle.gating.clone());
        self.gate_evaluator.store(Arc::new(gate_evaluator));
        self.parser_registry.store(Arc::new(parser_registry));
        tracing::info!(
            bundle_version = bundle.version,
            "bundle hot-swap applied; parser and gate evaluators rebuilt"
        );
    }

    async fn handle_request(&self, request: soth_mitm::RawRequest) -> soth_mitm::HandlerDecision {
        let mut req = mitm_request_to_core(&request);
        let connection_id = req.connection_meta.connection_id;
        let host = extract_host(
            req.headers.get("host").map(String::as_str),
            req.path.as_str(),
        );

        let bundle = self.bundle_handle.current();
        let detect_bundle = bundle.detect_slice();
        let outcome = self.gate_evaluator.load().evaluate_http(
            &req,
            &req.connection_meta.process_info,
            crate::gating::evaluator::GateOverrides {
                unknown_app_action: self
                    .pipeline_config
                    .unknown_app_action
                    .map(map_unknown_action),
                non_cataloged_host_action: self
                    .pipeline_config
                    .non_cataloged_host_action
                    .and_then(map_non_cataloged_action),
            },
        );
        crate::trace::http_gate(
            connection_id,
            req.method.as_str(),
            host.as_str(),
            req.path.as_str(),
            &outcome,
        );
        if self.pipeline_config.non_cataloged_host_action == Some(crate::config::GateAction::Block)
            && matches!(outcome.reason, soth_core::DecisionReason::NotInCatalog)
            && matches!(
                outcome.decision,
                soth_core::GateDecision::Skip | soth_core::GateDecision::Passthrough
            )
        {
            crate::trace::handler_decision(
                connection_id,
                "block",
                "non_cataloged_host_action override",
            );
            return soth_mitm::HandlerDecision::Block {
                status: 403,
                body: Bytes::from("host not in AI catalog"),
            };
        }

        match &outcome.decision {
            soth_core::GateDecision::Skip | soth_core::GateDecision::Passthrough => {
                crate::trace::handler_decision(connection_id, "allow", "gate skip/passthrough");
                return soth_mitm::HandlerDecision::Allow;
            }
            soth_core::GateDecision::Block { status, message } => {
                crate::trace::handler_decision(connection_id, "block", "gate block");
                return soth_mitm::HandlerDecision::Block {
                    status: *status,
                    body: Bytes::from(message.clone()),
                };
            }
            soth_core::GateDecision::Intercept => {}
        }

        let process_resolution =
            process_resolution_from_outcome(&outcome, req.connection_meta.process_info.as_ref());
        req.connection_meta.capture_mode = Some(outcome.capture_mode);
        req.connection_meta.matched_provider = outcome.matched_provider.clone();
        req.connection_meta.matched_application = outcome.matched_application.clone();
        req.connection_meta.app_identity = Some(build_app_identity(
            &process_resolution,
            outcome.matched_application.as_deref(),
        ));

        // Derive session key and bind this connection
        let session_key = self.session_store.derive_key(
            &process_resolution,
            outcome.matched_application.as_deref(),
        );
        self.session_store.get_or_create(&session_key);
        self.session_store
            .bind_connection(connection_id, session_key.clone());

        let original_body_len = req.body.len();
        let body_size_limit = self.pipeline_config.body_size_limit_bytes;
        let mut truncated_body_sizes = None;
        if req.body.len() > body_size_limit {
            truncated_body_sizes = Some((req.body.len(), body_size_limit));
            req.body = req.body.slice(..self.pipeline_config.body_size_limit_bytes);
        }

        let parser_registry = self.parser_registry.load();
        let pre_detect_snapshot = self.session_store.snapshot(&session_key);
        let mut detect_result =
            soth_detect::process_with_registry(parser_registry.as_ref(), &req, &detect_bundle, &pre_detect_snapshot);
        if let Some((actual_bytes, limit_bytes)) = truncated_body_sizes {
            let warning = soth_core::ParseWarning::BodyTruncated {
                actual_bytes: actual_bytes as u64,
                limit_bytes: limit_bytes as u64,
            };
            detect_result.warnings.push(warning.clone());
            detect_result.normalized.parse_warnings.push(warning);
            if matches!(detect_result.confidence, soth_core::ParseConfidence::Full) {
                detect_result.confidence = soth_core::ParseConfidence::Partial;
            }
            if matches!(
                detect_result.normalized.parse_confidence,
                soth_core::ParseConfidence::Full
            ) {
                detect_result.normalized.parse_confidence = soth_core::ParseConfidence::Partial;
            }
        }
        crate::trace::detect_summary(
            connection_id,
            original_body_len,
            truncated_body_sizes,
            &detect_result,
        );
        // Apply detect mutations to session and determine pipeline lane
        self.session_store
            .apply_detect_mutations(&session_key, &detect_result.session_mutations);
        let lane = crate::session::lane::determine_lane(&detect_result);

        let content_for_embedding = match lane {
            crate::session::Lane::CodeContextRepeat => None,
            _ => extract_content_for_embedding(&req.body),
        };

        let request_timestamp_ms = chrono::Utc::now().timestamp_millis();
        self.session_store
            .mark_request_started(&session_key, request_timestamp_ms);
        let session_snapshot = self.session_store.snapshot(&session_key);

        let proxy_ctx = soth_core::ProxyContext {
            org_id: self.org_id.clone(),
            user_id_hmac: build_user_id_hmac(
                &req.connection_meta,
                self.user_hmac_secret.as_bytes(),
            ),
            team_id: self.team_id.clone(),
            device_id_hash: self.device_id_hash.clone(),
            endpoint_hash: sha256_hex(format!("{}{}", host, req.path).as_bytes()),
            process_resolution,
            capture_mode: outcome.capture_mode,
            matched_provider: outcome.matched_provider.clone(),
            matched_application: outcome.matched_application.clone(),
            traffic_classification: outcome.traffic_classification,
            classification_source: soth_core::ClassificationSource::Proxy,
            session_snapshot: Some(session_snapshot),
            request_method: Some(map_request_method(req.method.as_str())),
            deployment_context: None,
            precomputed_commitment_nonce: None,
            precomputed_commitment_hash: None,
        };

        let raw_body_for_commitment = match outcome.capture_mode {
            soth_core::CaptureMode::MetadataOnly => None,
            _ => Some(req.body.clone()),
        };
        let raw_body_for_db = raw_body_for_commitment.clone();

        self.pending.insert(PendingCapture {
            connection_id,
            stored_at: Instant::now(),
            request_method: req.method.clone(),
            request_host: host.clone(),
            request_path: req.path.clone(),
            request_body_bytes: original_body_len,
            outcome: outcome.clone(),
            detect_result: detect_result.clone(),
            proxy_ctx: proxy_ctx.clone(),
            raw_body: raw_body_for_commitment,
        });

        let policy_block_enforced = Arc::new(AtomicBool::new(false));
        let mut block_rx = classify_task::spawn_classify_task(
            connection_id,
            detect_result,
            content_for_embedding,
            proxy_ctx,
            outcome.capture_mode,
            outcome.matched_provider.clone(),
            outcome.matched_application.clone(),
            raw_body_for_db,
            bundle.classify.clone(),
            bundle.policy.clone(),
            map_bundle_trust_level(bundle.trust_level),
            self.classify_config.clone(),
            policy_block_enforced.clone(),
            self.session_store.clone(),
            self.telemetry.clone(),
            self.classify_runtime.clone(),
            lane,
        );

        let timeout_ms = self.pipeline_config.block_signal_timeout_ms;
        if timeout_ms == 0 {
            match block_rx.try_recv() {
                Ok(kind) => {
                    if let soth_core::PolicyDecisionKind::Block { status, message } = kind {
                        policy_block_enforced.store(true, Ordering::Relaxed);
                        crate::trace::handler_decision(
                            connection_id,
                            "block",
                            "policy block signal immediate",
                        );
                        return soth_mitm::HandlerDecision::Block {
                            status,
                            body: Bytes::from(message),
                        };
                    }
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Closed) => {}
            }
            crate::trace::handler_decision(connection_id, "allow", "policy signal not ready");
            return soth_mitm::HandlerDecision::Allow;
        }

        match tokio::time::timeout(Duration::from_millis(timeout_ms), &mut block_rx).await {
            Ok(Ok(soth_core::PolicyDecisionKind::Block { status, message })) => {
                policy_block_enforced.store(true, Ordering::Relaxed);
                crate::trace::handler_decision(connection_id, "block", "policy block signal");
                soth_mitm::HandlerDecision::Block {
                    status,
                    body: Bytes::from(message),
                }
            }
            Ok(Ok(_)) => {
                crate::trace::handler_decision(connection_id, "allow", "policy non-block signal");
                soth_mitm::HandlerDecision::Allow
            }
            Ok(Err(_)) => {
                crate::trace::handler_decision(
                    connection_id,
                    "allow",
                    "policy signal channel closed",
                );
                soth_mitm::HandlerDecision::Allow
            }
            Err(_) => {
                crate::trace::handler_decision(connection_id, "allow", "policy signal timeout");
                soth_mitm::HandlerDecision::Allow
            }
        }
    }

    async fn handle_response(&self, response: soth_mitm::RawResponse) {
        let response = mitm_response_to_core(&response);
        let connection_id = response.connection_meta.connection_id;

        if self.streaming.contains(&connection_id) {
            return;
        }

        let Some(_pending) = self.pending.take(&connection_id) else {
            crate::trace::response_without_pending(
                connection_id,
                response.status,
                response.body.len(),
            );
            debug!(
                connection_id = %connection_id,
                status = response.status,
                response_body_bytes = response.body.len(),
                "response received without pending state; dropping usage update"
            );
            return;
        };

        let usage = response::extract_usage(response.body.as_ref());
        crate::trace::response_usage(connection_id, usage.as_ref());
        if let Some(usage) = usage {
            self.session_store
                .apply_response_usage(connection_id, &usage);
        }
    }

    async fn handle_stream_chunk(&self, chunk: soth_mitm::StreamChunk) {
        let chunk = mitm_stream_chunk_to_core(&chunk);

        if let Some(pending) = self.pending.take(&chunk.connection_id) {
            self.streaming.start_stream(pending);
        }

        self.streaming.on_chunk(&chunk);
    }

    async fn handle_stream_end(&self, connection_id: Uuid) {
        let Some(completed) = self.streaming.take(&connection_id) else {
            if let Some(pending) = self.pending.take(&connection_id) {
                let pending_age_ms = pending.stored_at.elapsed().as_millis();
                let stored_raw_body_bytes = pending
                    .raw_body
                    .as_ref()
                    .map(|body| body.len())
                    .unwrap_or_default();
                crate::trace::stream_finalized_without_chunks(
                    connection_id,
                    pending.request_method.as_str(),
                    pending.request_host.as_str(),
                    pending.request_path.as_str(),
                    pending.request_body_bytes,
                    stored_raw_body_bytes,
                    pending_age_ms,
                    pending.outcome.capture_mode,
                    pending.outcome.matched_provider.as_deref(),
                    pending.outcome.matched_application.as_deref(),
                    &pending.detect_result.parse_source,
                    pending.detect_result.normalized.parser_id.as_str(),
                );
                warn!(
                    connection_id = %connection_id,
                    method = pending.request_method,
                    host = pending.request_host,
                    path = pending.request_path,
                    request_body_bytes = pending.request_body_bytes,
                    stored_raw_body_bytes,
                    pending_age_ms = pending_age_ms as u64,
                    capture_mode = ?pending.outcome.capture_mode,
                    matched_provider = pending.outcome.matched_provider.as_deref().unwrap_or("unknown"),
                    matched_application = pending.outcome.matched_application.as_deref().unwrap_or("unknown"),
                    parse_source = ?pending.detect_result.parse_source,
                    parser_id = pending
                        .detect_result
                        .normalized
                        .parser_id
                        .as_str(),
                    "stream finalized without chunks; dropped pending request before response usage"
                );
            }
            return;
        };

        if let Some(usage) = completed.usage {
            self.session_store
                .apply_response_usage(connection_id, &usage);
        }

        if completed.chunk_count == 0 {
            warn!(connection_id = %connection_id, "stream closed without chunks");
        }
    }
}

impl soth_mitm::InterceptHandler for ProxyHandler {
    fn should_intercept_tls(
        &self,
        host: &str,
        _process_info: Option<&soth_mitm::ProcessInfo>,
    ) -> bool {
        let decision = self.gate_evaluator.load().evaluate_tls(host);
        crate::trace::tls_gate(host, &decision);
        matches!(decision, soth_core::GateDecision::Intercept)
    }

    fn on_request(
        &self,
        request: &soth_mitm::RawRequest,
    ) -> impl Future<Output = soth_mitm::HandlerDecision> + Send {
        let request = request.clone();
        async move { self.handle_request(request).await }
    }

    fn on_tls_failure(&self, host: &str, error: &str) {
        warn!(
            host = host,
            error = error,
            "tls interception failed; continuing without interception"
        );
    }

    fn on_stream_chunk(&self, chunk: &soth_mitm::StreamChunk) -> impl Future<Output = ()> + Send {
        let chunk = chunk.clone();
        async move { self.handle_stream_chunk(chunk).await }
    }

    fn on_stream_end(&self, connection_id: Uuid) -> impl Future<Output = ()> + Send {
        async move { self.handle_stream_end(connection_id).await }
    }

    fn on_response(&self, response: &soth_mitm::RawResponse) -> impl Future<Output = ()> + Send {
        let response = response.clone();
        async move { self.handle_response(response).await }
    }

    fn on_connection_close(&self, connection_id: Uuid) {
        let had_pending = self.pending.remove(&connection_id);
        let had_streaming = self.streaming.remove(&connection_id);
        let _ = self.session_store.unbind_connection(&connection_id);
        if had_pending || had_streaming {
            tracing::debug!(
                connection_id = %connection_id,
                had_pending,
                had_streaming,
                "connection closed with in-memory handler state; cleaned up"
            );
        }
    }
}

fn extract_host(header_host: Option<&str>, path: &str) -> String {
    if let Some(host) = header_host {
        let host = host.split(':').next().unwrap_or(host).trim();
        if !host.is_empty() {
            return host.to_ascii_lowercase();
        }
    }

    if let Some((_, rest)) = path.split_once("://") {
        let host = rest.split('/').next().unwrap_or(rest);
        let host = host.split(':').next().unwrap_or(host);
        return host.trim().to_ascii_lowercase();
    }

    "unknown".to_string()
}

fn extract_content_for_embedding(body: &Bytes) -> Option<String> {
    std::str::from_utf8(body.as_ref())
        .ok()
        .map(std::string::ToString::to_string)
}

fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

type HmacSha256 = Hmac<Sha256>;

fn build_user_id_hmac(meta: &soth_core::ConnectionMeta, secret: &[u8]) -> String {
    let pid = meta
        .process_info
        .as_ref()
        .and_then(|info| info.pid)
        .unwrap_or_default();
    let process_name = meta
        .process_info
        .as_ref()
        .and_then(|info| info.process_name.as_deref())
        .unwrap_or("unknown");
    let bundle_id = meta
        .process_info
        .as_ref()
        .and_then(|info| info.bundle_id.as_deref())
        .unwrap_or("unknown");
    let identity = format!("pid={pid}|process={process_name}|bundle={bundle_id}");
    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        return sha256_hex(identity.as_bytes());
    };
    mac.update(identity.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn process_resolution_from_outcome(
    outcome: &soth_core::GateOutcome,
    process_info: Option<&soth_core::ProcessInfo>,
) -> soth_core::ProcessResolution {
    let process_name = process_info.and_then(|info| info.process_name.clone());
    let bundle_id = process_info.and_then(|info| info.bundle_id.clone());
    let match_kind = if outcome.app_type == soth_core::AppType::Unknown {
        soth_core::ProcessMatchKind::Unknown
    } else if bundle_id.is_some() {
        soth_core::ProcessMatchKind::Exact
    } else if process_name.is_some() {
        soth_core::ProcessMatchKind::Pattern
    } else {
        soth_core::ProcessMatchKind::Unknown
    };

    soth_core::ProcessResolution {
        match_kind,
        app_type: outcome.app_type,
        capture_mode: Some(outcome.capture_mode),
        process_name,
        bundle_id,
    }
}

fn map_unknown_action(action: crate::config::GateAction) -> soth_core::UnknownAppAction {
    match action {
        crate::config::GateAction::Skip => soth_core::UnknownAppAction::Skip,
        crate::config::GateAction::Intercept => soth_core::UnknownAppAction::Intercept,
        crate::config::GateAction::Block => soth_core::UnknownAppAction::Block,
    }
}

fn map_non_cataloged_action(
    action: crate::config::GateAction,
) -> Option<soth_core::NonCatalogedAction> {
    match action {
        crate::config::GateAction::Skip => Some(soth_core::NonCatalogedAction::Skip),
        crate::config::GateAction::Intercept => Some(soth_core::NonCatalogedAction::Passthrough),
        crate::config::GateAction::Block => Some(soth_core::NonCatalogedAction::Skip),
    }
}

fn build_app_identity(
    process_resolution: &soth_core::ProcessResolution,
    matched_application: Option<&str>,
) -> soth_core::AppIdentity {
    let app_id = matched_application
        .map(std::string::ToString::to_string)
        .or_else(|| process_resolution.bundle_id.clone())
        .or_else(|| process_resolution.process_name.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let app_kind = process_resolution.app_type.to_app_kind();

    soth_core::AppIdentity {
        app_id: app_id.clone(),
        display_name: app_id,
        app_kind,
        is_known: process_resolution.match_kind != soth_core::ProcessMatchKind::Unknown,
        confidence: if process_resolution.match_kind == soth_core::ProcessMatchKind::Unknown {
            0.0
        } else {
            1.0
        },
    }
}

fn map_request_method(method: &str) -> soth_core::RequestMethod {
    match method.to_ascii_uppercase().as_str() {
        "GET" => soth_core::RequestMethod::Get,
        "POST" => soth_core::RequestMethod::Post,
        "PUT" => soth_core::RequestMethod::Put,
        "PATCH" => soth_core::RequestMethod::Patch,
        "DELETE" => soth_core::RequestMethod::Delete,
        "HEAD" => soth_core::RequestMethod::Head,
        "OPTIONS" => soth_core::RequestMethod::Options,
        _ => soth_core::RequestMethod::Unknown,
    }
}

fn map_bundle_trust_level(level: soth_bundle::BundleTrustLevel) -> soth_core::BundleTrustLevel {
    match level {
        soth_bundle::BundleTrustLevel::Verified => soth_core::BundleTrustLevel::Verified,
        soth_bundle::BundleTrustLevel::Unverified => soth_core::BundleTrustLevel::Unverified,
        soth_bundle::BundleTrustLevel::SignatureDisabled => {
            soth_core::BundleTrustLevel::SignatureDisabled
        }
    }
}

fn build_parser_registry(bundle: &soth_detect::OwnedDetectBundle) -> soth_detect::ParserRegistry {
    // Rebuild parser registry from the active detect bundle to honor hot-swapped parsing state.
    match soth_detect::build_registry(&bundle.as_slice()) {
        Ok(registry) => registry,
        Err(error) => {
            warn!(
                error = %error,
                "failed to build parser registry from bundle; falling back to default"
            );
            soth_detect::ParserRegistry::default()
        }
    }
}

fn mitm_request_to_core(request: &soth_mitm::RawRequest) -> soth_core::RawRequest {
    soth_core::RawRequest {
        method: request.method.clone(),
        path: request.path.clone(),
        headers: mitm_headers_to_core(&request.headers),
        body: request.body.clone(),
        connection_meta: mitm_connection_meta_to_core(request.connection_meta.as_ref()),
    }
}

fn mitm_response_to_core(response: &soth_mitm::RawResponse) -> soth_core::RawResponse {
    soth_core::RawResponse {
        status: response.status,
        headers: mitm_headers_to_core(&response.headers),
        body: response.body.clone(),
        connection_meta: mitm_connection_meta_to_core(response.connection_meta.as_ref()),
    }
}

fn mitm_stream_chunk_to_core(chunk: &soth_mitm::StreamChunk) -> soth_core::StreamChunk {
    soth_core::StreamChunk {
        connection_id: chunk.connection_id,
        payload: chunk.payload.clone(),
        sequence: chunk.sequence,
        frame_kind: match chunk.frame_kind {
            soth_mitm::FrameKind::SseData => soth_core::FrameKind::SseData,
            soth_mitm::FrameKind::NdjsonLine => soth_core::FrameKind::NdjsonLine,
            soth_mitm::FrameKind::GrpcMessage => soth_core::FrameKind::GrpcMessage,
            soth_mitm::FrameKind::WebSocketText => soth_core::FrameKind::WebSocketText,
            soth_mitm::FrameKind::WebSocketBinary => soth_core::FrameKind::WebSocketBinary,
            soth_mitm::FrameKind::WebSocketClose => soth_core::FrameKind::WebSocketClose,
        },
    }
}

fn mitm_headers_to_core(headers: &http::HeaderMap) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (name, value) in headers {
        if let Ok(value) = value.to_str() {
            out.insert(name.as_str().to_ascii_lowercase(), value.to_string());
        }
    }
    out
}

fn mitm_connection_meta_to_core(meta: &soth_mitm::ConnectionMeta) -> soth_core::ConnectionMeta {
    soth_core::ConnectionMeta {
        connection_id: meta.connection_id,
        socket_family: mitm_socket_family_to_core(&meta.socket_family),
        process_info: meta.process_info.as_ref().map(mitm_process_info_to_core),
        tls_info: meta.tls_info.as_ref().map(|info| soth_core::TlsInfo {
            sni: info.sni.clone(),
            alpn: info.negotiated_proto.clone(),
            protocol: None,
        }),
        app_identity: None,
        capture_mode: None,
        matched_provider: None,
        matched_application: None,
    }
}

fn mitm_socket_family_to_core(family: &soth_mitm::SocketFamily) -> soth_core::SocketFamily {
    match family {
        soth_mitm::SocketFamily::TcpV4 { local, remote } => soth_core::SocketFamily::TcpV4 {
            local: *local,
            remote: *remote,
        },
        soth_mitm::SocketFamily::TcpV6 { local, remote } => soth_core::SocketFamily::TcpV6 {
            local: *local,
            remote: *remote,
        },
        soth_mitm::SocketFamily::UnixDomain { path } => {
            soth_core::SocketFamily::UnixDomain { path: path.clone() }
        }
    }
}

fn mitm_process_info_to_core(info: &soth_mitm::ProcessInfo) -> soth_core::ProcessInfo {
    soth_core::ProcessInfo {
        pid: Some(info.pid),
        process_name: info.exe_name.clone(),
        bundle_id: info.bundle_id.clone(),
        parent_pid: info.parent_pid,
        parent_process_name: None,
        parent_bundle_id: None,
    }
}
