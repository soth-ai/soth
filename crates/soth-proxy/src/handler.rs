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
use sha2::Sha256;
use tokio::sync::oneshot::error::TryRecvError;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::classify_task;
use crate::config::PipelineConfig;
use crate::gating::GateEvaluator;
use crate::pending::{PendingCapture, PendingStore};
use crate::pending_emit::{self, PendingEmitStore};
use crate::response::{self, UsageSummary};
use crate::session::SessionManager;
use crate::streaming::StreamingStore;

const EMBEDDING_RETENTION_DAYS: u32 = 90;
const EMBEDDING_CLEANUP_INTERVAL_SECS: i64 = 24 * 60 * 60;
/// Responses larger than this are not parsed for usage extraction.
/// LLM API non-streaming responses are typically < 256 KB.
const MAX_RESPONSE_BODY_PARSE_BYTES: usize = 512 * 1024;

#[derive(Clone)]
pub struct ProxyHandler {
    bundle_handle: soth_bundle::BundleHandle,
    parser_registry: Arc<ArcSwap<soth_detect::ParserRegistry>>,
    gate_evaluator: Arc<ArcSwap<GateEvaluator>>,
    /// Pre-built entity index for O(1) identity resolution.
    ///
    /// Swapped atomically alongside `parser_registry` and `gate_evaluator`
    /// whenever the bundle is hot-reloaded via `on_bundle_updated`.
    /// Populated from the native registry bundle when available; falls back
    /// to an empty index so the proxy functions correctly without it.
    entity_index: Arc<ArcSwap<soth_core::EntityIndex>>,
    /// Pre-built environment index mapping parent process identifiers to their
    /// `EnvironmentClass`.  Built from `detect.environments` at bundle load
    /// time.  Used for shadow-IT surface fallback and IdePlugin gating.
    env_index: Arc<ArcSwap<soth_core::EnvIndex>>,
    session_store: Arc<SessionManager>,
    pending: Arc<PendingStore>,
    pending_emit: Arc<PendingEmitStore>,
    streaming: Arc<StreamingStore>,
    telemetry: Option<Arc<soth_telemetry::TelemetryPipeline>>,
    observer_broadcast: Option<soth_core::ObserverBroadcast>,
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
        observer_broadcast: Option<soth_core::ObserverBroadcast>,
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
        // Seed the entity index from the initial bundle so host resolution
        // works immediately — before the first hot-reload fires.
        let initial_entity_index = initial_bundle.entity_index.clone();
        // Env index is seeded from the initial bundle's detect data so that
        // parent-environment lookups work even before the first hot-reload.
        let initial_env_index = (*initial_bundle.env_index).clone();
        let classify_runtime =
            crate::classify_task::Runtime::new(db.clone(), classify_runtime_config);
        Self {
            bundle_handle,
            parser_registry: Arc::new(ArcSwap::from_pointee(initial_parser_registry)),
            gate_evaluator: Arc::new(ArcSwap::from_pointee(initial_gate_evaluator)),
            entity_index: Arc::new(ArcSwap::new(initial_entity_index)),
            env_index: Arc::new(ArcSwap::from_pointee(initial_env_index)),
            session_store: Arc::new(SessionManager::new(pipeline_config.session.clone())),
            pending: Arc::new(PendingStore::new()),
            pending_emit: Arc::new(PendingEmitStore::new()),
            streaming: Arc::new(StreamingStore::new()),
            telemetry,
            observer_broadcast,
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

        // Bounded reap: scan at most 256 entries per tick to avoid GC pauses
        const MAX_REAP_SCAN: usize = 256;
        self.pending
            .evict_stale(Duration::from_secs(300), MAX_REAP_SCAN);
        self.streaming
            .evict_stale(Duration::from_secs(300), MAX_REAP_SCAN);
        self.session_store.evict_stale(MAX_REAP_SCAN);
        self.expire_embeddings_if_due();

        // Run retention + WAL checkpoint on the same daily cadence
        crate::db::enforce_retention(&self.db, self.pipeline_config.retention_days);
        crate::db::wal_checkpoint(&self.db);

        // Evict stale pending_emit entries (classify completed but response never arrived).
        // Emit classify-only telemetry for these so they are not lost.
        let stale_entries = self
            .pending_emit
            .evict_stale(Duration::from_secs(60), MAX_REAP_SCAN);
        for (connection_id, stale) in stale_entries {
            if let Some(mut classify_data) = stale.classify_data {
                // Stamp session metadata even without response data
                classify_data.telemetry_event.session_request_count =
                    Some(stale.session_request_count);
                classify_data.telemetry_event.session_total_tokens =
                    Some(stale.session_total_tokens);
                classify_data.telemetry_event.session_credential_alerts =
                    Some(stale.session_credential_alerts);
                classify_data.telemetry_event.conversation_turn = stale.conversation_turn;

                if let Some(ref pipeline) = self.telemetry {
                    pipeline.push(classify_data.telemetry_event.clone());
                }
                if let Some(ref broadcast) = self.observer_broadcast {
                    let pre = soth_core::PreEmitEvent::from_telemetry_event(
                        &classify_data.telemetry_event,
                        classify_data.anomaly_score,
                        &classify_data.anomaly_flags,
                        classify_data.policy_decision_kind,
                        classify_data.capture_mode,
                    );
                    broadcast(&pre);
                }
                debug!(
                    connection_id = %connection_id,
                    "emitted stale classify-only telemetry event (response never arrived)"
                );
            }
        }
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
        // Store the bundle's entity_index directly — it's already behind an Arc.
        self.entity_index.store(Arc::clone(&bundle.entity_index));
        self.on_bundle_updated_with_index(bundle, None);
    }

    /// Hot-swap bundle state, optionally installing a new `EntityIndex`.
    ///
    /// Pass `Some(index)` when the caller has already built an
    /// `EntityIndex` from the accompanying native registry bundle.
    /// Pass `None` to leave the existing index untouched (safe: the prior
    /// index, even if empty, continues to serve requests).
    pub fn on_bundle_updated_with_index(
        &self,
        bundle: &soth_bundle::LoadedBundle,
        entity_index: Option<soth_core::EntityIndex>,
    ) {
        crate::heartbeat_telemetry::record_bundle_trust_level(bundle.trust_level);
        let parser_registry = build_parser_registry(bundle.detect.as_ref());
        let gate_evaluator = GateEvaluator::new(bundle.gating.clone());
        self.gate_evaluator.store(Arc::new(gate_evaluator));
        self.parser_registry.store(Arc::new(parser_registry));
        if let Some(index) = entity_index {
            self.entity_index.store(Arc::new(index));
        }
        // env_index is always rebuilt from the bundle's detect data; no
        // separate optional path needed — every LoadedBundle carries one.
        self.env_index.store(Arc::clone(&bundle.env_index));
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
        let entity_index = self.entity_index.load();
        let env_index = self.env_index.load();
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
            Some(&detect_bundle),
            entity_index.as_ref(),
            env_index.as_ref(),
        );
        crate::trace::http_gate(
            connection_id,
            req.method.as_str(),
            host.as_str(),
            req.path.as_str(),
            &outcome,
        );
        if self.pipeline_config.non_cataloged_host_action == Some(crate::config::GateAction::Block)
            && matches!(outcome.reason, crate::gating::DecisionReason::NotInCatalog)
            && matches!(
                outcome.decision,
                crate::gating::GateDecision::Skip | crate::gating::GateDecision::Passthrough
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
            crate::gating::GateDecision::Skip | crate::gating::GateDecision::Passthrough => {
                crate::trace::handler_decision(connection_id, "allow", "gate skip/passthrough");
                return soth_mitm::HandlerDecision::Allow;
            }
            crate::gating::GateDecision::Block { status, message } => {
                crate::trace::handler_decision(connection_id, "block", "gate block");
                return soth_mitm::HandlerDecision::Block {
                    status: *status,
                    body: Bytes::from(message.clone()),
                };
            }
            crate::gating::GateDecision::Intercept => {}
        }

        let entity_index = self.entity_index.load();
        let process_resolution = process_resolution_from_outcome(
            &outcome,
            req.connection_meta.process_info.as_ref(),
            Some(entity_index.as_ref()),
        );
        req.connection_meta.capture_mode = Some(outcome.capture_mode);
        req.connection_meta.matched_provider = outcome.matched_provider.clone();
        req.connection_meta.matched_application = outcome.matched_application.clone();
        req.connection_meta.app_identity = Some(build_app_identity(
            &process_resolution,
            outcome.matched_application.as_deref(),
        ));

        // Product identity from entity resolution (entity slug = product_id).
        // IdePlugin gating is now enforced inside resolve_tool(): if the parent
        // is not an IDE-class environment, resolve_tool() returns None and we
        // fall through to the shadow IT branch below.
        let env_index = self.env_index.load();
        let parent_bundle_id = req
            .connection_meta
            .process_info
            .as_ref()
            .and_then(|info| info.parent_bundle_id.as_deref());
        let parent_process_name = req
            .connection_meta
            .process_info
            .as_ref()
            .and_then(|info| info.parent_process_name.as_deref());
        let resolved_tool = entity_index.resolve_tool(
            process_resolution.bundle_id.as_deref(),
            process_resolution.process_name.as_deref(),
            parent_bundle_id,
            parent_process_name,
            env_index.as_ref(),
        );
        let (product_id, surface_type) = match resolved_tool {
            Some((entity, _)) => (Some(entity.id.clone()), entity.kind.to_surface_type()),
            None => {
                // Process didn't match a catalog entity. Derive surface_type
                // from the parent environment so the telemetry record carries
                // meaningful context. Also handles the IdePlugin case where
                // the parent is not an IDE (resolve_tool returns None).
                let parent_env_class =
                    env_index.resolve_parent(parent_bundle_id, parent_process_name);
                let surface = env_class_to_surface(parent_env_class);
                (None, surface)
            }
        };

        // Look up the matched destination entity to determine whether the
        // proxy has a parser for it. matched_application is the specific
        // product (e.g. `chatgpt`); matched_provider is the underlying API
        // surface (e.g. `openai`). Prefer application — that's the slug the
        // catalog publishes parser coverage against.
        let dest_slug = outcome
            .matched_application
            .as_deref()
            .or(outcome.matched_provider.as_deref());
        let matched_with_parser =
            dest_slug.and_then(|slug| entity_index.get(slug).map(|e| e.api_format.is_some()));
        let is_shadow_it = determine_shadow_it(matched_with_parser);

        // Derive session key and bind this connection
        let session_key = self
            .session_store
            .derive_key(&process_resolution, outcome.matched_application.as_deref());
        let session_result = self.session_store.get_or_create(&session_key);
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
        let mut detect_result = soth_detect::process_with_registry(
            parser_registry.as_ref(),
            &req,
            &detect_bundle,
            &pre_detect_snapshot,
        );
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
        // Concise per-request debug line: model + key metadata.
        // Always visible at RUST_LOG=soth_proxy=debug.
        {
            let n = &detect_result.normalized;
            debug!(
                provider = n.provider.as_str(),
                model = n.model.as_deref().unwrap_or("-"),
                tokens = n.estimated_input_tokens,
                confidence = ?detect_result.confidence,
                artifacts = detect_result.artifacts.len(),
                host = host.as_str(),
                "{method} {path}",
                method = req.method,
                path = req.path,
            );
        }

        crate::trace::detect_summary(
            connection_id,
            original_body_len,
            truncated_body_sizes,
            &detect_result,
        );
        crate::heartbeat_telemetry::record_detect_latency_us(detect_result.detect_latency_us);
        crate::trace::dev_verify_request(
            connection_id,
            req.method.as_str(),
            host.as_str(),
            req.path.as_str(),
            req.body.as_ref(),
            &detect_result,
            outcome.capture_mode,
        );
        // Apply detect mutations to session and determine pipeline lane
        self.session_store
            .apply_detect_mutations(&session_key, &detect_result.session_mutations);
        let lane = crate::session::lane::determine_lane(&detect_result);

        let content_for_embedding = match lane {
            crate::session::Lane::CodeContextRepeat => None,
            // Prefer parsed content (system prompt + user message) over raw body.
            // Raw body includes JSON structure, API params, temperature, etc. that
            // would pollute the embedding vector.
            // Both paths are capped at MAX_EMBEDDING_INPUT_BYTES so the tokenizer
            // never scans more than ~1 000 tokens before truncating to 128.
            _ => detect_result
                .user_prompt
                .clone()
                .map(truncate_for_embedding)
                .or_else(|| extract_content_for_embedding(&req.body)),
        };

        let request_timestamp_ms = chrono::Utc::now().timestamp_millis();
        self.session_store
            .mark_request_started(&session_key, request_timestamp_ms);
        let session_snapshot = self.session_store.snapshot(&session_key);
        // Capture session metadata for PendingEmitStore before snapshot is moved.
        let emit_session_request_count = session_snapshot.request_count;
        let emit_session_total_tokens = session_snapshot.total_tokens;
        let emit_session_credential_alerts = session_snapshot.credential_alerts;

        let proxy_ctx = soth_core::ProxyContext {
            identity: soth_core::IdentityContext {
                org_id: self.org_id.clone(),
                user_id_hmac: build_user_id_hmac(
                    &req.connection_meta,
                    self.user_hmac_secret.as_bytes(),
                ),
                team_id: self.team_id.clone(),
                device_id_hash: self.device_id_hash.clone(),
                endpoint_hash: sha256_hex(format!("{}{}", host, req.path).as_bytes()),
                capture_mode: outcome.capture_mode,
                traffic_classification: outcome.traffic_classification,
                classification_source: soth_core::ClassificationSource::Proxy,
                session_snapshot: Some(session_snapshot),
                declared_provider: outcome.matched_provider.clone(),
                declared_application: outcome.matched_application.clone(),
                session_id: Some(session_result.session_id),
                deployment_context: None,
                bundle_trust_level: Some(soth_core::BundleTrustLevel::SignatureDisabled),
                precomputed_commitment_nonce: None,
                precomputed_commitment_hash: None,
            },
            transport: soth_core::TransportContext {
                connection_id: Some(connection_id),
                request_method: Some(map_request_method(req.method.as_str())),
                ja4_hash: req
                    .connection_meta
                    .tls_info
                    .as_ref()
                    .and_then(|t| t.ja4_hash.clone()),
                tls_version: req
                    .connection_meta
                    .tls_info
                    .as_ref()
                    .and_then(|t| t.tls_version.clone()),
                alpn_protocol: req
                    .connection_meta
                    .tls_info
                    .as_ref()
                    .and_then(|t| t.alpn.clone()),
                h2_connection_id: req
                    .connection_meta
                    .h2_connection_id
                    .as_ref()
                    .map(|u| u.to_string()),
                h2_stream_id: req.connection_meta.h2_stream_id,
            },
            attribution: soth_core::AttributionContext {
                process_resolution,
                product_id,
                surface_type,
                is_shadow_it,
            },
        };

        let raw_body_for_commitment = match outcome.capture_mode {
            soth_core::CaptureMode::MetadataOnly => None,
            _ => Some(req.body.clone()),
        };
        let raw_body_for_db = raw_body_for_commitment.clone();

        // Initialize the PendingEmitStore slot with session metadata snapshot.
        // Both classify_task and response handlers will deposit their halves here.
        self.pending_emit.init_slot(
            connection_id,
            emit_session_request_count,
            emit_session_total_tokens,
            emit_session_credential_alerts,
            detect_result.normalized.conversation_turn,
        );

        // Detect WebSocket upgrade intent from request headers.
        // When a WebSocket upgrade is in progress, the request body is empty so
        // detect produces garbage (provider=unknown, model=null).  Defer the
        // classify task until the first WebSocket frame arrives with real data.
        //
        // NOTE: soth-mitm strips the `Upgrade` header (hop-by-hop).  Use
        // `Sec-WebSocket-Version` which survives the strip pass and is
        // mandatory per RFC 6455 §4.1 for all WebSocket upgrade requests.
        let is_websocket_upgrade = req.headers.contains_key("sec-websocket-version");

        if is_websocket_upgrade {
            // Seed provider from gating metadata so the DB record isn't "unknown".
            if detect_result.normalized.provider == "unknown" {
                if let Some(ref mp) = outcome.matched_provider {
                    detect_result.normalized.provider = provider_from_matched(mp);
                }
            }
            detect_result.normalized.stream = true;
        }

        // Wrap in Arc after all mutations are complete. Cloning into PendingCapture
        // and ClassifyTaskInput is now a cheap refcount bump instead of a deep copy.
        let detect_result = Arc::new(detect_result);
        let proxy_ctx = Arc::new(proxy_ctx);

        // ── Phase 5: Insert PendingCapture (unified WS + HTTP path) ─────────
        let deferred_classify = if is_websocket_upgrade {
            Some(crate::pending::DeferredClassify {
                content_for_embedding: content_for_embedding.clone(),
                raw_body_for_db: raw_body_for_db.clone(),
                classify_bundle: bundle.classify.clone(),
                policy_bundle: bundle.policy.clone(),
                bundle_trust_level: bundle.trust_level,
                classify_config: self.classify_config.clone(),
                lane,
            })
        } else {
            None
        };

        self.pending.insert(PendingCapture {
            connection_id,
            stored_at: Instant::now(),
            request_method: req.method.clone(),
            request_host: host.clone(),
            request_path: req.path.clone(),
            request_body_bytes: original_body_len,
            outcome: outcome.clone(),
            detect_result: Arc::clone(&detect_result),
            proxy_ctx: Arc::clone(&proxy_ctx),
            raw_body: raw_body_for_commitment,
            deferred_classify,
            is_websocket: is_websocket_upgrade,
        });

        if is_websocket_upgrade {
            crate::trace::handler_decision(
                connection_id,
                "allow",
                "websocket upgrade; classify deferred to first frame",
            );
            return soth_mitm::HandlerDecision::Allow;
        }

        let policy_block_enforced = Arc::new(AtomicBool::new(false));
        let mut block_rx = classify_task::spawn_classify_task(classify_task::ClassifyTaskInput {
            connection_id,
            detect_result,
            content_for_embedding,
            proxy_ctx,
            capture_mode: outcome.capture_mode,
            matched_provider: outcome.matched_provider.clone(),
            matched_application: outcome.matched_application.clone(),
            raw_body_for_commitment: raw_body_for_db,
            classify_bundle: bundle.classify.clone(),
            policy_bundle: bundle.policy.clone(),
            bundle_trust_level: bundle.trust_level,
            classify_config: self.classify_config.clone(),
            policy_block_enforced: policy_block_enforced.clone(),
            session_store: self.session_store.clone(),
            telemetry: self.telemetry.clone(),
            observer_broadcast: self.observer_broadcast.clone(),
            runtime: self.classify_runtime.clone(),
            lane,
            pending_emit_store: Some(self.pending_emit.clone()),
        });

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

        let Some(pending) = self.pending.take(&connection_id) else {
            // Empty responses (e.g. 204 from DELETE) are expected for requests
            // that the gate skipped (method not allowed).  Only log at debug
            // when the response carried a body we're actually dropping.
            if response.body.is_empty() {
                tracing::trace!(
                    connection_id = %connection_id,
                    status = response.status,
                    "empty response without pending state (likely method-filtered); ignoring"
                );
            } else {
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
            }
            return;
        };

        let response_body_bytes = response.body.len();

        // For streaming responses (SSE, NDJSON) delivered via H2, on_response
        // fires with only headers (empty body).  Start the streaming store so
        // on_stream_chunk can accumulate payload, then let handle_stream_end /
        // finalize_completed_stream deposit the actual usage.
        let content_type = response.headers.get("content-type").map(String::as_str);
        let is_streaming_content = content_type
            .map(|ct| {
                ct.contains("text/event-stream")
                    || ct.contains("application/x-ndjson")
                    || ct.contains("application/grpc")
            })
            .unwrap_or(false);
        if is_streaming_content && response_body_bytes == 0 {
            self.streaming.start_stream(pending);
            tracing::debug!(
                connection_id = %connection_id,
                content_type = content_type.unwrap_or("-"),
                "streaming response detected; deferring usage to stream end",
            );
            return;
        }

        // Guard: skip expensive body parsing for heavy content types (video, audio,
        // images, archives, binaries) or oversized bodies.  These can reach the
        // handler when non-AI hosts are intercepted via discovery mode.
        let skip_body_parse = is_heavy_content_type(content_type)
            || response_body_bytes > MAX_RESPONSE_BODY_PARSE_BYTES;

        let mut usage = if skip_body_parse {
            None
        } else {
            response::extract_usage(response.body.as_ref())
        };
        let body_prefix = if response_body_bytes > 0 {
            let end = response_body_bytes.min(200);
            String::from_utf8_lossy(&response.body[..end]).to_string()
        } else {
            String::new()
        };

        // If no usage was parsed but we have a substantial response body,
        // estimate tokens from body size.  This covers providers like Gemini web
        // that use proprietary response formats without standard usage metadata.
        if usage.is_none() && !skip_body_parse && response_body_bytes > 256 {
            let estimated_output_tokens = estimate_output_tokens(response_body_bytes as u64);
            usage = Some(UsageSummary {
                input_tokens: pending.detect_result.normalized.estimated_input_tokens as u64,
                output_tokens: estimated_output_tokens,
                estimated_output_cost_usd: 0.0,
                finish_reason: None,
            });
        }

        crate::trace::response_usage(
            connection_id,
            usage.as_ref(),
            response.status,
            response_body_bytes,
            body_prefix.as_str(),
        );
        crate::trace::dev_verify_response(
            connection_id,
            response.status,
            response.body.as_ref(),
            usage.as_ref(),
            pending.detect_result.normalized.provider.as_str(),
            pending.detect_result.normalized.model.as_deref(),
        );
        if let Some(ref usage) = usage {
            self.session_store
                .apply_response_usage(connection_id, usage);
            crate::db::update_stream_usage(&self.db, connection_id, usage, None);
        }

        // Deposit response-side data into PendingEmitStore for merge with classify.
        let latency_ms = pending.stored_at.elapsed().as_millis() as u64;
        let resp_data = pending_emit::response_data_from_usage(
            usage.as_ref().unwrap_or(&UsageSummary {
                input_tokens: 0,
                output_tokens: 0,
                estimated_output_cost_usd: 0.0,
                finish_reason: None,
            }),
            latency_ms,
            None, // no TTFB for non-streaming responses
        );
        self.deposit_response_and_maybe_emit(connection_id, resp_data);
    }

    async fn handle_stream_chunk(&self, chunk: soth_mitm::StreamChunk) {
        let chunk = mitm_stream_chunk_to_core(&chunk);

        if let Some(mut pending) = self.pending.take(&chunk.connection_id) {
            // If classify was deferred (WebSocket upgrade with empty body),
            // spawn it now enriched with data from the first frame.
            if let Some(deferred) = pending.deferred_classify.take() {
                // Re-run detect on the first frame body to get a fresh result
                // with model/tokens. The original detect result from the upgrade
                // request had an empty body (provider=unknown, model=null, 0 tokens).
                let refreshed_detect = if !chunk.payload.is_empty() {
                    let bundle = self.bundle_handle.current();
                    let detect_bundle = bundle.detect_slice();
                    let parser_registry = self.parser_registry.load();
                    let mut frame_req = soth_core::RawRequest {
                        method: pending.request_method.clone(),
                        path: pending.request_path.clone(),
                        headers: soth_core::RequestHeaders::new(),
                        body: chunk.payload.clone(),
                        connection_meta: soth_core::ConnectionMeta::from_transport(
                            pending.connection_id,
                            soth_core::SocketFamily::UnixDomain { path: None },
                            None,
                            None,
                        ),
                    };
                    frame_req.connection_meta.matched_provider =
                        pending.outcome.matched_provider.clone();
                    frame_req.connection_meta.matched_application =
                        pending.outcome.matched_application.clone();
                    frame_req.connection_meta.capture_mode = Some(pending.outcome.capture_mode);
                    let snapshot = soth_core::SessionSnapshot::default();
                    let result = soth_detect::process_with_registry(
                        parser_registry.as_ref(),
                        &frame_req,
                        &detect_bundle,
                        &snapshot,
                    );
                    // Only use the refreshed result if it has better confidence
                    // than the stale upgrade-request detect.
                    if result.confidence != soth_core::ParseConfidence::Heuristic {
                        Arc::new(result)
                    } else {
                        Arc::clone(&pending.detect_result)
                    }
                } else {
                    Arc::clone(&pending.detect_result)
                };

                // The WebSocket upgrade request has an empty body (HTTP GET),
                // so deferred.content_for_embedding is None. Use the first
                // frame's payload as embedding content instead — it typically
                // contains `response.create` JSON with the model and system
                // instructions, which is exactly what we want to embed.
                let first_frame_text = if !chunk.payload.is_empty() {
                    std::str::from_utf8(&chunk.payload)
                        .ok()
                        .map(|s| s.to_string())
                } else {
                    None
                };
                let content_for_embedding = first_frame_text.or(deferred.content_for_embedding);

                let policy_block_enforced = Arc::new(AtomicBool::new(false));
                let _block_rx =
                    classify_task::spawn_classify_task(classify_task::ClassifyTaskInput {
                        connection_id: pending.connection_id,
                        detect_result: refreshed_detect,
                        content_for_embedding,
                        proxy_ctx: Arc::clone(&pending.proxy_ctx),
                        capture_mode: pending.outcome.capture_mode,
                        matched_provider: pending.outcome.matched_provider.clone(),
                        matched_application: pending.outcome.matched_application.clone(),
                        raw_body_for_commitment: deferred.raw_body_for_db,
                        classify_bundle: deferred.classify_bundle,
                        policy_bundle: deferred.policy_bundle,
                        bundle_trust_level: deferred.bundle_trust_level,
                        classify_config: deferred.classify_config,
                        policy_block_enforced,
                        session_store: self.session_store.clone(),
                        telemetry: self.telemetry.clone(),
                        observer_broadcast: self.observer_broadcast.clone(),
                        runtime: self.classify_runtime.clone(),
                        lane: deferred.lane,
                        pending_emit_store: Some(self.pending_emit.clone()),
                    });
                // Block signal is ignored — the WebSocket upgrade was already allowed.
            }

            self.streaming.start_stream(pending);
        }

        let bundle = self.bundle_handle.current();
        let detect_bundle = bundle.detect_slice();
        if let Some(event) = self.streaming.on_chunk(&chunk, &detect_bundle) {
            match event {
                // A client→server frame delivered a new prompt.  Fire a
                // dev verify REQUEST block immediately so the user sees
                // the prompt without waiting for the response to finish.
                soth_detect::ChunkEvent::TurnRequest(req) => {
                    if let Some(state) = self.streaming.peek_pending(&chunk.connection_id) {
                        let provider = state.detect_result.normalized.provider.as_str().to_string();
                        crate::trace::stream_turn_request(
                            chunk.connection_id,
                            req.turn_number,
                            state.request_host.as_str(),
                            state.request_path.as_str(),
                            state.request_method.as_str(),
                            provider.as_str(),
                            req.model.as_deref(),
                            state.outcome.matched_application.as_deref(),
                            state.outcome.matched_provider.as_deref(),
                            state.outcome.capture_mode,
                            &req.prompt,
                        );
                    } else {
                        // Fallback: no pending capture state available.
                        crate::trace::stream_turn_request(
                            chunk.connection_id,
                            req.turn_number,
                            "",
                            "",
                            "ws",
                            "unknown",
                            req.model.as_deref(),
                            None,
                            None,
                            soth_core::CaptureMode::MetadataOnly,
                            &req.prompt,
                        );
                    }
                }
                // A WebSocket turn completed (response.completed).
                // Write a per-turn record immediately — don't wait for
                // connection close which could be hours away.
                soth_detect::ChunkEvent::TurnCompleted(turn) => {
                    if let Some(state) = self.streaming.peek_pending(&chunk.connection_id) {
                        crate::trace::stream_turn_completed(
                            chunk.connection_id,
                            turn.turn_number,
                            turn.model.as_deref(),
                            &turn.usage,
                            turn.prompt.as_deref(),
                            turn.content.as_deref(),
                        );
                        crate::db::write_stream_turn(&self.db, chunk.connection_id, &turn, &state);
                        // Push a per-turn TelemetryEvent into the cloud
                        // pipeline so long-lived WebSocket sessions (e.g.
                        // Microsoft Copilot) can show one row per assistant
                        // response rather than one row per WS connection.
                        //
                        // Gate: skip turn #1 because it was already emitted
                        // by the existing path — either by
                        // `classify_task::spawn_classify_task` at request
                        // time (for HTTP POST + SSE like Codex) or by the
                        // deferred-classify flow that fires on the first WS
                        // frame (for real WebSocket upgrades).  Emitting
                        // again here would double-count turn #1.  Only
                        // turns 2, 3, ...N need this extra push.
                        if turn.turn_number > 1 {
                            crate::classify_task::emit_stream_turn(
                                chunk.connection_id,
                                &turn,
                                &state,
                                self.telemetry.as_ref(),
                            );
                        }
                    }
                }
                // Artifact events are already merged into the session's
                // stream_artifacts by `self.streaming.on_chunk`.
                soth_detect::ChunkEvent::Artifact(_) => {}
            }
        }
    }

    /// Called by soth-mitm after the server sends a 101 Switching Protocols
    /// response, confirming the WebSocket upgrade succeeded.
    ///
    /// Fires after `on_request` and before the first `on_stream_chunk`,
    /// ordered by the per-flow dispatch queue in soth-mitm.
    async fn handle_websocket_start(&self, response: soth_mitm::RawResponse) {
        let connection_id = response.connection_meta.connection_id;
        debug!(
            connection_id = %connection_id,
            status = response.status,
            "websocket upgrade confirmed by server (101)"
        );
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

        self.finalize_completed_stream(connection_id, completed);
    }

    /// Finalize a completed stream: estimate usage, trace, update session/DB, emit.
    ///
    /// Shared by `handle_stream_end` and `on_connection_close` — the two paths
    /// that can close a stream. The caller is responsible for taking the
    /// `CompletedStream` from the streaming store.
    fn finalize_completed_stream(
        &self,
        connection_id: Uuid,
        mut completed: crate::streaming::CompletedStream,
    ) {
        // Merge streaming response artifacts (credentials found in response
        // chunks) into the detect result so they reach telemetry + DB.
        // Arc::make_mut gives us exclusive ownership by cloning only when other
        // references exist; when this is the sole reference it mutates in place.
        if !completed.stream_artifacts.is_empty() {
            Arc::make_mut(&mut completed.pending.detect_result)
                .artifacts
                .append(&mut completed.stream_artifacts);
        }

        let usage = completed.usage.unwrap_or_else(|| {
            let estimated_output_tokens =
                estimate_output_tokens(completed.accumulated_payload_bytes);
            UsageSummary {
                input_tokens: completed
                    .pending
                    .detect_result
                    .normalized
                    .estimated_input_tokens as u64,
                output_tokens: estimated_output_tokens,
                estimated_output_cost_usd: 0.0,
                finish_reason: None,
            }
        });

        crate::trace::stream_completed(
            connection_id,
            completed.chunk_count,
            completed.elapsed.as_millis() as u64,
            Some(&usage),
            completed.pending.request_host.as_str(),
            completed.pending.request_path.as_str(),
            completed
                .pending
                .detect_result
                .normalized
                .parser_id
                .as_str(),
            completed.pending.outcome.matched_provider.as_deref(),
            completed.pending.outcome.matched_application.as_deref(),
        );
        crate::trace::dev_verify_stream_complete(
            connection_id,
            completed.chunk_count,
            completed.elapsed.as_millis() as u64,
            Some(&usage),
            completed.pending.detect_result.normalized.provider.as_str(),
            completed.extracted_model.as_deref().or(completed
                .pending
                .detect_result
                .normalized
                .model
                .as_deref()),
            completed.pending.request_host.as_str(),
            completed.pending.request_path.as_str(),
        );

        self.session_store
            .apply_response_usage(connection_id, &usage);

        crate::db::update_stream_usage(
            &self.db,
            connection_id,
            &usage,
            completed.extracted_model.as_deref(),
        );

        if completed.chunk_count == 0 {
            warn!(connection_id = %connection_id, "stream closed without chunks");
        }

        let ttfb_ms = completed.ttfb.map(|d| d.as_millis() as u64);
        let resp_data = pending_emit::response_data_from_usage(
            &usage,
            completed.elapsed.as_millis() as u64,
            ttfb_ms,
        );
        self.deposit_response_and_maybe_emit(connection_id, resp_data);
    }

    /// Deposit response-side data into PendingEmitStore. If classify has already
    /// completed, the deposit atomically removes the slot and emits the merged
    /// telemetry event.
    fn deposit_response_and_maybe_emit(
        &self,
        connection_id: Uuid,
        resp_data: pending_emit::ResponseData,
    ) {
        if let Some(resolved) = self.pending_emit.deposit_response(connection_id, resp_data) {
            classify_task::merge_and_emit(
                connection_id,
                resolved,
                self.telemetry.as_ref(),
                self.observer_broadcast.as_ref(),
            );
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
        matches!(decision, crate::gating::GateDecision::Intercept)
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

    fn on_websocket_start(
        &self,
        response: &soth_mitm::RawResponse,
    ) -> impl Future<Output = ()> + Send {
        let response = response.clone();
        async move { self.handle_websocket_start(response).await }
    }

    fn on_stream_chunk(&self, chunk: &soth_mitm::StreamChunk) -> impl Future<Output = ()> + Send {
        let chunk = chunk.clone();
        async move { self.handle_stream_chunk(chunk).await }
    }

    async fn on_stream_end(&self, connection_id: Uuid) {
        self.handle_stream_end(connection_id).await;
    }

    fn on_response(&self, response: &soth_mitm::RawResponse) -> impl Future<Output = ()> + Send {
        let response = response.clone();
        async move { self.handle_response(response).await }
    }

    fn on_connection_close(&self, connection_id: Uuid) {
        let had_pending = self.pending.remove(&connection_id);
        let _ = self.session_store.unbind_connection(&connection_id);

        // If there's an active stream, finalize it instead of dropping.
        // This handles providers like Claude web where SSE connections stay
        // open indefinitely and handle_stream_end() never fires.
        if let Some(completed) = self.streaming.take(&connection_id) {
            self.finalize_completed_stream(connection_id, completed);
            tracing::debug!(
                connection_id = %connection_id,
                "connection closed; finalized active stream"
            );
        } else if !had_pending {
            // No active stream AND no pending state — safe to clean up the emit slot.
            // When had_pending is true but streaming.take() returned None,
            // handle_stream_end() already ran and deposited response data.
            // Classify may still be in flight — leave the slot for the
            // rendezvous or maintenance_tick stale eviction to handle.
            self.pending_emit.remove(&connection_id);
        } else {
            tracing::debug!(
                connection_id = %connection_id,
                "connection closed with pending state; classify may still be in flight"
            );
        }
    }
}

/// Estimate output tokens from accumulated payload bytes.
/// SSE JSON overhead is ~50% of payload, so effective text ≈ bytes / 2,
/// then ~4 chars per token → bytes / 8.
fn estimate_output_tokens(payload_bytes: u64) -> u64 {
    payload_bytes / 8
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

/// Maximum byte length of text fed into the embedding pipeline.
/// 4096 bytes is ~1 000 tokens at average English density, comfortably
/// above the 128-token tokenizer window while preventing the tokenizer
/// from scanning multi-megabyte bodies before truncating.  Kept at 1 MB
/// so agentic coding prompts (full repo context, multi-file pastes) are
/// not truncated — the tokenizer handles its own efficient truncation.
const MAX_EMBEDDING_INPUT_BYTES: usize = 1024 * 1024;

fn extract_content_for_embedding(body: &Bytes) -> Option<String> {
    let text = std::str::from_utf8(body.as_ref()).ok()?;
    if text.len() > MAX_EMBEDDING_INPUT_BYTES {
        Some(text[..MAX_EMBEDDING_INPUT_BYTES].to_string())
    } else {
        Some(text.to_string())
    }
}

fn truncate_for_embedding(text: String) -> String {
    if text.len() > MAX_EMBEDDING_INPUT_BYTES {
        text[..MAX_EMBEDDING_INPUT_BYTES].to_string()
    } else {
        text
    }
}

fn sha256_hex(input: &[u8]) -> String {
    soth_core::sha256_hex(input)
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
    outcome: &crate::gating::GateOutcome,
    process_info: Option<&soth_core::ProcessInfo>,
    entity_index: Option<&soth_core::EntityIndex>,
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

    // Attempt O(1) entity resolution from the pre-built index.
    // `resolve_tool` prefers bundle_id over process_name, matching the
    // same priority as the `match_kind` derivation above.
    // Parent info is not available here and IdePlugin gating does not apply
    // to ProcessResolution metadata population — pass empty parent context.
    let resolved = entity_index.and_then(|idx| {
        idx.resolve_tool(
            bundle_id.as_deref(),
            process_name.as_deref(),
            None,
            None,
            &soth_core::EnvIndex::default(),
        )
    });

    let (matched_app_id, tool_name, tool_kind, tool_category, provider_id) =
        if let Some((entity, _source)) = resolved {
            (
                Some(entity.id.clone()),
                Some(entity.name.clone()),
                Some(entity.kind.as_str().to_string()),
                Some(entity.category.clone()),
                entity.provider_id.clone(),
            )
        } else {
            // Fall back to the gating outcome's matched_application when the
            // entity index has no entry (empty index or unknown process).
            (outcome.matched_application.clone(), None, None, None, None)
        };

    soth_core::ProcessResolution {
        match_kind,
        app_type: outcome.app_type,
        capture_mode: Some(outcome.capture_mode),
        process_name,
        bundle_id,
        matched_app_id,
        tool_name,
        tool_kind,
        tool_category,
        provider_id,
    }
}

/// Convert an `EnvironmentClass` (the *parent* process's class) to the
/// `SurfaceType` that best describes a request originating from that context.
/// Used for shadow-IT fallback and IdePlugin-without-IDE gating.
fn env_class_to_surface(class: Option<soth_core::EnvironmentClass>) -> soth_core::SurfaceType {
    match class {
        Some(soth_core::EnvironmentClass::Terminal) => soth_core::SurfaceType::Cli,
        Some(soth_core::EnvironmentClass::IDE) => soth_core::SurfaceType::IdePlugin,
        Some(soth_core::EnvironmentClass::Browser) => soth_core::SurfaceType::WebApp,
        None => soth_core::SurfaceType::Unknown,
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

/// Map gating bundle entity_id strings to `DetectedProvider`.
///
/// Gating entity IDs are defined in the bundle and may use various naming
/// conventions (e.g., "openai", "google-gemini", "chatgpt").
fn provider_from_matched(matched: &str) -> String {
    match matched.to_ascii_lowercase().as_str() {
        "openai" | "chatgpt" | "codex" => "openai".to_string(),
        "anthropic" | "claude" => "anthropic".to_string(),
        "gemini" | "google-gemini" | "google" | "google_vertex" => "gemini".to_string(),
        "azure-openai" | "azure_openai" => "azure_openai".to_string(),
        "cohere" => "cohere".to_string(),
        "bedrock" => "bedrock".to_string(),
        "mistral" => "mistral".to_string(),
        "groq" => "groq".to_string(),
        "together" => "together".to_string(),
        "fireworks" => "fireworks".to_string(),
        "ollama" => "ollama".to_string(),
        "vllm" => "vllm".to_string(),
        "lmstudio" => "lmstudio".to_string(),
        "vertex-ai" | "vertex_ai" => "vertex_ai".to_string(),
        _ => "unknown".to_string(),
    }
}

fn build_parser_registry(bundle: &soth_core::OwnedDetectBundle) -> soth_detect::ParserRegistry {
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
        direction: chunk.direction.map(|d| match d {
            soth_mitm::FrameDirection::ClientToServer => soth_core::FrameDirection::ClientToServer,
            soth_mitm::FrameDirection::ServerToClient => soth_core::FrameDirection::ServerToClient,
        }),
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
            ja4_hash: info.ja4_hash.clone(),
            tls_version: info.tls_version.as_ref().map(|v| v.as_str().to_string()),
        }),
        app_identity: None,
        capture_mode: None,
        matched_provider: None,
        matched_application: None,
        h2_connection_id: meta.h2_connection_id.clone(),
        h2_stream_id: meta.h2_stream_id,
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

/// Returns true if the content-type looks like an AI/LLM API response.
/// Non-AI content (video, audio, images, HTML pages, etc.) should not
/// be parsed for usage extraction.
fn is_heavy_content_type(ct: Option<&str>) -> bool {
    let ct = match ct {
        Some(v) => v.trim().to_ascii_lowercase(),
        // No content-type header — could be AI, don't skip.
        None => return false,
    };
    let base = ct.split(';').next().unwrap_or("").trim();

    // Skip any video, audio, image, or font MIME type family.
    if base.starts_with("video/")
        || base.starts_with("audio/")
        || base.starts_with("image/")
        || base.starts_with("font/")
    {
        return true;
    }

    matches!(
        base,
        "application/octet-stream"
            | "application/pdf"
            | "application/zip"
            | "application/gzip"
            | "application/x-tar"
            | "application/x-gzip"
            | "application/x-bzip2"
            | "application/x-7z-compressed"
            | "application/x-rar-compressed"
            | "application/vnd.debian.binary-package"
            | "application/java-archive"
            | "application/wasm"
            | "application/x-shockwave-flash"
            | "application/vnd.ms-fontobject"
            | "application/x-protobuf"
            | "application/x-apple-diskimage"
            | "application/x-mach-binary"
            | "application/x-executable"
            | "application/x-iso9660-image"
    )
}

/// Decide whether a request flags as shadow IT given the parser
/// coverage of its matched destination entity.
///
/// **Definition.** Shadow IT here means "we recognise this AI tool
/// but cannot decode what is happening inside the request" — i.e.
/// the catalog has an entry for the destination but no parser /
/// `api_format` is available in the bundle. Our visibility is
/// limited to metadata (host, byte counts, latency).
///
/// Inputs: `matched_with_parser` is `Some(true)` when the destination
/// matched a catalog entity AND that entity has an `api_format`,
/// `Some(false)` when matched but no parser exists, and `None` when
/// nothing in the catalog matched (i.e. non-AI traffic or unknown AI).
///
/// Outputs:
/// - `Some(true)`  → not shadow. Catalog match with full parser
///   visibility — this is the "fully observed" path, surfaces in
///   regular AI inference dashboards rather than the shadow view.
/// - `Some(false)` → **shadow**. Catalog match without a parser. We
///   know which product is being used but can only see metadata.
///   This is the bucket the cloud's `/detect/shadow-ai` view
///   highlights so the org can prioritise parser coverage or
///   approval/blocking decisions.
/// - `None`        → not shadow. No catalog match at all — either
///   non-AI traffic (skipped at gate) or an AI tool we don't yet
///   know about. Org-approval and blocking are applied separately
///   in soth-cloud, so the proxy stays stateless about policy.
pub(crate) fn determine_shadow_it(matched_with_parser: Option<bool>) -> bool {
    matches!(matched_with_parser, Some(false))
}

#[cfg(test)]
mod shadow_it_tests {
    use super::determine_shadow_it;

    #[test]
    fn catalog_match_without_parser_is_shadow() {
        // ~64% of bundle entities (180/280 on dev box) have
        // api_format=None: the catalog knows the product (Notion AI,
        // HuggingChat, Manus, etc.) but no parser is shipped, so
        // requests are visible only as metadata. That's the
        // shadow bucket.
        assert!(determine_shadow_it(Some(false)));
    }

    #[test]
    fn catalog_match_with_parser_is_not_shadow() {
        // ChatGPT, Claude, Gemini, Cursor, Claude Code all have
        // dedicated parsers (api_format = "openai" / "anthropic" /
        // "claude_web" / etc.), so the proxy fully decodes the
        // request and the event flows through the regular AI
        // inference dashboards rather than the shadow view.
        assert!(!determine_shadow_it(Some(true)));
    }

    #[test]
    fn no_catalog_match_is_not_shadow() {
        // Non-AI traffic, or AI tools the catalog doesn't yet know
        // about. The shadow signal is meaningful only for detected
        // tools; emitting shadow=true here would drown the
        // dashboard in noise from generic web traffic.
        assert!(!determine_shadow_it(None));
    }
}
