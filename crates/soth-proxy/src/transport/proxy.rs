//! Hudsucker-based Forward Proxy
//!
//! Uses the battle-tested proxy engine crate for MITM proxy functionality.
//! Provides selective interception: AI domains get MITM'd, others tunnel through.

use async_stream::stream;
use http_body_util::{BodyExt, Full, StreamBody};
use hudsucker::{
    hyper::{Request, Response},
    hyper_util::client::legacy::Error as LegacyClientError,
    Body, HttpContext, HttpHandler, RequestOrResponse,
};
use parking_lot::Mutex;
use serde::Deserialize;
use soth_crypto::tls::LearnedPassthrough;
use soth_oisp::OispEngine;
use soth_oisp::OispStreamParser;
#[cfg(test)]
use soth_policy::PolicyEngine;
#[cfg(test)]
use std::collections::HashSet;
use std::collections::{BTreeMap, HashMap};
#[cfg(test)]
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tracing::{debug, info, warn};

#[cfg(test)]
use crate::enforcement::core as enforcement_core;
use crate::metrics;
use crate::process_attribution::ProcessAttribution;
use crate::transport::exchange_assembler::ExchangeAssemblerConfig;
use crate::transport::graphql_enrichment::extract_graphql_operation;
#[cfg(test)]
use crate::transport::host_fingerprint;
use crate::transport::mcp_detection::extract_mcp_request_method;
#[cfg(test)]
use crate::transport::mcp_detection::is_jsonrpc_response_for_mcp;
use crate::transport::pii_enrichment::PiiEventEnricher;
#[cfg(test)]
use crate::transport::proxy_detection::has_anthropic_api_key_header;
use crate::transport::proxy_detection::{
    detect_agent_from_process_name, detect_agent_from_user_agent, extract_host,
    resolve_bundle_detection,
};
pub use crate::transport::proxy_enforcer::{ProxyEnforcer, ProxyIdentityMode, ProxyPolicyMode};
use crate::transport::proxy_error::handle_forward_error;
use crate::transport::proxy_exchange::{
    append_detection_tags, apply_process_identity, finalize_and_enqueue_exchange_v2,
    record_proxy_budget_spend, seed_exchange_v2_spool,
};
use crate::transport::proxy_payload::{
    capture_sanitized_headers, decode_payload_for_logging, extract_gemini_bard_stream_text,
    is_chat_ui_host, is_gemini_bard_stream_path, parse_content_length, sanitize_request_headers,
};
#[cfg(test)]
use crate::transport::proxy_payload::{
    decode_body_for_logging, header_size_bytes, trim_cookie_header_for_chatgpt, try_decompress,
    CHATGPT_MAX_COOKIE_HEADER_BYTES, CHAT_UI_STRICT_TOTAL_HEADER_BYTES,
};
use crate::transport::proxy_request::{
    build_request_body_inspection_plan, resolve_host_target_info,
};
use crate::transport::proxy_response::{
    emit_non_stream_response_event, handle_mcp_jsonrpc_response,
};
use crate::transport::proxy_routing::{
    get_action as routing_get_action, get_connect_action as routing_get_connect_action,
    is_force_intercept_all_active as routing_is_force_intercept_all_active,
};
use crate::transport::proxy_support::{
    acquire_stream_buffer, append_capture_tags, append_catalog_discovery_tags,
    append_process_attribution_tags, append_stream_capture, decision_label_from_intercept_decision,
    is_blacklist_detection_reason, process_bundle_id_from_executable, release_stream_buffer,
    CatalogDiscoveryLimiter, TunnelDebugRuntime, STREAM_CAPTURE_MAX_BYTES,
};
#[cfg(test)]
use crate::transport::proxy_websocket::should_emit_non_mcp_ws_event;
use crate::transport::response_event_builder::{
    empty_response_placeholder, normalize_response_content,
};
use crate::transport::tier_enrichment::extract_subscription_tags;
use crate::transport::usage_enrichment::{
    create_stream_usage_parser, extract_model_from_request_for_mode, extract_usage_meta_for_mode,
    extract_usage_meta_from_stream_usage, ResponseUsageMeta,
};
use soth_core::config::{
    ExchangeV2Config, ForwardProxyConfig, HostAction, HostFilterConfig, HostFilterMode,
    ObserveConfig, RegistryMode,
};
use soth_core::types::TrafficEnvelope;
use soth_core::EventLogger;

/// AI request body structure for model extraction
#[derive(Debug, Deserialize)]
struct AiRequestBody {
    model: Option<String>,
}

/// Pending request info for correlating with responses
#[derive(Debug, Clone)]
pub(crate) struct PendingRequest {
    pub(crate) exchange_id: String,
    pub(crate) envelope: Option<TrafficEnvelope>,
    pub(crate) host: String,
    pub(crate) path: String,
    pub(crate) method: String,
    pub(crate) provider: Option<String>,
    pub(crate) agent: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) graphql_operation: Option<String>,
    pub(crate) started_at: Instant,
    /// Request body content for paired logging
    pub(crate) request_content: Option<String>,
    /// Whether request body capture was truncated/skipped.
    pub(crate) request_body_truncated: bool,
    /// Request payload size in bytes (wire payload)
    pub(crate) request_size_bytes: Option<u64>,
    /// Sanitized request headers captured post-forward sanitation
    pub(crate) headers: Option<BTreeMap<String, String>>,
    /// Request content-type from ingress.
    pub(crate) request_content_type: Option<String>,
    /// Whether this is traffic from an agent app (chatgpt.com, claude.ai) vs direct API
    pub(crate) is_agent_app: bool,
    /// JSON-RPC MCP method (when this request is identified as MCP traffic)
    pub(crate) mcp_method: Option<String>,
    /// Whether this pending request should be emitted as MCP source.
    pub(crate) is_mcp_jsonrpc: bool,
    /// True when captured through discovery-mode catalog interception.
    pub(crate) catalog_discovery: bool,
    /// Bundle-based interception classification reason.
    pub(crate) detection_reason: Option<String>,
    /// Confidence score for detection reason.
    pub(crate) parse_confidence: Option<f64>,
    /// Provider/agent entity id derived from bundle detection.
    pub(crate) target_entity_id: Option<String>,
    /// Source of detection metadata (bundle).
    pub(crate) detection_source: Option<String>,
    /// Whether interception matched blacklist/noise criteria.
    pub(crate) blacklist_match: bool,
    /// Policy decision metadata captured at request enforcement time.
    pub(crate) policy_allowed: Option<bool>,
    pub(crate) policy_reason: Option<String>,
    pub(crate) policy_version: Option<String>,
}

/// Thread-safe store for pending requests
pub(crate) type PendingRequests = Arc<Mutex<HashMap<u64, PendingRequest>>>;

static NEXT_PROXY_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

fn next_proxy_request_id() -> u64 {
    NEXT_PROXY_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
}

/// AI-aware HTTP handler for proxy transport
pub struct AiProxyHandler {
    /// Host filter config for selective interception
    hosts: Arc<HostFilterConfig>,
    /// Event logger for observability
    event_logger: Option<Arc<EventLogger>>,
    /// Session ID for this proxy instance
    session_id: String,
    /// Pending requests for response correlation
    pending_requests: PendingRequests,
    /// Optional enforcement runtime for identity/policy/budget checks
    enforcer: Option<Arc<ProxyEnforcer>>,
    /// User-defined tags attached to all emitted events.
    event_tags: Arc<BTreeMap<String, String>>,
    /// Optional PII enrichment before events are written.
    pii_enricher: Arc<PiiEventEnricher>,
    /// Adaptive learned TLS passthrough map (cert-pinning bypass).
    learned_passthrough: Option<Arc<LearnedPassthrough>>,
    /// Threshold of repeated failed intercept attempts before learning passthrough.
    learned_failure_threshold: u32,
    /// Rolling window for failure threshold accumulation.
    learned_failure_window: Duration,
    /// Platform-gated process attribution runtime.
    process_attribution: Arc<ProcessAttribution>,
    /// Migration mode for registry-driven detection/interception.
    registry_mode: RegistryMode,
    /// Bundle-driven classifier loaded from registry cache.
    oisp_engine: Arc<OispEngine>,
    /// Optional exchange.v2 assembly config (disabled when None).
    exchange_v2: Option<ExchangeAssemblerConfig>,
    /// One-time-per-day limiter for catalog-domain discovery captures.
    catalog_discovery_limiter: Arc<CatalogDiscoveryLimiter>,
    /// Maximum request/response body bytes to capture in observability payloads.
    capture_max_body_bytes: u64,
    /// Optional metadata-only diagnostics for tunneled/noise requests.
    tunnel_debug: TunnelDebugRuntime,
    /// Stable request/response correlation key for this handler clone lifecycle.
    request_correlation_id: u64,
    /// Debug override to force MITM interception for all non-local hosts.
    force_intercept_all: bool,
    /// Optional expiry for the debug force-intercept-all override.
    force_intercept_all_until: Option<SystemTime>,
}

impl Clone for AiProxyHandler {
    fn clone(&self) -> Self {
        Self {
            hosts: self.hosts.clone(),
            event_logger: self.event_logger.clone(),
            session_id: self.session_id.clone(),
            pending_requests: self.pending_requests.clone(),
            enforcer: self.enforcer.clone(),
            event_tags: self.event_tags.clone(),
            pii_enricher: self.pii_enricher.clone(),
            learned_passthrough: self.learned_passthrough.clone(),
            learned_failure_threshold: self.learned_failure_threshold,
            learned_failure_window: self.learned_failure_window,
            process_attribution: self.process_attribution.clone(),
            registry_mode: self.registry_mode,
            oisp_engine: self.oisp_engine.clone(),
            exchange_v2: self.exchange_v2.clone(),
            catalog_discovery_limiter: self.catalog_discovery_limiter.clone(),
            capture_max_body_bytes: self.capture_max_body_bytes,
            tunnel_debug: self.tunnel_debug.clone(),
            request_correlation_id: next_proxy_request_id(),
            force_intercept_all: self.force_intercept_all,
            force_intercept_all_until: self.force_intercept_all_until,
        }
    }
}

impl AiProxyHandler {
    pub fn new(
        config: &ForwardProxyConfig,
        observe: &ObserveConfig,
        oisp_engine: Arc<OispEngine>,
    ) -> Self {
        Self {
            hosts: Arc::new(config.hosts.clone()),
            event_logger: None,
            session_id: uuid::Uuid::new_v4().to_string(),
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
            enforcer: None,
            event_tags: Arc::new(observe.event_tags.clone()),
            pii_enricher: Arc::new(PiiEventEnricher::from_observe_config(observe)),
            learned_passthrough: None,
            learned_failure_threshold: config.tls.learned_passthrough.failure_threshold.max(1),
            learned_failure_window: config.tls.learned_passthrough.failure_window,
            process_attribution: Arc::new(ProcessAttribution::new(
                config.process_attribution.enabled,
                config.process_attribution.lookup_timeout,
                config.process_attribution.cache_ttl,
            )),
            registry_mode: config.registry_mode,
            oisp_engine,
            exchange_v2: None,
            catalog_discovery_limiter: Arc::new(CatalogDiscoveryLimiter::default()),
            capture_max_body_bytes: config.capture_max_body_bytes,
            tunnel_debug: TunnelDebugRuntime::new(
                config.tunnel_debug.enabled,
                config.tunnel_debug.include_noise,
                config.tunnel_debug.min_log_interval,
            ),
            request_correlation_id: next_proxy_request_id(),
            force_intercept_all: false,
            force_intercept_all_until: None,
        }
    }

    /// Set event logger for observability
    pub fn with_event_logger(mut self, logger: EventLogger) -> Self {
        let logger = Arc::new(logger);
        self.catalog_discovery_limiter
            .set_event_logger(logger.clone());
        self.event_logger = Some(logger);
        self
    }

    /// Set event logger for observability (Arc version for sharing)
    pub fn with_event_logger_arc(mut self, logger: Arc<EventLogger>) -> Self {
        self.catalog_discovery_limiter
            .set_event_logger(logger.clone());
        self.event_logger = Some(logger);
        self
    }

    /// Enable exchange.v2 assembly + queue output.
    pub fn with_exchange_v2(mut self, exchange_cfg: ExchangeV2Config) -> Self {
        if exchange_cfg.enabled {
            self.exchange_v2 = Some(ExchangeAssemblerConfig::from(&exchange_cfg));
        } else {
            self.exchange_v2 = None;
        }
        self
    }

    /// Set enforcement runtime for request allow/deny checks.
    pub fn with_enforcer(mut self, enforcer: ProxyEnforcer) -> Self {
        self.enforcer = Some(Arc::new(enforcer));
        self
    }

    /// Set learned passthrough runtime and threshold parameters.
    pub fn with_learned_passthrough(
        mut self,
        learned: Arc<LearnedPassthrough>,
        failure_threshold: u32,
        failure_window: Duration,
    ) -> Self {
        self.learned_passthrough = Some(learned);
        self.learned_failure_threshold = failure_threshold.max(1);
        self.learned_failure_window = failure_window;
        self
    }

    /// Enable debug catch-all interception for all non-local hosts.
    pub fn with_force_intercept_all(
        mut self,
        enabled: bool,
        expires_at: Option<SystemTime>,
    ) -> Self {
        self.force_intercept_all = enabled;
        self.force_intercept_all_until = expires_at;
        self
    }

    fn is_force_intercept_all_active(&self) -> bool {
        routing_is_force_intercept_all_active(
            self.force_intercept_all,
            self.force_intercept_all_until,
        )
    }

    /// Resolve action for host/path using registry engine decisions.
    /// Uses bundle-driven decisions only (no host-list fallback).
    fn get_action(&self, host: &str, path: &str) -> HostAction {
        routing_get_action(
            &self.hosts,
            self.oisp_engine.as_ref(),
            &self.catalog_discovery_limiter,
            self.force_intercept_all,
            self.force_intercept_all_until,
            host,
            path,
        )
    }

    /// Resolve action for CONNECT/TLS handshake where request path is not available yet.
    fn get_connect_action(&self, host: &str) -> HostAction {
        routing_get_connect_action(
            &self.hosts,
            self.oisp_engine.as_ref(),
            &self.catalog_discovery_limiter,
            self.force_intercept_all,
            self.force_intercept_all_until,
            host,
        )
    }
}

impl HttpHandler for AiProxyHandler {
    fn handle_request(
        &mut self,
        ctx: &HttpContext,
        req: Request<Body>,
    ) -> impl std::future::Future<Output = RequestOrResponse> + Send {
        let host = extract_host(&req);
        let uri = req.uri().clone();
        let path = uri.path().to_string();
        let path_for_filter = uri
            .path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| path.clone());
        let http_method = req.method().to_string();
        let is_connect = req.method() == hyper::Method::CONNECT;

        debug!(
            full_uri = %uri,
            path = %path,
            host = %host,
            method = %http_method,
            "Incoming request"
        );
        let host_action = if is_connect {
            self.get_connect_action(&host)
        } else {
            self.get_action(&host, &path_for_filter)
        };
        let is_blocked = matches!(host_action, HostAction::Block);
        let host_mode = self.hosts.mode;
        let catalog_discovery_limiter = self.catalog_discovery_limiter.clone();
        let host_target_info = resolve_host_target_info(
            &req,
            host_action,
            host_mode,
            &host,
            is_connect,
            self.oisp_engine.as_ref(),
            &catalog_discovery_limiter,
        );
        let should_capture_observability = host_target_info.should_capture_observability;
        let is_catalog_discovery_host = host_target_info.is_catalog_discovery_host;
        let host_is_ai_target = host_target_info.host_is_ai_target;
        let host_is_mcp_target = host_target_info.host_is_mcp_target;
        let host_is_agent_target = host_target_info.host_is_agent_target;
        let provider = host_target_info.provider.clone();
        let ua_header = req
            .headers()
            .get("user-agent")
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        let ua_agent = detect_agent_from_user_agent(&req);
        let enforcer = self.enforcer.clone();
        let session_id = self.session_id.clone();
        let did_header = enforcer.as_ref().map(|e| e.did_header().to_string());
        let signature_header = enforcer.as_ref().map(|e| e.signature_header().to_string());
        let identity_did = did_header
            .as_deref()
            .and_then(|header| req.headers().get(header))
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());
        let identity_signature = signature_header
            .as_deref()
            .and_then(|header| req.headers().get(header))
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());

        let request_plan = build_request_body_inspection_plan(
            &req,
            &path,
            &http_method,
            host_mode,
            should_capture_observability,
            host_is_ai_target,
            host_is_mcp_target,
            host_is_agent_target,
            is_catalog_discovery_host,
            self.capture_max_body_bytes,
        );
        let is_post = request_plan.is_post;
        let is_json = request_plan.is_json;
        let content_type = request_plan.content_type.clone();
        let request_content_encoding = request_plan.request_content_encoding.clone();
        let declared_request_size_bytes = request_plan.declared_request_size_bytes;
        let request_capture_oversized = request_plan.request_capture_oversized;
        let should_log_inference_request = request_plan.should_log_inference_request;
        let should_inspect_body = request_plan.should_inspect_body;
        let oisp_engine = self.oisp_engine.clone();
        let event_logger = self.event_logger.clone();
        let learned_passthrough = self.learned_passthrough.clone();
        let learned_failure_threshold = self.learned_failure_threshold;
        let learned_failure_window = self.learned_failure_window;
        let process_attribution = self.process_attribution.clone();
        let capture_max_body_bytes = self.capture_max_body_bytes;
        let tunnel_debug = self.tunnel_debug.clone();
        let client_addr = ctx.client_addr;
        let exchange_v2_cfg = self.exchange_v2.clone();
        let exchange_bundle_version = if exchange_v2_cfg.is_some() {
            Some(self.oisp_engine.bundle_version().to_string())
        } else {
            None
        };
        let should_resolve_process = !is_connect
            && ((should_capture_observability
                && (host_is_ai_target
                    || host_is_mcp_target
                    || host_is_agent_target
                    || (host_mode == HostFilterMode::Discovery)))
                || (tunnel_debug.enabled && !should_capture_observability));

        debug!(
            is_post = is_post,
            content_type = ?content_type,
            is_json = is_json,
            request_content_encoding = ?request_content_encoding,
            provider = ?provider,
            should_inspect = should_inspect_body,
            "Request inspection check"
        );

        let pending_requests = self.pending_requests.clone();
        let request_id = self.request_correlation_id;

        async move {
            // Check if blocked
            if is_blocked {
                warn!(host = %host, "Blocked request");
                return RequestOrResponse::Response(
                    Response::builder().status(403).body(Body::empty()).unwrap(),
                );
            }

            let process_identity = if should_resolve_process {
                process_attribution.resolve(client_addr).await
            } else {
                None
            };

            if is_connect && !matches!(host_action, HostAction::Intercept) {
                let decision_label = match host_action {
                    HostAction::Tunnel => "tunnel",
                    HostAction::Block => "block",
                    HostAction::Intercept => "intercept",
                };
                let process_pid = process_identity.as_ref().map(|value| value.pid);
                let process_name = process_identity.as_ref().map(|value| value.name.as_str());
                if tunnel_debug.should_log(decision_label, &host, process_pid, process_name) {
                    let process_bundle_id = process_identity.as_ref().and_then(|value| {
                        process_bundle_id_from_executable(value.executable.as_deref())
                    });
                    info!(
                        host = %host,
                        method = "CONNECT",
                        decision = %decision_label,
                        client_addr = %client_addr,
                        process_pid = ?process_pid,
                        process_name = %process_name.unwrap_or("-"),
                        process_app_type = %process_identity
                            .as_ref()
                            .map(|value| value.app_type.as_str())
                            .unwrap_or("-"),
                        process_bundle_id = ?process_bundle_id,
                        "Tunnel debug CONNECT metadata (no body capture)"
                    );
                }
            }

            if is_connect && matches!(host_action, HostAction::Intercept) {
                if let Some(ref learned) = learned_passthrough {
                    if !learned.should_passthrough(&host)
                        && learned.record_connect_attempt(
                            &host,
                            learned_failure_threshold,
                            learned_failure_window,
                        )
                    {
                        metrics::record_tls_learned_passthrough("learn");
                        metrics::set_tls_learned_passthrough_active(learned.active_count() as f64);
                        warn!(
                            host = %host,
                            threshold = learned_failure_threshold,
                            "Learned TLS passthrough host after repeated failed intercept attempts"
                        );
                    }
                }
            }

            // Capture body for AI/MCP requests and record payload-size metadata.
            let (body_content, request_size_bytes, model, req, request_body_truncated) =
                if should_inspect_body {
                    let (parts, body) = req.into_parts();
                    match body.collect().await {
                        Ok(collected) => {
                            let bytes = collected.to_bytes();
                            let body_len = bytes.len();
                            let (decoded_bytes, body_str) = decode_payload_for_logging(
                                &bytes,
                                request_content_encoding.as_deref(),
                            );

                            debug!(
                                body_len = body_len,
                                body_preview = %body_str.chars().take(100).collect::<String>(),
                                "Captured request body"
                            );

                            // Extract model from bundle parser first, then fallback to generic JSON.
                            let model = provider
                                .as_deref()
                                .and_then(|provider_name| {
                                    extract_model_from_request_for_mode(
                                        Some(oisp_engine.as_ref()),
                                        provider_name,
                                        &host,
                                        &decoded_bytes,
                                    )
                                })
                                .or_else(|| {
                                    serde_json::from_slice::<AiRequestBody>(&decoded_bytes)
                                        .ok()
                                        .and_then(|b| b.model)
                                });

                            // Reconstruct request with body
                            let new_body = Body::from(Full::new(bytes));
                            let req = Request::from_parts(parts, new_body);
                            (Some(body_str), Some(body_len as u64), model, req, false)
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to collect request body");
                            let req = Request::from_parts(parts, Body::empty());
                            (None, declared_request_size_bytes, None, req, false)
                        }
                    }
                } else {
                    debug!("Skipping body inspection");
                    let preview = if request_capture_oversized {
                        Some(format!(
                        "[request body truncated; declared size {} bytes exceeds capture limit {} bytes]",
                        declared_request_size_bytes.unwrap_or_default(),
                        capture_max_body_bytes
                    ))
                    } else {
                        None
                    };
                    (
                        preview,
                        declared_request_size_bytes,
                        None,
                        req,
                        request_capture_oversized,
                    )
                };
            if !is_connect && !should_capture_observability {
                let decision_label = decision_label_from_intercept_decision(
                    oisp_engine.should_intercept(&host, &path_for_filter),
                );
                let process_pid = process_identity.as_ref().map(|value| value.pid);
                let process_name = process_identity.as_ref().map(|value| value.name.as_str());
                if tunnel_debug.should_log(decision_label, &host, process_pid, process_name) {
                    let process_bundle_id = process_identity.as_ref().and_then(|value| {
                        process_bundle_id_from_executable(value.executable.as_deref())
                    });
                    info!(
                        host = %host,
                        path = %path,
                        method = %http_method,
                        decision = %decision_label,
                        client_addr = %client_addr,
                        provider_hint = ?provider,
                        agent_hint = ?ua_agent,
                        process_pid = ?process_pid,
                        process_name = %process_name.unwrap_or("-"),
                        process_app_type = %process_identity
                            .as_ref()
                            .map(|value| value.app_type.as_str())
                            .unwrap_or("-"),
                        process_bundle_id = ?process_bundle_id,
                        user_agent = ?ua_header,
                        "Tunnel debug metadata (no body capture)"
                    );
                } else {
                    debug!(
                        host = %host,
                        path = %path,
                        method = %http_method,
                        "Skipping observability capture for tunneled/noise request"
                    );
                }
            }
            let process_bundle_id = process_identity
                .as_ref()
                .and_then(|value| process_bundle_id_from_executable(value.executable.as_deref()));
            let process_agent = process_identity
                .as_ref()
                .and_then(|value| detect_agent_from_process_name(&value.name))
                .map(ToString::to_string);
            let bundle_detection = resolve_bundle_detection(
                oisp_engine.as_ref(),
                provider.as_deref(),
                &host,
                &path,
                ua_header.as_deref(),
                model.as_deref(),
                process_identity.as_ref().map(|value| value.name.as_str()),
                process_bundle_id.as_deref(),
                process_agent.as_deref(),
            );
            let agent = bundle_detection.agent.clone();
            let detection_reason = bundle_detection.detection_reason.clone();
            let parse_confidence = bundle_detection.parse_confidence;
            let detection_source = bundle_detection.detection_source.clone();
            let target_entity_id = bundle_detection.target_entity_id.clone();
            let mcp_request_method = if !is_connect
                && should_capture_observability
                && (host_is_mcp_target || (host_mode == HostFilterMode::Discovery))
            {
                body_content
                    .as_deref()
                    .and_then(|content| extract_mcp_request_method(content, &path))
            } else {
                None
            };
            let graphql_operation = if !is_connect && is_json {
                body_content.as_deref().and_then(extract_graphql_operation)
            } else {
                None
            };
            let graphql_blacklisted = graphql_operation
                .as_deref()
                .map(|operation| oisp_engine.matches_noise_keyword(operation))
                .unwrap_or(false);
            if graphql_blacklisted {
                metrics::record_filter_decision("http", "blacklist_graphql");
                info!(
                    host = %host,
                    path = %path,
                    graphql_operation = ?graphql_operation,
                    "Skipping observability capture for blacklisted GraphQL operation"
                );
            }
            let mut policy_allowed = None;
            let mut policy_version = None;

            if !is_connect {
                if let Some(ref learned) = learned_passthrough {
                    // Decrypted non-CONNECT request means intercept succeeded; clear any
                    // stale learning/failure state for this host.
                    learned.record_decrypted_request(&host);
                    metrics::set_tls_learned_passthrough_active(learned.active_count() as f64);
                }
            }

            if !is_connect {
                if let (Some(provider), Some(enforcer)) = (provider.as_deref(), enforcer.as_ref()) {
                    let envelope = apply_process_identity(
                        TrafficEnvelope::proxy(
                            &session_id,
                            request_id.to_string(),
                            provider,
                            &host,
                            &http_method,
                            &path,
                            model.as_deref(),
                            agent.as_deref(),
                            identity_did.as_deref(),
                            identity_signature.as_deref(),
                            body_content.as_deref(),
                        ),
                        process_identity.as_ref(),
                    );
                    let enforcement = enforcer.enforce_envelope_with_timeout(&envelope).await;

                    match enforcement {
                        Ok(identity_result) => {
                            policy_allowed = Some(true);
                            policy_version = identity_result.policy_version.clone();
                        }
                        Err((status, reason, _denied_policy_version)) => {
                            warn!(
                                status = status,
                                provider = provider,
                                host = %host,
                                path = %path,
                                reason = %reason,
                                "Proxy request denied by enforcement"
                            );
                            let response_body = serde_json::json!({
                                "error": reason,
                                "status": status,
                            });
                            return RequestOrResponse::Response(
                                Response::builder()
                                    .status(status)
                                    .header("content-type", "application/json")
                                    .body(Body::from(Full::new(response_body.to_string().into())))
                                    .unwrap(),
                            );
                        }
                    }
                }
            }

            // Log AI traffic (only inference endpoints, not images/tracking/etc)
            if is_connect {
                debug!(host = %host, "CONNECT handshake (skipping AI request logging)");
            } else if let Some(provider) = provider
                .as_deref()
                .filter(|_| !host_is_mcp_target && mcp_request_method.is_none())
            {
                let display_path = if path.is_empty() || path == "/" {
                    // For tunneled requests, path might be empty
                    "/".to_string()
                } else {
                    path.clone()
                };

                // Check if this request should be logged (blacklist non-inference content)
                let should_log = (is_catalog_discovery_host || should_log_inference_request)
                    && !graphql_blacklisted;

                if should_log {
                    info!(
                        agent = ?agent,
                        provider = provider,
                        host = %host,
                        path = %display_path,
                        method = %http_method,
                        model = ?model,
                        catalog_discovery = is_catalog_discovery_host,
                        "AI API request"
                    );
                } else {
                    debug!(
                        provider = provider,
                        path = %display_path,
                        graphql_blacklisted = graphql_blacklisted,
                        "Skipping non-inference or blacklisted endpoint"
                    );
                }

                // Dedicated visibility for Chat UI backend calls (used to debug 431 issues).
                if is_chat_ui_host(&host) && display_path.contains("/backend-api/") {
                    info!(
                        provider = provider,
                        host = %host,
                        path = %display_path,
                        method = %http_method,
                        should_log = should_log,
                        "Chat UI backend API request"
                    );
                }

                // Store pending request for response correlation (only for logged requests)
                if should_log {
                    let blacklist_match =
                        is_blacklist_detection_reason(detection_reason.as_deref());
                    let envelope = apply_process_identity(
                        TrafficEnvelope::proxy(
                            &session_id,
                            request_id.to_string(),
                            provider,
                            &host,
                            &http_method,
                            &display_path,
                            model.as_deref(),
                            agent.as_deref(),
                            identity_did.as_deref(),
                            identity_signature.as_deref(),
                            body_content.as_deref(),
                        ),
                        process_identity.as_ref(),
                    );
                    let mut pending = pending_requests.lock();
                    pending.insert(
                        request_id,
                        PendingRequest {
                            exchange_id: uuid::Uuid::new_v4().to_string(),
                            envelope: Some(envelope),
                            host: host.clone(),
                            path: display_path.clone(),
                            method: http_method.clone(),
                            provider: Some(provider.to_string()),
                            agent: agent.clone(),
                            model: model.clone(),
                            graphql_operation: graphql_operation.clone(),
                            started_at: Instant::now(),
                            request_content: body_content,
                            request_body_truncated,
                            request_size_bytes,
                            headers: None,
                            request_content_type: content_type.clone(),
                            is_agent_app: host_is_agent_target,
                            mcp_method: None,
                            is_mcp_jsonrpc: false,
                            catalog_discovery: is_catalog_discovery_host,
                            detection_reason: detection_reason.clone(),
                            parse_confidence,
                            target_entity_id: target_entity_id.clone(),
                            detection_source: detection_source.clone(),
                            blacklist_match,
                            policy_allowed,
                            policy_reason: None,
                            policy_version,
                        },
                    );
                }

                // Note: We don't log request events separately anymore.
                // Instead, we log a paired request/response event when the response arrives.
            } else if let Some(mcp_method) = mcp_request_method {
                info!(
                    host = %host,
                    path = %path,
                    method = %http_method,
                    mcp_method = %mcp_method,
                    "MCP JSON-RPC request"
                );

                let mut pending = pending_requests.lock();
                let blacklist_match = is_blacklist_detection_reason(detection_reason.as_deref());
                pending.insert(
                    request_id,
                    PendingRequest {
                        exchange_id: uuid::Uuid::new_v4().to_string(),
                        envelope: Some(apply_process_identity(
                            TrafficEnvelope::mcp_http(
                                &session_id,
                                Some(request_id.to_string()),
                                mcp_method.clone(),
                                &host,
                                &path,
                                agent.as_deref(),
                                identity_did.as_deref(),
                                identity_signature.as_deref(),
                                body_content.as_deref(),
                            ),
                            process_identity.as_ref(),
                        )),
                        host: host.clone(),
                        path: path.clone(),
                        method: http_method.clone(),
                        provider: None,
                        agent: agent.clone(),
                        model: None,
                        graphql_operation: None,
                        started_at: Instant::now(),
                        request_content: None,
                        request_body_truncated,
                        request_size_bytes,
                        headers: None,
                        request_content_type: content_type.clone(),
                        is_agent_app: false,
                        mcp_method: Some(mcp_method),
                        is_mcp_jsonrpc: true,
                        catalog_discovery: is_catalog_discovery_host,
                        detection_reason: detection_reason.clone(),
                        parse_confidence,
                        target_entity_id: target_entity_id.clone(),
                        detection_source: detection_source.clone(),
                        blacklist_match,
                        policy_allowed: None,
                        policy_reason: None,
                        policy_version: None,
                    },
                );
            } else {
                debug!(host = %host, path = %path, "Request (non-AI)");
            }

            // Sanitize headers to prevent 431 errors (removes proxy hop headers, etc.)
            // Only aggressive cookie trimming for ChatGPT (other providers keep all cookies)
            let (parts, body) = req.into_parts();
            let mut sanitized_req = Request::from_parts(parts, body);
            sanitize_request_headers(&mut sanitized_req, &host, &path);
            let sanitized_request_size_bytes = parse_content_length(sanitized_req.headers());
            let sanitized_headers = capture_sanitized_headers(sanitized_req.headers());

            // Persist sanitized header map and request-size metadata into pending request
            // so response-side paired events can include this context.
            let pending_for_spool = {
                let mut pending = pending_requests.lock();
                if let Some(entry) = pending.get_mut(&request_id) {
                    if entry.provider.is_some() {
                        entry.headers = Some(sanitized_headers);
                    }
                    if entry.request_size_bytes.is_none() {
                        entry.request_size_bytes =
                            request_size_bytes.or(sanitized_request_size_bytes);
                    }
                    if exchange_v2_cfg.is_some() {
                        Some(entry.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            if let (Some(exchange_cfg), Some(logger), Some(entry)) = (
                exchange_v2_cfg.as_ref(),
                event_logger.as_ref(),
                pending_for_spool.as_ref(),
            ) {
                seed_exchange_v2_spool(
                    logger,
                    exchange_cfg,
                    entry,
                    &session_id,
                    exchange_bundle_version.as_deref(),
                );
            }

            RequestOrResponse::Request(sanitized_req)
        }
    }

    fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        res: Response<Body>,
    ) -> impl std::future::Future<Output = Response<Body>> + Send {
        let status = res.status().as_u16();
        let pending_requests = self.pending_requests.clone();
        let event_logger = self.event_logger.clone();
        let event_tags = self.event_tags.clone();
        let pii_enricher = self.pii_enricher.clone();
        let session_id = self.session_id.clone();
        let request_id = self.request_correlation_id;
        let oisp_engine = self.oisp_engine.clone();
        let exchange_v2_cfg = self.exchange_v2.clone();
        let exchange_bundle_version = if exchange_v2_cfg.is_some() {
            Some(self.oisp_engine.bundle_version().to_string())
        } else {
            None
        };
        let capture_max_body_bytes = self.capture_max_body_bytes;
        let budget_tracker = self
            .enforcer
            .as_ref()
            .and_then(|enforcer| enforcer.budget_tracker());
        let response_headers = capture_sanitized_headers(res.headers());

        // Check content type for body inspection
        let content_type = res
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_ascii_lowercase());
        let is_json = content_type
            .as_deref()
            .map(|ct| ct.contains("application/json"))
            .unwrap_or(false);
        let is_sse = content_type
            .as_deref()
            .map(|ct| ct.contains("text/event-stream"))
            .unwrap_or(false);
        let is_grpc = content_type
            .as_deref()
            .map(|ct| ct.contains("application/grpc") || ct.contains("grpc-web"))
            .unwrap_or(false);
        let grpc_message_encoding = res
            .headers()
            .get("grpc-encoding")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_ascii_lowercase());
        let content_encoding = res
            .headers()
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_lowercase());
        let declared_response_size_bytes = parse_content_length(res.headers());

        async move {
            // Get pending request info
            let pending = {
                let mut requests = pending_requests.lock();
                requests.remove(&request_id)
            };

            let Some(pending) = pending else {
                debug!(status = status, "Response for non-tracked request");
                return res;
            };

            let latency_ms = pending.started_at.elapsed().as_millis() as u64;
            if pending.is_mcp_jsonrpc {
                return handle_mcp_jsonrpc_response(
                    res,
                    &pending,
                    status,
                    is_json,
                    content_type.as_deref(),
                    content_encoding.as_deref(),
                    &response_headers,
                    event_logger.as_ref(),
                    &event_tags,
                    &pii_enricher,
                    exchange_v2_cfg.as_ref(),
                    exchange_bundle_version.as_deref(),
                    &session_id,
                    capture_max_body_bytes,
                )
                .await;
            }

            let provider = pending
                .provider
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            let is_codex_response_path = pending
                .path
                .to_ascii_lowercase()
                .contains("/backend-api/codex/responses");
            let is_gemini_bard_response_path = is_gemini_bard_stream_path(&pending.path);
            let is_stream_response =
                is_sse || is_codex_response_path || is_gemini_bard_response_path;
            let mut response_usage = ResponseUsageMeta::default();
            let response_declared_oversized = declared_response_size_bytes
                .map(|size| size > capture_max_body_bytes)
                .unwrap_or(false);
            let mut response_body_truncated = false;
            let mut response_capture_reason: Option<&'static str> = None;
            let skip_response_capture = if pending.catalog_discovery {
                response_body_truncated = true;
                response_capture_reason = Some("catalog_discovery_metadata_only");
                true
            } else if response_declared_oversized {
                response_body_truncated = true;
                response_capture_reason = Some("declared_size_exceeded");
                true
            } else {
                false
            };

            // Streamed responses can be long-lived. Keep persistence append-only by emitting a
            // single finalized event once stream capture completes (no placeholder upsert).

            // For JSON responses, capture the body for logging (with decompression)
            // For SSE/Codex streams, use tee to forward immediately while accumulating for logging
            let (body_content, res, logged_in_stream) = if !skip_response_capture
                && (is_json || is_grpc)
                && !is_sse
                && !is_codex_response_path
                && !is_gemini_bard_response_path
            {
                let (parts, body) = res.into_parts();
                match body.collect().await {
                    Ok(collected) => {
                        let bytes = collected.to_bytes();
                        let (decoded_bytes, body_str) =
                            decode_payload_for_logging(&bytes, content_encoding.as_deref());

                        let usage_outcome = extract_usage_meta_for_mode(
                            Some(oisp_engine.as_ref()),
                            provider.as_str(),
                            &pending.host,
                            &decoded_bytes,
                            false,
                            content_type.as_deref(),
                            grpc_message_encoding.as_deref(),
                            pending.model.as_deref(),
                        )
                        .await;
                        response_usage = usage_outcome.primary;

                        // Return original bytes to client (they handle decompression)
                        let new_body = Body::from(Full::new(bytes));
                        let res = Response::from_parts(parts, new_body);
                        (Some(body_str), res, false)
                    }
                    Err(_) => {
                        let res = Response::from_parts(parts, Body::empty());
                        (None, res, false)
                    }
                }
            } else if !skip_response_capture && is_stream_response {
                // Streaming response: tee to forward chunks immediately while accumulating
                let (parts, body) = res.into_parts();

                // Use pooled buffer to reduce repeated allocations on high-throughput streams.
                let accumulated = Arc::new(Mutex::new(Some(acquire_stream_buffer())));
                let accumulated_clone = accumulated.clone();

                // Capture logging context for the spawned task
                let log_event_logger = event_logger.clone();
                let log_session_id = session_id.clone();
                let log_pending = pending.clone();
                let log_content_encoding = content_encoding.clone();
                let log_content_type = content_type.clone();
                let log_grpc_message_encoding = grpc_message_encoding.clone();
                let log_is_sse = is_sse;
                let log_oisp_engine = oisp_engine.clone();
                let log_budget_tracker = budget_tracker.clone();
                let log_event_tags = event_tags.clone();
                let log_pii_enricher = pii_enricher.clone();
                let log_exchange_v2_cfg = exchange_v2_cfg.clone();
                let log_exchange_bundle_version = exchange_bundle_version.clone();
                let log_response_headers = response_headers.clone();
                let log_provider = provider.clone();
                let log_stream_kind: &'static str = if is_sse {
                    "sse"
                } else if is_codex_response_path {
                    "codex"
                } else if is_gemini_bard_response_path {
                    "gemini_bard"
                } else {
                    "stream"
                };
                // Create a tee stream that yields frames while accumulating data
                let tee_stream = stream! {
                    let mut body = body;
                    let mut capture_limit_reported = false;
                    let mut stream_usage_parser: Option<OispStreamParser> = create_stream_usage_parser(
                        Some(log_oisp_engine.as_ref()),
                        log_provider.as_str(),
                        &log_pending.host,
                    );
                    loop {
                        match body.frame().await {
                            Some(Ok(frame)) => {
                                // Clone data for accumulation if it's a data frame
                                if let Some(data) = frame.data_ref() {
                                    if let Some(parser) = stream_usage_parser.as_mut() {
                                        parser.process_chunk(data);
                                    }
                                    let mut guard = accumulated_clone.lock();
                                    if let Some(ref mut acc) = *guard {
                                        // Limit accumulation to prevent memory issues.
                                        if append_stream_capture(acc, data) && !capture_limit_reported {
                                            capture_limit_reported = true;
                                            metrics::record_stream_capture_limit_reached(log_provider.as_str(), log_stream_kind);
                                            warn!(
                                                provider = %log_provider,
                                                host = %log_pending.host,
                                                path = %log_pending.path,
                                                max_bytes = STREAM_CAPTURE_MAX_BYTES,
                                                stream_kind = log_stream_kind,
                                                "Response stream capture limit reached; truncating buffered payload"
                                            );
                                        }
                                    }
                                }
                                // Yield the original frame immediately to client
                                yield Ok(frame);
                            }
                            Some(Err(e)) => {
                                warn!(error = %e, "Response stream error");
                                break;
                            }
                            None => {
                                // Stream ended
                                break;
                            }
                        }
                    }

                    // Stream ended - decompress and log the accumulated content
                    let (decoded_bytes, raw_content) = {
                        let raw_bytes = {
                            let mut guard = accumulated_clone.lock();
                            guard.take().unwrap_or_default()
                        };
                        let raw_len = raw_bytes.len();

                        debug!(
                            encoding = ?log_content_encoding,
                            raw_bytes = raw_len,
                            "Decompressing streamed response"
                        );

                        // Decode once and reuse decoded bytes for usage extraction.
                        let decoded = decode_payload_for_logging(&raw_bytes, log_content_encoding.as_deref());
                        release_stream_buffer(raw_bytes);
                        (decoded.0, decoded.1)
                    };
                    let stream_usage = stream_usage_parser.and_then(|parser| parser.finalize());
                    let mut usage_meta = extract_usage_meta_from_stream_usage(
                        Some(log_oisp_engine.as_ref()),
                        log_provider.as_str(),
                        &log_pending.host,
                        stream_usage,
                        log_pending.model.as_deref(),
                    );
                    if !usage_meta.has_signal() {
                        let usage_outcome = extract_usage_meta_for_mode(
                            Some(log_oisp_engine.as_ref()),
                            log_provider.as_str(),
                            &log_pending.host,
                            &decoded_bytes,
                            log_is_sse,
                            log_content_type.as_deref(),
                            log_grpc_message_encoding.as_deref(),
                            log_pending.model.as_deref(),
                        )
                        .await;
                        usage_meta = usage_outcome.primary;
                    }
                    if let Some(ref tracker) = log_budget_tracker {
                        record_proxy_budget_spend(
                            tracker,
                            &log_session_id,
                            &log_pending,
                            &usage_meta,
                        );
                    }
                    let response_text = if is_gemini_bard_stream_path(&log_pending.path) {
                        extract_gemini_bard_stream_text(&raw_content).unwrap_or(raw_content)
                    } else {
                        raw_content
                    };
                    let content = normalize_response_content(
                        Some(response_text.as_str()),
                        log_pending.request_content.as_deref(),
                        &log_pending.method,
                        &log_pending.path,
                        status,
                        log_is_sse,
                        true,
                    )
                    .unwrap_or_else(|| {
                        empty_response_placeholder(
                            &log_pending.method,
                            &log_pending.path,
                            status,
                            log_is_sse,
                        )
                    });

                    if let Some(ref logger) = log_event_logger {
                        let mut enriched_tags = (*log_event_tags).clone();
                        if log_pending.catalog_discovery {
                            append_catalog_discovery_tags(&mut enriched_tags, &log_pending.host);
                        }
                        append_process_attribution_tags(
                            &mut enriched_tags,
                            log_pending.envelope.as_ref(),
                        );
                        append_detection_tags(&mut enriched_tags, &log_pending);
                        append_capture_tags(
                            &mut enriched_tags,
                            log_pending.request_body_truncated,
                            capture_limit_reported,
                            if capture_limit_reported {
                                Some("stream_capture_limit_reached")
                            } else {
                                None
                            },
                            if capture_limit_reported {
                                Some(STREAM_CAPTURE_MAX_BYTES as u64)
                            } else {
                                None
                            },
                        );
                        let subscription_tags = extract_subscription_tags(
                            log_provider.as_str(),
                            &log_pending.host,
                            &log_pending.path,
                            content.as_str(),
                        );
                        if !subscription_tags.is_empty() {
                            enriched_tags.extend(subscription_tags);
                        }
                        let content_for_exchange = content.clone();
                        if let Some(exchange_cfg) = log_exchange_v2_cfg.as_ref() {
                            finalize_and_enqueue_exchange_v2(
                                logger,
                                exchange_cfg,
                                &log_pii_enricher,
                                &log_pending,
                                &log_session_id,
                                status,
                                true,
                                log_is_sse,
                                log_content_type.as_deref(),
                                Some(log_response_headers.clone()),
                                Some(content_for_exchange.as_str()),
                                &usage_meta,
                                Some(&enriched_tags),
                                capture_limit_reported,
                                if capture_limit_reported {
                                    Some("stream_capture_limit_reached")
                                } else {
                                    None
                                },
                                log_exchange_bundle_version.as_deref(),
                            );
                        }
                        debug!("Logged paired streamed request/response");
                    }
                };

                // Wrap the tee stream in StreamBody
                let stream_body = StreamBody::new(tee_stream);
                let new_body = Body::from(stream_body);
                let res = Response::from_parts(parts, new_body);

                // Return None for body_content - stream logging happens in tee stream.
                (None, res, true)
            } else {
                let placeholder = response_capture_reason.map(|reason| {
                    format!(
                        "[response body capture skipped: {} for {} {} (HTTP {})]",
                        reason, pending.method, pending.path, status
                    )
                });
                // Non-JSON, non-SSE - pass through without buffering
                (placeholder, res, false)
            };

            info!(
                provider = %provider,
                host = %pending.host,
                path = %pending.path,
                status = status,
                latency_ms = latency_ms,
                "AI API response"
            );

            if !logged_in_stream {
                if let Some(ref tracker) = budget_tracker {
                    record_proxy_budget_spend(tracker, &session_id, &pending, &response_usage);
                }
            }

            // Log paired request/response event (streamed responses are logged in tee stream)
            if !logged_in_stream {
                if let Some(ref logger) = event_logger {
                    emit_non_stream_response_event(
                        logger,
                        exchange_v2_cfg.as_ref(),
                        &pii_enricher,
                        &pending,
                        &session_id,
                        status,
                        is_stream_response,
                        is_sse,
                        content_type.as_deref(),
                        &response_headers,
                        body_content.as_deref(),
                        &response_usage,
                        &event_tags,
                        response_body_truncated,
                        response_capture_reason,
                        capture_max_body_bytes,
                        exchange_bundle_version.as_deref(),
                    );
                }
            }

            res
        }
    }

    fn handle_error(
        &mut self,
        ctx: &HttpContext,
        err: LegacyClientError,
    ) -> impl std::future::Future<Output = Response<Body>> + Send {
        let client_addr = ctx.client_addr;
        let request_id = self.request_correlation_id;
        let pending_requests = self.pending_requests.clone();
        let event_logger = self.event_logger.clone();
        let event_tags = self.event_tags.clone();
        let pii_enricher = self.pii_enricher.clone();
        let session_id = self.session_id.clone();
        let exchange_v2_cfg = self.exchange_v2.clone();
        let exchange_bundle_version = if exchange_v2_cfg.is_some() {
            Some(self.oisp_engine.bundle_version().to_string())
        } else {
            None
        };
        async move {
            handle_forward_error(
                client_addr,
                request_id,
                err,
                pending_requests,
                event_logger,
                event_tags,
                pii_enricher,
                session_id,
                exchange_v2_cfg,
                exchange_bundle_version,
            )
            .await
        }
    }

    /// Determine if CONNECT should be intercepted (MITM) or tunneled
    fn should_intercept(
        &mut self,
        _ctx: &HttpContext,
        req: &Request<Body>,
    ) -> impl std::future::Future<Output = bool> + Send {
        let host = extract_host(req);
        let action = self.get_connect_action(&host);
        let learned_passthrough = self.learned_passthrough.clone();
        let debug_force_intercept = self.is_force_intercept_all_active();

        async move {
            match action {
                HostAction::Intercept => {
                    if !debug_force_intercept {
                        if let Some(learned) = learned_passthrough.as_ref() {
                            if learned.should_passthrough(&host) {
                                metrics::record_tls_learned_passthrough("bypass");
                                metrics::set_tls_learned_passthrough_active(
                                    learned.active_count() as f64
                                );
                                debug!(host = %host, "Learned passthrough: blind tunnel");
                                return false;
                            }
                        }
                    } else {
                        debug!(
                            host = %host,
                            "Debug catch-all interception bypassing learned passthrough"
                        );
                    }
                    debug!(host = %host, "MITM intercept");
                    true
                }
                HostAction::Tunnel => {
                    debug!(host = %host, "Blind tunnel");
                    false
                }
                HostAction::Block => {
                    // Intercept so we can return 403 in handle_request
                    debug!(host = %host, "Will block");
                    true
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) use crate::transport::proxy_runtime::load_oisp_engine;
pub use crate::transport::proxy_runtime::{start_proxy, start_proxy_with_shutdown};

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod proxy_tests;
