//! Hudsucker-based Forward Proxy
//!
//! Uses the battle-tested hudsucker crate for MITM proxy functionality.
//! Provides selective interception: AI domains get MITM'd, others tunnel through.

use async_stream::stream;
use brotli::Decompressor as BrotliDecoder;
use chrono::{Duration as ChronoDuration, NaiveDate, Utc};
use flate2::read::GzDecoder;
use http_body_util::{BodyExt, Full, StreamBody};
use hudsucker::{
    certificate_authority::RcgenAuthority,
    hyper::{Request, Response},
    hyper_util::{
        client::legacy::Error as LegacyClientError, rt::TokioExecutor,
        server::conn::auto::Builder as AutoServerBuilder,
    },
    rcgen::{Issuer, KeyPair},
    rustls::crypto::aws_lc_rs,
    tokio_tungstenite::tungstenite::Message,
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse, WebSocketContext, WebSocketHandler,
};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde::Deserialize;
use soth_budget::{BudgetTracker, TokenCounter};
use soth_crypto::tls::LearnedPassthrough;
use soth_oisp::{InterceptDecision, OispEngine, OispStreamParser};
use soth_policy::PolicyEngine;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::error::Error as StdError;
use std::io::{Cursor, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use crate::enforcement::core as enforcement_core;
use crate::error::ProxyError;
use crate::json_security::strip_json_security_prefix_text;
use crate::metrics;
use crate::process_attribution::{ProcessAttribution, ProcessIdentity};
use crate::transport::exchange_assembler::{ExchangeAssembler, ExchangeAssemblerConfig};
use crate::transport::graphql_enrichment::extract_graphql_operation;
use crate::transport::host_fingerprint;
use crate::transport::mcp_detection::{extract_mcp_request_method, is_jsonrpc_response_for_mcp};
use crate::transport::pii_enrichment::PiiEventEnricher;
use crate::transport::response_event_builder::{
    build_paired_response_event, empty_response_placeholder, normalize_response_content,
    ResponseEventInput, ResponseKind,
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
use soth_core::types::exchange_v2::{
    ExchangeClient, ExchangeCost, ExchangeParse, ExchangeSourceClass, ExchangeTransport,
    ExchangeUsage,
};
use soth_core::types::{
    AgentInfo, DetectionSource, EventSource, TrafficEnvelope, WrapDirection, WrapEvent,
};
use soth_core::EventLogger;

/// AI request body structure for model extraction
#[derive(Debug, Deserialize)]
struct AiRequestBody {
    model: Option<String>,
}

/// Pending request info for correlating with responses
#[derive(Debug, Clone)]
struct PendingRequest {
    exchange_id: String,
    envelope: Option<TrafficEnvelope>,
    host: String,
    path: String,
    method: String,
    provider: Option<String>,
    agent: Option<&'static str>,
    model: Option<String>,
    graphql_operation: Option<String>,
    started_at: Instant,
    /// Request body content for paired logging
    request_content: Option<String>,
    /// Whether request body capture was truncated/skipped.
    request_body_truncated: bool,
    /// Request payload size in bytes (wire payload)
    request_size_bytes: Option<u64>,
    /// Sanitized request headers captured post-forward sanitation
    headers: Option<BTreeMap<String, String>>,
    /// Request content-type from ingress.
    request_content_type: Option<String>,
    /// Whether this is traffic from an agent app (chatgpt.com, claude.ai) vs direct API
    is_agent_app: bool,
    /// JSON-RPC MCP method (when this request is identified as MCP traffic)
    mcp_method: Option<String>,
    /// Whether this pending request should be emitted as MCP source.
    is_mcp_jsonrpc: bool,
    /// True when captured through discovery-mode catalog interception.
    catalog_discovery: bool,
    /// Bundle-based interception classification reason.
    detection_reason: Option<String>,
    /// Confidence score for detection reason.
    parse_confidence: Option<f64>,
    /// Policy decision metadata captured at request enforcement time.
    policy_allowed: Option<bool>,
    policy_reason: Option<String>,
    policy_version: Option<String>,
}

/// Thread-safe store for pending requests
type PendingRequests = Arc<Mutex<HashMap<u64, PendingRequest>>>;

static NEXT_PROXY_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

fn next_proxy_request_id() -> u64 {
    NEXT_PROXY_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
}

fn is_benign_proxy_forward_error(err: &LegacyClientError) -> bool {
    let mut source = err.source();
    while let Some(cause) = source {
        if let Some(hyper_error) = cause.downcast_ref::<hyper::Error>() {
            if hyper_error.is_canceled()
                || hyper_error.is_closed()
                || hyper_error.is_incomplete_message()
                || hyper_error.is_body_write_aborted()
            {
                return true;
            }
        }
        if let Some(io_error) = cause.downcast_ref::<std::io::Error>() {
            if matches!(
                io_error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::NotConnected
            ) {
                return true;
            }
        }
        source = cause.source();
    }
    false
}

const STREAM_CAPTURE_MAX_BYTES: usize = 1024 * 1024;
const STREAM_CAPTURE_INITIAL_CAPACITY: usize = 64 * 1024;
const STREAM_BUFFER_POOL_MAX_BUFFERS: usize = 32;
const PROCESS_ATTR_LOOKUP_TIMEOUT: Duration = Duration::from_millis(25);
const PROCESS_ATTR_CACHE_TTL: Duration = Duration::from_secs(30);

static STREAM_BUFFER_POOL: Lazy<Mutex<Vec<Vec<u8>>>> = Lazy::new(|| Mutex::new(Vec::new()));

fn acquire_stream_buffer() -> Vec<u8> {
    let mut pool = STREAM_BUFFER_POOL.lock();
    if let Some(mut buffer) = pool.pop() {
        buffer.clear();
        return buffer;
    }
    Vec::with_capacity(STREAM_CAPTURE_INITIAL_CAPACITY)
}

fn release_stream_buffer(mut buffer: Vec<u8>) {
    if buffer.capacity() > STREAM_CAPTURE_MAX_BYTES {
        return;
    }
    buffer.clear();
    let mut pool = STREAM_BUFFER_POOL.lock();
    if pool.len() < STREAM_BUFFER_POOL_MAX_BUFFERS {
        pool.push(buffer);
    }
}

/// Append a stream chunk into capture buffer with a hard memory cap.
/// Returns true when the cap is reached (or already reached).
fn append_stream_capture(buffer: &mut Vec<u8>, chunk: &[u8]) -> bool {
    if buffer.len() >= STREAM_CAPTURE_MAX_BYTES {
        return true;
    }
    let remaining = STREAM_CAPTURE_MAX_BYTES - buffer.len();
    let write_len = remaining.min(chunk.len());
    buffer.extend_from_slice(&chunk[..write_len]);
    write_len < chunk.len()
}

#[derive(Default)]
struct CatalogDiscoveryLimiter {
    seen_by_host_day: Mutex<HashMap<String, NaiveDate>>,
}

impl CatalogDiscoveryLimiter {
    fn normalized_host(host: &str) -> String {
        host.trim().to_ascii_lowercase()
    }

    fn reserve_once_per_day(&self, host: &str) -> bool {
        let normalized = Self::normalized_host(host);
        if normalized.is_empty() {
            return false;
        }

        let today = Utc::now().date_naive();
        let mut seen = self.seen_by_host_day.lock();
        let cutoff = today - ChronoDuration::days(1);
        seen.retain(|_, day| *day >= cutoff);
        if seen.get(normalized.as_str()) == Some(&today) {
            return false;
        }
        seen.insert(normalized, today);
        true
    }

    fn was_reserved_today(&self, host: &str) -> bool {
        let normalized = Self::normalized_host(host);
        if normalized.is_empty() {
            return false;
        }
        let today = Utc::now().date_naive();
        let seen = self.seen_by_host_day.lock();
        seen.get(normalized.as_str()) == Some(&today)
    }
}

fn append_catalog_discovery_tags(tags: &mut BTreeMap<String, String>, host: &str) {
    tags.insert("discovery_mode".to_string(), "catalog".to_string());
    tags.insert("discovery_capture".to_string(), "daily_first".to_string());
    tags.insert("discovery_payload".to_string(), "metadata_only".to_string());
    tags.insert("discovery_host".to_string(), host.to_string());
}

fn detection_reason_for_bucket(
    host_is_ai_target: bool,
    host_is_mcp_target: bool,
    host_is_agent_target: bool,
    is_catalog_discovery: bool,
) -> Option<&'static str> {
    if is_catalog_discovery {
        return Some("bundle.discovery.catalog");
    }
    if host_is_ai_target {
        return Some("bundle.whitelist.ai_inference");
    }
    if host_is_mcp_target {
        return Some("bundle.whitelist.mcp");
    }
    if host_is_agent_target {
        return Some("bundle.whitelist.agent_apps");
    }
    None
}

fn parse_confidence_for_reason(reason: Option<&str>) -> Option<f64> {
    match reason {
        Some("bundle.discovery.catalog") => Some(0.7),
        Some(_) => Some(1.0),
        None => None,
    }
}

fn append_capture_tags(
    tags: &mut BTreeMap<String, String>,
    request_body_truncated: bool,
    response_body_truncated: bool,
    response_reason: Option<&str>,
    capture_limit_bytes: Option<u64>,
) {
    if request_body_truncated {
        tags.insert("capture.request_body".to_string(), "truncated".to_string());
    }
    if response_body_truncated {
        tags.insert("capture.response_body".to_string(), "truncated".to_string());
        if let Some(reason) = response_reason {
            tags.insert("capture.response_reason".to_string(), reason.to_string());
        }
    }
    if let Some(limit) = capture_limit_bytes {
        tags.insert("capture.body_limit_bytes".to_string(), limit.to_string());
    }
}

/// Identity verification mode for proxy enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyIdentityMode {
    Disabled,
    Optional,
    Required,
}

/// Policy mode for proxy enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyPolicyMode {
    Disabled,
    Audit,
    Enforce,
}

/// Request enforcement configuration for hudsucker transport.
#[derive(Clone)]
pub struct ProxyEnforcer {
    identity_mode: ProxyIdentityMode,
    did_header: String,
    signature_header: String,
    trusted_dids: Arc<HashSet<String>>,
    required_principals: Arc<HashSet<String>>,
    policy_mode: ProxyPolicyMode,
    policy_engine: Option<Arc<PolicyEngine>>,
    policy_fail_open: bool,
    budget_tracker: Option<Arc<BudgetTracker>>,
    budget_block_on_exceeded: bool,
    budget_fail_open: bool,
    default_model: String,
    fail_open_enabled: bool,
    enforcement_timeout: Duration,
}

type EnforcementResult = enforcement_core::IdentityResult;

impl ProxyEnforcer {
    /// Create a default no-op enforcer.
    pub fn new() -> Self {
        Self {
            identity_mode: ProxyIdentityMode::Disabled,
            did_header: "X-Agent-DID".to_string(),
            signature_header: "X-Agent-Signature".to_string(),
            trusted_dids: Arc::new(HashSet::new()),
            required_principals: Arc::new(HashSet::new()),
            policy_mode: ProxyPolicyMode::Disabled,
            policy_engine: None,
            policy_fail_open: true,
            budget_tracker: None,
            budget_block_on_exceeded: true,
            budget_fail_open: true,
            default_model: "gpt-4o".to_string(),
            fail_open_enabled: true,
            enforcement_timeout: Duration::from_millis(500),
        }
    }

    pub fn with_identity_mode(
        mut self,
        mode: ProxyIdentityMode,
        trusted_dids: HashSet<String>,
    ) -> Self {
        self.identity_mode = mode;
        self.trusted_dids = Arc::new(trusted_dids);
        self
    }

    pub fn with_required_principals(mut self, required_principals: HashSet<String>) -> Self {
        self.required_principals = Arc::new(required_principals);
        self
    }

    pub fn with_identity_headers(
        mut self,
        did_header: impl Into<String>,
        signature_header: impl Into<String>,
    ) -> Self {
        self.did_header = did_header.into();
        self.signature_header = signature_header.into();
        self
    }

    pub fn with_policy(mut self, mode: ProxyPolicyMode, engine: PolicyEngine) -> Self {
        self.policy_mode = mode;
        self.policy_engine = Some(Arc::new(engine));
        self
    }

    pub fn with_budget(
        mut self,
        tracker: BudgetTracker,
        block_on_exceeded: bool,
        default_model: impl Into<String>,
    ) -> Self {
        self.budget_tracker = Some(Arc::new(tracker));
        self.budget_block_on_exceeded = block_on_exceeded;
        self.default_model = default_model.into();
        self
    }

    pub fn with_fail_open(
        mut self,
        enabled: bool,
        enforcement_timeout: Duration,
        policy_fail_open: bool,
        budget_fail_open: bool,
    ) -> Self {
        self.fail_open_enabled = enabled;
        self.enforcement_timeout = enforcement_timeout;
        self.policy_fail_open = policy_fail_open;
        self.budget_fail_open = budget_fail_open;
        self
    }

    pub fn did_header(&self) -> &str {
        &self.did_header
    }

    pub fn signature_header(&self) -> &str {
        &self.signature_header
    }

    pub fn policy_engine(&self) -> Option<Arc<PolicyEngine>> {
        self.policy_engine.clone()
    }

    fn core_identity_mode(&self) -> enforcement_core::IdentityMode {
        match self.identity_mode {
            ProxyIdentityMode::Disabled => enforcement_core::IdentityMode::Disabled,
            ProxyIdentityMode::Optional => enforcement_core::IdentityMode::Optional,
            ProxyIdentityMode::Required => enforcement_core::IdentityMode::Required,
        }
    }

    fn core_policy_mode(&self) -> enforcement_core::PolicyMode {
        match self.policy_mode {
            ProxyPolicyMode::Disabled => enforcement_core::PolicyMode::Disabled,
            ProxyPolicyMode::Audit => enforcement_core::PolicyMode::Audit,
            ProxyPolicyMode::Enforce => enforcement_core::PolicyMode::Enforce,
        }
    }

    fn enforce_envelope(
        &self,
        envelope: &TrafficEnvelope,
    ) -> Result<EnforcementResult, (u16, String, Option<String>)> {
        let result = enforcement_core::enforce_proxy_request(
            enforcement_core::ProxyEnforcementConfig {
                identity_mode: self.core_identity_mode(),
                trusted_dids: self.trusted_dids.as_ref(),
                required_principals: self.required_principals.as_ref(),
                policy_mode: self.core_policy_mode(),
                policy_engine: self.policy_engine.as_deref(),
                policy_fail_open: self.policy_fail_open,
                budget_tracker: self.budget_tracker.as_deref(),
                budget_block_on_exceeded: self.budget_block_on_exceeded,
                budget_fail_open: self.budget_fail_open,
                default_model: &self.default_model,
            },
            enforcement_core::ProxyEnforcementInput { envelope },
        );
        if let Err((_, ref reason, _)) = result {
            if self.policy_mode == ProxyPolicyMode::Audit {
                warn!("Policy audit violation: {}", reason);
            }
        }
        result
    }

    async fn enforce_envelope_with_timeout(
        &self,
        envelope: &TrafficEnvelope,
    ) -> Result<EnforcementResult, (u16, String, Option<String>)> {
        let envelope = envelope.clone();
        let identity_mode = self.core_identity_mode();
        let trusted_dids = Arc::clone(&self.trusted_dids);
        let required_principals = Arc::clone(&self.required_principals);
        let policy_mode = self.core_policy_mode();
        let policy_engine = self.policy_engine.clone();
        let policy_fail_open = self.policy_fail_open;
        let budget_tracker = self.budget_tracker.clone();
        let budget_block_on_exceeded = self.budget_block_on_exceeded;
        let budget_fail_open = self.budget_fail_open;
        let default_model = self.default_model.clone();

        let timeout_result = tokio::time::timeout(
            self.enforcement_timeout,
            tokio::task::spawn_blocking(move || {
                let config = enforcement_core::ProxyEnforcementConfig {
                    identity_mode,
                    trusted_dids: trusted_dids.as_ref(),
                    required_principals: required_principals.as_ref(),
                    policy_mode,
                    policy_engine: policy_engine.as_deref(),
                    policy_fail_open,
                    budget_tracker: budget_tracker.as_deref(),
                    budget_block_on_exceeded,
                    budget_fail_open,
                    default_model: &default_model,
                };
                enforcement_core::enforce_proxy_request(
                    config,
                    enforcement_core::ProxyEnforcementInput {
                        envelope: &envelope,
                    },
                )
            }),
        )
        .await;

        match timeout_result {
            Ok(Ok(result)) => result,
            Ok(Err(err)) => {
                if self.fail_open_enabled {
                    metrics::record_enforcement_failopen("panic");
                    warn!(
                        error = %err,
                        "Enforcement task join failed; failing open"
                    );
                    Ok(EnforcementResult::default())
                } else {
                    Err((
                        503,
                        "Enforcement unavailable (task join failure)".to_string(),
                        None,
                    ))
                }
            }
            Err(_) => {
                if self.fail_open_enabled {
                    metrics::record_enforcement_failopen("timeout");
                    warn!(
                        timeout_ms = self.enforcement_timeout.as_millis(),
                        "Enforcement timed out; failing open"
                    );
                    Ok(EnforcementResult::default())
                } else {
                    Err((
                        503,
                        format!(
                            "Enforcement timed out after {}ms",
                            self.enforcement_timeout.as_millis()
                        ),
                        None,
                    ))
                }
            }
        }
    }

    #[allow(dead_code)]
    fn enforce_request(
        &self,
        session_id: &str,
        provider: &str,
        host: &str,
        http_method: &str,
        path: &str,
        model: Option<&str>,
        request_body: Option<&str>,
        agent: Option<&str>,
        did: Option<&str>,
        signature: Option<&str>,
    ) -> Result<EnforcementResult, (u16, String, Option<String>)> {
        let envelope = TrafficEnvelope::proxy(
            session_id,
            "legacy-request",
            provider,
            host,
            http_method,
            path,
            model,
            agent,
            did,
            signature,
            request_body,
        );
        self.enforce_envelope(&envelope)
    }
}

impl Default for ProxyEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

/// Headers to remove from proxied requests to prevent 431 errors
/// These headers can accumulate or cause issues when passing through a MITM proxy
const HEADERS_TO_STRIP: &[&str] = &[
    // Proxy hop headers that can accumulate
    "via",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-server",
    "forwarded",
    "x-real-ip",
    // Connection management (we handle these)
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    // These can cause issues with MITM
    "expect-ct",
    "public-key-pins",
    "public-key-pins-report-only",
    // Alt-Svc can cause connection issues
    "alt-svc",
    // Cloudflare/CDN headers that can accumulate
    "cf-connecting-ip",
    "cf-ipcountry",
    "cf-ray",
    "cf-visitor",
    "true-client-ip",
    "x-cluster-client-ip",
];

/// Keep cookie header reasonably bounded without breaking login/session state.
const CHATGPT_MAX_COOKIE_HEADER_BYTES: usize = 3500;
/// Second-pass cap when total header budget is still too high.
const CHATGPT_STRICT_COOKIE_HEADER_BYTES: usize = 900;
/// Chat UI upstreams can be stricter than generic HTTP servers.
const CHAT_UI_STRICT_TOTAL_HEADER_BYTES: usize = 5200;
const CHAT_UI_MAX_TOTAL_HEADER_BYTES: usize = 3000;
const LARGE_HEADER_DEBUG_BYTES: usize = 8000;
const LARGE_HEADER_WARN_BYTES: usize = 12000;

fn is_chat_ui_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    if host.contains("chatgpt.com") {
        return true;
    }
    if host == "chat.openai.com" || host.ends_with(".chat.openai.com") {
        return true;
    }
    // Include OpenAI web subdomains while excluding the direct API domain.
    if host.ends_with(".openai.com") && !host.starts_with("api.") {
        return true;
    }
    false
}

fn chatgpt_cookie_priority(name: &str) -> u8 {
    match name {
        // NextAuth/Auth.js session and csrf cookies (highest priority for login state)
        "__Secure-next-auth.session-token" => 0,
        "__Host-next-auth.csrf-token" => 0,
        "__Secure-next-auth.callback-url" => 1,
        "__Secure-authjs.session-token" => 0,
        "__Host-authjs.csrf-token" => 0,
        "__Secure-authjs.callback-url" => 1,
        // OpenAI account identifiers
        "_account" | "_puid" | "oai-did" => 1,
        // Cloudflare access checks
        "__cf_bm" | "cf_clearance" => 1,
        _ => {
            if name.starts_with("__Secure-") || name.starts_with("__Host-") {
                return 2;
            }
            if name.starts_with("oai-") || name.starts_with("__cf") || name.starts_with("cf_") {
                return 3;
            }
            if name.contains("session") || name.contains("token") || name.contains("auth") {
                return 4;
            }
            10
        }
    }
}

fn trim_cookie_header_for_chatgpt(cookie_str: &str, max_bytes: usize) -> Option<String> {
    let parts: Vec<&str> = cookie_str
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    if parts.is_empty() {
        return None;
    }

    // Deduplicate by name while keeping the last seen value (browser semantics).
    let mut by_name: HashMap<String, (usize, String)> = HashMap::new();
    for (idx, raw_part) in parts.iter().enumerate() {
        let (name, value) = match raw_part.split_once('=') {
            Some((name, value)) => (name.trim(), value.trim()),
            None => continue,
        };
        if name.is_empty() {
            continue;
        }
        by_name.insert(name.to_string(), (idx, value.to_string()));
    }

    if by_name.is_empty() {
        return None;
    }

    let mut ranked: Vec<(u8, usize, String)> = by_name
        .into_iter()
        .map(|(name, (idx, value))| {
            let prio = chatgpt_cookie_priority(&name);
            (prio, idx, format!("{}={}", name, value))
        })
        .collect();
    ranked.sort_by_key(|(prio, idx, _)| (*prio, *idx));

    let mut kept = Vec::new();
    let mut total_len = 0usize;

    for (_, _, item) in ranked {
        let next_len = if kept.is_empty() {
            item.len()
        } else {
            total_len + 2 + item.len()
        };
        if next_len <= max_bytes {
            total_len = next_len;
            kept.push(item);
        }
    }

    if kept.is_empty() {
        return None;
    }

    Some(kept.join("; "))
}

fn header_size_bytes(headers: &hyper::HeaderMap) -> usize {
    headers
        .iter()
        .map(|(k, v)| k.as_str().len() + v.len() + 4)
        .sum()
}

fn parse_content_length(headers: &hyper::HeaderMap) -> Option<u64> {
    headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
}

fn is_sensitive_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "api-key"
            | "x-auth-token"
            | "x-csrf-token"
            | "x-xsrf-token"
    ) || name.contains("sentinel")
        || name.contains("token")
}

fn capture_sanitized_headers(headers: &hyper::HeaderMap) -> BTreeMap<String, String> {
    const MAX_CAPTURE_HEADERS: usize = 64;
    const MAX_HEADER_VALUE_CHARS: usize = 192;
    const REDACTED: &str = "[redacted]";

    let mut captured: BTreeMap<String, String> = BTreeMap::new();
    for (idx, (name, value)) in headers.iter().enumerate() {
        if idx >= MAX_CAPTURE_HEADERS {
            break;
        }

        let name = name.as_str().to_ascii_lowercase();
        let rendered = if is_sensitive_header(&name) {
            REDACTED.to_string()
        } else if let Ok(text) = value.to_str() {
            let char_count = text.chars().count();
            if char_count > MAX_HEADER_VALUE_CHARS {
                let mut truncated = String::with_capacity(MAX_HEADER_VALUE_CHARS + 3);
                for ch in text.chars().take(MAX_HEADER_VALUE_CHARS) {
                    truncated.push(ch);
                }
                truncated.push_str("...");
                truncated
            } else {
                text.to_string()
            }
        } else {
            format!("[binary:{} bytes]", value.as_bytes().len())
        };

        if let Some(existing) = captured.get_mut(&name) {
            if existing != &rendered {
                existing.push_str("; ");
                existing.push_str(&rendered);
            }
        } else {
            captured.insert(name, rendered);
        }
    }

    captured
}

fn is_required_chat_ui_header(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "user-agent"
            | "accept"
            | "accept-encoding"
            | "content-type"
            | "content-length"
            | "authorization"
            | "cookie"
            | "connection"
            | "upgrade"
            | "sec-websocket-key"
            | "sec-websocket-version"
            | "sec-websocket-protocol"
            | "origin"
            | "referer"
            | "accept-language"
    ) || name.starts_with("x-openai-")
        || name.starts_with("openai-")
}

fn reduce_chat_ui_headers_for_budget<T>(req: &mut Request<T>, path: &str) {
    let headers = req.headers_mut();
    let is_backend_api = path.contains("/backend-api/");

    // Do not run strict auth/header pruning for non-backend chat UI routes
    // (e.g. login/session pages), because dropping cookies there can cause auth loops.
    if !is_backend_api {
        return;
    }

    if header_size_bytes(headers) <= CHAT_UI_STRICT_TOTAL_HEADER_BYTES {
        return;
    }

    // Keep only a narrow allowlist of headers needed for auth + websocket + request semantics.
    let names: Vec<String> = headers.keys().map(|k| k.as_str().to_string()).collect();
    for name in names {
        if !is_required_chat_ui_header(&name) {
            headers.remove(name.as_str());
        }
    }

    // Re-trim cookie with stricter cap.
    if let Some(cookie_val) = headers.get("cookie").cloned() {
        if let Ok(cookie_str) = cookie_val.to_str() {
            if let Some(trimmed) =
                trim_cookie_header_for_chatgpt(cookie_str, CHATGPT_STRICT_COOKIE_HEADER_BYTES)
            {
                if let Ok(new_val) = hyper::header::HeaderValue::from_str(&trimmed) {
                    headers.remove("cookie");
                    headers.insert("cookie", new_val);
                }
            } else {
                headers.remove("cookie");
            }
        }
    }

    // If still too big, remove low-priority browser context headers.
    if header_size_bytes(headers) > CHAT_UI_MAX_TOTAL_HEADER_BYTES {
        for header_name in ["referer", "origin", "accept-language"] {
            headers.remove(header_name);
        }
    }

    // Absolute last resort for backend API only.
    if header_size_bytes(headers) > CHAT_UI_MAX_TOTAL_HEADER_BYTES {
        headers.remove("cookie");
    }
}

/// Sanitize request headers to prevent 431 errors and WebSocket issues
/// Only applies aggressive cookie trimming for ChatGPT (which has large cookies)
fn sanitize_request_headers<T>(req: &mut Request<T>, host: &str, path: &str) {
    let is_chatgpt = is_chat_ui_host(host);

    {
        let headers = req.headers_mut();

        // Remove known problematic headers
        for header_name in HEADERS_TO_STRIP {
            headers.remove(*header_name);
        }

        // Remove WebSocket compression extension to prevent "Reserved bits are non-zero" errors
        headers.remove("sec-websocket-extensions");

        // Remove Client Hints headers (only for ChatGPT to reduce header size)
        if is_chatgpt {
            headers.remove("sec-ch-ua");
            headers.remove("sec-ch-ua-mobile");
            headers.remove("sec-ch-ua-platform");
            headers.remove("sec-ch-ua-platform-version");
            headers.remove("sec-ch-ua-model");
            headers.remove("sec-ch-ua-full-version-list");
            headers.remove("sec-ch-ua-arch");
            headers.remove("sec-ch-ua-bitness");
            headers.remove("sec-ch-prefers-color-scheme");
            headers.remove("sec-ch-prefers-reduced-motion");
            headers.remove("upgrade-insecure-requests");
            headers.remove("dnt");
            headers.remove("priority");

            // Trim cookies for ChatGPT (they can exceed upstream header limits and trigger 431).
            if let Some(cookie_val) = headers.get("cookie").cloned() {
                if let Ok(cookie_str) = cookie_val.to_str() {
                    let original_len = cookie_str.len();
                    if let Some(trimmed) =
                        trim_cookie_header_for_chatgpt(cookie_str, CHATGPT_MAX_COOKIE_HEADER_BYTES)
                    {
                        let trimmed_len = trimmed.len();
                        if trimmed_len < original_len {
                            if let Ok(new_val) = hyper::header::HeaderValue::from_str(&trimmed) {
                                headers.remove("cookie");
                                headers.insert("cookie", new_val);
                                debug!(
                                    before = original_len,
                                    after = trimmed_len,
                                    saved = original_len - trimmed_len,
                                    max = CHATGPT_MAX_COOKIE_HEADER_BYTES,
                                    "ChatGPT cookie trimming"
                                );
                            }
                        }
                    } else {
                        // If parsing failed, remove malformed cookie header rather than forwarding an oversized header.
                        headers.remove("cookie");
                        debug!(
                            before = original_len,
                            "Dropped malformed ChatGPT cookie header"
                        );
                    }
                }
            }

            // Safety pass: if cookie is still too large, cap harder to avoid 431.
            if let Some(cookie_val) = headers.get("cookie").cloned() {
                if let Ok(cookie_str) = cookie_val.to_str() {
                    if cookie_str.len() > CHATGPT_MAX_COOKIE_HEADER_BYTES {
                        if let Some(trimmed) = trim_cookie_header_for_chatgpt(
                            cookie_str,
                            CHATGPT_MAX_COOKIE_HEADER_BYTES,
                        ) {
                            if let Ok(new_val) = hyper::header::HeaderValue::from_str(&trimmed) {
                                headers.remove("cookie");
                                headers.insert("cookie", new_val);
                            }
                        } else {
                            headers.remove("cookie");
                        }
                    }
                }
            }

            // If headers are still large, drop optional browser-only headers before forwarding.
            let mut total_size = header_size_bytes(headers);
            if total_size > 7600 {
                for header_name in [
                    "referer",
                    "origin",
                    "accept-language",
                    "sec-fetch-site",
                    "sec-fetch-mode",
                    "sec-fetch-dest",
                    "sec-fetch-user",
                ] {
                    headers.remove(header_name);
                }
                total_size = header_size_bytes(headers);
            }

            // Last resort: only drop cookie for backend API calls where bearer auth exists.
            // Keeping cookies on non-backend routes avoids login/session redirect loops.
            if total_size > 7600
                && path.contains("/backend-api/")
                && headers.contains_key("authorization")
            {
                headers.remove("cookie");
            }
        }
    }

    // Final strict budget pass for chat UI hosts.
    if is_chatgpt {
        reduce_chat_ui_headers_for_budget(req, path);
    }

    // Calculate final header size and warn if still large
    let headers = req.headers();
    let total_size = header_size_bytes(headers);

    if total_size > LARGE_HEADER_DEBUG_BYTES {
        let mut sizes: Vec<(String, usize)> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.len()))
            .collect();
        sizes.sort_by(|a, b| b.1.cmp(&a.1));
        let top3: String = sizes
            .iter()
            .take(3)
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(", ");

        if total_size > LARGE_HEADER_WARN_BYTES {
            warn!(
                total = total_size,
                top = %top3,
                host = %host,
                "Large headers"
            );
        } else {
            debug!(
                total = total_size,
                top = %top3,
                host = %host,
                "Large headers (within tolerated range after sanitization)"
            );
        }
    }
}

/// Detect compression type from magic bytes (fallback when content-encoding header is missing)
fn detect_compression_from_bytes(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() < 4 {
        return None;
    }
    // Zstd magic: 28 B5 2F FD
    if bytes[0] == 0x28 && bytes[1] == 0xB5 && bytes[2] == 0x2F && bytes[3] == 0xFD {
        return Some("zstd");
    }
    // Gzip magic: 1f 8b
    if bytes[0] == 0x1f && bytes[1] == 0x8b {
        return Some("gzip");
    }
    // Zlib/deflate magic: 78 01, 78 5e, 78 9c, 78 da
    if bytes[0] == 0x78
        && (bytes[1] == 0x01 || bytes[1] == 0x5e || bytes[1] == 0x9c || bytes[1] == 0xda)
    {
        return Some("deflate");
    }
    // Brotli doesn't have a fixed magic - only try as last resort with header hint
    None
}

fn parse_content_encoding_chain(encoding: Option<&str>) -> Vec<String> {
    let mut codings = Vec::new();
    if let Some(enc) = encoding {
        for token in enc.split(',') {
            let coding = token
                .trim()
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            if coding.is_empty() || coding == "identity" {
                continue;
            }
            codings.push(coding);
        }
    }
    codings
}

fn decompress_once(bytes: &[u8], encoding: &str) -> Option<Vec<u8>> {
    match encoding {
        "zstd" => {
            let cursor = Cursor::new(bytes);
            let mut decoder = zstd::stream::Decoder::new(cursor).ok()?;
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).ok()?;
            Some(out)
        }
        "gzip" => {
            let mut decoder = GzDecoder::new(bytes);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).ok()?;
            Some(out)
        }
        "br" | "brotli" => {
            let mut decoder = BrotliDecoder::new(bytes, 4096);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).ok()?;
            Some(out)
        }
        "deflate" => {
            // In practice "deflate" is often zlib-wrapped, sometimes raw deflate.
            use flate2::read::{DeflateDecoder, ZlibDecoder};

            let mut zlib_decoder = ZlibDecoder::new(bytes);
            let mut zlib_out = Vec::new();
            if zlib_decoder.read_to_end(&mut zlib_out).is_ok() && !zlib_out.is_empty() {
                return Some(zlib_out);
            }

            let mut deflate_decoder = DeflateDecoder::new(bytes);
            let mut deflate_out = Vec::new();
            if deflate_decoder.read_to_end(&mut deflate_out).is_ok() && !deflate_out.is_empty() {
                return Some(deflate_out);
            }

            None
        }
        _ => None,
    }
}

fn maybe_binary_placeholder(bytes: &[u8], encoding: Option<&str>) -> Option<String> {
    let lossy = String::from_utf8_lossy(bytes);
    let sample: Vec<char> = lossy.chars().take(4096).collect();
    let chars = sample.len().max(1);
    let replacement_chars = sample.iter().filter(|c| **c == '\u{FFFD}').count();
    let control_chars = sample
        .iter()
        .filter(|c| c.is_control() && **c != '\n' && **c != '\r' && **c != '\t')
        .count();
    let ascii_printable = sample
        .iter()
        .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        .count();
    let replacement_ratio = replacement_chars as f32 / chars as f32;
    let control_ratio = control_chars as f32 / chars as f32;
    let ascii_printable_ratio = ascii_printable as f32 / chars as f32;

    let has_magic = detect_compression_from_bytes(bytes).is_some();
    let looks_binary = replacement_chars >= 2
        || replacement_ratio >= 0.04
        || control_ratio >= 0.03
        || ascii_printable_ratio < 0.55
        || (has_magic && bytes.len() <= 16);

    if looks_binary {
        let coding = parse_content_encoding_chain(encoding)
            .first()
            .cloned()
            .or_else(|| detect_compression_from_bytes(bytes).map(str::to_string))
            .unwrap_or_else(|| "binary".to_string());
        return Some(format!(
            "[compressed/{} payload: {} bytes]",
            coding,
            bytes.len()
        ));
    }

    None
}

/// Try to decompress bytes using Content-Encoding chain, then heuristic fallbacks.
/// Returns original bytes if all decoding attempts fail.
fn try_decompress(bytes: &[u8], encoding: Option<&str>) -> Vec<u8> {
    let chain = parse_content_encoding_chain(encoding);

    // RFC: encodings are listed in application order; decode in reverse.
    if !chain.is_empty() {
        let mut current = bytes.to_vec();
        let mut ok = true;
        for coding in chain.iter().rev() {
            match decompress_once(&current, coding) {
                Some(next) => current = next,
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if ok && !current.is_empty() {
            return current;
        }
    }

    // Fallback 1: direct decode from magic bytes (missing/incorrect header).
    if let Some(detected) = detect_compression_from_bytes(bytes) {
        if let Some(out) = decompress_once(bytes, detected) {
            if !out.is_empty() {
                return out;
            }
        }
    }

    // Fallback 2: iterative magic decode for stacked codings.
    let mut current = bytes.to_vec();
    let mut changed = false;
    for _ in 0..3 {
        let Some(detected) = detect_compression_from_bytes(&current) else {
            break;
        };
        match decompress_once(&current, detected) {
            Some(next) if !next.is_empty() => {
                current = next;
                changed = true;
            }
            _ => break,
        }
    }
    if changed {
        return current;
    }

    bytes.to_vec()
}

fn render_decoded_body_for_logging(decoded: &[u8], encoding: Option<&str>) -> String {
    if let Ok(text) = std::str::from_utf8(decoded) {
        if let Some(marker) = maybe_binary_placeholder(decoded, encoding) {
            return marker;
        }
        return text.to_string();
    }
    if let Some(marker) = maybe_binary_placeholder(decoded, encoding) {
        return marker;
    }
    String::from_utf8_lossy(decoded).to_string()
}

#[cfg(test)]
fn decode_body_for_logging(bytes: &[u8], encoding: Option<&str>) -> String {
    let decoded = try_decompress(bytes, encoding);
    render_decoded_body_for_logging(&decoded, encoding)
}

fn decode_payload_for_logging(bytes: &[u8], encoding: Option<&str>) -> (Vec<u8>, String) {
    let decoded = try_decompress(bytes, encoding);
    let rendered = render_decoded_body_for_logging(&decoded, encoding);
    (decoded, rendered)
}
fn is_gemini_bard_stream_path(path: &str) -> bool {
    path.to_ascii_lowercase()
        .contains("bardfrontendservice/streamgenerate")
}

fn update_longest_text(candidate: &str, longest: &mut Option<String>) {
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return;
    }

    let should_replace = longest
        .as_ref()
        .map(|current| trimmed.len() > current.len())
        .unwrap_or(true);

    if should_replace {
        *longest = Some(trimmed.to_string());
    }
}

fn collect_bard_response_text(value: &serde_json::Value, longest: &mut Option<String>) {
    match value {
        serde_json::Value::Array(items) => {
            if let Some(id) = items.first().and_then(|v| v.as_str()) {
                if id.starts_with("rc_") {
                    if let Some(text_items) = items.get(1).and_then(|v| v.as_array()) {
                        for text_item in text_items {
                            if let Some(text) = text_item.as_str() {
                                update_longest_text(text, longest);
                            }
                        }
                    }
                }
            }

            for item in items {
                collect_bard_response_text(item, longest);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values() {
                collect_bard_response_text(item, longest);
            }
        }
        _ => {}
    }
}

fn extract_gemini_bard_stream_text(raw: &str) -> Option<String> {
    let mut longest: Option<String> = None;

    for line in raw.lines() {
        let trimmed = line.trim();
        let sanitized = strip_json_security_prefix_text(trimmed);
        if sanitized.is_empty() {
            continue;
        }

        if !sanitized.starts_with('[') {
            // Batch framing length lines are numeric and can be ignored.
            continue;
        }

        let Ok(wrapper) = serde_json::from_str::<serde_json::Value>(sanitized) else {
            continue;
        };

        let Some(records) = wrapper.as_array() else {
            continue;
        };

        for record in records {
            let Some(entry) = record.as_array() else {
                continue;
            };
            if entry.first().and_then(|v| v.as_str()) != Some("wrb.fr") {
                continue;
            }

            let Some(inner_json) = entry.get(2).and_then(|v| v.as_str()) else {
                continue;
            };

            let Ok(inner) = serde_json::from_str::<serde_json::Value>(inner_json) else {
                continue;
            };
            collect_bard_response_text(&inner, &mut longest);
        }
    }

    longest
}

/// Record proxy spend using response usage as the primary source, with request-body
/// token estimation as fallback when provider usage is unavailable.
fn record_proxy_budget_spend(
    tracker: &BudgetTracker,
    session_id: &str,
    pending: &PendingRequest,
    usage_meta: &ResponseUsageMeta,
) {
    let input_tokens = usage_meta.input_tokens.unwrap_or_else(|| {
        pending
            .request_content
            .as_deref()
            .map(TokenCounter::estimate_tokens)
            .unwrap_or(0)
    });
    let output_tokens = usage_meta.output_tokens.unwrap_or(0);

    if input_tokens == 0 && output_tokens == 0 {
        return;
    }

    let model = usage_meta
        .model
        .as_deref()
        .or(pending.model.as_deref())
        .unwrap_or("unknown");
    let agent_id = pending
        .envelope
        .as_ref()
        .and_then(|envelope| envelope.did.as_deref())
        .or(pending.agent);

    tracker.record_spend_with_cost(
        session_id,
        agent_id,
        model,
        input_tokens,
        output_tokens,
        usage_meta.cost_usd,
    );
}

fn source_class_for_pending(pending: &PendingRequest) -> ExchangeSourceClass {
    if pending.is_mcp_jsonrpc {
        ExchangeSourceClass::Mcp
    } else if pending.is_agent_app {
        ExchangeSourceClass::AgentApp
    } else {
        ExchangeSourceClass::AiInference
    }
}

fn transport_for_pending(
    pending: &PendingRequest,
    is_stream: bool,
    is_sse: bool,
) -> ExchangeTransport {
    if pending.is_mcp_jsonrpc {
        return ExchangeTransport::Jsonrpc;
    }
    if is_stream {
        if is_sse {
            return ExchangeTransport::Sse;
        }
        return ExchangeTransport::Ws;
    }
    ExchangeTransport::Https
}

fn event_source_for_pending(pending: &PendingRequest) -> EventSource {
    if pending.is_mcp_jsonrpc {
        EventSource::Mcp
    } else if pending.is_agent_app {
        EventSource::AgentApp
    } else {
        EventSource::AiProxy
    }
}

fn exchange_client_from_envelope(envelope: Option<&TrafficEnvelope>) -> Option<ExchangeClient> {
    let envelope = envelope?;
    if envelope.process_pid.is_none()
        && envelope.process_name.is_none()
        && envelope.process_executable.is_none()
    {
        return None;
    }

    let bundle_id = envelope.process_executable.as_deref().and_then(|path| {
        let lower = path.to_ascii_lowercase();
        lower.find(".app/").and_then(|idx| {
            let app_root = &path[..idx + 4];
            let app = app_root
                .rsplit('/')
                .next()
                .unwrap_or(app_root)
                .trim_end_matches(".app")
                .trim();
            if app.is_empty() {
                None
            } else {
                Some(format!(
                    "macos.{}",
                    app.chars()
                        .map(|ch| if ch.is_ascii_alphanumeric() {
                            ch.to_ascii_lowercase()
                        } else {
                            '_'
                        })
                        .collect::<String>()
                        .trim_matches('_')
                ))
            }
        })
    });

    let app_type = if bundle_id.is_some() {
        Some("desktop_app".to_string())
    } else {
        Some("cli".to_string())
    };

    Some(ExchangeClient {
        pid: envelope.process_pid,
        bundle_id,
        process_name: envelope.process_name.clone(),
        app_type,
        referrer_origin: None,
    })
}

#[allow(clippy::too_many_arguments)]
fn finalize_and_enqueue_exchange_v2(
    logger: &EventLogger,
    exchange_cfg: &ExchangeAssemblerConfig,
    pii_enricher: &PiiEventEnricher,
    pending: &PendingRequest,
    session_id: &str,
    status: u16,
    is_stream: bool,
    is_sse: bool,
    response_content_type: Option<&str>,
    response_headers: Option<BTreeMap<String, String>>,
    response_body: Option<&str>,
    usage_meta: &ResponseUsageMeta,
    tags: Option<&BTreeMap<String, String>>,
    response_truncated: bool,
    response_truncated_reason: Option<&str>,
    bundle_version: Option<&str>,
) {
    let mut assembler = ExchangeAssembler::new(
        exchange_cfg.clone(),
        pending.exchange_id.clone(),
        source_class_for_pending(pending),
        transport_for_pending(pending, is_stream, is_sse),
    );
    assembler.set_session_id(session_id.to_string());
    assembler.set_route(
        pending.provider.clone(),
        pending.agent.map(|value| value.to_string()),
        usage_meta.model.clone().or_else(|| pending.model.clone()),
        Some(pending.path.clone()),
        Some(pending.method.clone()),
    );
    assembler.set_client(exchange_client_from_envelope(pending.envelope.as_ref()));
    assembler.set_parse(Some(ExchangeParse {
        parser_version: Some("exchange_v2_edge".to_string()),
        bundle_version: bundle_version.map(ToString::to_string),
        parse_confidence: pending.parse_confidence,
        detection_reason: pending.detection_reason.clone(),
    }));
    assembler.set_request(
        pending.headers.clone(),
        pending.request_content_type.clone(),
        pending
            .request_content
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    assembler.set_response_meta(
        response_headers,
        Some(status),
        response_content_type.map(|value| value.to_string()),
    );
    if let Some(body) = response_body {
        assembler.append_response_chunk(body.as_bytes());
    }
    assembler.set_usage(ExchangeUsage {
        input_tokens: usage_meta.input_tokens,
        output_tokens: usage_meta.output_tokens,
        cache_read_tokens: usage_meta.cache_read_tokens,
        cache_write_tokens: usage_meta.cache_write_tokens,
        reasoning_tokens: usage_meta.reasoning_tokens,
    });
    assembler.set_cost(usage_meta.cost_usd.map(|estimated_usd| ExchangeCost {
        estimated_usd,
        currency: "USD".to_string(),
        pricing_version: bundle_version.map(ToString::to_string),
    }));
    assembler.set_discovery_capture(pending.catalog_discovery);
    if pending.catalog_discovery {
        assembler.mark_metadata_only("catalog_discovery_metadata_only");
    }
    if pending.request_body_truncated {
        assembler.mark_truncated("request_body_truncated");
    }
    if response_truncated {
        assembler.mark_truncated(response_truncated_reason.unwrap_or("response_body_truncated"));
    }
    let mut exchange_tags = tags.cloned().unwrap_or_default();
    if let Some(allowed) = pending.policy_allowed {
        exchange_tags
            .entry("policy.allowed".to_string())
            .or_insert_with(|| allowed.to_string());
    }
    if let Some(version) = pending.policy_version.as_ref() {
        exchange_tags
            .entry("policy.version".to_string())
            .or_insert_with(|| version.clone());
    }
    if let Some(reason) = pending.policy_reason.as_ref() {
        exchange_tags
            .entry("policy.reason".to_string())
            .or_insert_with(|| reason.clone());
    }
    if let Some(operation) = pending.graphql_operation.as_ref() {
        exchange_tags
            .entry("graphql.operation".to_string())
            .or_insert_with(|| operation.clone());
    }
    if let Some(method) = pending.mcp_method.as_ref() {
        exchange_tags
            .entry("mcp.method".to_string())
            .or_insert_with(|| method.clone());
    }
    if let Some(envelope) = pending.envelope.as_ref() {
        assembler.set_integrity_signature(envelope.signature.clone(), envelope.key_id.clone());
        if let Some(did) = envelope.did.as_ref() {
            exchange_tags
                .entry("identity.did".to_string())
                .or_insert_with(|| did.clone());
        }
        if let Some(signature_alg) = envelope.signature_alg.as_ref() {
            exchange_tags
                .entry("identity.signature_alg".to_string())
                .or_insert_with(|| signature_alg.clone());
        }
        if let Some(signed_fields_version) = envelope.signed_fields_version.as_ref() {
            exchange_tags
                .entry("identity.signed_fields_version".to_string())
                .or_insert_with(|| signed_fields_version.clone());
        }
        if let Some(process_executable) = envelope.process_executable.as_ref() {
            exchange_tags
                .entry("client.process_executable".to_string())
                .or_insert_with(|| process_executable.clone());
        }
    }
    assembler.set_tags((!exchange_tags.is_empty()).then_some(exchange_tags));
    let mut pii_probe = WrapEvent::new(
        session_id,
        &pending.host,
        WrapDirection::Out,
        AgentInfo::new(
            pending.agent.unwrap_or("unknown"),
            DetectionSource::Environment,
        ),
    )
    .with_source(event_source_for_pending(pending));
    if let Some(provider) = pending.provider.as_ref() {
        pii_probe = pii_probe.with_provider(provider.clone());
    }
    if let Some(model) = usage_meta.model.as_ref().or(pending.model.as_ref()) {
        pii_probe = pii_probe.with_model(model.clone());
    }
    pii_probe = pii_probe.with_method(
        pending
            .mcp_method
            .clone()
            .unwrap_or_else(|| format!("{} {}", pending.method, pending.path)),
    );
    if let Some(request_body) = pending.request_content.as_ref() {
        pii_probe = pii_probe.with_request(request_body.clone(), "");
    }
    if let Some(response_body) = response_body {
        pii_probe = pii_probe.with_response(response_body.to_string(), "");
    }
    pii_enricher.enrich(&mut pii_probe);
    assembler.set_pii_detected(pii_probe.pii_detected);

    let mut result = if response_truncated && response_truncated_reason == Some("partial_timeout") {
        assembler.finalize_timeout_with_blobs()
    } else {
        assembler.finalize_complete_with_blobs()
    };
    result.event.pii_types = pii_probe.pii_types;

    let payload_json = match serde_json::to_string(&result.event) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                exchange_id = %pending.exchange_id,
                error = %error,
                "Failed encoding exchange.v2 payload"
            );
            return;
        }
    };
    let blobs_json = if result.blobs.is_empty() {
        None
    } else {
        match serde_json::to_string(&result.blobs) {
            Ok(value) => Some(value),
            Err(error) => {
                warn!(
                    exchange_id = %pending.exchange_id,
                    error = %error,
                    "Failed encoding exchange.v2 blob payloads"
                );
                None
            }
        }
    };

    if let Err(error) = logger.enqueue_exchange_upload_with_blobs(
        &pending.exchange_id,
        &payload_json,
        blobs_json.as_deref(),
    ) {
        warn!(
            exchange_id = %pending.exchange_id,
            error = %error,
            "Failed enqueuing exchange.v2 payload"
        );
        return;
    }
    let _ = logger.finalize_exchange_spool(&pending.exchange_id, None);
    let _ = logger.delete_exchange_spool(&pending.exchange_id);
}

fn seed_exchange_v2_spool(
    logger: &EventLogger,
    exchange_cfg: &ExchangeAssemblerConfig,
    pending: &PendingRequest,
    session_id: &str,
    bundle_version: Option<&str>,
) {
    let mut assembler = ExchangeAssembler::new(
        exchange_cfg.clone(),
        pending.exchange_id.clone(),
        source_class_for_pending(pending),
        transport_for_pending(pending, false, false),
    );
    assembler.set_session_id(session_id.to_string());
    assembler.set_route(
        pending.provider.clone(),
        pending.agent.map(|value| value.to_string()),
        pending.model.clone(),
        Some(pending.path.clone()),
        Some(pending.method.clone()),
    );
    assembler.set_client(exchange_client_from_envelope(pending.envelope.as_ref()));
    assembler.set_request(
        pending.headers.clone(),
        pending.request_content_type.clone(),
        pending
            .request_content
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    assembler.set_discovery_capture(pending.catalog_discovery);
    assembler.set_parse(Some(ExchangeParse {
        parser_version: Some("exchange_v2_edge".to_string()),
        bundle_version: bundle_version.map(ToString::to_string),
        parse_confidence: pending.parse_confidence,
        detection_reason: pending.detection_reason.clone(),
    }));
    if let Some(envelope) = pending.envelope.as_ref() {
        assembler.set_integrity_signature(envelope.signature.clone(), envelope.key_id.clone());
    }
    let snapshot_json = match assembler.snapshot_json() {
        Ok(value) => value,
        Err(error) => {
            warn!(
                exchange_id = %pending.exchange_id,
                error = %error,
                "Failed serializing exchange spool snapshot"
            );
            return;
        }
    };
    let started_at = assembler.snapshot().started_at.to_rfc3339();
    if let Err(error) =
        logger.upsert_exchange_spool(&pending.exchange_id, &snapshot_json, &started_at)
    {
        warn!(
            exchange_id = %pending.exchange_id,
            error = %error,
            "Failed writing exchange spool snapshot"
        );
    }
}

fn apply_process_identity(
    mut envelope: TrafficEnvelope,
    process_identity: Option<&ProcessIdentity>,
) -> TrafficEnvelope {
    if let Some(process) = process_identity {
        envelope.process_pid = Some(process.pid);
        envelope.process_name = Some(process.name.clone());
        envelope.process_executable = process.executable.clone();
    }
    envelope
}

/// AI-aware HTTP handler for hudsucker
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
    /// Bundle-driven classifier loaded from registry cache or embedded fallback.
    oisp_engine: Arc<OispEngine>,
    /// Optional exchange.v2 assembly config (disabled when None).
    exchange_v2: Option<ExchangeAssemblerConfig>,
    /// One-time-per-day limiter for catalog-domain discovery captures.
    catalog_discovery_limiter: Arc<CatalogDiscoveryLimiter>,
    /// Maximum request/response body bytes to capture in observability payloads.
    capture_max_body_bytes: u64,
    /// Stable request/response correlation key for this handler clone lifecycle.
    request_correlation_id: u64,
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
            request_correlation_id: next_proxy_request_id(),
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
                PROCESS_ATTR_LOOKUP_TIMEOUT,
                PROCESS_ATTR_CACHE_TTL,
            )),
            registry_mode: config.registry_mode,
            oisp_engine,
            exchange_v2: None,
            catalog_discovery_limiter: Arc::new(CatalogDiscoveryLimiter::default()),
            capture_max_body_bytes: config.capture_max_body_bytes,
            request_correlation_id: next_proxy_request_id(),
        }
    }

    /// Set event logger for observability
    pub fn with_event_logger(mut self, logger: EventLogger) -> Self {
        self.event_logger = Some(Arc::new(logger));
        self
    }

    /// Set event logger for observability (Arc version for sharing)
    pub fn with_event_logger_arc(mut self, logger: Arc<EventLogger>) -> Self {
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

    /// Resolve action for host/path using registry engine decisions.
    /// Uses bundle-driven decisions only (no host-list fallback).
    fn get_action(&self, host: &str, path: &str) -> HostAction {
        if matches!(self.hosts.action_for_host(host), HostAction::Block) {
            metrics::record_filter_decision("http", "block");
            return HostAction::Block;
        }

        let engine = self.oisp_engine.as_ref();
        match engine.should_intercept(host, path) {
            InterceptDecision::Intercept { .. } => {
                metrics::record_filter_decision("http", "intercept");
                HostAction::Intercept
            }
            InterceptDecision::Passthrough => {
                if self.hosts.mode == HostFilterMode::Discovery
                    && engine.classify(host).is_none()
                    && engine.is_catalog_domain(host)
                    && self.catalog_discovery_limiter.reserve_once_per_day(host)
                {
                    metrics::record_filter_decision("http", "catalog_discovery_intercept");
                    info!(
                        host = %host,
                        "Catalog discovery interception enabled for first capture of the day"
                    );
                    HostAction::Intercept
                } else {
                    metrics::record_filter_decision("http", "passthrough");
                    HostAction::Tunnel
                }
            }
            InterceptDecision::Noise => {
                if self.hosts.mode == HostFilterMode::Discovery
                    && engine.classify(host).is_none()
                    && engine.is_catalog_domain(host)
                    && self.catalog_discovery_limiter.reserve_once_per_day(host)
                {
                    metrics::record_filter_decision("http", "catalog_discovery_intercept");
                    info!(
                        host = %host,
                        "Catalog discovery interception enabled for first capture of the day"
                    );
                    HostAction::Intercept
                } else {
                    metrics::record_filter_decision("http", "noise");
                    HostAction::Tunnel
                }
            }
            InterceptDecision::Tunnel => {
                if self.hosts.mode == HostFilterMode::Discovery
                    && engine.classify(host).is_none()
                    && engine.is_catalog_domain(host)
                    && self.catalog_discovery_limiter.reserve_once_per_day(host)
                {
                    metrics::record_filter_decision("http", "catalog_discovery_intercept");
                    info!(
                        host = %host,
                        "Catalog discovery interception enabled for first capture of the day"
                    );
                    HostAction::Intercept
                } else {
                    metrics::record_filter_decision("http", "tunnel");
                    HostAction::Tunnel
                }
            }
        }
    }

    /// Resolve action for CONNECT/TLS handshake where request path is not available yet.
    fn get_connect_action(&self, host: &str) -> HostAction {
        if matches!(self.hosts.action_for_host(host), HostAction::Block) {
            metrics::record_filter_decision("connect", "block");
            return HostAction::Block;
        }

        let engine = self.oisp_engine.as_ref();
        if engine.should_intercept_host(host) {
            metrics::record_filter_decision("connect", "intercept");
            HostAction::Intercept
        } else if self.hosts.mode == HostFilterMode::Discovery
            && engine.classify(host).is_none()
            && engine.is_catalog_domain(host)
            && self.catalog_discovery_limiter.reserve_once_per_day(host)
        {
            metrics::record_filter_decision("connect", "catalog_discovery_intercept");
            info!(
                host = %host,
                "Catalog discovery CONNECT interception enabled for first capture of the day"
            );
            HostAction::Intercept
        } else {
            metrics::record_filter_decision("connect", "tunnel");
            HostAction::Tunnel
        }
    }

    /// Extract host from URI or headers
    /// Handles both regular requests and CONNECT requests (authority form)
    fn extract_host<T>(req: &Request<T>) -> String {
        // Try uri.host() first (works for absolute URLs)
        req.uri()
            .host()
            .map(|h| h.to_string())
            // Try authority (works for CONNECT requests like "host:port")
            .or_else(|| req.uri().authority().map(|a| a.host().to_string()))
            // Fallback to Host header
            .or_else(|| {
                req.headers()
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .map(|h| h.split(':').next().unwrap_or(h).to_string())
            })
            .unwrap_or_default()
    }

    /// Detect agent/client from User-Agent header.
    fn detect_agent_from_user_agent<T>(req: &Request<T>) -> Option<&'static str> {
        let ua = req
            .headers()
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        let ua_lower = ua.to_lowercase();

        if ua_lower.contains("openai-codex") || ua_lower.contains("codex/") {
            Some("codex")
        } else if ua_lower.contains("claude-code")
            || ua_lower.contains("claude_code")
            || ua_lower.contains("claude code")
        {
            Some("claude-code")
        } else if ua_lower.contains("cursor") {
            Some("cursor")
        } else if ua_lower.contains("continue") {
            Some("continue")
        } else if ua_lower.contains("copilot") {
            Some("github-copilot")
        } else if ua_lower.contains("vscode") || ua_lower.contains("visual studio code") {
            Some("vscode")
        } else if ua_lower.contains("intellij") || ua_lower.contains("jetbrains") {
            Some("jetbrains")
        } else if ua_lower.contains("neovim") || ua_lower.contains("nvim") {
            Some("neovim")
        } else if ua_lower.contains("emacs") {
            Some("emacs")
        } else if ua_lower.contains("zed") {
            Some("zed")
        } else if ua_lower.contains("windsurf") {
            Some("windsurf")
        } else if ua_lower.contains("anthropic") || ua_lower.contains("claude") {
            Some("claude")
        } else if ua_lower.contains("openai") || ua_lower.contains("chatgpt") {
            Some("chatgpt")
        } else {
            // Unrecognized/non-empty User-Agent currently has no stable agent mapping.
            None
        }
    }

    /// Apply host/path/model heuristics to derive the final agent tag.
    /// This upgrades generic OpenAI/ChatGPT tags to `codex` when context proves it.
    #[cfg(test)]
    fn detect_agent_with_context(
        ua_agent: Option<&'static str>,
        host: &str,
        path: &str,
        model: Option<&str>,
    ) -> Option<&'static str> {
        Self::detect_agent_with_context_gated(ua_agent, host, path, model, true)
    }

    /// Same as `detect_agent_with_context`, but can disable host-driven inference.
    fn detect_agent_with_context_gated(
        ua_agent: Option<&'static str>,
        host: &str,
        path: &str,
        model: Option<&str>,
        allow_host_inference: bool,
    ) -> Option<&'static str> {
        host_fingerprint::detect_agent_with_context_gated(
            ua_agent,
            host,
            path,
            model,
            allow_host_inference,
        )
    }

    /// Check if a request should be logged for observability
    /// Uses blacklist approach: include everything EXCEPT obvious non-inference content
    fn should_log_request(path: &str, method: &str) -> bool {
        // CONNECT is transport setup, not an application request.
        if method.eq_ignore_ascii_case("CONNECT") {
            return false;
        }

        let path_lower = path.to_lowercase();

        // POST requests to AI providers are almost always inference - include them
        if method == "POST" {
            // Only skip obvious tracking POSTs
            if path_lower.contains("/v1/t")
                || path_lower.contains("/event_logging")
                || path_lower.contains("/analytics")
                || path_lower.contains("/tracking")
                || path_lower.contains("/segment")
                || path_lower.contains("/log")
                || path_lower.contains("/beacon")
            {
                return false;
            }
            return true;
        }

        // For GET/other methods, filter out static assets and noise

        // Skip static assets and images
        if path_lower.ends_with(".png")
            || path_lower.ends_with(".jpg")
            || path_lower.ends_with(".jpeg")
            || path_lower.ends_with(".gif")
            || path_lower.ends_with(".svg")
            || path_lower.ends_with(".ico")
            || path_lower.ends_with(".webp")
            || path_lower.ends_with(".css")
            || path_lower.ends_with(".js")
            || path_lower.ends_with(".map")
            || path_lower.ends_with(".woff")
            || path_lower.ends_with(".woff2")
            || path_lower.ends_with(".ttf")
            || path_lower.ends_with(".eot")
        {
            return false;
        }

        // Skip build/static paths
        if path_lower.contains("/_next/")
            || path_lower.contains("/static/")
            || path_lower.contains("/assets/")
            || path_lower.contains("/chunks/")
            || path_lower.contains("/webpack/")
        {
            return false;
        }

        // Skip tracking/analytics
        if path_lower.contains("/v1/t")
            || path_lower.contains("/event_logging")
            || path_lower.contains("/analytics")
            || path_lower.contains("/tracking")
            || path_lower.contains("/segment")
            || path_lower.contains("/beacon")
            || path_lower.contains("/metrics")
            || path_lower.contains("/healthz")
            || path_lower.contains("/ping")
        {
            return false;
        }

        // Include everything else (might be inference-related)
        true
    }
}

impl HttpHandler for AiProxyHandler {
    fn handle_request(
        &mut self,
        ctx: &HttpContext,
        req: Request<Body>,
    ) -> impl std::future::Future<Output = RequestOrResponse> + Send {
        let host = Self::extract_host(&req);
        let uri = req.uri().clone();
        let path = uri.path().to_string();
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
            self.get_action(&host, &path)
        };
        let is_blocked = matches!(host_action, HostAction::Block);
        let should_capture_observability = matches!(host_action, HostAction::Intercept);
        let host_mode = self.hosts.mode;
        let catalog_discovery_limiter = self.catalog_discovery_limiter.clone();
        let oisp_classification = if should_capture_observability {
            self.oisp_engine.classify(&host)
        } else {
            None
        };
        let is_catalog_discovery_host = should_capture_observability
            && host_mode == HostFilterMode::Discovery
            && oisp_classification.is_none()
            && self.oisp_engine.is_catalog_domain(&host)
            && catalog_discovery_limiter.was_reserved_today(&host);
        let (host_is_ai_target, host_is_mcp_target, host_is_agent_target, provider) =
            if let Some(classification) = oisp_classification.as_ref() {
                let (ai, mcp, agent) = match classification.entry_type_label() {
                    "ai_inference" => (true, false, false),
                    "mcp" => (false, true, false),
                    "agent_app" => (false, false, true),
                    _ => (false, false, false),
                };
                (ai, mcp, agent, Some(classification.provider_id.clone()))
            } else if is_catalog_discovery_host {
                (false, false, false, Some("catalog-discovery".to_string()))
            } else {
                (false, false, false, None)
            };
        let ua_agent = Self::detect_agent_from_user_agent(&req);
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

        // Check if we should inspect body
        let is_post = req.method() == hyper::Method::POST;
        let content_type = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let is_json = content_type
            .as_ref()
            .map(|ct| ct.contains("application/json"))
            .unwrap_or(false);
        let request_content_encoding = req
            .headers()
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_lowercase());
        let declared_request_size_bytes = parse_content_length(req.headers());
        let request_capture_oversized = declared_request_size_bytes
            .map(|size| size > self.capture_max_body_bytes)
            .unwrap_or(false);
        let should_log_inference_request = Self::should_log_request(&path, &http_method);
        // Only inspect request bodies for relevant host classes (or discovery mode).
        let should_inspect_body = is_post
            && should_capture_observability
            && (host_is_mcp_target
                || (((host_is_ai_target || host_is_agent_target)
                    || (host_mode == HostFilterMode::Discovery && is_json))
                    && should_log_inference_request))
            && !is_catalog_discovery_host
            && !request_capture_oversized;
        let oisp_engine = self.oisp_engine.clone();
        let event_logger = self.event_logger.clone();
        let event_tags = self.event_tags.clone();
        let pii_enricher = self.pii_enricher.clone();
        let learned_passthrough = self.learned_passthrough.clone();
        let learned_failure_threshold = self.learned_failure_threshold;
        let learned_failure_window = self.learned_failure_window;
        let process_attribution = self.process_attribution.clone();
        let capture_max_body_bytes = self.capture_max_body_bytes;
        let client_addr = ctx.client_addr;
        let exchange_v2_cfg = self.exchange_v2.clone();
        let exchange_bundle_version = if exchange_v2_cfg.is_some() {
            Some(self.oisp_engine.bundle_version().to_string())
        } else {
            None
        };
        let legacy_wrap_events_enabled = exchange_v2_cfg.is_none();
        let should_resolve_process = !is_connect
            && should_capture_observability
            && (host_is_ai_target
                || host_is_mcp_target
                || host_is_agent_target
                || (host_mode == HostFilterMode::Discovery));

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
                debug!(
                    host = %host,
                    path = %path,
                    method = %http_method,
                    "Skipping observability capture for tunneled/noise request"
                );
            }
            let agent = Self::detect_agent_with_context_gated(
                ua_agent,
                &host,
                &path,
                model.as_deref(),
                host_is_agent_target || (host_mode == HostFilterMode::Discovery),
            );
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
                            agent,
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
                let should_log = is_catalog_discovery_host || should_log_inference_request;

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
                        "Skipping non-inference endpoint"
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
                    let detection_reason = detection_reason_for_bucket(
                        host_is_ai_target,
                        host_is_mcp_target,
                        host_is_agent_target,
                        is_catalog_discovery_host,
                    );
                    let envelope = apply_process_identity(
                        TrafficEnvelope::proxy(
                            &session_id,
                            request_id.to_string(),
                            provider,
                            &host,
                            &http_method,
                            &display_path,
                            model.as_deref(),
                            agent,
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
                            agent,
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
                            detection_reason: detection_reason.map(ToString::to_string),
                            parse_confidence: parse_confidence_for_reason(detection_reason),
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

                if legacy_wrap_events_enabled {
                    if let Some(ref logger) = event_logger {
                        let mcp_agent =
                            AgentInfo::new(agent.unwrap_or("mcp"), DetectionSource::Environment);
                        let mut event =
                            WrapEvent::new(&session_id, &host, WrapDirection::In, mcp_agent)
                                .with_source(EventSource::Mcp)
                                .with_method(mcp_method.clone());
                        let envelope = apply_process_identity(
                            TrafficEnvelope::mcp_http(
                                &session_id,
                                Some(request_id.to_string()),
                                mcp_method.clone(),
                                &host,
                                &path,
                                agent,
                                identity_did.as_deref(),
                                identity_signature.as_deref(),
                                body_content.as_deref(),
                            ),
                            process_identity.as_ref(),
                        );
                        event = event.with_traffic_envelope(envelope);
                        if let Some(ref request_body) = body_content {
                            event = event.with_content(request_body.clone());
                        }
                        event = event.with_content_preview(format!("→ {} {}", http_method, path));
                        let mut tags = (*event_tags).clone();
                        if is_catalog_discovery_host {
                            append_catalog_discovery_tags(&mut tags, &host);
                        }
                        if !tags.is_empty() {
                            event = event.with_tags(tags);
                        }
                        pii_enricher.enrich(&mut event);
                        logger.log(&event);
                    }
                }

                let mut pending = pending_requests.lock();
                let detection_reason = detection_reason_for_bucket(
                    host_is_ai_target,
                    host_is_mcp_target,
                    host_is_agent_target,
                    is_catalog_discovery_host,
                );
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
                                agent,
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
                        agent,
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
                        detection_reason: detection_reason.map(ToString::to_string),
                        parse_confidence: parse_confidence_for_reason(detection_reason),
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
        let registry_mode = self.registry_mode;
        let oisp_engine = self.oisp_engine.clone();
        let exchange_v2_cfg = self.exchange_v2.clone();
        let exchange_bundle_version = if exchange_v2_cfg.is_some() {
            Some(self.oisp_engine.bundle_version().to_string())
        } else {
            None
        };
        let legacy_wrap_events_enabled = exchange_v2_cfg.is_none();
        let capture_max_body_bytes = self.capture_max_body_bytes;
        let budget_tracker = self
            .enforcer
            .as_ref()
            .and_then(|enforcer| enforcer.budget_tracker.clone());
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
                let (body_content, res) = if is_json {
                    let (parts, body) = res.into_parts();
                    match body.collect().await {
                        Ok(collected) => {
                            let bytes = collected.to_bytes();
                            let (_, body_str) =
                                decode_payload_for_logging(&bytes, content_encoding.as_deref());
                            let new_body = Body::from(Full::new(bytes));
                            let res = Response::from_parts(parts, new_body);
                            (Some(body_str), res)
                        }
                        Err(_) => {
                            let res = Response::from_parts(parts, Body::empty());
                            (None, res)
                        }
                    }
                } else {
                    (None, res)
                };

                if let Some(ref logger) = event_logger {
                    let mcp_agent = AgentInfo::new(
                        pending.agent.unwrap_or("mcp"),
                        DetectionSource::Environment,
                    );
                    let method_name = pending
                        .mcp_method
                        .clone()
                        .unwrap_or_else(|| format!("{} {}", pending.method, pending.path));
                    let response_size_bytes = body_content.as_ref().map(|body| body.len() as u64);
                    let response_payload = body_content.unwrap_or_else(|| {
                        format!(
                            "[no JSON-RPC response body captured for {} {} (HTTP {})]",
                            pending.method, pending.path, status
                        )
                    });

                    let mut event =
                        WrapEvent::new(&session_id, &pending.host, WrapDirection::Out, mcp_agent)
                            .with_source(EventSource::Mcp)
                            .with_method(method_name.clone())
                            .with_status_code(status)
                            .with_latency(latency_ms)
                            .with_content(response_payload.clone());
                    if let Some(envelope) = pending.envelope.clone() {
                        event = event.with_traffic_envelope(envelope);
                    }
                    event =
                        event.with_payload_sizes(pending.request_size_bytes, response_size_bytes);
                    event =
                        event.with_content_preview(format!("← {} (HTTP {})", method_name, status));
                    if let Some(allowed) = pending.policy_allowed {
                        event = event.with_policy(allowed, pending.policy_reason.clone());
                    }
                    if let Some(ref version) = pending.policy_version {
                        event = event.with_policy_version(version.clone());
                    }
                    let mut tags = (*event_tags).clone();
                    if pending.catalog_discovery {
                        append_catalog_discovery_tags(&mut tags, &pending.host);
                    }
                    append_capture_tags(
                        &mut tags,
                        pending.request_body_truncated,
                        false,
                        None,
                        if pending.request_body_truncated {
                            Some(capture_max_body_bytes)
                        } else {
                            None
                        },
                    );
                    let exchange_tags = tags.clone();
                    if legacy_wrap_events_enabled {
                        if !tags.is_empty() {
                            event = event.with_tags(tags);
                        }
                        pii_enricher.enrich(&mut event);
                        logger.log(&event);
                    }

                    if let Some(exchange_cfg) = exchange_v2_cfg.as_ref() {
                        finalize_and_enqueue_exchange_v2(
                            logger,
                            exchange_cfg,
                            &pii_enricher,
                            &pending,
                            &session_id,
                            status,
                            false,
                            false,
                            content_type.as_deref(),
                            Some(response_headers.clone()),
                            Some(response_payload.as_str()),
                            &ResponseUsageMeta::default(),
                            Some(&exchange_tags),
                            false,
                            None,
                            exchange_bundle_version.as_deref(),
                        );
                    }
                }

                return res;
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
            let mut response_size_bytes: Option<u64> = None;
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
                        response_size_bytes = Some(bytes.len() as u64);

                        let (decoded_bytes, body_str) =
                            decode_payload_for_logging(&bytes, content_encoding.as_deref());

                        let usage_outcome = extract_usage_meta_for_mode(
                            Some(oisp_engine.as_ref()),
                            registry_mode,
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
                let log_latency_ms = latency_ms;
                let log_content_encoding = content_encoding.clone();
                let log_content_type = content_type.clone();
                let log_grpc_message_encoding = grpc_message_encoding.clone();
                let log_is_sse = is_sse;
                let log_registry_mode = registry_mode;
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
                    let (decoded_bytes, raw_content, streamed_response_size_bytes) = {
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
                        (decoded.0, decoded.1, raw_len as u64)
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
                            log_registry_mode,
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
                        if legacy_wrap_events_enabled {
                            let mut event = build_paired_response_event(ResponseEventInput {
                                session_id: &log_session_id,
                                host: &log_pending.host,
                                provider: log_provider.as_str(),
                                agent: log_pending.agent,
                                method: &log_pending.method,
                                path: &log_pending.path,
                                graphql_operation: log_pending.graphql_operation.as_deref(),
                                is_agent_app: log_pending.is_agent_app,
                                status,
                                latency_ms: log_latency_ms,
                                request_content: log_pending.request_content.as_deref(),
                                response_content: Some(content),
                                request_size_bytes: log_pending.request_size_bytes,
                                response_size_bytes: Some(streamed_response_size_bytes),
                                headers: log_pending.headers.clone(),
                                tags: Some(&enriched_tags),
                                usage_meta: &usage_meta,
                                fallback_model: log_pending.model.as_deref(),
                                response_kind: ResponseKind::Stream { is_sse: log_is_sse },
                                traffic_envelope: log_pending.envelope.clone(),
                            });
                            if let Some(allowed) = log_pending.policy_allowed {
                                event = event.with_policy(allowed, log_pending.policy_reason.clone());
                            }
                            if let Some(ref version) = log_pending.policy_version {
                                event = event.with_policy_version(version.clone());
                            }

                            log_pii_enricher.enrich(&mut event);
                            logger.log(&event);
                        }
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
                response_size_bytes = declared_response_size_bytes;
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
                    let normalized_response = normalize_response_content(
                        body_content.as_deref(),
                        pending.request_content.as_deref(),
                        &pending.method,
                        &pending.path,
                        status,
                        is_sse,
                        false,
                    );
                    let normalized_response_for_exchange = normalized_response.clone();
                    let mut enriched_tags = (*event_tags).clone();
                    if pending.catalog_discovery {
                        append_catalog_discovery_tags(&mut enriched_tags, &pending.host);
                    }
                    append_capture_tags(
                        &mut enriched_tags,
                        pending.request_body_truncated,
                        response_body_truncated,
                        response_capture_reason,
                        if pending.request_body_truncated || response_body_truncated {
                            Some(capture_max_body_bytes)
                        } else {
                            None
                        },
                    );
                    if let Some(response_body) = normalized_response.as_deref() {
                        let subscription_tags = extract_subscription_tags(
                            provider.as_str(),
                            &pending.host,
                            &pending.path,
                            response_body,
                        );
                        if !subscription_tags.is_empty() {
                            enriched_tags.extend(subscription_tags);
                        }
                    }
                    if legacy_wrap_events_enabled {
                        let mut event = build_paired_response_event(ResponseEventInput {
                            session_id: &session_id,
                            host: &pending.host,
                            provider: provider.as_str(),
                            agent: pending.agent,
                            method: &pending.method,
                            path: &pending.path,
                            graphql_operation: pending.graphql_operation.as_deref(),
                            is_agent_app: pending.is_agent_app,
                            status,
                            latency_ms,
                            request_content: pending.request_content.as_deref(),
                            response_content: normalized_response,
                            request_size_bytes: pending.request_size_bytes,
                            response_size_bytes,
                            headers: pending.headers.clone(),
                            tags: Some(&enriched_tags),
                            usage_meta: &response_usage,
                            fallback_model: pending.model.as_deref(),
                            response_kind: if is_stream_response {
                                ResponseKind::Stream { is_sse }
                            } else {
                                ResponseKind::Http
                            },
                            traffic_envelope: pending.envelope.clone(),
                        });
                        if let Some(allowed) = pending.policy_allowed {
                            event = event.with_policy(allowed, pending.policy_reason.clone());
                        }
                        if let Some(ref version) = pending.policy_version {
                            event = event.with_policy_version(version.clone());
                        }
                        pii_enricher.enrich(&mut event);
                        logger.log(&event);
                    }
                    if let Some(exchange_cfg) = exchange_v2_cfg.as_ref() {
                        finalize_and_enqueue_exchange_v2(
                            logger,
                            exchange_cfg,
                            &pii_enricher,
                            &pending,
                            &session_id,
                            status,
                            is_stream_response,
                            is_sse,
                            content_type.as_deref(),
                            Some(response_headers.clone()),
                            normalized_response_for_exchange.as_deref(),
                            &response_usage,
                            Some(&enriched_tags),
                            response_body_truncated,
                            response_capture_reason,
                            exchange_bundle_version.as_deref(),
                        );
                    }
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
        let benign = is_benign_proxy_forward_error(&err);
        let error = err.to_string();
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
        let legacy_wrap_events_enabled = exchange_v2_cfg.is_none();
        async move {
            let pending = {
                let mut requests = pending_requests.lock();
                requests.remove(&request_id)
            };

            if let (Some(logger), Some(pending_req)) = (event_logger.as_ref(), pending.as_ref()) {
                let provider = pending_req
                    .provider
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string());
                let latency_ms = pending_req.started_at.elapsed().as_millis() as u64;
                let failure_status = hyper::StatusCode::BAD_GATEWAY.as_u16();
                let mut tags = (*event_tags).clone();
                tags.insert("transport_forward_error".to_string(), "true".to_string());
                if benign {
                    tags.insert(
                        "transport_forward_error_kind".to_string(),
                        "transient_disconnect".to_string(),
                    );
                }
                if pending_req.catalog_discovery {
                    append_catalog_discovery_tags(&mut tags, &pending_req.host);
                }
                let usage_meta = ResponseUsageMeta::default();
                if legacy_wrap_events_enabled {
                    let mut event = build_paired_response_event(ResponseEventInput {
                        session_id: &session_id,
                        host: &pending_req.host,
                        provider: provider.as_str(),
                        agent: pending_req.agent,
                        method: &pending_req.method,
                        path: &pending_req.path,
                        graphql_operation: pending_req.graphql_operation.as_deref(),
                        is_agent_app: pending_req.is_agent_app,
                        status: failure_status,
                        latency_ms,
                        request_content: pending_req.request_content.as_deref(),
                        response_content: Some(format!("[forward error] {error}")),
                        request_size_bytes: pending_req.request_size_bytes,
                        response_size_bytes: None,
                        headers: pending_req.headers.clone(),
                        tags: Some(&tags),
                        usage_meta: &usage_meta,
                        fallback_model: pending_req.model.as_deref(),
                        response_kind: ResponseKind::Http,
                        traffic_envelope: pending_req.envelope.clone(),
                    });
                    if let Some(allowed) = pending_req.policy_allowed {
                        event = event.with_policy(allowed, pending_req.policy_reason.clone());
                    }
                    if let Some(ref version) = pending_req.policy_version {
                        event = event.with_policy_version(version.clone());
                    }
                    pii_enricher.enrich(&mut event);
                    logger.log(&event);
                }
                if let Some(exchange_cfg) = exchange_v2_cfg.as_ref() {
                    let error_content = format!("[forward error] {error}");
                    finalize_and_enqueue_exchange_v2(
                        logger,
                        exchange_cfg,
                        &pii_enricher,
                        pending_req,
                        &session_id,
                        failure_status,
                        false,
                        false,
                        None,
                        None,
                        Some(error_content.as_str()),
                        &usage_meta,
                        Some(&tags),
                        true,
                        Some("transport_forward_error"),
                        exchange_bundle_version.as_deref(),
                    );
                }
            }

            if benign {
                debug!(
                    client_addr = %client_addr,
                    error = %error,
                    "Transient proxy forward failure (client/upstream disconnect)"
                );
            } else {
                warn!(
                    client_addr = %client_addr,
                    error = %error,
                    "Failed to forward request"
                );
            }

            Response::builder()
                .status(hyper::StatusCode::BAD_GATEWAY)
                .body(Body::empty())
                .expect("Failed to build proxy error response")
        }
    }

    /// Determine if CONNECT should be intercepted (MITM) or tunneled
    fn should_intercept(
        &mut self,
        _ctx: &HttpContext,
        req: &Request<Body>,
    ) -> impl std::future::Future<Output = bool> + Send {
        let host = Self::extract_host(req);
        let action = self.get_connect_action(&host);
        let learned_passthrough = self.learned_passthrough.clone();

        async move {
            match action {
                HostAction::Intercept => {
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

/// WebSocket handler for AI streaming connections
#[derive(Clone)]
pub struct AiWebSocketHandler {
    /// Event logger for observability
    event_logger: Option<Arc<EventLogger>>,
    /// Session ID
    session_id: String,
    /// Host filter config for source classification.
    hosts: Arc<HostFilterConfig>,
    /// Bundle-driven classifier.
    oisp_engine: Arc<OispEngine>,
    /// User-defined tags attached to emitted events.
    event_tags: Arc<BTreeMap<String, String>>,
    /// Optional PII enrichment before events are written.
    pii_enricher: Arc<PiiEventEnricher>,
}

impl AiWebSocketHandler {
    pub fn new(
        session_id: String,
        event_logger: Option<Arc<EventLogger>>,
        hosts: Arc<HostFilterConfig>,
        oisp_engine: Arc<OispEngine>,
        event_tags: Arc<BTreeMap<String, String>>,
        pii_enricher: Arc<PiiEventEnricher>,
    ) -> Self {
        Self {
            event_logger,
            session_id,
            hosts,
            oisp_engine,
            event_tags,
            pii_enricher,
        }
    }
}

fn should_emit_non_mcp_ws_event(is_agent_app: bool, provider: &str) -> bool {
    is_agent_app || provider != "unknown"
}

impl WebSocketHandler for AiWebSocketHandler {
    fn handle_message(
        &mut self,
        ctx: &WebSocketContext,
        msg: Message,
    ) -> impl std::future::Future<Output = Option<Message>> + Send {
        let event_logger = self.event_logger.clone();
        let session_id = self.session_id.clone();
        let hosts = self.hosts.clone();
        let oisp_engine = self.oisp_engine.clone();
        let event_tags = self.event_tags.clone();
        let pii_enricher = self.pii_enricher.clone();

        // Extract host/path and direction from context
        let (host, ws_path, direction) = match ctx {
            WebSocketContext::ClientToServer { dst, .. } => {
                let h = dst.host().unwrap_or("unknown").to_string();
                let p = dst.path().to_string();
                (h, p, WrapDirection::In)
            }
            WebSocketContext::ServerToClient { src, .. } => {
                let h = src.host().unwrap_or("unknown").to_string();
                let p = src.path().to_string();
                (h, p, WrapDirection::Out)
            }
        };

        let is_discovery = hosts.mode == HostFilterMode::Discovery;
        let oisp_classification = oisp_engine.classify(&host);
        let is_catalog_discovery_ws =
            is_discovery && oisp_classification.is_none() && oisp_engine.is_catalog_domain(&host);

        let (host_is_ai_target, host_is_mcp_target, host_is_agent_target, provider) =
            if let Some(classification) = oisp_classification.as_ref() {
                let (ai, mcp, agent) = match classification.entry_type_label() {
                    "ai_inference" => (true, false, false),
                    "mcp" => (false, true, false),
                    "agent_app" => (false, false, true),
                    _ => (false, false, false),
                };
                (ai, mcp, agent, classification.provider_id.clone())
            } else {
                (false, false, false, "unknown".to_string())
            };

        let is_agent_app = host_is_agent_target;
        let detected_ws_agent = AiProxyHandler::detect_agent_with_context_gated(
            None,
            &host,
            &ws_path,
            None,
            host_is_agent_target || is_discovery,
        );

        async move {
            match &msg {
                Message::Text(text) => {
                    let mcp_method = if host_is_mcp_target || is_discovery {
                        extract_mcp_request_method(text, &ws_path)
                    } else {
                        None
                    };
                    let is_mcp_response = (host_is_mcp_target || is_discovery)
                        && mcp_method.is_none()
                        && is_jsonrpc_response_for_mcp(text);
                    let is_actual_mcp = mcp_method.is_some() || is_mcp_response;

                    // Keep MCP host seed list focused on JSON-RPC traffic only.
                    // Non-MCP text frames on MCP hosts (for example Intercom pubsub noise)
                    // should not be reclassified as AI inference.
                    if host_is_mcp_target && !host_is_ai_target && !is_discovery && !is_actual_mcp {
                        debug!(
                            host = %host,
                            path = %ws_path,
                            len = text.len(),
                            "Skipping non-MCP WebSocket text frame on MCP host"
                        );
                        return Some(msg);
                    }

                    let event_shape = if let Some(method) = mcp_method {
                        Some((EventSource::Mcp, method, "mcp".to_string()))
                    } else if is_mcp_response {
                        Some((EventSource::Mcp, "response".to_string(), "mcp".to_string()))
                    } else if should_emit_non_mcp_ws_event(is_agent_app, provider.as_str()) {
                        let source = if is_agent_app {
                            EventSource::AgentApp
                        } else {
                            EventSource::AiProxy
                        };
                        let method = if ws_path == "/" {
                            "WebSocket".to_string()
                        } else {
                            format!("WebSocket {}", ws_path)
                        };
                        Some((source, method, provider.clone()))
                    } else {
                        None
                    };

                    if let Some((source, ws_method, provider_for_event)) = event_shape {
                        info!(
                            host = %host,
                            path = %ws_path,
                            provider = %provider_for_event,
                            agent = detected_ws_agent.unwrap_or(provider_for_event.as_str()),
                            len = text.len(),
                            "WebSocket text message"
                        );

                        // Log WebSocket message for observability
                        if let Some(ref logger) = event_logger {
                            let resolved_agent =
                                detected_ws_agent.unwrap_or_else(|| match source {
                                    EventSource::Mcp => "mcp",
                                    EventSource::AiProxy | EventSource::AgentApp => {
                                        if provider_for_event == "unknown" {
                                            "websocket"
                                        } else {
                                            provider_for_event.as_str()
                                        }
                                    }
                                });
                            let agent_info =
                                AgentInfo::new(resolved_agent, DetectionSource::Environment);

                            let mut event =
                                WrapEvent::new(&session_id, &host, direction, agent_info)
                                    .with_source(source)
                                    .with_provider(provider_for_event.clone())
                                    .with_method(ws_method.clone())
                                    .with_content(text.to_string());
                            let mut tags = (*event_tags).clone();
                            if is_catalog_discovery_ws {
                                append_catalog_discovery_tags(&mut tags, &host);
                            }
                            if !tags.is_empty() {
                                event = event.with_tags(tags);
                            }
                            if matches!(source, EventSource::Mcp) {
                                let envelope = TrafficEnvelope::mcp_http(
                                    &session_id,
                                    None::<String>,
                                    ws_method.clone(),
                                    &host,
                                    &ws_path,
                                    Some(resolved_agent),
                                    None,
                                    None,
                                    Some(text.as_ref()),
                                );
                                event = event.with_traffic_envelope(envelope);
                            }
                            pii_enricher.enrich(&mut event);
                            logger.log(&event);
                        }
                    } else {
                        debug!(
                            host = %host,
                            path = %ws_path,
                            "Skipping non-AI/non-MCP websocket payload from observability"
                        );
                    }
                }
                Message::Binary(data) => {
                    debug!(host = %host, len = data.len(), "WebSocket binary");
                }
                _ => {}
            }
            Some(msg)
        }
    }
}

fn load_oisp_engine(cache_path: Option<&Path>) -> Result<Arc<OispEngine>, ProxyError> {
    if let Some(path) = cache_path {
        match OispEngine::load_from_registry_cache(path) {
            Ok(Some(engine)) => {
                let engine = match engine.with_embedded_overlay() {
                    Ok(overlaid) => overlaid,
                    Err(error) => {
                        warn!(
                            cache = %path.display(),
                            error = %error,
                            "Failed applying embedded baseline overlay; continuing with cache bundle as-is"
                        );
                        engine
                    }
                };
                info!(
                    cache = %path.display(),
                    bundle_version = %engine.bundle_version(),
                    providers = engine.provider_count(),
                    domains = engine.domain_count(),
                    catalog_domains = engine.catalog_domain_count(),
                    "Loaded OISP bundle for proxy classification (embedded baseline overlay applied)"
                );
                return Ok(Arc::new(engine));
            }
            Ok(None) => {
                warn!(
                    cache = %path.display(),
                    "OISP registry cache not found; using embedded minimal fallback bundle"
                );
            }
            Err(error) => {
                warn!(
                    cache = %path.display(),
                    error = %error,
                    "Failed to load OISP registry cache; using embedded minimal fallback bundle"
                );
            }
        }
    } else {
        warn!("OISP registry cache path not configured; using embedded minimal fallback bundle");
    }

    match OispEngine::load_embedded_minimal_bundle() {
        Ok(engine) => {
            info!(
                bundle_version = %engine.bundle_version(),
                providers = engine.provider_count(),
                domains = engine.domain_count(),
                catalog_domains = engine.catalog_domain_count(),
                "Loaded embedded minimal OISP bundle"
            );
            Ok(Arc::new(engine))
        }
        Err(error) => {
            error!(error = %error, "Failed to load embedded minimal OISP bundle");
            Err(ProxyError::transport(format!(
                "Failed to load any OISP bundle (cache and embedded fallback both unavailable): {error}"
            )))
        }
    }
}

/// Start the hudsucker-based proxy with graceful shutdown support
pub async fn start_proxy(
    config: ForwardProxyConfig,
    ca_cert_path: &Path,
    ca_key_path: &Path,
) -> Result<(), ProxyError> {
    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Spawn signal handler
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let _ = shutdown_tx.send(());
    });

    start_proxy_with_shutdown(
        config,
        ca_cert_path,
        ca_key_path,
        async move {
            shutdown_rx.await.ok();
        },
        None,
        None,
        None,
        None,
        None,
    )
    .await
}

/// Start the hudsucker-based proxy with custom shutdown future
pub async fn start_proxy_with_shutdown<F>(
    config: ForwardProxyConfig,
    ca_cert_path: &Path,
    ca_key_path: &Path,
    shutdown: F,
    event_logger: Option<EventLogger>,
    enforcer: Option<ProxyEnforcer>,
    observe_config: Option<ObserveConfig>,
    oisp_registry_cache_path: Option<PathBuf>,
    exchange_v2_config: Option<ExchangeV2Config>,
) -> Result<(), ProxyError>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    // Load CA cert and key as strings (PEM format)
    let ca_cert_pem = std::fs::read_to_string(ca_cert_path)
        .map_err(|e| ProxyError::transport(format!("Failed to read CA cert: {}", e)))?;
    let ca_key_pem = std::fs::read_to_string(ca_key_path)
        .map_err(|e| ProxyError::transport(format!("Failed to read CA key: {}", e)))?;

    // Parse key pair
    let key_pair = KeyPair::from_pem(&ca_key_pem)
        .map_err(|e| ProxyError::transport(format!("Failed to parse CA key: {}", e)))?;

    // Create issuer from CA cert + key
    let issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, key_pair)
        .map_err(|e| ProxyError::transport(format!("Failed to create issuer: {}", e)))?;

    // Create CA with cache size of 1000 certs
    let ca = RcgenAuthority::new(issuer, 1000, aws_lc_rs::default_provider());

    let listen_addr: SocketAddr = config
        .socket_addr()
        .parse()
        .map_err(|e| ProxyError::transport(format!("Invalid listen address: {}", e)))?;

    // Create a shared session ID for both handlers
    let session_id = uuid::Uuid::new_v4().to_string();

    // Convert event_logger to Arc for sharing
    let event_logger_arc = event_logger.map(Arc::new);
    let ws_hosts = Arc::new(config.hosts.clone());
    let observe_config = observe_config.unwrap_or_default();
    let event_tags = Arc::new(observe_config.event_tags.clone());
    let pii_enricher = Arc::new(PiiEventEnricher::from_observe_config(&observe_config));
    let oisp_engine = load_oisp_engine(oisp_registry_cache_path.as_deref())?;
    let learned_passthrough = if config.tls.learned_passthrough.enabled {
        let learned = Arc::new(LearnedPassthrough::new(
            config.tls.learned_passthrough.state_path.clone(),
            config.hosts.ai_inference.clone(),
            config.tls.learned_passthrough.max_age,
        ));
        learned.load();
        metrics::set_tls_learned_passthrough_active(learned.active_count() as f64);
        Some(learned)
    } else {
        None
    };

    let handler = {
        let mut h = AiProxyHandler::new(&config, &observe_config, oisp_engine.clone());
        h.registry_mode = config.registry_mode;
        if let Some(ref logger) = event_logger_arc {
            h = h.with_event_logger_arc(logger.clone());
        }
        if let Some(ref proxy_enforcer) = enforcer {
            h = h.with_enforcer(proxy_enforcer.clone());
        }
        if let Some(ref exchange_cfg) = exchange_v2_config {
            h = h.with_exchange_v2(exchange_cfg.clone());
        }
        if let Some(ref learned) = learned_passthrough {
            h = h.with_learned_passthrough(
                learned.clone(),
                config.tls.learned_passthrough.failure_threshold,
                config.tls.learned_passthrough.failure_window,
            );
        }
        h
    };

    // Create WebSocket handler with event logger
    let ws_handler = AiWebSocketHandler::new(
        session_id,
        event_logger_arc,
        ws_hosts,
        oisp_engine.clone(),
        event_tags,
        pii_enricher,
    );

    info!("Starting soth proxy on {}", listen_addr);
    info!("  Registry mode -> {}", config.registry_mode);
    info!("  AI+MCP domains -> MITM intercept");
    info!("  Other domains -> blind tunnel");

    // ChatGPT web requests can carry extremely large sentinel/auth headers.
    // Raise parser budgets so requests are accepted and then sanitized in handler logic.
    let mut server = AutoServerBuilder::new(TokioExecutor::new());
    server
        .http1()
        .max_headers(512)
        .max_buf_size(1024 * 1024)
        .title_case_headers(true)
        .preserve_header_case(true);
    server.http2().max_header_list_size(262_144);

    let proxy = Proxy::builder()
        .with_addr(listen_addr)
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_server(server)
        .with_http_handler(handler)
        .with_websocket_handler(ws_handler)
        .with_graceful_shutdown(shutdown)
        .build()
        .map_err(|e| ProxyError::transport(format!("Failed to build proxy: {}", e)))?;

    proxy
        .start()
        .await
        .map_err(|e| ProxyError::transport(format!("Proxy error: {}", e)))?;

    if let Some(ref learned) = learned_passthrough {
        learned.persist();
        metrics::set_tls_learned_passthrough_active(learned.active_count() as f64);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use soth_core::types::policy::PolicyData;
    use soth_crypto::identity::Did;
    use std::io::Write;
    use tempfile::tempdir;

    fn gzip_compress(input: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).unwrap();
        encoder.finish().unwrap()
    }

    fn test_oisp_engine() -> Arc<OispEngine> {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache.json");
        let envelope = serde_json::json!({
            "schema_version": 1,
            "fetched_at": "2026-02-13T00:00:00Z",
            "etag": "etag-1",
            "metadata": {
                "bundle_type": "local",
                "version": "v1",
                "sha256": "abc",
                "compiled_at": "2026-02-13T00:00:00Z",
                "provider_count": 2,
                "domain_count": 2,
                "format_count": 1,
                "size_bytes": 123
            },
            "bundle": {
                "schema_version": 2,
                "version": "v1",
                "compiled_at": "2026-02-13T00:00:00Z",
                "bundle_type": "local",
                "domain_index": [
                    { "host": "api.openai.com", "provider_id": "openai", "entry_type": "ai-inference" },
                    { "host": "api.github.com", "provider_id": "github-mcp", "entry_type": "mcp" }
                ],
                "providers": {
                    "openai": { "id": "openai", "name": "OpenAI", "type": "ai-inference" },
                    "github-mcp": { "id": "github-mcp", "name": "GitHub MCP", "type": "mcp" }
                },
                "filters": {
                    "whitelist": ["api.openai.com", "api.github.com"],
                    "blacklist": [],
                    "passthrough": [],
                    "noise_keywords": []
                },
                "pricing": {},
                "catalog_domains": ["server.codeium.com", "*.githubcopilot.com"]
            }
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();
        OispEngine::load_from_registry_cache(&path)
            .unwrap()
            .map(Arc::new)
            .unwrap()
    }

    #[test]
    fn load_oisp_engine_falls_back_to_embedded_bundle_when_cache_missing() {
        let engine = load_oisp_engine(None).expect("embedded fallback bundle should load");
        assert!(engine.classify("api.openai.com").is_some());
    }

    #[test]
    fn load_oisp_engine_overlays_embedded_baseline_for_chatgpt_subdomains() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache.json");
        let envelope = serde_json::json!({
            "schema_version": 1,
            "fetched_at": "2026-02-14T00:00:00Z",
            "etag": "etag-1",
            "metadata": {
                "bundle_type": "cloud",
                "version": "cache-v1",
                "sha256": "abc",
                "compiled_at": "2026-02-14T00:00:00Z",
                "provider_count": 1,
                "domain_count": 1,
                "format_count": 1,
                "size_bytes": 123
            },
            "bundle": {
                "schema_version": 2,
                "version": "cache-v1",
                "compiled_at": "2026-02-14T00:00:00Z",
                "bundle_type": "cloud",
                "domain_index": {
                    "chatgpt.com": {
                        "category": "agent-apps",
                        "provider": "chatgpt"
                    }
                },
                "providers": {
                    "chatgpt": {
                        "name": "ChatGPT",
                        "category": "agent-apps",
                        "api_domains": ["chatgpt.com"],
                        "api_format": "openai"
                    }
                },
                "filters": {
                    "whitelist": ["chatgpt.com"],
                    "blacklist": [],
                    "passthrough": [],
                    "noise_keywords": []
                },
                "pricing": {},
                "formats": {}
            }
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();

        let engine = load_oisp_engine(Some(path.as_path())).expect("cache bundle should load");
        assert!(engine.classify("chatgpt.com").is_some());
        // This host is provided by embedded baseline overlay.
        assert!(engine.classify("ws.chatgpt.com").is_some());
        assert!(engine.should_intercept_host("ws.chatgpt.com:443"));
    }

    #[test]
    fn test_extract_mcp_request_method_with_rmcp_request() {
        let payload = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
        assert_eq!(
            extract_mcp_request_method(payload, "/streamable-http"),
            Some("tools/list".to_string())
        );
    }

    #[test]
    fn test_extract_mcp_request_method_with_rmcp_notification() {
        let payload = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        assert_eq!(
            extract_mcp_request_method(payload, "/transport"),
            Some("notifications/initialized".to_string())
        );
    }

    #[test]
    fn test_extract_mcp_request_method_rejects_custom_jsonrpc_methods_without_mcp_namespace() {
        let payload = r#"{"jsonrpc":"2.0","id":1,"method":"rpc.custom","params":{"x":1}}"#;
        assert_eq!(extract_mcp_request_method(payload, "/jsonrpc"), None);
        assert_eq!(extract_mcp_request_method(payload, "/api"), None);
    }

    #[test]
    fn test_is_jsonrpc_response_for_mcp_detects_response_and_error() {
        let response = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
        let error =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32803,"message":"resource not found"}}"#;
        let generic = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;

        assert!(is_jsonrpc_response_for_mcp(response));
        assert!(is_jsonrpc_response_for_mcp(error));
        assert!(!is_jsonrpc_response_for_mcp(generic));
    }

    #[test]
    fn test_registry_mode_action_uses_oisp_engine() {
        let mut config = ForwardProxyConfig::default();
        config.registry_mode = RegistryMode::Registry;
        config.hosts.ai_inference = vec![];
        config.hosts.mcp = vec![];
        config.hosts.agent_apps = vec![];
        let observe = ObserveConfig::default();
        let handler = AiProxyHandler::new(&config, &observe, test_oisp_engine());

        assert_eq!(
            handler.get_action("api.openai.com", "/v1/chat/completions"),
            HostAction::Intercept
        );
        assert_eq!(
            handler.get_action("api.github.com", "/mcp"),
            HostAction::Intercept
        );
        assert_eq!(
            handler.get_action("unknown.example.com", "/v1/messages"),
            HostAction::Tunnel
        );
    }

    #[test]
    fn test_registry_mode_tunnels_unclassified_hosts() {
        let mut config = ForwardProxyConfig::default();
        config.registry_mode = RegistryMode::Registry;
        config.hosts.ai_inference = vec![];
        config.hosts.mcp = vec![];
        config.hosts.agent_apps = vec![];
        let observe = ObserveConfig::default();
        let handler = AiProxyHandler::new(&config, &observe, test_oisp_engine());

        assert_eq!(
            handler.get_action("unknown.example.com", "/v1/chat/completions"),
            HostAction::Tunnel
        );
    }

    #[test]
    fn test_registry_mode_does_not_fall_back_to_configured_hosts() {
        let mut config = ForwardProxyConfig::default();
        config.registry_mode = RegistryMode::Registry;
        config.hosts.ai_inference = vec!["fallback-only.example".to_string()];
        config.hosts.mcp = vec!["fallback-mcp.example".to_string()];
        config.hosts.agent_apps = vec!["fallback-agent.example".to_string()];
        let observe = ObserveConfig::default();
        let handler = AiProxyHandler::new(&config, &observe, test_oisp_engine());

        assert_eq!(
            handler.get_action("fallback-only.example", "/v1/chat/completions"),
            HostAction::Tunnel
        );
    }

    #[test]
    fn test_connect_action_uses_host_only_oisp_decision() {
        let mut config = ForwardProxyConfig::default();
        config.registry_mode = RegistryMode::Registry;
        config.hosts.ai_inference = vec![];
        config.hosts.mcp = vec![];
        config.hosts.agent_apps = vec![];
        let observe = ObserveConfig::default();
        let handler = AiProxyHandler::new(&config, &observe, test_oisp_engine());

        assert_eq!(
            handler.get_connect_action("api.openai.com"),
            HostAction::Intercept
        );
        assert_eq!(
            handler.get_connect_action("api.openai.com:443"),
            HostAction::Intercept
        );
        assert_eq!(
            handler.get_connect_action("unknown.example.com"),
            HostAction::Tunnel
        );
    }

    #[test]
    fn test_discovery_mode_catalog_intercept_is_limited_to_first_daily_capture() {
        let mut config = ForwardProxyConfig::default();
        config.registry_mode = RegistryMode::Registry;
        config.hosts.mode = HostFilterMode::Discovery;
        config.hosts.ai_inference = vec![];
        config.hosts.mcp = vec![];
        config.hosts.agent_apps = vec![];
        let observe = ObserveConfig::default();
        let handler = AiProxyHandler::new(&config, &observe, test_oisp_engine());

        assert_eq!(
            handler.get_connect_action("server.codeium.com"),
            HostAction::Intercept
        );
        assert_eq!(
            handler.get_connect_action("server.codeium.com"),
            HostAction::Tunnel
        );
        // Registry-classified hosts stay intercepted even in discovery mode.
        assert_eq!(
            handler.get_connect_action("api.openai.com"),
            HostAction::Intercept
        );
    }

    #[test]
    fn test_detect_agent_from_user_agent_codex() {
        let req = Request::builder()
            .uri("https://chatgpt.com/backend-api/codex/responses")
            .header("user-agent", "OpenAI-Codex/1.0")
            .body(())
            .unwrap();
        assert_eq!(
            AiProxyHandler::detect_agent_from_user_agent(&req),
            Some("codex")
        );
    }

    #[test]
    fn test_detect_agent_from_user_agent_claude_code() {
        let req = Request::builder()
            .uri("https://api.anthropic.com/v1/messages")
            .header("user-agent", "claude-code/1.0")
            .body(())
            .unwrap();
        assert_eq!(
            AiProxyHandler::detect_agent_from_user_agent(&req),
            Some("claude-code")
        );
    }

    #[test]
    fn test_detect_agent_from_user_agent_claude_code_with_space() {
        let req = Request::builder()
            .uri("https://api.anthropic.com/v1/messages")
            .header("user-agent", "Claude Code/1.0")
            .body(())
            .unwrap();
        assert_eq!(
            AiProxyHandler::detect_agent_from_user_agent(&req),
            Some("claude-code")
        );
    }

    #[test]
    fn test_detect_agent_with_context_promotes_codex_path() {
        assert_eq!(
            AiProxyHandler::detect_agent_with_context(
                Some("chatgpt"),
                "chatgpt.com",
                "/backend-api/codex/responses",
                None
            ),
            Some("codex")
        );
        assert_eq!(
            AiProxyHandler::detect_agent_with_context(
                Some("chatgpt"),
                "chat.openai.com",
                "/backend-api/codex/responses",
                None
            ),
            Some("codex")
        );
    }

    #[test]
    fn test_detect_agent_with_context_promotes_codex_model() {
        assert_eq!(
            AiProxyHandler::detect_agent_with_context(
                Some("chatgpt"),
                "chatgpt.com",
                "/backend-api/f/conversation",
                Some("gpt-5.3-codex")
            ),
            Some("codex")
        );
    }

    #[test]
    fn test_detect_agent_with_context_promotes_codex_model_on_api_openai() {
        assert_eq!(
            AiProxyHandler::detect_agent_with_context(
                Some("chatgpt"),
                "api.openai.com",
                "/v1/responses",
                Some("gpt-5.3-codex")
            ),
            Some("codex")
        );
    }

    #[test]
    fn test_detect_agent_with_context_defaults_chatgpt_when_ua_missing() {
        assert_eq!(
            AiProxyHandler::detect_agent_with_context(
                None,
                "chatgpt.com",
                "/backend-api/f/conversation",
                None
            ),
            Some("chatgpt")
        );
    }

    #[test]
    fn test_detect_agent_with_context_defaults_claude_when_ua_missing() {
        assert_eq!(
            AiProxyHandler::detect_agent_with_context(
                None,
                "claude.ai",
                "/api/organizations",
                None
            ),
            Some("claude")
        );
    }

    #[test]
    fn test_detect_agent_with_context_defaults_gemini_when_ua_missing() {
        assert_eq!(
            AiProxyHandler::detect_agent_with_context(None, "gemini.google.com", "/app", None),
            Some("gemini")
        );
    }

    #[test]
    fn test_detect_agent_with_context_gated_disables_host_fallbacks() {
        assert_eq!(
            AiProxyHandler::detect_agent_with_context_gated(
                None,
                "gemini.google.com",
                "/app",
                None,
                false
            ),
            None
        );
        assert_eq!(
            AiProxyHandler::detect_agent_with_context_gated(
                Some("chatgpt"),
                "chatgpt.com",
                "/backend-api/f/conversation",
                None,
                false
            ),
            Some("chatgpt")
        );
        assert_eq!(
            AiProxyHandler::detect_agent_with_context_gated(
                None,
                "api.openai.com",
                "/v1/responses",
                Some("gpt-5.3-codex"),
                false
            ),
            Some("codex")
        );
    }

    #[test]
    fn test_detect_agent_with_context_domain_fallbacks() {
        assert_eq!(
            AiProxyHandler::detect_agent_with_context(None, "api2.cursor.sh", "/", None),
            Some("cursor")
        );
        assert_eq!(
            AiProxyHandler::detect_agent_with_context(
                None,
                "enterprise.githubcopilot.com",
                "/",
                None
            ),
            Some("github-copilot")
        );
        assert_eq!(
            AiProxyHandler::detect_agent_with_context(None, "server.codeium.com", "/", None),
            Some("windsurf")
        );
        assert_eq!(
            AiProxyHandler::detect_agent_with_context(None, "cloud.zed.dev", "/", None),
            Some("zed")
        );
        assert_eq!(
            AiProxyHandler::detect_agent_with_context(None, "api.jetbrains.ai", "/", None),
            Some("junie")
        );
        assert_eq!(
            AiProxyHandler::detect_agent_with_context(
                None,
                "codewhisperer.us-east-1.amazonaws.com",
                "/",
                None
            ),
            Some("amazon-q")
        );
        assert_eq!(
            AiProxyHandler::detect_agent_with_context(None, "statsig.anthropic.com", "/", None),
            Some("claude-code")
        );
        assert_eq!(
            AiProxyHandler::detect_agent_with_context(None, "gemini.google.com", "/", None),
            Some("gemini")
        );
    }

    #[test]
    fn test_should_log_request_skips_connect() {
        assert!(!AiProxyHandler::should_log_request("/", "CONNECT"));
    }

    #[test]
    fn test_should_log_request_skips_event_logging_paths() {
        assert!(!AiProxyHandler::should_log_request(
            "/api/event_logging/batch",
            "POST"
        ));
    }

    #[test]
    fn test_extract_gemini_bard_stream_text_prefers_latest_longest_chunk() {
        let body = r#"
)]}'
160
[["wrb.fr",null,"[null,[\"c_1\",\"r_1\"],null,null,[[\"rc_1\",[\"I'm listening\"]]]]"]]
220
[["wrb.fr",null,"[null,[\"c_1\",\"r_1\"],null,null,[[\"rc_1\",[\"I'm listening! Full answer\"]]]]"]]
"#;

        assert_eq!(
            extract_gemini_bard_stream_text(body),
            Some("I'm listening! Full answer".to_string())
        );
    }

    #[test]
    fn test_should_emit_non_mcp_ws_event() {
        assert!(should_emit_non_mcp_ws_event(true, "unknown"));
        assert!(should_emit_non_mcp_ws_event(false, "openai"));
        assert!(!should_emit_non_mcp_ws_event(false, "unknown"));
    }

    #[test]
    fn test_empty_response_placeholder_http() {
        let placeholder =
            empty_response_placeholder("POST", "/backend-api/codex/responses", 200, false);
        assert!(placeholder.contains("no HTTP response body captured"));
        assert!(placeholder.contains("POST /backend-api/codex/responses"));
    }

    #[test]
    fn test_empty_response_placeholder_sse() {
        let placeholder = empty_response_placeholder("POST", "/v1/messages", 200, true);
        assert!(placeholder.contains("no SSE payload captured"));
        assert!(placeholder.contains("POST /v1/messages"));
    }

    #[test]
    fn test_proxy_enforcer_identity_required_blocks_missing_identity() {
        let enforcer =
            ProxyEnforcer::new().with_identity_mode(ProxyIdentityMode::Required, HashSet::new());

        let result = enforcer.enforce_request(
            "session-1",
            "openai",
            "api.openai.com",
            "POST",
            "/v1/chat/completions",
            Some("gpt-4o"),
            Some(r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#),
            Some("cursor"),
            None,
            None,
        );

        assert!(matches!(result, Err((401, _, _))));
    }

    #[test]
    fn test_proxy_enforcer_identity_required_valid_signature() {
        let keypair = soth_crypto::identity::KeyPair::generate();
        let did = Did::from_key_pair(&keypair).unwrap().uri();

        let mut trusted = HashSet::new();
        trusted.insert(did.clone());
        let enforcer =
            ProxyEnforcer::new().with_identity_mode(ProxyIdentityMode::Required, trusted);

        let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#;
        let canonical = enforcement_core::canonical_proxy_request_bytes(
            "api.openai.com",
            "POST",
            "/v1/chat/completions",
            Some(body),
        )
        .unwrap();
        let signature = keypair.sign_base64(&canonical).unwrap();

        let result = enforcer.enforce_request(
            "session-1",
            "openai",
            "api.openai.com",
            "POST",
            "/v1/chat/completions",
            Some("gpt-4o"),
            Some(body),
            Some("cursor"),
            Some(&did),
            Some(&signature),
        );

        assert!(result.is_ok());
        let identity = result.unwrap();
        assert!(identity.verified);
        assert_eq!(identity.did, Some(did));
    }

    #[test]
    fn test_proxy_enforcer_identity_selected_principal_requires_signature() {
        let mut required_principals = HashSet::new();
        required_principals.insert("codex".to_string());
        let enforcer = ProxyEnforcer::new()
            .with_identity_mode(ProxyIdentityMode::Optional, HashSet::new())
            .with_required_principals(required_principals);

        let result = enforcer.enforce_request(
            "session-1",
            "openai",
            "api.openai.com",
            "POST",
            "/v1/chat/completions",
            Some("gpt-4o"),
            Some(r#"{"model":"gpt-4o"}"#),
            Some("codex"),
            None,
            None,
        );

        assert!(matches!(result, Err((401, _, _))));
    }

    #[test]
    fn test_proxy_enforcer_identity_selected_principal_allows_other_agents_without_signature() {
        let mut required_principals = HashSet::new();
        required_principals.insert("codex".to_string());
        let enforcer = ProxyEnforcer::new()
            .with_identity_mode(ProxyIdentityMode::Optional, HashSet::new())
            .with_required_principals(required_principals);

        let result = enforcer.enforce_request(
            "session-1",
            "openai",
            "api.openai.com",
            "POST",
            "/v1/chat/completions",
            Some("gpt-4o"),
            Some(r#"{"model":"gpt-4o"}"#),
            Some("chatgpt"),
            None,
            None,
        );

        assert!(result.is_ok());
        let identity = result.unwrap();
        assert!(!identity.verified);
        assert!(identity.did.is_none());
    }

    #[test]
    fn test_proxy_enforcer_policy_enforce_deny() {
        let engine = PolicyEngine::new();
        engine
            .set_policy_data(PolicyData {
                blocked_tools: vec!["openai:/v1/chat/completions".to_string()],
                ..Default::default()
            })
            .unwrap();

        let enforcer = ProxyEnforcer::new().with_policy(ProxyPolicyMode::Enforce, engine);

        let result = enforcer.enforce_request(
            "session-1",
            "openai",
            "api.openai.com",
            "POST",
            "/v1/chat/completions",
            Some("gpt-4o"),
            Some(r#"{"model":"gpt-4o"}"#),
            Some("cursor"),
            None,
            None,
        );

        assert!(matches!(result, Err((403, _, _))));
    }

    #[test]
    fn test_proxy_enforcer_budget_blocks_when_exceeded() {
        let tracker = BudgetTracker::new();
        tracker.set_global_budget(Some(0.0), None, None);
        tracker.record_spend("session-1", None, "gpt-4o", 10_000, 10_000);

        let enforcer = ProxyEnforcer::new().with_budget(tracker, true, "gpt-4o");
        let result = enforcer.enforce_request(
            "session-1",
            "openai",
            "api.openai.com",
            "POST",
            "/v1/chat/completions",
            Some("gpt-4o"),
            Some(r#"{"model":"gpt-4o"}"#),
            Some("cursor"),
            None,
            None,
        );

        assert!(matches!(result, Err((429, _, _))));
    }

    #[test]
    fn test_try_decompress_zstd() {
        let original = br#"{"ok":true,"source":"zstd"}"#;
        let compressed = zstd::stream::encode_all(Cursor::new(original), 0).unwrap();

        let decoded = try_decompress(&compressed, Some("zstd"));
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_try_decompress_stacked_chain_reverse_order() {
        let original = br#"{"ok":true,"source":"zstd+gzip"}"#;
        let zstd_first = zstd::stream::encode_all(Cursor::new(original), 0).unwrap();
        let gzip_last = gzip_compress(&zstd_first);

        // Applied order: zstd then gzip => header order "zstd, gzip"
        let decoded = try_decompress(&gzip_last, Some("zstd, gzip"));
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_try_decompress_magic_fallback_without_header() {
        let original = br#"{"ok":true,"source":"magic"}"#;
        let compressed = zstd::stream::encode_all(Cursor::new(original), 0).unwrap();

        let decoded = try_decompress(&compressed, None);
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_decode_body_for_logging_short_zstd_magic_placeholder() {
        let bytes = vec![0x28, 0xB5, 0x2F, 0xFD];
        let decoded = decode_body_for_logging(&bytes, Some("zstd"));
        assert!(decoded.contains("[compressed/zstd payload"));
    }

    #[test]
    fn test_append_stream_capture_caps_buffer() {
        let mut buffer = Vec::new();
        assert!(!append_stream_capture(&mut buffer, &[1, 2, 3]));
        assert_eq!(buffer.len(), 3);

        let remaining = STREAM_CAPTURE_MAX_BYTES - buffer.len();
        let mut chunk = vec![9u8; remaining + 16];
        assert!(append_stream_capture(&mut buffer, &chunk));
        assert_eq!(buffer.len(), STREAM_CAPTURE_MAX_BYTES);

        chunk.truncate(1);
        assert!(append_stream_capture(&mut buffer, &chunk));
        assert_eq!(buffer.len(), STREAM_CAPTURE_MAX_BYTES);
    }

    #[test]
    fn test_trim_cookie_header_for_chatgpt_keeps_auth_under_limit() {
        let mut cookies = vec![
            "__Secure-next-auth.session-token=primary-session-token-value".to_string(),
            "__Host-next-auth.csrf-token=csrf-token".to_string(),
            "_account=acct-123".to_string(),
            "cf_clearance=cf-token".to_string(),
        ];

        for i in 0..80 {
            cookies.push(format!("experiment_{}={}", i, "x".repeat(120)));
        }

        let raw = cookies.join("; ");
        let trimmed = trim_cookie_header_for_chatgpt(&raw, CHATGPT_MAX_COOKIE_HEADER_BYTES)
            .expect("expected cookie trimming result");

        assert!(trimmed.len() <= CHATGPT_MAX_COOKIE_HEADER_BYTES);
        assert!(trimmed.contains("__Secure-next-auth.session-token="));
        assert!(trimmed.contains("__Host-next-auth.csrf-token="));
    }

    #[test]
    fn test_sanitize_request_headers_trims_chatgpt_cookie_header() {
        let mut req = Request::builder()
            .uri("https://chatgpt.com/backend-api/conversation")
            .header("host", "chatgpt.com")
            .body(())
            .unwrap();

        let mut cookie_parts = vec![
            "__Secure-next-auth.session-token=session-token-value".to_string(),
            "__Host-next-auth.csrf-token=csrf-value".to_string(),
        ];
        for i in 0..100 {
            cookie_parts.push(format!("noise_{}={}", i, "y".repeat(100)));
        }
        req.headers_mut().insert(
            "cookie",
            hyper::header::HeaderValue::from_str(&cookie_parts.join("; ")).unwrap(),
        );

        sanitize_request_headers(&mut req, "chatgpt.com", "/backend-api/conversation");

        let cookie = req
            .headers()
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(!cookie.is_empty());
        assert!(cookie.len() <= CHATGPT_MAX_COOKIE_HEADER_BYTES);
    }

    #[test]
    fn test_sanitize_request_headers_trims_chat_openai_cookie_header() {
        let mut req = Request::builder()
            .uri("https://chat.openai.com/backend-api/conversation")
            .header("host", "chat.openai.com")
            .body(())
            .unwrap();

        let mut cookie_parts = vec![
            "__Secure-next-auth.session-token=session-token-value".to_string(),
            "__Host-next-auth.csrf-token=csrf-value".to_string(),
        ];
        for i in 0..100 {
            cookie_parts.push(format!("noise_{}={}", i, "z".repeat(100)));
        }
        req.headers_mut().insert(
            "cookie",
            hyper::header::HeaderValue::from_str(&cookie_parts.join("; ")).unwrap(),
        );

        sanitize_request_headers(&mut req, "chat.openai.com", "/backend-api/conversation");

        let cookie = req
            .headers()
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(!cookie.is_empty());
        assert!(cookie.len() <= CHATGPT_MAX_COOKIE_HEADER_BYTES);
    }

    #[test]
    fn test_sanitize_request_headers_reduces_total_budget_for_backend_api() {
        let mut req = Request::builder()
            .uri("https://chatgpt.com/backend-api/codex/responses")
            .header("host", "chatgpt.com")
            .header("authorization", "Bearer test-token")
            .header("origin", "https://chatgpt.com")
            .header("referer", "https://chatgpt.com/")
            .body(())
            .unwrap();

        let mut cookie_parts = vec![
            "__Secure-next-auth.session-token=session-token-value".to_string(),
            "__Host-next-auth.csrf-token=csrf-value".to_string(),
        ];
        for i in 0..180 {
            cookie_parts.push(format!("noise_{}={}", i, "q".repeat(120)));
        }
        req.headers_mut().insert(
            "cookie",
            hyper::header::HeaderValue::from_str(&cookie_parts.join("; ")).unwrap(),
        );
        req.headers_mut().insert(
            "x-debug-big-header",
            hyper::header::HeaderValue::from_str(&"x".repeat(9000)).unwrap(),
        );

        sanitize_request_headers(&mut req, "chatgpt.com", "/backend-api/codex/responses");

        let total_size = header_size_bytes(req.headers());
        assert!(total_size <= CHAT_UI_STRICT_TOTAL_HEADER_BYTES + 400);
        assert!(req.headers().get("x-debug-big-header").is_none());
        assert!(req.headers().get("cookie").is_none());
    }

    #[test]
    fn test_sanitize_request_headers_keeps_cookie_for_backend_api_with_auth_when_budget_ok() {
        let mut req = Request::builder()
            .uri("https://chatgpt.com/backend-api/f/conversation")
            .header("host", "chatgpt.com")
            .header("authorization", "Bearer test-token")
            .body(())
            .unwrap();

        req.headers_mut().insert(
            "cookie",
            hyper::header::HeaderValue::from_static(
                "__Secure-next-auth.session-token=abc; __Host-next-auth.csrf-token=def",
            ),
        );

        sanitize_request_headers(&mut req, "chatgpt.com", "/backend-api/f/conversation");

        assert!(req.headers().get("authorization").is_some());
        assert!(req.headers().get("cookie").is_some());
    }

    #[test]
    fn test_sanitize_request_headers_keeps_cookie_for_non_backend_auth_routes() {
        let mut req = Request::builder()
            .uri("https://chatgpt.com/api/auth/session")
            .header("host", "chatgpt.com")
            .header("authorization", "Bearer test-token")
            .body(())
            .unwrap();

        let mut cookie_parts = vec![
            "__Secure-next-auth.session-token=session-token-value".to_string(),
            "__Host-next-auth.csrf-token=csrf-value".to_string(),
        ];
        for i in 0..140 {
            cookie_parts.push(format!("noise_{}={}", i, "n".repeat(100)));
        }
        req.headers_mut().insert(
            "cookie",
            hyper::header::HeaderValue::from_str(&cookie_parts.join("; ")).unwrap(),
        );
        req.headers_mut().insert(
            "x-debug-big-header",
            hyper::header::HeaderValue::from_str(&"x".repeat(9000)).unwrap(),
        );

        sanitize_request_headers(&mut req, "chatgpt.com", "/api/auth/session");

        assert!(req.headers().get("authorization").is_some());
        assert!(req.headers().get("cookie").is_some());
        assert!(req.headers().get("x-debug-big-header").is_some());
    }

    #[test]
    fn test_is_chat_ui_host_detection() {
        assert!(is_chat_ui_host("chatgpt.com"));
        assert!(is_chat_ui_host("chat.openai.com"));
        assert!(is_chat_ui_host("foo.chat.openai.com"));
        assert!(is_chat_ui_host("auth.openai.com"));
        assert!(!is_chat_ui_host("api.openai.com"));
        assert!(!is_chat_ui_host("example.com"));
    }

    #[test]
    fn test_custom_server_builder_accepts_large_headers_config() {
        let mut server = AutoServerBuilder::new(TokioExecutor::new());
        server
            .http1()
            .max_headers(512)
            .max_buf_size(1024 * 1024)
            .title_case_headers(true)
            .preserve_header_case(true);
        server.http2().max_header_list_size(262_144);
    }
}
