//! Hudsucker-based Forward Proxy
//!
//! Uses the battle-tested hudsucker crate for MITM proxy functionality.
//! Provides selective interception: AI domains get MITM'd, others tunnel through.

use async_stream::stream;
use brotli::Decompressor as BrotliDecoder;
use flate2::read::GzDecoder;
use http_body_util::{BodyExt, Full, StreamBody};
use hudsucker::{
    certificate_authority::RcgenAuthority,
    hyper::{Request, Response},
    hyper_util::{rt::TokioExecutor, server::conn::auto::Builder as AutoServerBuilder},
    rcgen::{Issuer, KeyPair},
    rustls::crypto::aws_lc_rs,
    tokio_tungstenite::tungstenite::Message,
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse, WebSocketContext, WebSocketHandler,
};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde::Deserialize;
use soth_budget::{BudgetTracker, PricingCatalog, TokenCounter};
use soth_policy::PolicyEngine;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Cursor, Read};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};

#[cfg(feature = "dashboard")]
use soth_dashboard::{DashboardState, DenialEntry};

use crate::enforcement::core as enforcement_core;
use crate::error::ProxyError;
use crate::providers::ProviderRegistry;
use crate::transport::host_fingerprint;
use crate::transport::mcp_detection::{extract_mcp_request_method, is_jsonrpc_response_for_mcp};
use crate::transport::pii_enrichment::PiiEventEnricher;
use crate::transport::response_event_builder::{
    build_paired_response_event, empty_response_placeholder, normalize_response_content,
    ResponseEventInput, ResponseKind,
};
use crate::transport::usage_enrichment::{
    build_http_request_for_provider, extract_usage_meta_from_decoded_payload,
    resolve_provider_parser, ResponseUsageMeta,
};
use soth_core::config::{
    ForwardProxyConfig, HostAction, HostFilterConfig, HostFilterMode, ObserveConfig,
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
    request_id: u64,
    event_id: String,
    envelope: Option<TrafficEnvelope>,
    host: String,
    path: String,
    method: String,
    provider: Option<&'static str>,
    agent: Option<&'static str>,
    model: Option<String>,
    started_at: Instant,
    /// Request body content for paired logging
    request_content: Option<String>,
    /// Request payload size in bytes (wire payload)
    request_size_bytes: Option<u64>,
    /// Sanitized request headers captured post-forward sanitation
    headers: Option<BTreeMap<String, String>>,
    /// Whether this is traffic from an agent app (chatgpt.com, claude.ai) vs direct API
    is_agent_app: bool,
    /// JSON-RPC MCP method (when this request is identified as MCP traffic)
    mcp_method: Option<String>,
    /// Whether this pending request should be emitted as MCP source.
    is_mcp_jsonrpc: bool,
    /// Policy decision metadata captured at request enforcement time.
    policy_allowed: Option<bool>,
    policy_reason: Option<String>,
    policy_version: Option<String>,
}

/// Thread-safe store for pending requests
type PendingRequests = Arc<Mutex<HashMap<u64, PendingRequest>>>;

/// Generate a request ID from context
fn request_id_from_ctx(ctx: &HttpContext) -> u64 {
    // Use the context's internal connection/request tracking
    // Hash the pointer address as a simple unique ID
    ctx as *const _ as u64
}

const STREAM_CAPTURE_MAX_BYTES: usize = 1024 * 1024;
const STREAM_CAPTURE_INITIAL_CAPACITY: usize = 64 * 1024;
const STREAM_BUFFER_POOL_MAX_BUFFERS: usize = 32;

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
    policy_mode: ProxyPolicyMode,
    policy_engine: Option<Arc<PolicyEngine>>,
    budget_tracker: Option<Arc<BudgetTracker>>,
    budget_block_on_exceeded: bool,
    default_model: String,
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
            policy_mode: ProxyPolicyMode::Disabled,
            policy_engine: None,
            budget_tracker: None,
            budget_block_on_exceeded: true,
            default_model: "gpt-4o".to_string(),
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
                policy_mode: self.core_policy_mode(),
                policy_engine: self.policy_engine.as_deref(),
                budget_tracker: self.budget_tracker.as_deref(),
                budget_block_on_exceeded: self.budget_block_on_exceeded,
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

    if total_size > 8000 {
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

        warn!(
            total = total_size,
            top = %top3,
            host = %host,
            "Large headers"
        );
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
        if trimmed.is_empty() || trimmed.starts_with(")]}'") {
            continue;
        }

        if !trimmed.starts_with('[') {
            // Batch framing length lines are numeric and can be ignored.
            continue;
        }

        let Ok(wrapper) = serde_json::from_str::<serde_json::Value>(trimmed) else {
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

    tracker.record_spend(session_id, agent_id, model, input_tokens, output_tokens);
}

/// AI-aware HTTP handler for hudsucker
#[derive(Clone)]
pub struct AiProxyHandler {
    /// Host filter config for selective interception
    hosts: Arc<HostFilterConfig>,
    /// Dashboard state for metrics
    #[cfg(feature = "dashboard")]
    dashboard: Option<DashboardState>,
    /// Event logger for observability
    event_logger: Option<Arc<EventLogger>>,
    /// Session ID for this proxy instance
    session_id: String,
    /// Pending requests for response correlation
    pending_requests: PendingRequests,
    /// Optional enforcement runtime for identity/policy/budget checks
    enforcer: Option<Arc<ProxyEnforcer>>,
    /// Provider parser registry
    provider_registry: Arc<ProviderRegistry>,
    /// LiteLLM-style pricing catalog
    pricing_catalog: Arc<PricingCatalog>,
    /// User-defined tags attached to all emitted events.
    event_tags: Arc<BTreeMap<String, String>>,
    /// Optional PII enrichment before events are written.
    pii_enricher: Arc<PiiEventEnricher>,
}

impl AiProxyHandler {
    pub fn new(config: &ForwardProxyConfig, observe: &ObserveConfig) -> Self {
        Self {
            hosts: Arc::new(config.hosts.clone()),
            #[cfg(feature = "dashboard")]
            dashboard: None,
            event_logger: None,
            session_id: uuid::Uuid::new_v4().to_string(),
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
            enforcer: None,
            provider_registry: Arc::new(ProviderRegistry::new()),
            pricing_catalog: Arc::new(PricingCatalog::with_defaults()),
            event_tags: Arc::new(observe.event_tags.clone()),
            pii_enricher: Arc::new(PiiEventEnricher::from_observe_config(observe)),
        }
    }

    #[cfg(feature = "dashboard")]
    pub fn with_dashboard(mut self, dashboard: DashboardState) -> Self {
        self.dashboard = Some(dashboard);
        self
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

    /// Set enforcement runtime for request allow/deny checks.
    pub fn with_enforcer(mut self, enforcer: ProxyEnforcer) -> Self {
        self.enforcer = Some(Arc::new(enforcer));
        self
    }

    /// Check if host is blocked
    fn is_blocked(&self, host: &str) -> bool {
        matches!(self.hosts.action_for_host(host), HostAction::Block)
    }

    /// Get action for host
    fn get_action(&self, host: &str) -> HostAction {
        self.hosts.action_for_host(host)
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

    /// Detect AI provider from host
    fn detect_provider(host: &str) -> Option<&'static str> {
        host_fingerprint::detect_provider(host)
    }

    /// Resolve provider classification for HTTP request handling.
    fn resolve_http_provider(
        host: &str,
        host_is_ai_target: bool,
        host_mode: HostFilterMode,
    ) -> Option<&'static str> {
        let detected_provider = Self::detect_provider(host);
        if host_is_ai_target {
            detected_provider.or(Some("inference"))
        } else if host_mode == HostFilterMode::Discovery {
            // Discovery mode should still classify known AI providers even when host
            // is not pre-seeded in ai_inference.
            detected_provider
        } else {
            None
        }
    }

    /// Resolve provider classification for WebSocket handling.
    fn resolve_ws_provider(
        host: &str,
        host_is_ai_target: bool,
        host_is_mcp_target: bool,
        host_mode: HostFilterMode,
    ) -> (&'static str, bool) {
        let detected_provider = Self::detect_provider(host);
        let is_discovered_ai_target =
            host_mode == HostFilterMode::Discovery && detected_provider.is_some();
        let provider = if host_is_ai_target {
            detected_provider.unwrap_or("inference")
        } else if is_discovered_ai_target {
            // Discovery mode should still classify known providers outside the
            // explicit host seed list.
            detected_provider.unwrap_or("unknown")
        } else if host_is_mcp_target {
            "mcp"
        } else {
            "unknown"
        };

        (provider, is_discovered_ai_target)
    }

    /// Check if host is in the configured agent app domain class.
    fn is_agent_app(hosts: &HostFilterConfig, host: &str) -> bool {
        hosts.should_check_agent_app(host)
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
        let is_blocked = self.is_blocked(&host);
        let host_is_ai_target = self.hosts.should_check_ai_inference(&host);
        let host_is_mcp_target = self.hosts.should_check_mcp(&host);
        let host_is_agent_target = Self::is_agent_app(&self.hosts, &host);
        let host_mode = self.hosts.mode;
        let provider = Self::resolve_http_provider(
            &host,
            host_is_ai_target || host_is_agent_target,
            host_mode,
        );
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
        // Only inspect request bodies for relevant host classes (or discovery mode).
        let should_inspect_body = is_post
            && ((host_is_ai_target || host_is_agent_target)
                || host_is_mcp_target
                || (host_mode == HostFilterMode::Discovery && is_json));
        let provider_registry = self.provider_registry.clone();
        let event_logger = self.event_logger.clone();
        let event_tags = self.event_tags.clone();
        let pii_enricher = self.pii_enricher.clone();

        debug!(
            is_post = is_post,
            content_type = ?content_type,
            is_json = is_json,
            request_content_encoding = ?request_content_encoding,
            provider = ?provider,
            should_inspect = should_inspect_body,
            "Request inspection check"
        );

        #[cfg(feature = "dashboard")]
        let dashboard = self.dashboard.clone();
        let pending_requests = self.pending_requests.clone();
        let request_id = request_id_from_ctx(ctx);

        async move {
            // Check if blocked
            if is_blocked {
                warn!(host = %host, "Blocked request");
                return RequestOrResponse::Response(
                    Response::builder().status(403).body(Body::empty()).unwrap(),
                );
            }

            // Capture body for AI/MCP requests and record payload-size metadata.
            let declared_request_size_bytes = parse_content_length(req.headers());
            let (body_content, request_size_bytes, model, req) = if should_inspect_body {
                let (parts, body) = req.into_parts();
                match body.collect().await {
                    Ok(collected) => {
                        let bytes = collected.to_bytes();
                        let body_len = bytes.len();
                        let (decoded_bytes, body_str) =
                            decode_payload_for_logging(&bytes, request_content_encoding.as_deref());

                        debug!(
                            body_len = body_len,
                            body_preview = %body_str.chars().take(100).collect::<String>(),
                            "Captured request body"
                        );

                        // Extract model from provider-specific schema first, then fallback to generic JSON.
                        let model = provider
                            .and_then(|provider_name| {
                                resolve_provider_parser(&provider_registry, &host, provider_name)
                            })
                            .and_then(|parser| {
                                let request = build_http_request_for_provider(
                                    &http_method,
                                    &path,
                                    &parts.headers,
                                    Some(decoded_bytes.clone()),
                                );
                                parser.extract_model(&request)
                            })
                            .or_else(|| {
                                serde_json::from_slice::<AiRequestBody>(&decoded_bytes)
                                    .ok()
                                    .and_then(|b| b.model)
                            });

                        // Reconstruct request with body
                        let new_body = Body::from(Full::new(bytes));
                        let req = Request::from_parts(parts, new_body);
                        (Some(body_str), Some(body_len as u64), model, req)
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to collect request body");
                        let req = Request::from_parts(parts, Body::empty());
                        (None, declared_request_size_bytes, None, req)
                    }
                }
            } else {
                debug!("Skipping body inspection");
                (None, declared_request_size_bytes, None, req)
            };
            let agent = Self::detect_agent_with_context_gated(
                ua_agent,
                &host,
                &path,
                model.as_deref(),
                host_is_agent_target || host_mode == HostFilterMode::Discovery,
            );
            let mcp_request_method =
                if !is_connect && (host_is_mcp_target || host_mode == HostFilterMode::Discovery) {
                    body_content
                        .as_deref()
                        .and_then(|content| extract_mcp_request_method(content, &path))
                } else {
                    None
                };
            let mut policy_allowed = None;
            let mut policy_version = None;

            if !is_connect {
                if let (Some(provider), Some(enforcer)) = (provider, enforcer.as_ref()) {
                    let envelope = TrafficEnvelope::proxy(
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
                    );
                    let enforcement = enforcer.enforce_envelope(&envelope);

                    match enforcement {
                        Ok(identity_result) => {
                            policy_allowed = Some(true);
                            policy_version = identity_result.policy_version.clone();
                            #[cfg(feature = "dashboard")]
                            if let Some(ref dashboard) = dashboard {
                                if let Some(ref did) = identity_result.did {
                                    dashboard.record_identity_verification(
                                        did,
                                        identity_result.verified,
                                    );
                                }
                                if let Some(ref version) = identity_result.policy_version {
                                    dashboard.set_policy_active_version(version.clone());
                                }
                                if enforcer.policy_mode != ProxyPolicyMode::Disabled {
                                    dashboard.record_policy_evaluation(true, None);
                                }
                            }
                        }
                        Err((status, reason, denied_policy_version)) => {
                            warn!(
                                status = status,
                                provider = provider,
                                host = %host,
                                path = %path,
                                reason = %reason,
                                "Proxy request denied by enforcement"
                            );

                            #[cfg(feature = "dashboard")]
                            if let Some(ref dashboard) = dashboard {
                                if let Some(ref did) = identity_did {
                                    dashboard.record_identity_verification(did, false);
                                }
                                if let Some(ref version) = denied_policy_version {
                                    dashboard.set_policy_active_version(version.clone());
                                }
                                if enforcer.policy_mode != ProxyPolicyMode::Disabled {
                                    dashboard.record_policy_evaluation(
                                        false,
                                        Some(DenialEntry {
                                            timestamp: chrono::Utc::now().to_rfc3339(),
                                            method: format!("{} {}", http_method, path),
                                            tool: Some(format!("{provider}:{path}")),
                                            reason: reason.clone(),
                                        }),
                                    );
                                }
                            }

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
            } else if let Some(provider) = provider {
                let display_path = if path.is_empty() || path == "/" {
                    // For tunneled requests, path might be empty
                    "/".to_string()
                } else {
                    path.clone()
                };

                // Check if this request should be logged (blacklist non-inference content)
                let should_log = Self::should_log_request(&display_path, &http_method);

                if should_log {
                    info!(
                        agent = ?agent,
                        provider = provider,
                        host = %host,
                        path = %display_path,
                        method = %http_method,
                        model = ?model,
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

                #[cfg(feature = "dashboard")]
                if let Some(ref dashboard) = dashboard {
                    if should_log {
                        let request_id_str = request_id.to_string();
                        dashboard.record_proxy_request(
                            Some(&request_id_str),
                            provider,
                            &host,
                            &http_method,
                            &display_path,
                        );
                    }
                }

                // Store pending request for response correlation (only for logged requests)
                if should_log {
                    let envelope = TrafficEnvelope::proxy(
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
                    );
                    let mut pending = pending_requests.lock();
                    pending.insert(
                        request_id,
                        PendingRequest {
                            request_id,
                            event_id: uuid::Uuid::new_v4().to_string(),
                            envelope: Some(envelope),
                            host: host.clone(),
                            path: display_path.clone(),
                            method: http_method.clone(),
                            provider: Some(provider),
                            agent,
                            model: model.clone(),
                            started_at: Instant::now(),
                            request_content: body_content,
                            request_size_bytes,
                            headers: None,
                            is_agent_app: host_is_agent_target,
                            mcp_method: None,
                            is_mcp_jsonrpc: false,
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

                if let Some(ref logger) = event_logger {
                    let mcp_agent =
                        AgentInfo::new(agent.unwrap_or("mcp"), DetectionSource::Environment);
                    let mut event =
                        WrapEvent::new(&session_id, &host, WrapDirection::In, mcp_agent)
                            .with_source(EventSource::Mcp)
                            .with_method(mcp_method.clone());
                    let envelope = TrafficEnvelope::mcp_http(
                        &session_id,
                        Some(request_id.to_string()),
                        mcp_method.clone(),
                        &host,
                        &path,
                        agent,
                        identity_did.as_deref(),
                        identity_signature.as_deref(),
                        body_content.as_deref(),
                    );
                    event = event.with_traffic_envelope(envelope);
                    if let Some(ref request_body) = body_content {
                        event = event.with_content(request_body.clone());
                    }
                    event = event.with_content_preview(format!("→ {} {}", http_method, path));
                    if !event_tags.is_empty() {
                        event = event.with_tags((*event_tags).clone());
                    }
                    pii_enricher.enrich(&mut event);
                    logger.log(&event);
                }

                let mut pending = pending_requests.lock();
                pending.insert(
                    request_id,
                    PendingRequest {
                        request_id,
                        event_id: uuid::Uuid::new_v4().to_string(),
                        envelope: Some(TrafficEnvelope::mcp_http(
                            &session_id,
                            Some(request_id.to_string()),
                            mcp_method.clone(),
                            &host,
                            &path,
                            agent,
                            identity_did.as_deref(),
                            identity_signature.as_deref(),
                            body_content.as_deref(),
                        )),
                        host: host.clone(),
                        path: path.clone(),
                        method: http_method.clone(),
                        provider: None,
                        agent,
                        model: None,
                        started_at: Instant::now(),
                        request_content: None,
                        request_size_bytes,
                        headers: None,
                        is_agent_app: false,
                        mcp_method: Some(mcp_method),
                        is_mcp_jsonrpc: true,
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
            {
                let mut pending = pending_requests.lock();
                if let Some(entry) = pending.get_mut(&request_id) {
                    if entry.provider.is_some() {
                        entry.headers = Some(sanitized_headers);
                    }
                    if entry.request_size_bytes.is_none() {
                        entry.request_size_bytes =
                            request_size_bytes.or(sanitized_request_size_bytes);
                    }
                }
            }

            RequestOrResponse::Request(sanitized_req)
        }
    }

    fn handle_response(
        &mut self,
        ctx: &HttpContext,
        res: Response<Body>,
    ) -> impl std::future::Future<Output = Response<Body>> + Send {
        let status = res.status().as_u16();
        let pending_requests = self.pending_requests.clone();
        let event_logger = self.event_logger.clone();
        let event_tags = self.event_tags.clone();
        let pii_enricher = self.pii_enricher.clone();
        let session_id = self.session_id.clone();
        let request_id = request_id_from_ctx(ctx);
        let provider_registry = self.provider_registry.clone();
        let pricing_catalog = self.pricing_catalog.clone();
        let budget_tracker = self
            .enforcer
            .as_ref()
            .and_then(|enforcer| enforcer.budget_tracker.clone());

        #[cfg(feature = "dashboard")]
        let dashboard = self.dashboard.clone();

        // Check content type for body inspection
        let is_json = res
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.contains("application/json"))
            .unwrap_or(false);
        let is_sse = res
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.contains("text/event-stream"))
            .unwrap_or(false);
        let content_encoding = res
            .headers()
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_lowercase());

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
                            .with_content(response_payload);
                    if let Some(envelope) = pending.envelope.clone() {
                        event = event.with_traffic_envelope(envelope);
                    }
                    event =
                        event.with_payload_sizes(pending.request_size_bytes, response_size_bytes);
                    event.id = pending.event_id.clone();
                    event =
                        event.with_content_preview(format!("← {} (HTTP {})", method_name, status));
                    if let Some(allowed) = pending.policy_allowed {
                        event = event.with_policy(allowed, pending.policy_reason.clone());
                    }
                    if let Some(ref version) = pending.policy_version {
                        event = event.with_policy_version(version.clone());
                    }
                    if !event_tags.is_empty() {
                        event = event.with_tags((*event_tags).clone());
                    }
                    pii_enricher.enrich(&mut event);
                    logger.log(&event);
                }

                return res;
            }

            let provider = pending.provider.unwrap_or("unknown");
            let is_codex_response_path = pending
                .path
                .to_ascii_lowercase()
                .contains("/backend-api/codex/responses");
            let is_gemini_bard_response_path = is_gemini_bard_stream_path(&pending.path);
            let mut response_usage = ResponseUsageMeta::default();

            // Streamed responses can be long-lived and may get dropped before completion.
            // Emit a placeholder row immediately, then overwrite by ID when stream capture finishes.
            if is_sse || is_codex_response_path || is_gemini_bard_response_path {
                if let Some(ref logger) = event_logger {
                    let placeholder =
                        empty_response_placeholder(&pending.method, &pending.path, status, is_sse);
                    let mut event = build_paired_response_event(ResponseEventInput {
                        session_id: &session_id,
                        host: &pending.host,
                        provider,
                        agent: pending.agent,
                        method: &pending.method,
                        path: &pending.path,
                        is_agent_app: pending.is_agent_app,
                        status,
                        latency_ms,
                        request_content: pending.request_content.as_deref(),
                        response_content: Some(placeholder),
                        request_size_bytes: pending.request_size_bytes,
                        response_size_bytes: None,
                        headers: pending.headers.clone(),
                        tags: Some(event_tags.as_ref()),
                        usage_meta: &response_usage,
                        fallback_model: pending.model.as_deref(),
                        response_kind: ResponseKind::Stream { is_sse },
                        traffic_envelope: pending.envelope.clone(),
                    });
                    event.id = pending.event_id.clone();
                    if let Some(allowed) = pending.policy_allowed {
                        event = event.with_policy(allowed, pending.policy_reason.clone());
                    }
                    if let Some(ref version) = pending.policy_version {
                        event = event.with_policy_version(version.clone());
                    }
                    pii_enricher.enrich(&mut event);
                    logger.log(&event);
                }
            }

            // For JSON responses, capture the body for logging (with decompression)
            // For SSE/Codex streams, use tee to forward immediately while accumulating for logging
            let mut response_size_bytes: Option<u64> = None;
            let (body_content, res, logged_in_stream) = if is_json
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

                        response_usage = extract_usage_meta_from_decoded_payload(
                            &provider_registry,
                            &pricing_catalog,
                            provider,
                            &pending.host,
                            &decoded_bytes,
                            false,
                            pending.model.as_deref(),
                        );

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
            } else if is_sse || is_codex_response_path || is_gemini_bard_response_path {
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
                let log_is_sse = is_sse;
                let log_event_id = pending.event_id.clone();
                let log_provider_registry = provider_registry.clone();
                let log_pricing_catalog = pricing_catalog.clone();
                let log_budget_tracker = budget_tracker.clone();
                let log_event_tags = event_tags.clone();
                let log_pii_enricher = pii_enricher.clone();
                #[cfg(feature = "dashboard")]
                let log_dashboard = dashboard.clone();

                // Create a tee stream that yields frames while accumulating data
                let tee_stream = stream! {
                    let mut body = body;
                    loop {
                        match body.frame().await {
                            Some(Ok(frame)) => {
                                // Clone data for accumulation if it's a data frame
                                if let Some(data) = frame.data_ref() {
                                    let mut guard = accumulated_clone.lock();
                                    if let Some(ref mut acc) = *guard {
                                        // Limit accumulation to prevent memory issues.
                                        if acc.len() < STREAM_CAPTURE_MAX_BYTES {
                                            let remaining = STREAM_CAPTURE_MAX_BYTES - acc.len();
                                            let write_len = remaining.min(data.len());
                                            acc.extend_from_slice(&data[..write_len]);
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
                    let usage_meta = extract_usage_meta_from_decoded_payload(
                        &log_provider_registry,
                        &log_pricing_catalog,
                        provider,
                        &log_pending.host,
                        &decoded_bytes,
                        log_is_sse,
                        log_pending.model.as_deref(),
                    );
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

                    #[cfg(feature = "dashboard")]
                    if let Some(ref dashboard) = log_dashboard {
                        let request_id_str = log_pending.request_id.to_string();
                        dashboard.record_proxy_response(
                            Some(&request_id_str),
                            provider,
                            status,
                            log_latency_ms,
                            usage_meta
                                .model
                                .as_deref()
                                .or(log_pending.model.as_deref()),
                            usage_meta.input_tokens,
                            usage_meta.output_tokens,
                            usage_meta.cost_usd,
                        );
                    }

                    if let Some(ref logger) = log_event_logger {
                        let mut event = build_paired_response_event(ResponseEventInput {
                            session_id: &log_session_id,
                            host: &log_pending.host,
                            provider,
                            agent: log_pending.agent,
                            method: &log_pending.method,
                            path: &log_pending.path,
                            is_agent_app: log_pending.is_agent_app,
                            status,
                            latency_ms: log_latency_ms,
                            request_content: log_pending.request_content.as_deref(),
                            response_content: Some(content),
                            request_size_bytes: log_pending.request_size_bytes,
                            response_size_bytes: Some(streamed_response_size_bytes),
                            headers: log_pending.headers.clone(),
                            tags: Some(log_event_tags.as_ref()),
                            usage_meta: &usage_meta,
                            fallback_model: log_pending.model.as_deref(),
                            response_kind: ResponseKind::Stream { is_sse: log_is_sse },
                            traffic_envelope: log_pending.envelope.clone(),
                        });
                        event.id = log_event_id.clone();
                        if let Some(allowed) = log_pending.policy_allowed {
                            event = event.with_policy(allowed, log_pending.policy_reason.clone());
                        }
                        if let Some(ref version) = log_pending.policy_version {
                            event = event.with_policy_version(version.clone());
                        }

                        log_pii_enricher.enrich(&mut event);
                        logger.log(&event);
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
                // Non-JSON, non-SSE - pass through without buffering
                (None, res, false)
            };

            info!(
                provider = provider,
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

            #[cfg(feature = "dashboard")]
            if !logged_in_stream {
                if let Some(ref dashboard) = dashboard {
                    let request_id_str = pending.request_id.to_string();
                    dashboard.record_proxy_response(
                        Some(&request_id_str),
                        provider,
                        status,
                        latency_ms,
                        response_usage.model.as_deref().or(pending.model.as_deref()),
                        response_usage.input_tokens,
                        response_usage.output_tokens,
                        response_usage.cost_usd,
                    );
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
                        false,
                        false,
                    );
                    let mut event = build_paired_response_event(ResponseEventInput {
                        session_id: &session_id,
                        host: &pending.host,
                        provider,
                        agent: pending.agent,
                        method: &pending.method,
                        path: &pending.path,
                        is_agent_app: pending.is_agent_app,
                        status,
                        latency_ms,
                        request_content: pending.request_content.as_deref(),
                        response_content: normalized_response,
                        request_size_bytes: pending.request_size_bytes,
                        response_size_bytes,
                        headers: pending.headers.clone(),
                        tags: Some(event_tags.as_ref()),
                        usage_meta: &response_usage,
                        fallback_model: pending.model.as_deref(),
                        response_kind: ResponseKind::Http,
                        traffic_envelope: pending.envelope.clone(),
                    });
                    event.id = pending.event_id.clone();
                    if let Some(allowed) = pending.policy_allowed {
                        event = event.with_policy(allowed, pending.policy_reason.clone());
                    }
                    if let Some(ref version) = pending.policy_version {
                        event = event.with_policy_version(version.clone());
                    }
                    pii_enricher.enrich(&mut event);
                    logger.log(&event);
                }
            }

            res
        }
    }

    /// Determine if CONNECT should be intercepted (MITM) or tunneled
    fn should_intercept(
        &mut self,
        _ctx: &HttpContext,
        req: &Request<Body>,
    ) -> impl std::future::Future<Output = bool> + Send {
        let host = Self::extract_host(req);
        let action = self.get_action(&host);

        async move {
            match action {
                HostAction::Intercept => {
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
        event_tags: Arc<BTreeMap<String, String>>,
        pii_enricher: Arc<PiiEventEnricher>,
    ) -> Self {
        Self {
            event_logger,
            session_id,
            hosts,
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

        let host_is_ai_target = hosts.should_check_ai_inference(&host);
        let host_is_mcp_target = hosts.should_check_mcp(&host);
        let host_is_agent_target = AiProxyHandler::is_agent_app(&hosts, &host);
        let is_discovery = hosts.mode == HostFilterMode::Discovery;
        let (provider, _is_discovered_ai_target) = AiProxyHandler::resolve_ws_provider(
            &host,
            host_is_ai_target || host_is_agent_target,
            host_is_mcp_target,
            hosts.mode,
        );

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
                        Some((EventSource::Mcp, method, "mcp"))
                    } else if is_mcp_response {
                        Some((EventSource::Mcp, "response".to_string(), "mcp"))
                    } else if should_emit_non_mcp_ws_event(is_agent_app, provider) {
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
                        Some((source, method, provider))
                    } else {
                        None
                    };

                    if let Some((source, ws_method, provider_for_event)) = event_shape {
                        info!(
                            host = %host,
                            path = %ws_path,
                            provider = provider_for_event,
                            agent = detected_ws_agent.unwrap_or(provider_for_event),
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
                                            provider_for_event
                                        }
                                    }
                                });
                            let agent_info =
                                AgentInfo::new(resolved_agent, DetectionSource::Environment);

                            let mut event =
                                WrapEvent::new(&session_id, &host, direction, agent_info)
                                    .with_source(source)
                                    .with_provider(provider_for_event)
                                    .with_method(ws_method.clone())
                                    .with_content(text.to_string());
                            if !event_tags.is_empty() {
                                event = event.with_tags((*event_tags).clone());
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

/// Start the hudsucker-based proxy with graceful shutdown support
pub async fn start_proxy(
    config: ForwardProxyConfig,
    ca_cert_path: &Path,
    ca_key_path: &Path,
    #[cfg(feature = "dashboard")] dashboard: Option<DashboardState>,
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
        #[cfg(feature = "dashboard")]
        dashboard,
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
    #[cfg(feature = "dashboard")] dashboard: Option<DashboardState>,
    event_logger: Option<EventLogger>,
    enforcer: Option<ProxyEnforcer>,
    observe_config: Option<ObserveConfig>,
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

    #[cfg(feature = "dashboard")]
    let handler = {
        let mut h = AiProxyHandler::new(&config, &observe_config);
        if let Some(d) = dashboard {
            h = h.with_dashboard(d);
        }
        if let Some(ref logger) = event_logger_arc {
            h = h.with_event_logger_arc(logger.clone());
        }
        if let Some(ref proxy_enforcer) = enforcer {
            h = h.with_enforcer(proxy_enforcer.clone());
        }
        h
    };

    #[cfg(not(feature = "dashboard"))]
    let handler = {
        let mut h = AiProxyHandler::new(&config, &observe_config);
        if let Some(ref logger) = event_logger_arc {
            h = h.with_event_logger_arc(logger.clone());
        }
        if let Some(ref proxy_enforcer) = enforcer {
            h = h.with_enforcer(proxy_enforcer.clone());
        }
        h
    };

    // Create WebSocket handler with event logger
    let ws_handler = AiWebSocketHandler::new(
        session_id,
        event_logger_arc,
        ws_hosts,
        event_tags,
        pii_enricher,
    );

    info!("Starting soth proxy on {}", listen_addr);
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

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use soth_core::types::policy::PolicyData;
    use soth_identity::Did;
    use std::io::Write;

    fn gzip_compress(input: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).unwrap();
        encoder.finish().unwrap()
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
    fn test_detect_provider() {
        assert_eq!(
            AiProxyHandler::detect_provider("chatgpt.com"),
            Some("chatgpt")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("chat.openai.com"),
            Some("chatgpt")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("gemini.google.com"),
            Some("gemini")
        );
        assert_eq!(AiProxyHandler::detect_provider("claude.ai"), Some("claude"));
        assert_eq!(
            AiProxyHandler::detect_provider("app.claude.ai"),
            Some("claude")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("api.openai.com"),
            Some("openai")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("foo.openai.azure.com"),
            Some("openai")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("api.anthropic.com"),
            Some("anthropic")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("a-api.anthropic.com"),
            Some("claude")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("a-cdn.anthropic.com"),
            Some("claude")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("s-cdn.anthropic.com"),
            Some("claude")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("api.claude.ai"),
            Some("anthropic")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("anthropic.com"),
            Some("anthropic")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("us-central1-aiplatform.googleapis.com"),
            Some("google")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("generativelanguage.googleapis.com"),
            Some("google")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("api.groq.com"),
            Some("groq")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("bedrock.us-east-1.amazonaws.com"),
            Some("bedrock")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("api2.cursor.sh"),
            Some("cursor")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("api3.cursor.sh"),
            Some("cursor")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("enterprise.githubcopilot.com"),
            Some("github-copilot")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("server.codeium.com"),
            Some("windsurf")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("cloud.zed.dev"),
            Some("zed")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("api.jetbrains.ai"),
            Some("junie")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("codewhisperer.us-east-1.amazonaws.com"),
            Some("amazon-q")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("statsig.anthropic.com"),
            Some("claude-code")
        );
        assert_eq!(AiProxyHandler::detect_provider("evilchatgpt.com"), None);
        assert_eq!(
            AiProxyHandler::detect_provider("foo.githubcopilot.com.evil.com"),
            None
        );
        assert_eq!(AiProxyHandler::detect_provider("google.com"), None);
        assert_eq!(AiProxyHandler::detect_provider("example.com"), None);
    }

    #[test]
    fn test_resolve_http_provider_discovery_classifies_known_ai_host() {
        assert_eq!(
            AiProxyHandler::resolve_http_provider(
                "chat.openai.com",
                false,
                HostFilterMode::Discovery
            ),
            Some("chatgpt")
        );
        assert_eq!(
            AiProxyHandler::resolve_http_provider(
                "gemini.google.com",
                false,
                HostFilterMode::Discovery
            ),
            Some("gemini")
        );
        assert_eq!(
            AiProxyHandler::resolve_http_provider(
                "unknown.example.com",
                false,
                HostFilterMode::Discovery
            ),
            None
        );
        assert_eq!(
            AiProxyHandler::resolve_http_provider(
                "chat.openai.com",
                false,
                HostFilterMode::Selective
            ),
            None
        );
    }

    #[test]
    fn test_resolve_ws_provider_discovery_classifies_known_ai_host() {
        let (provider, discovered) = AiProxyHandler::resolve_ws_provider(
            "chat.openai.com",
            false,
            false,
            HostFilterMode::Discovery,
        );
        assert_eq!(provider, "chatgpt");
        assert!(discovered);

        let (provider, discovered) = AiProxyHandler::resolve_ws_provider(
            "api.github.com",
            false,
            true,
            HostFilterMode::Selective,
        );
        assert_eq!(provider, "mcp");
        assert!(!discovered);
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
    fn test_is_agent_app_classification() {
        let hosts = HostFilterConfig::default();
        assert!(AiProxyHandler::is_agent_app(&hosts, "chatgpt.com"));
        assert!(AiProxyHandler::is_agent_app(&hosts, "chat.openai.com"));
        assert!(AiProxyHandler::is_agent_app(&hosts, "gemini.google.com"));
        assert!(AiProxyHandler::is_agent_app(&hosts, "claude.ai"));
        assert!(AiProxyHandler::is_agent_app(&hosts, "api2.cursor.sh"));
        assert!(AiProxyHandler::is_agent_app(
            &hosts,
            "enterprise.githubcopilot.com"
        ));
        assert!(AiProxyHandler::is_agent_app(&hosts, "server.codeium.com"));
        assert!(AiProxyHandler::is_agent_app(&hosts, "cloud.zed.dev"));
        assert!(AiProxyHandler::is_agent_app(&hosts, "api.jetbrains.ai"));
        assert!(AiProxyHandler::is_agent_app(
            &hosts,
            "codewhisperer.us-east-1.amazonaws.com"
        ));
        assert!(AiProxyHandler::is_agent_app(
            &hosts,
            "statsig.anthropic.com"
        ));
        assert!(AiProxyHandler::is_agent_app(&hosts, "a-api.anthropic.com"));
        assert!(AiProxyHandler::is_agent_app(&hosts, "a-cdn.anthropic.com"));
        assert!(AiProxyHandler::is_agent_app(&hosts, "s-cdn.anthropic.com"));
        assert!(!AiProxyHandler::is_agent_app(&hosts, "api.openai.com"));
        assert!(!AiProxyHandler::is_agent_app(&hosts, "api.anthropic.com"));
        assert!(!AiProxyHandler::is_agent_app(&hosts, "api.claude.ai"));
        assert!(!AiProxyHandler::is_agent_app(&hosts, "anthropic.com"));
        assert!(!AiProxyHandler::is_agent_app(
            &hosts,
            "foo.gemini.google.com.evil.com"
        ));
    }

    #[test]
    fn test_should_log_request_skips_connect() {
        assert!(!AiProxyHandler::should_log_request("/", "CONNECT"));
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
        let keypair = soth_identity::KeyPair::generate();
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
