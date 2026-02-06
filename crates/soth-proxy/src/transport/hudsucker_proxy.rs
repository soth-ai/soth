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
use parking_lot::Mutex;
use serde::Deserialize;
use soth_budget::{BudgetTracker, TokenCounter};
use soth_core::types::policy::PolicyInputBuilder;
use soth_identity::{signing::verify_bytes, signing::SignatureBlock, Did};
use soth_policy::PolicyEngine;
use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};

#[cfg(feature = "dashboard")]
use soth_dashboard::{DashboardState, DenialEntry};

use crate::error::ProxyError;
use soth_core::config::{ForwardProxyConfig, HostAction, HostFilterConfig};
use soth_core::types::{AgentInfo, DetectionSource, EventSource, WrapDirection, WrapEvent};
use soth_core::EventLogger;

/// Minimal JSON-RPC request structure for detection
#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: Option<String>,
    method: Option<String>,
    #[serde(default)]
    id: Option<serde_json::Value>,
}

/// AI request body structure for model extraction
#[derive(Debug, Deserialize)]
struct AiRequestBody {
    model: Option<String>,
    #[serde(default)]
    messages: Vec<serde_json::Value>,
    #[serde(default)]
    prompt: Option<String>,
}

/// Pending request info for correlating with responses
#[derive(Debug, Clone)]
struct PendingRequest {
    request_id: u64,
    host: String,
    path: String,
    method: String,
    provider: &'static str,
    agent: Option<&'static str>,
    model: Option<String>,
    started_at: Instant,
    /// Request body content for paired logging
    request_content: Option<String>,
    /// Whether this is traffic from an agent app (chatgpt.com, claude.ai) vs direct API
    is_agent_app: bool,
}

/// Thread-safe store for pending requests
type PendingRequests = Arc<Mutex<HashMap<u64, PendingRequest>>>;

/// Generate a request ID from context
fn request_id_from_ctx(ctx: &HttpContext) -> u64 {
    // Use the context's internal connection/request tracking
    // Hash the pointer address as a simple unique ID
    ctx as *const _ as u64
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

#[derive(Debug, Clone, Default)]
struct EnforcementResult {
    identity_verified: bool,
    did: Option<String>,
    policy_version: Option<String>,
}

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

    fn parse_signature(raw_signature: &str, did: &str) -> Result<SignatureBlock, String> {
        let signature = match serde_json::from_str::<SignatureBlock>(raw_signature) {
            Ok(block) => block,
            Err(_) => SignatureBlock {
                algorithm: "Ed25519".to_string(),
                value: raw_signature.to_string(),
                signer: did.to_string(),
                created: chrono::Utc::now(),
            },
        };

        if signature.algorithm != "Ed25519" {
            return Err(format!(
                "Unsupported signature algorithm: {}",
                signature.algorithm
            ));
        }
        if signature.signer != did {
            return Err(format!(
                "Signature signer mismatch: signer={}, did={}",
                signature.signer, did
            ));
        }

        Ok(signature)
    }

    fn canonical_request_bytes(
        host: &str,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<Vec<u8>, String> {
        let value = serde_json::json!({
            "host": host,
            "method": method,
            "path": path,
            "body": body.unwrap_or(""),
        });
        soth_identity::canonicalize_json(&value)
            .map_err(|e| format!("Failed to canonicalize proxy request for signing: {e}"))
    }

    fn verify_identity(
        &self,
        host: &str,
        method: &str,
        path: &str,
        body: Option<&str>,
        did: Option<&str>,
        signature: Option<&str>,
    ) -> Result<EnforcementResult, String> {
        if self.identity_mode == ProxyIdentityMode::Disabled {
            return Ok(EnforcementResult::default());
        }

        match (did, signature) {
            (None, None) => {
                if self.identity_mode == ProxyIdentityMode::Required {
                    Err("Identity required: missing DID and signature".to_string())
                } else {
                    Ok(EnforcementResult::default())
                }
            }
            (Some(did), None) => {
                if self.identity_mode == ProxyIdentityMode::Required {
                    Err("Identity required: signature missing".to_string())
                } else {
                    Ok(EnforcementResult {
                        identity_verified: false,
                        did: Some(did.to_string()),
                        policy_version: None,
                    })
                }
            }
            (None, Some(_)) => Err("Signature provided without DID".to_string()),
            (Some(did), Some(signature)) => {
                if !self.trusted_dids.contains(did) {
                    return Err(format!("DID not in trust store: {did}"));
                }

                let parsed_did = Did::parse(did).map_err(|e| format!("Invalid DID: {e}"))?;
                let keypair = parsed_did
                    .to_key_pair()
                    .map_err(|e| format!("Invalid DID key: {e}"))?;

                let signature_block = Self::parse_signature(signature, did)?;
                let canonical = Self::canonical_request_bytes(host, method, path, body)?;
                let verified = verify_bytes(&canonical, &signature_block, &keypair)
                    .map_err(|e| format!("Signature verification failed: {e}"))?;

                if !verified {
                    return Err(format!("Invalid signature for DID: {did}"));
                }

                Ok(EnforcementResult {
                    identity_verified: true,
                    did: Some(did.to_string()),
                    policy_version: None,
                })
            }
        }
    }

    fn evaluate_policy(
        &self,
        session_id: &str,
        provider: &str,
        host: &str,
        http_method: &str,
        path: &str,
        model: Option<&str>,
        agent: Option<&str>,
        identity: &EnforcementResult,
    ) -> Result<(bool, Option<String>, Option<String>), String> {
        let Some(engine) = self.policy_engine.as_ref() else {
            return Ok((true, None, None));
        };

        let mut builder = PolicyInputBuilder::new()
            .session_id(session_id)
            .method(format!("proxy/{}", http_method.to_lowercase()))
            .tool(format!("{provider}:{path}"))
            .arguments_json(serde_json::json!({
                "provider": provider,
                "host": host,
                "method": http_method,
                "path": path,
                "model": model,
            }));

        if let Some(agent) = agent {
            builder = builder.agent_id(agent);
        }

        if identity.identity_verified {
            builder = builder.identity_verified(true);
            if let Some(ref did) = identity.did {
                builder = builder.identity_did(did);
            }
        }

        let input = builder.build();
        let result = engine
            .evaluate(&input)
            .map_err(|e| format!("Policy evaluation failed: {e}"))?;
        let policy_version = Some(result.policy_version);
        let decision = result.decision;

        if decision.allow {
            Ok((true, None, policy_version))
        } else {
            let reason = decision
                .reason
                .or_else(|| {
                    if decision.violations.is_empty() {
                        None
                    } else {
                        Some(decision.violations.join("; "))
                    }
                })
                .unwrap_or_else(|| "Policy denied proxy request".to_string());
            Ok((false, Some(reason), policy_version))
        }
    }

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
        let mut identity =
            match self.verify_identity(host, http_method, path, request_body, did, signature) {
                Ok(result) => result,
                Err(err) => {
                    if self.identity_mode == ProxyIdentityMode::Required {
                        return Err((401, err, None));
                    }
                    warn!("Optional identity verification failed: {}", err);
                    EnforcementResult {
                        identity_verified: false,
                        did: did.map(|s| s.to_string()),
                        policy_version: None,
                    }
                }
            };

        if let Some(tracker) = self.budget_tracker.as_ref() {
            let agent_id = identity.did.as_deref().or(agent).map(|s| s.to_string());

            if self.budget_block_on_exceeded && tracker.is_budget_exceeded(agent_id.as_deref()) {
                return Err((429, "Budget exceeded".to_string(), None));
            }

            if let Some(body) = request_body {
                let input_tokens = TokenCounter::estimate_tokens(body);
                let effective_model = model.unwrap_or(&self.default_model);
                tracker.record_spend(
                    session_id,
                    agent_id.as_deref(),
                    effective_model,
                    input_tokens,
                    0,
                );
            }
        }

        let (allowed, denial_reason, policy_version) = match self.evaluate_policy(
            session_id,
            provider,
            host,
            http_method,
            path,
            model,
            agent,
            &identity,
        ) {
            Ok(result) => result,
            Err(err) => return Err((500, err, None)),
        };
        identity.policy_version = policy_version.clone();

        if !allowed {
            let reason = denial_reason.unwrap_or_else(|| "Policy denied".to_string());
            match self.policy_mode {
                ProxyPolicyMode::Enforce => return Err((403, reason, policy_version)),
                ProxyPolicyMode::Audit => warn!("Policy audit violation: {}", reason),
                ProxyPolicyMode::Disabled => {}
            }
        }

        Ok(identity)
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

fn decode_body_for_logging(bytes: &[u8], encoding: Option<&str>) -> String {
    let decoded = try_decompress(bytes, encoding);
    if let Ok(text) = String::from_utf8(decoded.clone()) {
        if let Some(marker) = maybe_binary_placeholder(&decoded, encoding) {
            return marker;
        }
        return text;
    }
    if let Some(marker) = maybe_binary_placeholder(&decoded, encoding) {
        return marker;
    }
    String::from_utf8_lossy(&decoded).to_string()
}

fn empty_response_placeholder(method: &str, path: &str, status: u16, is_sse: bool) -> String {
    if is_sse {
        return format!(
            "[no SSE payload captured for {} {} (HTTP {})]",
            method, path, status
        );
    }
    if path.to_ascii_lowercase().contains("/backend-api/codex/responses") {
        return format!(
            "[no HTTP response body captured for {} {} (HTTP {}) - Codex output may be streamed via WebSocket]",
            method, path, status
        );
    }
    format!(
        "[no HTTP response body captured for {} {} (HTTP {})]",
        method, path, status
    )
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
}

impl AiProxyHandler {
    pub fn new(config: &ForwardProxyConfig) -> Self {
        Self {
            hosts: Arc::new(config.hosts.clone()),
            #[cfg(feature = "dashboard")]
            dashboard: None,
            event_logger: None,
            session_id: uuid::Uuid::new_v4().to_string(),
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
            enforcer: None,
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
        } else if ua_lower.contains("claude-code") || ua_lower.contains("claude_code") {
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
        } else if !ua.is_empty() {
            // Return first part of User-Agent as fallback
            None
        } else {
            None
        }
    }

    fn is_codex_path(path: &str) -> bool {
        let path_lower = path.to_ascii_lowercase();
        path_lower.contains("/backend-api/codex/")
            || path_lower.starts_with("/codex")
            || path_lower.contains("/codex/")
    }

    fn is_codex_model(model: &str) -> bool {
        model.to_ascii_lowercase().contains("codex")
    }

    fn is_chatgpt_web_host(host: &str) -> bool {
        host.contains("chatgpt.com")
            || host == "chat.openai.com"
            || host.ends_with(".chat.openai.com")
    }

    fn is_claude_web_host(host: &str) -> bool {
        if !(host == "claude.ai" || host.ends_with(".claude.ai")) {
            return false;
        }
        !host.starts_with("api.") && !host.contains(".api.")
    }

    /// Apply host/path/model heuristics to derive the final agent tag.
    /// This upgrades generic OpenAI/ChatGPT tags to `codex` when context proves it.
    fn detect_agent_with_context(
        ua_agent: Option<&'static str>,
        host: &str,
        path: &str,
        model: Option<&str>,
    ) -> Option<&'static str> {
        let host_lower = host.to_ascii_lowercase();
        let is_chatgpt_web_host = Self::is_chatgpt_web_host(&host_lower);
        let is_claude_web_host = Self::is_claude_web_host(&host_lower);

        if is_chatgpt_web_host && Self::is_codex_path(path) {
            return Some("codex");
        }

        if let Some(model_name) = model {
            if Self::is_codex_model(model_name) {
                return Some("codex");
            }
        }

        if ua_agent.is_none() && is_chatgpt_web_host {
            return Some("chatgpt");
        }
        if ua_agent.is_none() && is_claude_web_host {
            return Some("claude");
        }

        ua_agent
    }

    /// Detect AI provider from host
    fn detect_provider(host: &str) -> Option<&'static str> {
        let host = host.to_ascii_lowercase();

        // ChatGPT web/agent surfaces
        if Self::is_chatgpt_web_host(&host) {
            Some("chatgpt")
        // Claude web/agent surfaces
        } else if Self::is_claude_web_host(&host) {
            Some("claude")
        // OpenAI API inference endpoints
        } else if host == "api.openai.com"
            || host.ends_with(".api.openai.com")
            || host.contains("openai.azure.com")
        {
            Some("openai")
        // Anthropic inference endpoints
        } else if host == "api.claude.ai"
            || host.ends_with(".api.claude.ai")
            || host == "api.anthropic.com"
            || host.ends_with(".api.anthropic.com")
            || host.contains("anthropic.com")
        {
            Some("anthropic")
        } else if host.contains("googleapis.com")
            && (host.contains("aiplatform") || host.contains("generativelanguage"))
        {
            Some("google")
        } else if host.contains("cohere.") {
            Some("cohere")
        } else if host.contains("mistral.ai") {
            Some("mistral")
        } else if host.contains("groq.com") {
            Some("groq")
        } else if host.contains("together.xyz") {
            Some("together")
        } else if host.contains("perplexity.ai") {
            Some("perplexity")
        } else if host.contains("replicate.com") {
            Some("replicate")
        } else if host.contains("huggingface.co") {
            Some("huggingface")
        } else if host.contains("fireworks.ai") {
            Some("fireworks")
        } else if host.contains("x.ai") {
            Some("xai")
        } else if host.contains("bedrock") && host.contains("amazonaws.com") {
            Some("bedrock")
        } else {
            None
        }
    }

    /// Check if host is an agent app (end-user application) vs direct API
    /// Agent apps: chatgpt.com, claude.ai (web/desktop apps)
    /// Direct API: api.openai.com, api.anthropic.com (programmatic access)
    fn is_agent_app(host: &str) -> bool {
        let host = host.to_ascii_lowercase();

        // OpenAI/ChatGPT web apps (chat.openai.com, chatgpt.com)
        // Exclude api.openai.com which is direct API
        if Self::is_chatgpt_web_host(&host) {
            return true;
        }

        // Claude web/desktop app (claude.ai)
        if Self::is_claude_web_host(&host) {
            return true;
        }

        // Perplexity web app
        if host.contains("perplexity.ai") {
            return !host.starts_with("api.") && !host.contains(".api.");
        }
        // Google AI Studio
        if host.contains("aistudio.google.com") || host.contains("makersuite.google.com") {
            return true;
        }
        false
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
        let provider = Self::detect_provider(&host);
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
        let should_inspect_body = is_post && provider.is_some(); // Always inspect AI POST requests

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

            // Capture body for AI requests
            let (body_content, model, req) = if should_inspect_body {
                let (parts, body) = req.into_parts();
                match body.collect().await {
                    Ok(collected) => {
                        let bytes = collected.to_bytes();
                        let body_len = bytes.len();
                        let body_str =
                            decode_body_for_logging(&bytes, request_content_encoding.as_deref());

                        debug!(
                            body_len = body_len,
                            body_preview = %body_str.chars().take(100).collect::<String>(),
                            "Captured request body"
                        );

                        // Extract model from request body
                        let model = serde_json::from_str::<AiRequestBody>(&body_str)
                            .ok()
                            .and_then(|b| b.model);

                        // Reconstruct request with body
                        let new_body = Body::from(Full::new(bytes));
                        let req = Request::from_parts(parts, new_body);
                        (Some(body_str), model, req)
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to collect request body");
                        let req = Request::from_parts(parts, Body::empty());
                        (None, None, req)
                    }
                }
            } else {
                debug!("Skipping body inspection");
                (None, None, req)
            };
            let agent = Self::detect_agent_with_context(ua_agent, &host, &path, model.as_deref());

            if !is_connect {
                if let (Some(provider), Some(enforcer)) = (provider, enforcer.as_ref()) {
                    let enforcement = enforcer.enforce_request(
                        &session_id,
                        provider,
                        &host,
                        &http_method,
                        &path,
                        model.as_deref(),
                        body_content.as_deref(),
                        agent,
                        identity_did.as_deref(),
                        identity_signature.as_deref(),
                    );

                    match enforcement {
                        Ok(identity_result) =>
                        {
                            #[cfg(feature = "dashboard")]
                            if let Some(ref dashboard) = dashboard {
                                if let Some(ref did) = identity_result.did {
                                    dashboard.record_identity_verification(
                                        did,
                                        identity_result.identity_verified,
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
                        Err((status, reason, policy_version)) => {
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
                                if let Some(ref version) = policy_version {
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
                    let mut pending = pending_requests.lock();
                    pending.insert(
                        request_id,
                        PendingRequest {
                            request_id,
                            host: host.clone(),
                            path: display_path.clone(),
                            method: http_method.clone(),
                            provider,
                            agent,
                            model: model.clone(),
                            started_at: Instant::now(),
                            request_content: body_content,
                            is_agent_app: Self::is_agent_app(&host),
                        },
                    );
                }

                // Note: We don't log request events separately anymore.
                // Instead, we log a paired request/response event when the response arrives.
            } else {
                debug!(host = %host, path = %path, "Request (non-AI)");
            }

            // Sanitize headers to prevent 431 errors (removes proxy hop headers, etc.)
            // Only aggressive cookie trimming for ChatGPT (other providers keep all cookies)
            let (parts, body) = req.into_parts();
            let mut sanitized_req = Request::from_parts(parts, body);
            sanitize_request_headers(&mut sanitized_req, &host, &path);

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
        let session_id = self.session_id.clone();
        let request_id = request_id_from_ctx(ctx);

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
            let is_codex_response_path = pending
                .path
                .to_ascii_lowercase()
                .contains("/backend-api/codex/responses");

            // For JSON responses, capture the body for logging (with decompression)
            // For SSE/Codex streams, use tee to forward immediately while accumulating for logging
            let (body_content, res, logged_in_stream) = if is_json && !is_sse && !is_codex_response_path {
                let (parts, body) = res.into_parts();
                match body.collect().await {
                    Ok(collected) => {
                        let bytes = collected.to_bytes();

                        // Decode for logging (decompression + binary guard)
                        let body_str = decode_body_for_logging(&bytes, content_encoding.as_deref());
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
            } else if is_sse || is_codex_response_path {
                // Streaming response: tee to forward chunks immediately while accumulating
                let (parts, body) = res.into_parts();

                // Create channels for the accumulated content
                let accumulated = Arc::new(Mutex::new(Vec::<u8>::with_capacity(64 * 1024)));
                let accumulated_clone = accumulated.clone();

                // Capture logging context for the spawned task
                let log_event_logger = event_logger.clone();
                let log_session_id = session_id.clone();
                let log_pending = pending.clone();
                let log_latency_ms = latency_ms;
                let log_content_encoding = content_encoding.clone();
                let log_is_sse = is_sse;

                // Create a tee stream that yields frames while accumulating data
                let tee_stream = stream! {
                    let mut body = body;
                    loop {
                        match body.frame().await {
                            Some(Ok(frame)) => {
                                // Clone data for accumulation if it's a data frame
                                if let Some(data) = frame.data_ref() {
                                    let mut acc = accumulated_clone.lock();
                                    // Limit accumulation to prevent memory issues (max 1MB)
                                    if acc.len() < 1024 * 1024 {
                                        acc.extend_from_slice(data);
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
                    let raw_content = {
                        let acc = accumulated_clone.lock();
                        let raw_bytes = acc.clone();
                        let raw_len = raw_bytes.len();
                        drop(acc); // Release lock before decompression

                        debug!(
                            encoding = ?log_content_encoding,
                            raw_bytes = raw_len,
                            "Decompressing streamed response"
                        );

                        // Decode using header/magic decompression + binary guard
                        decode_body_for_logging(&raw_bytes, log_content_encoding.as_deref())
                    };
                    let content = if raw_content.trim().is_empty() {
                        empty_response_placeholder(
                            &log_pending.method,
                            &log_pending.path,
                            status,
                            log_is_sse,
                        )
                    } else {
                        raw_content
                    };

                    if let Some(ref logger) = log_event_logger {
                        let agent_name = log_pending.agent.unwrap_or(log_pending.provider);
                        let agent_info = AgentInfo::new(agent_name, DetectionSource::Environment);
                        let method_str = format!("{} {}", log_pending.method, log_pending.path);

                        let source = if log_pending.is_agent_app { EventSource::AgentApp } else { EventSource::AiProxy };
                        let mut event = WrapEvent::new(&log_session_id, &log_pending.host, WrapDirection::Out, agent_info)
                            .with_source(source)
                            .with_provider(log_pending.provider)
                            .with_method(method_str)
                            .with_status_code(status)
                            .with_latency(log_latency_ms);

                        // Add paired request/response content
                        if let Some(ref req_body) = log_pending.request_content {
                            event = event.with_request(req_body.clone(), "");
                        }
                        event = event.with_response(content.clone(), "");
                        // Keep content populated for legacy inspectors that still read `content`.
                        event = event.with_content(content);

                        // Keep compact row summary; full payload is in request_content/response_content.
                        event = event.with_content_preview(format!(
                            "→ {} {} | ← {} {}",
                            log_pending.method,
                            log_pending.path,
                            if log_is_sse { "SSE" } else { "STREAM" },
                            status
                        ));

                        if let Some(ref m) = log_pending.model {
                            event = event.with_model(m.clone());
                        }

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
                provider = pending.provider,
                host = %pending.host,
                path = %pending.path,
                status = status,
                latency_ms = latency_ms,
                "AI API response"
            );

            #[cfg(feature = "dashboard")]
            if let Some(ref dashboard) = dashboard {
                let request_id_str = pending.request_id.to_string();
                dashboard.record_proxy_response(
                    Some(&request_id_str),
                    pending.provider,
                    status,
                    latency_ms,
                    pending.model.as_deref(),
                    None, // input_tokens
                    None, // output_tokens
                    None, // cost_usd
                );
            }

            // Log paired request/response event (streamed responses are logged in tee stream)
            if !logged_in_stream {
                if let Some(ref logger) = event_logger {
                    let agent_name = pending.agent.unwrap_or(pending.provider);
                    let agent_info = AgentInfo::new(agent_name, DetectionSource::Environment);
                    let method_str = format!("{} {}", pending.method, pending.path);

                    let source = if pending.is_agent_app {
                        EventSource::AgentApp
                    } else {
                        EventSource::AiProxy
                    };
                    let mut event = WrapEvent::new(
                        &session_id,
                        pending.host.clone(),
                        WrapDirection::Out,
                        agent_info,
                    )
                    .with_source(source)
                    .with_provider(pending.provider)
                    .with_method(method_str)
                    .with_status_code(status)
                    .with_latency(latency_ms);

                    // Add paired request/response content
                    if let Some(ref req_body) = pending.request_content {
                        event = event.with_request(req_body.clone(), "");
                    }
                    let normalized_response = body_content
                        .as_ref()
                        .filter(|resp| !resp.trim().is_empty())
                        .cloned()
                        .or_else(|| {
                            if pending.request_content.is_some() || pending.method == "POST" {
                                Some(empty_response_placeholder(
                                    &pending.method,
                                    &pending.path,
                                    status,
                                    false,
                                ))
                            } else {
                                None
                            }
                        });
                    if let Some(resp_body) = normalized_response {
                        event = event.with_response(resp_body.clone(), "");
                        // Also set content field for Inspector backward compatibility
                        event = event.with_content(resp_body);
                    }

                    // Keep compact row summary; full payload is in request_content/response_content.
                    event = event.with_content_preview(format!(
                        "→ {} {} | ← HTTP {}",
                        pending.method, pending.path, status
                    ));

                    // Add model if we had it from request
                    if let Some(ref m) = pending.model {
                        event = event.with_model(m.clone());
                    }

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
}

impl AiWebSocketHandler {
    pub fn new(session_id: String, event_logger: Option<Arc<EventLogger>>) -> Self {
        Self {
            event_logger,
            session_id,
        }
    }
}

impl WebSocketHandler for AiWebSocketHandler {
    fn handle_message(
        &mut self,
        ctx: &WebSocketContext,
        msg: Message,
    ) -> impl std::future::Future<Output = Option<Message>> + Send {
        let event_logger = self.event_logger.clone();
        let session_id = self.session_id.clone();

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

        // Detect provider from host
        let provider = AiProxyHandler::detect_provider(&host).unwrap_or("unknown");

        let is_agent_app = AiProxyHandler::is_agent_app(&host);
        let ws_agent = AiProxyHandler::detect_agent_with_context(None, &host, &ws_path, None)
            .unwrap_or("websocket");

        async move {
            match &msg {
                Message::Text(text) => {
                    info!(
                        host = %host,
                        path = %ws_path,
                        provider = provider,
                        agent = ws_agent,
                        len = text.len(),
                        "WebSocket text message"
                    );

                    // Log WebSocket message for observability
                    if let Some(ref logger) = event_logger {
                        let agent_info = AgentInfo::new(ws_agent, DetectionSource::Environment);

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

                        let event = WrapEvent::new(&session_id, &host, direction, agent_info)
                            .with_source(source)
                            .with_provider(provider)
                            .with_method(method)
                            .with_content(text.to_string());
                        logger.log(&event);
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

    #[cfg(feature = "dashboard")]
    let handler = {
        let mut h = AiProxyHandler::new(&config);
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
        let mut h = AiProxyHandler::new(&config);
        if let Some(ref logger) = event_logger_arc {
            h = h.with_event_logger_arc(logger.clone());
        }
        if let Some(ref proxy_enforcer) = enforcer {
            h = h.with_enforcer(proxy_enforcer.clone());
        }
        h
    };

    // Create WebSocket handler with event logger
    let ws_handler = AiWebSocketHandler::new(session_id, event_logger_arc);

    info!("Starting hudsucker proxy on {}", listen_addr);
    info!("  AI domains -> MITM intercept");
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
    fn test_detect_provider() {
        assert_eq!(
            AiProxyHandler::detect_provider("chatgpt.com"),
            Some("chatgpt")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("chat.openai.com"),
            Some("chatgpt")
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
        assert_eq!(AiProxyHandler::detect_provider("google.com"), None);
        assert_eq!(AiProxyHandler::detect_provider("example.com"), None);
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
    fn test_is_agent_app_classification() {
        assert!(AiProxyHandler::is_agent_app("chatgpt.com"));
        assert!(AiProxyHandler::is_agent_app("claude.ai"));
        assert!(!AiProxyHandler::is_agent_app("api.openai.com"));
        assert!(!AiProxyHandler::is_agent_app("api.anthropic.com"));
        assert!(!AiProxyHandler::is_agent_app("api.claude.ai"));
        assert!(!AiProxyHandler::is_agent_app("anthropic.com"));
    }

    #[test]
    fn test_should_log_request_skips_connect() {
        assert!(!AiProxyHandler::should_log_request("/", "CONNECT"));
    }

    #[test]
    fn test_empty_response_placeholder_http() {
        let placeholder = empty_response_placeholder("POST", "/backend-api/codex/responses", 200, false);
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
        let canonical = ProxyEnforcer::canonical_request_bytes(
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
        assert!(identity.identity_verified);
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
