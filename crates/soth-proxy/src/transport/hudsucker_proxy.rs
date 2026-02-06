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

/// Safely truncate a string to max_chars characters without splitting UTF-8
fn safe_truncate(s: &str, max_chars: usize) -> String {
    let truncated: String = s.chars().take(max_chars).collect();
    if truncated.len() < s.len() {
        format!("{}...", truncated)
    } else {
        truncated
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

/// Sanitize request headers to prevent 431 errors and WebSocket issues
/// Only applies aggressive cookie trimming for ChatGPT (which has large cookies)
fn sanitize_request_headers<T>(req: &mut Request<T>, host: &str) {
    let headers = req.headers_mut();
    let is_chatgpt = host.contains("chatgpt.com");

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

        // Only trim cookies for ChatGPT (they have huge cookies that cause 431)
        if let Some(cookie_val) = headers.get("cookie").cloned() {
            if let Ok(cookie_str) = cookie_val.to_str() {
                let original_len = cookie_str.len();

                // Keep only essential cookies for ChatGPT auth
                let essential_cookies: Vec<&str> = cookie_str
                    .split("; ")
                    .filter(|c| {
                        let name = c.split('=').next().unwrap_or("");
                        // Essential ChatGPT/OpenAI auth cookies
                        name.starts_with("__Secure")
                            || name.starts_with("__Host")
                            || name.starts_with("__cf")
                            || name.starts_with("cf_")
                            || name == "_puid"
                            || name == "_account"
                            || name.starts_with("oai-")
                            || name.contains("session")
                            || name.contains("token")
                            || name.contains("auth")
                    })
                    .collect();

                let trimmed = essential_cookies.join("; ");
                let trimmed_len = trimmed.len();

                if trimmed_len < original_len {
                    if let Ok(new_val) = hyper::header::HeaderValue::from_str(&trimmed) {
                        headers.remove("cookie");
                        headers.insert("cookie", new_val);
                        debug!(
                            before = original_len,
                            after = trimmed_len,
                            saved = original_len - trimmed_len,
                            "ChatGPT cookie trimming"
                        );
                    }
                }
            }
        }
    }

    // Calculate final header size and warn if still large
    let total_size: usize = headers
        .iter()
        .map(|(k, v)| k.as_str().len() + v.len() + 4)
        .sum();

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

/// Try to decompress bytes, returns decompressed data or original if decompression fails
fn try_decompress(bytes: &[u8], encoding: Option<&str>) -> Vec<u8> {
    let encoding = encoding.or_else(|| detect_compression_from_bytes(bytes));

    match encoding {
        Some("zstd") => {
            let cursor = Cursor::new(bytes);
            if let Ok(mut decoder) = zstd::stream::Decoder::new(cursor) {
                let mut decompressed = Vec::new();
                if decoder.read_to_end(&mut decompressed).is_ok() && !decompressed.is_empty() {
                    return decompressed;
                }
            }
        }
        Some("gzip") => {
            let mut decoder = GzDecoder::new(bytes);
            let mut decompressed = Vec::new();
            if decoder.read_to_end(&mut decompressed).is_ok() && !decompressed.is_empty() {
                return decompressed;
            }
        }
        Some("br") | Some("brotli") => {
            let mut decoder = BrotliDecoder::new(bytes, 4096);
            let mut decompressed = Vec::new();
            if decoder.read_to_end(&mut decompressed).is_ok() && !decompressed.is_empty() {
                return decompressed;
            }
        }
        Some("deflate") => {
            use flate2::read::DeflateDecoder;
            let mut decoder = DeflateDecoder::new(bytes);
            let mut decompressed = Vec::new();
            if decoder.read_to_end(&mut decompressed).is_ok() && !decompressed.is_empty() {
                return decompressed;
            }
        }
        _ => {}
    }

    // Return original if no decompression or decompression failed
    bytes.to_vec()
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

    /// Detect agent/client from User-Agent header
    fn detect_agent<T>(req: &Request<T>) -> Option<&'static str> {
        let ua = req
            .headers()
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        let ua_lower = ua.to_lowercase();

        if ua_lower.contains("claude-code") || ua_lower.contains("claude_code") {
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

    /// Detect AI provider from host
    fn detect_provider(host: &str) -> Option<&'static str> {
        if host.contains("openai.com")
            || host.contains("openai.azure.com")
            || host.contains("chatgpt.com")
        {
            Some("openai")
        } else if host.contains("anthropic.com") || host.contains("claude.ai") {
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
        // OpenAI/ChatGPT web apps (chat.openai.com, chatgpt.com)
        // Exclude api.openai.com which is direct API
        if host.contains("openai.com") || host.contains("chatgpt.com") {
            return !host.starts_with("api.") && !host.contains(".api.");
        }
        // Claude web/desktop app (claude.ai)
        // Exclude api.anthropic.com which is direct API
        if host.contains("anthropic.com") || host.contains("claude.ai") {
            return !host.starts_with("api.") && !host.contains(".api.");
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

        debug!(
            full_uri = %uri,
            path = %path,
            host = %host,
            method = %http_method,
            "Incoming request"
        );
        let is_blocked = self.is_blocked(&host);
        let provider = Self::detect_provider(&host);
        let agent = Self::detect_agent(&req);
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
        let should_inspect_body = is_post && provider.is_some(); // Always inspect AI POST requests

        debug!(
            is_post = is_post,
            content_type = ?content_type,
            is_json = is_json,
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
                        let body_str = String::from_utf8_lossy(&bytes).to_string();

                        debug!(
                            body_len = body_len,
                            body_preview = %body_str.chars().take(100).collect::<String>(),
                            "Captured request body"
                        );

                        // Extract model from request body
                        let model = serde_json::from_slice::<AiRequestBody>(&bytes)
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
                    Ok(identity_result) => {
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

            // Log AI traffic (only inference endpoints, not images/tracking/etc)
            if let Some(provider) = provider {
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
            sanitize_request_headers(&mut sanitized_req, &host);

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

            // For JSON responses, capture the body for logging (with decompression)
            // For SSE, use stream tee to forward immediately while accumulating for logging
            let (body_content, res) = if is_json && !is_sse {
                let (parts, body) = res.into_parts();
                match body.collect().await {
                    Ok(collected) => {
                        let bytes = collected.to_bytes();

                        // Decompress for logging (uses header or magic byte detection)
                        let decompressed = try_decompress(&bytes, content_encoding.as_deref());

                        let body_str = String::from_utf8_lossy(&decompressed).to_string();
                        // Return original bytes to client (they handle decompression)
                        let new_body = Body::from(Full::new(bytes));
                        let res = Response::from_parts(parts, new_body);
                        (Some(body_str), res)
                    }
                    Err(_) => {
                        let res = Response::from_parts(parts, Body::empty());
                        (None, res)
                    }
                }
            } else if is_sse {
                // SSE streaming: tee the stream to forward chunks immediately while accumulating
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
                                warn!(error = %e, "SSE stream error");
                                break;
                            }
                            None => {
                                // Stream ended
                                break;
                            }
                        }
                    }

                    // Stream ended - decompress and log the accumulated content
                    let content = {
                        let acc = accumulated_clone.lock();
                        let raw_bytes = acc.clone();
                        let raw_len = raw_bytes.len();
                        drop(acc); // Release lock before decompression

                        debug!(
                            encoding = ?log_content_encoding,
                            raw_bytes = raw_len,
                            "Decompressing SSE response"
                        );

                        // Decompress using header or magic byte detection
                        let decompressed = try_decompress(&raw_bytes, log_content_encoding.as_deref());

                        String::from_utf8_lossy(&decompressed).to_string()
                    };

                    if let Some(ref logger) = log_event_logger {
                        let agent_name = log_pending.agent.unwrap_or(log_pending.provider);
                        let agent_info = AgentInfo::new(agent_name, DetectionSource::Environment);
                        let method_str = format!("{} {}", log_pending.method, log_pending.path);

                        // Create request preview
                        let request_preview = log_pending.request_content
                            .as_ref()
                            .map(|b| safe_truncate(b, 300))
                            .unwrap_or_else(|| format!("{} {}", log_pending.method, log_pending.path));

                        // Create response preview (more for SSE)
                        let response_preview = safe_truncate(&content, 500);

                        let source = if log_pending.is_agent_app { EventSource::AgentApp } else { EventSource::AiProxy };
                        let mut event = WrapEvent::new(&log_session_id, &log_pending.host, WrapDirection::Out, agent_info)
                            .with_source(source)
                            .with_provider(log_pending.provider)
                            .with_method(method_str)
                            .with_status_code(status)
                            .with_latency(log_latency_ms);

                        // Add paired request/response content
                        if let Some(ref req_body) = log_pending.request_content {
                            event = event.with_request(req_body.clone(), request_preview.clone());
                        }
                        event = event.with_response(content, response_preview.clone());

                        // Also set content_preview for backward compatibility
                        event = event.with_content_preview(format!("→ {} | ← {} (SSE)", request_preview, response_preview));

                        if let Some(ref m) = log_pending.model {
                            event = event.with_model(m.clone());
                        }

                        logger.log(&event);
                        debug!("Logged paired SSE request/response");
                    }
                };

                // Wrap the tee stream in StreamBody
                let stream_body = StreamBody::new(tee_stream);
                let new_body = Body::from(stream_body);
                let res = Response::from_parts(parts, new_body);

                // Return None for body_content - the SSE logging happens in the stream
                (None, res)
            } else {
                // Non-JSON, non-SSE - pass through without buffering
                (None, res)
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

            // Log paired request/response event (skip SSE - it logs in the stream tee)
            if !is_sse {
                if let Some(ref logger) = event_logger {
                    let agent_name = pending.agent.unwrap_or(pending.provider);
                    let agent_info = AgentInfo::new(agent_name, DetectionSource::Environment);
                    let method_str = format!("{} {}", pending.method, pending.path);

                    // Create request preview
                    let request_preview = pending
                        .request_content
                        .as_ref()
                        .map(|b| safe_truncate(b, 300))
                        .unwrap_or_else(|| format!("{} {}", pending.method, pending.path));

                    // Create response preview
                    let response_preview = body_content
                        .as_ref()
                        .map(|b| safe_truncate(b, 300))
                        .unwrap_or_else(|| format!("HTTP {}", status));

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
                        event = event.with_request(req_body.clone(), request_preview.clone());
                    }
                    if let Some(ref resp_body) = body_content {
                        event = event.with_response(resp_body.clone(), response_preview.clone());
                        // Also set content field for Inspector backward compatibility
                        event = event.with_content(resp_body.clone());
                    }

                    // Also set content_preview for backward compatibility
                    event = event.with_content_preview(format!(
                        "→ {} | ← {}",
                        request_preview, response_preview
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

        // Extract host and direction from context
        let (host, direction) = match ctx {
            WebSocketContext::ClientToServer { dst, .. } => {
                let h = dst.host().unwrap_or("unknown").to_string();
                (h, WrapDirection::In)
            }
            WebSocketContext::ServerToClient { src, .. } => {
                let h = src.host().unwrap_or("unknown").to_string();
                (h, WrapDirection::Out)
            }
        };

        // Detect provider from host
        let provider = if host.contains("openai.com")
            || host.contains("openai.azure.com")
            || host.contains("chatgpt.com")
        {
            "openai"
        } else if host.contains("anthropic.com") || host.contains("claude.ai") {
            "anthropic"
        } else if host.contains("googleapis.com") {
            "google"
        } else {
            "unknown"
        };

        // Determine if this is an agent app (chatgpt.com, claude.ai, chat.openai.com) or direct API
        // Agent apps: web/desktop clients (chatgpt.com, chat.openai.com, claude.ai)
        // Direct API: api.openai.com, api.anthropic.com (programmatic access)
        let is_agent_app = {
            let h = host.as_str();
            if h.contains("openai.com") || h.contains("chatgpt.com") {
                !h.starts_with("api.") && !h.contains(".api.")
            } else if h.contains("anthropic.com") || h.contains("claude.ai") {
                !h.starts_with("api.") && !h.contains(".api.")
            } else if h.contains("perplexity.ai") {
                !h.starts_with("api.") && !h.contains(".api.")
            } else {
                h.contains("aistudio.google.com") || h.contains("makersuite.google.com")
            }
        };

        async move {
            match &msg {
                Message::Text(text) => {
                    info!(host = %host, provider = provider, len = text.len(), "WebSocket text message");

                    // Log WebSocket message for observability
                    if let Some(ref logger) = event_logger {
                        let agent_info = AgentInfo::new("websocket", DetectionSource::Environment);

                        // Create content preview (first 300 chars)
                        let content_preview = safe_truncate(text, 300);

                        let source = if is_agent_app {
                            EventSource::AgentApp
                        } else {
                            EventSource::AiProxy
                        };

                        let event = WrapEvent::new(&session_id, &host, direction, agent_info)
                            .with_source(source)
                            .with_provider(provider)
                            .with_method("WebSocket")
                            .with_content(text.to_string())
                            .with_content_preview(content_preview);
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

    let proxy = Proxy::builder()
        .with_addr(listen_addr)
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
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
    use soth_core::types::policy::PolicyData;
    use soth_identity::Did;

    #[test]
    fn test_detect_provider() {
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
            AiProxyHandler::detect_provider("claude.ai"),
            Some("anthropic")
        );
        assert_eq!(
            AiProxyHandler::detect_provider("api.claude.ai"),
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
}
