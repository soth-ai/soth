use super::*;
use crate::transport::proxy_detection::should_log_request;
use crate::transport::proxy_payload::is_header_budget_sensitive_host;
use crate::transport::proxy_support::{DiscoveryKind, DiscoveryReserveResult};
use flate2::{write::GzEncoder, Compression};
use hudsucker::hyper_util::{rt::TokioExecutor, server::conn::auto::Builder as AutoServerBuilder};
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
fn load_oisp_engine_without_cache_path_returns_error() {
    let error = match load_oisp_engine(None) {
        Ok(_) => panic!("missing cache path should error"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("registry cache path not configured"));
}

#[test]
fn load_oisp_engine_uses_cache_bundle_without_embedded_overlay() {
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
    assert!(engine.classify("ws.chatgpt.com").is_none());
    assert!(!engine.should_intercept_host("ws.chatgpt.com:443"));
}

#[test]
fn load_oisp_engine_missing_cache_bundle_returns_error() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("missing_registry_bundle_cache.json");
    let error = match load_oisp_engine(Some(path.as_path())) {
        Ok(_) => panic!("missing cache should return error"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("registry cache not found"));
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
    config.registry_mode = RegistryMode::BundleOnly;
    let observe = ObserveConfig::default();
    let handler = AiProxyHandler::new(&config, &observe, test_oisp_engine());

    assert_eq!(
        handler.get_action("api.openai.com", "/v1/chat/completions", "POST"),
        HostAction::Intercept
    );
    assert_eq!(
        handler.get_action("api.github.com", "/mcp", "POST"),
        HostAction::Intercept
    );
    assert_eq!(
        handler.get_action("unknown.example.com", "/v1/messages", "POST"),
        HostAction::Tunnel
    );
}

#[test]
fn test_registry_mode_tunnels_unclassified_hosts() {
    let mut config = ForwardProxyConfig::default();
    config.registry_mode = RegistryMode::BundleOnly;
    let observe = ObserveConfig::default();
    let handler = AiProxyHandler::new(&config, &observe, test_oisp_engine());

    assert_eq!(
        handler.get_action("unknown.example.com", "/v1/chat/completions", "POST"),
        HostAction::Tunnel
    );
}

#[test]
fn test_registry_mode_does_not_fall_back_to_configured_hosts() {
    let mut config = ForwardProxyConfig::default();
    config.registry_mode = RegistryMode::BundleOnly;
    config.hosts.block = vec!["fallback-only.example".to_string()];
    let observe = ObserveConfig::default();
    let handler = AiProxyHandler::new(&config, &observe, test_oisp_engine());

    assert_eq!(
        handler.get_action("fallback-only.example", "/v1/chat/completions", "POST"),
        HostAction::Block
    );
}

#[test]
fn test_connect_action_uses_host_only_oisp_decision() {
    let mut config = ForwardProxyConfig::default();
    config.registry_mode = RegistryMode::BundleOnly;
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
fn test_debug_force_intercept_all_intercepts_unknown_remote_hosts() {
    let mut config = ForwardProxyConfig::default();
    config.registry_mode = RegistryMode::BundleOnly;
    config.hosts.mode = HostFilterMode::Selective;
    let observe = ObserveConfig::default();

    let handler = AiProxyHandler::new(&config, &observe, test_oisp_engine())
        .with_force_intercept_all(true, None);

    assert_eq!(
        handler.get_connect_action("unknown.example.com"),
        HostAction::Intercept
    );
    assert_eq!(handler.get_connect_action("localhost"), HostAction::Tunnel);
}

#[test]
fn test_debug_force_intercept_all_respects_expiry() {
    let mut config = ForwardProxyConfig::default();
    config.registry_mode = RegistryMode::BundleOnly;
    config.hosts.mode = HostFilterMode::Selective;
    let observe = ObserveConfig::default();

    let expired = SystemTime::now()
        .checked_sub(Duration::from_secs(1))
        .expect("system clock should support one-second subtraction");
    let handler = AiProxyHandler::new(&config, &observe, test_oisp_engine())
        .with_force_intercept_all(true, Some(expired));

    assert_eq!(
        handler.get_connect_action("unknown.example.com"),
        HostAction::Tunnel
    );
}

#[test]
fn test_discovery_mode_catalog_intercept_is_limited_to_first_daily_capture() {
    let mut config = ForwardProxyConfig::default();
    config.registry_mode = RegistryMode::BundleOnly;
    config.hosts.mode = HostFilterMode::Discovery;
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
fn test_catalog_discovery_limiter_persists_once_per_day_state() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let logger = Arc::new(EventLogger::new(db_path).unwrap());

    let limiter = CatalogDiscoveryLimiter::default();
    limiter.set_event_logger(logger.clone());
    assert_eq!(
        limiter.reserve_once_per_day(DiscoveryKind::Catalog, "server.codeium.com"),
        DiscoveryReserveResult::Reserved
    );
    assert_eq!(
        limiter.reserve_once_per_day(DiscoveryKind::Catalog, "server.codeium.com"),
        DiscoveryReserveResult::AlreadySeen
    );

    let limiter_after_restart = CatalogDiscoveryLimiter::default();
    limiter_after_restart.set_event_logger(logger);
    assert_eq!(
        limiter_after_restart.reserve_once_per_day(DiscoveryKind::Catalog, "server.codeium.com"),
        DiscoveryReserveResult::AlreadySeen
    );
}

#[test]
fn test_catalog_discovery_limiter_enforces_daily_cap() {
    let limiter = CatalogDiscoveryLimiter::with_catalog_daily_cap(1);

    assert_eq!(
        limiter.reserve_once_per_day(DiscoveryKind::Catalog, "server.codeium.com"),
        DiscoveryReserveResult::Reserved
    );
    assert_eq!(
        limiter.reserve_once_per_day(DiscoveryKind::Catalog, "api.githubcopilot.com"),
        DiscoveryReserveResult::DailyCapReached
    );
}

#[test]
fn test_should_log_request_skips_connect() {
    assert!(!should_log_request("/", "CONNECT"));
}

#[test]
fn test_should_log_request_skips_event_logging_paths() {
    assert!(!should_log_request("/api/event_logging/batch", "POST"));
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
    assert!(!placeholder.contains("Codex output may be streamed via WebSocket"));
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
    let enforcer = ProxyEnforcer::new().with_identity_mode(ProxyIdentityMode::Required, trusted);

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
    let tracker = soth_budget::BudgetTracker::new();
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

    let chunk = vec![9u8; 64 * 1024];
    while buffer.len() < STREAM_CAPTURE_MAX_BYTES {
        let remaining = STREAM_CAPTURE_MAX_BYTES - buffer.len();
        let write_len = remaining.min(chunk.len());
        assert!(!append_stream_capture(&mut buffer, &chunk[..write_len]));
    }
    assert_eq!(buffer.len(), STREAM_CAPTURE_MAX_BYTES);

    assert!(append_stream_capture(&mut buffer, &[9u8; 1]));
    assert_eq!(buffer.len(), STREAM_CAPTURE_MAX_BYTES);
}

#[test]
fn test_trim_cookie_header_for_budget_keeps_auth_under_limit() {
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
    let trimmed = trim_cookie_header_for_budget(&raw, COOKIE_MAX_HEADER_BYTES)
        .expect("expected cookie trimming result");

    assert!(trimmed.len() <= COOKIE_MAX_HEADER_BYTES);
    assert!(trimmed.contains("__Secure-next-auth.session-token="));
    assert!(trimmed.contains("__Host-next-auth.csrf-token="));
}

#[test]
fn test_sanitize_request_headers_trims_cookie_header() {
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
    assert!(cookie.len() <= COOKIE_MAX_HEADER_BYTES);
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
    assert!(cookie.len() <= COOKIE_MAX_HEADER_BYTES);
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
    assert!(total_size <= HEADER_STRICT_TOTAL_BYTES + 400);
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
fn test_is_header_budget_sensitive_host_detection() {
    assert!(is_header_budget_sensitive_host("agent.example.com"));
    assert!(is_header_budget_sensitive_host("api.example.com"));
    assert!(!is_header_budget_sensitive_host(""));
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

#[test]
fn test_metadata_policy_never_downgrades_skip_reason() {
    assert!(!should_downgrade_skip_reason_for_metadata_policy(
        EXCHANGE_SKIP_REASON_NO_BUNDLE_ID
    ));
    assert!(!should_downgrade_skip_reason_for_metadata_policy(
        EXCHANGE_SKIP_REASON_APP_NOT_ALLOWED
    ));
    assert!(!should_downgrade_skip_reason_for_metadata_policy(
        EXCHANGE_SKIP_REASON_APP_RATE_LIMITED
    ));
    assert!(!should_downgrade_skip_reason_for_metadata_policy(
        EXCHANGE_SKIP_REASON_DOMAIN_RATE_LIMITED
    ));
    assert!(!should_downgrade_skip_reason_for_metadata_policy(
        EXCHANGE_SKIP_REASON_NOT_WHITELISTED
    ));
}

#[test]
fn test_map_request_decision_reason_to_skip_reason_contract_safe_values() {
    assert_eq!(
        map_request_decision_reason_to_skip_reason(Some("whitelist_path_miss")),
        EXCHANGE_SKIP_REASON_NOT_WHITELISTED
    );
    assert_eq!(
        map_request_decision_reason_to_skip_reason(Some("deny_paths_exact")),
        EXCHANGE_SKIP_REASON_BLACKLISTED
    );
    assert_eq!(
        map_request_decision_reason_to_skip_reason(Some("metadata_only")),
        EXCHANGE_SKIP_REASON_NOT_WHITELISTED
    );
    assert_eq!(
        map_request_decision_reason_to_skip_reason(Some("some_unknown_reason")),
        EXCHANGE_SKIP_REASON_NOT_WHITELISTED
    );
}

#[test]
fn test_decision_step_from_request_decision_maps_bundle_reasons() {
    assert_eq!(
        decision_step_from_request_decision(
            Some("app_origin_not_allowed"),
            &RequestDecisionOutcome::Tunnel
        ),
        EXCHANGE_DECISION_STEP_APP_GATE
    );
    assert_eq!(
        decision_step_from_request_decision(
            Some("whitelist_path_miss"),
            &RequestDecisionOutcome::MetadataOnly
        ),
        EXCHANGE_DECISION_STEP_WHITELIST
    );
    assert_eq!(
        decision_step_from_request_decision(
            Some("deny_paths_exact"),
            &RequestDecisionOutcome::MetadataOnly
        ),
        EXCHANGE_DECISION_STEP_URL_BLACKLIST
    );
    assert_eq!(
        decision_step_from_request_decision(
            Some("blacklisted_graphql"),
            &RequestDecisionOutcome::Noise
        ),
        EXCHANGE_DECISION_STEP_URL_BLACKLIST
    );
}
