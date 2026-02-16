use super::*;
use crate::transport::proxy_detection::{should_log_request, should_treat_anthropic_api_as_agent};
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
fn load_oisp_engine_requires_configured_cache_path() {
    let error = match load_oisp_engine(None) {
        Ok(_) => panic!("expected missing cache path to fail"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("compiled registry bundle is required"));
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
fn load_oisp_engine_requires_existing_cache_bundle() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("missing_registry_bundle_cache.json");
    let error = match load_oisp_engine(Some(path.as_path())) {
        Ok(_) => panic!("expected missing cache bundle to fail"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("compiled registry bundle is required"));
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
    config.registry_mode = RegistryMode::BundleOnly;
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
    config.registry_mode = RegistryMode::BundleOnly;
    config.hosts.block = vec!["fallback-only.example".to_string()];
    let observe = ObserveConfig::default();
    let handler = AiProxyHandler::new(&config, &observe, test_oisp_engine());

    assert_eq!(
        handler.get_action("fallback-only.example", "/v1/chat/completions"),
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
fn test_detect_agent_from_user_agent_codex() {
    let req = Request::builder()
        .uri("https://chatgpt.com/backend-api/codex/responses")
        .header("user-agent", "OpenAI-Codex/1.0")
        .body(())
        .unwrap();
    assert_eq!(detect_agent_from_user_agent(&req), Some("codex"));
}

#[test]
fn test_detect_agent_from_user_agent_warp() {
    let req = Request::builder()
        .uri("https://api.anthropic.com/v1/messages")
        .header("user-agent", "Warp/0.2026.01")
        .body(())
        .unwrap();
    assert_eq!(detect_agent_from_user_agent(&req), Some("warp"));
}

#[test]
fn test_detect_agent_from_user_agent_claude_code() {
    let req = Request::builder()
        .uri("https://api.anthropic.com/v1/messages")
        .header("user-agent", "claude-code/1.0")
        .body(())
        .unwrap();
    assert_eq!(detect_agent_from_user_agent(&req), Some("claude-code"));
}

#[test]
fn test_detect_agent_from_user_agent_claude_code_with_space() {
    let req = Request::builder()
        .uri("https://api.anthropic.com/v1/messages")
        .header("user-agent", "Claude Code/1.0")
        .body(())
        .unwrap();
    assert_eq!(detect_agent_from_user_agent(&req), Some("claude-code"));
}

#[test]
fn test_anthropic_api_key_header_marks_inference() {
    let req = Request::builder()
        .uri("https://api.anthropic.com/v1/messages")
        .header("x-api-key", "sk-ant-test")
        .body(())
        .unwrap();
    assert!(has_anthropic_api_key_header(&req));
    assert!(!should_treat_anthropic_api_as_agent(
        "api.anthropic.com",
        &req
    ));
}

#[test]
fn test_anthropic_without_api_key_marks_agent() {
    let req = Request::builder()
        .uri("https://api.anthropic.com/v1/messages")
        .header("user-agent", "Warp/0.2026.01")
        .body(())
        .unwrap();
    assert!(!has_anthropic_api_key_header(&req));
    assert!(should_treat_anthropic_api_as_agent(
        "api.anthropic.com",
        &req
    ));
}

#[test]
fn test_detect_agent_with_context_promotes_codex_path() {
    assert_eq!(
        host_fingerprint::detect_agent_with_context(
            Some("chatgpt"),
            "chatgpt.com",
            "/backend-api/codex/responses",
            None
        ),
        Some("codex")
    );
    assert_eq!(
        host_fingerprint::detect_agent_with_context(
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
        host_fingerprint::detect_agent_with_context(
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
        host_fingerprint::detect_agent_with_context(
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
        host_fingerprint::detect_agent_with_context(
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
        host_fingerprint::detect_agent_with_context(None, "claude.ai", "/api/organizations", None),
        Some("claude")
    );
}

#[test]
fn test_detect_agent_with_context_defaults_gemini_when_ua_missing() {
    assert_eq!(
        host_fingerprint::detect_agent_with_context(None, "gemini.google.com", "/app", None),
        Some("gemini")
    );
}

#[test]
fn test_detect_agent_with_context_gated_disables_host_fallbacks() {
    assert_eq!(
        host_fingerprint::detect_agent_with_context_gated(
            None,
            "gemini.google.com",
            "/app",
            None,
            false
        ),
        None
    );
    assert_eq!(
        host_fingerprint::detect_agent_with_context_gated(
            Some("chatgpt"),
            "chatgpt.com",
            "/backend-api/f/conversation",
            None,
            false
        ),
        Some("chatgpt")
    );
    assert_eq!(
        host_fingerprint::detect_agent_with_context_gated(
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
        host_fingerprint::detect_agent_with_context(None, "api2.cursor.sh", "/", None),
        Some("cursor")
    );
    assert_eq!(
        host_fingerprint::detect_agent_with_context(
            None,
            "enterprise.githubcopilot.com",
            "/",
            None
        ),
        Some("github-copilot")
    );
    assert_eq!(
        host_fingerprint::detect_agent_with_context(None, "server.codeium.com", "/", None),
        Some("windsurf")
    );
    assert_eq!(
        host_fingerprint::detect_agent_with_context(None, "cloud.zed.dev", "/", None),
        Some("zed")
    );
    assert_eq!(
        host_fingerprint::detect_agent_with_context(None, "api.jetbrains.ai", "/", None),
        Some("junie")
    );
    assert_eq!(
        host_fingerprint::detect_agent_with_context(
            None,
            "codewhisperer.us-east-1.amazonaws.com",
            "/",
            None
        ),
        Some("amazon-q")
    );
    assert_eq!(
        host_fingerprint::detect_agent_with_context(None, "statsig.anthropic.com", "/", None),
        Some("claude-code")
    );
    assert_eq!(
        host_fingerprint::detect_agent_with_context(None, "gemini.google.com", "/", None),
        Some("gemini")
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
