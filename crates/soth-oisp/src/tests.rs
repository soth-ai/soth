use super::*;
use serde_json::json;
use std::collections::BTreeMap;
use tempfile::tempdir;

fn sample_bundle() -> CompiledBundle {
    parse_compiled_bundle(&json!({
            "version": "v1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "local",
            "domain_index": [
                { "host": "api.openai.com", "provider_id": "openai", "entry_type": "ai-inference" },
                { "host": "*.chatgpt.com", "provider_id": "chatgpt", "entry_type": "agent-app" }
            ],
            "providers": {
                "openai": { "id": "openai", "name": "OpenAI", "type": "ai-inference", "api_format": "openai" },
                "chatgpt": { "id": "chatgpt", "name": "ChatGPT", "type": "agent-app" }
            },
            "filters": {
                "passthrough": ["statsig.anthropic.com"],
                "noise_keywords": ["analytics"]
            },
            "pricing": {}
        }))
        .unwrap()
}

#[test]
fn classify_prefers_exact_match_before_wildcard() {
    let engine = OispEngine::new(sample_bundle()).unwrap();
    let class = engine.classify("api.openai.com").unwrap();
    assert_eq!(class.provider_id, "openai");
    assert_eq!(class.entry_type, EntryType::AiInference);
}

#[test]
fn classify_matches_wildcard() {
    let engine = OispEngine::new(sample_bundle()).unwrap();
    let class = engine.classify("ws.chatgpt.com").unwrap();
    assert_eq!(class.provider_id, "chatgpt");
    assert_eq!(class.entry_type, EntryType::AgentApp);
}

#[test]
fn should_intercept_honors_noise_and_passthrough() {
    let engine = OispEngine::new(sample_bundle()).unwrap();
    assert_eq!(
        engine.should_intercept("api.openai.com", "/v1/analytics"),
        InterceptDecision::Noise
    );
    assert_eq!(
        engine.should_intercept("statsig.anthropic.com", "/v1/t"),
        InterceptDecision::Passthrough
    );
    assert_eq!(
        engine.should_intercept("api.openai.com", "/v1/chat/completions"),
        InterceptDecision::Intercept {
            provider_id: "openai".to_string(),
            entry_type: EntryType::AiInference
        }
    );
}

#[test]
fn should_intercept_honors_path_filters_when_present() {
    let engine = OispEngine::new(
        parse_compiled_bundle(&json!({
            "version": "v1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "local",
            "domain_index": [
                {
                    "host": "api.openai.com",
                    "provider_id": "openai",
                    "entry_type": "ai-inference",
                    "paths": ["/v1/chat/completions", "/v1/responses*"]
                }
            ],
            "providers": {
                "openai": { "id": "openai", "name": "OpenAI", "type": "ai-inference" }
            },
            "filters": {},
            "pricing": {}
        }))
        .unwrap(),
    )
    .unwrap();

    assert_eq!(
        engine.should_intercept("api.openai.com", "/v1/chat/completions"),
        InterceptDecision::Intercept {
            provider_id: "openai".to_string(),
            entry_type: EntryType::AiInference
        }
    );
    assert_eq!(
        engine.should_intercept("api.openai.com", "/v1/responses/stream"),
        InterceptDecision::Intercept {
            provider_id: "openai".to_string(),
            entry_type: EntryType::AiInference
        }
    );
    assert_eq!(
        engine.should_intercept("api.openai.com", "/v1/models"),
        InterceptDecision::Tunnel
    );

    assert!(engine.should_intercept_host("api.openai.com"));
}

#[test]
fn should_intercept_honors_path_filters_with_query_string() {
    let engine = OispEngine::new(
        parse_compiled_bundle(&json!({
            "version": "v1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "local",
            "domain_index": [
                {
                    "host": "api.openai.com",
                    "provider_id": "openai",
                    "entry_type": "ai-inference",
                    "paths": ["/v1/chat/completions"]
                }
            ],
            "providers": {
                "openai": { "id": "openai", "name": "OpenAI", "type": "ai-inference" }
            },
            "filters": {},
            "pricing": {}
        }))
        .unwrap(),
    )
    .unwrap();

    assert_eq!(
        engine.should_intercept("api.openai.com", "/v1/chat/completions?trace=1"),
        InterceptDecision::Intercept {
            provider_id: "openai".to_string(),
            entry_type: EntryType::AiInference
        }
    );
}

#[test]
fn catalog_domains_are_available_for_discovery_checks() {
    let engine = OispEngine::new(
        parse_compiled_bundle(&json!({
            "version": "v2",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "cloud",
            "core": {
                "providers": {
                    "openai": { "id": "openai", "name": "OpenAI", "type": "ai-inference" }
                },
                "domain_index": [
                    {
                        "host": "api.openai.com",
                        "provider_id": "openai",
                        "entry_type": "ai-inference"
                    }
                ]
            },
            "filters": {},
            "catalog": {
                "domains": ["server.codeium.com", "*.githubcopilot.com"]
            }
        }))
        .unwrap(),
    )
    .unwrap();

    assert_eq!(engine.catalog_domain_count(), 2);
    assert!(engine.is_catalog_domain("server.codeium.com"));
    assert!(engine.is_catalog_domain("api.githubcopilot.com"));
}

#[test]
fn gating_rules_parse_and_match_app_and_host_origins() {
    let engine = OispEngine::new(
        parse_compiled_bundle(&json!({
            "schema_version": 3,
            "version": "v3",
            "compiled_at": "2026-02-19T00:00:00Z",
            "bundle_type": "cloud",
            "core": {
                "providers": {
                    "openai": { "id": "openai", "name": "OpenAI", "type": "ai-inference" }
                },
                "domain_index": [
                    {
                        "host": "api.openai.com",
                        "provider_id": "openai",
                        "entry_type": "ai-inference"
                    }
                ]
            },
            "filters": {},
            "gating": {
                "allowed_app_origins": {
                    "hosts": ["com.google.chrome", "org.mozilla.firefox"],
                    "non_hosts": ["com.anthropic.claudefordesktop"],
                    "apps_with_parsers": ["com.anthropic.claudefordesktop"]
                },
                "allowed_host_origins": ["https://chatgpt.com", "claude.ai"]
            }
        }))
        .unwrap(),
    )
    .unwrap();

    assert_eq!(
        engine.classify_app_origin("com.google.chrome"),
        Some("host")
    );
    assert_eq!(
        engine.classify_app_origin("com.anthropic.claudefordesktop"),
        Some("non_host")
    );
    assert!(engine.app_has_parser("com.anthropic.claudefordesktop"));
    assert!(engine.has_host_origin_rules());
    assert!(engine.is_allowed_host_origin("https://chatgpt.com/backend-api"));
    assert!(!engine.is_allowed_host_origin("https://example.com"));
}

#[test]
fn gating_rules_match_scoped_package_identifiers() {
    let engine = OispEngine::new(
        parse_compiled_bundle(&json!({
            "schema_version": 3,
            "version": "v3",
            "compiled_at": "2026-02-20T00:00:00Z",
            "bundle_type": "cloud",
            "core": {
                "providers": {
                    "openai": { "id": "openai", "name": "OpenAI", "type": "agent-app" }
                },
                "domain_index": [
                    {
                        "host": "chatgpt.com",
                        "provider_id": "openai",
                        "entry_type": "agent-app"
                    }
                ]
            },
            "filters": {},
            "gating": {
                "allowed_app_origins": {
                    "non_hosts": ["@openai/codex"],
                    "apps_with_parsers": ["@openai/codex"]
                },
                "allowed_host_origins": ["chatgpt.com"]
            }
        }))
        .unwrap(),
    )
    .unwrap();

    assert_eq!(
        engine.classify_app_origin("@openai/codex"),
        Some("non_host")
    );
    assert!(engine.app_has_parser("@openai/codex"));
    assert_eq!(engine.classify_app_origin("@openai"), None);
}

#[test]
fn parse_filters_supports_sensor_config_alias_fields() {
    let engine = OispEngine::new(
        parse_compiled_bundle(&json!({
            "schema_version": 3,
            "version": "alias-filters-v1",
            "compiled_at": "2026-02-20T00:00:00Z",
            "bundle_type": "cloud",
            "core": {
                "providers": {
                    "openai": { "id": "openai", "name": "OpenAI", "type": "ai-inference" }
                },
                "domain_index": [
                    { "host": "api.openai.com", "provider_id": "openai", "entry_type": "ai-inference" }
                ]
            },
            "whitelistedDomains": ["api.openai.com"],
            "passthroughDomains": ["metrics.openai.com"],
            "blacklistedWords": ["telemetry"]
        }))
        .unwrap(),
    )
    .unwrap();

    assert!(matches!(
        engine.should_intercept("api.openai.com", "/v1/responses"),
        InterceptDecision::Intercept { .. }
    ));
    assert!(matches!(
        engine.should_intercept("metrics.openai.com", "/events"),
        InterceptDecision::Passthrough
    ));
    assert!(engine.matches_noise_keyword("telemetry ping"));
}

#[test]
fn bundle_classification_depends_on_loaded_bundle_content() {
    let engine = OispEngine::new(
            parse_compiled_bundle(&json!({
                "version": "v1",
                "compiled_at": "2026-02-14T00:00:00Z",
                "bundle_type": "cloud",
                "domain_index": [
                    { "host": "api.openai.com", "provider_id": "openai", "entry_type": "ai-inference" },
                    { "host": "chatgpt.com", "provider_id": "chatgpt", "entry_type": "agent-app" },
                    { "host": "api.anthropic.com", "provider_id": "anthropic", "entry_type": "ai-inference" },
                    { "host": "app.warp.dev", "provider_id": "warp", "entry_type": "agent-app" },
                    { "host": "api.warp.dev", "provider_id": "warp", "entry_type": "agent-app" }
                ],
                "providers": {
                    "openai": { "id": "openai", "name": "OpenAI", "type": "ai-inference" },
                    "chatgpt": { "id": "chatgpt", "name": "ChatGPT", "type": "agent-app" },
                    "anthropic": { "id": "anthropic", "name": "Anthropic", "type": "ai-inference" },
                    "warp": { "id": "warp", "name": "Warp", "type": "agent-app" }
                },
                "filters": {},
                "pricing": {}
            }))
            .unwrap(),
        )
        .unwrap();
    assert!(!engine.bundle_version().trim().is_empty());
    assert!(engine.provider_count() > 0);
    assert!(engine.classify("api.openai.com").is_some());
    assert!(engine.classify("chatgpt.com").is_some());
    assert!(engine.classify("app.warp.dev").is_some());
    assert!(engine.classify("api.warp.dev").is_some());
    assert!(engine.classify("api.anthropic.com").is_some());
}

#[test]
fn bundle_classification_does_not_include_implicit_overlay_hosts() {
    let primary = OispEngine::new(
            parse_compiled_bundle(&json!({
                "version": "primary-v1",
                "compiled_at": "2026-02-14T00:00:00Z",
                "bundle_type": "cloud",
                "domain_index": [
                    { "host": "api.example.com", "provider_id": "example", "entry_type": "ai-inference" }
                ],
                "providers": {
                    "example": { "id": "example", "name": "Example", "type": "ai-inference", "api_format": "openai" }
                },
                "filters": {},
                "pricing": {},
                "formats": {
                    "openai": {
                        "request": { "model": "$.model" },
                        "response": { "json": { "extract": { "model": "$.model" } } }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

    assert!(primary.classify("api.example.com").is_some());
    assert!(primary.classify("chatgpt.com").is_none());
    assert!(primary.classify("app.warp.dev").is_none());
    assert!(primary.classify("api.warp.dev").is_none());
    assert!(primary.classify("api.openai.com").is_none());
}

#[test]
fn detection_rules_work_for_codex_and_warp_when_declared_in_bundle() {
    let engine = OispEngine::new(
        parse_compiled_bundle(&json!({
            "version": "v1",
            "compiled_at": "2026-02-14T00:00:00Z",
            "bundle_type": "cloud",
            "domain_index": [
                { "host": "ws.chatgpt.com", "provider_id": "chatgpt", "entry_type": "agent-app" },
                { "host": "api.warp.dev", "provider_id": "warp", "entry_type": "agent-app" }
            ],
            "providers": {
                "chatgpt": {
                    "id": "chatgpt",
                    "name": "ChatGPT",
                    "type": "agent-app",
                    "detection": {
                        "path_rules": [
                            {
                                "id": "chatgpt_codex_path",
                                "agent": "codex",
                                "reason": "path_contains_codex",
                                "confidence": 0.96,
                                "path": "/backend-api/codex/*"
                            }
                        ]
                    }
                },
                "warp": {
                    "id": "warp",
                    "name": "Warp",
                    "type": "agent-app",
                    "detection": {
                        "ua_rules": [
                            {
                                "id": "warp_ua",
                                "agent": "warp",
                                "reason": "ua_prefix_warp",
                                "confidence": 0.9,
                                "prefix": "warp/"
                            }
                        ]
                    }
                }
            },
            "filters": {},
            "pricing": {}
        }))
        .unwrap(),
    )
    .unwrap();
    let codex = engine
        .evaluate_detection_for_host(
            "ws.chatgpt.com",
            &DetectionContext {
                host: Some("ws.chatgpt.com".to_string()),
                path: Some("/backend-api/codex/responses".to_string()),
                ..DetectionContext::default()
            },
        )
        .expect("codex detection should exist");
    assert_eq!(codex.agent.as_deref(), Some("codex"));

    let warp = engine
        .evaluate_detection_for_host(
            "api.warp.dev",
            &DetectionContext {
                host: Some("api.warp.dev".to_string()),
                path: Some("/graphql/v2".to_string()),
                user_agent: Some("Warp/0.2026.01".to_string()),
                ..DetectionContext::default()
            },
        )
        .expect("warp detection should exist");
    assert_eq!(warp.agent.as_deref(), Some("warp"));
}

#[test]
fn launch_subset_supports_openai_and_anthropic_app_and_path_detection() {
    let engine = OispEngine::new(
        parse_compiled_bundle(&json!({
            "schema_version": 3,
            "version": "v1",
            "compiled_at": "2026-02-19T00:00:00Z",
            "bundle_type": "cloud",
            "domain_index": [
                {
                    "host": "api.openai.com",
                    "provider_id": "openai",
                    "entry_type": "ai-inference",
                    "paths": ["/v1/chat/completions", "/v1/responses"]
                },
                {
                    "host": "chatgpt.com",
                    "provider_id": "chatgpt",
                    "entry_type": "agent-app",
                    "paths": ["/backend-api/**"]
                },
                {
                    "host": "api.anthropic.com",
                    "provider_id": "anthropic",
                    "entry_type": "ai-inference",
                    "paths": ["/v1/messages"]
                },
                {
                    "host": "claude.ai",
                    "provider_id": "claude-web",
                    "entry_type": "agent-app",
                    "paths": ["/api/**"]
                }
            ],
            "providers": {
                "openai": {
                    "id": "openai",
                    "detection_id": "prv_openai",
                    "name": "OpenAI",
                    "type": "ai-inference",
                    "api_format": "openai"
                },
                "chatgpt": {
                    "id": "chatgpt",
                    "detection_id": "agt_chatgpt",
                    "name": "ChatGPT",
                    "type": "agent-app",
                    "detection": {
                        "path_rules": [
                            {
                                "id": "chatgpt_codex_path",
                                "agent": "codex",
                                "reason": "path_contains_codex",
                                "confidence": 0.96,
                                "path": "/backend-api/codex/*"
                            }
                        ]
                    }
                },
                "anthropic": {
                    "id": "anthropic",
                    "detection_id": "prv_anthropic",
                    "name": "Anthropic",
                    "type": "ai-inference",
                    "api_format": "anthropic",
                    "detection": {
                        "ua_rules": [
                            {
                                "id": "anthropic_ua_claude_code",
                                "agent": "claude-code",
                                "contains": ["claude-code", "claude code"]
                            }
                        ],
                        "process_rules": [
                            {
                                "id": "anthropic_process_claude_code",
                                "agent": "claude-code",
                                "contains": ["claude-code", "claude code"]
                            },
                            {
                                "id": "anthropic_process_claude",
                                "agent": "claude",
                                "contains": "claude"
                            }
                        ]
                    }
                },
                "claude-web": {
                    "id": "claude-web",
                    "detection_id": "agt_claude_web",
                    "name": "Claude Web",
                    "type": "agent-app"
                }
            },
            "filters": {},
            "pricing": {}
        }))
        .unwrap(),
    )
    .unwrap();

    assert_eq!(
        engine.should_intercept("api.openai.com", "/v1/chat/completions"),
        InterceptDecision::Intercept {
            provider_id: "openai".to_string(),
            entry_type: EntryType::AiInference
        }
    );
    assert_eq!(
        engine.should_intercept("chatgpt.com", "/backend-api/conversation"),
        InterceptDecision::Intercept {
            provider_id: "chatgpt".to_string(),
            entry_type: EntryType::AgentApp
        }
    );
    assert_eq!(
        engine.should_intercept("api.anthropic.com", "/v1/messages"),
        InterceptDecision::Intercept {
            provider_id: "anthropic".to_string(),
            entry_type: EntryType::AiInference
        }
    );
    assert_eq!(
        engine.should_intercept("claude.ai", "/api/organizations"),
        InterceptDecision::Intercept {
            provider_id: "claude-web".to_string(),
            entry_type: EntryType::AgentApp
        }
    );
    assert_eq!(
        engine.should_intercept("api.openai.com", "/v1/models"),
        InterceptDecision::Tunnel
    );
    assert_eq!(
        engine.should_intercept("api.anthropic.com", "/v1/complete"),
        InterceptDecision::Tunnel
    );

    let codex = engine
        .evaluate_detection_for_host(
            "chatgpt.com",
            &DetectionContext {
                host: Some("chatgpt.com".to_string()),
                path: Some("/backend-api/codex/responses".to_string()),
                ..DetectionContext::default()
            },
        )
        .expect("codex detection should exist");
    assert_eq!(codex.agent.as_deref(), Some("codex"));

    let claude_code = engine
        .evaluate_detection_for_host(
            "api.anthropic.com",
            &DetectionContext {
                host: Some("api.anthropic.com".to_string()),
                path: Some("/v1/messages".to_string()),
                user_agent: Some("claude-code/1.0".to_string()),
                process_name: Some("claude-code".to_string()),
                ..DetectionContext::default()
            },
        )
        .expect("claude-code detection should exist");
    assert_eq!(claude_code.agent.as_deref(), Some("claude-code"));

    let claude = engine
        .evaluate_detection_for_host(
            "api.anthropic.com",
            &DetectionContext {
                host: Some("api.anthropic.com".to_string()),
                path: Some("/v1/messages".to_string()),
                process_name: Some("claude".to_string()),
                ..DetectionContext::default()
            },
        )
        .expect("claude detection should exist");
    assert_eq!(claude.agent.as_deref(), Some("claude"));
}

#[test]
fn load_from_registry_cache_reads_envelope_bundle() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("registry_bundle_cache.json");
    let envelope = json!({
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
        "bundle": sample_bundle()
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();

    let engine = OispEngine::load_from_registry_cache(&path)
        .unwrap()
        .unwrap();
    assert_eq!(engine.bundle_version(), "v1");
    assert_eq!(engine.provider_count(), 2);
}

#[test]
fn load_from_registry_cache_returns_none_when_missing() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("missing.json");
    let loaded = OispEngine::load_from_registry_cache(&path).unwrap();
    assert!(loaded.is_none());
}

#[test]
fn classify_returns_none_for_unknown_host() {
    let engine = OispEngine::new(sample_bundle()).unwrap();
    assert!(engine.classify("example.com").is_none());
}

#[test]
fn bundle_metadata_accessors_are_stable() {
    let engine = OispEngine::new(sample_bundle()).unwrap();
    assert_eq!(engine.bundle_version(), "v1");
    assert_eq!(engine.provider_count(), 2);
    assert_eq!(engine.domain_count(), 2);
}

#[test]
fn should_intercept_returns_tunnel_for_unknown_host() {
    let engine = OispEngine::new(sample_bundle()).unwrap();
    assert_eq!(
        engine.should_intercept("unknown.host", "/v1/messages"),
        InterceptDecision::Tunnel
    );
}

#[test]
fn host_matches_pattern_supports_middle_wildcard() {
    assert!(host_matches_pattern(
        "bedrock.us-east-1.amazonaws.com",
        "bedrock.*.amazonaws.com"
    ));
    assert!(!host_matches_pattern(
        "bedrock.amazonaws.com",
        "bedrock.*.amazonaws.com"
    ));
}

#[test]
fn host_matches_pattern_normalizes_host_port_and_trailing_dot() {
    assert!(host_matches_pattern("chatgpt.com:443", "chatgpt.com"));
    assert!(host_matches_pattern("CHATGPT.COM.", "chatgpt.com"));
    assert!(host_matches_pattern(
        "https://ws.chatgpt.com/backend-api",
        "*.chatgpt.com"
    ));
}

#[test]
fn classify_accepts_connect_authority_shape() {
    let engine = OispEngine::new(sample_bundle()).unwrap();
    assert!(engine.classify("api.openai.com:443").is_some());
    assert!(engine.should_intercept_host("api.openai.com:443"));
}

#[test]
fn contains_noise_keyword_matches_case_insensitive() {
    let keywords = vec!["Analytics".to_string()];
    assert!(contains_noise_keyword_for_host(
        "api.openai.com",
        "/v1/ANALYTICS/query",
        &keywords
    ));
    assert!(!contains_noise_keyword_for_host(
        "api.openai.com",
        "/v1/messages",
        &keywords
    ));
}

#[test]
fn contains_noise_keyword_host_scoped_pattern_requires_host_match() {
    let keywords = vec!["api.anthropic.com/api/hello".to_string()];
    assert!(contains_noise_keyword_for_host(
        "api.anthropic.com",
        "/api/hello",
        &keywords
    ));
    assert!(!contains_noise_keyword_for_host(
        "chatgpt.com",
        "/api/hello",
        &keywords
    ));
}

#[test]
fn matches_noise_keyword_uses_bundle_keywords() {
    let engine = OispEngine::new(sample_bundle()).unwrap();
    assert!(engine.matches_noise_keyword("GetAnalyticsDashboard"));
    assert!(!engine.matches_noise_keyword("CreateConversation"));
}

#[test]
fn select_best_domain_match_prefers_longer_wildcard() {
    let entries = vec![
        DomainIndexEntry {
            host: "*.openai.com".to_string(),
            provider_id: "broad".to_string(),
            entry_type: EntryType::AiInference,
            paths: Vec::new(),
        },
        DomainIndexEntry {
            host: "api.*.openai.com".to_string(),
            provider_id: "specific".to_string(),
            entry_type: EntryType::AiInference,
            paths: Vec::new(),
        },
    ];
    let selected =
        select_best_domain_match(&entries, "api.us.openai.com").expect("match should exist");
    assert_eq!(selected.provider_id, "specific");
}

#[test]
fn classify_uses_provider_type_from_provider_map() {
    let mut bundle = sample_bundle();
    let providers = BTreeMap::from([(
        "openai".to_string(),
        types::bundle::ResolvedProvider {
            id: "openai".to_string(),
            detection_id: None,
            name: "OpenAI".to_string(),
            entry_type: EntryType::Mcp,
            api_format: None,
            domains: vec!["api.openai.com".to_string()],
            user_agent_patterns: Vec::new(),
            detection: None,
        },
    )]);
    bundle.providers = providers;
    bundle.domain_index = vec![DomainIndexEntry {
        host: "api.openai.com".to_string(),
        provider_id: "openai".to_string(),
        entry_type: EntryType::AiInference,
        paths: Vec::new(),
    }];
    let engine = OispEngine::new(bundle).unwrap();
    let class = engine.classify("api.openai.com").unwrap();
    assert_eq!(class.entry_type, EntryType::Mcp);
}

#[test]
fn calculate_cost_uses_provider_hint_and_prefix_model_match() {
    let engine = OispEngine::new(parse_compiled_bundle(&json!({
            "version": "v1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "local",
            "domain_index": [
                { "host": "chatgpt.com", "provider_id": "chatgpt", "entry_type": "agent-app" }
            ],
            "providers": {
                "chatgpt": { "id": "chatgpt", "name": "ChatGPT", "type": "agent-app", "api_format": "openai" }
            },
            "filters": {},
            "pricing": {
                "openai": {
                    "gpt-5.3-codex": {
                        "input_per_million_usd": 2.0,
                        "output_per_million_usd": 8.0
                    }
                }
            }
        })).unwrap()).unwrap();

    let cost = engine.calculate_cost(
        &["chatgpt", "openai"],
        "gpt-5.3-codex-2026-02-01",
        1_000_000,
        500_000,
        None,
        None,
    );
    assert!(cost.is_some());
    assert!((cost.unwrap() - 6.0).abs() < 1e-9);
}

#[test]
fn evaluate_detection_prefers_model_rule_with_detection_id() {
    let engine = OispEngine::new(
        parse_compiled_bundle(&json!({
            "schema_version": 3,
            "version": "v1",
            "compiled_at": "2026-02-16T00:00:00Z",
            "bundle_type": "local",
            "domain_index": [
                { "host": "chatgpt.com", "provider_id": "chatgpt", "entry_type": "agent-app" }
            ],
            "providers": {
                "chatgpt": {
                    "id": "chatgpt",
                    "detection_id": "agt_abc123",
                    "name": "ChatGPT",
                    "type": "agent-app",
                    "api_format": "openai",
                    "detection": {
                        "ua_rules": [
                            {
                                "id": "ua-1",
                                "reason": "ua_match",
                                "confidence": 0.80,
                                "agent": "chatgpt",
                                "contains": "chatgpt"
                            }
                        ],
                        "model_rules": [
                            {
                                "id": "model-1",
                                "reason": "model_match",
                                "confidence": 0.99,
                                "priority": 10,
                                "agent": "codex",
                                "model": "*codex*"
                            }
                        ]
                    }
                }
            },
            "filters": {},
            "pricing": {}
        }))
        .unwrap(),
    )
    .unwrap();

    let outcome = engine
        .evaluate_detection(
            "chatgpt",
            &DetectionContext {
                host: Some("chatgpt.com".to_string()),
                user_agent: Some("chatgpt desktop".to_string()),
                model: Some("gpt-5.3-codex".to_string()),
                ..DetectionContext::default()
            },
        )
        .expect("outcome");

    assert_eq!(outcome.agent.as_deref(), Some("codex"));
    assert_eq!(outcome.detection_reason, "model_match");
    assert!((outcome.parse_confidence - 0.99).abs() < 1e-9);
    assert_eq!(outcome.detection_id.as_deref(), Some("agt_abc123"));
}

#[test]
fn evaluate_detection_is_deterministic_for_same_context() {
    let engine = OispEngine::new(
        parse_compiled_bundle(&json!({
            "schema_version": 3,
            "version": "v1",
            "compiled_at": "2026-02-16T00:00:00Z",
            "bundle_type": "local",
            "domain_index": [
                { "host": "chatgpt.com", "provider_id": "chatgpt", "entry_type": "agent-app" }
            ],
            "providers": {
                "chatgpt": {
                    "id": "chatgpt",
                    "detection_id": "agt_abc123",
                    "name": "ChatGPT",
                    "type": "agent-app",
                    "api_format": "openai",
                    "detection": {
                        "ua_rules": [
                            {
                                "id": "z-rule",
                                "reason": "ua_match",
                                "confidence": 0.90,
                                "agent": "chatgpt",
                                "contains": "desktop"
                            },
                            {
                                "id": "a-rule",
                                "reason": "ua_match",
                                "confidence": 0.90,
                                "agent": "codex",
                                "contains": "desktop"
                            }
                        ]
                    }
                }
            },
            "filters": {},
            "pricing": {}
        }))
        .unwrap(),
    )
    .unwrap();

    let context = DetectionContext {
        host: Some("chatgpt.com".to_string()),
        user_agent: Some("chatgpt desktop".to_string()),
        ..DetectionContext::default()
    };

    let first = engine
        .evaluate_detection("chatgpt", &context)
        .expect("first outcome");
    let second = engine
        .evaluate_detection("chatgpt", &context)
        .expect("second outcome");

    assert_eq!(first, second);
    assert_eq!(first.agent.as_deref(), Some("codex"));
    assert_eq!(first.detection_reason, "ua_match");
    assert_eq!(first.detection_id.as_deref(), Some("agt_abc123"));
}

#[test]
fn evaluate_detection_rules_only_returns_none_without_match() {
    let engine = OispEngine::new(
        parse_compiled_bundle(&json!({
            "schema_version": 3,
            "version": "v1",
            "compiled_at": "2026-02-16T00:00:00Z",
            "bundle_type": "local",
            "domain_index": [
                { "host": "chatgpt.com", "provider_id": "chatgpt", "entry_type": "agent-app" }
            ],
            "providers": {
                "chatgpt": {
                    "id": "chatgpt",
                    "detection_id": "agt_abc123",
                    "name": "ChatGPT",
                    "type": "agent-app",
                    "api_format": "openai",
                    "detection": {
                        "ua_rules": [
                            {
                                "id": "ua-chatgpt",
                                "reason": "ua_match",
                                "confidence": 0.90,
                                "agent": "chatgpt",
                                "contains": "chatgpt"
                            }
                        ]
                    }
                }
            },
            "filters": {},
            "pricing": {}
        }))
        .unwrap(),
    )
    .unwrap();

    let context = DetectionContext {
        user_agent: Some("unknown-client".to_string()),
        ..DetectionContext::default()
    };

    assert!(engine
        .evaluate_detection_rules_only("chatgpt", &context)
        .is_none());
}

#[test]
fn evaluate_detection_across_entry_types_prefers_highest_confidence_rule() {
    let engine = OispEngine::new(
        parse_compiled_bundle(&json!({
            "schema_version": 3,
            "version": "v1",
            "compiled_at": "2026-02-16T00:00:00Z",
            "bundle_type": "local",
            "domain_index": [
                { "host": "chatgpt.com", "provider_id": "chatgpt", "entry_type": "agent-app" },
                { "host": "claude.ai", "provider_id": "claude", "entry_type": "agent-app" }
            ],
            "providers": {
                "chatgpt": {
                    "id": "chatgpt",
                    "detection_id": "agt_chatgpt",
                    "name": "ChatGPT",
                    "type": "agent-app",
                    "api_format": "openai",
                    "detection": {
                        "ua_rules": [
                            {
                                "id": "ua-chatgpt",
                                "reason": "ua_match",
                                "confidence": 0.91,
                                "agent": "chatgpt",
                                "contains": "assistant-client"
                            }
                        ]
                    }
                },
                "claude": {
                    "id": "claude",
                    "detection_id": "agt_claude",
                    "name": "Claude",
                    "type": "agent-app",
                    "api_format": "anthropic",
                    "detection": {
                        "ua_rules": [
                            {
                                "id": "ua-claude",
                                "reason": "ua_match",
                                "confidence": 0.97,
                                "agent": "claude",
                                "contains": "assistant-client"
                            }
                        ]
                    }
                }
            },
            "filters": {},
            "pricing": {}
        }))
        .unwrap(),
    )
    .unwrap();

    let context = DetectionContext {
        user_agent: Some("assistant-client/1.0".to_string()),
        ..DetectionContext::default()
    };

    let outcome = engine
        .evaluate_detection_across_entry_types(&context, &[EntryType::AgentApp])
        .expect("detection outcome");
    assert_eq!(outcome.provider_id, "claude");
    assert_eq!(outcome.entry_type, EntryType::AgentApp);
    assert_eq!(outcome.outcome.agent.as_deref(), Some("claude"));
    assert!((outcome.outcome.parse_confidence - 0.97).abs() < 1e-9);
    assert_eq!(outcome.outcome.detection_id.as_deref(), Some("agt_claude"));
}

#[test]
fn load_from_registry_cache_accepts_catalog_registry_shape() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("registry_bundle_cache.json");
    let envelope = json!({
        "fetched_at": "2026-02-13T00:00:00Z",
        "etag": "etag-1",
        "metadata": {
            "bundle_type": "local",
            "version": "catalog-v1",
            "sha256": "abc",
            "compiled_at": "2026-02-13T00:00:00Z",
            "provider_count": 1,
            "domain_count": 1,
            "format_count": 1,
            "size_bytes": 123
        },
        "bundle": {
            "schema_version": 2,
            "version": "catalog-v1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "local",
            "domain_index": {
                "api.openai.com": {
                    "category": "ai-inference",
                    "pattern_type": "exact",
                    "provider": "openai"
                }
            },
            "providers": {
                "openai": {
                    "name": "OpenAI",
                    "category": "ai-inference",
                    "api_format": "openai",
                    "api_domains": ["api.openai.com"],
                    "detection": {
                        "path_patterns": ["/v1/chat/completions"]
                    }
                }
            },
            "interception_patterns": {
                "api.openai.com": [
                    { "action": "intercept", "path": "/v1/chat/completions" }
                ]
            },
            "noise_filter": { "words": [], "paths": [] },
            "passthrough": { "domains": [], "patterns": [] },
            "filters": {
                "whitelist": ["api.openai.com"],
                "blacklist": [],
                "passthrough": [],
                "noise_keywords": []
            },
            "pricing": {
                "openai": [
                    {
                        "model_pattern": "gpt-5",
                        "input_per_million": 1.0,
                        "output_per_million": 2.0
                    }
                ]
            }
        }
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();

    let engine = OispEngine::load_from_registry_cache(&path)
        .unwrap()
        .unwrap();
    assert_eq!(engine.bundle_version(), "catalog-v1");
    assert_eq!(
        engine.should_intercept("api.openai.com", "/v1/chat/completions"),
        InterceptDecision::Intercept {
            provider_id: "openai".to_string(),
            entry_type: EntryType::AiInference
        }
    );
    let cost = engine.calculate_cost(&["openai"], "gpt-5", 1_000_000, 1_000_000, None, None);
    assert_eq!(cost, Some(3.0));
}

#[test]
fn load_from_registry_cache_falls_back_to_last_good_when_primary_invalid() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("registry_bundle_cache.json");
    let valid_envelope = json!({
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
        "bundle": sample_bundle()
    });
    let fallback_path = path
        .parent()
        .unwrap()
        .join("registry_bundle_cache.json.last_good");
    std::fs::write(
        &fallback_path,
        serde_json::to_vec_pretty(&valid_envelope).unwrap(),
    )
    .unwrap();

    let invalid_primary = json!({
        "schema_version": 1,
        "fetched_at": "2026-02-13T00:00:00Z",
        "etag": "etag-bad",
        "metadata": {
            "bundle_type": "local",
            "version": "bad-v1",
            "sha256": "bad",
            "compiled_at": "2026-02-13T00:00:00Z",
            "provider_count": 0,
            "domain_count": 0,
            "format_count": 1,
            "size_bytes": 123
        },
        "bundle": { "version": "bad-v1" }
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&invalid_primary).unwrap()).unwrap();

    let engine = OispEngine::load_from_registry_cache(&path)
        .unwrap()
        .unwrap();

    assert_eq!(
        engine.should_intercept("api.openai.com", "/v1/chat/completions"),
        InterceptDecision::Intercept {
            provider_id: "openai".to_string(),
            entry_type: EntryType::AiInference
        }
    );
    assert_eq!(engine.bundle_version(), "v1");
}
