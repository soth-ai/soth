use serde_json::json;
use soth_oisp::types::bundle::parse_compiled_bundle;
use soth_oisp::{DetectionContext, OispEngine};
use std::time::Instant;

fn sample_contexts() -> Vec<DetectionContext> {
    vec![
        DetectionContext {
            host: Some("chatgpt.com".to_string()),
            path: Some("/backend-api/codex/responses".to_string()),
            user_agent: Some("openai-codex/1.0".to_string()),
            model: Some("gpt-5.3-codex".to_string()),
            process_name: Some("codex".to_string()),
            bundle_id: None,
            client_name: Some("codex".to_string()),
            client_version: Some("1.0.0".to_string()),
            env_keys: vec!["OPENAI_API_KEY".to_string()],
        },
        DetectionContext {
            host: Some("api.anthropic.com".to_string()),
            path: Some("/v1/messages".to_string()),
            user_agent: Some("claude-code".to_string()),
            model: Some("claude-opus-4-6".to_string()),
            process_name: Some("claude".to_string()),
            bundle_id: None,
            client_name: Some("claude".to_string()),
            client_version: Some("1.2.3".to_string()),
            env_keys: vec!["ANTHROPIC_API_KEY".to_string()],
        },
        DetectionContext {
            host: Some("ws.chatgpt.com".to_string()),
            path: Some("/c2/ws/user/user-123".to_string()),
            user_agent: Some("chatgpt".to_string()),
            model: None,
            process_name: Some("chatgpt".to_string()),
            bundle_id: None,
            client_name: Some("chatgpt".to_string()),
            client_version: None,
            env_keys: vec!["HTTP_PROXY".to_string(), "HTTPS_PROXY".to_string()],
        },
    ]
}

fn sample_engine() -> OispEngine {
    OispEngine::new(
        parse_compiled_bundle(&json!({
            "version": "perf-v1",
            "compiled_at": "2026-02-15T00:00:00Z",
            "bundle_type": "cloud",
            "domain_index": [
                { "host": "chatgpt.com", "provider_id": "chatgpt", "entry_type": "agent-app" },
                { "host": "ws.chatgpt.com", "provider_id": "chatgpt", "entry_type": "agent-app" },
                { "host": "api.anthropic.com", "provider_id": "anthropic", "entry_type": "ai-inference" }
            ],
            "providers": {
                "chatgpt": {
                    "id": "chatgpt",
                    "name": "ChatGPT",
                    "type": "agent-app",
                    "detection": {
                        "ua_rules": [
                            { "id": "chatgpt_ua", "agent": "chatgpt", "reason": "ua", "confidence": 0.8, "contains": "chatgpt" }
                        ],
                        "path_rules": [
                            { "id": "codex_path", "agent": "codex", "reason": "path", "confidence": 0.96, "path": "/backend-api/codex/*" }
                        ]
                    }
                },
                "anthropic": {
                    "id": "anthropic",
                    "name": "Anthropic",
                    "type": "ai-inference",
                    "detection": {
                        "ua_rules": [
                            { "id": "claude_ua", "agent": "claude", "reason": "ua", "confidence": 0.85, "contains": "claude" }
                        ]
                    }
                }
            },
            "filters": {},
            "pricing": {}
        }))
        .expect("valid detection benchmark bundle"),
    )
    .expect("engine should build for benchmark")
}

#[test]
#[ignore = "manual benchmark; run explicitly when tuning detection path"]
fn benchmark_detection_cache_hot_path() {
    let engine = sample_engine();
    let contexts = sample_contexts();
    let rounds = 50_000usize;

    let t1 = Instant::now();
    for idx in 0..rounds {
        let context = &contexts[idx % contexts.len()];
        let host = context.host.as_deref().unwrap_or("chatgpt.com");
        let provider = engine
            .classify(host)
            .map(|classification| classification.provider_id)
            .unwrap_or_else(|| "chatgpt".to_string());
        let _ = engine.evaluate_detection(provider.as_str(), context);
    }
    let coldish = t1.elapsed();

    let t2 = Instant::now();
    for idx in 0..rounds {
        let context = &contexts[idx % contexts.len()];
        let host = context.host.as_deref().unwrap_or("chatgpt.com");
        let provider = engine
            .classify(host)
            .map(|classification| classification.provider_id)
            .unwrap_or_else(|| "chatgpt".to_string());
        let _ = engine.evaluate_detection(provider.as_str(), context);
    }
    let warm = t2.elapsed();

    eprintln!(
        "detection bench rounds={} pass1_ms={} pass2_ms={}",
        rounds,
        coldish.as_millis(),
        warm.as_millis()
    );

    // Keep this robust across machines; second pass should not regress badly.
    assert!(
        warm <= coldish.mul_f64(3.0),
        "unexpected regression: warm={warm:?} coldish={coldish:?}"
    );
}
