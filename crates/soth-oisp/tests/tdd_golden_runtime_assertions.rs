use std::fs;
use std::path::PathBuf;

use serde_json::{json, Value};
use soth_oisp::types::bundle::parse_compiled_bundle;
use soth_oisp::{ConnectDecisionAction, OispEngine, RequestDecisionOutcome};

fn category_from_detection_id(detection_id: Option<&str>) -> &'static str {
    match detection_id.unwrap_or_default() {
        value if value.starts_with("agent.") => "agent-app",
        value if value.starts_with("mcp.") => "mcp",
        _ => "ai-inference",
    }
}

fn normalize_fixture_for_oisp_parser(mut value: Value) -> Value {
    let Some(root) = value.as_object_mut() else {
        return value;
    };

    let mut required_provider_ids: Vec<String> = Vec::new();
    if let Some(domain_index) = root
        .get("core")
        .and_then(|value| value.get("domain_index"))
        .and_then(Value::as_array)
    {
        for entry in domain_index {
            if let Some(provider_id) = entry.get("provider_id").and_then(Value::as_str) {
                required_provider_ids.push(provider_id.to_string());
            }
        }
    }
    if let Some(rules) = root
        .get("decision_rules")
        .and_then(|value| value.get("rules"))
        .and_then(Value::as_array)
    {
        for rule in rules {
            if let Some(provider_id) = rule.get("provider").and_then(Value::as_str) {
                required_provider_ids.push(provider_id.to_string());
            }
        }
    }

    required_provider_ids.sort();
    required_provider_ids.dedup();

    let domain_index = root
        .get("core")
        .and_then(|value| value.get("domain_index"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let rules = root
        .get("decision_rules")
        .and_then(|value| value.get("rules"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let Some(core) = root.get_mut("core").and_then(Value::as_object_mut) else {
        return value;
    };
    let Some(providers) = core.get_mut("providers").and_then(Value::as_object_mut) else {
        return value;
    };

    for provider_id in required_provider_ids {
        if providers.contains_key(provider_id.as_str()) {
            continue;
        }

        let hosts: Vec<String> = domain_index
            .iter()
            .filter_map(|entry| {
                let pid = entry.get("provider_id").and_then(Value::as_str)?;
                if pid != provider_id {
                    return None;
                }
                entry
                    .get("host")
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            })
            .collect();

        let detection_id = rules
            .iter()
            .find_map(|rule| {
                let pid = rule.get("provider").and_then(Value::as_str)?;
                if pid != provider_id {
                    return None;
                }
                rule.get("detection_id")
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            })
            .or_else(|| {
                domain_index.iter().find_map(|entry| {
                    let pid = entry.get("provider_id").and_then(Value::as_str)?;
                    if pid != provider_id {
                        return None;
                    }
                    entry
                        .get("detection_id")
                        .and_then(Value::as_str)
                        .map(ToString::to_string)
                })
            });

        providers.insert(
            provider_id.clone(),
            json!({
                "id": provider_id,
                "name": provider_id,
                "category": category_from_detection_id(detection_id.as_deref()),
                "detection_id": detection_id,
                "api_domains": hosts
            }),
        );
    }

    value
}

fn load_golden_engine() -> OispEngine {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/TDD_GOLDEN_FINAL_BUNDLE.json");
    let raw = fs::read_to_string(path).expect("read TDD_GOLDEN_FINAL_BUNDLE.json");
    let value: Value = serde_json::from_str(&raw).expect("parse golden bundle json");
    let value = normalize_fixture_for_oisp_parser(value);
    let bundle = parse_compiled_bundle(&value).expect("parse compiled bundle");
    OispEngine::new(bundle).expect("build oisp engine")
}

#[test]
fn runtime_connect_assertions_match_golden_fixture() {
    let engine = load_golden_engine();

    let r001 = engine.evaluate_connect_decision(
        "api.anthropic.com",
        Some("com.anthropic.claudefordesktop"),
        Some("non_host"),
    );
    assert_eq!(r001.action, ConnectDecisionAction::Intercept);
    assert_eq!(
        r001.rule_id.as_deref(),
        Some("connect.non_host.claude_desktop.api_anthropic")
    );

    let r002 = engine.evaluate_connect_decision("chatgpt.com", Some("unknown"), Some("unknown"));
    assert_eq!(r002.action, ConnectDecisionAction::Intercept);
    assert_eq!(
        r002.reason.as_deref(),
        Some("whitelisted_unknown_app_action")
    );

    let r003 = engine.evaluate_connect_decision("ab.chatgpt.com", Some("unknown"), Some("unknown"));
    assert_eq!(r003.action, ConnectDecisionAction::Passthrough);
}

#[test]
fn runtime_request_assertions_match_golden_fixture() {
    let engine = load_golden_engine();

    let r101 = engine.evaluate_request_decision(
        "api.anthropic.com",
        "/v1/messages/count",
        Some("POST"),
        Some("non_host"),
    );
    assert_eq!(r101.outcome, RequestDecisionOutcome::MetadataOnly);
    assert_eq!(
        r101.rule_id.as_deref(),
        Some("rule.non_host.agent.claude.app.api.anthropic.com.v1.messages")
    );
    assert_eq!(r101.reason.as_deref(), Some("deny_paths_exact"));

    let r102 = engine.evaluate_request_decision(
        "api.anthropic.com",
        "/v1/messages",
        Some("POST"),
        Some("non_host"),
    );
    assert_eq!(r102.outcome, RequestDecisionOutcome::Full);
    assert_eq!(r102.detection_id.as_deref(), Some("agent.claude.app"));
    assert_eq!(r102.provider_id.as_deref(), Some("claude"));

    let r103 = engine.evaluate_request_decision(
        "api.anthropic.com",
        "/v1/messages",
        Some("POST"),
        Some("host"),
    );
    assert_eq!(r103.outcome, RequestDecisionOutcome::Full);
    assert_eq!(r103.detection_id.as_deref(), Some("ai.anthropic.service"));
    assert_eq!(r103.provider_id.as_deref(), Some("anthropic"));

    let r104 = engine.evaluate_request_decision(
        "openrouter.ai",
        "/api/v1/responses",
        Some("POST"),
        Some("unknown"),
    );
    assert_eq!(r104.outcome, RequestDecisionOutcome::Full);
    assert_eq!(r104.detection_id.as_deref(), Some("ai.openrouter.service"));
    assert_eq!(r104.provider_id.as_deref(), Some("openrouter"));

    let r105 = engine.evaluate_request_decision(
        "chatgpt.com",
        "/backend-api/wham/usage",
        Some("GET"),
        Some("unknown"),
    );
    assert_eq!(r105.outcome, RequestDecisionOutcome::MetadataOnly);
    assert_eq!(r105.reason.as_deref(), Some("whitelist_path_miss"));
}
