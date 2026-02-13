//! Host/domain-based provider and agent attribution for proxy traffic.
//!
//! Attribution now delegates to `soth-registry` so detection signatures are
//! centralized and reusable across runtime surfaces.

use soth_registry as registry;

pub fn is_codex_path(path: &str) -> bool {
    let path_lower = path.to_ascii_lowercase();
    path_lower.contains("/backend-api/codex/")
        || path_lower.starts_with("/codex")
        || path_lower.contains("/codex/")
}

pub fn is_codex_model(model: &str) -> bool {
    model.to_ascii_lowercase().contains("codex")
}

pub fn is_chatgpt_web_host(host: &str) -> bool {
    registry::is_chatgpt_web_host(host)
}

pub fn is_gemini_web_host(host: &str) -> bool {
    registry::is_gemini_web_host(host)
}

pub fn is_claude_web_host(host: &str) -> bool {
    registry::is_claude_web_host(host)
}

/// Apply host/path/model heuristics to derive the final agent tag.
/// This upgrades generic OpenAI/ChatGPT tags to `codex` when context proves it.
pub fn detect_agent_with_context(
    ua_agent: Option<&'static str>,
    host: &str,
    path: &str,
    model: Option<&str>,
) -> Option<&'static str> {
    detect_agent_with_context_gated(ua_agent, host, path, model, true)
}

/// Same as `detect_agent_with_context`, but allows the caller to disable
/// host-driven inference when a host is not in configured agent-app domains.
pub fn detect_agent_with_context_gated(
    ua_agent: Option<&'static str>,
    host: &str,
    path: &str,
    model: Option<&str>,
    allow_host_inference: bool,
) -> Option<&'static str> {
    if allow_host_inference && registry::is_chatgpt_web_host(host) && is_codex_path(path) {
        return Some("codex");
    }

    if let Some(model_name) = model {
        if is_codex_model(model_name) {
            return Some("codex");
        }
    }

    if allow_host_inference {
        if let Some(agent) = registry::detect_agent_app(host) {
            return Some(agent);
        }
    }

    ua_agent
}

/// Detect AI provider from host.
pub fn detect_provider(host: &str) -> Option<&'static str> {
    registry::detect_provider(host)
}

/// Check if host is an agent app (end-user application) vs direct API.
pub fn is_agent_app(host: &str) -> bool {
    registry::is_agent_app(host)
}

/// Compute legacy detection class from configured host classes.
pub fn legacy_detection_class(
    host_is_ai_target: bool,
    host_is_mcp_target: bool,
    host_is_agent_target: bool,
) -> &'static str {
    if host_is_mcp_target {
        "mcp"
    } else if host_is_agent_target {
        "agent_app"
    } else if host_is_ai_target {
        "ai_inference"
    } else {
        "unknown"
    }
}

/// Return true when legacy host-class detection and registry entry type disagree.
pub fn detection_shadow_mismatch(legacy_class: &str, registry_entry_type: Option<&str>) -> bool {
    let registry_class = registry_entry_type.unwrap_or("unknown");
    legacy_class != registry_class
}

/// Return true when legacy provider tag and registry provider tag disagree.
pub fn provider_shadow_mismatch(
    legacy_provider: Option<&str>,
    registry_provider: Option<&str>,
) -> bool {
    normalize_provider_label(legacy_provider) != normalize_provider_label(registry_provider)
}

fn normalize_provider_label(provider: Option<&str>) -> &str {
    match provider.unwrap_or("unknown").trim() {
        "" => "unknown",
        value => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_detection_class_priority_is_stable() {
        assert_eq!(legacy_detection_class(true, true, true), "mcp");
        assert_eq!(legacy_detection_class(true, false, true), "agent_app");
        assert_eq!(legacy_detection_class(true, false, false), "ai_inference");
        assert_eq!(legacy_detection_class(false, false, false), "unknown");
    }

    #[test]
    fn detection_shadow_mismatch_compares_classes() {
        assert!(detection_shadow_mismatch("ai_inference", Some("agent_app")));
        assert!(!detection_shadow_mismatch("mcp", Some("mcp")));
        assert!(!detection_shadow_mismatch("unknown", None));
    }

    #[test]
    fn provider_shadow_mismatch_normalizes_missing_values() {
        assert!(!provider_shadow_mismatch(None, Some("unknown")));
        assert!(!provider_shadow_mismatch(Some(""), None));
        assert!(provider_shadow_mismatch(Some("chatgpt"), Some("anthropic")));
    }
}
