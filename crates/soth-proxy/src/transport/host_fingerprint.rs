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
