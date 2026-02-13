//! Host/domain-based provider and agent attribution for proxy traffic.
//!
//! These heuristics are only used as fallback context hints. Primary
//! classification should come from the OISP bundle-driven engine.

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
    let host = lower_host(host);
    host_eq_or_subdomain(&host, "chatgpt.com") || host_eq_or_subdomain(&host, "chat.openai.com")
}

pub fn is_gemini_web_host(host: &str) -> bool {
    let host = lower_host(host);
    host_eq_or_subdomain(&host, "gemini.google.com")
}

pub fn is_claude_web_host(host: &str) -> bool {
    let host = lower_host(host);
    if !(host == "claude.ai" || host.ends_with(".claude.ai")) {
        return false;
    }
    !host.starts_with("api.") && !host.contains(".api.")
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
    if allow_host_inference && is_chatgpt_web_host(host) && is_codex_path(path) {
        return Some("codex");
    }

    if let Some(model_name) = model {
        if is_codex_model(model_name) {
            return Some("codex");
        }
    }

    if allow_host_inference {
        if let Some(agent) = detect_agent_app_host(host) {
            return Some(agent);
        }
    }

    ua_agent
}

fn host_eq_or_subdomain(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

fn lower_host(host: &str) -> String {
    host.trim().to_ascii_lowercase()
}

fn is_cursor_host(host: &str) -> bool {
    host == "api2.cursor.sh" || host == "api3.cursor.sh" || host.ends_with(".cursor.sh")
}

fn is_copilot_host(host: &str) -> bool {
    host_eq_or_subdomain(host, "githubcopilot.com") || host == "copilot-proxy.githubusercontent.com"
}

fn is_windsurf_host(host: &str) -> bool {
    host == "server.codeium.com" || host_eq_or_subdomain(host, "codeium.com")
}

fn is_zed_host(host: &str) -> bool {
    host == "cloud.zed.dev" || host_eq_or_subdomain(host, "zed.dev")
}

fn is_junie_host(host: &str) -> bool {
    host == "api.jetbrains.ai" || host_eq_or_subdomain(host, "jetbrains.ai")
}

fn is_amazon_q_host(host: &str) -> bool {
    (host.starts_with("codewhisperer.") || host.contains(".codewhisperer."))
        && host.ends_with(".amazonaws.com")
}

fn is_claude_agent_edge_host(host: &str) -> bool {
    host == "a-api.anthropic.com"
        || host.ends_with(".a-api.anthropic.com")
        || host == "a-cdn.anthropic.com"
        || host.ends_with(".a-cdn.anthropic.com")
        || host == "s-cdn.anthropic.com"
        || host.ends_with(".s-cdn.anthropic.com")
}

fn detect_agent_app_host(host: &str) -> Option<&'static str> {
    let host = lower_host(host);
    if is_chatgpt_web_host(&host) {
        Some("chatgpt")
    } else if is_gemini_web_host(&host) {
        Some("gemini")
    } else if is_claude_web_host(&host) || is_claude_agent_edge_host(&host) {
        Some("claude")
    } else if is_cursor_host(&host) {
        Some("cursor")
    } else if is_copilot_host(&host) {
        Some("github-copilot")
    } else if is_windsurf_host(&host) {
        Some("windsurf")
    } else if is_zed_host(&host) {
        Some("zed")
    } else if is_junie_host(&host) {
        Some("junie")
    } else if is_amazon_q_host(&host) {
        Some("amazon-q")
    } else if host == "statsig.anthropic.com" {
        Some("claude-code")
    } else if host.contains("perplexity.ai") && !host.starts_with("api.") && !host.contains(".api.")
    {
        Some("perplexity")
    } else if host.contains("aistudio.google.com") || host.contains("makersuite.google.com") {
        Some("aistudio")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_path_detection_catches_known_routes() {
        assert!(is_codex_path("/backend-api/codex/responses"));
        assert!(is_codex_path("/codex/run"));
        assert!(!is_codex_path("/backend-api/f/conversation"));
    }
}
