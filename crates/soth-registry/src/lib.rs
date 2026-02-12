//! Structured host/model detection registry.
//!
//! This crate centralizes provider and agent-app attribution logic so transport
//! layers can rely on one data plane instead of hardcoded per-module heuristics.

fn host_eq_or_subdomain(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

fn lower_host(host: &str) -> String {
    host.trim().to_ascii_lowercase()
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

pub fn is_claude_agent_edge_host(host: &str) -> bool {
    let host = lower_host(host);
    host == "a-api.anthropic.com"
        || host.ends_with(".a-api.anthropic.com")
        || host == "a-cdn.anthropic.com"
        || host.ends_with(".a-cdn.anthropic.com")
        || host == "s-cdn.anthropic.com"
        || host.ends_with(".s-cdn.anthropic.com")
}

pub fn is_claude_api_host(host: &str) -> bool {
    let host = lower_host(host);
    host == "api.claude.ai"
        || host.ends_with(".api.claude.ai")
        || host == "api.anthropic.com"
        || host.ends_with(".api.anthropic.com")
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

fn is_claude_code_host(host: &str) -> bool {
    host == "statsig.anthropic.com"
}

pub fn detect_provider(host: &str) -> Option<&'static str> {
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
    } else if is_claude_code_host(&host) {
        Some("claude-code")
    } else if host == "api.openai.com"
        || host.ends_with(".api.openai.com")
        || host_eq_or_subdomain(&host, "openai.azure.com")
    {
        Some("openai")
    } else if is_claude_api_host(&host) || host == "anthropic.com" {
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

/// Detect end-user agent application identity from host.
pub fn detect_agent_app(host: &str) -> Option<&'static str> {
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
    } else if is_claude_code_host(&host) {
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

pub fn is_agent_app(host: &str) -> bool {
    detect_agent_app(host).is_some()
}

/// Model-based provider hint for unclassified hosts.
pub fn detect_provider_from_model(model: &str) -> Option<&'static str> {
    let model = model.to_ascii_lowercase();
    if model.starts_with("gpt-") || model.starts_with("o1") || model.starts_with("o3") {
        Some("openai")
    } else if model.starts_with("claude-") {
        Some("anthropic")
    } else if model.starts_with("gemini-") {
        Some("google")
    } else if model.starts_with("mistral-") {
        Some("mistral")
    } else if model.starts_with("llama") {
        Some("meta")
    } else {
        None
    }
}

pub fn canonical_inference_host(provider: &str) -> Option<&'static str> {
    match provider.trim().to_ascii_lowercase().as_str() {
        "openai" | "chatgpt" | "codex" | "github-copilot" => Some("api.openai.com"),
        "anthropic" | "claude" | "claude-code" => Some("api.anthropic.com"),
        "google" | "gemini" => Some("generativelanguage.googleapis.com"),
        "cohere" => Some("api.cohere.com"),
        "mistral" => Some("api.mistral.ai"),
        "groq" => Some("api.groq.com"),
        "together" => Some("api.together.xyz"),
        "perplexity" => Some("api.perplexity.ai"),
        "fireworks" => Some("api.fireworks.ai"),
        _ => None,
    }
}

pub fn known_agent_apps() -> &'static [&'static str] {
    &[
        "chatgpt",
        "gemini",
        "claude",
        "cursor",
        "github-copilot",
        "windsurf",
        "zed",
        "junie",
        "amazon-q",
        "claude-code",
        "perplexity",
        "aistudio",
    ]
}

pub fn known_inference_providers() -> &'static [&'static str] {
    &[
        "openai",
        "anthropic",
        "google",
        "cohere",
        "mistral",
        "groq",
        "together",
        "perplexity",
        "replicate",
        "huggingface",
        "fireworks",
        "xai",
        "bedrock",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_api_hosts_are_not_agent_app_hosts() {
        assert!(!is_agent_app("api.anthropic.com"));
        assert!(!is_agent_app("api.claude.ai"));
        assert!(is_agent_app("claude.ai"));
    }

    #[test]
    fn detect_provider_for_core_hosts() {
        assert_eq!(detect_provider("api.openai.com"), Some("openai"));
        assert_eq!(detect_provider("api.anthropic.com"), Some("anthropic"));
        assert_eq!(detect_provider("chatgpt.com"), Some("chatgpt"));
    }

    #[test]
    fn detect_agent_apps_for_known_hosts() {
        assert_eq!(
            detect_agent_app("statsig.anthropic.com"),
            Some("claude-code")
        );
        assert_eq!(detect_agent_app("api2.cursor.sh"), Some("cursor"));
        assert_eq!(detect_agent_app("cloud.zed.dev"), Some("zed"));
    }
}
