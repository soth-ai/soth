//! Host/domain-based provider and agent attribution for proxy traffic.
//!
//! This module centralizes host/path/model fingerprinting used by the
//! hudsucker transport hot path.

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
    host.contains("chatgpt.com") || host == "chat.openai.com" || host.ends_with(".chat.openai.com")
}

pub fn is_claude_web_host(host: &str) -> bool {
    if !(host == "claude.ai" || host.ends_with(".claude.ai")) {
        return false;
    }
    !host.starts_with("api.") && !host.contains(".api.")
}

fn is_cursor_host(host: &str) -> bool {
    host == "api2.cursor.sh" || host == "api3.cursor.sh" || host.ends_with(".cursor.sh")
}

fn is_copilot_host(host: &str) -> bool {
    host.contains("githubcopilot.com") || host == "copilot-proxy.githubusercontent.com"
}

fn is_windsurf_host(host: &str) -> bool {
    host == "server.codeium.com" || host.ends_with(".codeium.com")
}

fn is_zed_host(host: &str) -> bool {
    host == "cloud.zed.dev" || host.ends_with(".zed.dev")
}

fn is_junie_host(host: &str) -> bool {
    host == "api.jetbrains.ai" || host.ends_with(".jetbrains.ai")
}

fn is_amazon_q_host(host: &str) -> bool {
    (host.starts_with("codewhisperer.") || host.contains(".codewhisperer."))
        && host.ends_with(".amazonaws.com")
}

fn is_claude_code_host(host: &str) -> bool {
    host == "statsig.anthropic.com"
}

/// Apply host/path/model heuristics to derive the final agent tag.
/// This upgrades generic OpenAI/ChatGPT tags to `codex` when context proves it.
pub fn detect_agent_with_context(
    ua_agent: Option<&'static str>,
    host: &str,
    path: &str,
    model: Option<&str>,
) -> Option<&'static str> {
    let host_lower = host.to_ascii_lowercase();
    let is_chatgpt_web = is_chatgpt_web_host(&host_lower);
    let is_claude_web = is_claude_web_host(&host_lower);

    if is_chatgpt_web && is_codex_path(path) {
        return Some("codex");
    }

    if let Some(model_name) = model {
        if is_codex_model(model_name) {
            return Some("codex");
        }
    }

    if is_cursor_host(&host_lower) {
        return Some("cursor");
    }
    if is_copilot_host(&host_lower) {
        return Some("github-copilot");
    }
    if is_windsurf_host(&host_lower) {
        return Some("windsurf");
    }
    if is_zed_host(&host_lower) {
        return Some("zed");
    }
    if is_junie_host(&host_lower) {
        return Some("junie");
    }
    if is_amazon_q_host(&host_lower) {
        return Some("amazon-q");
    }
    if is_claude_code_host(&host_lower) {
        return Some("claude-code");
    }

    if ua_agent.is_none() && is_chatgpt_web {
        return Some("chatgpt");
    }
    if ua_agent.is_none() && is_claude_web {
        return Some("claude");
    }

    ua_agent
}

/// Detect AI provider from host.
pub fn detect_provider(host: &str) -> Option<&'static str> {
    let host = host.to_ascii_lowercase();

    // ChatGPT web/agent surfaces
    if is_chatgpt_web_host(&host) {
        Some("chatgpt")
    // Claude web/agent surfaces
    } else if is_claude_web_host(&host) {
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
    // OpenAI API inference endpoints
    } else if host == "api.openai.com"
        || host.ends_with(".api.openai.com")
        || host.contains("openai.azure.com")
    {
        Some("openai")
    // Anthropic inference endpoints
    } else if host == "api.claude.ai"
        || host.ends_with(".api.claude.ai")
        || host == "api.anthropic.com"
        || host.ends_with(".api.anthropic.com")
        || host.contains("anthropic.com")
    {
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

/// Check if host is an agent app (end-user application) vs direct API.
/// Agent apps: chatgpt.com, claude.ai, editor-integrated coding agents.
pub fn is_agent_app(host: &str) -> bool {
    let host = host.to_ascii_lowercase();

    // OpenAI/ChatGPT web apps (chat.openai.com, chatgpt.com)
    // Exclude api.openai.com which is direct API.
    if is_chatgpt_web_host(&host) {
        return true;
    }

    // Claude web/desktop app (claude.ai).
    if is_claude_web_host(&host) {
        return true;
    }

    if is_cursor_host(&host)
        || is_copilot_host(&host)
        || is_windsurf_host(&host)
        || is_zed_host(&host)
        || is_junie_host(&host)
        || is_amazon_q_host(&host)
        || is_claude_code_host(&host)
    {
        return true;
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
