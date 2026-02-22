//! Agent name canonicalization for wrap sessions.

/// Canonicalize arbitrary agent labels to the naming convention used by wrap detection.
pub fn canonicalize_agent_name(raw: &str) -> String {
    normalize_agent_name(raw)
}

fn normalize_agent_name(raw: &str) -> String {
    let lower = raw.to_lowercase();

    if lower.contains("codex") {
        return "Codex".to_string();
    }

    if lower.contains("chatgpt") {
        return "ChatGPT".to_string();
    }

    if lower.contains("claude") {
        if lower.contains("desktop") {
            return "Claude Desktop".to_string();
        }
        if lower.contains("code") || lower.contains("cli") {
            return "Claude Code".to_string();
        }
        if lower.contains("android") || lower.contains("ios") || lower.contains("mobile") {
            return "Claude Mobile".to_string();
        }
        return "Claude".to_string();
    }

    if lower.contains("cursor") {
        return "Cursor".to_string();
    }

    if lower.contains("windsurf") || lower.contains("codeium") {
        return "Windsurf".to_string();
    }

    if lower.contains("zed") {
        return "Zed".to_string();
    }

    if lower.contains("vscode") || lower.contains("visual studio code") {
        return "VS Code".to_string();
    }

    if lower.contains("copilot") {
        return "GitHub Copilot".to_string();
    }

    if lower.contains("continue") {
        return "Continue".to_string();
    }

    if lower.contains("aider") {
        return "Aider".to_string();
    }

    raw.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_agent_name() {
        assert_eq!(normalize_agent_name("OpenAI Codex"), "Codex");
        assert_eq!(normalize_agent_name("chatgpt-desktop"), "ChatGPT");
        assert_eq!(normalize_agent_name("Claude Desktop"), "Claude Desktop");
        assert_eq!(normalize_agent_name("claude-desktop"), "Claude Desktop");
        assert_eq!(normalize_agent_name("Claude Code"), "Claude Code");
        assert_eq!(normalize_agent_name("claude-cli"), "Claude Code");
        assert_eq!(normalize_agent_name("Cursor"), "Cursor");
        assert_eq!(normalize_agent_name("cursor-ai"), "Cursor");
        assert_eq!(normalize_agent_name("Windsurf"), "Windsurf");
        assert_eq!(normalize_agent_name("codeium"), "Windsurf");
        assert_eq!(normalize_agent_name("unknown-client"), "unknown-client");
    }
}
