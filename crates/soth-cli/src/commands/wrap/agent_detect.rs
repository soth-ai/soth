//! Agent detection for wrap sessions
//!
//! Detects which AI agent is using the wrapped MCP server.

use serde_json::Value;
use soth_core::types::{AgentInfo, DetectionSource};

/// Detect agent from MCP initialize message clientInfo
pub fn detect_from_initialize(params: &Value) -> Option<AgentInfo> {
    let client_info = params.get("clientInfo")?;
    let name = client_info.get("name")?.as_str()?;
    let version = client_info
        .get("version")
        .and_then(|v| v.as_str())
        .map(String::from);

    let normalized_name = normalize_agent_name(name);
    let mut agent = AgentInfo::new(normalized_name, DetectionSource::McpInitialize);
    if let Some(v) = version {
        agent = agent.with_version(v);
    }
    Some(agent)
}

/// Canonicalize arbitrary agent labels to the same naming convention used by wrap detection.
pub fn canonicalize_agent_name(raw: &str) -> String {
    normalize_agent_name(raw)
}

/// Detect agent from environment variables
pub fn detect_from_env() -> Option<AgentInfo> {
    // Claude Code
    if std::env::var("CLAUDE_CODE_ENTRY_POINT").is_ok() {
        return Some(
            AgentInfo::new("Claude Code", DetectionSource::Environment).with_version(
                std::env::var("CLAUDE_CODE_VERSION").unwrap_or_else(|_| "unknown".to_string()),
            ),
        );
    }

    // Check for Claude Code session
    if std::env::var("CLAUDE_CODE_SESSION").is_ok() {
        return Some(AgentInfo::new("Claude Code", DetectionSource::Environment));
    }

    // Cursor
    if std::env::var("CURSOR_TRACE_ID").is_ok() || std::env::var("CURSOR_SESSION_ID").is_ok() {
        return Some(AgentInfo::new("Cursor", DetectionSource::Environment));
    }

    // Windsurf / Codeium
    if std::env::var("CODEIUM_API_KEY").is_ok() || std::env::var("WINDSURF_SESSION").is_ok() {
        return Some(AgentInfo::new("Windsurf", DetectionSource::Environment));
    }

    // Zed
    if std::env::var("ZED_WORKSPACE_ID").is_ok() {
        return Some(AgentInfo::new("Zed", DetectionSource::Environment));
    }

    // VS Code with Copilot
    if std::env::var("VSCODE_PID").is_ok() {
        // Check for Copilot specifically
        if std::env::var("GITHUB_COPILOT_SESSION").is_ok() {
            return Some(AgentInfo::new(
                "GitHub Copilot",
                DetectionSource::Environment,
            ));
        }
        return Some(AgentInfo::new("VS Code", DetectionSource::Environment));
    }

    None
}

/// Detect agent from parent process (platform-specific)
#[cfg(unix)]
pub fn detect_from_process_tree() -> Option<AgentInfo> {
    use std::process::Command;

    // Get parent process ID first
    let ppid_output = Command::new("ps")
        .args(["-o", "ppid=", "-p"])
        .arg(std::process::id().to_string())
        .output()
        .ok()?;

    let ppid = String::from_utf8_lossy(&ppid_output.stdout)
        .trim()
        .to_string();

    let parent_output = Command::new("ps")
        .args(["-o", "comm=", "-p", &ppid])
        .output()
        .ok()?;

    let parent_name = String::from_utf8_lossy(&parent_output.stdout)
        .trim()
        .to_lowercase();

    classify_process_name(&parent_name)
}

#[cfg(not(unix))]
pub fn detect_from_process_tree() -> Option<AgentInfo> {
    // Process tree detection not implemented for non-Unix
    None
}

/// Normalize agent name for consistency
fn normalize_agent_name(raw: &str) -> String {
    let lower = raw.to_lowercase();

    if lower.contains("codex") {
        return "Codex".to_string();
    }

    if lower.contains("chatgpt") {
        return "ChatGPT".to_string();
    }

    // Claude variants
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

    // Cursor
    if lower.contains("cursor") {
        return "Cursor".to_string();
    }

    // Windsurf / Codeium
    if lower.contains("windsurf") || lower.contains("codeium") {
        return "Windsurf".to_string();
    }

    // Zed
    if lower.contains("zed") {
        return "Zed".to_string();
    }

    // VS Code
    if lower.contains("vscode") || lower.contains("visual studio code") {
        return "VS Code".to_string();
    }

    // GitHub Copilot
    if lower.contains("copilot") {
        return "GitHub Copilot".to_string();
    }

    // Continue.dev
    if lower.contains("continue") {
        return "Continue".to_string();
    }

    // Aider
    if lower.contains("aider") {
        return "Aider".to_string();
    }

    // Return original if no match
    raw.to_string()
}

fn classify_process_name(parent_name: &str) -> Option<AgentInfo> {
    if parent_name.contains("codex") {
        return Some(AgentInfo::new("Codex", DetectionSource::ProcessTree));
    }

    if parent_name.contains("claude") {
        if parent_name.contains("desktop") || parent_name.contains("electron") {
            return Some(AgentInfo::new(
                "Claude Desktop",
                DetectionSource::ProcessTree,
            ));
        }
        if parent_name.contains("code") || parent_name.contains("cli") {
            return Some(AgentInfo::new("Claude Code", DetectionSource::ProcessTree));
        }
        return Some(AgentInfo::new("Claude", DetectionSource::ProcessTree));
    }

    if parent_name.contains("cursor") {
        return Some(AgentInfo::new("Cursor", DetectionSource::ProcessTree));
    }

    if parent_name.contains("windsurf") || parent_name.contains("codeium") {
        return Some(AgentInfo::new("Windsurf", DetectionSource::ProcessTree));
    }

    if parent_name.contains("zed") {
        return Some(AgentInfo::new("Zed", DetectionSource::ProcessTree));
    }

    if parent_name == "code"
        || parent_name == "code-insiders"
        || parent_name.contains("vscode")
        || parent_name.contains("visual studio code")
    {
        return Some(AgentInfo::new("VS Code", DetectionSource::ProcessTree));
    }

    None
}

/// Try all detection methods in order of reliability
pub fn detect_agent() -> AgentInfo {
    // 1. Environment is most reliable
    if let Some(agent) = detect_from_env() {
        return agent;
    }

    // 2. Process tree as fallback
    if let Some(agent) = detect_from_process_tree() {
        return agent;
    }

    // 3. Unknown
    AgentInfo::unknown()
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

    #[test]
    fn test_detect_from_initialize() {
        let params = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "Claude Desktop",
                "version": "0.7.1"
            }
        });

        let agent = detect_from_initialize(&params).unwrap();
        assert_eq!(agent.name, "Claude Desktop");
        assert_eq!(agent.version, Some("0.7.1".to_string()));
        assert_eq!(agent.detected_from, DetectionSource::McpInitialize);
    }

    #[test]
    fn test_detect_from_initialize_no_version() {
        let params = serde_json::json!({
            "clientInfo": {
                "name": "Cursor"
            }
        });

        let agent = detect_from_initialize(&params).unwrap();
        assert_eq!(agent.name, "Cursor");
        assert_eq!(agent.version, None);
    }

    #[test]
    fn test_detect_from_initialize_missing() {
        let params = serde_json::json!({});
        assert!(detect_from_initialize(&params).is_none());
    }

    #[test]
    fn test_classify_process_name_codex_precedes_vscode() {
        let agent = classify_process_name("codex").expect("expected codex classification");
        assert_eq!(agent.name, "Codex");
    }

    #[test]
    fn test_classify_process_name_vscode() {
        let agent = classify_process_name("code").expect("expected vscode classification");
        assert_eq!(agent.name, "VS Code");
    }

    #[test]
    fn test_classify_process_name_claude_code() {
        let agent =
            classify_process_name("claude-code").expect("expected claude-code classification");
        assert_eq!(agent.name, "Claude Code");
    }

    #[test]
    fn test_classify_process_name_no_false_positive_for_xcode() {
        assert!(classify_process_name("xcodebuild").is_none());
    }
}
