use crate::types::{AppIdentity, AppKind, ApplicationEntry, DetectBundleSlice, ProcessInfo};
use crate::util::{host_without_port, lookup_domain_provider};
use serde_json::Value as JsonValue;

/// Default script runtime names used when the bundle does not provide its own list.
/// These are generic interpreter/runtime process names — not app-specific.
const DEFAULT_SCRIPT_RUNTIMES: &[&str] = &[
    "python", "python3", "node", "bun", "deno", "ruby", "bash", "zsh",
];

pub fn resolve_app_identity(
    process_info: &ProcessInfo,
    bundle: &DetectBundleSlice<'_>,
) -> AppIdentity {
    resolve_app_identity_for_host(process_info, None, bundle)
}

pub fn resolve_app_identity_for_host(
    process_info: &ProcessInfo,
    host: Option<&str>,
    bundle: &DetectBundleSlice<'_>,
) -> AppIdentity {
    let host_lc = host.map(|value| host_without_port(value).to_ascii_lowercase());

    // 1. Bundle ID match (highest priority, confidence 0.9)
    if let Some(bundle_id) = process_info.bundle_id.as_deref() {
        if let Some((app_id, app)) = find_by_bundle_id(bundle_id, bundle) {
            let mut confidence: f32 = 0.9;
            if host_matches_detection(app, host_lc.as_deref()) {
                confidence = (confidence + 0.05f32).min(1.0f32);
            }
            return AppIdentity {
                app_id: app_id.to_string(),
                display_name: app.name.clone().unwrap_or_else(|| app_id.to_string()),
                app_kind: app_kind_for_application(app),
                is_known: true,
                confidence,
            };
        }
    }

    // 2. Process name match (confidence 0.8)
    if let Some(process_name) = process_info.process_name.as_deref() {
        if let Some((app_id, app)) = find_by_process_name(process_name, bundle) {
            let mut confidence: f32 = 0.8;
            if host_matches_detection(app, host_lc.as_deref()) {
                confidence = (confidence + 0.1f32).min(1.0f32);
            }
            return AppIdentity {
                app_id: app_id.to_string(),
                display_name: app.name.clone().unwrap_or_else(|| app_id.to_string()),
                app_kind: app_kind_for_application(app),
                is_known: true,
                confidence,
            };
        }
    }

    // 3. Parent process name for script runtimes (confidence 0.6)
    if let Some(parent) = process_info.parent_process_name.as_deref() {
        if is_script_runtime(process_info.process_name.as_deref(), bundle) {
            if let Some((app_id, app)) = find_by_process_name(parent, bundle) {
                let mut confidence: f32 = 0.6;
                if host_matches_detection(app, host_lc.as_deref()) {
                    confidence = (confidence + 0.1f32).min(1.0f32);
                }
                return AppIdentity {
                    app_id: app_id.to_string(),
                    display_name: app.name.clone().unwrap_or_else(|| app_id.to_string()),
                    app_kind: app_kind_for_application(app),
                    is_known: true,
                    confidence,
                };
            }
        }
    }

    // 4. Host-based detection fallback (confidence 0.55)
    //    Skips hosts that resolve to a known LLM provider in domain_index,
    //    since those are shared API domains (e.g. api.anthropic.com) that
    //    identify the provider, not the calling application.
    if let Some(host_value) = host_lc.as_deref() {
        if let Some((app_id, app)) = find_by_detection_host(host_value, bundle) {
            return AppIdentity {
                app_id: app_id.to_string(),
                display_name: app.name.clone().unwrap_or_else(|| app_id.to_string()),
                app_kind: app_kind_for_application(app),
                is_known: true,
                confidence: 0.55,
            };
        }
    }

    AppIdentity::default()
}

fn find_by_process_name<'a>(
    process_name: &str,
    bundle: &'a DetectBundleSlice<'_>,
) -> Option<(&'a String, &'a ApplicationEntry)> {
    let process_lc = process_name.to_ascii_lowercase();

    // Only match against the explicit process_names field.
    // The display `name` is NOT a process identifier — it should not trigger
    // identity matches (e.g. "Claude" the display name vs "claude" the binary).
    bundle.applications.iter().find(|(_, app)| {
        app.process_names
            .iter()
            .any(|name| process_lc.contains(&name.to_ascii_lowercase()))
    })
}

fn find_by_bundle_id<'a>(
    bundle_id: &str,
    bundle: &'a DetectBundleSlice<'_>,
) -> Option<(&'a String, &'a ApplicationEntry)> {
    bundle.applications.iter().find(|(_, app)| {
        app.bundle_ids
            .iter()
            .any(|item| item.eq_ignore_ascii_case(bundle_id))
    })
}

fn find_by_detection_host<'a>(
    host_lc: &str,
    bundle: &'a DetectBundleSlice<'_>,
) -> Option<(&'a String, &'a ApplicationEntry)> {
    // Guard: skip if this host maps to a known LLM provider — it is a shared
    // API domain (e.g. api.openai.com) that does not uniquely identify an app.
    if lookup_domain_provider(bundle.domain_index, host_lc).is_some() {
        return None;
    }
    bundle
        .applications
        .iter()
        .find(|(_, app)| host_matches_detection(app, Some(host_lc)))
}

/// Check if the process is a script runtime (interpreter).
/// Uses the bundle's `script_runtimes` list when available, otherwise falls
/// back to a built-in default list of common runtimes.
fn is_script_runtime(process_name: Option<&str>, bundle: &DetectBundleSlice<'_>) -> bool {
    let Some(name) = process_name else {
        return false;
    };

    let lower = name.to_ascii_lowercase();

    if !bundle.script_runtimes.is_empty() {
        return bundle
            .script_runtimes
            .iter()
            .any(|rt| lower.contains(&rt.to_ascii_lowercase()));
    }

    DEFAULT_SCRIPT_RUNTIMES
        .iter()
        .any(|item| lower.contains(item))
}

fn app_kind_for_application(app: &ApplicationEntry) -> AppKind {
    app.app_type
        .as_deref()
        .map(AppKind::from_type_str)
        .unwrap_or(AppKind::AgentApp)
}

fn host_matches_detection(app: &ApplicationEntry, host_lc: Option<&str>) -> bool {
    let Some(host_lc) = host_lc else {
        return false;
    };
    let Some(detection) = app.detection.as_ref() else {
        return false;
    };
    let Some(hosts) = detection.get("hosts").and_then(JsonValue::as_array) else {
        return false;
    };
    hosts
        .iter()
        .filter_map(|entry| entry.get("pattern").and_then(JsonValue::as_str))
        .map(|pattern| pattern.to_ascii_lowercase())
        .any(|pattern| glob_match(pattern.as_str(), host_lc))
}

fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == text;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    let starts_anchored = !pattern.starts_with('*');
    let ends_anchored = !pattern.ends_with('*');

    let mut index = 0usize;
    let mut first_non_empty = true;
    for part in parts.iter().copied().filter(|part| !part.is_empty()) {
        if first_non_empty && starts_anchored {
            if !text[index..].starts_with(part) {
                return false;
            }
            index += part.len();
            first_non_empty = false;
            continue;
        }

        match text[index..].find(part) {
            Some(pos) => index += pos + part.len(),
            None => return false,
        }
        first_non_empty = false;
    }

    if ends_anchored {
        let last_non_empty = pattern
            .split('*')
            .filter(|part| !part.is_empty())
            .next_back()
            .unwrap_or("");
        text.ends_with(last_non_empty)
    } else {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::OwnedDetectBundle;
    use std::collections::HashMap;

    /// Build a bundle fixture with proper application entries.
    /// All identity knowledge comes from the bundle — no hardcoded builtins.
    fn test_bundle() -> OwnedDetectBundle {
        let mut applications = HashMap::new();

        applications.insert(
            "claude-code".to_string(),
            ApplicationEntry {
                app_id: Some("claude-code".to_string()),
                name: Some("Claude Code".to_string()),
                bundle_ids: vec!["com.anthropic.claude-code".to_string()],
                process_names: vec!["claude".to_string()],
                app_type: Some("cli".to_string()),
                ..ApplicationEntry::default()
            },
        );
        applications.insert(
            "claude-desktop".to_string(),
            ApplicationEntry {
                app_id: Some("claude-desktop".to_string()),
                name: Some("Claude Desktop".to_string()),
                bundle_ids: vec!["com.anthropic.claudefordesktop".to_string()],
                process_names: vec![],
                app_type: Some("agent-app".to_string()),
                ..ApplicationEntry::default()
            },
        );
        applications.insert(
            "cursor".to_string(),
            ApplicationEntry {
                app_id: Some("cursor".to_string()),
                name: Some("Cursor".to_string()),
                bundle_ids: vec![
                    "com.todesktop.230313mzl4w4u92".to_string(),
                    "com.todesktop.cursor".to_string(),
                ],
                process_names: vec!["Cursor".to_string()],
                app_type: Some("ide".to_string()),
                detection: Some(serde_json::json!({
                    "hosts": [
                        { "pattern": "*.cursor.sh" }
                    ]
                })),
                ..ApplicationEntry::default()
            },
        );
        applications.insert(
            "codex".to_string(),
            ApplicationEntry {
                app_id: Some("codex".to_string()),
                name: Some("OpenAI Codex CLI".to_string()),
                bundle_ids: vec![],
                process_names: vec!["codex".to_string()],
                app_type: Some("cli".to_string()),
                ..ApplicationEntry::default()
            },
        );
        applications.insert(
            "windsurf".to_string(),
            ApplicationEntry {
                app_id: Some("windsurf".to_string()),
                name: Some("Windsurf".to_string()),
                bundle_ids: vec![
                    "com.codeium.windsurf".to_string(),
                    "codeium.windsurf".to_string(),
                ],
                process_names: vec!["Windsurf".to_string()],
                app_type: Some("ide".to_string()),
                detection: Some(serde_json::json!({
                    "hosts": [
                        { "pattern": "*.codeium.com" }
                    ]
                })),
                ..ApplicationEntry::default()
            },
        );
        applications.insert(
            "github-copilot".to_string(),
            ApplicationEntry {
                app_id: Some("github-copilot".to_string()),
                name: Some("GitHub Copilot".to_string()),
                bundle_ids: vec![],
                process_names: vec!["copilot".to_string()],
                app_type: Some("ide".to_string()),
                detection: Some(serde_json::json!({
                    "hosts": [
                        { "pattern": "copilot-proxy.githubusercontent.com" },
                        { "pattern": "*.githubcopilot.com" }
                    ]
                })),
                ..ApplicationEntry::default()
            },
        );
        applications.insert(
            "chatgpt".to_string(),
            ApplicationEntry {
                app_id: Some("chatgpt".to_string()),
                name: Some("ChatGPT".to_string()),
                bundle_ids: vec![],
                process_names: vec![],
                app_type: Some("agent-app".to_string()),
                detection: Some(serde_json::json!({
                    "hosts": [
                        { "pattern": "chatgpt.com" },
                        { "pattern": "chat.openai.com" }
                    ]
                })),
                ..ApplicationEntry::default()
            },
        );
        applications.insert(
            "claude-web".to_string(),
            ApplicationEntry {
                app_id: Some("claude-web".to_string()),
                name: Some("Claude".to_string()),
                bundle_ids: vec![],
                process_names: vec![],
                app_type: Some("agent-app".to_string()),
                detection: Some(serde_json::json!({
                    "hosts": [
                        { "pattern": "claude.ai" }
                    ]
                })),
                ..ApplicationEntry::default()
            },
        );
        applications.insert(
            "gemini-web".to_string(),
            ApplicationEntry {
                app_id: Some("gemini-web".to_string()),
                name: Some("Gemini".to_string()),
                bundle_ids: vec![],
                process_names: vec![],
                app_type: Some("agent-app".to_string()),
                detection: Some(serde_json::json!({
                    "hosts": [
                        { "pattern": "gemini.google.com" }
                    ]
                })),
                ..ApplicationEntry::default()
            },
        );
        applications.insert(
            "gemini-cli".to_string(),
            ApplicationEntry {
                app_id: Some("gemini-cli".to_string()),
                name: Some("Gemini CLI".to_string()),
                bundle_ids: vec![],
                process_names: vec!["gemini".to_string()],
                app_type: Some("cli".to_string()),
                ..ApplicationEntry::default()
            },
        );

        let mut domain_index = HashMap::new();
        domain_index.insert("api.openai.com".to_string(), "openai".to_string());
        domain_index.insert("api.anthropic.com".to_string(), "anthropic".to_string());
        domain_index.insert(
            "generativelanguage.googleapis.com".to_string(),
            "google".to_string(),
        );

        OwnedDetectBundle {
            applications,
            domain_index,
            ..OwnedDetectBundle::default()
        }
    }

    fn process(name: &str) -> ProcessInfo {
        ProcessInfo {
            pid: None,
            process_name: Some(name.to_string()),
            bundle_id: None,
            parent_pid: None,
            parent_process_name: None,
            parent_bundle_id: None,
        }
    }

    fn process_with_bundle_id(name: &str, bundle_id: &str) -> ProcessInfo {
        ProcessInfo {
            pid: None,
            process_name: Some(name.to_string()),
            bundle_id: Some(bundle_id.to_string()),
            parent_pid: None,
            parent_process_name: None,
            parent_bundle_id: None,
        }
    }

    fn process_with_parent(name: &str, parent: &str) -> ProcessInfo {
        ProcessInfo {
            pid: None,
            process_name: Some(name.to_string()),
            bundle_id: None,
            parent_pid: None,
            parent_process_name: Some(parent.to_string()),
            parent_bundle_id: None,
        }
    }

    // -- Bundle-driven identity (no builtins) --

    #[test]
    fn empty_bundle_returns_unknown() {
        let bundle = OwnedDetectBundle::default();
        let id = resolve_app_identity(&process("claude"), &bundle.as_slice());
        assert!(!id.is_known);
    }

    // -- Claude Code --

    #[test]
    fn claude_code_by_process_name() {
        let bundle = test_bundle();
        let id = resolve_app_identity(&process("claude"), &bundle.as_slice());
        assert_eq!(id.app_id, "claude-code");
        assert_eq!(id.app_kind, AppKind::Cli);
        assert!(id.is_known);
        assert!(id.confidence >= 0.8);
    }

    #[test]
    fn claude_code_by_bundle_id() {
        let bundle = test_bundle();
        let id = resolve_app_identity(
            &process_with_bundle_id("claude", "com.anthropic.claude-code"),
            &bundle.as_slice(),
        );
        assert_eq!(id.app_id, "claude-code");
        assert!(id.confidence >= 0.9);
    }

    #[test]
    fn claude_code_via_node_parent() {
        let bundle = test_bundle();
        let id = resolve_app_identity(
            &process_with_parent("node", "claude"),
            &bundle.as_slice(),
        );
        assert_eq!(id.app_id, "claude-code");
        assert!(id.confidence >= 0.6);
    }

    // -- Claude Desktop --

    #[test]
    fn claude_desktop_by_bundle_id() {
        let bundle = test_bundle();
        let id = resolve_app_identity(
            &process_with_bundle_id("Claude", "com.anthropic.claudefordesktop"),
            &bundle.as_slice(),
        );
        assert_eq!(id.app_id, "claude-desktop");
        assert_eq!(id.app_kind, AppKind::AgentApp);
        assert!(id.confidence >= 0.9);
    }

    // -- Cursor --

    #[test]
    fn cursor_by_process_name() {
        let bundle = test_bundle();
        let id = resolve_app_identity(&process("Cursor"), &bundle.as_slice());
        assert_eq!(id.app_id, "cursor");
        assert_eq!(id.app_kind, AppKind::Ide);
        assert!(id.is_known);
    }

    #[test]
    fn cursor_by_bundle_id() {
        let bundle = test_bundle();
        let id = resolve_app_identity(
            &process_with_bundle_id("Cursor", "com.todesktop.230313mzl4w4u92"),
            &bundle.as_slice(),
        );
        assert_eq!(id.app_id, "cursor");
        assert!(id.confidence >= 0.9);
    }

    // -- Codex --

    #[test]
    fn codex_by_process_name() {
        let bundle = test_bundle();
        let id = resolve_app_identity(&process("codex"), &bundle.as_slice());
        assert_eq!(id.app_id, "codex");
        assert_eq!(id.app_kind, AppKind::Cli);
        assert!(id.is_known);
    }

    // -- Windsurf --

    #[test]
    fn windsurf_by_process_name() {
        let bundle = test_bundle();
        let id = resolve_app_identity(&process("Windsurf"), &bundle.as_slice());
        assert_eq!(id.app_id, "windsurf");
        assert_eq!(id.app_kind, AppKind::Ide);
        assert!(id.is_known);
    }

    #[test]
    fn windsurf_by_bundle_id() {
        let bundle = test_bundle();
        let id = resolve_app_identity(
            &process_with_bundle_id("windsurf", "com.codeium.windsurf"),
            &bundle.as_slice(),
        );
        assert_eq!(id.app_id, "windsurf");
        assert!(id.confidence >= 0.9);
    }

    // -- GitHub Copilot --

    #[test]
    fn copilot_by_process_name() {
        let bundle = test_bundle();
        let id = resolve_app_identity(&process("copilot"), &bundle.as_slice());
        assert_eq!(id.app_id, "github-copilot");
        assert!(id.is_known);
    }

    // -- Host-based identity --

    #[test]
    fn chatgpt_by_host() {
        let bundle = test_bundle();
        let id = resolve_app_identity_for_host(
            &process("Safari"),
            Some("chatgpt.com"),
            &bundle.as_slice(),
        );
        assert_eq!(id.app_id, "chatgpt");
        assert!(id.is_known);
        assert!(id.confidence >= 0.55);
    }

    #[test]
    fn claude_web_by_host() {
        let bundle = test_bundle();
        let id = resolve_app_identity_for_host(
            &process("Safari"),
            Some("claude.ai"),
            &bundle.as_slice(),
        );
        assert_eq!(id.app_id, "claude-web");
        assert!(id.is_known);
    }

    // -- Provider host guard --

    #[test]
    fn provider_host_does_not_poison_identity() {
        let bundle = test_bundle();
        // An unknown app calling api.openai.com should NOT be identified as any app
        let id = resolve_app_identity_for_host(
            &process("my-custom-tool"),
            Some("api.openai.com"),
            &bundle.as_slice(),
        );
        assert!(!id.is_known, "provider API host must not resolve app identity");
    }

    #[test]
    fn provider_host_does_not_poison_anthropic() {
        let bundle = test_bundle();
        // Cursor calling api.anthropic.com — identity comes from process, not host
        let id = resolve_app_identity_for_host(
            &process("Cursor"),
            Some("api.anthropic.com"),
            &bundle.as_slice(),
        );
        assert_eq!(id.app_id, "cursor");
        assert!(id.confidence >= 0.8);
    }

    // -- Unknown --

    #[test]
    fn unknown_process_returns_default() {
        let bundle = test_bundle();
        let id = resolve_app_identity(&process("some-random-tool"), &bundle.as_slice());
        assert!(!id.is_known);
    }

    // -- Bundle entries with custom names --

    #[test]
    fn custom_bundle_entry_works() {
        let mut bundle = OwnedDetectBundle::default();
        bundle.applications.insert(
            "my-internal-tool".to_string(),
            ApplicationEntry {
                app_id: Some("my-internal-tool".to_string()),
                name: Some("Internal AI Tool".to_string()),
                process_names: vec!["my-tool".to_string()],
                app_type: Some("cli".to_string()),
                ..ApplicationEntry::default()
            },
        );
        let id = resolve_app_identity(&process("my-tool"), &bundle.as_slice());
        assert_eq!(id.app_id, "my-internal-tool");
        assert_eq!(id.display_name, "Internal AI Tool");
        assert!(id.is_known);
    }

    // -- Script runtime with bundle-driven list --

    #[test]
    fn script_runtime_uses_bundle_list() {
        let mut bundle = test_bundle();
        bundle.script_runtimes = vec!["my-runtime".to_string()];
        let id = resolve_app_identity(
            &process_with_parent("my-runtime", "claude"),
            &bundle.as_slice(),
        );
        assert_eq!(id.app_id, "claude-code");
        assert!(id.confidence >= 0.6);
    }

    #[test]
    fn script_runtime_default_fallback() {
        let bundle = test_bundle();
        // bundle.script_runtimes is empty, so defaults are used
        let id = resolve_app_identity(
            &process_with_parent("python3", "claude"),
            &bundle.as_slice(),
        );
        assert_eq!(id.app_id, "claude-code");
        assert!(id.confidence >= 0.6);
    }

    // -- Copilot host-based --

    #[test]
    fn copilot_by_wildcard_host() {
        let bundle = test_bundle();
        let id = resolve_app_identity_for_host(
            &process("some-editor"),
            Some("api.githubcopilot.com"),
            &bundle.as_slice(),
        );
        assert_eq!(id.app_id, "github-copilot");
        assert!(id.is_known);
        assert!(id.confidence >= 0.55);
    }

    #[test]
    fn copilot_by_exact_host() {
        let bundle = test_bundle();
        let id = resolve_app_identity_for_host(
            &process("some-editor"),
            Some("copilot-proxy.githubusercontent.com"),
            &bundle.as_slice(),
        );
        assert_eq!(id.app_id, "github-copilot");
        assert!(id.is_known);
    }

    // -- ChatGPT alternate host --

    #[test]
    fn chatgpt_by_alternate_host() {
        let bundle = test_bundle();
        let id = resolve_app_identity_for_host(
            &process("Safari"),
            Some("chat.openai.com"),
            &bundle.as_slice(),
        );
        assert_eq!(id.app_id, "chatgpt");
        assert!(id.is_known);
    }

    // -- Gemini --

    #[test]
    fn gemini_web_by_host() {
        let bundle = test_bundle();
        let id = resolve_app_identity_for_host(
            &process("Chrome"),
            Some("gemini.google.com"),
            &bundle.as_slice(),
        );
        assert_eq!(id.app_id, "gemini-web");
        assert!(id.is_known);
        assert!(id.confidence >= 0.55);
    }

    #[test]
    fn gemini_cli_by_process_name() {
        let bundle = test_bundle();
        let id = resolve_app_identity(&process("gemini"), &bundle.as_slice());
        assert_eq!(id.app_id, "gemini-cli");
        assert_eq!(id.app_kind, AppKind::Cli);
        assert!(id.is_known);
        assert!(id.confidence >= 0.8);
    }

    // -- Confidence boost: process + matching host --

    #[test]
    fn cursor_process_plus_host_boosts_confidence() {
        let bundle = test_bundle();
        // Cursor process alone = 0.8
        let id_process_only =
            resolve_app_identity(&process("Cursor"), &bundle.as_slice());
        assert!(id_process_only.confidence >= 0.8);

        // Cursor process + matching cursor.sh host = boosted
        let id_boosted = resolve_app_identity_for_host(
            &process("Cursor"),
            Some("api.cursor.sh"),
            &bundle.as_slice(),
        );
        assert_eq!(id_boosted.app_id, "cursor");
        assert!(
            id_boosted.confidence > id_process_only.confidence,
            "host match should boost confidence: {} > {}",
            id_boosted.confidence,
            id_process_only.confidence,
        );
    }

    #[test]
    fn windsurf_process_plus_host_boosts_confidence() {
        let bundle = test_bundle();
        let id_process_only =
            resolve_app_identity(&process("Windsurf"), &bundle.as_slice());
        let id_boosted = resolve_app_identity_for_host(
            &process("Windsurf"),
            Some("api.codeium.com"),
            &bundle.as_slice(),
        );
        assert_eq!(id_boosted.app_id, "windsurf");
        assert!(
            id_boosted.confidence > id_process_only.confidence,
            "host match should boost: {} > {}",
            id_boosted.confidence,
            id_process_only.confidence,
        );
    }

    #[test]
    fn bundle_id_plus_host_boosts_confidence() {
        let bundle = test_bundle();
        let id_bid_only = resolve_app_identity(
            &process_with_bundle_id("claude", "com.anthropic.claude-code"),
            &bundle.as_slice(),
        );
        assert!(id_bid_only.confidence >= 0.9);

        // When calling api.anthropic.com (a provider domain), no host boost
        let id_provider_host = resolve_app_identity_for_host(
            &process_with_bundle_id("claude", "com.anthropic.claude-code"),
            Some("api.anthropic.com"),
            &bundle.as_slice(),
        );
        assert_eq!(id_provider_host.confidence, id_bid_only.confidence,
            "provider host should NOT boost confidence");
    }

    // -- Process name wins over host --

    #[test]
    fn process_identity_wins_over_host() {
        let bundle = test_bundle();
        // Cursor process calling claude.ai → identity should be cursor (process wins)
        let id = resolve_app_identity_for_host(
            &process("Cursor"),
            Some("claude.ai"),
            &bundle.as_slice(),
        );
        assert_eq!(id.app_id, "cursor");
        assert!(id.confidence >= 0.8);
    }

    #[test]
    fn bundle_id_wins_over_host() {
        let bundle = test_bundle();
        // Claude Code bundle_id but calling chatgpt.com → identity should be claude-code
        let id = resolve_app_identity_for_host(
            &process_with_bundle_id("claude", "com.anthropic.claude-code"),
            Some("chatgpt.com"),
            &bundle.as_slice(),
        );
        assert_eq!(id.app_id, "claude-code");
        assert!(id.confidence >= 0.9);
    }

    // -- Copilot process + host combined --

    #[test]
    fn copilot_process_plus_host_boosts_confidence() {
        let bundle = test_bundle();
        let id_process_only =
            resolve_app_identity(&process("copilot"), &bundle.as_slice());
        let id_boosted = resolve_app_identity_for_host(
            &process("copilot"),
            Some("api.githubcopilot.com"),
            &bundle.as_slice(),
        );
        assert_eq!(id_boosted.app_id, "github-copilot");
        assert!(
            id_boosted.confidence > id_process_only.confidence,
            "copilot host match should boost: {} > {}",
            id_boosted.confidence,
            id_process_only.confidence,
        );
    }

    // -- Parent process with host boost --

    #[test]
    fn script_runtime_parent_with_host_boosts_confidence() {
        let bundle = test_bundle();
        let id_no_host = resolve_app_identity(
            &process_with_parent("node", "claude"),
            &bundle.as_slice(),
        );
        assert!(id_no_host.confidence >= 0.6);

        // node spawned by claude, calling claude.ai — no host boost because
        // claude-code has no detection.hosts. This tests the guard.
        let id_with_host = resolve_app_identity_for_host(
            &process_with_parent("node", "claude"),
            Some("claude.ai"),
            &bundle.as_slice(),
        );
        assert_eq!(id_with_host.app_id, "claude-code");
        // claude-code has no detection.hosts, so no boost
        assert_eq!(id_with_host.confidence, id_no_host.confidence);
    }
}
