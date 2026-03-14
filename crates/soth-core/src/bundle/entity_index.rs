//! Unified entity index for O(1) identity resolution.
//!
//! Built from a `NativeBundle.entities` array at bundle load time.
//! Replaces the multi-step `gating_from_detect()` derivation with a
//! simple flat index keyed by bundle_id, process_name, and host.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::artifacts::CaptureMode;
use crate::classify::AppType;

/// Fine-grained entity kind. Transmitted as `tool_kind` in telemetry.
///
/// Unlike `AppType` (Host/NonHost/Unknown), this preserves the full
/// granularity from the detect bundle all the way to the cloud dashboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Browser,
    Ide,
    Cli,
    AgentApp,
    BrowserApp,
    Platform,
    Desktop,
    #[default]
    Other,
}

impl EntityKind {
    /// Parse from string (case-insensitive). Returns `Other` for unknown values.
    pub fn from_str_loose(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "browser" | "host" => Self::Browser,
            "ide" | "code_editor" | "code-editor" => Self::Ide,
            "cli" | "cli_tool" | "cli-tool" => Self::Cli,
            "agent_app" | "agent-app" | "agent" => Self::AgentApp,
            "browser_app" | "browser-app" | "web_app" | "web-app" => Self::BrowserApp,
            "platform" | "provider" => Self::Platform,
            "desktop" | "desktop_app" | "desktop-app" => Self::Desktop,
            _ => Self::Other,
        }
    }

    /// Convert to the coarse `AppType` for gating compatibility.
    pub fn to_app_type(self) -> AppType {
        match self {
            Self::Browser | Self::BrowserApp => AppType::Host,
            Self::Ide | Self::Cli | Self::AgentApp | Self::Platform | Self::Desktop => {
                AppType::NonHost
            }
            Self::Other => AppType::Unknown,
        }
    }

    /// Returns the telemetry `source_class` string for backward compat.
    pub fn source_class(self) -> &'static str {
        match self {
            Self::Browser | Self::BrowserApp => "browser",
            Self::Ide | Self::Cli | Self::AgentApp | Self::Platform | Self::Desktop => "agent_app",
            Self::Other => "unknown",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::Ide => "ide",
            Self::Cli => "cli",
            Self::AgentApp => "agent_app",
            Self::BrowserApp => "browser_app",
            Self::Platform => "platform",
            Self::Desktop => "desktop",
            Self::Other => "other",
        }
    }
}

/// A fully-resolved entity record. Everything the proxy needs at request time.
#[derive(Debug, Clone)]
pub struct ResolvedEntity {
    /// Canonical entity slug (e.g. "cursor", "anthropic").
    pub id: String,
    /// Human-readable display name (e.g. "Cursor", "Anthropic").
    pub name: String,
    /// Fine-grained kind.
    pub kind: EntityKind,
    /// Dashboard category (e.g. "Code Editor", "AI Platform").
    pub category: String,
    /// Coarse app type for gating compatibility. Derived from `kind`.
    pub app_type: AppType,
    /// Default capture mode.
    pub capture_mode: CaptureMode,
    /// API format key (only for providers, e.g. "openai", "anthropic").
    pub api_format: Option<String>,
    /// Linked provider slug (e.g. "openai" for ChatGPT).
    pub provider_id: Option<String>,
}

/// O(1) lookup index built from NativeBundle entities.
///
/// Three indexes cover the three resolution paths:
/// - `by_bundle_id`: macOS bundle ID → entity index
/// - `by_process_name`: Process name → entity index
/// - `by_host`: HTTP host → entity index
pub struct EntityIndex {
    by_bundle_id: HashMap<String, usize>,
    by_process_name: HashMap<String, usize>,
    by_host: HashMap<String, usize>,
    entities: Vec<ResolvedEntity>,
}

impl EntityIndex {
    /// Build an index from raw entity data (typically from NativeBundle.entities).
    ///
    /// Each entry is a tuple: (slug, name, kind_str, category, capture_mode_str,
    ///     api_format, provider_id, signals)
    /// where signals is a list of (signal_kind_str, pattern).
    pub fn build(entries: Vec<EntityIndexEntry>) -> Self {
        let mut by_bundle_id = HashMap::new();
        let mut by_process_name = HashMap::new();
        let mut by_host = HashMap::new();
        let mut entities = Vec::with_capacity(entries.len());

        for entry in entries {
            let kind = EntityKind::from_str_loose(&entry.kind);
            let capture_mode = parse_capture_mode(&entry.capture_mode);

            let resolved = ResolvedEntity {
                id: entry.slug.clone(),
                name: entry.name,
                kind,
                category: entry.category.unwrap_or_else(|| "AI Tool".to_string()),
                app_type: kind.to_app_type(),
                capture_mode,
                api_format: entry.api_format,
                provider_id: entry.provider_id,
            };

            let idx = entities.len();
            entities.push(resolved);

            for (signal_kind, pattern) in &entry.signals {
                let key = pattern.to_ascii_lowercase();
                match signal_kind.as_str() {
                    "ProcessBundleId" => {
                        by_bundle_id.entry(key).or_insert(idx);
                    }
                    "ProcessName" => {
                        by_process_name.entry(key).or_insert(idx);
                    }
                    "HttpHost" | "TlsSni" => {
                        by_host.entry(key).or_insert(idx);
                    }
                    _ => {}
                }
            }
        }

        Self {
            by_bundle_id,
            by_process_name,
            by_host,
            entities,
        }
    }

    /// Resolve a tool identity from process info.
    /// Returns the resolved entity and the match source for diagnostics.
    pub fn resolve_tool(
        &self,
        bundle_id: Option<&str>,
        process_name: Option<&str>,
    ) -> Option<(&ResolvedEntity, &'static str)> {
        // 1. Try bundle_id (most specific on macOS)
        if let Some(bid) = bundle_id {
            if let Some(&idx) = self.by_bundle_id.get(&bid.to_ascii_lowercase()) {
                return Some((&self.entities[idx], "bundle_id"));
            }
        }
        // 2. Try process_name
        if let Some(pname) = process_name {
            if let Some(&idx) = self.by_process_name.get(&pname.to_ascii_lowercase()) {
                return Some((&self.entities[idx], "process_name"));
            }
        }
        None
    }

    /// Resolve a provider from HTTP host.
    pub fn resolve_host(&self, host: &str) -> Option<&ResolvedEntity> {
        self.by_host
            .get(&host.to_ascii_lowercase())
            .map(|&idx| &self.entities[idx])
    }

    /// Get an entity by slug.
    pub fn get(&self, slug: &str) -> Option<&ResolvedEntity> {
        self.entities.iter().find(|e| e.id == slug)
    }

    /// Total number of indexed entities.
    pub fn len(&self) -> usize {
        self.entities.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entities.is_empty()
    }

    /// All entities.
    pub fn entities(&self) -> &[ResolvedEntity] {
        &self.entities
    }
}

/// Input for building an EntityIndex entry. Decoupled from NativeBundle types
/// so soth-core doesn't depend on soth-interface.
pub struct EntityIndexEntry {
    pub slug: String,
    pub name: String,
    pub kind: String,
    pub category: Option<String>,
    pub capture_mode: String,
    pub api_format: Option<String>,
    pub provider_id: Option<String>,
    /// (signal_kind, pattern) pairs extracted from matching rules.
    pub signals: Vec<(String, String)>,
}

fn parse_capture_mode(s: &str) -> CaptureMode {
    match s.to_ascii_lowercase().as_str() {
        "full" | "full_content" => CaptureMode::Full,
        "sensitive_artifacts" => CaptureMode::SensitiveArtifacts,
        _ => CaptureMode::MetadataOnly,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entries() -> Vec<EntityIndexEntry> {
        vec![
            EntityIndexEntry {
                slug: "cursor".into(),
                name: "Cursor".into(),
                kind: "ide".into(),
                category: Some("Code Editor".into()),
                capture_mode: "metadata_only".into(),
                api_format: None,
                provider_id: None,
                signals: vec![
                    ("ProcessBundleId".into(), "com.todesktop.230313mzl4w4u92".into()),
                    ("ProcessName".into(), "Cursor".into()),
                ],
            },
            EntityIndexEntry {
                slug: "anthropic".into(),
                name: "Anthropic".into(),
                kind: "platform".into(),
                category: Some("AI Platform".into()),
                capture_mode: "metadata_only".into(),
                api_format: Some("anthropic".into()),
                provider_id: None,
                signals: vec![("HttpHost".into(), "api.anthropic.com".into())],
            },
            EntityIndexEntry {
                slug: "chatgpt".into(),
                name: "ChatGPT".into(),
                kind: "browser_app".into(),
                category: Some("AI Chat".into()),
                capture_mode: "metadata_only".into(),
                api_format: None,
                provider_id: Some("openai".into()),
                signals: vec![
                    ("HttpHost".into(), "chatgpt.com".into()),
                    ("HttpHost".into(), "chat.openai.com".into()),
                ],
            },
            EntityIndexEntry {
                slug: "claude-code".into(),
                name: "Claude Code".into(),
                kind: "cli".into(),
                category: Some("CLI Tool".into()),
                capture_mode: "metadata_only".into(),
                api_format: None,
                provider_id: Some("anthropic".into()),
                signals: vec![
                    ("ProcessBundleId".into(), "com.anthropic.claude-code".into()),
                    ("ProcessName".into(), "claude-code".into()),
                ],
            },
        ]
    }

    #[test]
    fn build_and_resolve_by_bundle_id() {
        let idx = EntityIndex::build(sample_entries());
        assert_eq!(idx.len(), 4);

        let (entity, source) = idx
            .resolve_tool(Some("com.todesktop.230313mzl4w4u92"), None)
            .unwrap();
        assert_eq!(entity.id, "cursor");
        assert_eq!(entity.name, "Cursor");
        assert_eq!(entity.kind, EntityKind::Ide);
        assert_eq!(entity.category, "Code Editor");
        assert_eq!(entity.app_type, AppType::NonHost);
        assert_eq!(source, "bundle_id");
    }

    #[test]
    fn resolve_by_process_name() {
        let idx = EntityIndex::build(sample_entries());

        let (entity, source) = idx.resolve_tool(None, Some("claude-code")).unwrap();
        assert_eq!(entity.id, "claude-code");
        assert_eq!(entity.kind, EntityKind::Cli);
        assert_eq!(source, "process_name");
    }

    #[test]
    fn resolve_by_host() {
        let idx = EntityIndex::build(sample_entries());

        let entity = idx.resolve_host("api.anthropic.com").unwrap();
        assert_eq!(entity.id, "anthropic");
        assert_eq!(entity.kind, EntityKind::Platform);

        let entity = idx.resolve_host("chatgpt.com").unwrap();
        assert_eq!(entity.id, "chatgpt");
        assert_eq!(entity.kind, EntityKind::BrowserApp);
    }

    #[test]
    fn case_insensitive_lookup() {
        let idx = EntityIndex::build(sample_entries());

        let (entity, _) = idx
            .resolve_tool(Some("COM.TODESKTOP.230313mzl4w4u92"), None)
            .unwrap();
        assert_eq!(entity.id, "cursor");

        let entity = idx.resolve_host("API.ANTHROPIC.COM").unwrap();
        assert_eq!(entity.id, "anthropic");
    }

    #[test]
    fn unknown_returns_none() {
        let idx = EntityIndex::build(sample_entries());
        assert!(idx.resolve_tool(Some("com.unknown.app"), None).is_none());
        assert!(idx.resolve_host("unknown.example.com").is_none());
    }

    #[test]
    fn bundle_id_preferred_over_process_name() {
        let idx = EntityIndex::build(sample_entries());
        // Cursor has both bundle_id and process_name; bundle_id should match first
        let (entity, source) = idx
            .resolve_tool(
                Some("com.todesktop.230313mzl4w4u92"),
                Some("SomethingElse"),
            )
            .unwrap();
        assert_eq!(entity.id, "cursor");
        assert_eq!(source, "bundle_id");
    }

    #[test]
    fn entity_kind_round_trip() {
        assert_eq!(EntityKind::from_str_loose("ide"), EntityKind::Ide);
        assert_eq!(EntityKind::from_str_loose("CLI"), EntityKind::Cli);
        assert_eq!(EntityKind::from_str_loose("browser"), EntityKind::Browser);
        assert_eq!(EntityKind::from_str_loose("platform"), EntityKind::Platform);
        assert_eq!(EntityKind::from_str_loose("agent-app"), EntityKind::AgentApp);
        assert_eq!(EntityKind::from_str_loose("browser_app"), EntityKind::BrowserApp);
        assert_eq!(EntityKind::from_str_loose("garbage"), EntityKind::Other);
    }

    #[test]
    fn entity_kind_to_app_type() {
        assert_eq!(EntityKind::Browser.to_app_type(), AppType::Host);
        assert_eq!(EntityKind::BrowserApp.to_app_type(), AppType::Host);
        assert_eq!(EntityKind::Ide.to_app_type(), AppType::NonHost);
        assert_eq!(EntityKind::Cli.to_app_type(), AppType::NonHost);
        assert_eq!(EntityKind::Platform.to_app_type(), AppType::NonHost);
        assert_eq!(EntityKind::Other.to_app_type(), AppType::Unknown);
    }

    #[test]
    fn source_class_backward_compat() {
        assert_eq!(EntityKind::Browser.source_class(), "browser");
        assert_eq!(EntityKind::BrowserApp.source_class(), "browser");
        assert_eq!(EntityKind::Ide.source_class(), "agent_app");
        assert_eq!(EntityKind::Cli.source_class(), "agent_app");
        assert_eq!(EntityKind::Other.source_class(), "unknown");
    }
}
