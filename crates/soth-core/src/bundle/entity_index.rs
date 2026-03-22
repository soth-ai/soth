//! Unified entity index for O(1) identity resolution.
//!
//! Built from a `NativeBundle.entities` array at bundle load time.
//! Replaces the multi-step `gating_from_detect()` derivation with a
//! simple flat index keyed by bundle_id, process_name, and host.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::artifacts::CaptureMode;
use crate::bundle::env_index::{EnvIndex, EnvironmentClass};
use crate::bundle::gating::ProcessAction;
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
    IdePlugin,
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
            "ide_plugin" | "ide-plugin" => Self::IdePlugin,
            "cli" | "cli_tool" | "cli-tool" => Self::Cli,
            "agent_app" | "agent-app" | "agent" => Self::AgentApp,
            "browser_app" | "browser-app" | "web_app" | "web-app" => Self::BrowserApp,
            "platform" | "provider" => Self::Platform,
            "desktop" | "desktop_app" | "desktop-app" => Self::Desktop,
            _ => Self::Other,
        }
    }

    /// Returns the telemetry `source_class` string for backward compat.
    pub fn source_class(self) -> &'static str {
        match self {
            Self::Browser | Self::BrowserApp => "browser",
            Self::Ide
            | Self::IdePlugin
            | Self::Cli
            | Self::AgentApp
            | Self::Platform
            | Self::Desktop => "agent_app",
            Self::Other => "unknown",
        }
    }

    /// Convert to the product `SurfaceType` for taxonomy reporting.
    pub fn to_surface_type(self) -> crate::classify::SurfaceType {
        use crate::classify::SurfaceType;
        match self {
            Self::Browser | Self::BrowserApp => SurfaceType::WebApp,
            Self::Ide => SurfaceType::Ide,
            Self::IdePlugin => SurfaceType::IdePlugin,
            Self::Cli => SurfaceType::Cli,
            Self::AgentApp => SurfaceType::Agent,
            Self::Desktop => SurfaceType::Desktop,
            Self::Platform => SurfaceType::Sdk,
            Self::Other => SurfaceType::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::Ide => "ide",
            Self::IdePlugin => "ide_plugin",
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
    /// Vendor slug (maker of this product, e.g. "anysphere" for Cursor).
    pub vendor_slug: Option<String>,
    /// Process-level action for gating (default: Intercept).
    pub action: ProcessAction,
}

/// Matched host entity with the host rule that fired (carries PathRules for gating).
#[derive(Debug, Clone)]
pub struct HostEntityMatch {
    pub entity_idx: usize,
    pub host_pattern: String,
    pub methods: Vec<String>,
    pub paths: crate::bundle::gating::PathRules,
    pub specificity: usize,
}

/// Paired host match result: best provider AND best application independently.
#[derive(Debug, Clone, Default)]
pub struct HostEntityMatchSet {
    pub provider: Option<HostEntityMatch>,
    pub application: Option<HostEntityMatch>,
}

/// Unified entity resolver — single authority for "given (host, process, path),
/// which entity?" Replaces EntityCatalog + IdentityIndex + domain_index lookups.
///
/// Four indexes cover all resolution paths:
/// - `by_bundle_id`: macOS bundle ID → entity index (O(1))
/// - `by_process_name`: Process name → entity index (O(1))
/// - `by_host`: HTTP host → entity index (O(1) exact)
/// - `wildcard_hosts`: wildcard host patterns → entity index (linear scan, sorted by specificity)
pub struct EntityIndex {
    by_bundle_id: HashMap<String, usize>,
    by_process_name: HashMap<String, usize>,
    by_host: HashMap<String, usize>,
    /// (pattern, entity_idx, methods, path_rules, specificity) — sorted descending by specificity
    wildcard_hosts: Vec<(String, usize, Vec<String>, crate::bundle::gating::PathRules, usize)>,
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
        let mut wildcard_hosts: Vec<(String, usize, Vec<String>, crate::bundle::gating::PathRules, usize)> = Vec::new();
        let mut entities = Vec::with_capacity(entries.len());

        for entry in entries {
            let kind = EntityKind::from_str_loose(&entry.kind);
            let capture_mode = parse_capture_mode(&entry.capture_mode);

            let resolved = ResolvedEntity {
                id: entry.slug.clone(),
                name: entry.name,
                kind,
                category: entry.category.unwrap_or_else(|| "AI Tool".to_string()),
                app_type: kind.to_surface_type().app_type(),
                capture_mode,
                api_format: entry.api_format,
                provider_id: entry.provider_id,
                vendor_slug: entry.vendor_slug,
                action: entry.action,
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

            // Index host rules with path constraints for wildcard matching.
            for (pattern, methods, paths) in &entry.host_rules {
                let key = pattern.to_ascii_lowercase();
                let spec = crate::bundle::detect::pattern_specificity(&key);
                if key.contains('*') {
                    wildcard_hosts.push((key, idx, methods.clone(), paths.clone(), spec));
                } else {
                    // Exact hosts also go into wildcard_hosts so they carry
                    // path rules for evaluate_path_rules. The exact by_host
                    // index is for fast O(1) entity resolution without rules.
                    wildcard_hosts.push((key, idx, methods.clone(), paths.clone(), spec));
                }
            }
        }

        // Sort wildcard hosts by specificity descending for best-match-first.
        wildcard_hosts.sort_by(|a, b| b.4.cmp(&a.4));

        Self {
            by_bundle_id,
            by_process_name,
            by_host,
            wildcard_hosts,
            entities,
        }
    }

    /// Resolve a tool identity from process info.
    ///
    /// Returns the resolved entity and the match source for diagnostics.
    ///
    /// # IdePlugin gating
    ///
    /// `IdePlugin` entities only match when the parent process is an IDE-class
    /// environment (as determined by `env_index`).  If the parent is not an IDE
    /// (e.g. the plugin binary is invoked directly from a terminal or the parent
    /// is unknown), `None` is returned so the caller treats the request as
    /// shadow IT and falls back to parent-environment surface derivation.
    ///
    /// `Cli` entities have no parent gate — a known CLI product is always CLI
    /// regardless of whether its parent is a terminal, script, or anything else.
    /// Parent environment class is only used for shadow IT surface derivation in
    /// the `None` branch of the caller.
    pub fn resolve_tool(
        &self,
        bundle_id: Option<&str>,
        process_name: Option<&str>,
        parent_bundle_id: Option<&str>,
        parent_process_name: Option<&str>,
        env_index: &EnvIndex,
    ) -> Option<(&ResolvedEntity, &'static str)> {
        // 1. Try bundle_id (most specific on macOS)
        let candidate = if let Some(bid) = bundle_id {
            if let Some(&idx) = self.by_bundle_id.get(&bid.to_ascii_lowercase()) {
                Some((&self.entities[idx], "bundle_id"))
            } else {
                None
            }
        } else {
            None
        };

        // 2. Fall through to process_name if bundle_id didn't match
        let candidate = candidate.or_else(|| {
            if let Some(pname) = process_name {
                if let Some(&idx) = self.by_process_name.get(&pname.to_ascii_lowercase()) {
                    return Some((&self.entities[idx], "process_name"));
                }
            }
            None
        });

        // 3. Apply the IdePlugin parent-environment gate.
        //    IdePlugin entities only match when parent is an IDE-class environment.
        //    Cli kind has no parent gate — a known CLI product is always CLI
        //    regardless of whether its parent is a terminal, script, or anything else.
        //    Parent environment class is only used for shadow IT surface derivation (None branch in handler).
        if let Some((entity, source)) = candidate {
            if entity.kind == EntityKind::IdePlugin {
                let parent_is_ide = env_index.resolve_parent(parent_bundle_id, parent_process_name)
                    == Some(EnvironmentClass::IDE);
                if !parent_is_ide {
                    return None;
                }
            }
            Some((entity, source))
        } else {
            None
        }
    }

    /// Resolve a provider from HTTP host (O(1) exact match, no path rules).
    pub fn resolve_host(&self, host: &str) -> Option<&ResolvedEntity> {
        self.by_host
            .get(&host.to_ascii_lowercase())
            .map(|&idx| &self.entities[idx])
    }

    /// Resolve host with full wildcard matching and path rules.
    /// Returns the best provider AND best application match independently,
    /// with the host rule that fired (carrying PathRules for gating).
    ///
    /// Replaces `match_entities(EntityCatalog, host)` from stage2_whitelist.
    pub fn resolve_host_with_rules(&self, host: &str) -> HostEntityMatchSet {
        let host_lc = host.to_ascii_lowercase();
        let mut best_provider: Option<HostEntityMatch> = None;
        let mut best_app: Option<HostEntityMatch> = None;

        for (pattern, idx, methods, paths, spec) in &self.wildcard_hosts {
            if !host_pattern_matches(pattern, &host_lc) {
                continue;
            }
            let entity = &self.entities[*idx];
            let is_provider = matches!(entity.kind, EntityKind::Platform);
            let matched = HostEntityMatch {
                entity_idx: *idx,
                host_pattern: pattern.clone(),
                methods: methods.clone(),
                paths: paths.clone(),
                specificity: *spec,
            };

            if is_provider {
                if best_provider.as_ref().map_or(true, |b| *spec > b.specificity) {
                    best_provider = Some(matched);
                }
            } else if best_app.as_ref().map_or(true, |b| *spec > b.specificity) {
                best_app = Some(matched);
            }
        }

        HostEntityMatchSet {
            provider: best_provider,
            application: best_app,
        }
    }

    /// Get the entity for a host match.
    pub fn entity_for_host_match(&self, m: &HostEntityMatch) -> &ResolvedEntity {
        &self.entities[m.entity_idx]
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
    pub vendor_slug: Option<String>,
    /// Process-level action (default: Intercept).
    pub action: ProcessAction,
    /// (signal_kind, pattern) pairs extracted from matching rules.
    pub signals: Vec<(String, String)>,
    /// Host rules with path constraints for gating. Built from matching rules
    /// that combine HttpHost + HttpPath signals.
    pub host_rules: Vec<(String, Vec<String>, crate::bundle::gating::PathRules)>,
}

/// Host pattern matching: supports `=exact`, `*.wildcard.com`, and suffix matching.
fn host_pattern_matches(pattern: &str, host: &str) -> bool {
    if pattern.is_empty() || host.is_empty() {
        return false;
    }
    if let Some(exact) = pattern.strip_prefix('=') {
        return host == exact;
    }
    if pattern.contains('*') {
        return crate::bundle::detect::glob_match(pattern, host);
    }
    // Suffix match: "openai.com" matches "openai.com" and "api.openai.com"
    host == pattern || (host.ends_with(pattern) && host.as_bytes().get(host.len() - pattern.len() - 1) == Some(&b'.'))
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
                vendor_slug: None,
                action: ProcessAction::Intercept,
                host_rules: vec![],
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
                vendor_slug: None,
                action: ProcessAction::Intercept,
                host_rules: vec![],
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
                vendor_slug: None,
                action: ProcessAction::Intercept,
                host_rules: vec![],
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
                vendor_slug: None,
                action: ProcessAction::Intercept,
                host_rules: vec![],
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
            .resolve_tool(Some("com.todesktop.230313mzl4w4u92"), None, None, None, &EnvIndex::default())
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

        let (entity, source) = idx.resolve_tool(None, Some("claude-code"), None, None, &EnvIndex::default()).unwrap();
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
            .resolve_tool(Some("COM.TODESKTOP.230313mzl4w4u92"), None, None, None, &EnvIndex::default())
            .unwrap();
        assert_eq!(entity.id, "cursor");

        let entity = idx.resolve_host("API.ANTHROPIC.COM").unwrap();
        assert_eq!(entity.id, "anthropic");
    }

    #[test]
    fn unknown_returns_none() {
        let idx = EntityIndex::build(sample_entries());
        assert!(idx.resolve_tool(Some("com.unknown.app"), None, None, None, &EnvIndex::default()).is_none());
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
                None,
                None,
                &EnvIndex::default(),
            )
            .unwrap();
        assert_eq!(entity.id, "cursor");
        assert_eq!(source, "bundle_id");
    }

    fn ide_plugin_entries() -> Vec<EntityIndexEntry> {
        vec![
            EntityIndexEntry {
                slug: "copilot".into(),
                name: "GitHub Copilot".into(),
                kind: "ide_plugin".into(),
                category: Some("IDE Plugin".into()),
                capture_mode: "metadata_only".into(),
                api_format: None,
                provider_id: Some("openai".into()),
                vendor_slug: Some("github".into()),
                action: ProcessAction::Intercept,
                host_rules: vec![],
                signals: vec![
                    ("ProcessBundleId".into(), "com.github.copilot".into()),
                    ("ProcessName".into(), "copilot".into()),
                ],
            },
        ]
    }

    fn ide_env_index() -> EnvIndex {
        EnvIndex::build(&[crate::bundle::env_index::BundleEnvironment {
            slug: "vscode".into(),
            class: EnvironmentClass::IDE,
            bundle_ids: vec!["com.microsoft.vscode".into()],
            process_names: vec!["code".into()],
        }])
    }

    #[test]
    fn ide_plugin_matches_when_parent_is_ide() {
        let idx = EntityIndex::build(ide_plugin_entries());
        let env = ide_env_index();

        let result = idx.resolve_tool(
            Some("com.github.copilot"),
            None,
            Some("com.microsoft.vscode"),
            None,
            &env,
        );
        assert!(result.is_some());
        let (entity, source) = result.unwrap();
        assert_eq!(entity.id, "copilot");
        assert_eq!(entity.kind, EntityKind::IdePlugin);
        assert_eq!(source, "bundle_id");
    }

    #[test]
    fn ide_plugin_blocked_when_parent_is_terminal() {
        let idx = EntityIndex::build(ide_plugin_entries());
        let env = EnvIndex::build(&[crate::bundle::env_index::BundleEnvironment {
            slug: "zsh".into(),
            class: EnvironmentClass::Terminal,
            bundle_ids: vec![],
            process_names: vec!["zsh".into()],
        }]);

        // copilot invoked from a terminal — should be treated as shadow IT (None)
        let result = idx.resolve_tool(
            Some("com.github.copilot"),
            None,
            None,
            Some("zsh"),
            &env,
        );
        assert!(result.is_none(), "IdePlugin must not match when parent is not an IDE");
    }

    #[test]
    fn ide_plugin_blocked_when_parent_unknown() {
        let idx = EntityIndex::build(ide_plugin_entries());
        // Empty env_index → parent resolves to None → not IDE → gate blocks
        let result = idx.resolve_tool(
            Some("com.github.copilot"),
            None,
            None,
            None,
            &EnvIndex::default(),
        );
        assert!(result.is_none(), "IdePlugin must not match when parent environment is unknown");
    }

    #[test]
    fn cli_matches_regardless_of_parent() {
        // Cli kind has no parent gate — must match even when parent is a terminal
        let idx = EntityIndex::build(sample_entries());
        let env = EnvIndex::build(&[crate::bundle::env_index::BundleEnvironment {
            slug: "zsh".into(),
            class: EnvironmentClass::Terminal,
            bundle_ids: vec![],
            process_names: vec!["zsh".into()],
        }]);

        let result = idx.resolve_tool(None, Some("claude-code"), None, Some("zsh"), &env);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0.kind, EntityKind::Cli);
    }

    #[test]
    fn entity_kind_round_trip() {
        assert_eq!(EntityKind::from_str_loose("ide"), EntityKind::Ide);
        assert_eq!(EntityKind::from_str_loose("ide_plugin"), EntityKind::IdePlugin);
        assert_eq!(EntityKind::from_str_loose("ide-plugin"), EntityKind::IdePlugin);
        assert_eq!(EntityKind::from_str_loose("CLI"), EntityKind::Cli);
        assert_eq!(EntityKind::from_str_loose("browser"), EntityKind::Browser);
        assert_eq!(EntityKind::from_str_loose("platform"), EntityKind::Platform);
        assert_eq!(EntityKind::from_str_loose("agent-app"), EntityKind::AgentApp);
        assert_eq!(EntityKind::from_str_loose("browser_app"), EntityKind::BrowserApp);
        assert_eq!(EntityKind::from_str_loose("garbage"), EntityKind::Other);
    }

    #[test]
    fn entity_kind_to_app_type_via_surface() {
        assert_eq!(EntityKind::Browser.to_surface_type().app_type(), AppType::Host);
        assert_eq!(EntityKind::BrowserApp.to_surface_type().app_type(), AppType::Host);
        assert_eq!(EntityKind::Ide.to_surface_type().app_type(), AppType::NonHost);
        assert_eq!(EntityKind::IdePlugin.to_surface_type().app_type(), AppType::NonHost);
        assert_eq!(EntityKind::Cli.to_surface_type().app_type(), AppType::NonHost);
        assert_eq!(EntityKind::Platform.to_surface_type().app_type(), AppType::NonHost);
        assert_eq!(EntityKind::Other.to_surface_type().app_type(), AppType::Unknown);
    }

    #[test]
    fn ide_vs_ide_plugin_surface_type() {
        use crate::classify::SurfaceType;
        assert_eq!(EntityKind::Ide.to_surface_type(), SurfaceType::Ide);
        assert_eq!(EntityKind::IdePlugin.to_surface_type(), SurfaceType::IdePlugin);
    }

    #[test]
    fn source_class_backward_compat() {
        assert_eq!(EntityKind::Browser.source_class(), "browser");
        assert_eq!(EntityKind::BrowserApp.source_class(), "browser");
        assert_eq!(EntityKind::Ide.source_class(), "agent_app");
        assert_eq!(EntityKind::IdePlugin.source_class(), "agent_app");
        assert_eq!(EntityKind::Cli.source_class(), "agent_app");
        assert_eq!(EntityKind::Other.source_class(), "unknown");
    }
}
