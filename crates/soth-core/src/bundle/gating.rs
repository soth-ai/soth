use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{AppType, CaptureMode};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GatingBundle {
    pub identity_index: IdentityIndex,
    pub gates: GateConfig,
    pub entities: EntityCatalog,
}

impl GatingBundle {
    pub fn normalize_host_patterns_in_place(&mut self) {
        self.gates.stage0_tls.tls_intercept_hosts =
            normalize_host_pattern_set(&self.gates.stage0_tls.tls_intercept_hosts);
        self.gates.stage0_tls.passthrough_domains =
            normalize_host_pattern_set(&self.gates.stage0_tls.passthrough_domains);
        self.gates.stage5_host_origin.allowed_host_origins =
            normalize_host_pattern_set(&self.gates.stage5_host_origin.allowed_host_origins);

        normalize_entity_hosts(&mut self.entities.providers);
        normalize_entity_hosts(&mut self.entities.web_apps);
        normalize_entity_hosts(&mut self.entities.native_apps);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentityIndex {
    #[serde(default)]
    pub hosts: HashMap<String, IdentityEntry>,
    #[serde(default)]
    pub non_hosts: HashMap<String, IdentityEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityEntry {
    pub entity_id: EntityId,
    pub app_type: AppType,
    pub capture_mode: CaptureMode,
    pub action: ProcessAction,
}

impl Default for IdentityEntry {
    fn default() -> Self {
        Self {
            entity_id: "unknown".to_string(),
            app_type: AppType::Unknown,
            capture_mode: CaptureMode::MetadataOnly,
            action: ProcessAction::Intercept,
        }
    }
}

pub type EntityId = String;
pub type HostPattern = String;
pub type HttpMethod = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProcessAction {
    #[default]
    Intercept,
    Skip,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GateConfig {
    #[serde(default)]
    pub order: Vec<GateStage>,
    pub defaults: GateDefaults,
    pub stage0_tls: Stage0Config,
    pub stage1_app_origin: Stage1Config,
    pub stage2_whitelist: Stage2Config,
    pub stage3_blacklist: Stage3Config,
    pub stage4_app_type: Stage4Config,
    pub stage5_host_origin: Stage5Config,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStage {
    Stage0Tls,
    Stage1AppOrigin,
    Stage2Whitelist,
    Stage3Blacklist,
    Stage4AppType,
    Stage5HostOrigin,
    Intercept,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateDefaults {
    pub sensor_enabled: bool,
    pub fail_open_on_config_error: bool,
    pub unknown_app_action: UnknownAppAction,
    pub non_cataloged_host_action: NonCatalogedAction,
    pub discovery: DiscoveryConfig,
}

impl Default for GateDefaults {
    fn default() -> Self {
        Self {
            sensor_enabled: true,
            fail_open_on_config_error: true,
            unknown_app_action: UnknownAppAction::Skip,
            non_cataloged_host_action: NonCatalogedAction::Skip,
            discovery: DiscoveryConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    pub unknown_app_daily_limit: u32,
    pub unknown_domain_daily_limit: u32,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            unknown_app_daily_limit: 1,
            unknown_domain_daily_limit: 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UnknownAppAction {
    #[default]
    Skip,
    Intercept,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NonCatalogedAction {
    #[default]
    Skip,
    Passthrough,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Stage0Config {
    #[serde(default)]
    pub tls_intercept_hosts: HashSet<HostPattern>,
    #[serde(default)]
    pub passthrough_domains: HashSet<HostPattern>,
    #[serde(default)]
    pub enable_discovery: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Stage1Config {
    #[serde(default)]
    pub skip_if_unresolved_process: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage2Config {
    pub allow_empty_means_allow_all_except_denied: bool,
}

impl Default for Stage2Config {
    fn default() -> Self {
        Self {
            allow_empty_means_allow_all_except_denied: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage3Config {
    #[serde(default)]
    pub blacklisted_keywords: Vec<String>,
    #[serde(default)]
    pub blacklisted_path_substrings: Vec<String>,
    #[serde(default)]
    pub graphql_operation_blacklist: Vec<String>,
    #[serde(default)]
    pub graphql_operation_blacklist_enabled: bool,
    pub match_type: BlacklistMatchType,
}

impl Default for Stage3Config {
    fn default() -> Self {
        Self {
            blacklisted_keywords: Vec::new(),
            blacklisted_path_substrings: Vec::new(),
            graphql_operation_blacklist: Vec::new(),
            graphql_operation_blacklist_enabled: false,
            match_type: BlacklistMatchType::CaseInsensitiveSubstring,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BlacklistMatchType {
    #[default]
    CaseInsensitiveSubstring,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage4Config {
    pub derive_from_identity_index: bool,
}

impl Default for Stage4Config {
    fn default() -> Self {
        Self {
            derive_from_identity_index: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Stage5Config {
    #[serde(default)]
    pub allowed_host_origins: HashSet<String>,
    #[serde(default)]
    pub skip_for_discovery_capture: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EntityCatalog {
    #[serde(default)]
    pub providers: Vec<EntityTrafficRules>,
    #[serde(default)]
    pub web_apps: Vec<EntityTrafficRules>,
    #[serde(default)]
    pub native_apps: Vec<EntityTrafficRules>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityTrafficRules {
    pub entity_id: EntityId,
    pub capture_mode: CaptureMode,
    #[serde(default)]
    pub hosts: Vec<HostRule>,
}

impl Default for EntityTrafficRules {
    fn default() -> Self {
        Self {
            entity_id: "unknown".to_string(),
            capture_mode: CaptureMode::MetadataOnly,
            hosts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostRule {
    pub pattern: HostPattern,
    #[serde(default)]
    pub methods: Vec<HttpMethod>,
    pub paths: PathRules,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathRules {
    #[serde(default)]
    pub deny_exact: Vec<String>,
    #[serde(default)]
    pub deny_glob: Vec<String>,
    #[serde(default)]
    pub allow: Vec<String>,
}

pub fn normalize_bundle_host_pattern(value: &str) -> Option<String> {
    let raw = value.trim().to_ascii_lowercase();
    if raw.is_empty() {
        return None;
    }
    let anchored_end = raw.ends_with('$');
    let had_wildcard = raw.contains('*');

    let mut normalized = raw
        .split_once("://")
        .map(|(_, rest)| rest.to_string())
        .unwrap_or(raw);

    if let Some((head, _)) = normalized.split_once('/') {
        normalized = head.to_string();
    }
    if let Some((head, _)) = normalized.split_once('?') {
        normalized = head.to_string();
    }
    if let Some((head, _)) = normalized.split_once('#') {
        normalized = head.to_string();
    }

    normalized = normalized
        .trim_start_matches('^')
        .trim_end_matches('$')
        .to_string();
    normalized = normalized.replace("\\.", ".");
    normalized = normalized.replace(".*", "*");
    normalized = normalized.replace("**", "*");
    normalized = normalized.trim_end_matches(':').to_string();

    if !normalized.contains('*') {
        if let Some((host, port)) = normalized.rsplit_once(':') {
            if !host.contains(':') && port.chars().all(|c| c.is_ascii_digit()) {
                normalized = host.to_string();
            }
        }
    }

    normalized = normalized.trim().trim_matches('.').to_string();

    if normalized.is_empty() {
        None
    } else if anchored_end && !had_wildcard {
        Some(format!("={normalized}"))
    } else {
        Some(normalized)
    }
}

fn normalize_host_pattern_set(input: &HashSet<String>) -> HashSet<String> {
    input
        .iter()
        .filter_map(|value| normalize_bundle_host_pattern(value))
        .collect::<HashSet<_>>()
}

fn normalize_entity_hosts(rules: &mut [EntityTrafficRules]) {
    for rule in rules {
        for host in &mut rule.hosts {
            host.pattern = normalize_bundle_host_pattern(host.pattern.as_str()).unwrap_or_default();
        }
        rule.hosts.retain(|host| !host.pattern.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn normalize_bundle_host_pattern_converts_regex_like_forms() {
        let cases = [
            (".*.apple.com$", "*.apple.com"),
            ("^.*\\.manus\\.computer$", "*.manus.computer"),
            ("^f-log-.*\\.grammarly\\.io$", "f-log-*.grammarly.io"),
            (
                "^multiplayer\\.api\\.gamma\\.app$",
                "=multiplayer.api.gamma.app",
            ),
            ("accounts.google.com$", "=accounts.google.com"),
            ("api.apple-cloudkit.com:", "api.apple-cloudkit.com"),
        ];

        for (input, expected) in cases {
            assert_eq!(
                normalize_bundle_host_pattern(input).as_deref(),
                Some(expected),
                "input={input}"
            );
        }
    }

    #[test]
    fn normalize_bundle_in_place_applies_to_gate_sets() {
        let mut bundle = GatingBundle::default();
        bundle
            .gates
            .stage0_tls
            .passthrough_domains
            .insert("^.*\\.manus\\.computer$".to_string());
        bundle
            .gates
            .stage0_tls
            .passthrough_domains
            .insert("^multiplayer\\.api\\.gamma\\.app$".to_string());
        bundle
            .gates
            .stage5_host_origin
            .allowed_host_origins
            .insert("https://ChatGPT.com/".to_string());
        bundle.entities.providers.push(EntityTrafficRules {
            entity_id: "p".to_string(),
            capture_mode: CaptureMode::MetadataOnly,
            hosts: vec![HostRule {
                pattern: "^f-log-.*\\.grammarly\\.io$".to_string(),
                methods: Vec::new(),
                paths: PathRules::default(),
            }],
        });

        bundle.normalize_host_patterns_in_place();

        let passthrough = &bundle.gates.stage0_tls.passthrough_domains;
        assert!(passthrough.contains("*.manus.computer"));
        assert!(passthrough.contains("=multiplayer.api.gamma.app"));
        assert!(bundle
            .gates
            .stage5_host_origin
            .allowed_host_origins
            .contains("chatgpt.com"));
        assert_eq!(
            bundle.entities.providers[0].hosts[0].pattern,
            "f-log-*.grammarly.io"
        );

        let unique = passthrough.iter().cloned().collect::<HashSet<_>>();
        assert_eq!(unique.len(), passthrough.len());
    }
}
