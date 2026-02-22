use super::provider::{DetectionSpec, EntryType, ModelPricing};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[path = "bundle_parse.rs"]
mod bundle_parse;
pub use bundle_parse::{parse_compiled_bundle, parse_provider_definitions};

#[cfg(test)]
#[path = "bundle_tests.rs"]
mod tests;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BundleType {
    Local,
    Cloud,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FilterAction {
    Capture,
    Noise,
    Passthrough,
    Tunnel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainIndexEntry {
    pub host: String,
    pub provider_id: String,
    pub entry_type: EntryType,
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DomainFilters {
    #[serde(default)]
    pub whitelist: Vec<String>,
    #[serde(default)]
    pub blacklist: Vec<String>,
    #[serde(default)]
    pub passthrough: Vec<String>,
    #[serde(default)]
    pub noise_keywords: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AllowedAppOrigins {
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub non_hosts: Vec<String>,
    #[serde(default)]
    pub apps_with_parsers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct BundleGating {
    #[serde(default)]
    pub allowed_app_origins: AllowedAppOrigins,
    #[serde(default)]
    pub allowed_host_origins: Vec<String>,
}

fn default_true() -> bool {
    true
}

fn connect_policy_version() -> u32 {
    1
}

fn decision_rules_version() -> u32 {
    1
}

fn default_non_whitelisted_host_action() -> String {
    "tunnel".to_string()
}

fn default_unknown_connect_app_action() -> String {
    "host_only".to_string()
}

fn default_whitelisted_unknown_app_action() -> String {
    "intercept".to_string()
}

fn default_host_miss_action() -> String {
    "tunnel".to_string()
}

fn default_non_host_miss_action() -> String {
    "metadata_only".to_string()
}

fn default_unknown_request_app_action() -> String {
    "metadata_only".to_string()
}

fn default_path_precedence() -> Vec<String> {
    vec![
        "deny_paths_exact".to_string(),
        "deny_paths_glob".to_string(),
        "allow_paths".to_string(),
    ]
}

fn default_whitelist_path_miss_reason() -> String {
    "whitelist_path_miss".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ConnectPolicy {
    #[serde(default = "connect_policy_version")]
    pub version: u32,
    #[serde(default)]
    pub defaults: ConnectPolicyDefaults,
    #[serde(default)]
    pub rules: Vec<ConnectPolicyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConnectPolicyDefaults {
    #[serde(default = "default_non_whitelisted_host_action")]
    pub non_whitelisted_host_action: String,
    #[serde(default = "default_unknown_connect_app_action")]
    pub unknown_app_action: String,
    #[serde(default = "default_whitelisted_unknown_app_action")]
    pub whitelisted_unknown_app_action: String,
}

impl Default for ConnectPolicyDefaults {
    fn default() -> Self {
        Self {
            non_whitelisted_host_action: default_non_whitelisted_host_action(),
            unknown_app_action: default_unknown_connect_app_action(),
            whitelisted_unknown_app_action: default_whitelisted_unknown_app_action(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ConnectPolicyRule {
    #[serde(default)]
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub app_type: Vec<String>,
    #[serde(default)]
    pub app_identifiers: Vec<String>,
    #[serde(default)]
    pub host_allow: Vec<String>,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DecisionRules {
    #[serde(default = "decision_rules_version")]
    pub version: u32,
    #[serde(default)]
    pub defaults: DecisionRuleDefaults,
    #[serde(default)]
    pub rules: Vec<DecisionRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DecisionRuleDefaults {
    #[serde(default = "default_host_miss_action")]
    pub host_miss_action: String,
    #[serde(default = "default_non_host_miss_action")]
    pub non_host_miss_action: String,
    #[serde(default = "default_unknown_request_app_action")]
    pub unknown_app_action: String,
    #[serde(default = "default_path_precedence")]
    pub path_precedence: Vec<String>,
    #[serde(default = "default_whitelist_path_miss_reason")]
    pub whitelist_path_miss_reason: String,
}

impl Default for DecisionRuleDefaults {
    fn default() -> Self {
        Self {
            host_miss_action: default_host_miss_action(),
            non_host_miss_action: default_non_host_miss_action(),
            unknown_app_action: default_unknown_request_app_action(),
            path_precedence: default_path_precedence(),
            whitelist_path_miss_reason: default_whitelist_path_miss_reason(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DecisionRule {
    #[serde(default)]
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: i64,
    #[serde(default)]
    pub host_pattern: String,
    #[serde(default)]
    pub app_type: Vec<String>,
    #[serde(default)]
    pub method: Vec<String>,
    #[serde(default)]
    pub allow_paths: Vec<String>,
    #[serde(default)]
    pub deny_paths_exact: Vec<String>,
    #[serde(default)]
    pub deny_paths_glob: Vec<String>,
    #[serde(default)]
    pub detection_id: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub capture_mode: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct BundleStats {
    #[serde(default)]
    pub providers: usize,
    #[serde(default)]
    pub domains: usize,
    #[serde(default)]
    pub formats: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResolvedProvider {
    pub id: String,
    #[serde(default)]
    pub detection_id: Option<String>,
    pub name: String,
    #[serde(rename = "type")]
    pub entry_type: EntryType,
    #[serde(default)]
    pub api_format: Option<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub user_agent_patterns: Vec<String>,
    #[serde(default)]
    pub detection: Option<DetectionSpec>,
}

pub fn compiled_bundle_schema_version() -> u32 {
    3
}

fn is_supported_compiled_bundle_schema_version(schema_version: u32) -> bool {
    matches!(schema_version, 1..=4)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompiledBundle {
    #[serde(default = "compiled_bundle_schema_version")]
    pub schema_version: u32,
    pub version: String,
    pub compiled_at: String,
    pub bundle_type: BundleType,
    #[serde(default)]
    pub domain_index: Vec<DomainIndexEntry>,
    #[serde(default)]
    pub providers: BTreeMap<String, ResolvedProvider>,
    #[serde(default)]
    pub filters: DomainFilters,
    #[serde(default)]
    pub pricing: BTreeMap<String, BTreeMap<String, ModelPricing>>,
    #[serde(default)]
    pub stats: BundleStats,
    #[serde(default)]
    pub formats: BTreeMap<String, Value>,
    #[serde(default)]
    pub catalog_domains: Vec<String>,
    #[serde(default)]
    pub gating: BundleGating,
    #[serde(default)]
    pub connect_policy: ConnectPolicy,
    #[serde(default)]
    pub decision_rules: DecisionRules,
    #[serde(default)]
    pub meta: Option<Value>,
    #[serde(default)]
    pub signatures: Option<Value>,
}

impl CompiledBundle {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !is_supported_compiled_bundle_schema_version(self.schema_version) {
            anyhow::bail!(
                "unsupported compiled bundle schema_version {} (supported: 1, 2, 3, 4)",
                self.schema_version,
            );
        }
        if self.version.trim().is_empty() {
            anyhow::bail!("compiled bundle version is required");
        }
        if self.compiled_at.trim().is_empty() {
            anyhow::bail!("compiled bundle compiled_at is required");
        }
        if self.providers.is_empty() {
            anyhow::bail!("compiled bundle must include at least one provider");
        }
        for (provider_id, provider) in &self.providers {
            if provider_id.trim().is_empty() {
                anyhow::bail!("provider map key cannot be empty");
            }
            if provider.id.trim().is_empty() {
                anyhow::bail!("provider `{provider_id}` id cannot be empty");
            }
            if provider.id != *provider_id {
                anyhow::bail!(
                    "provider map key `{provider_id}` does not match provider.id `{}`",
                    provider.id
                );
            }
            if provider
                .detection_id
                .as_ref()
                .is_some_and(|detection_id| detection_id.trim().is_empty())
            {
                anyhow::bail!("provider `{provider_id}` has empty detection_id");
            }
        }
        for entry in &self.domain_index {
            if entry.host.trim().is_empty() {
                anyhow::bail!("domain_index host cannot be empty");
            }
            if entry.provider_id.trim().is_empty() {
                anyhow::bail!("domain_index provider_id cannot be empty");
            }
            if !self.providers.contains_key(&entry.provider_id) {
                anyhow::bail!(
                    "domain_index host `{}` references unknown provider `{}`",
                    entry.host,
                    entry.provider_id
                );
            }
        }
        for (idx, rule) in self.decision_rules.rules.iter().enumerate() {
            if !rule.enabled {
                continue;
            }
            if rule.host_pattern.trim().is_empty() {
                anyhow::bail!("decision_rules.rules[{idx}] host_pattern cannot be empty");
            }
            if rule.allow_paths.is_empty() {
                anyhow::bail!("decision_rules.rules[{idx}] allow_paths cannot be empty");
            }
        }
        Ok(())
    }
}
