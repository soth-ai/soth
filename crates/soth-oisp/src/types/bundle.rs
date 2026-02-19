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
    #[serde(default)]
    pub provider_entity_id: Option<String>,
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
    pub entity_id: Option<String>,
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
    matches!(schema_version, 1..=3)
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
    pub meta: Option<Value>,
    #[serde(default)]
    pub signatures: Option<Value>,
}

impl CompiledBundle {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !is_supported_compiled_bundle_schema_version(self.schema_version) {
            anyhow::bail!(
                "unsupported compiled bundle schema_version {} (supported: 1, 2, 3)",
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
                .entity_id
                .as_ref()
                .is_some_and(|entity_id| entity_id.trim().is_empty())
            {
                anyhow::bail!("provider `{provider_id}` has empty entity_id");
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
        Ok(())
    }
}
