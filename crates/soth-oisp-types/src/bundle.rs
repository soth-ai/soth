use crate::provider::{EntryType, ModelPricing, ProviderDefinition};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

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
    pub name: String,
    #[serde(rename = "type")]
    pub entry_type: EntryType,
    #[serde(default)]
    pub api_format: Option<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub user_agent_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompiledBundle {
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
}

impl CompiledBundle {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.version.trim().is_empty() {
            anyhow::bail!("compiled bundle version is required");
        }
        if self.providers.is_empty() {
            anyhow::bail!("compiled bundle must include at least one provider");
        }
        Ok(())
    }
}

pub fn parse_compiled_bundle(value: &Value) -> anyhow::Result<CompiledBundle> {
    let bundle: CompiledBundle =
        serde_json::from_value(value.clone()).context("invalid compiled bundle schema")?;
    bundle.validate()?;
    Ok(bundle)
}

pub fn parse_provider_definitions(value: &Value) -> anyhow::Result<Vec<ProviderDefinition>> {
    let providers: Vec<ProviderDefinition> =
        serde_json::from_value(value.clone()).context("invalid provider definition schema")?;
    if providers.is_empty() {
        anyhow::bail!("provider definition list cannot be empty");
    }
    Ok(providers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_compiled_bundle_accepts_minimal_valid_shape() {
        let value = json!({
            "version": "2026.02.13-r1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "cloud",
            "domain_index": [],
            "providers": {
                "openai": {
                    "id": "openai",
                    "name": "OpenAI",
                    "type": "ai-inference",
                    "domains": ["api.openai.com"]
                }
            },
            "filters": {},
            "pricing": {},
            "stats": {}
        });

        let parsed = parse_compiled_bundle(&value).unwrap();
        assert_eq!(parsed.version, "2026.02.13-r1");
        assert!(parsed.providers.contains_key("openai"));
    }

    #[test]
    fn parse_compiled_bundle_rejects_missing_providers() {
        let value = json!({
            "version": "2026.02.13-r1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "cloud",
            "providers": {}
        });
        let err = parse_compiled_bundle(&value).unwrap_err();
        assert!(err.to_string().contains("at least one provider"));
    }
}
