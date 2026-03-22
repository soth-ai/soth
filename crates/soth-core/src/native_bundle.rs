//! NativeBundle wire types — the shared contract between soth-cloud (compiler)
//! and the edge proxy (consumer).
//!
//! These types are the canonical schema for compiled bundle JSON payloads.
//! They were originally defined in `soth-interface` (the cloud-side crate) and
//! are duplicated here so the edge proxy workspace is fully self-contained
//! without a cross-repo path dependency.
//!
//! **Keep in sync** with `soth-cloud/crates/soth-interface/src/registry.rs`
//! whenever the bundle schema changes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const NATIVE_BUNDLE_SCHEMA_VERSION: i32 = 4;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NativeBundle {
    pub schema_version: i32,
    pub metadata: NativeBundleMetadata,
    #[serde(default)]
    pub vendors: Vec<NativeBundleVendor>,
    #[serde(default, alias = "providers")]
    pub llm_providers: Vec<NativeBundleEntity>,
    #[serde(default, alias = "applications")]
    pub products: Vec<NativeBundleEntity>,
    #[serde(default)]
    pub formats: Vec<NativeBundleFormat>,
    #[serde(default)]
    pub filters: Vec<NativeBundleFilter>,
    #[serde(default)]
    pub settings: Vec<NativeBundleSetting>,
    #[serde(default)]
    pub domain_index: BTreeMap<String, Vec<NativeBundleDomainIndexEntry>>,
    #[serde(default)]
    pub entities: Vec<NativeBundleEntity>,
    #[serde(default)]
    pub tool_catalog: Vec<NativeBundleCatalogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NativeBundleMetadata {
    pub version: String,
    pub compiled_at: String,
    pub compiled_by: String,
    pub notes: Option<String>,
    pub vendor_count: usize,
    #[serde(alias = "provider_count")]
    pub llm_provider_count: usize,
    #[serde(alias = "application_count")]
    pub product_count: usize,
    pub rule_count: usize,
    pub format_count: usize,
    pub filter_count: usize,
    pub settings_count: usize,
    #[serde(default)]
    pub entity_count: usize,
    #[serde(default)]
    pub tool_catalog_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NativeBundleVendor {
    pub slug: String,
    pub name: String,
    pub vendor_url: Option<String>,
    pub hq_country: Option<String>,
    pub hq_city: Option<String>,
    #[serde(default)]
    pub metadata: Value,
    #[serde(default)]
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NativeBundleEntity {
    pub slug: String,
    #[serde(default)]
    pub entity_kind: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    pub vendor_slug: Option<String>,
    pub name: String,
    pub category: Option<String>,
    pub subtype: Option<String>,
    pub api_format: Option<String>,
    pub description: Option<String>,
    pub notes: Option<String>,
    pub primary_url: Option<String>,
    pub docs_url: Option<String>,
    pub logo_url: Option<String>,
    pub primary_domain: Option<String>,
    pub risk_level: Option<String>,
    pub risk_score: Option<i32>,
    pub capture: NativeBundleCapture,
    #[serde(default)]
    pub metadata: Value,
    #[serde(default)]
    pub details: Value,
    #[serde(default)]
    pub matching_rules: Vec<NativeBundleRule>,
    #[serde(default)]
    pub provider_links: Vec<NativeBundleProviderLink>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NativeBundleCapture {
    pub mode: String,
    #[serde(default)]
    pub methods: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NativeBundleRule {
    #[serde(alias = "rule_key")]
    pub rule_id: String,
    pub priority: u32,
    pub requires_all: bool,
    pub notes: Option<String>,
    #[serde(default)]
    pub metadata: Value,
    #[serde(default)]
    pub signals: Vec<NativeBundleSignal>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NativeBundleSignal {
    #[serde(alias = "signal_kind")]
    pub kind: String,
    #[serde(alias = "signal_name")]
    pub name: Option<String>,
    #[serde(alias = "signal_pattern")]
    pub pattern: String,
    #[serde(default)]
    pub is_negated: bool,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NativeBundleProviderLink {
    pub provider_slug: String,
    pub relation_kind: String,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NativeBundleFormat {
    pub entity_kind: Option<String>,
    pub entity_slug: Option<String>,
    pub format_key: String,
    pub format_type: String,
    #[serde(default)]
    pub definition: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NativeBundleFilter {
    pub filter_key: String,
    pub filter_type: String,
    #[serde(default)]
    pub definition: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NativeBundleSetting {
    pub setting_key: String,
    #[serde(default)]
    pub definition: Value,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NativeBundleCatalogEntry {
    pub slug: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor_slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default)]
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct NativeBundleDomainIndexEntry {
    #[serde(alias = "entity_kind")]
    pub entity_type: String,
    pub entity_slug: String,
    #[serde(default)]
    pub rule_id: String,
    pub priority: u32,
}
