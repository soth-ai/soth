use super::provider::{EntryType, ModelPricing, ProviderDefinition};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
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
}

pub fn compiled_bundle_schema_version() -> u32 {
    3
}

fn is_supported_compiled_bundle_schema_version(schema_version: u32) -> bool {
    matches!(schema_version, 1 | 2 | 3)
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

pub fn parse_compiled_bundle(value: &Value) -> anyhow::Result<CompiledBundle> {
    let mut primary_validation_error: Option<anyhow::Error> = None;

    if let Ok(mut bundle) = serde_json::from_value::<CompiledBundle>(value.clone()) {
        normalize_compiled_bundle(&mut bundle);
        match bundle.validate() {
            Ok(()) => return Ok(bundle),
            Err(error) => primary_validation_error = Some(error),
        }
    }

    if let Ok(mut bundle) = parse_sectioned_bundle(value) {
        normalize_compiled_bundle(&mut bundle);
        match bundle.validate() {
            Ok(()) => return Ok(bundle),
            Err(error) => {
                if primary_validation_error.is_none() {
                    primary_validation_error = Some(error);
                }
            }
        }
    }

    let mut bundle = match parse_catalog_bundle(value) {
        Ok(bundle) => bundle,
        Err(error) => {
            if let Some(primary) = primary_validation_error {
                return Err(primary);
            }
            return Err(error.context("invalid compiled bundle schema"));
        }
    };
    normalize_compiled_bundle(&mut bundle);
    if let Err(error) = bundle.validate() {
        if let Some(primary) = primary_validation_error {
            return Err(primary);
        }
        return Err(error);
    }
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

fn parse_catalog_bundle(value: &Value) -> anyhow::Result<CompiledBundle> {
    let object = value
        .as_object()
        .context("catalog bundle root must be a JSON object")?;

    let version = object
        .get("version")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or("unknown")
        .to_string();
    let compiled_at = object
        .get("compiled_at")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or("unknown")
        .to_string();
    let bundle_type = parse_bundle_type(object.get("bundle_type").and_then(Value::as_str));

    let providers = parse_catalog_providers(
        object
            .get("providers")
            .and_then(Value::as_object)
            .context("catalog bundle requires providers object")?,
    )?;
    let provider_path_hints = collect_provider_path_hints(
        object
            .get("providers")
            .and_then(Value::as_object)
            .context("catalog bundle requires providers object")?,
    );

    let interception_patterns = object
        .get("interception_patterns")
        .and_then(Value::as_object);
    let domain_index = parse_catalog_domain_index(
        object
            .get("domain_index")
            .context("catalog bundle requires domain_index")?,
        &providers,
        &provider_path_hints,
        interception_patterns,
    )?;
    let filters = parse_catalog_filters(object, &domain_index, interception_patterns)?;
    let pricing = parse_pricing_catalog(object.get("pricing"));

    let stats = object
        .get("stats")
        .cloned()
        .and_then(|raw| serde_json::from_value::<BundleStats>(raw).ok())
        .unwrap_or(BundleStats {
            providers: providers.len(),
            domains: domain_index.len(),
            formats: object
                .get("formats")
                .and_then(Value::as_object)
                .map(|formats| formats.len())
                .unwrap_or(0),
        });

    let formats = object
        .get("formats")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let catalog_domains = parse_catalog_domains(object, None);

    Ok(CompiledBundle {
        schema_version: compiled_bundle_schema_version(),
        version,
        compiled_at,
        bundle_type,
        domain_index,
        providers,
        filters,
        pricing,
        stats,
        formats,
        catalog_domains,
        meta: object.get("meta").cloned(),
        signatures: object.get("signatures").cloned(),
    })
}

fn parse_sectioned_bundle(value: &Value) -> anyhow::Result<CompiledBundle> {
    let root = value
        .as_object()
        .context("sectioned bundle root must be a JSON object")?;
    let core = root
        .get("core")
        .and_then(Value::as_object)
        .context("sectioned bundle requires core section")?;

    let version = root
        .get("version")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or("unknown")
        .to_string();
    let compiled_at = root
        .get("compiled_at")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or("unknown")
        .to_string();
    let bundle_type = parse_bundle_type(root.get("bundle_type").and_then(Value::as_str));
    let schema_version = root
        .get("schema_version")
        .and_then(Value::as_u64)
        .map(|value| value as u32)
        .unwrap_or(compiled_bundle_schema_version());

    let providers_raw = core
        .get("providers")
        .context("sectioned bundle core.providers is required")?;
    let providers = parse_providers_any_shape(providers_raw)?;
    let provider_path_hints = providers_raw
        .as_object()
        .map(collect_provider_path_hints)
        .unwrap_or_default();
    let interception_patterns = core
        .get("interception_patterns")
        .and_then(Value::as_object)
        .or_else(|| root.get("interception_patterns").and_then(Value::as_object));
    let domain_index = parse_catalog_domain_index(
        core.get("domain_index")
            .context("sectioned bundle core.domain_index is required")?,
        &providers,
        &provider_path_hints,
        interception_patterns,
    )?;
    let filters = parse_filters_section(root, core, &domain_index, interception_patterns)?;
    let pricing = parse_pricing_catalog(core.get("pricing").or_else(|| root.get("pricing")));
    let formats = root
        .get("formats")
        .or_else(|| core.get("formats"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let catalog_domains = parse_catalog_domains(root, Some(core));

    let stats = root
        .get("stats")
        .cloned()
        .and_then(|raw| serde_json::from_value::<BundleStats>(raw).ok())
        .unwrap_or(BundleStats {
            providers: providers.len(),
            domains: domain_index.len(),
            formats: formats.len(),
        });

    Ok(CompiledBundle {
        schema_version,
        version,
        compiled_at,
        bundle_type,
        domain_index,
        providers,
        filters,
        pricing,
        stats,
        formats,
        catalog_domains,
        meta: root.get("meta").cloned(),
        signatures: root.get("signatures").cloned(),
    })
}

fn parse_providers_any_shape(value: &Value) -> anyhow::Result<BTreeMap<String, ResolvedProvider>> {
    if let Ok(parsed) = serde_json::from_value::<BTreeMap<String, ResolvedProvider>>(value.clone())
    {
        return Ok(parsed);
    }
    let providers_value = value
        .as_object()
        .context("providers section must be an object")?;
    parse_catalog_providers(providers_value)
}

fn parse_catalog_providers(
    providers_value: &Map<String, Value>,
) -> anyhow::Result<BTreeMap<String, ResolvedProvider>> {
    let mut providers = BTreeMap::new();
    for (provider_id, provider_value) in providers_value {
        let provider_obj = provider_value
            .as_object()
            .with_context(|| format!("provider `{provider_id}` entry must be object"))?;

        let entry_type = parse_entry_type(provider_obj.get("category").and_then(Value::as_str));
        let name = provider_obj
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .unwrap_or(provider_id)
            .to_string();
        let api_format = provider_obj
            .get("api_format")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToString::to_string);
        let entity_id = provider_obj
            .get("entity_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToString::to_string);

        let mut domains = extract_string_array(provider_obj.get("api_domains"));
        let mut user_agent_patterns = extract_string_array(provider_obj.get("user_agent_patterns"));
        if let Some(detection) = provider_obj.get("detection").and_then(Value::as_object) {
            domains.extend(extract_string_array(detection.get("host_patterns")));
            user_agent_patterns.extend(extract_string_array(detection.get("header_hints")));
            domains.extend(extract_detection_rule_strings(
                detection,
                "host_rules",
                &["host", "pattern", "contains", "suffix", "regex", "value"],
            ));
            user_agent_patterns.extend(extract_detection_rule_strings(
                detection,
                "ua_rules",
                &["contains", "equals", "pattern", "regex", "value"],
            ));
        }
        dedup_sort_strings(&mut domains);
        dedup_sort_strings(&mut user_agent_patterns);

        providers.insert(
            provider_id.clone(),
            ResolvedProvider {
                id: provider_id.clone(),
                entity_id,
                name,
                entry_type,
                api_format,
                domains,
                user_agent_patterns,
            },
        );
    }
    Ok(providers)
}

fn collect_provider_path_hints(
    providers_value: &Map<String, Value>,
) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for (provider_id, provider_value) in providers_value {
        let Some(provider_obj) = provider_value.as_object() else {
            continue;
        };
        let mut paths = Vec::new();
        if let Some(detection) = provider_obj.get("detection").and_then(Value::as_object) {
            paths.extend(extract_string_array(detection.get("path_patterns")));
            paths.extend(extract_detection_rule_strings(
                detection,
                "path_rules",
                &["path", "pattern", "contains", "prefix", "regex", "value"],
            ));
        }
        if let Some(features) = provider_obj.get("features").and_then(Value::as_object) {
            for feature in features.values() {
                if let Some(patterns) = feature.get("patterns").and_then(Value::as_array) {
                    for pattern in patterns {
                        if let Some(raw) = pattern.as_str() {
                            let value = raw.trim();
                            if !value.is_empty() {
                                paths.push(value.to_string());
                            }
                        }
                    }
                }
            }
        }
        dedup_sort_strings(&mut paths);
        if !paths.is_empty() {
            out.insert(provider_id.clone(), paths);
        }
    }
    out
}

fn parse_catalog_domain_index(
    domain_index_value: &Value,
    providers: &BTreeMap<String, ResolvedProvider>,
    provider_path_hints: &BTreeMap<String, Vec<String>>,
    interception_patterns: Option<&Map<String, Value>>,
) -> anyhow::Result<Vec<DomainIndexEntry>> {
    if let Some(entries_array) = domain_index_value.as_array() {
        let mut entries: Vec<DomainIndexEntry> =
            if let Ok(parsed) = serde_json::from_value(Value::Array(entries_array.clone())) {
                parsed
            } else {
                entries_array
                    .iter()
                    .map(|entry| {
                        parse_catalog_domain_index_array_entry(
                            entry,
                            providers,
                            provider_path_hints,
                            interception_patterns,
                        )
                    })
                    .collect::<anyhow::Result<Vec<_>>>()
                    .context("failed parsing domain_index array")?
            };
        for entry in &mut entries {
            if let Some(extra) = provider_path_hints.get(&entry.provider_id) {
                entry.paths.extend(extra.iter().cloned());
            }
            if entry.provider_entity_id.is_none() {
                entry.provider_entity_id = providers
                    .get(&entry.provider_id)
                    .and_then(|provider| provider.entity_id.clone());
            }
            if let Some(host_rules) = interception_patterns
                .and_then(|patterns| patterns.get(&entry.host))
                .and_then(Value::as_array)
            {
                for rule in host_rules {
                    if let Some(path) = rule.get("path").and_then(Value::as_str) {
                        let value = path.trim();
                        if !value.is_empty() {
                            entry.paths.push(value.to_string());
                        }
                    }
                }
            }
            prune_catch_all_path_rules(&mut entry.paths, &entry.entry_type);
            dedup_sort_strings(&mut entry.paths);
        }
        return Ok(entries);
    }

    let entries_map = domain_index_value
        .as_object()
        .context("domain_index must be object or array")?;
    let mut out = Vec::new();
    for (host, entry_value) in entries_map {
        let entry_obj = entry_value
            .as_object()
            .with_context(|| format!("domain_index entry for `{host}` must be object"))?;
        let provider_id = entry_obj
            .get("provider")
            .and_then(Value::as_str)
            .or_else(|| entry_obj.get("provider_id").and_then(Value::as_str))
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .context(format!(
                "domain_index entry for `{host}` is missing provider/provider_id"
            ))?
            .to_string();

        let default_entry_type = providers
            .get(&provider_id)
            .map(|provider| provider.entry_type.clone())
            .unwrap_or(EntryType::AiInference);
        let entry_type = parse_entry_type_with_default(
            entry_obj.get("category").and_then(Value::as_str),
            default_entry_type,
        );

        let mut paths = extract_string_array(entry_obj.get("paths"));
        if let Some(extra) = provider_path_hints.get(&provider_id) {
            paths.extend(extra.iter().cloned());
        }
        if let Some(host_rules) = interception_patterns
            .and_then(|patterns| patterns.get(host))
            .and_then(Value::as_array)
        {
            for rule in host_rules {
                if let Some(path) = rule.get("path").and_then(Value::as_str) {
                    let value = path.trim();
                    if !value.is_empty() {
                        paths.push(value.to_string());
                    }
                }
            }
        }
        prune_catch_all_path_rules(&mut paths, &entry_type);
        dedup_sort_strings(&mut paths);
        let provider_entity_id = providers
            .get(&provider_id)
            .and_then(|provider| provider.entity_id.clone());

        out.push(DomainIndexEntry {
            host: host.clone(),
            provider_id,
            provider_entity_id,
            entry_type,
            paths,
        });
    }
    Ok(out)
}

fn parse_catalog_domain_index_array_entry(
    entry_value: &Value,
    providers: &BTreeMap<String, ResolvedProvider>,
    provider_path_hints: &BTreeMap<String, Vec<String>>,
    interception_patterns: Option<&Map<String, Value>>,
) -> anyhow::Result<DomainIndexEntry> {
    let entry_obj = entry_value
        .as_object()
        .context("domain_index array entry must be object")?;

    let host = entry_obj
        .get("host")
        .and_then(Value::as_str)
        .or_else(|| entry_obj.get("domain").and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .context("domain_index array entry missing host/domain")?
        .to_string();

    let provider_id = entry_obj
        .get("provider_id")
        .and_then(Value::as_str)
        .or_else(|| entry_obj.get("provider").and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .context(format!(
            "domain_index array entry for `{host}` missing provider/provider_id"
        ))?
        .to_string();

    let default_entry_type = providers
        .get(&provider_id)
        .map(|provider| provider.entry_type.clone())
        .unwrap_or(EntryType::AiInference);
    let entry_type = entry_obj
        .get("entry_type")
        .and_then(Value::as_str)
        .map(|raw| parse_entry_type_with_default(Some(raw), default_entry_type.clone()))
        .unwrap_or_else(|| {
            parse_entry_type_with_default(
                entry_obj.get("category").and_then(Value::as_str),
                default_entry_type,
            )
        });

    let mut paths = extract_string_array(entry_obj.get("paths"));
    if let Some(extra) = provider_path_hints.get(&provider_id) {
        paths.extend(extra.iter().cloned());
    }
    if let Some(host_rules) = interception_patterns
        .and_then(|patterns| patterns.get(&host))
        .and_then(Value::as_array)
    {
        for rule in host_rules {
            if let Some(path) = rule.get("path").and_then(Value::as_str) {
                let value = path.trim();
                if !value.is_empty() {
                    paths.push(value.to_string());
                }
            }
        }
    }
    prune_catch_all_path_rules(&mut paths, &entry_type);
    dedup_sort_strings(&mut paths);
    let provider_entity_id = providers
        .get(&provider_id)
        .and_then(|provider| provider.entity_id.clone());

    Ok(DomainIndexEntry {
        host,
        provider_id,
        provider_entity_id,
        entry_type,
        paths,
    })
}

fn parse_catalog_filters(
    root: &Map<String, Value>,
    domain_index: &[DomainIndexEntry],
    interception_patterns: Option<&Map<String, Value>>,
) -> anyhow::Result<DomainFilters> {
    if let Some(raw_filters) = root.get("filters") {
        let mut filters: DomainFilters =
            serde_json::from_value(raw_filters.clone()).context("invalid filters object")?;
        normalize_domain_filters(&mut filters);
        return Ok(filters);
    }

    let mut whitelist = interception_patterns
        .map(|patterns| patterns.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    if whitelist.is_empty() {
        whitelist = domain_index
            .iter()
            .map(|entry| entry.host.clone())
            .collect();
    }

    let mut passthrough =
        extract_string_array(root.get("passthrough").and_then(|v| v.get("domains")));
    passthrough.extend(
        extract_string_array(root.get("passthrough").and_then(|v| v.get("patterns")))
            .into_iter()
            .map(|pattern| normalize_pattern_for_host_matching(&pattern)),
    );
    let mut noise_keywords =
        extract_string_array(root.get("noise_filter").and_then(|v| v.get("words")));
    noise_keywords.extend(extract_string_array(
        root.get("noise_filter").and_then(|v| v.get("paths")),
    ));

    let mut filters = DomainFilters {
        whitelist,
        blacklist: Vec::new(),
        passthrough,
        noise_keywords,
    };
    normalize_domain_filters(&mut filters);
    Ok(filters)
}

fn parse_filters_section(
    root: &Map<String, Value>,
    core: &Map<String, Value>,
    domain_index: &[DomainIndexEntry],
    interception_patterns: Option<&Map<String, Value>>,
) -> anyhow::Result<DomainFilters> {
    if let Some(raw_filters) = root.get("filters").or_else(|| core.get("filters")) {
        let mut filters: DomainFilters =
            serde_json::from_value(raw_filters.clone()).context("invalid filters section")?;
        normalize_domain_filters(&mut filters);
        return Ok(filters);
    }
    parse_catalog_filters(root, domain_index, interception_patterns)
}

fn parse_catalog_domains(
    root: &Map<String, Value>,
    core: Option<&Map<String, Value>>,
) -> Vec<String> {
    let mut domains = Vec::new();
    domains.extend(extract_catalog_domains_from_value(
        root.get("catalog_domains"),
    ));
    domains.extend(extract_catalog_domains_from_value(
        root.get("catalog").or_else(|| root.get("tool_catalog")),
    ));

    if let Some(core) = core {
        domains.extend(extract_catalog_domains_from_value(
            core.get("catalog_domains"),
        ));
        domains.extend(extract_catalog_domains_from_value(core.get("catalog")));
    }

    dedup_sort_strings(&mut domains);
    domains
}

fn extract_catalog_domains_from_value(value: Option<&Value>) -> Vec<String> {
    let Some(value) = value else {
        return Vec::new();
    };
    if let Some(values) = value.as_array() {
        return values
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(ToString::to_string)
            .collect();
    }
    if let Some(object) = value.as_object() {
        let mut out = Vec::new();
        out.extend(extract_string_array(object.get("domains")));
        out.extend(extract_string_array(object.get("hosts")));
        out.extend(extract_string_array(object.get("catalog_domains")));
        out.extend(extract_string_array(object.get("sites")));
        return out;
    }
    Vec::new()
}

fn parse_pricing_catalog(
    value: Option<&Value>,
) -> BTreeMap<String, BTreeMap<String, ModelPricing>> {
    let Some(pricing_obj) = value.and_then(Value::as_object) else {
        return BTreeMap::new();
    };
    let mut out = BTreeMap::new();
    for (provider_id, provider_value) in pricing_obj {
        let models = parse_provider_pricing(provider_value);
        if !models.is_empty() {
            out.insert(provider_id.clone(), models);
        }
    }
    out
}

fn parse_provider_pricing(value: &Value) -> BTreeMap<String, ModelPricing> {
    let mut out = BTreeMap::new();

    if let Some(entries) = value.as_array() {
        for entry in entries {
            let model = entry
                .get("model_pattern")
                .and_then(Value::as_str)
                .or_else(|| entry.get("model").and_then(Value::as_str))
                .map(str::trim)
                .filter(|v| !v.is_empty());
            let Some(model) = model else {
                continue;
            };
            if let Some(pricing) = parse_model_pricing(entry) {
                out.insert(model.to_string(), pricing);
            }
        }
        return out;
    }

    let Some(obj) = value.as_object() else {
        return out;
    };

    if let Some(models) = obj.get("models").and_then(Value::as_object) {
        for (model, model_value) in models {
            if let Some(pricing) = parse_model_pricing(model_value) {
                out.insert(model.clone(), pricing);
            }
        }
        return out;
    }

    for (model, model_value) in obj {
        if let Some(pricing) = parse_model_pricing(model_value) {
            out.insert(model.clone(), pricing);
        }
    }
    out
}

fn parse_model_pricing(value: &Value) -> Option<ModelPricing> {
    if let Ok(parsed) = serde_json::from_value::<ModelPricing>(value.clone()) {
        if has_any_pricing_field(&parsed) {
            return Some(parsed);
        }
    }
    let object = value.as_object()?;
    let parsed = ModelPricing {
        input_per_million_usd: object
            .get("input_per_million_usd")
            .and_then(Value::as_f64)
            .or_else(|| object.get("input_per_million").and_then(Value::as_f64)),
        output_per_million_usd: object
            .get("output_per_million_usd")
            .and_then(Value::as_f64)
            .or_else(|| object.get("output_per_million").and_then(Value::as_f64)),
        cache_read_per_million_usd: object
            .get("cache_read_per_million_usd")
            .and_then(Value::as_f64)
            .or_else(|| object.get("cache_read_per_million").and_then(Value::as_f64)),
        cache_write_per_million_usd: object
            .get("cache_write_per_million_usd")
            .and_then(Value::as_f64)
            .or_else(|| {
                object
                    .get("cache_write_per_million")
                    .and_then(Value::as_f64)
            }),
    };
    has_any_pricing_field(&parsed).then_some(parsed)
}

fn has_any_pricing_field(pricing: &ModelPricing) -> bool {
    pricing.input_per_million_usd.is_some()
        || pricing.output_per_million_usd.is_some()
        || pricing.cache_read_per_million_usd.is_some()
        || pricing.cache_write_per_million_usd.is_some()
}

fn normalize_compiled_bundle(bundle: &mut CompiledBundle) {
    for provider in bundle.providers.values_mut() {
        provider.entity_id = normalize_optional_string(provider.entity_id.take());
        dedup_sort_strings(&mut provider.domains);
        dedup_sort_strings(&mut provider.user_agent_patterns);
    }
    for entry in &mut bundle.domain_index {
        entry.provider_entity_id = normalize_optional_string(entry.provider_entity_id.take());
        dedup_sort_strings(&mut entry.paths);
    }
    normalize_domain_filters(&mut bundle.filters);
    dedup_sort_strings(&mut bundle.catalog_domains);
    if bundle.stats.providers == 0 {
        bundle.stats.providers = bundle.providers.len();
    }
    if bundle.stats.domains == 0 {
        bundle.stats.domains = bundle.domain_index.len();
    }
}

fn normalize_domain_filters(filters: &mut DomainFilters) {
    dedup_sort_strings(&mut filters.whitelist);
    dedup_sort_strings(&mut filters.blacklist);
    dedup_sort_strings(&mut filters.passthrough);
    dedup_sort_strings(&mut filters.noise_keywords);
}

fn parse_bundle_type(raw: Option<&str>) -> BundleType {
    match raw.unwrap_or_default().trim().to_ascii_lowercase().as_str() {
        "cloud" => BundleType::Cloud,
        _ => BundleType::Local,
    }
}

fn parse_entry_type(raw: Option<&str>) -> EntryType {
    parse_entry_type_with_default(raw, EntryType::AiInference)
}

fn parse_entry_type_with_default(raw: Option<&str>, default: EntryType) -> EntryType {
    match raw.unwrap_or_default().trim().to_ascii_lowercase().as_str() {
        "ai-inference" | "ai_inference" => EntryType::AiInference,
        "agent-app" | "agent-apps" | "agent_apps" => EntryType::AgentApp,
        "mcp" => EntryType::Mcp,
        _ => default,
    }
}

fn extract_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn extract_detection_rule_strings(
    detection: &Map<String, Value>,
    rule_key: &str,
    field_candidates: &[&str],
) -> Vec<String> {
    let mut out = Vec::new();
    let Some(rules) = detection.get(rule_key).and_then(Value::as_array) else {
        return out;
    };
    for rule in rules {
        if let Some(text) = rule.as_str() {
            let text = text.trim();
            if !text.is_empty() {
                out.push(text.to_string());
            }
            continue;
        }
        let Some(obj) = rule.as_object() else {
            continue;
        };
        for field in field_candidates {
            if let Some(values) = obj.get(*field) {
                out.extend(extract_strings_from_value(values));
            }
        }
    }
    out
}

fn extract_strings_from_value(value: &Value) -> Vec<String> {
    if let Some(text) = value.as_str() {
        let text = text.trim();
        return if text.is_empty() {
            Vec::new()
        } else {
            vec![text.to_string()]
        };
    }
    if let Some(values) = value.as_array() {
        return values
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>();
    }
    Vec::new()
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn dedup_sort_strings(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn prune_catch_all_path_rules(paths: &mut Vec<String>, entry_type: &EntryType) {
    if !matches!(entry_type, EntryType::AgentApp) {
        return;
    }
    let has_specific = paths
        .iter()
        .any(|path| !is_catch_all_path_pattern(path.as_str()));
    if !has_specific {
        return;
    }
    paths.retain(|path| !is_catch_all_path_pattern(path.as_str()));
}

fn is_catch_all_path_pattern(pattern: &str) -> bool {
    matches!(pattern.trim(), "*" | "**" | "/*" | "/**")
}

fn normalize_pattern_for_host_matching(pattern: &str) -> String {
    let mut out = pattern.trim().to_string();
    if out.starts_with('^') {
        out.remove(0);
    }
    if out.ends_with('$') {
        out.pop();
    }
    out = out.replace("\\.", ".");
    if out.starts_with(".*.") {
        out = format!("*.{}", &out[3..]);
    } else if out.starts_with(".*") {
        out = format!("*{}", &out[2..]);
    }
    out
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
    fn parse_compiled_bundle_accepts_catalog_style_shape() {
        let value = json!({
            "version": "catalog-v1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "local",
            "domain_index": {
                "api.openai.com": {
                    "category": "ai-inference",
                    "pattern_type": "exact",
                    "provider": "openai"
                }
            },
            "providers": {
                "openai": {
                    "name": "OpenAI",
                    "category": "ai-inference",
                    "api_format": "openai",
                    "api_domains": ["api.openai.com"],
                    "detection": {
                        "path_patterns": ["/v1/chat/completions"]
                    }
                }
            },
            "interception_patterns": {
                "api.openai.com": [
                    { "action": "intercept", "path": "/v1/chat/completions" }
                ]
            },
            "pricing": {
                "openai": [
                    {
                        "model_pattern": "gpt-5",
                        "input_per_million": 1.0,
                        "output_per_million": 2.0
                    }
                ]
            }
        });

        let parsed = parse_compiled_bundle(&value).unwrap();
        assert_eq!(parsed.version, "catalog-v1");
        assert_eq!(parsed.domain_index.len(), 1);
        assert!(parsed
            .domain_index
            .first()
            .unwrap()
            .paths
            .contains(&"/v1/chat/completions".to_string()));
        assert_eq!(
            parsed.pricing["openai"]["gpt-5"].input_per_million_usd,
            Some(1.0)
        );
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

    #[test]
    fn parse_compiled_bundle_rejects_unknown_domain_provider() {
        let value = json!({
            "version": "2026.02.13-r1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "cloud",
            "domain_index": [
                {
                    "host": "api.openai.com",
                    "provider_id": "openai",
                    "entry_type": "ai-inference"
                }
            ],
            "providers": {
                "anthropic": {
                    "id": "anthropic",
                    "name": "Anthropic",
                    "type": "ai-inference"
                }
            }
        });
        let err = parse_compiled_bundle(&value).unwrap_err();
        assert!(err
            .to_string()
            .contains("references unknown provider `openai`"));
    }

    #[test]
    fn parse_compiled_bundle_accepts_sectioned_v2_shape_with_catalog_domains() {
        let value = json!({
            "schema_version": 2,
            "version": "2026.02.13-r2",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "cloud",
            "meta": {
                "release_id": "rel-1",
                "sections": {
                    "core": { "required": true },
                    "filters": { "required": true },
                    "catalog": { "required": false },
                    "formats": { "required": false }
                }
            },
            "core": {
                "providers": {
                    "openai": {
                        "id": "openai",
                        "name": "OpenAI",
                        "type": "ai-inference",
                        "api_format": "openai"
                    }
                },
                "domain_index": [
                    {
                        "host": "api.openai.com",
                        "provider_id": "openai",
                        "entry_type": "ai-inference"
                    }
                ],
                "pricing": {
                    "openai": {
                        "gpt-5": {
                            "input_per_million_usd": 1.0,
                            "output_per_million_usd": 2.0
                        }
                    }
                }
            },
            "filters": {
                "whitelist": ["api.openai.com"],
                "passthrough": ["statsig.anthropic.com"]
            },
            "catalog": {
                "domains": ["server.codeium.com", "*.githubcopilot.com"]
            },
            "formats": {
                "openai": { "streaming": { "format": "sse" } }
            }
        });

        let parsed = parse_compiled_bundle(&value).unwrap();
        assert_eq!(parsed.schema_version, 2);
        assert_eq!(parsed.version, "2026.02.13-r2");
        assert_eq!(parsed.domain_index.len(), 1);
        assert_eq!(parsed.providers.len(), 1);
        assert_eq!(parsed.catalog_domains.len(), 2);
        assert!(parsed
            .catalog_domains
            .contains(&"server.codeium.com".to_string()));
        assert!(parsed.meta.is_some());
    }

    #[test]
    fn parse_compiled_bundle_accepts_sectioned_v3_shape_with_entity_ids() {
        let value = json!({
            "schema_version": 3,
            "version": "2026.02.13-r3",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "cloud",
            "meta": {
                "release_id": "rel-2",
                "sections": {
                    "core": { "required": true },
                    "filters": { "required": true }
                }
            },
            "core": {
                "providers": {
                    "openai": {
                        "id": "openai",
                        "entity_id": "prv_4n7k2q9m1x",
                        "name": "OpenAI",
                        "type": "ai-inference",
                        "api_format": "openai",
                        "detection": {
                            "ua_rules": [{ "contains": "openai", "agent": "openai" }],
                            "path_rules": [{ "path": "/v1/chat/completions" }]
                        }
                    }
                },
                "domain_index": [
                    {
                        "host": "api.openai.com",
                        "provider_id": "openai",
                        "entry_type": "ai-inference"
                    }
                ],
                "pricing": {}
            },
            "filters": {
                "whitelist": ["api.openai.com"],
                "blacklist": ["tracking"],
                "passthrough": [],
                "noise_keywords": []
            }
        });

        let parsed = parse_compiled_bundle(&value).unwrap();
        assert_eq!(parsed.schema_version, 3);
        let provider = parsed.providers.get("openai").unwrap();
        assert_eq!(provider.entity_id.as_deref(), Some("prv_4n7k2q9m1x"));
        let entry = parsed.domain_index.first().unwrap();
        assert_eq!(entry.provider_entity_id.as_deref(), Some("prv_4n7k2q9m1x"));
    }
}
