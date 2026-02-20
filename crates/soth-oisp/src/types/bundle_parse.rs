use super::*;
use crate::matchers::normalize_host_for_matching;
use crate::types::provider::{DetectionRule, ProviderDefinition};
use anyhow::Context;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

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
    let gating = parse_bundle_gating(object, None);

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
        gating,
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
    let gating = parse_bundle_gating(root, Some(core));

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
        gating,
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
        let detection_id = provider_obj
            .get("detection_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToString::to_string);

        let mut domains = extract_string_array(provider_obj.get("api_domains"));
        let mut user_agent_patterns = extract_string_array(provider_obj.get("user_agent_patterns"));
        let detection = provider_obj
            .get("detection")
            .and_then(|value| serde_json::from_value::<DetectionSpec>(value.clone()).ok());
        if let Some(detection_obj) = provider_obj.get("detection").and_then(Value::as_object) {
            domains.extend(extract_string_array(detection_obj.get("host_patterns")));
            user_agent_patterns.extend(extract_string_array(detection_obj.get("header_hints")));
            domains.extend(extract_detection_rule_strings(
                detection_obj,
                "host_rules",
                &["host", "pattern", "contains", "suffix", "regex", "value"],
            ));
            user_agent_patterns.extend(extract_detection_rule_strings(
                detection_obj,
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
                detection_id,
                name,
                entry_type,
                api_format,
                domains,
                user_agent_patterns,
                detection,
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
                if let Some(patterns) = feature.get("patterns") {
                    collect_feature_pattern_paths(patterns, &mut paths);
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

fn collect_feature_pattern_paths(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(raw) => {
            let path = raw.trim();
            if !path.is_empty() {
                out.push(path.to_string());
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_feature_pattern_paths(item, out);
            }
        }
        Value::Object(map) => {
            for key in ["url", "path", "pattern", "route", "endpoint"] {
                if let Some(raw) = map.get(key).and_then(Value::as_str) {
                    let path = raw.trim();
                    if !path.is_empty() {
                        out.push(path.to_string());
                    }
                }
            }
            for nested_key in ["request", "response"] {
                if let Some(nested) = map.get(nested_key) {
                    collect_feature_pattern_paths(nested, out);
                }
            }
        }
        _ => {}
    }
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
        out.push(DomainIndexEntry {
            host: host.clone(),
            provider_id,
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
    Ok(DomainIndexEntry {
        host,
        provider_id,
        entry_type,
        paths,
    })
}

fn parse_catalog_filters(
    root: &Map<String, Value>,
    domain_index: &[DomainIndexEntry],
    interception_patterns: Option<&Map<String, Value>>,
) -> anyhow::Result<DomainFilters> {
    let mut filters = if let Some(raw_filters) = root.get("filters") {
        serde_json::from_value(raw_filters.clone()).context("invalid filters object")?
    } else {
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
                .map(|pattern| normalize_host_pattern_for_matching(&pattern)),
        );
        let mut noise_keywords =
            extract_string_array(root.get("noise_filter").and_then(|v| v.get("words")));
        noise_keywords.extend(extract_string_array(
            root.get("noise_filter").and_then(|v| v.get("paths")),
        ));

        DomainFilters {
            whitelist,
            blacklist: Vec::new(),
            passthrough,
            noise_keywords,
        }
    };
    merge_sensor_filter_aliases_into_filters(root, None, &mut filters);
    normalize_domain_filters(&mut filters);
    Ok(filters)
}

fn parse_filters_section(
    root: &Map<String, Value>,
    core: &Map<String, Value>,
    domain_index: &[DomainIndexEntry],
    interception_patterns: Option<&Map<String, Value>>,
) -> anyhow::Result<DomainFilters> {
    let mut filters = if let Some(raw_filters) = root.get("filters").or_else(|| core.get("filters"))
    {
        let filters: DomainFilters =
            serde_json::from_value(raw_filters.clone()).context("invalid filters section")?;
        filters
    } else {
        parse_catalog_filters(root, domain_index, interception_patterns)?
    };
    merge_sensor_filter_aliases_into_filters(root, Some(core), &mut filters);
    normalize_domain_filters(&mut filters);
    Ok(filters)
}

fn merge_sensor_filter_aliases_into_filters(
    root: &Map<String, Value>,
    core: Option<&Map<String, Value>>,
    filters: &mut DomainFilters,
) {
    filters.whitelist.extend(extract_sensor_filter_alias_values(
        root,
        core,
        "whitelistedDomains",
    ));
    for pattern in &mut filters.whitelist {
        *pattern = normalize_host_pattern_for_matching(pattern.as_str());
    }
    filters
        .passthrough
        .extend(extract_sensor_filter_alias_values(
            root,
            core,
            "passthroughDomains",
        ));
    for pattern in &mut filters.passthrough {
        *pattern = normalize_host_pattern_for_matching(pattern.as_str());
    }
    filters
        .noise_keywords
        .extend(extract_sensor_filter_alias_values(
            root,
            core,
            "blacklistedWords",
        ));
}

fn extract_sensor_filter_alias_values(
    root: &Map<String, Value>,
    core: Option<&Map<String, Value>>,
    key: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    out.extend(extract_string_array(root.get(key)));
    if let Some(data) = root.get("data").and_then(Value::as_object) {
        out.extend(extract_string_array(data.get(key)));
    }
    if let Some(core) = core {
        out.extend(extract_string_array(core.get(key)));
        if let Some(data) = core.get("data").and_then(Value::as_object) {
            out.extend(extract_string_array(data.get(key)));
        }
    }
    out
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

fn parse_bundle_gating(
    root: &Map<String, Value>,
    core: Option<&Map<String, Value>>,
) -> BundleGating {
    let mut allowed_app_origins = AllowedAppOrigins::default();
    let mut allowed_host_origins = Vec::new();

    collect_allowed_app_origins(root.get("allowed_app_origins"), &mut allowed_app_origins);
    allowed_host_origins.extend(extract_allowed_host_origins(
        root.get("allowed_host_origins"),
    ));
    if let Some(data) = root.get("data").and_then(Value::as_object) {
        collect_allowed_app_origins(data.get("allowed_app_origins"), &mut allowed_app_origins);
        allowed_host_origins.extend(extract_allowed_host_origins(
            data.get("allowed_host_origins"),
        ));
        if let Some(gating) = data.get("gating").and_then(Value::as_object) {
            collect_allowed_app_origins(
                gating.get("allowed_app_origins"),
                &mut allowed_app_origins,
            );
            allowed_host_origins.extend(extract_allowed_host_origins(
                gating.get("allowed_host_origins"),
            ));
        }
    }

    if let Some(gating) = root.get("gating").and_then(Value::as_object) {
        collect_allowed_app_origins(gating.get("allowed_app_origins"), &mut allowed_app_origins);
        allowed_host_origins.extend(extract_allowed_host_origins(
            gating.get("allowed_host_origins"),
        ));
    }

    if let Some(core) = core {
        collect_allowed_app_origins(core.get("allowed_app_origins"), &mut allowed_app_origins);
        allowed_host_origins.extend(extract_allowed_host_origins(
            core.get("allowed_host_origins"),
        ));
        if let Some(data) = core.get("data").and_then(Value::as_object) {
            collect_allowed_app_origins(data.get("allowed_app_origins"), &mut allowed_app_origins);
            allowed_host_origins.extend(extract_allowed_host_origins(
                data.get("allowed_host_origins"),
            ));
        }
        if let Some(gating) = core.get("gating").and_then(Value::as_object) {
            collect_allowed_app_origins(
                gating.get("allowed_app_origins"),
                &mut allowed_app_origins,
            );
            allowed_host_origins.extend(extract_allowed_host_origins(
                gating.get("allowed_host_origins"),
            ));
        }
    }

    normalize_identifier_patterns(&mut allowed_app_origins.hosts);
    normalize_identifier_patterns(&mut allowed_app_origins.non_hosts);
    normalize_identifier_patterns(&mut allowed_app_origins.apps_with_parsers);
    normalize_host_origin_patterns(&mut allowed_host_origins);

    BundleGating {
        allowed_app_origins,
        allowed_host_origins,
    }
}

fn collect_allowed_app_origins(value: Option<&Value>, out: &mut AllowedAppOrigins) {
    let Some(value) = value else {
        return;
    };
    let Some(object) = value.as_object() else {
        return;
    };

    out.hosts.extend(extract_string_array(
        object.get("hosts").or_else(|| object.get("host")),
    ));
    out.non_hosts.extend(extract_string_array(
        object
            .get("non_hosts")
            .or_else(|| object.get("nonHosts"))
            .or_else(|| object.get("non_hosts_apps")),
    ));
    out.apps_with_parsers.extend(extract_string_array(
        object
            .get("apps_with_parsers")
            .or_else(|| object.get("appsWithParsers"))
            .or_else(|| object.get("with_parsers")),
    ));
}

fn extract_allowed_host_origins(value: Option<&Value>) -> Vec<String> {
    let Some(value) = value else {
        return Vec::new();
    };

    if let Some(items) = value.as_array() {
        return items
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
        out.extend(extract_string_array(object.get("origins")));
        out.extend(extract_string_array(object.get("allowed")));
        return out;
    }

    Vec::new()
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
        provider.detection_id = normalize_optional_string(provider.detection_id.take());
        dedup_sort_strings(&mut provider.domains);
        dedup_sort_strings(&mut provider.user_agent_patterns);
        if let Some(detection) = provider.detection.as_mut() {
            normalize_detection_spec(detection);
        }
    }
    for entry in &mut bundle.domain_index {
        dedup_sort_strings(&mut entry.paths);
    }
    normalize_domain_filters(&mut bundle.filters);
    dedup_sort_strings(&mut bundle.catalog_domains);
    normalize_bundle_gating(&mut bundle.gating);
    if bundle.stats.providers == 0 {
        bundle.stats.providers = bundle.providers.len();
    }
    if bundle.stats.domains == 0 {
        bundle.stats.domains = bundle.domain_index.len();
    }
}

fn normalize_domain_filters(filters: &mut DomainFilters) {
    normalize_filter_host_patterns(&mut filters.whitelist);
    normalize_filter_host_patterns(&mut filters.passthrough);
    dedup_sort_strings(&mut filters.whitelist);
    dedup_sort_strings(&mut filters.blacklist);
    dedup_sort_strings(&mut filters.passthrough);
    dedup_sort_strings(&mut filters.noise_keywords);
}

fn normalize_filter_host_patterns(values: &mut Vec<String>) {
    let mut normalized = Vec::with_capacity(values.len());
    for value in values.drain(..) {
        let host = normalize_host_pattern_for_matching(value.as_str());
        if host.is_empty() {
            continue;
        }
        normalized.push(host);
    }
    *values = normalized;
}

fn normalize_bundle_gating(gating: &mut BundleGating) {
    normalize_identifier_patterns(&mut gating.allowed_app_origins.hosts);
    normalize_identifier_patterns(&mut gating.allowed_app_origins.non_hosts);
    normalize_identifier_patterns(&mut gating.allowed_app_origins.apps_with_parsers);
    normalize_host_origin_patterns(&mut gating.allowed_host_origins);
}

fn normalize_detection_spec(detection: &mut DetectionSpec) {
    dedup_sort_strings(&mut detection.host_patterns);
    dedup_sort_strings(&mut detection.path_patterns);
    dedup_sort_strings(&mut detection.header_hints);
    normalize_detection_rules(&mut detection.ua_rules, "ua_match");
    normalize_detection_rules(&mut detection.path_rules, "path_match");
    normalize_detection_rules(&mut detection.model_rules, "model_match");
    normalize_detection_rules(&mut detection.process_rules, "process_match");
    normalize_detection_rules(&mut detection.env_rules, "env_match");
}

fn normalize_detection_rules(rules: &mut Vec<DetectionRule>, default_reason: &str) {
    for rule in rules.iter_mut() {
        rule.id = normalize_optional_string(rule.id.take());
        rule.agent = normalize_optional_string(rule.agent.take());
        rule.reason = normalize_optional_string(rule.reason.take())
            .or_else(|| Some(default_reason.to_string()));
        if let Some(confidence) = rule.confidence {
            rule.confidence = Some(confidence.clamp(0.0, 1.0));
        }
        if rule.enabled.is_none() {
            rule.enabled = Some(true);
        }

        let mut cleaned = std::collections::HashMap::new();
        for (key, value) in std::mem::take(&mut rule.matchers) {
            let normalized_key = key.trim().to_ascii_lowercase();
            if normalized_key.is_empty() {
                continue;
            }
            let normalized_value = normalize_detection_matcher_value(value);
            if !normalized_value.is_null() {
                cleaned.insert(normalized_key, normalized_value);
            }
        }
        rule.matchers = cleaned;
    }

    rules.retain(|rule| {
        rule.enabled.unwrap_or(true)
            && !rule.matchers.is_empty()
            && rule
                .reason
                .as_deref()
                .is_some_and(|reason| !reason.trim().is_empty())
    });
    rules.sort_by_key(|rule| std::cmp::Reverse(detection_rule_sort_key(rule)));
    rules.dedup_by(|left, right| detection_rule_sort_key(left) == detection_rule_sort_key(right));
}

fn detection_rule_sort_key(rule: &DetectionRule) -> (i32, i32, String, String, String) {
    let confidence = (rule.confidence.unwrap_or(0.0).clamp(0.0, 1.0) * 1000.0).round() as i32;
    (
        rule.priority.unwrap_or(0),
        confidence,
        rule.id.clone().unwrap_or_default(),
        rule.reason.clone().unwrap_or_default(),
        rule.agent.clone().unwrap_or_default(),
    )
}

fn normalize_detection_matcher_value(value: Value) -> Value {
    match value {
        Value::String(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                Value::Null
            } else {
                Value::String(trimmed.to_string())
            }
        }
        Value::Array(entries) => {
            let mut out = Vec::new();
            for entry in entries {
                let normalized = normalize_detection_matcher_value(entry);
                if !normalized.is_null() {
                    out.push(normalized);
                }
            }
            if out.is_empty() {
                Value::Null
            } else {
                Value::Array(out)
            }
        }
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, entry) in map {
                let normalized_key = key.trim().to_ascii_lowercase();
                if normalized_key.is_empty() {
                    continue;
                }
                let normalized = normalize_detection_matcher_value(entry);
                if !normalized.is_null() {
                    out.insert(normalized_key, normalized);
                }
            }
            if out.is_empty() {
                Value::Null
            } else {
                Value::Object(out)
            }
        }
        other => other,
    }
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

fn normalize_identifier_patterns(values: &mut Vec<String>) {
    let mut normalized = Vec::with_capacity(values.len());
    for value in values.drain(..) {
        let text = value.trim();
        if text.is_empty() {
            continue;
        }
        normalized.push(text.to_ascii_lowercase());
    }
    *values = normalized;
    dedup_sort_strings(values);
}

fn normalize_host_origin_patterns(values: &mut Vec<String>) {
    let mut normalized = Vec::with_capacity(values.len());
    for value in values.drain(..) {
        let origin = normalize_host_for_matching(value.as_str());
        if origin.is_empty() {
            continue;
        }
        normalized.push(origin);
    }
    *values = normalized;
    dedup_sort_strings(values);
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

fn normalize_host_pattern_for_matching(pattern: &str) -> String {
    let normalized = normalize_pattern_for_host_matching(pattern);
    let host_only = normalized
        .split_once('/')
        .map(|(host, _)| host)
        .unwrap_or(normalized.as_str())
        .trim_end_matches(':')
        .trim();
    host_only.to_string()
}
