use anyhow::Context;
use serde_json::Value;
use soth_oisp_types::bundle::{
    parse_compiled_bundle, BundleStats, BundleType, CompiledBundle, DomainFilters,
    DomainIndexEntry, ResolvedProvider,
};
use soth_oisp_types::provider::{EntryType, ModelPricing};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    pub provider_id: String,
    pub entry_type: EntryType,
    pub api_format: Option<String>,
}

impl Classification {
    pub fn entry_type_label(&self) -> &'static str {
        match self.entry_type {
            EntryType::AiInference => "ai_inference",
            EntryType::AgentApp => "agent_app",
            EntryType::Mcp => "mcp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptDecision {
    Intercept {
        provider_id: String,
        entry_type: EntryType,
    },
    Passthrough,
    Noise,
    Tunnel,
}

#[derive(Clone)]
pub struct OispEngine {
    bundle: Arc<CompiledBundle>,
}

impl OispEngine {
    pub fn new(bundle: CompiledBundle) -> anyhow::Result<Self> {
        bundle.validate()?;
        Ok(Self {
            bundle: Arc::new(bundle),
        })
    }

    pub fn bundle_version(&self) -> &str {
        &self.bundle.version
    }

    pub fn provider_count(&self) -> usize {
        self.bundle.providers.len()
    }

    pub fn domain_count(&self) -> usize {
        self.bundle.domain_index.len()
    }

    pub fn classify(&self, host: &str) -> Option<Classification> {
        let entry = select_best_domain_match(&self.bundle.domain_index, host)?;
        let provider = self.bundle.providers.get(&entry.provider_id)?;
        Some(Classification {
            provider_id: entry.provider_id.clone(),
            entry_type: provider.entry_type.clone(),
            api_format: provider.api_format.clone(),
        })
    }

    pub fn should_intercept(&self, host: &str, path: &str) -> InterceptDecision {
        if contains_noise_keyword(path, &self.bundle.filters.noise_keywords) {
            return InterceptDecision::Noise;
        }

        if host_matches_any(host, &self.bundle.filters.passthrough) {
            return InterceptDecision::Passthrough;
        }

        if !self.bundle.filters.whitelist.is_empty()
            && !host_matches_any(host, &self.bundle.filters.whitelist)
        {
            return InterceptDecision::Tunnel;
        }

        if host_matches_any(host, &self.bundle.filters.blacklist) {
            return InterceptDecision::Tunnel;
        }

        let Some(entry) = select_best_domain_match(&self.bundle.domain_index, host) else {
            return InterceptDecision::Tunnel;
        };

        if !entry.paths.is_empty() && !path_matches_any(path, &entry.paths) {
            return InterceptDecision::Tunnel;
        }

        let Some(provider) = self.bundle.providers.get(&entry.provider_id) else {
            return InterceptDecision::Tunnel;
        };

        InterceptDecision::Intercept {
            provider_id: entry.provider_id.clone(),
            entry_type: provider.entry_type.clone(),
        }
    }

    /// Calculate request cost using bundle pricing for a provider/model pair.
    ///
    /// `provider_hints` are checked in order (for example: provider_id then api_format).
    /// If no hinted provider contains the model, all providers are scanned as a fallback.
    pub fn calculate_cost(
        &self,
        provider_hints: &[&str],
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
        cache_read_tokens: Option<u64>,
        cache_write_tokens: Option<u64>,
    ) -> Option<f64> {
        let model = model.trim();
        if model.is_empty() {
            return None;
        }

        for provider_hint in provider_hints {
            let provider_hint = provider_hint.trim();
            if provider_hint.is_empty() {
                continue;
            }
            if let Some((_, pricing)) = self
                .bundle
                .pricing
                .iter()
                .find(|(provider, _)| provider.eq_ignore_ascii_case(provider_hint))
                .and_then(|(_, models)| find_model_pricing(models, model))
            {
                return calculate_cost_from_pricing(
                    pricing,
                    input_tokens,
                    output_tokens,
                    cache_read_tokens,
                    cache_write_tokens,
                );
            }
        }

        for models in self.bundle.pricing.values() {
            if let Some((_, pricing)) = find_model_pricing(models, model) {
                return calculate_cost_from_pricing(
                    pricing,
                    input_tokens,
                    output_tokens,
                    cache_read_tokens,
                    cache_write_tokens,
                );
            }
        }

        None
    }

    pub fn load_from_registry_cache(path: &Path) -> anyhow::Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed reading registry cache {}", path.display()))?;
        let root: Value = serde_json::from_str(&content)
            .with_context(|| format!("failed parsing registry cache {}", path.display()))?;
        let (bundle_value, metadata_value) = if root.get("bundle").is_some() {
            (
                root.get("bundle")
                    .cloned()
                    .context("registry cache envelope missing bundle field")?,
                root.get("metadata").cloned(),
            )
        } else {
            (root, None)
        };

        let bundle = parse_bundle_with_compat(&bundle_value, metadata_value.as_ref())
            .context("failed parsing compiled bundle")?;
        Ok(Some(Self::new(bundle)?))
    }
}

fn parse_bundle_with_compat(
    bundle_value: &Value,
    metadata_value: Option<&Value>,
) -> anyhow::Result<CompiledBundle> {
    match parse_compiled_bundle(bundle_value) {
        Ok(bundle) => Ok(bundle),
        Err(primary_error) => parse_registry_catalog_bundle(bundle_value, metadata_value)
            .map_err(|fallback_error| {
                anyhow::anyhow!(
                    "compiled schema parse failed: {}; registry schema parse failed: {}",
                    primary_error,
                    fallback_error
                )
            }),
    }
}

fn parse_registry_catalog_bundle(
    bundle_value: &Value,
    metadata_value: Option<&Value>,
) -> anyhow::Result<CompiledBundle> {
    let object = bundle_value
        .as_object()
        .context("registry bundle must be a JSON object")?;
    let metadata = metadata_value.and_then(Value::as_object);

    let version = object
        .get("version")
        .and_then(Value::as_str)
        .or_else(|| metadata.and_then(|m| m.get("version").and_then(Value::as_str)))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_string();
    let compiled_at = object
        .get("compiled_at")
        .and_then(Value::as_str)
        .or_else(|| metadata.and_then(|m| m.get("compiled_at").and_then(Value::as_str)))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_string();
    let bundle_type = parse_bundle_type(
        object
            .get("bundle_type")
            .and_then(Value::as_str)
            .or_else(|| metadata.and_then(|m| m.get("bundle_type").and_then(Value::as_str))),
    );

    let provider_values = object
        .get("providers")
        .and_then(Value::as_object)
        .context("registry schema requires providers object")?;
    let mut providers: BTreeMap<String, ResolvedProvider> = BTreeMap::new();
    let mut provider_paths: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (provider_id, provider_value) in provider_values {
        let provider_obj = provider_value.as_object().with_context(|| {
            format!("provider `{provider_id}` entry must be a JSON object")
        })?;
        let entry_type = parse_entry_type(
            provider_obj.get("category").and_then(Value::as_str),
            EntryType::AiInference,
        );
        let name = provider_obj
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(provider_id)
            .to_string();
        let api_format = provider_obj
            .get("api_format")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);

        let mut domains = extract_string_array(provider_obj.get("api_domains"));
        let mut user_agent_patterns = Vec::new();
        let mut paths = Vec::new();
        if let Some(detection) = provider_obj.get("detection").and_then(Value::as_object) {
            domains.extend(extract_string_array(detection.get("host_patterns")));
            user_agent_patterns.extend(extract_string_array(detection.get("header_hints")));
            paths.extend(extract_string_array(detection.get("path_patterns")));
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
                            continue;
                        }
                        if let Some(pattern_obj) = pattern.as_object() {
                            let maybe_path = pattern_obj
                                .get("url")
                                .and_then(Value::as_str)
                                .or_else(|| pattern_obj.get("path").and_then(Value::as_str));
                            if let Some(raw) = maybe_path {
                                let value = raw.trim();
                                if !value.is_empty() {
                                    paths.push(value.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        dedup_sort_strings(&mut domains);
        dedup_sort_strings(&mut user_agent_patterns);
        dedup_sort_strings(&mut paths);
        if !paths.is_empty() {
            provider_paths.insert(provider_id.clone(), paths);
        }

        providers.insert(
            provider_id.clone(),
            ResolvedProvider {
                id: provider_id.clone(),
                name,
                entry_type,
                api_format,
                domains,
                user_agent_patterns,
            },
        );
    }

    let interception_patterns = object
        .get("interception_patterns")
        .and_then(Value::as_object);

    let domain_index_values = object
        .get("domain_index")
        .and_then(Value::as_object)
        .context("registry schema requires domain_index object")?;
    let mut domain_index = Vec::new();
    for (host, entry_value) in domain_index_values {
        let entry_obj = entry_value
            .as_object()
            .with_context(|| format!("domain_index entry for `{host}` must be object"))?;
        let provider_id = entry_obj
            .get("provider")
            .and_then(Value::as_str)
            .or_else(|| entry_obj.get("provider_id").and_then(Value::as_str))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or_default()
            .to_string();
        if provider_id.is_empty() {
            continue;
        }

        let default_entry_type = providers
            .get(&provider_id)
            .map(|provider| provider.entry_type.clone())
            .unwrap_or(EntryType::AiInference);
        let entry_type = parse_entry_type(
            entry_obj.get("category").and_then(Value::as_str),
            default_entry_type,
        );
        let mut paths = extract_string_array(entry_obj.get("paths"));
        if let Some(extra_paths) = provider_paths.get(&provider_id) {
            paths.extend(extra_paths.iter().cloned());
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

        domain_index.push(DomainIndexEntry {
            host: host.clone(),
            provider_id,
            entry_type,
            paths,
        });
    }

    let mut whitelist = interception_patterns
        .map(|patterns| patterns.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    if whitelist.is_empty() {
        whitelist = domain_index
            .iter()
            .map(|entry| entry.host.clone())
            .collect::<Vec<_>>();
    }

    let mut passthrough = extract_string_array(object.get("passthrough").and_then(|v| v.get("domains")));
    passthrough.extend(
        extract_string_array(object.get("passthrough").and_then(|v| v.get("patterns")))
            .into_iter()
            .map(|pattern| normalize_pattern_for_host_matching(&pattern)),
    );
    let mut noise_keywords = extract_string_array(object.get("noise_filter").and_then(|v| v.get("words")));
    noise_keywords.extend(extract_string_array(
        object.get("noise_filter").and_then(|v| v.get("paths")),
    ));
    dedup_sort_strings(&mut whitelist);
    dedup_sort_strings(&mut passthrough);
    dedup_sort_strings(&mut noise_keywords);

    let filters = DomainFilters {
        whitelist,
        blacklist: Vec::new(),
        passthrough,
        noise_keywords,
    };

    let mut pricing: BTreeMap<String, BTreeMap<String, ModelPricing>> = BTreeMap::new();
    if let Some(pricing_values) = object.get("pricing").and_then(Value::as_object) {
        for (provider_id, provider_pricing_value) in pricing_values {
            let mut models = BTreeMap::new();
            if let Some(entries) = provider_pricing_value.as_array() {
                for entry in entries {
                    let Some(model_pattern) = entry.get("model_pattern").and_then(Value::as_str) else {
                        continue;
                    };
                    let model_pattern = model_pattern.trim();
                    if model_pattern.is_empty() {
                        continue;
                    }
                    let model_pricing = ModelPricing {
                        input_per_million_usd: entry
                            .get("input_per_million_usd")
                            .and_then(Value::as_f64)
                            .or_else(|| entry.get("input_per_million").and_then(Value::as_f64)),
                        output_per_million_usd: entry
                            .get("output_per_million_usd")
                            .and_then(Value::as_f64)
                            .or_else(|| entry.get("output_per_million").and_then(Value::as_f64)),
                        cache_read_per_million_usd: entry
                            .get("cache_read_per_million_usd")
                            .and_then(Value::as_f64)
                            .or_else(|| {
                                entry
                                    .get("cache_read_per_million")
                                    .and_then(Value::as_f64)
                            }),
                        cache_write_per_million_usd: entry
                            .get("cache_write_per_million_usd")
                            .and_then(Value::as_f64)
                            .or_else(|| {
                                entry
                                    .get("cache_write_per_million")
                                    .and_then(Value::as_f64)
                            }),
                    };
                    models.insert(model_pattern.to_string(), model_pricing);
                }
            } else if let Some(model_map) = provider_pricing_value.as_object() {
                for (model_id, model_value) in model_map {
                    if let Ok(model_pricing) =
                        serde_json::from_value::<ModelPricing>(model_value.clone())
                    {
                        models.insert(model_id.clone(), model_pricing);
                    }
                }
            }
            if !models.is_empty() {
                pricing.insert(provider_id.clone(), models);
            }
        }
    }

    let stats = object
        .get("stats")
        .cloned()
        .and_then(|value| serde_json::from_value::<BundleStats>(value).ok())
        .unwrap_or(BundleStats {
            providers: providers.len(),
            domains: domain_index.len(),
            formats: 0,
        });

    Ok(CompiledBundle {
        version,
        compiled_at,
        bundle_type,
        domain_index,
        providers,
        filters,
        pricing,
        stats,
    })
}

fn parse_bundle_type(raw: Option<&str>) -> BundleType {
    match raw.unwrap_or_default().trim().to_ascii_lowercase().as_str() {
        "cloud" => BundleType::Cloud,
        _ => BundleType::Local,
    }
}

fn parse_entry_type(raw: Option<&str>, default: EntryType) -> EntryType {
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

fn select_best_domain_match<'a>(
    entries: &'a [DomainIndexEntry],
    host: &str,
) -> Option<&'a DomainIndexEntry> {
    let host = host.to_ascii_lowercase();

    if let Some(exact) = entries
        .iter()
        .find(|entry| !entry.host.contains('*') && entry.host.eq_ignore_ascii_case(host.as_str()))
    {
        return Some(exact);
    }

    entries
        .iter()
        .filter(|entry| entry.host.contains('*'))
        .filter(|entry| host_matches_pattern(host.as_str(), entry.host.as_str()))
        .max_by_key(|entry| wildcard_specificity(entry.host.as_str()))
}

fn wildcard_specificity(pattern: &str) -> usize {
    pattern.chars().filter(|ch| *ch != '*').count()
}

fn contains_noise_keyword(path: &str, keywords: &[String]) -> bool {
    if keywords.is_empty() {
        return false;
    }

    let lower_path = path.to_ascii_lowercase();
    keywords
        .iter()
        .any(|keyword| lower_path.contains(&keyword.to_ascii_lowercase()))
}

fn host_matches_any(host: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|pattern| host_matches_pattern(host, pattern))
}

fn host_matches_pattern(host: &str, pattern: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();

    if !pattern.contains('*') {
        return host == pattern;
    }

    if let Some(star_pos) = pattern.find('*') {
        let prefix = &pattern[..star_pos];
        let suffix = &pattern[star_pos + 1..];
        if host.starts_with(prefix) && host.ends_with(suffix) {
            let middle_len = host.len().saturating_sub(prefix.len() + suffix.len());
            return middle_len > 0;
        }
    }

    false
}

fn path_matches_any(path: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|pattern| path_matches_pattern(path, pattern.as_str()))
}

fn path_matches_pattern(path: &str, pattern: &str) -> bool {
    let path = path.to_ascii_lowercase();
    let mut pattern = pattern.trim().to_ascii_lowercase();
    if pattern.is_empty() {
        return false;
    }
    while pattern.contains("**") {
        pattern = pattern.replace("**", "*");
    }
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return path == pattern || (pattern.ends_with('/') && path.starts_with(pattern.as_str()));
    }
    wildcard_match(path.as_str(), pattern.as_str())
}

fn wildcard_match(text: &str, pattern: &str) -> bool {
    let text = text.as_bytes();
    let pattern = pattern.as_bytes();
    let mut text_idx = 0usize;
    let mut pattern_idx = 0usize;
    let mut last_star: Option<usize> = None;
    let mut last_match = 0usize;

    while text_idx < text.len() {
        if pattern_idx < pattern.len() && pattern[pattern_idx] == text[text_idx] {
            text_idx += 1;
            pattern_idx += 1;
            continue;
        }

        if pattern_idx < pattern.len() && pattern[pattern_idx] == b'*' {
            last_star = Some(pattern_idx);
            pattern_idx += 1;
            last_match = text_idx;
            continue;
        }

        if let Some(star_idx) = last_star {
            pattern_idx = star_idx + 1;
            last_match += 1;
            text_idx = last_match;
            continue;
        }

        return false;
    }

    while pattern_idx < pattern.len() && pattern[pattern_idx] == b'*' {
        pattern_idx += 1;
    }

    pattern_idx == pattern.len()
}

fn find_model_pricing<'a>(
    models: &'a std::collections::BTreeMap<String, ModelPricing>,
    model: &str,
) -> Option<(&'a str, &'a ModelPricing)> {
    let model_lower = model.to_ascii_lowercase();

    if let Some((id, pricing)) = models
        .iter()
        .find(|(id, _)| id.eq_ignore_ascii_case(model_lower.as_str()))
    {
        return Some((id.as_str(), pricing));
    }

    models
        .iter()
        .filter(|(id, _)| {
            let id_lower = id.to_ascii_lowercase();
            model_lower.starts_with(id_lower.as_str()) || id_lower.starts_with(model_lower.as_str())
        })
        .max_by_key(|(id, _)| id.len())
        .map(|(id, pricing)| (id.as_str(), pricing))
}

fn calculate_cost_from_pricing(
    pricing: &ModelPricing,
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: Option<u64>,
    cache_write_tokens: Option<u64>,
) -> Option<f64> {
    let input_rate = pricing.input_per_million_usd.unwrap_or(0.0);
    let output_rate = pricing.output_per_million_usd.unwrap_or(0.0);
    let cache_read_rate = pricing.cache_read_per_million_usd.unwrap_or(0.0);
    let cache_write_rate = pricing.cache_write_per_million_usd.unwrap_or(0.0);

    if input_rate == 0.0 && output_rate == 0.0 && cache_read_rate == 0.0 && cache_write_rate == 0.0
    {
        return None;
    }

    let cost = (input_tokens as f64 / 1_000_000.0) * input_rate
        + (output_tokens as f64 / 1_000_000.0) * output_rate
        + (cache_read_tokens.unwrap_or(0) as f64 / 1_000_000.0) * cache_read_rate
        + (cache_write_tokens.unwrap_or(0) as f64 / 1_000_000.0) * cache_write_rate;
    Some(cost)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    fn sample_bundle() -> CompiledBundle {
        parse_compiled_bundle(&json!({
            "version": "v1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "local",
            "domain_index": [
                { "host": "api.openai.com", "provider_id": "openai", "entry_type": "ai-inference" },
                { "host": "*.chatgpt.com", "provider_id": "chatgpt", "entry_type": "agent-app" }
            ],
            "providers": {
                "openai": { "id": "openai", "name": "OpenAI", "type": "ai-inference", "api_format": "openai" },
                "chatgpt": { "id": "chatgpt", "name": "ChatGPT", "type": "agent-app" }
            },
            "filters": {
                "passthrough": ["statsig.anthropic.com"],
                "noise_keywords": ["analytics"]
            },
            "pricing": {}
        }))
        .unwrap()
    }

    #[test]
    fn classify_prefers_exact_match_before_wildcard() {
        let engine = OispEngine::new(sample_bundle()).unwrap();
        let class = engine.classify("api.openai.com").unwrap();
        assert_eq!(class.provider_id, "openai");
        assert_eq!(class.entry_type, EntryType::AiInference);
    }

    #[test]
    fn classify_matches_wildcard() {
        let engine = OispEngine::new(sample_bundle()).unwrap();
        let class = engine.classify("ws.chatgpt.com").unwrap();
        assert_eq!(class.provider_id, "chatgpt");
        assert_eq!(class.entry_type, EntryType::AgentApp);
    }

    #[test]
    fn should_intercept_honors_noise_and_passthrough() {
        let engine = OispEngine::new(sample_bundle()).unwrap();
        assert_eq!(
            engine.should_intercept("api.openai.com", "/v1/analytics"),
            InterceptDecision::Noise
        );
        assert_eq!(
            engine.should_intercept("statsig.anthropic.com", "/v1/t"),
            InterceptDecision::Passthrough
        );
        assert_eq!(
            engine.should_intercept("api.openai.com", "/v1/chat/completions"),
            InterceptDecision::Intercept {
                provider_id: "openai".to_string(),
                entry_type: EntryType::AiInference
            }
        );
    }

    #[test]
    fn should_intercept_honors_path_filters_when_present() {
        let engine = OispEngine::new(
            parse_compiled_bundle(&json!({
                "version": "v1",
                "compiled_at": "2026-02-13T00:00:00Z",
                "bundle_type": "local",
                "domain_index": [
                    {
                        "host": "api.openai.com",
                        "provider_id": "openai",
                        "entry_type": "ai-inference",
                        "paths": ["/v1/chat/completions", "/v1/responses*"]
                    }
                ],
                "providers": {
                    "openai": { "id": "openai", "name": "OpenAI", "type": "ai-inference" }
                },
                "filters": {},
                "pricing": {}
            }))
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            engine.should_intercept("api.openai.com", "/v1/chat/completions"),
            InterceptDecision::Intercept {
                provider_id: "openai".to_string(),
                entry_type: EntryType::AiInference
            }
        );
        assert_eq!(
            engine.should_intercept("api.openai.com", "/v1/responses/stream"),
            InterceptDecision::Intercept {
                provider_id: "openai".to_string(),
                entry_type: EntryType::AiInference
            }
        );
        assert_eq!(
            engine.should_intercept("api.openai.com", "/v1/models"),
            InterceptDecision::Tunnel
        );
    }

    #[test]
    fn load_from_registry_cache_reads_envelope_bundle() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache.json");
        let envelope = json!({
            "schema_version": 1,
            "fetched_at": "2026-02-13T00:00:00Z",
            "etag": "etag-1",
            "metadata": {
                "bundle_type": "local",
                "version": "v1",
                "sha256": "abc",
                "compiled_at": "2026-02-13T00:00:00Z",
                "provider_count": 2,
                "domain_count": 2,
                "format_count": 1,
                "size_bytes": 123
            },
            "bundle": sample_bundle()
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();

        let engine = OispEngine::load_from_registry_cache(&path)
            .unwrap()
            .unwrap();
        assert_eq!(engine.bundle_version(), "v1");
        assert_eq!(engine.provider_count(), 2);
    }

    #[test]
    fn load_from_registry_cache_returns_none_when_missing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing.json");
        let loaded = OispEngine::load_from_registry_cache(&path).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn classify_returns_none_for_unknown_host() {
        let engine = OispEngine::new(sample_bundle()).unwrap();
        assert!(engine.classify("example.com").is_none());
    }

    #[test]
    fn bundle_metadata_accessors_are_stable() {
        let engine = OispEngine::new(sample_bundle()).unwrap();
        assert_eq!(engine.bundle_version(), "v1");
        assert_eq!(engine.provider_count(), 2);
        assert_eq!(engine.domain_count(), 2);
    }

    #[test]
    fn should_intercept_returns_tunnel_for_unknown_host() {
        let engine = OispEngine::new(sample_bundle()).unwrap();
        assert_eq!(
            engine.should_intercept("unknown.host", "/v1/messages"),
            InterceptDecision::Tunnel
        );
    }

    #[test]
    fn host_matches_pattern_supports_middle_wildcard() {
        assert!(host_matches_pattern(
            "bedrock.us-east-1.amazonaws.com",
            "bedrock.*.amazonaws.com"
        ));
        assert!(!host_matches_pattern(
            "bedrock.amazonaws.com",
            "bedrock.*.amazonaws.com"
        ));
    }

    #[test]
    fn contains_noise_keyword_matches_case_insensitive() {
        let keywords = vec!["Analytics".to_string()];
        assert!(contains_noise_keyword("/v1/ANALYTICS/query", &keywords));
        assert!(!contains_noise_keyword("/v1/messages", &keywords));
    }

    #[test]
    fn select_best_domain_match_prefers_longer_wildcard() {
        let entries = vec![
            DomainIndexEntry {
                host: "*.openai.com".to_string(),
                provider_id: "broad".to_string(),
                entry_type: EntryType::AiInference,
                paths: Vec::new(),
            },
            DomainIndexEntry {
                host: "api.*.openai.com".to_string(),
                provider_id: "specific".to_string(),
                entry_type: EntryType::AiInference,
                paths: Vec::new(),
            },
        ];
        let selected =
            select_best_domain_match(&entries, "api.us.openai.com").expect("match should exist");
        assert_eq!(selected.provider_id, "specific");
    }

    #[test]
    fn classify_uses_provider_type_from_provider_map() {
        let mut bundle = sample_bundle();
        let providers = BTreeMap::from([(
            "openai".to_string(),
            soth_oisp_types::bundle::ResolvedProvider {
                id: "openai".to_string(),
                name: "OpenAI".to_string(),
                entry_type: EntryType::Mcp,
                api_format: None,
                domains: vec!["api.openai.com".to_string()],
                user_agent_patterns: Vec::new(),
            },
        )]);
        bundle.providers = providers;
        bundle.domain_index = vec![DomainIndexEntry {
            host: "api.openai.com".to_string(),
            provider_id: "openai".to_string(),
            entry_type: EntryType::AiInference,
            paths: Vec::new(),
        }];
        let engine = OispEngine::new(bundle).unwrap();
        let class = engine.classify("api.openai.com").unwrap();
        assert_eq!(class.entry_type, EntryType::Mcp);
    }

    #[test]
    fn calculate_cost_uses_provider_hint_and_prefix_model_match() {
        let engine = OispEngine::new(parse_compiled_bundle(&json!({
            "version": "v1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "local",
            "domain_index": [
                { "host": "chatgpt.com", "provider_id": "chatgpt", "entry_type": "agent-app" }
            ],
            "providers": {
                "chatgpt": { "id": "chatgpt", "name": "ChatGPT", "type": "agent-app", "api_format": "openai" }
            },
            "filters": {},
            "pricing": {
                "openai": {
                    "gpt-5.3-codex": {
                        "input_per_million_usd": 2.0,
                        "output_per_million_usd": 8.0
                    }
                }
            }
        })).unwrap()).unwrap();

        let cost = engine.calculate_cost(
            &["chatgpt", "openai"],
            "gpt-5.3-codex-2026-02-01",
            1_000_000,
            500_000,
            None,
            None,
        );
        assert!(cost.is_some());
        assert!((cost.unwrap() - 6.0).abs() < 1e-9);
    }

    #[test]
    fn load_from_registry_cache_parses_registry_catalog_shape() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache.json");
        let envelope = json!({
            "fetched_at": "2026-02-13T00:00:00Z",
            "etag": "etag-1",
            "metadata": {
                "bundle_type": "local",
                "version": "catalog-v1",
                "sha256": "abc",
                "compiled_at": "2026-02-13T00:00:00Z",
                "provider_count": 1,
                "domain_count": 1,
                "format_count": 1,
                "size_bytes": 123
            },
            "bundle": {
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
                "noise_filter": { "words": [], "paths": [] },
                "passthrough": { "domains": [], "patterns": [] },
                "pricing": {
                    "openai": [
                        {
                            "model_pattern": "gpt-5",
                            "input_per_million": 1.0,
                            "output_per_million": 2.0
                        }
                    ]
                }
            }
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();

        let engine = OispEngine::load_from_registry_cache(&path)
            .unwrap()
            .unwrap();
        assert_eq!(engine.bundle_version(), "catalog-v1");
        assert_eq!(
            engine.should_intercept("api.openai.com", "/v1/chat/completions"),
            InterceptDecision::Intercept {
                provider_id: "openai".to_string(),
                entry_type: EntryType::AiInference
            }
        );
        assert_eq!(
            engine.should_intercept("api.openai.com", "/v1/models"),
            InterceptDecision::Tunnel
        );

        let cost = engine.calculate_cost(&["openai"], "gpt-5", 1_000_000, 1_000_000, None, None);
        assert_eq!(cost, Some(3.0));
    }

    #[test]
    fn registry_catalog_agent_paths_drop_catch_all_when_specific_paths_exist() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache.json");
        let envelope = json!({
            "metadata": {
                "bundle_type": "local",
                "version": "catalog-v1",
                "compiled_at": "2026-02-13T00:00:00Z"
            },
            "bundle": {
                "version": "catalog-v1",
                "compiled_at": "2026-02-13T00:00:00Z",
                "bundle_type": "local",
                "domain_index": {
                    "chatgpt.com": {
                        "category": "agent-apps",
                        "pattern_type": "exact",
                        "provider": "chatgpt"
                    }
                },
                "providers": {
                    "chatgpt": {
                        "name": "ChatGPT",
                        "category": "agent-apps"
                    }
                },
                "interception_patterns": {
                    "chatgpt.com": [
                        { "action": "intercept", "path": "**" },
                        { "action": "intercept", "path": "/backend-api/**/conversation" }
                    ]
                },
                "noise_filter": { "words": [], "paths": [] },
                "passthrough": { "domains": [], "patterns": [] },
                "pricing": {}
            }
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();

        let engine = OispEngine::load_from_registry_cache(&path)
            .unwrap()
            .unwrap();

        assert_eq!(
            engine.should_intercept("chatgpt.com", "/backend-api/f/conversation"),
            InterceptDecision::Intercept {
                provider_id: "chatgpt".to_string(),
                entry_type: EntryType::AgentApp
            }
        );
        assert_eq!(
            engine.should_intercept("chatgpt.com", "/backend-api/wham/usage"),
            InterceptDecision::Tunnel
        );
    }
}
