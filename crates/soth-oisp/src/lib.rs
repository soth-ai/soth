use anyhow::Context;
use serde_json::Value;
use soth_oisp_types::bundle::{parse_compiled_bundle, CompiledBundle, DomainIndexEntry};
use soth_oisp_types::provider::{EntryType, ModelPricing};
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

    pub fn catalog_domain_count(&self) -> usize {
        self.bundle.catalog_domains.len()
    }

    pub fn is_catalog_domain(&self, host: &str) -> bool {
        host_matches_any(host, &self.bundle.catalog_domains)
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

    /// Host-only interception decision for CONNECT/TLS handshake phase where path is unknown.
    pub fn should_intercept_host(&self, host: &str) -> bool {
        if host_matches_any(host, &self.bundle.filters.passthrough) {
            return false;
        }

        if !self.bundle.filters.whitelist.is_empty()
            && !host_matches_any(host, &self.bundle.filters.whitelist)
        {
            return false;
        }

        if host_matches_any(host, &self.bundle.filters.blacklist) {
            return false;
        }

        self.classify(host).is_some()
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
        match load_from_registry_cache_path(path) {
            Ok(Some(engine)) => Ok(Some(engine)),
            Ok(None) => load_from_registry_cache_path(&registry_cache_last_good_path(path)),
            Err(primary_error) => {
                let fallback_path = registry_cache_last_good_path(path);
                if !fallback_path.exists() {
                    return Err(primary_error);
                }
                match load_from_registry_cache_path(&fallback_path) {
                    Ok(Some(engine)) => Ok(Some(engine)),
                    Ok(None) => Err(primary_error),
                    Err(fallback_error) => Err(anyhow::anyhow!(
                        "primary registry cache invalid ({primary_error}); last-known-good cache invalid ({fallback_error})"
                    )),
                }
            }
        }
    }
}

fn registry_cache_last_good_path(path: &Path) -> std::path::PathBuf {
    let filename = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "registry_bundle_cache.json".to_string());
    let fallback_filename = format!("{filename}.last_good");
    match path.parent() {
        Some(parent) => parent.join(fallback_filename),
        None => std::path::PathBuf::from(fallback_filename),
    }
}

fn load_from_registry_cache_path(path: &Path) -> anyhow::Result<Option<OispEngine>> {
    if !path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading registry cache {}", path.display()))?;
    let root: Value = serde_json::from_str(&content)
        .with_context(|| format!("failed parsing registry cache {}", path.display()))?;
    let bundle_value = extract_compiled_bundle_value(&root)
        .context("registry cache missing compiled bundle payload")?;

    let bundle = parse_compiled_bundle(&bundle_value).context("failed parsing OISP bundle")?;
    Ok(Some(OispEngine::new(bundle)?))
}

fn extract_compiled_bundle_value(root: &Value) -> anyhow::Result<Value> {
    if parse_compiled_bundle(root).is_ok() {
        return Ok(root.clone());
    }

    let object = root
        .as_object()
        .context("registry cache root must be an object")?;
    if let Some(inner) = object.get("bundle").cloned() {
        return Ok(inner);
    }
    if let Some(inner) = object.get("compiled_bundle").cloned() {
        return Ok(inner);
    }
    if let Some(data) = object.get("data").and_then(Value::as_object) {
        if let Some(inner) = data.get("bundle").cloned() {
            return Ok(inner);
        }
        if let Some(inner) = data.get("compiled_bundle").cloned() {
            return Ok(inner);
        }
    }
    anyhow::bail!("registry cache envelope does not contain bundle/compiled_bundle field");
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

        assert!(engine.should_intercept_host("api.openai.com"));
    }

    #[test]
    fn catalog_domains_are_available_for_discovery_checks() {
        let engine = OispEngine::new(
            parse_compiled_bundle(&json!({
                "version": "v2",
                "compiled_at": "2026-02-13T00:00:00Z",
                "bundle_type": "cloud",
                "core": {
                    "providers": {
                        "openai": { "id": "openai", "name": "OpenAI", "type": "ai-inference" }
                    },
                    "domain_index": [
                        {
                            "host": "api.openai.com",
                            "provider_id": "openai",
                            "entry_type": "ai-inference"
                        }
                    ]
                },
                "filters": {},
                "catalog": {
                    "domains": ["server.codeium.com", "*.githubcopilot.com"]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        assert_eq!(engine.catalog_domain_count(), 2);
        assert!(engine.is_catalog_domain("server.codeium.com"));
        assert!(engine.is_catalog_domain("api.githubcopilot.com"));
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
    fn load_from_registry_cache_accepts_catalog_registry_shape() {
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
        let cost = engine.calculate_cost(&["openai"], "gpt-5", 1_000_000, 1_000_000, None, None);
        assert_eq!(cost, Some(3.0));
    }

    #[test]
    fn load_from_registry_cache_falls_back_to_last_good_when_primary_invalid() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache.json");
        let valid_envelope = json!({
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
        let fallback_path = path
            .parent()
            .unwrap()
            .join("registry_bundle_cache.json.last_good");
        std::fs::write(
            &fallback_path,
            serde_json::to_vec_pretty(&valid_envelope).unwrap(),
        )
        .unwrap();

        let invalid_primary = json!({
            "schema_version": 1,
            "fetched_at": "2026-02-13T00:00:00Z",
            "etag": "etag-bad",
            "metadata": {
                "bundle_type": "local",
                "version": "bad-v1",
                "sha256": "bad",
                "compiled_at": "2026-02-13T00:00:00Z",
                "provider_count": 0,
                "domain_count": 0,
                "format_count": 1,
                "size_bytes": 123
            },
            "bundle": { "version": "bad-v1" }
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&invalid_primary).unwrap()).unwrap();

        let engine = OispEngine::load_from_registry_cache(&path)
            .unwrap()
            .unwrap();

        assert_eq!(
            engine.should_intercept("api.openai.com", "/v1/chat/completions"),
            InterceptDecision::Intercept {
                provider_id: "openai".to_string(),
                entry_type: EntryType::AiInference
            }
        );
        assert_eq!(engine.bundle_version(), "v1");
    }
}
