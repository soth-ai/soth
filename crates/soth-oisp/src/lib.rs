use anyhow::Context;
use serde_json::Value;
use soth_oisp_types::bundle::{parse_compiled_bundle, CompiledBundle, DomainIndexEntry};
use soth_oisp_types::provider::EntryType;
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

        match self.classify(host) {
            Some(classification) => InterceptDecision::Intercept {
                provider_id: classification.provider_id,
                entry_type: classification.entry_type,
            },
            None => InterceptDecision::Tunnel,
        }
    }

    pub fn load_from_registry_cache(path: &Path) -> anyhow::Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed reading registry cache {}", path.display()))?;
        let root: Value = serde_json::from_str(&content)
            .with_context(|| format!("failed parsing registry cache {}", path.display()))?;
        let bundle_value = if root.get("bundle").is_some() {
            root.get("bundle")
                .cloned()
                .context("registry cache envelope missing bundle field")?
        } else {
            root
        };

        let bundle =
            parse_compiled_bundle(&bundle_value).context("failed parsing compiled bundle")?;
        Ok(Some(Self::new(bundle)?))
    }
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
}
