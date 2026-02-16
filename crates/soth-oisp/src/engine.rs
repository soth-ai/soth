use crate::cache::BoundedCache;
use crate::matchers::{
    contains_noise_keyword_for_host, contains_noise_keyword_text, host_matches_any,
    normalize_host_for_matching, path_matches_any, select_best_domain_match,
};
use crate::parse_helpers::{
    decode_grpc_frame_payloads, extract_string_from_field_path_value,
    extract_usage_from_response_value, format_uses_grpc_frames, format_uses_strip_xssi,
    parse_json_with_xssi_fallback, parse_stream_parser_config, parse_stream_payload_with_config,
    strip_json_security_prefix_bytes,
};
use crate::pricing::{calculate_cost_from_pricing, find_model_pricing};
use crate::registry_cache::{load_from_registry_cache_path, registry_cache_last_good_path};
use crate::types;
use crate::{
    Classification, CompiledBundle, EntryType, InterceptDecision, OispEngine, OispStreamParser,
    ProviderUsage,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

impl OispStreamParser {
    pub fn process_chunk(&mut self, chunk: &[u8]) {
        if !chunk.is_empty() {
            self.buffer.extend_from_slice(chunk);
        }
    }

    pub fn finalize(self) -> Option<ProviderUsage> {
        parse_stream_payload_with_config(&self.buffer, &self.config)
    }
}

impl OispEngine {
    pub fn new(bundle: CompiledBundle) -> anyhow::Result<Self> {
        bundle.validate()?;
        Ok(Self {
            bundle: Arc::new(bundle),
            classification_cache: Arc::new(Mutex::new(BoundedCache::new(2_048))),
            detection_cache: Arc::new(Mutex::new(BoundedCache::new(8_192))),
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

    pub fn ai_inference_domain_patterns(&self) -> Vec<String> {
        let mut patterns = BTreeSet::new();
        for entry in &self.bundle.domain_index {
            if entry.entry_type == EntryType::AiInference {
                patterns.insert(entry.host.clone());
            }
        }
        patterns.into_iter().collect()
    }

    pub fn whitelist_count(&self) -> usize {
        self.bundle.filters.whitelist.len()
    }

    pub fn blacklist_count(&self) -> usize {
        self.bundle.filters.blacklist.len()
    }

    pub fn passthrough_count(&self) -> usize {
        self.bundle.filters.passthrough.len()
    }

    pub fn noise_keyword_count(&self) -> usize {
        self.bundle.filters.noise_keywords.len()
    }

    pub fn is_catalog_domain(&self, host: &str) -> bool {
        let host = normalize_host_for_matching(host);
        host_matches_any(host.as_str(), &self.bundle.catalog_domains)
    }

    pub fn classify(&self, host: &str) -> Option<Classification> {
        let host = normalize_host_for_matching(host);
        if host.is_empty() {
            return None;
        }
        if let Some(cached) = self
            .classification_cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&host))
        {
            return cached;
        }
        let outcome =
            select_best_domain_match(&self.bundle.domain_index, host.as_str()).and_then(|entry| {
                self.bundle
                    .providers
                    .get(&entry.provider_id)
                    .map(|provider| Classification {
                        provider_id: entry.provider_id.clone(),
                        entry_type: provider.entry_type.clone(),
                        api_format: provider.api_format.clone(),
                    })
            });
        if let Ok(mut cache) = self.classification_cache.lock() {
            cache.insert(host, outcome.clone());
        }
        outcome
    }

    pub fn should_intercept(&self, host: &str, path: &str) -> InterceptDecision {
        let host = normalize_host_for_matching(host);
        let path_only = path.split_once('?').map(|(raw, _)| raw).unwrap_or(path);

        if contains_noise_keyword_for_host(host.as_str(), path, &self.bundle.filters.noise_keywords)
        {
            return InterceptDecision::Noise;
        }

        if host_matches_any(host.as_str(), &self.bundle.filters.passthrough) {
            return InterceptDecision::Passthrough;
        }

        if !self.bundle.filters.whitelist.is_empty()
            && !host_matches_any(host.as_str(), &self.bundle.filters.whitelist)
        {
            return InterceptDecision::Tunnel;
        }

        if host_matches_any(host.as_str(), &self.bundle.filters.blacklist) {
            return InterceptDecision::Tunnel;
        }

        let Some(entry) = select_best_domain_match(&self.bundle.domain_index, host.as_str()) else {
            return InterceptDecision::Tunnel;
        };

        if !entry.paths.is_empty() && !path_matches_any(path_only, &entry.paths) {
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
        let host = normalize_host_for_matching(host);

        if host_matches_any(host.as_str(), &self.bundle.filters.passthrough) {
            return false;
        }

        if !self.bundle.filters.whitelist.is_empty()
            && !host_matches_any(host.as_str(), &self.bundle.filters.whitelist)
        {
            return false;
        }

        if host_matches_any(host.as_str(), &self.bundle.filters.blacklist) {
            return false;
        }

        self.classify(host.as_str()).is_some()
    }

    /// Returns true when `text` contains any bundle noise keyword.
    pub fn matches_noise_keyword(&self, text: &str) -> bool {
        contains_noise_keyword_text(text, &self.bundle.filters.noise_keywords)
    }

    /// Calculate request cost using bundle pricing for a provider/model pair.
    ///
    /// `provider_hints` are checked in order (for example: provider_id then api_format).
    /// No global fallback scan is performed; callers must provide explicit provider hints.
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

        None
    }

    /// Apply provider format body transforms before request/response extraction.
    ///
    /// Supported transforms:
    /// - XSSI stripping prefixes
    /// - gRPC frame envelope decoding (length-prefixed binary)
    pub fn apply_body_transform(&self, provider_id: &str, body: &[u8]) -> Vec<u8> {
        let mut transformed = body.to_vec();
        let Some(format_value) = self.resolve_provider_format(provider_id) else {
            return transformed;
        };

        if format_uses_grpc_frames(format_value) {
            transformed = decode_grpc_frame_payloads(&transformed).unwrap_or(transformed);
        }
        if format_uses_strip_xssi(format_value) {
            transformed = strip_json_security_prefix_bytes(&transformed).to_vec();
        }
        transformed
    }

    /// Extract model from request payload according to provider format request parser.
    pub fn extract_model_from_request(&self, provider_id: &str, body: &[u8]) -> Option<String> {
        let transformed = self.apply_body_transform(provider_id, body);
        let format_value = self.resolve_provider_format(provider_id)?;
        let request = format_value.get("request")?;
        let model_path = request.get("model")?;
        let root = parse_json_with_xssi_fallback(&transformed)?;
        extract_string_from_field_path_value(&root, model_path)
    }

    /// Extract model from response payload according to provider format response parser.
    pub fn extract_model_from_response(&self, provider_id: &str, body: &[u8]) -> Option<String> {
        self.extract_usage_from_response(provider_id, body)
            .and_then(|usage| usage.model)
    }

    /// Extract usage/model fields from response payload using provider format response parser.
    pub fn extract_usage_from_response(
        &self,
        provider_id: &str,
        body: &[u8],
    ) -> Option<ProviderUsage> {
        let transformed = self.apply_body_transform(provider_id, body);
        let format_value = self.resolve_provider_format(provider_id)?;
        let response = format_value.get("response")?;
        extract_usage_from_response_value(&transformed, response)
    }

    /// Create a stateful stream parser configured from provider format rules.
    pub fn create_stream_parser(&self, provider_id: &str) -> Option<OispStreamParser> {
        let format_value = self.resolve_provider_format(provider_id)?;
        let response = format_value.get("response")?;
        let stream = response.get("stream")?;
        let config = parse_stream_parser_config(stream)?;
        Some(OispStreamParser {
            config,
            buffer: Vec::new(),
        })
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

    fn resolve_provider_format(&self, provider_id: &str) -> Option<&Value> {
        let provider = self.bundle.providers.get(provider_id)?;
        let mut keys = Vec::with_capacity(2);
        if let Some(api_format) = provider.api_format.as_deref() {
            keys.push(api_format);
        }
        keys.push(provider_id);

        for key in &keys {
            if let Some(found) = self.bundle.formats.get(*key) {
                return Some(found);
            }
            if let Some(found) = self
                .bundle
                .formats
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(key))
                .map(|(_, value)| value)
            {
                return Some(found);
            }
        }

        None
    }

    pub(crate) fn resolve_provider(
        &self,
        provider_id: &str,
    ) -> Option<&types::bundle::ResolvedProvider> {
        self.bundle.providers.get(provider_id).or_else(|| {
            self.bundle
                .providers
                .iter()
                .find(|(candidate, _)| candidate.eq_ignore_ascii_case(provider_id))
                .map(|(_, provider)| provider)
        })
    }
}
