use anyhow::Context;
use regex::Regex;
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;

pub mod types;

use types::bundle::{parse_compiled_bundle, CompiledBundle, DomainIndexEntry};
use types::provider::{DetectionRule, EntryType, ModelPricing, StreamFormat};

const EMBEDDED_MINIMAL_BUNDLE_JSON: &str = include_str!("../assets/minimal_registry_bundle.json");

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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: Option<u64>,
    pub cache_write_tokens: Option<u64>,
    pub reasoning_tokens: Option<u64>,
    pub model: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetectionContext {
    pub host: Option<String>,
    pub path: Option<String>,
    pub user_agent: Option<String>,
    pub model: Option<String>,
    pub process_name: Option<String>,
    pub bundle_id: Option<String>,
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    pub env_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DetectionOutcome {
    pub agent: Option<String>,
    pub detection_reason: String,
    pub parse_confidence: f64,
    pub target_entity_id: Option<String>,
}

#[derive(Debug, Clone)]
struct DetectionCandidate {
    outcome: DetectionOutcome,
    precedence: i32,
    stable_key: String,
}

impl ProviderUsage {
    pub fn has_signal(&self) -> bool {
        self.input_tokens > 0
            || self.output_tokens > 0
            || self.cache_read_tokens.unwrap_or(0) > 0
            || self.cache_write_tokens.unwrap_or(0) > 0
            || self.reasoning_tokens.unwrap_or(0) > 0
            || self
                .model
                .as_deref()
                .map(str::trim)
                .map(|s| !s.is_empty())
                .unwrap_or(false)
    }
}

#[derive(Debug, Clone)]
struct StreamRuleConfig {
    when: Option<String>,
    extract: Vec<(String, Value)>,
    extract_usage: Vec<(String, Value)>,
}

#[derive(Debug, Clone)]
struct StreamParserConfig {
    format: StreamFormat,
    prefixes: Vec<String>,
    skip_values: Vec<String>,
    header_strip: Option<String>,
    rules: Vec<StreamRuleConfig>,
}

#[derive(Debug, Clone)]
pub struct OispStreamParser {
    config: StreamParserConfig,
    buffer: Vec<u8>,
}

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
        let entry = select_best_domain_match(&self.bundle.domain_index, host.as_str())?;
        let provider = self.bundle.providers.get(&entry.provider_id)?;
        Some(Classification {
            provider_id: entry.provider_id.clone(),
            entry_type: provider.entry_type.clone(),
            api_format: provider.api_format.clone(),
        })
    }

    pub fn evaluate_detection_for_host(
        &self,
        host: &str,
        context: &DetectionContext,
    ) -> Option<DetectionOutcome> {
        let classification = self.classify(host)?;
        self.evaluate_detection(classification.provider_id.as_str(), context)
    }

    pub fn evaluate_detection(
        &self,
        provider_id: &str,
        context: &DetectionContext,
    ) -> Option<DetectionOutcome> {
        let provider = self.resolve_provider(provider_id)?;
        let mut candidates = Vec::<DetectionCandidate>::new();

        if let Some(detection) = provider.detection.as_ref() {
            collect_detection_candidates(
                &mut candidates,
                DetectionRuleGroup::Model,
                &detection.model_rules,
                provider,
                context,
            );
            collect_detection_candidates(
                &mut candidates,
                DetectionRuleGroup::Path,
                &detection.path_rules,
                provider,
                context,
            );
            collect_detection_candidates(
                &mut candidates,
                DetectionRuleGroup::Ua,
                &detection.ua_rules,
                provider,
                context,
            );
            collect_detection_candidates(
                &mut candidates,
                DetectionRuleGroup::Process,
                &detection.process_rules,
                provider,
                context,
            );
            collect_detection_candidates(
                &mut candidates,
                DetectionRuleGroup::Env,
                &detection.env_rules,
                provider,
                context,
            );
        }

        if let Some(best) = candidates
            .into_iter()
            .max_by(|left, right| compare_detection_candidates(left, right))
        {
            return Some(best.outcome);
        }

        let fallback_agent =
            (provider.entry_type == EntryType::AgentApp).then(|| provider.id.clone());
        let fallback_reason = if fallback_agent.is_some() {
            "host_classification"
        } else {
            "fallback_unknown"
        };
        let fallback_confidence = if fallback_agent.is_some() { 0.70 } else { 0.0 };

        Some(DetectionOutcome {
            agent: fallback_agent,
            detection_reason: fallback_reason.to_string(),
            parse_confidence: fallback_confidence,
            target_entity_id: provider.entity_id.clone(),
        })
    }

    pub fn should_intercept(&self, host: &str, path: &str) -> InterceptDecision {
        let host = normalize_host_for_matching(host);
        let path_only = path.split_once('?').map(|(raw, _)| raw).unwrap_or(path);

        if contains_noise_keyword(path, &self.bundle.filters.noise_keywords) {
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
        contains_noise_keyword(text, &self.bundle.filters.noise_keywords)
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

    /// Load the repository-shipped minimal bundle used as local fallback when cache/cloud bundle
    /// is missing or invalid.
    pub fn load_embedded_minimal_bundle() -> anyhow::Result<Self> {
        let root: Value = serde_json::from_str(EMBEDDED_MINIMAL_BUNDLE_JSON)
            .context("failed parsing embedded minimal bundle JSON")?;
        let bundle_value = extract_compiled_bundle_value(&root)
            .context("embedded minimal bundle missing compiled payload")?;
        build_engine_from_bundle_value(&bundle_value)
            .context("failed loading embedded minimal bundle")
    }

    /// Overlay embedded minimal bundle coverage onto a loaded bundle engine.
    ///
    /// This preserves cloud/cache bundle behavior while ensuring baseline host/format coverage
    /// for core providers is always present.
    pub fn with_embedded_overlay(&self) -> anyhow::Result<Self> {
        let mut merged = (*self.bundle).clone();
        let embedded = embedded_minimal_compiled_bundle()?;
        merge_compiled_bundle(&mut merged, embedded);
        OispEngine::new(merged)
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

    fn resolve_provider(&self, provider_id: &str) -> Option<&types::bundle::ResolvedProvider> {
        self.bundle.providers.get(provider_id).or_else(|| {
            self.bundle
                .providers
                .iter()
                .find(|(candidate, _)| candidate.eq_ignore_ascii_case(provider_id))
                .map(|(_, provider)| provider)
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DetectionRuleGroup {
    Model,
    Path,
    Ua,
    Process,
    Env,
}

fn compare_detection_candidates(
    left: &DetectionCandidate,
    right: &DetectionCandidate,
) -> std::cmp::Ordering {
    left.precedence
        .cmp(&right.precedence)
        .then_with(|| {
            left.outcome
                .parse_confidence
                .total_cmp(&right.outcome.parse_confidence)
        })
        // Keep stable deterministic tie-breaks: lexical-min wins.
        .then_with(|| right.stable_key.cmp(&left.stable_key))
}

fn collect_detection_candidates(
    out: &mut Vec<DetectionCandidate>,
    group: DetectionRuleGroup,
    rules: &[DetectionRule],
    provider: &types::bundle::ResolvedProvider,
    context: &DetectionContext,
) {
    for rule in rules {
        if !rule.enabled.unwrap_or(true) {
            continue;
        }
        if !detection_rule_matches_context(rule, group, context) {
            continue;
        }

        let detection_reason = normalize_string(rule.reason.clone())
            .unwrap_or_else(|| detection_group_default_reason(group).to_string());
        let parse_confidence = rule
            .confidence
            .map(|value| value.clamp(0.0, 1.0))
            .unwrap_or_else(|| detection_group_default_confidence(group));
        let agent = normalize_string(rule.agent.clone())
            .or_else(|| (provider.entry_type == EntryType::AgentApp).then(|| provider.id.clone()));
        let stable_key = format!(
            "{}|{}|{}|{}",
            rule.id.clone().unwrap_or_default(),
            detection_reason,
            agent.clone().unwrap_or_default(),
            serialize_matchers_for_key(rule)
        );

        out.push(DetectionCandidate {
            outcome: DetectionOutcome {
                agent,
                detection_reason,
                parse_confidence,
                target_entity_id: provider.entity_id.clone(),
            },
            precedence: detection_group_precedence(group) + rule.priority.unwrap_or(0),
            stable_key,
        });
    }
}

fn detection_group_precedence(group: DetectionRuleGroup) -> i32 {
    match group {
        DetectionRuleGroup::Model => 5_000,
        DetectionRuleGroup::Path => 4_000,
        DetectionRuleGroup::Ua => 3_000,
        DetectionRuleGroup::Process => 2_000,
        DetectionRuleGroup::Env => 1_000,
    }
}

fn detection_group_default_reason(group: DetectionRuleGroup) -> &'static str {
    match group {
        DetectionRuleGroup::Model => "model_match",
        DetectionRuleGroup::Path => "path_match",
        DetectionRuleGroup::Ua => "ua_match",
        DetectionRuleGroup::Process => "process_match",
        DetectionRuleGroup::Env => "env_match",
    }
}

fn detection_group_default_confidence(group: DetectionRuleGroup) -> f64 {
    match group {
        DetectionRuleGroup::Model => 0.98,
        DetectionRuleGroup::Path => 0.95,
        DetectionRuleGroup::Ua => 0.90,
        DetectionRuleGroup::Process => 0.85,
        DetectionRuleGroup::Env => 0.80,
    }
}

fn detection_rule_matches_context(
    rule: &DetectionRule,
    group: DetectionRuleGroup,
    context: &DetectionContext,
) -> bool {
    if rule.matchers.is_empty() {
        return false;
    }

    let mut matched_any = false;
    for (raw_key, value) in &rule.matchers {
        let key = raw_key.trim().to_ascii_lowercase();
        if key.is_empty() {
            continue;
        }
        let is_match = match key.as_str() {
            "contains" | "pattern" | "value" => {
                match_group_values(group, context, value, string_contains_case_insensitive)
            }
            "equals" => match_group_values(group, context, value, string_equals_case_insensitive),
            "prefix" => match_group_values(group, context, value, string_prefix_case_insensitive),
            "suffix" => match_group_values(group, context, value, string_suffix_case_insensitive),
            "regex" => match_group_values(group, context, value, string_regex_match),
            "path" => context
                .path
                .as_deref()
                .is_some_and(|path| match_patterns(path, value, path_matches_pattern)),
            "host" => context
                .host
                .as_deref()
                .is_some_and(|host| match_patterns(host, value, host_matches_pattern)),
            "model" => context
                .model
                .as_deref()
                .is_some_and(|model| match_patterns(model, value, wildcard_or_exact_match)),
            "process" => context
                .process_name
                .as_deref()
                .is_some_and(|name| match_patterns(name, value, wildcard_or_exact_match)),
            "bundle_id" => context
                .bundle_id
                .as_deref()
                .is_some_and(|bundle_id| match_patterns(bundle_id, value, wildcard_or_exact_match)),
            "env" | "env_key" => match_env_keys(context, value),
            "client_name" => context
                .client_name
                .as_deref()
                .is_some_and(|name| match_patterns(name, value, wildcard_or_exact_match)),
            "client_version" => context
                .client_version
                .as_deref()
                .is_some_and(|version| match_patterns(version, value, wildcard_or_exact_match)),
            _ => false,
        };
        matched_any = true;
        if !is_match {
            return false;
        }
    }

    matched_any
}

fn match_group_values(
    group: DetectionRuleGroup,
    context: &DetectionContext,
    matcher_value: &Value,
    matcher: fn(&str, &str) -> bool,
) -> bool {
    let subjects = detection_group_subjects(group, context);
    if subjects.is_empty() {
        return false;
    }
    let patterns = detection_matcher_patterns(matcher_value);
    if patterns.is_empty() {
        return false;
    }

    subjects
        .iter()
        .any(|subject| patterns.iter().any(|pattern| matcher(subject, pattern)))
}

fn detection_group_subjects<'a>(
    group: DetectionRuleGroup,
    context: &'a DetectionContext,
) -> Vec<&'a str> {
    let mut out = Vec::new();
    match group {
        DetectionRuleGroup::Model => {
            if let Some(model) = context.model.as_deref() {
                out.push(model);
            }
        }
        DetectionRuleGroup::Path => {
            if let Some(path) = context.path.as_deref() {
                out.push(path);
            }
        }
        DetectionRuleGroup::Ua => {
            if let Some(ua) = context.user_agent.as_deref() {
                out.push(ua);
            }
            if let Some(client) = context.client_name.as_deref() {
                out.push(client);
            }
        }
        DetectionRuleGroup::Process => {
            if let Some(name) = context.process_name.as_deref() {
                out.push(name);
            }
            if let Some(bundle_id) = context.bundle_id.as_deref() {
                out.push(bundle_id);
            }
        }
        DetectionRuleGroup::Env => {
            for key in &context.env_keys {
                if !key.trim().is_empty() {
                    out.push(key.as_str());
                }
            }
        }
    }
    out
}

fn match_env_keys(context: &DetectionContext, matcher_value: &Value) -> bool {
    if context.env_keys.is_empty() {
        return false;
    }
    let patterns = detection_matcher_patterns(matcher_value);
    if patterns.is_empty() {
        return false;
    }
    context.env_keys.iter().any(|entry| {
        patterns
            .iter()
            .any(|pattern| wildcard_or_exact_match(entry.as_str(), pattern))
    })
}

fn match_patterns(subject: &str, matcher_value: &Value, matcher: fn(&str, &str) -> bool) -> bool {
    let patterns = detection_matcher_patterns(matcher_value);
    if patterns.is_empty() {
        return false;
    }
    patterns.iter().any(|pattern| matcher(subject, pattern))
}

fn detection_matcher_patterns(value: &Value) -> Vec<String> {
    match value {
        Value::String(raw) => normalize_string(Some(raw.clone())).into_iter().collect(),
        Value::Array(entries) => entries
            .iter()
            .filter_map(|entry| match entry {
                Value::String(raw) => normalize_string(Some(raw.clone())),
                Value::Number(number) => Some(number.to_string()),
                Value::Bool(flag) => Some(flag.to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn wildcard_or_exact_match(text: &str, pattern: &str) -> bool {
    let text = text.trim().to_ascii_lowercase();
    let pattern = pattern.trim().to_ascii_lowercase();
    if text.is_empty() || pattern.is_empty() {
        return false;
    }
    if pattern.contains('*') {
        wildcard_match(text.as_str(), pattern.as_str())
    } else {
        text == pattern
    }
}

fn string_contains_case_insensitive(subject: &str, pattern: &str) -> bool {
    subject
        .to_ascii_lowercase()
        .contains(pattern.trim().to_ascii_lowercase().as_str())
}

fn string_equals_case_insensitive(subject: &str, pattern: &str) -> bool {
    subject.trim().eq_ignore_ascii_case(pattern.trim())
}

fn string_prefix_case_insensitive(subject: &str, pattern: &str) -> bool {
    subject
        .to_ascii_lowercase()
        .starts_with(pattern.trim().to_ascii_lowercase().as_str())
}

fn string_suffix_case_insensitive(subject: &str, pattern: &str) -> bool {
    subject
        .to_ascii_lowercase()
        .ends_with(pattern.trim().to_ascii_lowercase().as_str())
}

fn string_regex_match(subject: &str, pattern: &str) -> bool {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return false;
    }
    Regex::new(trimmed)
        .ok()
        .is_some_and(|regex| regex.is_match(subject))
}

fn serialize_matchers_for_key(rule: &DetectionRule) -> String {
    let mut keys = rule.matchers.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    let mut items = Vec::new();
    for key in keys {
        let value = rule
            .matchers
            .get(key.as_str())
            .map(serde_json::to_string)
            .transpose()
            .ok()
            .flatten()
            .unwrap_or_default();
        items.push(format!("{key}={value}"));
    }
    items.join("|")
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
    Ok(Some(build_engine_from_bundle_value(&bundle_value)?))
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

fn build_engine_from_bundle_value(bundle_value: &Value) -> anyhow::Result<OispEngine> {
    validate_runtime_bundle_contract(bundle_value)
        .context("bundle payload failed runtime contract validation")?;
    let bundle = parse_compiled_bundle(bundle_value).context("failed parsing OISP bundle")?;
    OispEngine::new(bundle).context("failed constructing OISP engine")
}

fn validate_runtime_bundle_contract(bundle_value: &Value) -> anyhow::Result<()> {
    let object = bundle_value
        .as_object()
        .context("bundle payload root must be an object")?;

    let schema_version = object
        .get("schema_version")
        .and_then(Value::as_u64)
        .context("bundle payload missing required `schema_version`")?;
    if schema_version == 0 {
        anyhow::bail!("bundle payload `schema_version` must be greater than 0");
    }

    let filters = object
        .get("filters")
        .and_then(Value::as_object)
        .context("bundle payload missing required `filters` object")?;
    for key in ["whitelist", "blacklist", "passthrough", "noise_keywords"] {
        let value = filters
            .get(key)
            .with_context(|| format!("bundle payload filters missing required `{key}`"))?;
        if !value.is_array() {
            anyhow::bail!("bundle payload filters.{key} must be an array");
        }
    }

    Ok(())
}

fn embedded_minimal_compiled_bundle() -> anyhow::Result<CompiledBundle> {
    let root: Value = serde_json::from_str(EMBEDDED_MINIMAL_BUNDLE_JSON)
        .context("failed parsing embedded minimal bundle JSON")?;
    let bundle_value = extract_compiled_bundle_value(&root)
        .context("embedded minimal bundle missing compiled payload")?;
    parse_compiled_bundle(&bundle_value).context("failed parsing embedded minimal bundle")
}

fn entry_type_key(entry_type: &EntryType) -> &'static str {
    match entry_type {
        EntryType::AiInference => "ai_inference",
        EntryType::AgentApp => "agent_app",
        EntryType::Mcp => "mcp",
    }
}

fn dedupe_sort(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn merge_compiled_bundle(primary: &mut CompiledBundle, baseline: CompiledBundle) {
    for (provider_id, provider) in baseline.providers {
        primary.providers.entry(provider_id).or_insert(provider);
    }

    let mut index_pos: std::collections::HashMap<(String, String, String), usize> =
        std::collections::HashMap::new();
    for (idx, entry) in primary.domain_index.iter().enumerate() {
        index_pos.insert(
            (
                entry.host.clone(),
                entry.provider_id.clone(),
                entry_type_key(&entry.entry_type).to_string(),
            ),
            idx,
        );
    }
    for mut entry in baseline.domain_index {
        let key = (
            entry.host.clone(),
            entry.provider_id.clone(),
            entry_type_key(&entry.entry_type).to_string(),
        );
        if let Some(existing_idx) = index_pos.get(&key).copied() {
            if let Some(existing) = primary.domain_index.get_mut(existing_idx) {
                existing.paths.append(&mut entry.paths);
                dedupe_sort(&mut existing.paths);
            }
        } else {
            index_pos.insert(key, primary.domain_index.len());
            primary.domain_index.push(entry);
        }
    }

    for (format_key, format_value) in baseline.formats {
        primary.formats.entry(format_key).or_insert(format_value);
    }

    for (provider_id, models) in baseline.pricing {
        let provider_models = primary.pricing.entry(provider_id).or_default();
        for (model, price) in models {
            provider_models.entry(model).or_insert(price);
        }
    }

    primary
        .filters
        .whitelist
        .extend(baseline.filters.whitelist.into_iter());
    primary
        .filters
        .blacklist
        .extend(baseline.filters.blacklist.into_iter());
    primary
        .filters
        .passthrough
        .extend(baseline.filters.passthrough.into_iter());
    primary
        .filters
        .noise_keywords
        .extend(baseline.filters.noise_keywords.into_iter());
    dedupe_sort(&mut primary.filters.whitelist);
    dedupe_sort(&mut primary.filters.blacklist);
    dedupe_sort(&mut primary.filters.passthrough);
    dedupe_sort(&mut primary.filters.noise_keywords);

    primary
        .catalog_domains
        .extend(baseline.catalog_domains.into_iter());
    dedupe_sort(&mut primary.catalog_domains);

    primary.stats.providers = primary.providers.len();
    primary.stats.domains = primary.domain_index.len();
    primary.stats.formats = primary.formats.len();
}

fn format_uses_strip_xssi(format_value: &Value) -> bool {
    let Some(body_transform) = format_value.get("body_transform") else {
        return false;
    };

    match body_transform {
        Value::String(raw) => {
            let normalized = raw.trim().to_ascii_lowercase();
            normalized == "strip_xssi" || normalized == "strip-xssi"
        }
        Value::Array(entries) => entries.iter().any(|entry| {
            entry
                .as_str()
                .map(|raw| {
                    let normalized = raw.trim().to_ascii_lowercase();
                    normalized == "strip_xssi" || normalized == "strip-xssi"
                })
                .unwrap_or(false)
        }),
        Value::Object(map) => {
            map.contains_key("strip_prefix")
                || map
                    .get("strip_xssi")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
        }
        _ => false,
    }
}

fn format_uses_grpc_frames(format_value: &Value) -> bool {
    let Some(body_transform) = format_value.get("body_transform") else {
        return false;
    };

    match body_transform {
        Value::String(raw) => {
            let normalized = raw.trim().to_ascii_lowercase();
            normalized == "grpc_frames" || normalized == "grpc-frames"
        }
        Value::Array(entries) => entries.iter().any(|entry| {
            entry
                .as_str()
                .map(|raw| {
                    let normalized = raw.trim().to_ascii_lowercase();
                    normalized == "grpc_frames" || normalized == "grpc-frames"
                })
                .unwrap_or(false)
        }),
        Value::Object(map) => map
            .get("grpc_frames")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        _ => false,
    }
}

fn strip_json_security_prefix_bytes(payload: &[u8]) -> &[u8] {
    let Ok(text) = std::str::from_utf8(payload) else {
        return payload;
    };
    let stripped = strip_json_security_prefix_text(text);
    if stripped.len() == text.len() {
        payload
    } else {
        stripped.as_bytes()
    }
}

fn strip_json_security_prefix_text(text: &str) -> &str {
    let trimmed = text.trim_start_matches(|ch: char| ch.is_ascii_whitespace());
    for prefix in [")]}'", ")]}',", "for(;;);", "while(1);"] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return rest
                .trim_start_matches(|ch: char| ch.is_ascii_whitespace() || ch == ',' || ch == ';');
        }
    }
    text
}

fn parse_json_with_xssi_fallback(payload: &[u8]) -> Option<Value> {
    if let Ok(root) = serde_json::from_slice::<Value>(payload) {
        return Some(root);
    }

    let stripped = strip_json_security_prefix_bytes(payload);
    if stripped.len() != payload.len() {
        return serde_json::from_slice::<Value>(stripped).ok();
    }

    None
}

fn extract_usage_from_response_value(payload: &[u8], response: &Value) -> Option<ProviderUsage> {
    let mut aggregate = ProviderUsage::default();
    let mut saw_signal = false;

    if let Some(root) = parse_json_with_xssi_fallback(payload) {
        if let Some(parsed) = extract_usage_from_json_value(&root, response) {
            merge_provider_usage(&mut aggregate, parsed);
            saw_signal = saw_signal || aggregate.has_signal();
        }
    }

    let text = std::str::from_utf8(payload).ok()?;

    if let Some(parsed) = extract_from_batchexecute_wrapped_payloads(text, response) {
        merge_provider_usage(&mut aggregate, parsed);
        saw_signal = saw_signal || aggregate.has_signal();
    }

    if let Some(parsed) = extract_from_json_lines(text, response) {
        merge_provider_usage(&mut aggregate, parsed);
        saw_signal = saw_signal || aggregate.has_signal();
    }

    if let Some(parsed) = extract_from_sse_lines(text, response) {
        merge_provider_usage(&mut aggregate, parsed);
        saw_signal = saw_signal || aggregate.has_signal();
    }

    if saw_signal || aggregate.has_signal() {
        Some(aggregate)
    } else {
        None
    }
}

fn extract_usage_from_json_value(root: &Value, response: &Value) -> Option<ProviderUsage> {
    let mut out = ProviderUsage::default();

    if let Some(json) = response.get("json") {
        apply_json_extract(out_ref(&mut out), root, json.get("extract"));
        apply_usage_extract(out_ref(&mut out), root, json.get("extract_usage"));
    }

    if let Some(non_streaming) = response.get("non_streaming") {
        apply_json_extract(out_ref(&mut out), root, non_streaming.get("extract"));
        apply_usage_extract(out_ref(&mut out), root, non_streaming.get("extract_usage"));
    }

    if let Some(streaming) = response.get("streaming") {
        if let Some(rules) = streaming.get("rules").and_then(Value::as_array) {
            for rule in rules {
                if !rule_matches(rule.get("when").and_then(Value::as_str), root) {
                    continue;
                }
                apply_json_extract(out_ref(&mut out), root, rule.get("extract"));
                apply_usage_extract(out_ref(&mut out), root, rule.get("extract_usage"));
            }
        }
    }

    if out.has_signal() {
        Some(out)
    } else {
        None
    }
}

fn out_ref(out: &mut ProviderUsage) -> &mut ProviderUsage {
    out
}

fn apply_json_extract(out: &mut ProviderUsage, root: &Value, extract_map: Option<&Value>) {
    let Some(map) = extract_map.and_then(Value::as_object) else {
        return;
    };

    if out.model.is_none() {
        if let Some(path) = map.get("model") {
            out.model = extract_string_from_field_path_value(root, path);
        }
    }
}

fn apply_usage_extract(out: &mut ProviderUsage, root: &Value, usage_map: Option<&Value>) {
    let Some(map) = usage_map.and_then(Value::as_object) else {
        return;
    };

    for (field, path_spec) in map {
        let value = extract_u64_from_field_path_value(root, path_spec);
        match field.as_str() {
            "input_tokens" | "prompt_tokens" => {
                out.input_tokens = merge_token(out.input_tokens, value);
            }
            "output_tokens" | "completion_tokens" => {
                out.output_tokens = merge_token(out.output_tokens, value);
            }
            "cache_read_tokens" | "cache_read_input_tokens" => {
                out.cache_read_tokens = Some(merge_option_token(out.cache_read_tokens, value));
            }
            "cache_write_tokens" | "cache_creation_input_tokens" => {
                out.cache_write_tokens = Some(merge_option_token(out.cache_write_tokens, value));
            }
            "reasoning_tokens" => {
                out.reasoning_tokens = Some(merge_option_token(out.reasoning_tokens, value));
            }
            _ => {}
        }
    }
}

fn merge_token(current: u64, next: Option<u64>) -> u64 {
    let Some(next) = next else {
        return current;
    };
    if current == 0 {
        return next;
    }
    if next >= current {
        next
    } else {
        current.saturating_add(next)
    }
}

fn merge_option_token(current: Option<u64>, next: Option<u64>) -> u64 {
    merge_token(current.unwrap_or(0), next)
}

fn merge_provider_usage(current: &mut ProviderUsage, next: ProviderUsage) {
    current.input_tokens = merge_token(current.input_tokens, Some(next.input_tokens));
    current.output_tokens = merge_token(current.output_tokens, Some(next.output_tokens));
    current.cache_read_tokens = Some(merge_option_token(
        current.cache_read_tokens,
        next.cache_read_tokens,
    ));
    current.cache_write_tokens = Some(merge_option_token(
        current.cache_write_tokens,
        next.cache_write_tokens,
    ));
    current.reasoning_tokens = Some(merge_option_token(
        current.reasoning_tokens,
        next.reasoning_tokens,
    ));
    if current.model.is_none() {
        current.model = normalize_string(next.model);
    }
}

fn extract_from_json_lines(text: &str, response: &Value) -> Option<ProviderUsage> {
    let mut aggregate = ProviderUsage::default();
    let mut saw = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        if let Some(parsed) = extract_usage_from_json_value(&value, response) {
            saw = true;
            merge_provider_usage(&mut aggregate, parsed);
        }
    }

    if saw && aggregate.has_signal() {
        Some(aggregate)
    } else {
        None
    }
}

fn extract_from_batchexecute_wrapped_payloads(
    text: &str,
    response: &Value,
) -> Option<ProviderUsage> {
    let mut aggregate = ProviderUsage::default();
    let mut saw = false;

    for line in text.lines() {
        let trimmed = strip_json_security_prefix_text(line.trim()).trim();
        if trimmed.is_empty() || !trimmed.starts_with('[') {
            continue;
        }
        let Ok(wrapper) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        let Some(records) = wrapper.as_array() else {
            continue;
        };
        for record in records {
            let Some(entry) = record.as_array() else {
                continue;
            };
            if entry.first().and_then(Value::as_str) != Some("wrb.fr") {
                continue;
            }
            let Some(inner_json) = entry.get(2).and_then(Value::as_str) else {
                continue;
            };
            let Ok(inner) = serde_json::from_str::<Value>(inner_json) else {
                continue;
            };

            if let Some(parsed) = extract_usage_from_json_value(&inner, response) {
                saw = true;
                merge_provider_usage(&mut aggregate, parsed);
            }
        }
    }

    if saw && aggregate.has_signal() {
        Some(aggregate)
    } else {
        None
    }
}

fn extract_from_sse_lines(text: &str, response: &Value) -> Option<ProviderUsage> {
    let mut aggregate = ProviderUsage::default();
    let mut saw = false;

    for line in text.lines() {
        let trimmed = line.trim_end_matches('\r').trim_start();
        if let Some(payload) = trimmed.strip_prefix("data:") {
            let payload = payload.trim();
            if payload.is_empty() || payload == "[DONE]" {
                continue;
            }
            let Ok(value) = serde_json::from_str::<Value>(payload) else {
                continue;
            };
            if let Some(parsed) = extract_usage_from_json_value(&value, response) {
                saw = true;
                merge_provider_usage(&mut aggregate, parsed);
            }
        }
    }

    if saw && aggregate.has_signal() {
        Some(aggregate)
    } else {
        None
    }
}

fn parse_stream_parser_config(stream: &Value) -> Option<StreamParserConfig> {
    let format = stream
        .get("format")
        .cloned()
        .and_then(|v| serde_json::from_value::<StreamFormat>(v).ok())?;

    let prefixes = stream
        .get("format_options")
        .and_then(|v| v.get("prefixes"))
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec!["data: ".to_string()]);

    let skip_values = stream
        .get("format_options")
        .and_then(|v| v.get("skip_values"))
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec!["[DONE]".to_string()]);

    let header_strip = stream
        .get("format_options")
        .and_then(|v| v.get("header_strip"))
        .and_then(Value::as_str)
        .map(ToString::to_string);

    let rules = stream
        .get("rules")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(parse_stream_rule_config)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Some(StreamParserConfig {
        format,
        prefixes,
        skip_values,
        header_strip,
        rules,
    })
}

fn parse_stream_rule_config(value: &Value) -> Option<StreamRuleConfig> {
    let obj = value.as_object()?;
    let when = obj
        .get("when")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    let extract = obj
        .get("extract")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let extract_usage = obj
        .get("extract_usage")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Some(StreamRuleConfig {
        when,
        extract,
        extract_usage,
    })
}

fn parse_stream_payload_with_config(
    payload: &[u8],
    config: &StreamParserConfig,
) -> Option<ProviderUsage> {
    match config.format {
        StreamFormat::Sse => parse_sse_stream_payload(payload, config),
        StreamFormat::Ndjson => parse_ndjson_stream_payload(payload, config),
        StreamFormat::LengthPrefixed => parse_length_prefixed_stream_payload(payload, config),
        StreamFormat::Websocket => parse_ndjson_stream_payload(payload, config),
    }
}

fn parse_sse_stream_payload(payload: &[u8], config: &StreamParserConfig) -> Option<ProviderUsage> {
    let text = std::str::from_utf8(payload).ok()?;
    let mut aggregate = ProviderUsage::default();
    let mut saw = false;

    for line in text.lines() {
        let trimmed = line.trim_end_matches('\r').trim_start();
        let content = if let Some(prefix) = config
            .prefixes
            .iter()
            .find(|prefix| trimmed.starts_with(prefix.as_str()))
        {
            trimmed[prefix.len()..].trim()
        } else {
            continue;
        };

        if content.is_empty()
            || config
                .skip_values
                .iter()
                .any(|skip| skip.eq_ignore_ascii_case(content))
        {
            continue;
        }

        let Ok(value) = serde_json::from_str::<Value>(content) else {
            continue;
        };
        if let Some(parsed) = apply_stream_rules(&value, config) {
            saw = true;
            merge_provider_usage(&mut aggregate, parsed);
        }
    }

    if saw && aggregate.has_signal() {
        Some(aggregate)
    } else {
        None
    }
}

fn parse_ndjson_stream_payload(
    payload: &[u8],
    config: &StreamParserConfig,
) -> Option<ProviderUsage> {
    let text = std::str::from_utf8(payload).ok()?;
    let mut aggregate = ProviderUsage::default();
    let mut saw = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        if let Some(parsed) = apply_stream_rules(&value, config) {
            saw = true;
            merge_provider_usage(&mut aggregate, parsed);
        }
    }

    if saw && aggregate.has_signal() {
        Some(aggregate)
    } else {
        None
    }
}

fn parse_length_prefixed_stream_payload(
    payload: &[u8],
    config: &StreamParserConfig,
) -> Option<ProviderUsage> {
    let text = std::str::from_utf8(payload).ok()?;
    let stripped = if let Some(prefix) = config.header_strip.as_deref() {
        text.strip_prefix(prefix).unwrap_or(text)
    } else {
        text
    };
    parse_ndjson_stream_payload(stripped.as_bytes(), config)
        .or_else(|| parse_sse_stream_payload(stripped.as_bytes(), config))
}

fn apply_stream_rules(root: &Value, config: &StreamParserConfig) -> Option<ProviderUsage> {
    let mut out = ProviderUsage::default();
    let mut matched = false;

    for rule in &config.rules {
        if !rule_matches(rule.when.as_deref(), root) {
            continue;
        }
        matched = true;
        for (field, path_spec) in &rule.extract {
            if field == "model" && out.model.is_none() {
                out.model = extract_string_from_field_path_value(root, path_spec);
            }
        }
        for (field, path_spec) in &rule.extract_usage {
            let value = extract_u64_from_field_path_value(root, path_spec);
            match field.as_str() {
                "input_tokens" | "prompt_tokens" => {
                    out.input_tokens = merge_token(out.input_tokens, value)
                }
                "output_tokens" | "completion_tokens" => {
                    out.output_tokens = merge_token(out.output_tokens, value)
                }
                "cache_read_tokens" | "cache_read_input_tokens" => {
                    out.cache_read_tokens = Some(merge_option_token(out.cache_read_tokens, value))
                }
                "cache_write_tokens" | "cache_creation_input_tokens" => {
                    out.cache_write_tokens = Some(merge_option_token(out.cache_write_tokens, value))
                }
                "reasoning_tokens" => {
                    out.reasoning_tokens = Some(merge_option_token(out.reasoning_tokens, value))
                }
                _ => {}
            }
        }
    }

    if matched && out.has_signal() {
        Some(out)
    } else {
        None
    }
}

fn rule_matches(when: Option<&str>, root: &Value) -> bool {
    let Some(raw) = when.map(str::trim).filter(|w| !w.is_empty()) else {
        return true;
    };

    // Simple conjunction support: `a and b and c`.
    for clause in raw.split(" and ").map(str::trim).filter(|c| !c.is_empty()) {
        if let Some(inner) = clause
            .strip_prefix("$not(")
            .and_then(|value| value.strip_suffix(')'))
        {
            if rule_matches(Some(inner.trim()), root) {
                return false;
            }
            continue;
        }

        if let Some(path) = clause
            .strip_prefix("$exists(")
            .and_then(|value| value.strip_suffix(')'))
            .map(str::trim)
        {
            if extract_field_path_value(root, path).is_none() {
                return false;
            }
            continue;
        }

        if let Some((left, right)) = clause.split_once(" = ") {
            let left = left.trim();
            let right = right.trim().trim_matches('\'').trim_matches('"');
            if left.starts_with("$type(") && left.ends_with(')') {
                let path = left.trim_start_matches("$type(").trim_end_matches(')');
                let Some(value) = extract_field_path_value(root, path.trim()) else {
                    return false;
                };
                let actual = match value {
                    Value::Null => "null",
                    Value::Bool(_) => "bool",
                    Value::Number(_) => "number",
                    Value::String(_) => "string",
                    Value::Array(_) => "array",
                    Value::Object(_) => "object",
                };
                if !actual.eq_ignore_ascii_case(right) {
                    return false;
                }
                continue;
            }

            let Some(value) = extract_field_path_value(root, left) else {
                return false;
            };
            let actual = match value {
                Value::String(raw) => raw.as_str(),
                Value::Bool(true) => "true",
                Value::Bool(false) => "false",
                _ => return false,
            };
            if !actual.eq_ignore_ascii_case(right) {
                return false;
            }
            continue;
        }

        // Unknown clause syntax: fail open for compatibility.
    }

    true
}

fn extract_u64_from_field_path_value(root: &Value, field_path: &Value) -> Option<u64> {
    field_path_candidates(field_path)
        .into_iter()
        .find_map(|path| extract_u64_from_path(root, path.as_str()))
}

fn extract_u64_from_path(root: &Value, path: &str) -> Option<u64> {
    let value = extract_field_path_value(root, path)?;
    match value {
        Value::Number(number) => number
            .as_u64()
            .or_else(|| number.as_i64().and_then(|raw| u64::try_from(raw).ok()))
            .or_else(|| number.as_f64().map(|raw| raw.max(0.0).round() as u64)),
        Value::String(raw) => raw.trim().parse::<u64>().ok().or_else(|| {
            raw.trim()
                .parse::<f64>()
                .ok()
                .map(|parsed| parsed.max(0.0).round() as u64)
        }),
        _ => None,
    }
}

fn extract_string_from_field_path_value(root: &Value, field_path: &Value) -> Option<String> {
    field_path_candidates(field_path)
        .into_iter()
        .find_map(|path| extract_string_from_path(root, path.as_str()))
}

fn field_path_candidates(field_path: &Value) -> Vec<String> {
    match field_path {
        Value::String(path) => vec![path.clone()],
        Value::Array(entries) => entries
            .iter()
            .filter_map(|entry| entry.as_str().map(|value| value.to_string()))
            .collect(),
        Value::Object(map) => map
            .get("path")
            .and_then(Value::as_str)
            .map(|value| vec![value.to_string()])
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn extract_string_from_path(root: &Value, path: &str) -> Option<String> {
    let value = extract_field_path_value(root, path)?;
    match value {
        Value::String(raw) => normalize_string(Some(raw.clone())),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn normalize_string(value: Option<String>) -> Option<String> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn decode_grpc_frame_payloads(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() < 5 {
        return None;
    }
    let mut cursor = 0usize;
    let mut out = Vec::with_capacity(payload.len());
    let mut frames = 0usize;

    while cursor + 5 <= payload.len() {
        let flag = payload[cursor];
        if flag > 1 {
            return None;
        }
        let len = u32::from_be_bytes([
            payload[cursor + 1],
            payload[cursor + 2],
            payload[cursor + 3],
            payload[cursor + 4],
        ]) as usize;
        let start = cursor + 5;
        let end = start.checked_add(len)?;
        if end > payload.len() {
            return None;
        }
        out.extend_from_slice(&payload[start..end]);
        cursor = end;
        frames += 1;
        if frames > 64 {
            break;
        }
    }

    if frames == 0 {
        None
    } else {
        Some(out)
    }
}

fn extract_field_path_value<'a>(root: &'a Value, raw_path: &str) -> Option<&'a Value> {
    let normalized = normalize_path(raw_path)?;
    if normalized.is_empty() {
        return Some(root);
    }

    let mut current = root;
    for segment in split_path_segments(normalized.as_str()) {
        current = apply_segment(current, segment.as_str())?;
    }

    Some(current)
}

fn normalize_path(raw_path: &str) -> Option<String> {
    let trimmed = raw_path.trim();
    if trimmed.is_empty() {
        return None;
    }

    let without_dollar = trimmed
        .strip_prefix("$.")
        .or_else(|| trimmed.strip_prefix('$'))
        .unwrap_or(trimmed);

    let normalized = without_dollar.trim_start_matches('.');
    if normalized.is_empty() {
        None
    } else {
        Some(normalized.to_string())
    }
}

fn split_path_segments(path: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut bracket_depth: i32 = 0;

    for ch in path.chars() {
        match ch {
            '.' if bracket_depth == 0 => {
                if !current.is_empty() {
                    segments.push(std::mem::take(&mut current));
                }
            }
            '[' => {
                bracket_depth += 1;
                current.push(ch);
            }
            ']' => {
                bracket_depth = (bracket_depth - 1).max(0);
                current.push(ch);
            }
            _ => current.push(ch),
        }
    }

    if !current.is_empty() {
        segments.push(current);
    }

    segments
}

fn apply_segment<'a>(value: &'a Value, segment: &str) -> Option<&'a Value> {
    let segment = segment.trim();
    if segment.is_empty() {
        return Some(value);
    }

    let (field, indexes) = parse_segment(segment);

    let mut current = if let Some(field) = field {
        value.get(field)?
    } else {
        value
    };

    for index in indexes {
        let array = current.as_array()?;
        let resolved_index = if index < 0 {
            let from_end = usize::try_from(index.unsigned_abs()).ok()?;
            if from_end == 0 || from_end > array.len() {
                return None;
            }
            array.len() - from_end
        } else {
            usize::try_from(index).ok()?
        };
        current = array.get(resolved_index)?;
    }

    Some(current)
}

fn parse_segment(segment: &str) -> (Option<&str>, Vec<i32>) {
    let first_bracket = segment.find('[');
    let field = first_bracket
        .map(|idx| &segment[..idx])
        .or(Some(segment))
        .map(str::trim)
        .and_then(|value| if value.is_empty() { None } else { Some(value) });

    let mut indexes = Vec::new();
    let mut remaining = first_bracket.map(|idx| &segment[idx..]).unwrap_or("");

    while let Some(open_idx) = remaining.find('[') {
        let tail = &remaining[(open_idx + 1)..];
        let Some(close_idx) = tail.find(']') else {
            break;
        };
        let raw_index = tail[..close_idx].trim();
        if let Ok(parsed) = raw_index.parse::<i32>() {
            indexes.push(parsed);
        }
        remaining = &tail[(close_idx + 1)..];
    }

    (field, indexes)
}

fn select_best_domain_match<'a>(
    entries: &'a [DomainIndexEntry],
    host: &str,
) -> Option<&'a DomainIndexEntry> {
    let host = normalize_host_for_matching(host);

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
    let host = normalize_host_for_matching(host);
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();

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

fn normalize_host_for_matching(host: &str) -> String {
    let mut value = host.trim();

    if let Some(rest) = value.strip_prefix("http://") {
        value = rest;
    } else if let Some(rest) = value.strip_prefix("https://") {
        value = rest;
    }

    if let Some((authority, _)) = value.split_once('/') {
        value = authority;
    }

    if let Some(stripped) = value.strip_suffix('.') {
        value = stripped;
    }

    // Bracketed IPv6 literal: [::1]:443 or [::1]
    if let Some(inner) = value.strip_prefix('[').and_then(|rest| {
        let end = rest.find(']')?;
        Some(&rest[..end])
    }) {
        return inner.to_ascii_lowercase();
    }

    if let Some((host_part, port_part)) = value.rsplit_once(':') {
        if !host_part.contains(':')
            && !host_part.is_empty()
            && !port_part.is_empty()
            && port_part.chars().all(|ch| ch.is_ascii_digit())
        {
            value = host_part;
        }
    }

    value.to_ascii_lowercase()
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
    fn should_intercept_honors_path_filters_with_query_string() {
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
                        "paths": ["/v1/chat/completions"]
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
            engine.should_intercept("api.openai.com", "/v1/chat/completions?trace=1"),
            InterceptDecision::Intercept {
                provider_id: "openai".to_string(),
                entry_type: EntryType::AiInference
            }
        );
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
    fn embedded_minimal_bundle_loads_and_classifies_core_hosts() {
        let engine = OispEngine::load_embedded_minimal_bundle().unwrap();
        assert!(!engine.bundle_version().trim().is_empty());
        assert!(engine.provider_count() > 0);
        assert!(engine.classify("api.openai.com").is_some());
        assert!(engine.classify("chatgpt.com").is_some());
        assert!(engine.classify("api.anthropic.com").is_some());
    }

    #[test]
    fn embedded_overlay_adds_missing_baseline_coverage() {
        let primary = OispEngine::new(
            parse_compiled_bundle(&json!({
                "version": "primary-v1",
                "compiled_at": "2026-02-14T00:00:00Z",
                "bundle_type": "cloud",
                "domain_index": [
                    { "host": "api.example.com", "provider_id": "example", "entry_type": "ai-inference" }
                ],
                "providers": {
                    "example": { "id": "example", "name": "Example", "type": "ai-inference", "api_format": "openai" }
                },
                "filters": {},
                "pricing": {},
                "formats": {
                    "openai": {
                        "request": { "model": "$.model" },
                        "response": { "json": { "extract": { "model": "$.model" } } }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let merged = primary.with_embedded_overlay().unwrap();
        assert!(merged.classify("api.example.com").is_some());
        assert!(merged.classify("chatgpt.com").is_some());
        assert!(merged.classify("api.openai.com").is_some());
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
    fn host_matches_pattern_normalizes_host_port_and_trailing_dot() {
        assert!(host_matches_pattern("chatgpt.com:443", "chatgpt.com"));
        assert!(host_matches_pattern("CHATGPT.COM.", "chatgpt.com"));
        assert!(host_matches_pattern(
            "https://ws.chatgpt.com/backend-api",
            "*.chatgpt.com"
        ));
    }

    #[test]
    fn classify_accepts_connect_authority_shape() {
        let engine = OispEngine::new(sample_bundle()).unwrap();
        assert!(engine.classify("api.openai.com:443").is_some());
        assert!(engine.should_intercept_host("api.openai.com:443"));
    }

    #[test]
    fn contains_noise_keyword_matches_case_insensitive() {
        let keywords = vec!["Analytics".to_string()];
        assert!(contains_noise_keyword("/v1/ANALYTICS/query", &keywords));
        assert!(!contains_noise_keyword("/v1/messages", &keywords));
    }

    #[test]
    fn matches_noise_keyword_uses_bundle_keywords() {
        let engine = OispEngine::new(sample_bundle()).unwrap();
        assert!(engine.matches_noise_keyword("GetAnalyticsDashboard"));
        assert!(!engine.matches_noise_keyword("CreateConversation"));
    }

    #[test]
    fn select_best_domain_match_prefers_longer_wildcard() {
        let entries = vec![
            DomainIndexEntry {
                host: "*.openai.com".to_string(),
                provider_id: "broad".to_string(),
                provider_entity_id: None,
                entry_type: EntryType::AiInference,
                paths: Vec::new(),
            },
            DomainIndexEntry {
                host: "api.*.openai.com".to_string(),
                provider_id: "specific".to_string(),
                provider_entity_id: None,
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
            types::bundle::ResolvedProvider {
                id: "openai".to_string(),
                entity_id: None,
                name: "OpenAI".to_string(),
                entry_type: EntryType::Mcp,
                api_format: None,
                domains: vec!["api.openai.com".to_string()],
                user_agent_patterns: Vec::new(),
                detection: None,
            },
        )]);
        bundle.providers = providers;
        bundle.domain_index = vec![DomainIndexEntry {
            host: "api.openai.com".to_string(),
            provider_id: "openai".to_string(),
            provider_entity_id: None,
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
    fn evaluate_detection_prefers_model_rule_with_entity_id() {
        let engine = OispEngine::new(
            parse_compiled_bundle(&json!({
                "schema_version": 3,
                "version": "v1",
                "compiled_at": "2026-02-16T00:00:00Z",
                "bundle_type": "local",
                "domain_index": [
                    { "host": "chatgpt.com", "provider_id": "chatgpt", "entry_type": "agent-app", "provider_entity_id": "agt_abc123" }
                ],
                "providers": {
                    "chatgpt": {
                        "id": "chatgpt",
                        "entity_id": "agt_abc123",
                        "name": "ChatGPT",
                        "type": "agent-app",
                        "api_format": "openai",
                        "detection": {
                            "ua_rules": [
                                {
                                    "id": "ua-1",
                                    "reason": "ua_match",
                                    "confidence": 0.80,
                                    "agent": "chatgpt",
                                    "contains": "chatgpt"
                                }
                            ],
                            "model_rules": [
                                {
                                    "id": "model-1",
                                    "reason": "model_match",
                                    "confidence": 0.99,
                                    "priority": 10,
                                    "agent": "codex",
                                    "model": "*codex*"
                                }
                            ]
                        }
                    }
                },
                "filters": {},
                "pricing": {}
            }))
            .unwrap(),
        )
        .unwrap();

        let outcome = engine
            .evaluate_detection(
                "chatgpt",
                &DetectionContext {
                    host: Some("chatgpt.com".to_string()),
                    user_agent: Some("chatgpt desktop".to_string()),
                    model: Some("gpt-5.3-codex".to_string()),
                    ..DetectionContext::default()
                },
            )
            .expect("outcome");

        assert_eq!(outcome.agent.as_deref(), Some("codex"));
        assert_eq!(outcome.detection_reason, "model_match");
        assert!((outcome.parse_confidence - 0.99).abs() < 1e-9);
        assert_eq!(outcome.target_entity_id.as_deref(), Some("agt_abc123"));
    }

    #[test]
    fn evaluate_detection_is_deterministic_for_same_context() {
        let engine = OispEngine::new(
            parse_compiled_bundle(&json!({
                "schema_version": 3,
                "version": "v1",
                "compiled_at": "2026-02-16T00:00:00Z",
                "bundle_type": "local",
                "domain_index": [
                    { "host": "chatgpt.com", "provider_id": "chatgpt", "entry_type": "agent-app", "provider_entity_id": "agt_abc123" }
                ],
                "providers": {
                    "chatgpt": {
                        "id": "chatgpt",
                        "entity_id": "agt_abc123",
                        "name": "ChatGPT",
                        "type": "agent-app",
                        "api_format": "openai",
                        "detection": {
                            "ua_rules": [
                                {
                                    "id": "z-rule",
                                    "reason": "ua_match",
                                    "confidence": 0.90,
                                    "agent": "chatgpt",
                                    "contains": "desktop"
                                },
                                {
                                    "id": "a-rule",
                                    "reason": "ua_match",
                                    "confidence": 0.90,
                                    "agent": "codex",
                                    "contains": "desktop"
                                }
                            ]
                        }
                    }
                },
                "filters": {},
                "pricing": {}
            }))
            .unwrap(),
        )
        .unwrap();

        let context = DetectionContext {
            host: Some("chatgpt.com".to_string()),
            user_agent: Some("chatgpt desktop".to_string()),
            ..DetectionContext::default()
        };

        let first = engine
            .evaluate_detection("chatgpt", &context)
            .expect("first outcome");
        let second = engine
            .evaluate_detection("chatgpt", &context)
            .expect("second outcome");

        assert_eq!(first, second);
        assert_eq!(first.agent.as_deref(), Some("codex"));
        assert_eq!(first.detection_reason, "ua_match");
        assert_eq!(first.target_entity_id.as_deref(), Some("agt_abc123"));
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
                "schema_version": 2,
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
                "filters": {
                    "whitelist": ["api.openai.com"],
                    "blacklist": [],
                    "passthrough": [],
                    "noise_keywords": []
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
