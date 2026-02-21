use crate::cache::BoundedCache;
use crate::matchers::{
    contains_noise_keyword_for_host, contains_noise_keyword_text, host_matches_any,
    host_matches_pattern, identifier_matches_any, normalize_host_for_matching,
    normalize_identifier_for_matching, path_matches_any, select_best_domain_match,
};
use crate::parse_helpers::{
    decode_grpc_frame_payloads, extract_string_from_field_path_value,
    extract_text_from_field_path_value, extract_usage_from_response_value, format_uses_grpc_frames,
    format_uses_strip_xssi, parse_json_with_xssi_fallback, parse_stream_parser_config,
    parse_stream_payload_with_config, strip_json_security_prefix_bytes,
};
use crate::pricing::{calculate_cost_from_pricing, find_model_pricing};
use crate::registry_cache::load_from_registry_cache_path;
use crate::types;
use crate::{
    Classification, CompiledBundle, ConnectDecision, ConnectDecisionAction, EntryType,
    InterceptDecision, OispEngine, OispStreamParser, ProviderUsage, RequestDecision,
    RequestDecisionOutcome,
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

    /// Debug helper for transport decision tracing.
    ///
    /// Returns whether the given host matches bundle whitelist filters.
    /// When whitelist is empty, this returns `true` (allow-all semantics).
    pub fn is_host_whitelisted_for_debug(&self, host: &str) -> bool {
        let host = normalize_host_for_matching(host);
        if host.is_empty() {
            return false;
        }
        self.is_whitelisted_host(host.as_str())
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

    pub fn classify_app_origin(&self, app_identifier: &str) -> Option<&'static str> {
        let app_identifier = normalize_identifier_for_matching(app_identifier);
        if app_identifier.is_empty() {
            return None;
        }
        if identifier_matches_any(
            app_identifier.as_str(),
            &self.bundle.gating.allowed_app_origins.non_hosts,
        ) {
            return Some("non_host");
        }
        if identifier_matches_any(
            app_identifier.as_str(),
            &self.bundle.gating.allowed_app_origins.hosts,
        ) {
            return Some("host");
        }
        None
    }

    pub fn app_has_parser(&self, app_identifier: &str) -> bool {
        let app_identifier = normalize_identifier_for_matching(app_identifier);
        if app_identifier.is_empty() {
            return false;
        }
        identifier_matches_any(
            app_identifier.as_str(),
            &self.bundle.gating.allowed_app_origins.apps_with_parsers,
        )
    }

    pub fn has_app_origin_rules(&self) -> bool {
        !self.bundle.gating.allowed_app_origins.hosts.is_empty()
            || !self.bundle.gating.allowed_app_origins.non_hosts.is_empty()
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
        self.should_intercept_with_context(host, path, None, None)
    }

    pub fn should_intercept_with_context(
        &self,
        host: &str,
        path: &str,
        method: Option<&str>,
        app_type: Option<&str>,
    ) -> InterceptDecision {
        let decision = self.evaluate_request_decision(host, path, method, app_type);
        match decision.outcome {
            RequestDecisionOutcome::Noise => InterceptDecision::Noise,
            RequestDecisionOutcome::Passthrough => InterceptDecision::Passthrough,
            RequestDecisionOutcome::Tunnel => InterceptDecision::Tunnel,
            RequestDecisionOutcome::Full | RequestDecisionOutcome::MetadataOnly => {
                let provider_id = decision.provider_id.or_else(|| {
                    self.classify(host)
                        .as_ref()
                        .map(|classification| classification.provider_id.clone())
                });
                let Some(provider_id) = provider_id else {
                    return InterceptDecision::Tunnel;
                };
                let entry_type = decision.entry_type.or_else(|| {
                    self.resolve_provider(provider_id.as_str())
                        .map(|provider| provider.entry_type.clone())
                });
                let Some(entry_type) = entry_type else {
                    return InterceptDecision::Tunnel;
                };
                InterceptDecision::Intercept {
                    provider_id,
                    entry_type,
                }
            }
        }
    }

    pub fn evaluate_request_decision(
        &self,
        host: &str,
        path: &str,
        method: Option<&str>,
        app_type: Option<&str>,
    ) -> RequestDecision {
        let host = normalize_host_for_matching(host);
        if host.is_empty() {
            return RequestDecision {
                outcome: RequestDecisionOutcome::Tunnel,
                provider_id: None,
                entry_type: None,
                detection_id: None,
                rule_id: None,
                reason: Some("host_missing".to_string()),
            };
        }
        let path_only = path.split_once('?').map(|(raw, _)| raw).unwrap_or(path);

        if contains_noise_keyword_for_host(host.as_str(), path, &self.bundle.filters.noise_keywords)
        {
            return RequestDecision {
                outcome: RequestDecisionOutcome::Noise,
                provider_id: None,
                entry_type: None,
                detection_id: None,
                rule_id: None,
                reason: Some("noise_keyword".to_string()),
            };
        }

        if host_matches_any(host.as_str(), &self.bundle.filters.passthrough) {
            return RequestDecision {
                outcome: RequestDecisionOutcome::Passthrough,
                provider_id: None,
                entry_type: None,
                detection_id: None,
                rule_id: None,
                reason: Some("passthrough".to_string()),
            };
        }

        if host_matches_any(host.as_str(), &self.bundle.filters.blacklist) {
            return RequestDecision {
                outcome: RequestDecisionOutcome::Tunnel,
                provider_id: None,
                entry_type: None,
                detection_id: None,
                rule_id: None,
                reason: Some("blacklist".to_string()),
            };
        }

        let app_type = normalize_app_type(app_type);
        let classification = self.classify(host.as_str());
        let precedence = path_precedence(
            self.bundle
                .decision_rules
                .defaults
                .path_precedence
                .as_slice(),
        );
        let mut host_rule_seen = false;
        for rule in &self.bundle.decision_rules.rules {
            if !rule.enabled || !host_matches_pattern(host.as_str(), rule.host_pattern.as_str()) {
                continue;
            }
            if !rule.app_type.is_empty()
                && !rule
                    .app_type
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(app_type))
            {
                continue;
            }
            if !matches_method(method, rule.method.as_slice()) {
                continue;
            }

            host_rule_seen = true;

            for check in &precedence {
                if *check == "deny_paths_exact"
                    && path_matches_exact(path_only, rule.deny_paths_exact.as_slice())
                {
                    return self.request_decision_from_rule(
                        classification.as_ref(),
                        rule,
                        RequestDecisionOutcome::MetadataOnly,
                        "deny_paths_exact",
                    );
                }
                if *check == "deny_paths_glob"
                    && path_matches_any(path_only, rule.deny_paths_glob.as_slice())
                {
                    return self.request_decision_from_rule(
                        classification.as_ref(),
                        rule,
                        RequestDecisionOutcome::MetadataOnly,
                        "deny_paths_glob",
                    );
                }
                if *check == "allow_paths"
                    && path_matches_any(path_only, rule.allow_paths.as_slice())
                {
                    let outcome = match rule.capture_mode.as_deref() {
                        Some("metadata_only") => RequestDecisionOutcome::MetadataOnly,
                        _ => RequestDecisionOutcome::Full,
                    };
                    let default_reason = rule
                        .reason
                        .as_deref()
                        .filter(|value| !value.trim().is_empty())
                        .unwrap_or("rule.path_policy.matched");
                    return self.request_decision_from_rule(
                        classification.as_ref(),
                        rule,
                        outcome,
                        default_reason,
                    );
                }
            }
        }

        let host_whitelisted = self.is_whitelisted_host(host.as_str());
        let miss_action = match app_type {
            "host" => self
                .bundle
                .decision_rules
                .defaults
                .host_miss_action
                .as_str(),
            "non_host" => self
                .bundle
                .decision_rules
                .defaults
                .non_host_miss_action
                .as_str(),
            _ => self
                .bundle
                .decision_rules
                .defaults
                .unknown_app_action
                .as_str(),
        };

        if host_rule_seen && host_whitelisted {
            return self.request_decision_from_classification(
                classification.as_ref(),
                RequestDecisionOutcome::MetadataOnly,
                self.bundle
                    .decision_rules
                    .defaults
                    .whitelist_path_miss_reason
                    .as_str(),
            );
        }

        if host_whitelisted && miss_action == "metadata_only" {
            return self.request_decision_from_classification(
                classification.as_ref(),
                RequestDecisionOutcome::MetadataOnly,
                self.bundle
                    .decision_rules
                    .defaults
                    .whitelist_path_miss_reason
                    .as_str(),
            );
        }

        if miss_action == "metadata_only" {
            return self.request_decision_from_classification(
                classification.as_ref(),
                RequestDecisionOutcome::MetadataOnly,
                "rule_miss_metadata_only",
            );
        }

        self.request_decision_from_classification(
            classification.as_ref(),
            RequestDecisionOutcome::Tunnel,
            "rule_miss_tunnel",
        )
    }

    /// Host-only interception decision for CONNECT/TLS handshake phase where path is unknown.
    pub fn should_intercept_host(&self, host: &str) -> bool {
        matches!(
            self.evaluate_connect_decision(host, None, Some("unknown"))
                .action,
            ConnectDecisionAction::Intercept
        )
    }

    pub fn evaluate_connect_decision(
        &self,
        host: &str,
        app_identifier: Option<&str>,
        app_type: Option<&str>,
    ) -> ConnectDecision {
        let host = normalize_host_for_matching(host);
        if host.is_empty() {
            return ConnectDecision {
                action: ConnectDecisionAction::Tunnel,
                rule_id: None,
                reason: Some("host_missing".to_string()),
            };
        }

        if host_matches_any(host.as_str(), &self.bundle.filters.passthrough) {
            return ConnectDecision {
                action: ConnectDecisionAction::Passthrough,
                rule_id: None,
                reason: Some("passthrough".to_string()),
            };
        }

        if host_matches_any(host.as_str(), &self.bundle.filters.blacklist) {
            return ConnectDecision {
                action: ConnectDecisionAction::Tunnel,
                rule_id: None,
                reason: Some("blacklist".to_string()),
            };
        }

        let app_type = normalize_app_type(app_type);
        let app_identifier = app_identifier
            .map(normalize_identifier_for_matching)
            .filter(|value| !value.is_empty());
        let host_whitelisted = self.is_whitelisted_host(host.as_str());
        let host_known = self.classify(host.as_str()).is_some()
            || self.has_decision_rule_for_host(host.as_str());

        for rule in &self.bundle.connect_policy.rules {
            if !rule.enabled {
                continue;
            }
            if !rule.app_type.is_empty()
                && !rule
                    .app_type
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(app_type))
            {
                continue;
            }
            if !rule.app_identifiers.is_empty() {
                let Some(identifier) = app_identifier.as_deref() else {
                    continue;
                };
                if !identifier_matches_any(identifier, rule.app_identifiers.as_slice()) {
                    continue;
                }
            }
            if !rule.host_allow.is_empty()
                && !host_matches_any(host.as_str(), rule.host_allow.as_slice())
            {
                continue;
            }
            return connect_decision_from_action(
                rule.action.as_str(),
                Some(rule.id.as_str()),
                rule.reason.as_deref(),
                host_whitelisted && host_known,
                self.bundle
                    .connect_policy
                    .defaults
                    .non_whitelisted_host_action
                    .as_str(),
            );
        }

        if app_type == "unknown" && host_whitelisted && host_known {
            return connect_decision_from_action(
                self.bundle
                    .connect_policy
                    .defaults
                    .whitelisted_unknown_app_action
                    .as_str(),
                None,
                Some("whitelisted_unknown_app_action"),
                true,
                self.bundle
                    .connect_policy
                    .defaults
                    .non_whitelisted_host_action
                    .as_str(),
            );
        }
        connect_decision_from_action(
            self.bundle
                .connect_policy
                .defaults
                .unknown_app_action
                .as_str(),
            None,
            Some("connect_policy_default"),
            host_whitelisted && host_known,
            self.bundle
                .connect_policy
                .defaults
                .non_whitelisted_host_action
                .as_str(),
        )
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

    /// Extract request prompt/query text from payload according to provider format request parser.
    ///
    /// This is used by downstream PII enrichment so detection runs on parsed user input
    /// fields (for example `prompt`, `messages`, `query`) rather than raw request JSON.
    pub fn extract_pii_probe_from_request(&self, provider_id: &str, body: &[u8]) -> Option<String> {
        let transformed = self.apply_body_transform(provider_id, body);
        let format_value = self.resolve_provider_format(provider_id)?;
        let request = format_value.get("request")?;
        let root = parse_json_with_xssi_fallback(&transformed)?;

        const REQUEST_TEXT_KEYS: &[&str] = &[
            "prompt",
            "query",
            "input",
            "message",
            "messages",
            "contents",
            "chat_history",
            "text",
            "content",
            "system",
            "system_instruction",
        ];

        for key in REQUEST_TEXT_KEYS {
            let Some(path_spec) = request.get(*key) else {
                continue;
            };
            if let Some(text) = extract_text_from_field_path_value(&root, path_spec) {
                if !text.trim().is_empty() {
                    return Some(text);
                }
            }
        }

        None
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
        load_from_registry_cache_path(path)
    }

    fn resolve_provider_format(&self, provider_id: &str) -> Option<&Value> {
        let provider = self.resolve_provider(provider_id)?;
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

    pub fn canonical_provider_id(&self, provider_id: &str) -> Option<String> {
        self.bundle
            .providers
            .get(provider_id)
            .map(|_| provider_id.to_string())
            .or_else(|| {
                self.bundle
                    .providers
                    .keys()
                    .find(|candidate| candidate.eq_ignore_ascii_case(provider_id))
                    .cloned()
            })
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

    fn has_decision_rule_for_host(&self, host: &str) -> bool {
        self.bundle
            .decision_rules
            .rules
            .iter()
            .any(|rule| rule.enabled && host_matches_pattern(host, rule.host_pattern.as_str()))
    }

    fn is_whitelisted_host(&self, host: &str) -> bool {
        self.bundle.filters.whitelist.is_empty()
            || host_matches_any(host, self.bundle.filters.whitelist.as_slice())
    }

    fn request_decision_from_rule(
        &self,
        classification: Option<&Classification>,
        rule: &types::bundle::DecisionRule,
        outcome: RequestDecisionOutcome,
        reason: &str,
    ) -> RequestDecision {
        let provider_id = rule.provider.clone().or_else(|| {
            classification
                .as_ref()
                .map(|classification| classification.provider_id.clone())
        });
        let entry_type = provider_id
            .as_deref()
            .and_then(|provider_id| self.resolve_provider(provider_id))
            .map(|provider| provider.entry_type.clone())
            .or_else(|| {
                classification
                    .as_ref()
                    .map(|classification| classification.entry_type.clone())
            });
        let detection_id = rule.detection_id.clone();
        RequestDecision {
            outcome,
            provider_id,
            entry_type,
            detection_id,
            rule_id: (!rule.id.is_empty()).then(|| rule.id.clone()),
            reason: Some(reason.to_string()),
        }
    }

    fn request_decision_from_classification(
        &self,
        classification: Option<&Classification>,
        outcome: RequestDecisionOutcome,
        reason: &str,
    ) -> RequestDecision {
        let provider_id = classification.map(|classification| classification.provider_id.clone());
        let entry_type = classification.map(|classification| classification.entry_type.clone());
        RequestDecision {
            outcome,
            provider_id,
            entry_type,
            detection_id: None,
            rule_id: None,
            reason: Some(reason.to_string()),
        }
    }
}

fn normalize_app_type(app_type: Option<&str>) -> &'static str {
    match app_type
        .unwrap_or("unknown")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "host" => "host",
        "non_host" => "non_host",
        _ => "unknown",
    }
}

fn matches_method(method: Option<&str>, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    let Some(method) = method else {
        return true;
    };
    let method = method.trim();
    if method.is_empty() {
        return true;
    }
    allowed
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(method))
}

fn path_matches_exact(path: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return false;
    }
    let normalized = path.trim().to_ascii_lowercase();
    patterns
        .iter()
        .any(|pattern| pattern.trim().eq_ignore_ascii_case(normalized.as_str()))
}

fn path_precedence(raw: &[String]) -> Vec<&str> {
    let mut precedence = Vec::new();
    for value in raw {
        match value.trim() {
            "deny_paths_exact" => precedence.push("deny_paths_exact"),
            "deny_paths_glob" => precedence.push("deny_paths_glob"),
            "allow_paths" => precedence.push("allow_paths"),
            _ => {}
        }
    }
    if precedence.is_empty() {
        precedence.extend(["deny_paths_exact", "deny_paths_glob", "allow_paths"]);
    }
    precedence
}

fn connect_decision_from_action(
    action: &str,
    rule_id: Option<&str>,
    reason: Option<&str>,
    host_allowed: bool,
    non_whitelisted_fallback: &str,
) -> ConnectDecision {
    let normalized = action.trim().to_ascii_lowercase();
    let fallback = non_whitelisted_fallback.trim().to_ascii_lowercase();
    let action = match normalized.as_str() {
        "intercept" => ConnectDecisionAction::Intercept,
        "passthrough" => ConnectDecisionAction::Passthrough,
        "host_only" => {
            if host_allowed {
                ConnectDecisionAction::Intercept
            } else if fallback == "passthrough" {
                ConnectDecisionAction::Passthrough
            } else if fallback == "intercept" {
                ConnectDecisionAction::Intercept
            } else {
                ConnectDecisionAction::Tunnel
            }
        }
        _ => ConnectDecisionAction::Tunnel,
    };
    ConnectDecision {
        action,
        rule_id: rule_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string),
        reason: reason
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string),
    }
}
