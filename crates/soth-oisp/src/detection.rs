use crate::matchers::{path_matches_pattern, wildcard_match};
use crate::parse_helpers::normalize_string;
use crate::types::bundle::ResolvedProvider;
use crate::types::provider::{DetectionRule, EntryType};
use crate::{DetectionContext, DetectionOutcome};
use regex::Regex;
use serde_json::Value;
use std::hash::{Hash, Hasher};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DetectionRuleGroup {
    Model,
    Path,
    Ua,
    Process,
    Env,
}

#[derive(Debug, Clone)]
pub(crate) struct DetectionCandidate {
    pub(crate) outcome: DetectionOutcome,
    pub(crate) precedence: i32,
    pub(crate) stable_key: String,
}

pub(crate) fn compare_detection_candidates(
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

pub(crate) fn detection_cache_key_hash(provider_id: &str, context: &DetectionContext) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    provider_id.trim().to_ascii_lowercase().hash(&mut hasher);

    hash_opt_trim(context.host.as_deref(), &mut hasher);
    hash_opt_trim(context.path.as_deref(), &mut hasher);
    hash_opt_trim(context.user_agent.as_deref(), &mut hasher);
    hash_opt_trim(context.model.as_deref(), &mut hasher);
    hash_opt_trim(context.process_name.as_deref(), &mut hasher);
    hash_opt_trim(context.bundle_id.as_deref(), &mut hasher);
    hash_opt_trim(context.client_name.as_deref(), &mut hasher);
    hash_opt_trim(context.client_version.as_deref(), &mut hasher);

    for key in &context.env_keys {
        let trimmed = key.trim();
        if !trimmed.is_empty() {
            trimmed.hash(&mut hasher);
        }
    }
    hasher.finish()
}

fn hash_opt_trim(value: Option<&str>, state: &mut impl Hasher) {
    match value
        .map(str::trim)
        .filter(|candidate| !candidate.is_empty())
    {
        Some(normalized) => normalized.hash(state),
        None => 0u8.hash(state),
    }
}

pub(crate) fn collect_detection_candidates(
    out: &mut Vec<DetectionCandidate>,
    group: DetectionRuleGroup,
    rules: &[DetectionRule],
    provider: &ResolvedProvider,
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
                detection_id: provider.detection_id.clone(),
            },
            precedence: detection_group_precedence(group) + rule.priority.unwrap_or(0),
            stable_key,
        });
    }
}

fn detection_group_precedence(_group: DetectionRuleGroup) -> i32 {
    0
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

fn detection_group_subjects(group: DetectionRuleGroup, context: &DetectionContext) -> Vec<&str> {
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
