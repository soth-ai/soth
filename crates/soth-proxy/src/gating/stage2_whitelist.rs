use soth_core::{DecisionReason, EntityCatalog, HostRule};

use crate::gating::stage0_tls::host_pattern_matches;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityMatchKind {
    Provider,
    Application,
}

#[derive(Debug, Clone)]
pub struct EntityMatch {
    pub kind: EntityMatchKind,
    pub entity_id: String,
    pub capture_mode: soth_core::CaptureMode,
    pub host_rule: HostRule,
}

pub fn match_entity(catalog: &EntityCatalog, host: &str) -> Option<EntityMatch> {
    let mut best: Option<(usize, EntityMatch)> = None;

    for entity in &catalog.providers {
        for rule in &entity.hosts {
            if host_pattern_matches(rule.pattern.as_str(), host) {
                let score = specificity(rule.pattern.as_str());
                let current = EntityMatch {
                    kind: EntityMatchKind::Provider,
                    entity_id: entity.entity_id.clone(),
                    capture_mode: entity.capture_mode,
                    host_rule: rule.clone(),
                };
                if best.as_ref().is_none_or(|(s, _)| score > *s) {
                    best = Some((score, current));
                }
            }
        }
    }

    for entity in catalog.web_apps.iter().chain(catalog.native_apps.iter()) {
        for rule in &entity.hosts {
            if host_pattern_matches(rule.pattern.as_str(), host) {
                let score = specificity(rule.pattern.as_str());
                let current = EntityMatch {
                    kind: EntityMatchKind::Application,
                    entity_id: entity.entity_id.clone(),
                    capture_mode: entity.capture_mode,
                    host_rule: rule.clone(),
                };
                if best.as_ref().is_none_or(|(s, _)| score > *s) {
                    best = Some((score, current));
                }
            }
        }
    }

    best.map(|(_, matched)| matched)
}

pub fn evaluate_path_rules(
    matched: &EntityMatch,
    path: &str,
    method: &str,
    allow_empty_means_allow_all_except_denied: bool,
) -> Option<DecisionReason> {
    let rules = &matched.host_rule.paths;
    if rules.deny_exact.iter().any(|p| p == path) {
        return Some(DecisionReason::PathDeniedExact);
    }
    if rules
        .deny_glob
        .iter()
        .any(|pattern| glob_match(pattern, path))
    {
        return Some(DecisionReason::PathDeniedGlob);
    }

    let path_allowed = if rules.allow.is_empty() {
        allow_empty_means_allow_all_except_denied
    } else {
        rules.allow.iter().any(|pattern| glob_match(pattern, path))
    };
    if !path_allowed {
        return Some(DecisionReason::PathDeniedGlob);
    }

    let method_allowed = matched.host_rule.methods.is_empty()
        || matched
            .host_rule
            .methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method));
    if !method_allowed {
        return Some(DecisionReason::MethodNotAllowed);
    }
    None
}

fn specificity(pattern: &str) -> usize {
    pattern.chars().filter(|ch| *ch != '*').count()
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }
    if !pattern.contains('*') {
        return pattern == text;
    }

    let starts_with_wildcard = pattern.starts_with('*');
    let ends_with_wildcard = pattern.ends_with('*');
    let parts: Vec<&str> = pattern.split('*').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() {
        return true;
    }

    let mut cursor = 0usize;
    for (idx, part) in parts.iter().enumerate() {
        let is_first = idx == 0;
        let is_last = idx + 1 == parts.len();

        if is_first && !starts_with_wildcard {
            if !text[cursor..].starts_with(part) {
                return false;
            }
            cursor += part.len();
            continue;
        }

        if is_last && !ends_with_wildcard {
            return text.ends_with(part);
        }

        if let Some(offset) = text[cursor..].find(part) {
            cursor += offset + part.len();
        } else {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use soth_core::{CaptureMode, HostRule, PathRules};

    fn matched_with(paths: PathRules, methods: &[&str]) -> EntityMatch {
        EntityMatch {
            kind: EntityMatchKind::Provider,
            entity_id: "p".to_string(),
            capture_mode: CaptureMode::MetadataOnly,
            host_rule: HostRule {
                pattern: "api.openai.com".to_string(),
                methods: methods.iter().map(|m| (*m).to_string()).collect(),
                paths,
            },
        }
    }

    #[test]
    fn deny_exact_precedes_method_check() {
        let matched = matched_with(
            PathRules {
                deny_exact: vec!["/v1/models".to_string()],
                deny_glob: vec![],
                allow: vec![],
            },
            &["POST"],
        );
        let reason = evaluate_path_rules(&matched, "/v1/models", "GET", true);
        assert_eq!(reason, Some(DecisionReason::PathDeniedExact));
    }

    #[test]
    fn allow_empty_still_enforces_method() {
        let matched = matched_with(PathRules::default(), &["POST"]);
        let reason = evaluate_path_rules(&matched, "/v1/chat/completions", "GET", true);
        assert_eq!(reason, Some(DecisionReason::MethodNotAllowed));
    }

    #[test]
    fn explicit_allow_list_blocks_non_matching_paths() {
        let matched = matched_with(
            PathRules {
                deny_exact: vec![],
                deny_glob: vec![],
                allow: vec!["/v1/chat/*".to_string()],
            },
            &["POST"],
        );
        let reason = evaluate_path_rules(&matched, "/v1/models", "POST", true);
        assert_eq!(reason, Some(DecisionReason::PathDeniedGlob));
    }

    #[test]
    fn explicit_allow_and_method_allows_request() {
        let matched = matched_with(
            PathRules {
                deny_exact: vec![],
                deny_glob: vec![],
                allow: vec!["/v1/chat/*".to_string()],
            },
            &["POST"],
        );
        let reason = evaluate_path_rules(&matched, "/v1/chat/completions", "POST", true);
        assert_eq!(reason, None);
    }
}
