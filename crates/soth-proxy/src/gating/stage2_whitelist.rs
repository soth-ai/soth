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

#[derive(Debug, Clone, Default)]
pub struct EntityMatchSet {
    pub provider: Option<EntityMatch>,
    pub application: Option<EntityMatch>,
}

impl EntityMatchSet {
    /// Pick the single best match (highest specificity, prefer provider on tie).
    pub fn best(&self) -> Option<&EntityMatch> {
        match (&self.provider, &self.application) {
            (Some(p), Some(a)) => {
                let p_score = specificity(&p.host_rule.pattern);
                let a_score = specificity(&a.host_rule.pattern);
                if p_score >= a_score {
                    Some(p)
                } else {
                    Some(a)
                }
            }
            (Some(p), None) => Some(p),
            (None, Some(a)) => Some(a),
            (None, None) => None,
        }
    }
}

pub fn match_entities(catalog: &EntityCatalog, host: &str) -> EntityMatchSet {
    let mut best_provider: Option<(usize, EntityMatch)> = None;
    let mut best_app: Option<(usize, EntityMatch)> = None;

    for entity in &catalog.providers {
        for rule in &entity.hosts {
            if host_pattern_matches(rule.pattern.as_str(), host) {
                let score = specificity(rule.pattern.as_str());
                if best_provider.as_ref().map_or(true, |(s, _)| score > *s) {
                    best_provider = Some((
                        score,
                        EntityMatch {
                            kind: EntityMatchKind::Provider,
                            entity_id: entity.entity_id.clone(),
                            capture_mode: entity.capture_mode,
                            host_rule: rule.clone(),
                        },
                    ));
                }
            }
        }
    }

    for entity in catalog.web_apps.iter().chain(catalog.native_apps.iter()) {
        for rule in &entity.hosts {
            if host_pattern_matches(rule.pattern.as_str(), host) {
                let score = specificity(rule.pattern.as_str());
                if best_app.as_ref().map_or(true, |(s, _)| score > *s) {
                    best_app = Some((
                        score,
                        EntityMatch {
                            kind: EntityMatchKind::Application,
                            entity_id: entity.entity_id.clone(),
                            capture_mode: entity.capture_mode,
                            host_rule: rule.clone(),
                        },
                    ));
                }
            }
        }
    }

    EntityMatchSet {
        provider: best_provider.map(|(_, m)| m),
        application: best_app.map(|(_, m)| m),
    }
}

pub fn match_entity(catalog: &EntityCatalog, host: &str) -> Option<EntityMatch> {
    match_entities(catalog, host).best().cloned()
}

pub fn evaluate_path_rules(
    matched: &EntityMatch,
    path: &str,
    method: &str,
    allow_empty_means_allow_all_except_denied: bool,
) -> Option<DecisionReason> {
    let rules = &matched.host_rule.paths;
    // Path rules are defined on the path component only — strip any query string
    // so that `/v1/messages?beta=true` matches the allow pattern `/v1/messages`.
    // Lowercase both sides for case-insensitive matching (matching fingerprint convention).
    let path_only = path
        .split('?')
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();

    if rules
        .deny_exact
        .iter()
        .any(|p| p.to_ascii_lowercase() == path_only)
    {
        return Some(DecisionReason::PathDeniedExact);
    }
    if rules.deny_glob.iter().any(|pattern| {
        glob_match(&pattern.to_ascii_lowercase(), &path_only)
    }) {
        return Some(DecisionReason::PathDeniedGlob);
    }

    let path_allowed = if rules.allow.is_empty() {
        allow_empty_means_allow_all_except_denied
    } else {
        rules
            .allow
            .iter()
            .any(|pattern| glob_match(&pattern.to_ascii_lowercase(), &path_only))
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
    soth_core::bundle::detect::pattern_specificity(pattern)
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }
    soth_parse::glob_match(pattern, text)
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
                priority: None,
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

    #[test]
    fn case_insensitive_path_matching() {
        // deny_exact should match regardless of case
        let matched = matched_with(
            PathRules {
                deny_exact: vec!["/V1/Models".to_string()],
                deny_glob: vec![],
                allow: vec![],
            },
            &[],
        );
        assert_eq!(
            evaluate_path_rules(&matched, "/v1/models", "GET", true),
            Some(DecisionReason::PathDeniedExact),
        );

        // allow patterns should match regardless of case
        let matched = matched_with(
            PathRules {
                deny_exact: vec![],
                deny_glob: vec![],
                allow: vec!["/V1/Chat/*".to_string()],
            },
            &["POST"],
        );
        assert_eq!(
            evaluate_path_rules(&matched, "/v1/chat/completions", "POST", true),
            None,
        );
    }
}
