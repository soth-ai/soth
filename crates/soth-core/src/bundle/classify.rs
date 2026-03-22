//! Signal-based entity classification.
//!
//! Evaluates `MatchingRule`s on providers and applications to determine
//! which entity (if any) matches a given request. Moved from soth-parse
//! so gating can call it directly instead of duplicating in detect.

use crate::bundle::detect::{glob_match, host_without_port};
use crate::{MatchingRule, RequestHeaders, SignalKind};

/// Result of signal-based entity classification.
#[derive(Debug, Clone)]
pub struct ClassifyResult {
    /// Matched entity identifier (provider_id or app_id).
    pub entity_id: String,
    /// Whether the match is a provider ("provider") or application ("application").
    pub entity_kind: &'static str,
    /// The matching rule that fired.
    pub rule_id: String,
    /// Priority of the matching rule (higher = more specific).
    pub priority: u32,
}

/// Paired result returning the best provider AND best application match independently.
#[derive(Debug, Clone, Default)]
pub struct ClassifyPairResult {
    pub provider: Option<ClassifyResult>,
    pub application: Option<ClassifyResult>,
}

/// Classify a request returning the best provider AND best application match
/// independently. This allows both to be resolved from matching_rules in a single pass.
///
/// Takes iterators of (entity_key, canonical_entity_id, matching_rules) for
/// providers and applications respectively.
#[allow(clippy::too_many_arguments)]
pub fn classify_request_pair<'a>(
    host: Option<&str>,
    path: &str,
    headers: &RequestHeaders,
    process_bundle_id: Option<&str>,
    process_name: Option<&str>,
    parent_process_name: Option<&str>,
    providers: impl Iterator<Item = (&'a str, &'a str, &'a [MatchingRule])>,
    applications: impl Iterator<Item = (&'a str, &'a str, &'a [MatchingRule])>,
) -> ClassifyPairResult {
    let host_lc = host.map(|h| {
        host_without_port(h)
            .trim_end_matches('.')
            .to_ascii_lowercase()
    });
    let path_lc = path.to_ascii_lowercase();
    let content_type = header_value(headers, "content-type").map(|v| v.to_ascii_lowercase());

    let mut best_provider: Option<ClassifyResult> = None;
    let mut best_application: Option<ClassifyResult> = None;

    for (_key, entity_id, rules) in providers {
        for rule in rules {
            if rule_matches(
                rule,
                host_lc.as_deref(),
                &path_lc,
                headers,
                content_type.as_deref(),
                process_bundle_id,
                process_name,
                parent_process_name,
            ) && best_provider
                .as_ref()
                .is_none_or(|b| rule.priority > b.priority)
            {
                best_provider = Some(ClassifyResult {
                    entity_id: entity_id.to_string(),
                    entity_kind: "provider",
                    rule_id: rule.rule_id.clone(),
                    priority: rule.priority,
                });
            }
        }
    }

    for (_key, entity_id, rules) in applications {
        for rule in rules {
            if rule_matches(
                rule,
                host_lc.as_deref(),
                &path_lc,
                headers,
                content_type.as_deref(),
                process_bundle_id,
                process_name,
                parent_process_name,
            ) && best_application
                .as_ref()
                .is_none_or(|b| rule.priority > b.priority)
            {
                best_application = Some(ClassifyResult {
                    entity_id: entity_id.to_string(),
                    entity_kind: "application",
                    rule_id: rule.rule_id.clone(),
                    priority: rule.priority,
                });
            }
        }
    }

    ClassifyPairResult {
        provider: best_provider,
        application: best_application,
    }
}

/// Evaluate whether a single matching rule fires against the given request context.
#[allow(clippy::too_many_arguments)]
fn rule_matches(
    rule: &MatchingRule,
    host_lc: Option<&str>,
    path_lc: &str,
    headers: &RequestHeaders,
    content_type: Option<&str>,
    process_bundle_id: Option<&str>,
    process_name: Option<&str>,
    parent_process_name: Option<&str>,
) -> bool {
    if rule.signals.is_empty() {
        return false;
    }

    // Reject rules whose only non-negated signals are catch-all path globs (e.g. "**").
    // These provide no specificity and would match every request, causing false positives.
    let has_specific_signal = rule.signals.iter().any(|s| {
        if s.is_negated {
            return false;
        }
        match s.kind {
            SignalKind::HttpPath => {
                let trimmed = s.pattern.trim();
                trimmed != "**" && trimmed != "*" && trimmed != "/**"
            }
            _ => true,
        }
    });
    if !has_specific_signal {
        return false;
    }

    if rule.requires_all {
        rule.signals.iter().all(|signal| {
            let raw_match = signal_matches(
                &signal.kind,
                &signal.pattern,
                host_lc,
                path_lc,
                headers,
                content_type,
                process_bundle_id,
                process_name,
                parent_process_name,
            );
            if signal.is_negated {
                !raw_match
            } else {
                raw_match
            }
        })
    } else {
        rule.signals.iter().any(|signal| {
            let raw_match = signal_matches(
                &signal.kind,
                &signal.pattern,
                host_lc,
                path_lc,
                headers,
                content_type,
                process_bundle_id,
                process_name,
                parent_process_name,
            );
            if signal.is_negated {
                !raw_match
            } else {
                raw_match
            }
        })
    }
}

/// Check if a single signal matches the request context.
#[allow(clippy::too_many_arguments)]
fn signal_matches(
    kind: &SignalKind,
    pattern: &str,
    host_lc: Option<&str>,
    path_lc: &str,
    headers: &RequestHeaders,
    content_type: Option<&str>,
    process_bundle_id: Option<&str>,
    process_name: Option<&str>,
    parent_process_name: Option<&str>,
) -> bool {
    let pattern_lc = pattern.to_ascii_lowercase();
    match kind {
        SignalKind::HttpHost => host_lc.is_some_and(|host| glob_match(&pattern_lc, host)),
        SignalKind::HttpPath => {
            let path_only = path_lc.split('?').next().unwrap_or(path_lc);
            glob_match(&pattern_lc, path_only)
        }
        SignalKind::HttpMethod => {
            header_value(headers, ":method").is_some_and(|m| m.eq_ignore_ascii_case(pattern))
        }
        SignalKind::HttpHeader => {
            if let Some((name, expected)) = pattern.split_once(':') {
                header_value(headers, name.trim()).is_some_and(|v| {
                    v.to_ascii_lowercase()
                        .contains(&expected.trim().to_ascii_lowercase())
                })
            } else {
                header_value(headers, pattern.trim()).is_some()
            }
        }
        SignalKind::ContentType => content_type.is_some_and(|ct| ct.contains(&pattern_lc)),
        SignalKind::TlsSni => host_lc.is_some_and(|host| glob_match(&pattern_lc, host)),
        SignalKind::ProcessBundleId => {
            process_bundle_id.is_some_and(|bid| bid.eq_ignore_ascii_case(pattern))
        }
        SignalKind::ProcessName => process_name.is_some_and(|pn| pn.eq_ignore_ascii_case(pattern)),
        SignalKind::ParentProcessName => {
            parent_process_name.is_some_and(|ppn| ppn.eq_ignore_ascii_case(pattern))
        }
        SignalKind::BodyStructure => {
            // Body structure matching requires deeper inspection; skip at this stage.
            false
        }
    }
}

fn header_value<'a>(headers: &'a RequestHeaders, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MatchingRule, SignalKind, SignalMatcher};

    fn make_rule(
        rule_id: &str,
        priority: u32,
        requires_all: bool,
        signals: Vec<SignalMatcher>,
    ) -> MatchingRule {
        MatchingRule {
            rule_id: rule_id.to_string(),
            priority,
            requires_all,
            signals,
            ..Default::default()
        }
    }

    fn host_signal(pattern: &str) -> SignalMatcher {
        SignalMatcher {
            kind: SignalKind::HttpHost,
            pattern: pattern.to_string(),
            ..Default::default()
        }
    }

    fn path_signal(pattern: &str) -> SignalMatcher {
        SignalMatcher {
            kind: SignalKind::HttpPath,
            pattern: pattern.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn classify_by_host() {
        let rules = vec![make_rule(
            "openai-host",
            900,
            false,
            vec![host_signal("api.openai.com")],
        )];
        let providers: Vec<(&str, &str, &[MatchingRule])> =
            vec![("openai", "openai", rules.as_slice())];
        let applications: Vec<(&str, &str, &[MatchingRule])> = vec![];

        let headers =
            std::collections::BTreeMap::from([("host".to_string(), "api.openai.com".to_string())]);

        let result = classify_request_pair(
            Some("api.openai.com"),
            "/v1/chat/completions",
            &headers,
            None,
            None,
            None,
            providers.into_iter(),
            applications.into_iter(),
        );

        assert!(result.provider.is_some());
        assert_eq!(result.provider.unwrap().entity_id, "openai");
    }

    #[test]
    fn classify_requires_all() {
        let rules = vec![make_rule(
            "cursor-api",
            950,
            true,
            vec![
                host_signal("api.openai.com"),
                SignalMatcher {
                    kind: SignalKind::ProcessName,
                    pattern: "Cursor".to_string(),
                    ..Default::default()
                },
            ],
        )];
        let providers: Vec<(&str, &str, &[MatchingRule])> =
            vec![("openai", "openai", rules.as_slice())];
        let apps: Vec<(&str, &str, &[MatchingRule])> = vec![];

        let headers =
            std::collections::BTreeMap::from([("host".to_string(), "api.openai.com".to_string())]);

        // Without process_name — should NOT match (requires_all)
        let result = classify_request_pair(
            Some("api.openai.com"),
            "/v1/chat",
            &headers,
            None,
            None,
            None,
            providers.clone().into_iter(),
            apps.clone().into_iter(),
        );
        assert!(result.provider.is_none());

        // With process_name — should match
        let result = classify_request_pair(
            Some("api.openai.com"),
            "/v1/chat",
            &headers,
            None,
            Some("Cursor"),
            None,
            providers.into_iter(),
            apps.into_iter(),
        );
        assert!(result.provider.is_some());
        assert_eq!(result.provider.unwrap().entity_id, "openai");
    }

    #[test]
    fn classify_highest_priority_wins() {
        let rules_low = vec![make_rule("generic", 100, false, vec![path_signal("/v1/*")])];
        let rules_high = vec![make_rule(
            "specific",
            900,
            false,
            vec![host_signal("api.openai.com")],
        )];

        let providers: Vec<(&str, &str, &[MatchingRule])> = vec![
            ("generic_llm", "generic_llm", rules_low.as_slice()),
            ("openai", "openai", rules_high.as_slice()),
        ];
        let apps: Vec<(&str, &str, &[MatchingRule])> = vec![];

        let headers =
            std::collections::BTreeMap::from([("host".to_string(), "api.openai.com".to_string())]);

        let result = classify_request_pair(
            Some("api.openai.com"),
            "/v1/chat/completions",
            &headers,
            None,
            None,
            None,
            providers.into_iter(),
            apps.into_iter(),
        );

        assert_eq!(result.provider.unwrap().entity_id, "openai");
    }
}
