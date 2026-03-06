use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use soth_core::{
    AppType, CaptureMode, DecisionReason, GateDecision, GateOutcome, GateStage, GatingBundle,
    NonCatalogedAction, ProcessInfo, TrafficClassification, UnknownAppAction,
};

use crate::gating::stage0_tls::{normalize_sni, HostMatcher};
use crate::gating::stage1_app_origin::{resolve_identity, IdentityMatch};
use crate::gating::stage2_whitelist::{
    evaluate_path_rules, match_entity, EntityMatch, EntityMatchKind,
};
use crate::gating::stage3_blacklist;
use crate::gating::stage4_app_type;
use crate::gating::stage5_host_origin::{extract_host_from_url, origin_allowed};
use crate::heartbeat_telemetry;

#[derive(Debug, Default)]
struct DiscoveryCounters {
    date: String,
    app_hits: HashMap<String, u32>,
    domain_hits: HashMap<String, u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoveryCounterOutcome {
    InterceptFirstSeen,
    InterceptAlreadySeen,
    CapReached,
}

impl DiscoveryCounters {
    fn reset_if_new_day(&mut self) {
        let today = Utc::now().date_naive().format("%Y-%m-%d").to_string();
        if self.date != today {
            self.date = today;
            self.app_hits.clear();
            self.domain_hits.clear();
        }
    }

    fn app_allowed(&mut self, key: &str, limit: u32) -> DiscoveryCounterOutcome {
        self.reset_if_new_day();
        let counter = self.app_hits.entry(key.to_string()).or_insert(0);
        if *counter >= limit {
            return DiscoveryCounterOutcome::CapReached;
        }
        let outcome = if *counter == 0 {
            DiscoveryCounterOutcome::InterceptFirstSeen
        } else {
            DiscoveryCounterOutcome::InterceptAlreadySeen
        };
        *counter += 1;
        outcome
    }

    fn domain_allowed(&mut self, key: &str, limit: u32) -> DiscoveryCounterOutcome {
        self.reset_if_new_day();
        let counter = self.domain_hits.entry(key.to_string()).or_insert(0);
        if *counter >= limit {
            return DiscoveryCounterOutcome::CapReached;
        }
        let outcome = if *counter == 0 {
            DiscoveryCounterOutcome::InterceptFirstSeen
        } else {
            DiscoveryCounterOutcome::InterceptAlreadySeen
        };
        *counter += 1;
        outcome
    }
}

#[derive(Clone)]
pub struct GateEvaluator {
    bundle: Arc<GatingBundle>,
    discovery_counters: Arc<Mutex<DiscoveryCounters>>,
    tls_intercept_matcher: HostMatcher,
    tls_passthrough_matcher: HostMatcher,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct GateOverrides {
    pub unknown_app_action: Option<UnknownAppAction>,
    pub non_cataloged_host_action: Option<NonCatalogedAction>,
}

impl GateEvaluator {
    pub fn new(bundle: Arc<GatingBundle>) -> Self {
        let tls_intercept_matcher =
            HostMatcher::from_patterns(&bundle.gates.stage0_tls.tls_intercept_hosts);
        let tls_passthrough_matcher =
            HostMatcher::from_patterns(&bundle.gates.stage0_tls.passthrough_domains);
        Self {
            bundle,
            discovery_counters: Arc::new(Mutex::new(DiscoveryCounters::default())),
            tls_intercept_matcher,
            tls_passthrough_matcher,
        }
    }

    pub fn bundle(&self) -> &Arc<GatingBundle> {
        &self.bundle
    }

    pub fn maintenance_tick(&self) {
        if let Ok(mut counters) = self.discovery_counters.lock() {
            counters.reset_if_new_day();
        }
    }

    pub fn evaluate_tls(&self, sni: &str) -> GateDecision {
        let defaults = &self.bundle.gates.defaults;
        if !defaults.sensor_enabled {
            crate::trace::tls_stage(
                sni,
                "passthrough",
                DecisionReason::TlsDefaultPassthrough,
                "sensor disabled",
            );
            return GateDecision::Passthrough;
        }

        let host = normalize_sni(sni);
        if host.is_empty() {
            crate::trace::tls_stage(
                sni,
                "passthrough",
                DecisionReason::TlsDefaultPassthrough,
                "empty host",
            );
            return GateDecision::Passthrough;
        }

        if self.tls_passthrough_matcher.matches(host.as_str()) {
            crate::trace::tls_stage(
                host.as_str(),
                "passthrough",
                DecisionReason::TlsPassthroughDomain,
                "matched passthrough list",
            );
            return GateDecision::Passthrough;
        }
        if self.tls_intercept_matcher.matches(host.as_str()) {
            crate::trace::tls_stage(
                host.as_str(),
                "intercept",
                DecisionReason::TlsInterceptCatalog,
                "matched tls intercept catalog",
            );
            return GateDecision::Intercept;
        }

        let cfg = &self.bundle.gates.stage0_tls;
        if cfg.enable_discovery {
            let limit = defaults.discovery.unknown_domain_daily_limit.max(1);
            if self.allow_domain_discovery(host.as_str(), limit) {
                crate::trace::tls_stage(
                    host.as_str(),
                    "intercept",
                    DecisionReason::TlsDiscovery,
                    "domain discovery",
                );
                return GateDecision::Intercept;
            }
        }

        crate::trace::tls_stage(
            host.as_str(),
            "passthrough",
            DecisionReason::TlsDefaultPassthrough,
            "default passthrough",
        );
        GateDecision::Passthrough
    }

    pub fn evaluate_http(
        &self,
        req: &soth_core::RawRequest,
        process_info: &Option<ProcessInfo>,
        overrides: GateOverrides,
    ) -> GateOutcome {
        let connection_id = req.connection_meta.connection_id;
        let host = request_host(req);
        let defaults = &self.bundle.gates.defaults;
        let unknown_app_action = overrides
            .unknown_app_action
            .unwrap_or(defaults.unknown_app_action);
        let non_cataloged_host_action = overrides
            .non_cataloged_host_action
            .unwrap_or(defaults.non_cataloged_host_action);

        let identity = process_info
            .as_ref()
            .and_then(|info| resolve_identity(&self.bundle.identity_index, info));
        crate::trace::stage1_identity_resolution(
            connection_id,
            host.as_str(),
            req.path.as_str(),
            process_info.as_ref(),
            identity.as_ref(),
        );

        if let Some(matched) = identity.as_ref() {
            match matched.entry.action {
                soth_core::ProcessAction::Skip => {
                    crate::trace::gate_stage(
                        connection_id,
                        GateStage::Stage1AppOrigin,
                        "skip",
                        Some(DecisionReason::ProcessAction),
                        "process action skip",
                    );
                    return outcome_skip(
                        DecisionReason::ProcessAction,
                        GateStage::Stage1AppOrigin,
                        false,
                    );
                }
                soth_core::ProcessAction::Block => {
                    crate::trace::gate_stage(
                        connection_id,
                        GateStage::Stage1AppOrigin,
                        "block",
                        Some(DecisionReason::ProcessAction),
                        "process action block",
                    );
                    return outcome_block(
                        DecisionReason::ProcessAction,
                        GateStage::Stage1AppOrigin,
                        false,
                    );
                }
                soth_core::ProcessAction::Intercept => crate::trace::gate_stage(
                    connection_id,
                    GateStage::Stage1AppOrigin,
                    "continue",
                    None,
                    "process action intercept",
                ),
            }
        }

        let unresolved = process_info.is_none()
            || process_info
                .as_ref()
                .map(|info| info.bundle_id.is_none() && info.process_name.is_none())
                .unwrap_or(true);
        let apply_unknown_policy = identity.is_none()
            && (!unresolved
                || self
                    .bundle
                    .gates
                    .stage1_app_origin
                    .skip_if_unresolved_process);
        if apply_unknown_policy {
            match unknown_app_action {
                UnknownAppAction::Skip => {
                    crate::trace::gate_stage(
                        connection_id,
                        GateStage::Stage1AppOrigin,
                        "skip",
                        Some(DecisionReason::UnknownAppPolicy),
                        "unknown app policy skip",
                    );
                    return outcome_skip(
                        DecisionReason::UnknownAppPolicy,
                        GateStage::Stage1AppOrigin,
                        false,
                    );
                }
                UnknownAppAction::Block => {
                    crate::trace::gate_stage(
                        connection_id,
                        GateStage::Stage1AppOrigin,
                        "block",
                        Some(DecisionReason::UnknownAppPolicy),
                        "unknown app policy block",
                    );
                    return outcome_block(
                        DecisionReason::UnknownAppPolicy,
                        GateStage::Stage1AppOrigin,
                        false,
                    );
                }
                UnknownAppAction::Intercept => {
                    crate::trace::gate_stage(
                        connection_id,
                        GateStage::Stage1AppOrigin,
                        "continue",
                        None,
                        "unknown app policy intercept",
                    );
                    if let Some(info) = process_info.as_ref() {
                        let key = info
                            .bundle_id
                            .as_ref()
                            .or(info.process_name.as_ref())
                            .map(|v| v.trim().to_ascii_lowercase());
                        if let Some(key) = key {
                            let limit = defaults.discovery.unknown_app_daily_limit.max(1);
                            let _ = self.allow_app_discovery(key.as_str(), limit);
                        }
                    }
                }
            }
        } else {
            crate::trace::gate_stage(
                connection_id,
                GateStage::Stage1AppOrigin,
                "continue",
                None,
                "stage1 passed",
            );
        }

        let entity_match = match_entity(&self.bundle.entities, host.as_str());
        let app_type = stage4_app_type::derive(identity.as_ref());

        let discovery_capture = entity_match.is_none()
            && app_type == AppType::Host
            && self.bundle.gates.stage0_tls.enable_discovery
            && referer_in_catalog(req, &self.tls_intercept_matcher)
            && self.allow_domain_discovery(
                host.as_str(),
                defaults.discovery.unknown_domain_daily_limit.max(1),
            );

        if entity_match.is_none() && !discovery_capture {
            return match non_cataloged_host_action {
                NonCatalogedAction::Skip => {
                    crate::trace::gate_stage(
                        connection_id,
                        GateStage::Stage2Whitelist,
                        "skip",
                        Some(DecisionReason::NotInCatalog),
                        "not in catalog",
                    );
                    outcome_skip(
                        DecisionReason::NotInCatalog,
                        GateStage::Stage2Whitelist,
                        false,
                    )
                }
                NonCatalogedAction::Passthrough => {
                    crate::trace::gate_stage(
                        connection_id,
                        GateStage::Stage2Whitelist,
                        "passthrough",
                        Some(DecisionReason::NotInCatalog),
                        "not in catalog",
                    );
                    outcome_passthrough(
                        DecisionReason::NotInCatalog,
                        GateStage::Stage2Whitelist,
                        false,
                    )
                }
            };
        }

        if let Some(matched) = entity_match.as_ref() {
            if let Some(reason) = evaluate_path_rules(
                matched,
                req.path.as_str(),
                req.method.as_str(),
                self.bundle
                    .gates
                    .stage2_whitelist
                    .allow_empty_means_allow_all_except_denied,
            ) {
                crate::trace::gate_stage(
                    connection_id,
                    GateStage::Stage2Whitelist,
                    "skip",
                    Some(reason),
                    "path/method rule rejected",
                );
                return outcome_skip(reason, GateStage::Stage2Whitelist, discovery_capture);
            }
        }
        let stage2_note = if discovery_capture {
            "discovery capture"
        } else if entity_match.is_some() {
            "entity match accepted"
        } else {
            "whitelist allowed by override"
        };
        crate::trace::gate_stage(
            connection_id,
            GateStage::Stage2Whitelist,
            "continue",
            None,
            stage2_note,
        );

        if let Some(reason) = stage3_blacklist::evaluate(
            &self.bundle.gates.stage3_blacklist,
            host.as_str(),
            req.path.as_str(),
            req.body.as_ref(),
        ) {
            match reason {
                DecisionReason::BlacklistedKeyword => {
                    heartbeat_telemetry::record_blacklist_keyword_dropped();
                }
                DecisionReason::BlacklistedGraphQLOperation => {
                    heartbeat_telemetry::record_blacklist_graphql_dropped();
                }
                _ => {}
            }
            crate::trace::gate_stage(
                connection_id,
                GateStage::Stage3Blacklist,
                "skip",
                Some(reason),
                "blacklist matched",
            );
            return outcome_skip(reason, GateStage::Stage3Blacklist, discovery_capture);
        }
        crate::trace::gate_stage(
            connection_id,
            GateStage::Stage3Blacklist,
            "continue",
            None,
            "blacklist clear",
        );

        crate::trace::gate_stage(
            connection_id,
            GateStage::Stage4AppType,
            "continue",
            None,
            match app_type {
                AppType::Host => "app_type host",
                AppType::NonHost => "app_type non_host",
                AppType::Unknown => "app_type unknown",
            },
        );

        if app_type == AppType::Host
            && !(self
                .bundle
                .gates
                .stage5_host_origin
                .skip_for_discovery_capture
                && discovery_capture)
            && !origin_allowed(
                &req.headers,
                &self.bundle.gates.stage5_host_origin.allowed_host_origins,
            )
        {
            crate::trace::gate_stage(
                connection_id,
                GateStage::Stage5HostOrigin,
                "skip",
                Some(DecisionReason::HostOriginNotAllowed),
                "origin gate rejected",
            );
            return outcome_skip(
                DecisionReason::HostOriginNotAllowed,
                GateStage::Stage5HostOrigin,
                discovery_capture,
            );
        }
        crate::trace::gate_stage(
            connection_id,
            GateStage::Stage5HostOrigin,
            "continue",
            None,
            if app_type == AppType::Host {
                "origin gate passed"
            } else {
                "origin gate skipped for non-host"
            },
        );

        let capture_mode =
            derive_capture_mode(identity.as_ref(), entity_match.as_ref(), discovery_capture);
        let (matched_provider, matched_application) = classify_entity_match(entity_match.as_ref());
        let traffic_classification = derive_traffic_classification(
            matched_provider.is_some(),
            matched_application.is_some(),
            app_type,
        );
        crate::trace::gate_stage(
            connection_id,
            GateStage::Intercept,
            "intercept",
            Some(DecisionReason::Intercept),
            "all gates passed",
        );

        GateOutcome {
            decision: GateDecision::Intercept,
            reason: DecisionReason::Intercept,
            app_type,
            capture_mode,
            matched_provider,
            matched_application,
            traffic_classification,
            discovery_capture,
            terminal_stage: GateStage::Intercept,
        }
    }

    fn allow_app_discovery(&self, app_key: &str, limit: u32) -> bool {
        if let Ok(mut counters) = self.discovery_counters.lock() {
            return match counters.app_allowed(app_key, limit) {
                DiscoveryCounterOutcome::InterceptFirstSeen => {
                    heartbeat_telemetry::record_discovery_catalog_intercept();
                    true
                }
                DiscoveryCounterOutcome::InterceptAlreadySeen => {
                    heartbeat_telemetry::record_discovery_catalog_seen_skip();
                    true
                }
                DiscoveryCounterOutcome::CapReached => {
                    heartbeat_telemetry::record_discovery_catalog_cap_skip();
                    false
                }
            };
        }
        false
    }

    fn allow_domain_discovery(&self, host: &str, limit: u32) -> bool {
        if let Ok(mut counters) = self.discovery_counters.lock() {
            return match counters.domain_allowed(host, limit) {
                DiscoveryCounterOutcome::InterceptFirstSeen => {
                    heartbeat_telemetry::record_discovery_catalog_intercept();
                    true
                }
                DiscoveryCounterOutcome::InterceptAlreadySeen => {
                    heartbeat_telemetry::record_discovery_catalog_seen_skip();
                    true
                }
                DiscoveryCounterOutcome::CapReached => {
                    heartbeat_telemetry::record_discovery_catalog_cap_skip();
                    false
                }
            };
        }
        false
    }
}

fn request_host(req: &soth_core::RawRequest) -> String {
    if let Some(host) = req
        .headers
        .get("host")
        .or_else(|| req.headers.get(":authority"))
    {
        let normalized = normalize_sni(host);
        if !normalized.is_empty() {
            return normalized;
        }
    }
    extract_host_from_url(req.path.as_str()).unwrap_or_else(|| "unknown".to_string())
}

fn referer_in_catalog(req: &soth_core::RawRequest, matcher: &HostMatcher) -> bool {
    ["origin", "referer"]
        .iter()
        .filter_map(|name| header_value(&req.headers, name))
        .filter_map(extract_host_from_url)
        .any(|host| matcher.matches(host.as_str()))
}

fn header_value<'a>(headers: &'a soth_core::RequestHeaders, key: &str) -> Option<&'a str> {
    headers
        .iter()
        .find_map(|(k, v)| k.eq_ignore_ascii_case(key).then_some(v.as_str()))
}

fn derive_capture_mode(
    identity: Option<&IdentityMatch>,
    entity_match: Option<&EntityMatch>,
    discovery_capture: bool,
) -> CaptureMode {
    let mut mode = identity
        .map(|matched| matched.entry.capture_mode)
        .unwrap_or(CaptureMode::MetadataOnly);

    if let Some(matched) = entity_match {
        mode = matched.capture_mode;
    }

    if discovery_capture {
        CaptureMode::MetadataOnly
    } else {
        mode
    }
}

fn classify_entity_match(entity_match: Option<&EntityMatch>) -> (Option<String>, Option<String>) {
    let Some(matched) = entity_match else {
        return (None, None);
    };
    match matched.kind {
        EntityMatchKind::Provider => (Some(matched.entity_id.clone()), None),
        EntityMatchKind::Application => (None, Some(matched.entity_id.clone())),
    }
}

fn derive_traffic_classification(
    provider_matched: bool,
    application_matched: bool,
    app_type: AppType,
) -> TrafficClassification {
    if application_matched {
        return TrafficClassification::ApplicationUsage;
    }
    if provider_matched {
        return match app_type {
            AppType::NonHost => TrafficClassification::ToolUsage,
            AppType::Host | AppType::Unknown => TrafficClassification::UnknownAgent,
        };
    }
    TrafficClassification::Other
}

fn outcome_skip(reason: DecisionReason, stage: GateStage, discovery_capture: bool) -> GateOutcome {
    GateOutcome {
        decision: GateDecision::Skip,
        reason,
        app_type: AppType::Unknown,
        capture_mode: CaptureMode::MetadataOnly,
        matched_provider: None,
        matched_application: None,
        traffic_classification: TrafficClassification::Other,
        discovery_capture,
        terminal_stage: stage,
    }
}

fn outcome_passthrough(
    reason: DecisionReason,
    stage: GateStage,
    discovery_capture: bool,
) -> GateOutcome {
    GateOutcome {
        decision: GateDecision::Passthrough,
        reason,
        app_type: AppType::Unknown,
        capture_mode: CaptureMode::MetadataOnly,
        matched_provider: None,
        matched_application: None,
        traffic_classification: TrafficClassification::Other,
        discovery_capture,
        terminal_stage: stage,
    }
}

fn outcome_block(reason: DecisionReason, stage: GateStage, discovery_capture: bool) -> GateOutcome {
    GateOutcome {
        decision: GateDecision::Block {
            status: 403,
            message: "blocked by gate".to_string(),
        },
        reason,
        app_type: AppType::Unknown,
        capture_mode: CaptureMode::MetadataOnly,
        matched_provider: None,
        matched_application: None,
        traffic_classification: TrafficClassification::Other,
        discovery_capture,
        terminal_stage: stage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heartbeat_telemetry;
    use std::collections::{HashMap, HashSet};

    fn bundle_with_defaults(skip_if_unresolved_process: bool) -> Arc<GatingBundle> {
        Arc::new(GatingBundle {
            identity_index: soth_core::IdentityIndex {
                hosts: HashMap::new(),
                non_hosts: HashMap::new(),
            },
            gates: soth_core::GateConfig {
                order: vec![
                    GateStage::Stage0Tls,
                    GateStage::Stage1AppOrigin,
                    GateStage::Stage2Whitelist,
                    GateStage::Stage3Blacklist,
                    GateStage::Stage4AppType,
                    GateStage::Stage5HostOrigin,
                    GateStage::Intercept,
                ],
                defaults: soth_core::GateDefaults {
                    sensor_enabled: true,
                    fail_open_on_config_error: true,
                    unknown_app_action: UnknownAppAction::Skip,
                    non_cataloged_host_action: NonCatalogedAction::Skip,
                    discovery: soth_core::DiscoveryConfig::default(),
                    source_unknown_app_action: None,
                    source_whitelisted_unknown_app_action: None,
                    source_non_whitelisted_host_action: None,
                    source_browser_default_action: None,
                },
                stage0_tls: soth_core::Stage0Config {
                    tls_intercept_hosts: HashSet::from(["api.openai.com".to_string()]),
                    passthrough_domains: HashSet::new(),
                    enable_discovery: false,
                },
                stage1_app_origin: soth_core::Stage1Config {
                    skip_if_unresolved_process,
                },
                stage2_whitelist: soth_core::Stage2Config {
                    allow_empty_means_allow_all_except_denied: true,
                },
                stage3_blacklist: soth_core::Stage3Config::default(),
                stage4_app_type: soth_core::Stage4Config::default(),
                stage5_host_origin: soth_core::Stage5Config {
                    allowed_host_origins: HashSet::new(),
                    skip_for_discovery_capture: true,
                },
            },
            entities: soth_core::EntityCatalog {
                providers: vec![soth_core::EntityTrafficRules {
                    entity_id: "openai".to_string(),
                    capture_mode: CaptureMode::MetadataOnly,
                    hosts: vec![soth_core::HostRule {
                        pattern: "api.openai.com".to_string(),
                        methods: vec!["POST".to_string()],
                        paths: soth_core::PathRules {
                            deny_exact: Vec::new(),
                            deny_glob: Vec::new(),
                            allow: vec!["/v1/chat/completions".to_string()],
                        },
                        priority: None,
                    }],
                    api_format: None,
                    entity_type: None,
                    pricing: None,
                    capture: None,
                    detection: None,
                }],
                web_apps: Vec::new(),
                native_apps: Vec::new(),
            },
        })
    }

    fn request_for(host: &str) -> soth_core::RawRequest {
        soth_core::RawRequest {
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: soth_core::RequestHeaders::from([("host".to_string(), host.to_string())]),
            body: bytes::Bytes::new(),
            connection_meta: soth_core::ConnectionMeta::from_transport(
                uuid::Uuid::new_v4(),
                soth_core::SocketFamily::UnixDomain { path: None },
                None,
                None,
            ),
        }
    }

    #[test]
    fn unknown_policy_applies_for_unmatched_resolved_process() {
        let evaluator = GateEvaluator::new(bundle_with_defaults(true));
        let req = request_for("api.openai.com");
        let process_info = Some(ProcessInfo {
            pid: Some(42),
            process_name: Some("some-client".to_string()),
            bundle_id: Some("com.some.client".to_string()),
            parent_pid: None,
            parent_process_name: None,
            parent_bundle_id: None,
        });

        let outcome = evaluator.evaluate_http(&req, &process_info, GateOverrides::default());
        assert!(matches!(outcome.decision, GateDecision::Skip));
        assert_eq!(outcome.reason, DecisionReason::UnknownAppPolicy);
        assert_eq!(outcome.terminal_stage, GateStage::Stage1AppOrigin);
    }

    #[test]
    fn unresolved_process_can_bypass_unknown_policy_when_disabled() {
        let evaluator = GateEvaluator::new(bundle_with_defaults(false));
        let req = request_for("api.openai.com");

        let outcome = evaluator.evaluate_http(&req, &None, GateOverrides::default());
        assert!(matches!(outcome.decision, GateDecision::Intercept));
        assert_eq!(outcome.reason, DecisionReason::Intercept);
        assert_eq!(outcome.terminal_stage, GateStage::Intercept);
    }

    fn counter_value(key: &str) -> u64 {
        heartbeat_telemetry::heartbeat_telemetry_snapshot()
            .counters
            .get(key)
            .copied()
            .unwrap_or(0)
    }

    #[test]
    fn blacklist_match_updates_heartbeat_counter() {
        let mut bundle = (*bundle_with_defaults(false)).clone();
        bundle.gates.stage3_blacklist.blacklisted_keywords = vec!["chat".to_string()];
        let evaluator = GateEvaluator::new(Arc::new(bundle));
        let mut req = request_for("api.openai.com");
        req.body = bytes::Bytes::from_static(b"contains token marker");

        let before = counter_value("edge.blacklist.keyword_dropped_total");
        let outcome = evaluator.evaluate_http(&req, &None, GateOverrides::default());
        let after = counter_value("edge.blacklist.keyword_dropped_total");

        assert!(matches!(outcome.decision, GateDecision::Skip));
        assert_eq!(outcome.reason, DecisionReason::BlacklistedKeyword);
        assert!(after >= before + 1);
    }

    #[test]
    fn repeated_discovery_updates_seen_skip_counter() {
        let mut bundle = (*bundle_with_defaults(false)).clone();
        bundle.gates.stage0_tls.tls_intercept_hosts.clear();
        bundle.gates.stage0_tls.enable_discovery = true;
        bundle.gates.defaults.discovery.unknown_domain_daily_limit = 2;
        let evaluator = GateEvaluator::new(Arc::new(bundle));

        let host = "unknown-discovery.example.com";
        let before_intercept = counter_value("edge.discovery.catalog.intercept_total");
        let before_seen_skip = counter_value("edge.discovery.catalog.already_seen_skip_total");
        let first = evaluator.evaluate_tls(host);
        let second = evaluator.evaluate_tls(host);
        let after_intercept = counter_value("edge.discovery.catalog.intercept_total");
        let after_seen_skip = counter_value("edge.discovery.catalog.already_seen_skip_total");

        assert!(matches!(first, GateDecision::Intercept));
        assert!(matches!(second, GateDecision::Intercept));
        assert!(after_intercept >= before_intercept + 1);
        assert!(after_seen_skip >= before_seen_skip + 1);
    }
}
