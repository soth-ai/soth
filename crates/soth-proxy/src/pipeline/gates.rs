use soth_core::{
    AppType, CaptureMode, ProcessMatchKind, ProcessResolution, RequestHeaders,
    TrafficClassification,
};

use crate::config::{GateAction, PipelineConfig};
use crate::pipeline::capture_mode::derive_capture_mode;
use crate::pipeline::registry::Registry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalStage {
    Connect,
    HttpRequest,
}

#[derive(Debug, Clone)]
pub struct EdgeRequest {
    pub method: String,
    pub host: String,
    pub path: String,
    pub headers: RequestHeaders,
    pub process: ProcessResolution,
    pub stage: EvalStage,
}

#[derive(Debug, Clone)]
pub struct DetectionOutcome {
    pub action: OutcomeAction,
    pub capture_mode: CaptureMode,
    pub matched_provider: Option<String>,
    pub matched_application: Option<String>,
    pub traffic_classification: TrafficClassification,
    pub discovery_capture: bool,
    pub decision_reason: DecisionReason,
}

#[derive(Debug, Clone)]
pub enum OutcomeAction {
    Intercept,
    Skip,
    Block { status: u16, message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionReason {
    ProcessAction,
    NotInCatalog,
    UnknownAppPolicy,
    Blacklisted,
    HostOriginNotAllowed,
    CaptureDisabled,
    MethodNotAllowed,
    Intercept,
}

pub fn evaluate(
    req: &EdgeRequest,
    registry: &Registry,
    config: &PipelineConfig,
) -> DetectionOutcome {
    if req.process.match_kind != ProcessMatchKind::Unknown
        && req.process.app_type == AppType::Unknown
    {
        return outcome_skip(DecisionReason::ProcessAction, registry);
    }

    let in_catalog = registry.in_ai_catalog(req.host.as_str());
    let discovery_capture = !in_catalog
        && req.process.app_type == AppType::Host
        && referer_in_catalog(&req.headers, registry);

    if !in_catalog && !discovery_capture {
        return match config.non_cataloged_host_action {
            GateAction::Skip => outcome_skip(DecisionReason::NotInCatalog, registry),
            GateAction::Block => outcome_block(
                403,
                "host not in AI catalog".to_string(),
                DecisionReason::NotInCatalog,
                registry,
            ),
            GateAction::Intercept => outcome_intercept_placeholder(registry, discovery_capture),
        };
    }

    if req.process.match_kind == ProcessMatchKind::Unknown
        && config.unknown_app_action != GateAction::Intercept
    {
        return match config.unknown_app_action {
            GateAction::Skip => outcome_skip(DecisionReason::UnknownAppPolicy, registry),
            GateAction::Block => outcome_block(
                403,
                "unknown process blocked".to_string(),
                DecisionReason::UnknownAppPolicy,
                registry,
            ),
            GateAction::Intercept => outcome_intercept_placeholder(registry, discovery_capture),
        };
    }

    let full_url = format!("{}{}", req.host, req.path);
    if registry
        .find_blacklisted_keyword(full_url.as_str())
        .is_some()
    {
        return outcome_skip(DecisionReason::Blacklisted, registry);
    }

    if req.stage == EvalStage::HttpRequest
        && req.process.app_type == AppType::Host
        && !discovery_capture
        && !origin_or_referer_in_catalog(&req.headers, registry)
    {
        return outcome_skip(DecisionReason::HostOriginNotAllowed, registry);
    }

    let matched_provider = registry.match_provider(req.host.as_str());
    let matched_application = registry
        .match_application(
            req.process.process_name.as_deref(),
            req.process.bundle_id.as_deref(),
        )
        .map(|rule| rule.app_id.clone());

    if matched_provider.is_none() && matched_application.is_none() && !discovery_capture {
        return outcome_skip(DecisionReason::NotInCatalog, registry);
    }

    if req.stage == EvalStage::HttpRequest {
        let method = req.method.to_ascii_uppercase();
        if !matches!(
            method.as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
        ) {
            return outcome_skip(DecisionReason::MethodNotAllowed, registry);
        }
    }

    let capture_mode = derive_capture_mode(
        &req.process,
        matched_provider.as_deref(),
        discovery_capture,
        registry,
    );

    let traffic_classification = derive_traffic_classification(
        matched_provider.is_some(),
        req.process.app_type,
        matched_application.is_some(),
    );

    DetectionOutcome {
        action: OutcomeAction::Intercept,
        capture_mode,
        matched_provider,
        matched_application,
        traffic_classification,
        discovery_capture,
        decision_reason: DecisionReason::Intercept,
    }
}

fn outcome_skip(reason: DecisionReason, registry: &Registry) -> DetectionOutcome {
    DetectionOutcome {
        action: OutcomeAction::Skip,
        capture_mode: registry.capture_default_mode(),
        matched_provider: None,
        matched_application: None,
        traffic_classification: TrafficClassification::Other,
        discovery_capture: false,
        decision_reason: reason,
    }
}

fn outcome_block(
    status: u16,
    message: String,
    reason: DecisionReason,
    registry: &Registry,
) -> DetectionOutcome {
    DetectionOutcome {
        action: OutcomeAction::Block { status, message },
        capture_mode: registry.capture_default_mode(),
        matched_provider: None,
        matched_application: None,
        traffic_classification: TrafficClassification::Other,
        discovery_capture: false,
        decision_reason: reason,
    }
}

fn outcome_intercept_placeholder(registry: &Registry, discovery_capture: bool) -> DetectionOutcome {
    DetectionOutcome {
        action: OutcomeAction::Intercept,
        capture_mode: if discovery_capture {
            CaptureMode::MetadataOnly
        } else {
            registry.capture_default_mode()
        },
        matched_provider: None,
        matched_application: None,
        traffic_classification: TrafficClassification::Other,
        discovery_capture,
        decision_reason: DecisionReason::Intercept,
    }
}

fn derive_traffic_classification(
    provider_match: bool,
    app_type: AppType,
    application_match: bool,
) -> TrafficClassification {
    if application_match {
        return TrafficClassification::ApplicationUsage;
    }

    if provider_match {
        return match app_type {
            AppType::NonHost => TrafficClassification::ToolUsage,
            AppType::Host => TrafficClassification::UnknownAgent,
            AppType::Unknown => TrafficClassification::UnknownAgent,
        };
    }

    TrafficClassification::Other
}

fn origin_or_referer_in_catalog(headers: &RequestHeaders, registry: &Registry) -> bool {
    host_from_url_header(headers, "origin")
        .or_else(|| host_from_url_header(headers, "referer"))
        .is_some_and(|host| registry.in_ai_catalog(host.as_str()))
}

fn referer_in_catalog(headers: &RequestHeaders, registry: &Registry) -> bool {
    host_from_url_header(headers, "referer")
        .is_some_and(|host| registry.in_ai_catalog(host.as_str()))
}

fn host_from_url_header(headers: &RequestHeaders, key: &str) -> Option<String> {
    let value = headers.get(key)?;
    parse_host_from_url_like(value.as_str())
}

fn parse_host_from_url_like(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    let without_scheme = value
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(value);

    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);
    let host = host_port.split(':').next().unwrap_or(host_port).trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use soth_core::{AppType, CaptureMode, ProcessMatchKind, ProcessResolution};

    use super::*;

    fn fixture_registry() -> Registry {
        let mut bundle = soth_detect::OwnedDetectBundle::default();
        bundle
            .domain_index
            .insert("api.openai.com".to_string(), "openai".to_string());
        bundle.llm_providers.insert(
            "openai".to_string(),
            soth_detect::ProviderEntry {
                provider_id: Some("openai".to_string()),
                name: Some("openai".to_string()),
                api_format: Some("openai_rest".to_string()),
            },
        );
        bundle.applications.insert(
            "cursor".to_string(),
            soth_detect::ApplicationEntry {
                app_id: Some("cursor".to_string()),
                name: Some("Cursor".to_string()),
                bundle_ids: vec!["com.cursor.app".to_string()],
                process_names: vec!["cursor".to_string()],
            },
        );
        bundle.capture_rules.default_mode = CaptureMode::SensitiveArtifacts;
        bundle
            .capture_rules
            .full_capture_providers
            .push("openai".to_string());
        bundle.filters.path_keywords = vec!["/blocked".to_string()];
        Registry::from_detect_bundle(&bundle)
    }

    fn default_process() -> ProcessResolution {
        ProcessResolution {
            match_kind: ProcessMatchKind::Exact,
            app_type: AppType::NonHost,
            capture_mode: Some(CaptureMode::SensitiveArtifacts),
            process_name: Some("cursor".to_string()),
            bundle_id: Some("com.cursor.app".to_string()),
        }
    }

    fn edge_request(
        method: &str,
        host: &str,
        path: &str,
        headers: RequestHeaders,
        process: ProcessResolution,
        stage: EvalStage,
    ) -> EdgeRequest {
        EdgeRequest {
            method: method.to_string(),
            host: host.to_string(),
            path: path.to_string(),
            headers,
            process,
            stage,
        }
    }

    fn config_with_defaults() -> PipelineConfig {
        PipelineConfig::default()
    }

    fn process_without_application_match(app_type: AppType) -> ProcessResolution {
        ProcessResolution {
            match_kind: ProcessMatchKind::Unknown,
            app_type,
            capture_mode: Some(CaptureMode::SensitiveArtifacts),
            process_name: Some("tooling-client".to_string()),
            bundle_id: Some("com.example.tooling".to_string()),
        }
    }

    #[test]
    fn gate1_process_action_short_circuits_before_catalog() {
        let registry = fixture_registry();
        let process = ProcessResolution {
            match_kind: ProcessMatchKind::Exact,
            app_type: AppType::Unknown,
            capture_mode: Some(CaptureMode::MetadataOnly),
            process_name: Some("known-proc".to_string()),
            bundle_id: None,
        };
        let req = edge_request(
            "POST",
            "api.openai.com",
            "/v1/chat/completions",
            BTreeMap::new(),
            process,
            EvalStage::HttpRequest,
        );

        let outcome = evaluate(&req, &registry, &config_with_defaults());
        assert!(matches!(outcome.action, OutcomeAction::Skip));
        assert_eq!(outcome.decision_reason, DecisionReason::ProcessAction);
    }

    #[test]
    fn gate2_non_catalog_default_skips() {
        let registry = fixture_registry();
        let req = edge_request(
            "POST",
            "example.invalid",
            "/v1/chat/completions",
            BTreeMap::new(),
            default_process(),
            EvalStage::HttpRequest,
        );

        let outcome = evaluate(&req, &registry, &config_with_defaults());
        assert!(matches!(outcome.action, OutcomeAction::Skip));
        assert_eq!(outcome.decision_reason, DecisionReason::NotInCatalog);
    }

    #[test]
    fn gate2_non_catalog_can_block_via_config() {
        let registry = fixture_registry();
        let mut cfg = config_with_defaults();
        cfg.non_cataloged_host_action = GateAction::Block;
        let req = edge_request(
            "POST",
            "example.invalid",
            "/v1/chat/completions",
            BTreeMap::new(),
            default_process(),
            EvalStage::HttpRequest,
        );

        let outcome = evaluate(&req, &registry, &cfg);
        assert!(matches!(
            outcome.action,
            OutcomeAction::Block { status: 403, .. }
        ));
        assert_eq!(outcome.decision_reason, DecisionReason::NotInCatalog);
    }

    #[test]
    fn gate3_unknown_app_policy_applies_for_unknown_process() {
        let registry = fixture_registry();
        let process = ProcessResolution {
            match_kind: ProcessMatchKind::Unknown,
            app_type: AppType::Unknown,
            capture_mode: None,
            process_name: None,
            bundle_id: None,
        };
        let req = edge_request(
            "POST",
            "api.openai.com",
            "/v1/chat/completions",
            BTreeMap::new(),
            process,
            EvalStage::HttpRequest,
        );
        let outcome = evaluate(&req, &registry, &config_with_defaults());
        assert!(matches!(outcome.action, OutcomeAction::Skip));
        assert_eq!(outcome.decision_reason, DecisionReason::UnknownAppPolicy);
    }

    #[test]
    fn gate4_blacklist_skips() {
        let registry = fixture_registry();
        let req = edge_request(
            "POST",
            "api.openai.com",
            "/blocked/v1/chat/completions",
            BTreeMap::new(),
            default_process(),
            EvalStage::HttpRequest,
        );
        let mut cfg = config_with_defaults();
        cfg.unknown_app_action = GateAction::Intercept;

        let outcome = evaluate(&req, &registry, &cfg);
        assert!(matches!(outcome.action, OutcomeAction::Skip));
        assert_eq!(outcome.decision_reason, DecisionReason::Blacklisted);
    }

    #[test]
    fn gate5_host_origin_check_skips_without_origin_or_referer() {
        let registry = fixture_registry();
        let process = ProcessResolution {
            match_kind: ProcessMatchKind::Exact,
            app_type: AppType::Host,
            capture_mode: Some(CaptureMode::MetadataOnly),
            process_name: Some("chrome".to_string()),
            bundle_id: Some("com.google.Chrome".to_string()),
        };
        let req = edge_request(
            "POST",
            "api.openai.com",
            "/v1/chat/completions",
            BTreeMap::new(),
            process,
            EvalStage::HttpRequest,
        );
        let mut cfg = config_with_defaults();
        cfg.unknown_app_action = GateAction::Intercept;

        let outcome = evaluate(&req, &registry, &cfg);
        assert!(matches!(outcome.action, OutcomeAction::Skip));
        assert_eq!(
            outcome.decision_reason,
            DecisionReason::HostOriginNotAllowed
        );
    }

    #[test]
    fn method_filter_rejects_trace_for_http_stage() {
        let registry = fixture_registry();
        let req = edge_request(
            "TRACE",
            "api.openai.com",
            "/v1/chat/completions",
            BTreeMap::new(),
            default_process(),
            EvalStage::HttpRequest,
        );
        let mut cfg = config_with_defaults();
        cfg.unknown_app_action = GateAction::Intercept;

        let outcome = evaluate(&req, &registry, &cfg);
        assert!(matches!(outcome.action, OutcomeAction::Skip));
        assert_eq!(outcome.decision_reason, DecisionReason::MethodNotAllowed);
    }

    #[test]
    fn capture_mode_precedence_provider_overrides_process_default() {
        let registry = fixture_registry();
        let process = ProcessResolution {
            capture_mode: Some(CaptureMode::MetadataOnly),
            ..default_process()
        };
        let req = edge_request(
            "POST",
            "api.openai.com",
            "/v1/chat/completions",
            BTreeMap::new(),
            process,
            EvalStage::HttpRequest,
        );
        let mut cfg = config_with_defaults();
        cfg.unknown_app_action = GateAction::Intercept;

        let outcome = evaluate(&req, &registry, &cfg);
        assert!(matches!(outcome.action, OutcomeAction::Intercept));
        assert_eq!(outcome.capture_mode, CaptureMode::Full);
    }

    #[test]
    fn discovery_capture_forces_metadata_only() {
        let registry = fixture_registry();
        let process = ProcessResolution {
            match_kind: ProcessMatchKind::Exact,
            app_type: AppType::Host,
            capture_mode: Some(CaptureMode::FullContent),
            process_name: Some("chrome".to_string()),
            bundle_id: None,
        };
        let mut headers = BTreeMap::new();
        headers.insert(
            "referer".to_string(),
            "https://api.openai.com/v1/chat/completions".to_string(),
        );
        let req = edge_request(
            "POST",
            "new-ai-host.example",
            "/v1/chat/completions",
            headers,
            process,
            EvalStage::HttpRequest,
        );
        let mut cfg = config_with_defaults();
        cfg.non_cataloged_host_action = GateAction::Intercept;
        cfg.unknown_app_action = GateAction::Intercept;

        let outcome = evaluate(&req, &registry, &cfg);
        assert!(matches!(outcome.action, OutcomeAction::Intercept));
        assert!(outcome.discovery_capture);
        assert_eq!(outcome.capture_mode, CaptureMode::MetadataOnly);
    }

    #[test]
    fn traffic_classification_matches_contract_table() {
        let registry = fixture_registry();
        let mut cfg = config_with_defaults();
        cfg.unknown_app_action = GateAction::Intercept;

        let tool_usage = evaluate(
            &edge_request(
                "POST",
                "api.openai.com",
                "/v1/chat/completions",
                BTreeMap::new(),
                process_without_application_match(AppType::NonHost),
                EvalStage::HttpRequest,
            ),
            &registry,
            &cfg,
        );
        assert_eq!(
            tool_usage.traffic_classification,
            TrafficClassification::ToolUsage
        );

        let unknown_agent = evaluate(
            &edge_request(
                "POST",
                "api.openai.com",
                "/v1/chat/completions",
                BTreeMap::from([(
                    "origin".to_string(),
                    "https://api.openai.com/workbench".to_string(),
                )]),
                process_without_application_match(AppType::Host),
                EvalStage::HttpRequest,
            ),
            &registry,
            &cfg,
        );
        assert_eq!(
            unknown_agent.traffic_classification,
            TrafficClassification::UnknownAgent
        );

        let app_usage = evaluate(
            &edge_request(
                "POST",
                "api.openai.com",
                "/v1/chat/completions",
                BTreeMap::new(),
                default_process(),
                EvalStage::HttpRequest,
            ),
            &registry,
            &cfg,
        );
        assert_eq!(
            app_usage.traffic_classification,
            TrafficClassification::ApplicationUsage
        );
    }
}
