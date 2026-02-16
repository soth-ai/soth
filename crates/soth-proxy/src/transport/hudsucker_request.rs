//! Request-side planning helpers for hudsucker transport.

use hudsucker::{hyper::Request, Body};
use soth_core::config::{HostAction, HostFilterMode};
use soth_oisp::OispEngine;

use crate::transport::hudsucker_detection::{
    should_log_request, should_treat_anthropic_api_as_agent,
};
use crate::transport::hudsucker_payload::parse_content_length;
use crate::transport::hudsucker_support::{CatalogDiscoveryLimiter, DiscoveryKind};

#[derive(Debug, Clone)]
pub(crate) struct HostTargetInfo {
    pub(crate) should_capture_observability: bool,
    pub(crate) is_catalog_discovery_host: bool,
    pub(crate) host_is_ai_target: bool,
    pub(crate) host_is_mcp_target: bool,
    pub(crate) host_is_agent_target: bool,
    pub(crate) provider: Option<String>,
}

pub(crate) fn resolve_host_target_info(
    req: &Request<Body>,
    host_action: HostAction,
    host_mode: HostFilterMode,
    host: &str,
    is_connect: bool,
    oisp_engine: &OispEngine,
    catalog_discovery_limiter: &CatalogDiscoveryLimiter,
) -> HostTargetInfo {
    let should_capture_observability = matches!(host_action, HostAction::Intercept);
    let oisp_classification = if should_capture_observability {
        oisp_engine.classify(host)
    } else {
        None
    };
    let is_catalog_discovery_host = should_capture_observability
        && host_mode == HostFilterMode::Discovery
        && oisp_classification.is_none()
        && oisp_engine.is_catalog_domain(host)
        && catalog_discovery_limiter.was_reserved_today(DiscoveryKind::Catalog, host);
    let (mut host_is_ai_target, host_is_mcp_target, mut host_is_agent_target, provider) =
        if let Some(classification) = oisp_classification.as_ref() {
            let (ai, mcp, agent) = match classification.entry_type_label() {
                "ai_inference" => (true, false, false),
                "mcp" => (false, true, false),
                "agent_app" => (false, false, true),
                _ => (false, false, false),
            };
            (ai, mcp, agent, Some(classification.provider_id.clone()))
        } else if is_catalog_discovery_host {
            (false, false, false, Some("catalog-discovery".to_string()))
        } else {
            (false, false, false, None)
        };
    let anthropic_agent_override = should_capture_observability
        && !is_connect
        && should_treat_anthropic_api_as_agent(host, req);
    if anthropic_agent_override {
        host_is_ai_target = false;
        host_is_agent_target = true;
    }

    HostTargetInfo {
        should_capture_observability,
        is_catalog_discovery_host,
        host_is_ai_target,
        host_is_mcp_target,
        host_is_agent_target,
        provider,
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RequestBodyInspectionPlan {
    pub(crate) is_post: bool,
    pub(crate) content_type: Option<String>,
    pub(crate) is_json: bool,
    pub(crate) request_content_encoding: Option<String>,
    pub(crate) declared_request_size_bytes: Option<u64>,
    pub(crate) request_capture_oversized: bool,
    pub(crate) should_log_inference_request: bool,
    pub(crate) should_inspect_body: bool,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_request_body_inspection_plan(
    req: &Request<Body>,
    path: &str,
    http_method: &str,
    host_mode: HostFilterMode,
    should_capture_observability: bool,
    host_is_ai_target: bool,
    host_is_mcp_target: bool,
    host_is_agent_target: bool,
    is_catalog_discovery_host: bool,
    capture_max_body_bytes: u64,
) -> RequestBodyInspectionPlan {
    let is_post = req.method() == hyper::Method::POST;
    let content_type = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let is_json = content_type
        .as_ref()
        .map(|ct| ct.contains("application/json"))
        .unwrap_or(false);
    let request_content_encoding = req
        .headers()
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_lowercase());
    let declared_request_size_bytes = parse_content_length(req.headers());
    let request_capture_oversized = declared_request_size_bytes
        .map(|size| size > capture_max_body_bytes)
        .unwrap_or(false);
    let should_log_inference_request = should_log_request(path, http_method);
    let should_inspect_body = is_post
        && should_capture_observability
        && (host_is_mcp_target
            || (((host_is_ai_target || host_is_agent_target)
                || (host_mode == HostFilterMode::Discovery && is_json))
                && should_log_inference_request))
        && !is_catalog_discovery_host
        && !request_capture_oversized;

    RequestBodyInspectionPlan {
        is_post,
        content_type,
        is_json,
        request_content_encoding,
        declared_request_size_bytes,
        request_capture_oversized,
        should_log_inference_request,
        should_inspect_body,
    }
}
