//! Exchange-v2 projection and enrichment helpers for proxy transport.

use crate::process_attribution::ProcessIdentity;
use crate::transport::exchange_assembler::{ExchangeAssembler, ExchangeAssemblerConfig};
use crate::transport::pii_enrichment::PiiEventEnricher;
use crate::transport::proxy_support::process_bundle_id_from_executable;
use crate::transport::usage_enrichment::ResponseUsageMeta;
use soth_budget::{BudgetTracker, TokenCounter};
use soth_core::types::exchange_v2::{
    ExchangeClient, ExchangeCost, ExchangeParse, ExchangeSourceClass, ExchangeTransport,
    ExchangeUsage,
};
use soth_core::types::{
    AgentInfo, DetectionSource, EventSource, TrafficEnvelope, WrapDirection, WrapEvent,
};
use soth_core::EventLogger;
use std::collections::BTreeMap;
use tracing::warn;

use crate::transport::proxy::PendingRequest;

pub(crate) fn append_detection_tags(tags: &mut BTreeMap<String, String>, pending: &PendingRequest) {
    append_detection_tags_from_values(
        tags,
        pending.detection_source.as_deref(),
        pending.detection_reason.as_deref(),
        pending.parse_confidence,
        pending.target_entity_id.as_deref(),
    );
}

fn append_detection_tags_from_values(
    tags: &mut BTreeMap<String, String>,
    detection_source: Option<&str>,
    detection_reason: Option<&str>,
    parse_confidence: Option<f64>,
    target_entity_id: Option<&str>,
) {
    if let Some(source) = detection_source {
        tags.insert("detection.source".to_string(), source.to_string());
    }
    if let Some(reason) = detection_reason {
        tags.insert("detection.reason".to_string(), reason.to_string());
    }
    if let Some(confidence) = parse_confidence {
        tags.insert(
            "detection.parse_confidence".to_string(),
            format!("{confidence:.3}"),
        );
    }
    if let Some(entity_id) = target_entity_id {
        tags.insert(
            "detection.target_entity_id".to_string(),
            entity_id.to_string(),
        );
    }
}

/// Record proxy spend using response usage as the primary source, with request-body
/// token estimation as fallback when provider usage is unavailable.
pub(crate) fn record_proxy_budget_spend(
    tracker: &BudgetTracker,
    session_id: &str,
    pending: &PendingRequest,
    usage_meta: &ResponseUsageMeta,
) {
    let input_tokens = usage_meta.input_tokens.unwrap_or_else(|| {
        pending
            .request_content
            .as_deref()
            .map(TokenCounter::estimate_tokens)
            .unwrap_or(0)
    });
    let output_tokens = usage_meta.output_tokens.unwrap_or(0);

    if input_tokens == 0 && output_tokens == 0 {
        return;
    }

    let model = usage_meta
        .model
        .as_deref()
        .or(pending.model.as_deref())
        .unwrap_or("unknown");
    let agent_id = pending
        .envelope
        .as_ref()
        .and_then(|envelope| envelope.did.as_deref())
        .or(pending.agent.as_deref());

    tracker.record_spend_with_cost(
        session_id,
        agent_id,
        model,
        input_tokens,
        output_tokens,
        usage_meta.cost_usd,
    );
}

fn source_class_for_pending(pending: &PendingRequest) -> ExchangeSourceClass {
    if pending.is_mcp_jsonrpc {
        ExchangeSourceClass::Mcp
    } else if pending.is_agent_app {
        ExchangeSourceClass::AgentApp
    } else {
        ExchangeSourceClass::AiInference
    }
}

fn transport_for_pending(
    pending: &PendingRequest,
    is_stream: bool,
    is_sse: bool,
) -> ExchangeTransport {
    if pending.is_mcp_jsonrpc {
        return ExchangeTransport::Jsonrpc;
    }
    if is_stream {
        if is_sse {
            return ExchangeTransport::Sse;
        }
        return ExchangeTransport::Ws;
    }
    ExchangeTransport::Https
}

fn event_source_for_pending(pending: &PendingRequest) -> EventSource {
    if pending.is_mcp_jsonrpc {
        EventSource::Mcp
    } else if pending.is_agent_app {
        EventSource::AgentApp
    } else {
        EventSource::AiProxy
    }
}

fn exchange_client_from_envelope(envelope: Option<&TrafficEnvelope>) -> Option<ExchangeClient> {
    let envelope = envelope?;
    let process_name = envelope
        .process_name
        .clone()
        .or_else(|| envelope.agent.clone())
        .or_else(|| envelope.provider.clone());
    let bundle_id = process_bundle_id_from_executable(envelope.process_executable.as_deref())
        .or_else(|| bundle_id_from_agent_hint(envelope.agent.as_deref()));
    let app_type = envelope
        .process_app_type
        .clone()
        .or_else(|| classify_process_app_type(process_name.as_deref(), bundle_id.as_deref()))
        .or_else(|| infer_agent_fallback_app_type(envelope.agent.as_deref()))
        .or_else(|| Some("unknown".to_string()));

    if envelope.process_pid.is_none()
        && process_name.is_none()
        && bundle_id.is_none()
        && app_type.is_none()
    {
        return None;
    }

    Some(ExchangeClient {
        pid: envelope.process_pid,
        bundle_id,
        process_name,
        app_type,
        referrer_origin: None,
    })
}

fn classify_process_app_type(
    process_name: Option<&str>,
    bundle_id: Option<&str>,
) -> Option<String> {
    if let Some(name) = process_name {
        let lower = name.to_ascii_lowercase();
        let has_any = |needles: &[&str]| needles.iter().any(|needle| lower.contains(needle));
        if has_any(&[
            "chrome", "firefox", "safari", "edge", "brave", "arc", "opera",
        ]) {
            return Some("browser".to_string());
        }
        if has_any(&[
            "claude-code",
            "codex",
            "terminal",
            "bash",
            "zsh",
            "fish",
            "python",
            "node",
            "npm",
            "cargo",
        ]) {
            return Some("cli".to_string());
        }
        if has_any(&[
            "cursor",
            "code",
            "windsurf",
            "jetbrains",
            "zed",
            "xcode",
            "vim",
        ]) {
            return Some("editor".to_string());
        }
        if has_any(&["service", "daemon", "launchd", "systemd"]) {
            return Some("service".to_string());
        }
    }
    if bundle_id.is_some() {
        return Some("desktop_app".to_string());
    }
    None
}

fn bundle_id_from_agent_hint(agent: Option<&str>) -> Option<String> {
    let agent = agent
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())?;
    let normalized = agent
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    if normalized.is_empty() {
        None
    } else {
        Some(format!("agent.{normalized}"))
    }
}

fn infer_agent_fallback_app_type(agent: Option<&str>) -> Option<String> {
    let lower = agent?.to_ascii_lowercase();
    let has_any = |needles: &[&str]| needles.iter().any(|needle| lower.contains(needle));
    if has_any(&["codex", "claude-code", "terminal", "shell", "cli"]) {
        return Some("cli".to_string());
    }
    if has_any(&[
        "cursor",
        "windsurf",
        "vscode",
        "copilot",
        "jetbrains",
        "zed",
    ]) {
        return Some("editor".to_string());
    }
    if has_any(&["chatgpt", "claude", "warp"]) {
        return Some("desktop_app".to_string());
    }
    Some("unknown".to_string())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn finalize_and_enqueue_exchange_v2(
    logger: &EventLogger,
    exchange_cfg: &ExchangeAssemblerConfig,
    pii_enricher: &PiiEventEnricher,
    pending: &PendingRequest,
    session_id: &str,
    status: u16,
    is_stream: bool,
    is_sse: bool,
    response_content_type: Option<&str>,
    response_headers: Option<BTreeMap<String, String>>,
    response_body: Option<&str>,
    usage_meta: &ResponseUsageMeta,
    tags: Option<&BTreeMap<String, String>>,
    response_truncated: bool,
    response_truncated_reason: Option<&str>,
    bundle_version: Option<&str>,
) {
    let mut assembler = ExchangeAssembler::new(
        exchange_cfg.clone(),
        pending.exchange_id.clone(),
        source_class_for_pending(pending),
        transport_for_pending(pending, is_stream, is_sse),
    );
    assembler.set_session_id(session_id.to_string());
    assembler.set_route(
        pending.provider.clone(),
        pending.agent.clone(),
        usage_meta.model.clone().or_else(|| pending.model.clone()),
        Some(pending.path.clone()),
        Some(pending.method.clone()),
    );
    assembler.set_client(exchange_client_from_envelope(pending.envelope.as_ref()));
    assembler.set_parse(Some(ExchangeParse {
        parser_version: Some("exchange_v2_edge".to_string()),
        bundle_version: bundle_version.map(ToString::to_string),
        parse_confidence: pending.parse_confidence,
        detection_reason: pending.detection_reason.clone(),
        target_entity_id: pending.target_entity_id.clone(),
        detection_source: pending.detection_source.clone(),
    }));
    assembler.set_blacklist_match(pending.blacklist_match);
    assembler.set_request(
        pending.headers.clone(),
        pending.request_content_type.clone(),
        pending
            .request_content
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    assembler.set_response_meta(
        response_headers,
        Some(status),
        response_content_type.map(|value| value.to_string()),
    );
    if let Some(body) = response_body {
        assembler.append_response_chunk(body.as_bytes());
    }
    assembler.set_usage(ExchangeUsage {
        input_tokens: usage_meta.input_tokens,
        output_tokens: usage_meta.output_tokens,
        cache_read_tokens: usage_meta.cache_read_tokens,
        cache_write_tokens: usage_meta.cache_write_tokens,
        reasoning_tokens: usage_meta.reasoning_tokens,
    });
    assembler.set_cost(usage_meta.cost_usd.map(|estimated_usd| ExchangeCost {
        estimated_usd,
        currency: "USD".to_string(),
        pricing_version: bundle_version.map(ToString::to_string),
    }));
    assembler.set_discovery_capture(pending.catalog_discovery);
    if pending.catalog_discovery {
        assembler.mark_metadata_only("catalog_discovery_metadata_only");
    }
    if pending.request_body_truncated {
        assembler.mark_truncated("request_body_truncated");
    }
    if response_truncated {
        assembler.mark_truncated(response_truncated_reason.unwrap_or("response_body_truncated"));
    }
    let mut exchange_tags = tags.cloned().unwrap_or_default();
    if let Some(allowed) = pending.policy_allowed {
        exchange_tags
            .entry("policy.allowed".to_string())
            .or_insert_with(|| allowed.to_string());
    }
    if let Some(version) = pending.policy_version.as_ref() {
        exchange_tags
            .entry("policy.version".to_string())
            .or_insert_with(|| version.clone());
    }
    if let Some(reason) = pending.policy_reason.as_ref() {
        exchange_tags
            .entry("policy.reason".to_string())
            .or_insert_with(|| reason.clone());
    }
    if let Some(operation) = pending.graphql_operation.as_ref() {
        exchange_tags
            .entry("graphql.operation".to_string())
            .or_insert_with(|| operation.clone());
    }
    if let Some(method) = pending.mcp_method.as_ref() {
        exchange_tags
            .entry("mcp.method".to_string())
            .or_insert_with(|| method.clone());
    }
    append_detection_tags(&mut exchange_tags, pending);
    if let Some(envelope) = pending.envelope.as_ref() {
        assembler.set_integrity_signature(envelope.signature.clone(), envelope.key_id.clone());
        if let Some(did) = envelope.did.as_ref() {
            exchange_tags
                .entry("identity.did".to_string())
                .or_insert_with(|| did.clone());
        }
        if let Some(signature_alg) = envelope.signature_alg.as_ref() {
            exchange_tags
                .entry("identity.signature_alg".to_string())
                .or_insert_with(|| signature_alg.clone());
        }
        if let Some(signed_fields_version) = envelope.signed_fields_version.as_ref() {
            exchange_tags
                .entry("identity.signed_fields_version".to_string())
                .or_insert_with(|| signed_fields_version.clone());
        }
        if let Some(process_executable) = envelope.process_executable.as_ref() {
            exchange_tags
                .entry("client.process_executable".to_string())
                .or_insert_with(|| process_executable.clone());
        }
    }
    assembler.set_tags((!exchange_tags.is_empty()).then_some(exchange_tags));
    let mut pii_probe = WrapEvent::new(
        session_id,
        &pending.host,
        WrapDirection::Out,
        AgentInfo::new(
            pending.agent.as_deref().unwrap_or("unknown"),
            DetectionSource::Environment,
        ),
    )
    .with_source(event_source_for_pending(pending));
    if let Some(provider) = pending.provider.as_ref() {
        pii_probe = pii_probe.with_provider(provider.clone());
    }
    if let Some(model) = usage_meta.model.as_ref().or(pending.model.as_ref()) {
        pii_probe = pii_probe.with_model(model.clone());
    }
    pii_probe = pii_probe.with_method(
        pending
            .mcp_method
            .clone()
            .unwrap_or_else(|| format!("{} {}", pending.method, pending.path)),
    );
    if let Some(request_body) = pending
        .request_content_for_pii
        .as_ref()
        .or(pending.request_content.as_ref())
    {
        pii_probe = pii_probe.with_request(request_body.clone(), "");
    }
    if let Some(response_body) = response_body {
        pii_probe = pii_probe.with_response(response_body.to_string(), "");
    }
    pii_enricher.enrich(&mut pii_probe);
    assembler.set_pii_detected(pii_probe.pii_detected);

    let mut result = if response_truncated && response_truncated_reason == Some("partial_timeout") {
        assembler.finalize_timeout_with_blobs()
    } else {
        assembler.finalize_complete_with_blobs()
    };
    result.event.pii_types = pii_probe.pii_types;

    let payload_json = match serde_json::to_string(&result.event) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                exchange_id = %pending.exchange_id,
                error = %error,
                "Failed encoding exchange.v2 payload"
            );
            return;
        }
    };
    let blobs_json = if result.blobs.is_empty() {
        None
    } else {
        match serde_json::to_string(&result.blobs) {
            Ok(value) => Some(value),
            Err(error) => {
                warn!(
                    exchange_id = %pending.exchange_id,
                    error = %error,
                    "Failed encoding exchange.v2 blob payloads"
                );
                None
            }
        }
    };

    if let Err(error) = logger.enqueue_exchange_upload_with_blobs(
        &pending.exchange_id,
        &payload_json,
        blobs_json.as_deref(),
    ) {
        warn!(
            exchange_id = %pending.exchange_id,
            error = %error,
            "Failed enqueuing exchange.v2 payload"
        );
        return;
    }
    let _ = logger.finalize_exchange_spool(&pending.exchange_id, None);
    let _ = logger.delete_exchange_spool(&pending.exchange_id);
}

pub(crate) fn seed_exchange_v2_spool(
    logger: &EventLogger,
    exchange_cfg: &ExchangeAssemblerConfig,
    pending: &PendingRequest,
    session_id: &str,
    bundle_version: Option<&str>,
) {
    let mut assembler = ExchangeAssembler::new(
        exchange_cfg.clone(),
        pending.exchange_id.clone(),
        source_class_for_pending(pending),
        transport_for_pending(pending, false, false),
    );
    assembler.set_session_id(session_id.to_string());
    assembler.set_route(
        pending.provider.clone(),
        pending.agent.clone(),
        pending.model.clone(),
        Some(pending.path.clone()),
        Some(pending.method.clone()),
    );
    assembler.set_client(exchange_client_from_envelope(pending.envelope.as_ref()));
    assembler.set_request(
        pending.headers.clone(),
        pending.request_content_type.clone(),
        pending
            .request_content
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    assembler.set_discovery_capture(pending.catalog_discovery);
    assembler.set_parse(Some(ExchangeParse {
        parser_version: Some("exchange_v2_edge".to_string()),
        bundle_version: bundle_version.map(ToString::to_string),
        parse_confidence: pending.parse_confidence,
        detection_reason: pending.detection_reason.clone(),
        target_entity_id: pending.target_entity_id.clone(),
        detection_source: pending.detection_source.clone(),
    }));
    assembler.set_blacklist_match(pending.blacklist_match);
    if let Some(envelope) = pending.envelope.as_ref() {
        assembler.set_integrity_signature(envelope.signature.clone(), envelope.key_id.clone());
    }
    let snapshot_json = match assembler.snapshot_json() {
        Ok(value) => value,
        Err(error) => {
            warn!(
                exchange_id = %pending.exchange_id,
                error = %error,
                "Failed serializing exchange spool snapshot"
            );
            return;
        }
    };
    let started_at = assembler.snapshot().started_at.to_rfc3339();
    if let Err(error) =
        logger.upsert_exchange_spool(&pending.exchange_id, &snapshot_json, &started_at)
    {
        warn!(
            exchange_id = %pending.exchange_id,
            error = %error,
            "Failed writing exchange spool snapshot"
        );
    }
}

pub(crate) fn apply_process_identity(
    mut envelope: TrafficEnvelope,
    process_identity: Option<&ProcessIdentity>,
) -> TrafficEnvelope {
    if let Some(process) = process_identity {
        envelope.process_pid = Some(process.pid);
        envelope.process_name = Some(process.name.clone());
        envelope.process_executable = process.executable.clone();
        envelope.process_app_type = Some(process.app_type.clone());
        envelope.process_attribution_source = Some(process.attribution_source.clone());
        envelope.process_attribution_confidence = Some(process.attribution_confidence);
    } else {
        if envelope.process_name.is_none() {
            envelope.process_name = envelope
                .agent
                .clone()
                .or_else(|| envelope.provider.clone())
                .or_else(|| envelope.host.clone());
        }
        if envelope.process_app_type.is_none() {
            envelope.process_app_type = classify_process_app_type(
                envelope.process_name.as_deref(),
                process_bundle_id_from_executable(envelope.process_executable.as_deref())
                    .as_deref(),
            )
            .or_else(|| infer_agent_fallback_app_type(envelope.agent.as_deref()));
            if envelope.process_app_type.is_none() {
                envelope.process_app_type = Some("unknown".to_string());
            }
        }
        if envelope.process_attribution_source.is_none() && envelope.process_name.is_some() {
            envelope.process_attribution_source = Some("heuristic_agent_fallback".to_string());
        }
        if envelope.process_attribution_confidence.is_none() && envelope.process_name.is_some() {
            envelope.process_attribution_confidence = Some(0.35);
        }
    }
    envelope
}

#[cfg(test)]
mod tests {
    use super::{apply_process_identity, exchange_client_from_envelope};
    use soth_core::types::TrafficEnvelope;

    #[test]
    fn apply_process_identity_uses_heuristic_fallback_when_lookup_missing() {
        let envelope = TrafficEnvelope::proxy(
            "s1",
            "r1",
            "anthropic",
            "api.anthropic.com",
            "POST",
            "/v1/messages",
            Some("claude-opus-4-6"),
            Some("claude"),
            None,
            None,
            Some("{}"),
        );
        let enriched = apply_process_identity(envelope, None);
        assert_eq!(enriched.process_name.as_deref(), Some("claude"));
        assert_eq!(enriched.process_app_type.as_deref(), Some("desktop_app"));
        assert_eq!(
            enriched.process_attribution_source.as_deref(),
            Some("heuristic_agent_fallback")
        );
        assert_eq!(enriched.process_attribution_confidence, Some(0.35));
    }

    #[test]
    fn exchange_client_falls_back_to_agent_when_process_fields_missing() {
        let envelope = TrafficEnvelope::proxy(
            "s1",
            "r1",
            "chatgpt",
            "chatgpt.com",
            "POST",
            "/backend-api/codex/responses",
            Some("gpt-5.3-codex"),
            Some("codex"),
            None,
            None,
            Some("{}"),
        );
        let client = exchange_client_from_envelope(Some(&envelope)).expect("client expected");
        assert_eq!(client.process_name.as_deref(), Some("codex"));
        assert_eq!(client.app_type.as_deref(), Some("cli"));
        assert_eq!(client.bundle_id.as_deref(), Some("agent.codex"));
    }
}
