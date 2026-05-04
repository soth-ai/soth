//! In-process → wire conversion.
//!
//! `map_event` is the single canonical translator from the rich
//! in-process `soth_core::TelemetryEvent` to the cloud-bound
//! `api_types::TelemetryEvent`. The proxy (`soth-sync`) and the SDK
//! (`soth-sdk-core`) both call this so an envelope or field change
//! made here propagates to both sides at once. Drift here is what
//! produced the SDK→cloud `topic_cluster_id` 422 we hit before this
//! crate existed.

use std::collections::HashMap;

use soth_core::{ClassificationFlag, TelemetryPolicyKind, UseCaseLabelReason};

use crate::api_types::TelemetryEvent;

pub fn map_event(event: &soth_core::TelemetryEvent) -> TelemetryEvent {
    let mut tags = HashMap::new();
    let detected_credential_types = event.sensitive_code_flags.detected_secret_types.clone();
    if let Some(endpoint_type) = enum_name(&event.endpoint_type) {
        tags.insert("endpoint_type".to_string(), endpoint_type);
    }
    if let Some(capture_mode) = enum_name(&event.capture_mode) {
        tags.insert("capture_mode".to_string(), capture_mode);
    }
    if let Some(parse_confidence) = enum_name(&event.parse_confidence) {
        tags.insert("parse_confidence".to_string(), parse_confidence);
    }
    if let Some(request_method) = enum_name(&event.request_method) {
        tags.insert("request_method".to_string(), request_method);
    }
    if let Ok(parse_source_json) = serde_json::to_string(&event.parse_source) {
        tags.insert("parse_source".to_string(), parse_source_json);
    }
    if let Some(bundle_trust_level) = event.bundle_trust_level.as_ref().and_then(enum_name) {
        tags.insert("bundle_trust_level".to_string(), bundle_trust_level);
    }

    // Emit app identity from process_resolution so cloud can group by tool
    if let Some(ref pr) = event.process_resolution {
        let source_class = match pr.app_type {
            soth_core::AppType::NonHost => "agent_app",
            soth_core::AppType::Host => "browser",
            soth_core::AppType::Unknown => "unknown",
        };
        tags.insert("source_class".to_string(), source_class.to_string());

        let tool_key = pr
            .matched_app_id
            .as_deref()
            .or(pr.process_name.as_deref())
            .or(pr.bundle_id.as_deref());
        if let Some(key) = tool_key {
            tags.insert("tool_identity_key".to_string(), key.to_string());
        }
        if let Some(ref name) = pr.process_name {
            tags.insert("process_name".to_string(), name.clone());
        }
        if let Some(ref bid) = pr.bundle_id {
            tags.insert("bundle_id".to_string(), bid.clone());
        }
        if let Some(match_kind) = enum_name(&pr.match_kind) {
            tags.insert("match_kind".to_string(), match_kind);
        }
        if let Some(ref name) = pr.tool_name {
            tags.insert("tool_name".to_string(), name.clone());
        }
        if let Some(ref kind) = pr.tool_kind {
            tags.insert("tool_kind".to_string(), kind.clone());
        }
        if let Some(ref cat) = pr.tool_category {
            tags.insert("tool_category".to_string(), cat.clone());
        }
        if let Some(ref pid) = pr.provider_id {
            tags.insert("provider_id".to_string(), pid.clone());
        }
    }

    if let Some(ref ja4) = event.ja4_hash {
        if !ja4.is_empty() {
            tags.insert("ja4_hash".to_string(), ja4.clone());
        }
    }
    if let Some(ref tv) = event.tls_version {
        if !tv.is_empty() {
            tags.insert("tls_version".to_string(), tv.clone());
        }
    }
    if let Some(ref alpn) = event.alpn_protocol {
        if !alpn.is_empty() {
            tags.insert("alpn_protocol".to_string(), alpn.clone());
        }
    }
    if let Some(ref h2cid) = event.h2_connection_id {
        if !h2cid.is_empty() {
            tags.insert("h2_connection_id".to_string(), h2cid.clone());
        }
    }
    if let Some(h2sid) = event.h2_stream_id {
        tags.insert("h2_stream_id".to_string(), h2sid.to_string());
    }

    // Historian-not-enriched warning is intentionally NOT emitted here
    // (`soth-api-types` is a pure-types crate with no `tracing` dep).
    // The proxy logs it at the call site that builds the batch; the
    // SDK doesn't run historian enrichment so the case never fires.
    let _ = matches!(
        event.use_case_label_reason,
        UseCaseLabelReason::HistorianNotEnriched
    );

    TelemetryEvent {
        event_id: event.event_id.to_string(),
        timestamp: event.timestamp_epoch_ms / 1_000,
        provider: Some(event.provider.clone()),
        model: event.model.clone(),
        use_case_label: enum_name(&event.use_case),
        use_case_label_reason: enum_name(&event.use_case_label_reason),
        use_case_confidence: if event.use_case_confidence > 0.0 {
            Some(event.use_case_confidence)
        } else {
            None
        },
        secondary_label: event.secondary_label.as_ref().and_then(enum_name),
        topic_cluster_id: if event.topic_cluster_id > 0 {
            Some(event.topic_cluster_id.to_string())
        } else {
            None
        },
        semantic_hash: if event.semantic_hash.is_empty() {
            None
        } else {
            Some(event.semantic_hash.clone())
        },
        is_semantic_collision: event.is_semantic_collision,
        collision_response_stability: event.collision_response_stability.map(f64::from),
        anomaly_score: event.anomaly_score.map(f64::from),
        volatility_class: enum_name(&event.volatility_class),
        input_tokens: event.estimated_input_tokens.map(u64::from),
        output_tokens: event.estimated_output_tokens.map(u64::from),
        estimated_cost_usd: event.estimated_cost_usd.map(f64::from),
        policy_decision: event.policy_kind.as_ref().and_then(enum_name),
        policy_rule_id: event.policy_rule_id.clone(),
        redaction_event: Some(matches!(
            event.policy_kind,
            Some(TelemetryPolicyKind::Redact)
        )),
        credential_pattern_detected: Some(
            event.sensitive_code_flags.credential_pattern_detected
                || event
                    .classification_flags
                    .contains(&ClassificationFlag::CredentialDetected),
        ),
        detected_secret_types: if detected_credential_types.is_empty() {
            None
        } else {
            Some(detected_credential_types.clone())
        },
        detected_credential_types,
        languages: enum_names(&event.languages),
        import_categories: enum_names(&event.import_categories),
        auth_logic_detected: true_option(event.sensitive_code_flags.auth_logic_detected),
        crypto_operations_detected: true_option(
            event.sensitive_code_flags.crypto_operations_detected,
        ),
        network_calls_detected: true_option(event.sensitive_code_flags.network_calls_detected),
        file_io_detected: true_option(event.sensitive_code_flags.file_io_detected),
        private_key_detected: true_option(event.sensitive_code_flags.private_key_detected),
        hardcoded_secret_detected: true_option(
            event.sensitive_code_flags.hardcoded_secret_detected,
        ),
        org_pattern_matches: event.sensitive_code_flags.org_pattern_matches.clone(),
        anomaly_flags: enum_names(&event.anomaly_flags),
        endpoint_hash: if event.endpoint_hash.is_empty() {
            None
        } else {
            Some(event.endpoint_hash.clone())
        },
        code_fraction: if event.code_fraction > 0.0 {
            Some(f64::from(event.code_fraction))
        } else {
            None
        },
        tags,
        session_key_hash: if event.session_key_hash.is_empty() {
            None
        } else {
            Some(event.session_key_hash.clone())
        },
        is_prefix_repeat: if event.is_prefix_repeat {
            Some(true)
        } else {
            None
        },
        is_code_context_repeat: if event.is_code_context_repeat {
            Some(true)
        } else {
            None
        },
        novel_token_count: if event.novel_token_count > 0 {
            Some(u64::from(event.novel_token_count))
        } else {
            None
        },
        repeated_token_count: if event.repeated_token_count > 0 {
            Some(u64::from(event.repeated_token_count))
        } else {
            None
        },
        first_step_event_id: event.first_step_event_id.clone(),
        original_event_id: event.original_event_id.clone(),
        data_source: enum_name(&event.data_source),
        dynamic_fraction: if event.dynamic_fraction > 0.0 {
            Some(event.dynamic_fraction)
        } else {
            None
        },
        system_prompt_hash: event.system_prompt_hash.clone(),
        tool_definition_hash: event.tool_definition_hash.clone(),
        prefix_repeat_signature: event.prefix_repeat_signature.clone(),
        complexity_score: if event.complexity_score > 0 {
            Some(event.complexity_score)
        } else {
            None
        },
        actual_output_tokens: event.actual_output_tokens,
        finish_reason: event.finish_reason.clone(),
        response_latency_ms: event.response_latency_ms,
        ttfb_ms: event.ttfb_ms,
        session_request_count: event.session_request_count,
        session_total_tokens: event.session_total_tokens,
        session_credential_alerts: event.session_credential_alerts,
        conversation_turn: event.conversation_turn,
        ws_turn_number: event.ws_turn_number,
        session_id: event.session_id.map(|u| u.to_string()),
        product_id: event.product_id.clone(),
        surface_type: enum_name(&event.surface_type),
        is_shadow_it: if event.is_shadow_it { Some(true) } else { None },
        interaction_mode: enum_name(&event.interaction_mode),
    }
}

fn enum_name<T: serde::Serialize>(value: &T) -> Option<String> {
    match serde_json::to_value(value).ok()? {
        serde_json::Value::String(value) => Some(value),
        _ => None,
    }
}

fn enum_names<T: serde::Serialize>(values: &[T]) -> Vec<String> {
    values.iter().filter_map(enum_name).collect()
}

fn true_option(value: bool) -> Option<bool> {
    if value {
        Some(true)
    } else {
        None
    }
}
