use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use soth_core::{
    derive_proxy_signing_seed, ClassificationFlag, TelemetryPolicyKind, UseCaseLabelReason,
};
use soth_telemetry::{SignedBatch, TransmittedBatch};
use std::collections::HashMap;
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::api_types::{TelemetryBatchRequest, TelemetryEvent};
use crate::circuit_breaker::CircuitBreaker;
use crate::http_client::SothHttpClient;

#[derive(Debug, Clone)]
pub enum TelemetrySendOutcome {
    Sent,
    Retryable { reason: String },
    NonRetryable { reason: String },
}

/// Defaults used when no explicit circuit-breaker config is provided.
const DEFAULT_CB_FAILURE_THRESHOLD: u32 = 5;
const DEFAULT_CB_OPEN_DURATION_MS: u64 = 30_000; // 30 s
const DEFAULT_CB_SUCCESS_THRESHOLD: u32 = 3;

#[derive(Clone)]
pub struct TelemetrySender {
    cloud: SothHttpClient,
    endpoint_path: String,
    device_id_hash: String,
    signing_key: SigningKey,
    /// Shared across clones so all copies of a sender observe the same breaker state.
    circuit: Arc<CircuitBreaker>,
}

impl TelemetrySender {
    pub fn new(
        endpoint: impl Into<String>,
        api_key: impl Into<String>,
        endpoint_path: impl Into<String>,
        device_id_hash: impl Into<String>,
        telemetry_signing_key_hex: Option<String>,
        local_secret: &[u8],
    ) -> Result<Self> {
        let endpoint_path = normalize_endpoint_path(endpoint_path.into());
        let device_id_hash = normalize_device_id_hash(device_id_hash.into());
        let signing_key = build_signing_key(
            telemetry_signing_key_hex.as_deref(),
            device_id_hash.as_str(),
            local_secret,
        )?;
        Ok(Self {
            cloud: SothHttpClient::new(endpoint, api_key),
            endpoint_path,
            device_id_hash,
            signing_key,
            circuit: Arc::new(CircuitBreaker::new(
                DEFAULT_CB_FAILURE_THRESHOLD,
                DEFAULT_CB_OPEN_DURATION_MS,
                DEFAULT_CB_SUCCESS_THRESHOLD,
            )),
        })
    }

    pub async fn send_batch(&self, batch: &TransmittedBatch) -> TelemetrySendOutcome {
        if !self.circuit.allow_request() {
            tracing::debug!(
                state = self.circuit.state_label(),
                "telemetry circuit breaker open, skipping batch send"
            );
            return TelemetrySendOutcome::Retryable {
                reason: "telemetry circuit breaker open".to_string(),
            };
        }

        let request = match self.batch_to_request(batch) {
            Ok(request) => request,
            Err(error) => {
                // Serialization / key errors are non-retryable and should not
                // count as network failures against the circuit breaker.
                return TelemetrySendOutcome::NonRetryable {
                    reason: error.to_string(),
                };
            }
        };

        let response = self
            .cloud
            .post(self.endpoint_path.as_str())
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await;

        match response {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    self.circuit.record_success();
                    TelemetrySendOutcome::Sent
                } else if is_retryable_status(status) {
                    self.circuit.record_failure();
                    TelemetrySendOutcome::Retryable {
                        reason: format!("telemetry batch rejected with status {}", status.as_u16()),
                    }
                } else {
                    // Non-retryable HTTP errors (4xx auth/validation) should not
                    // penalise the circuit breaker — they indicate a protocol or
                    // configuration problem rather than an infra outage.
                    TelemetrySendOutcome::NonRetryable {
                        reason: format!("telemetry batch rejected with status {}", status.as_u16()),
                    }
                }
            }
            Err(error) => {
                if error.is_timeout() || error.is_connect() || error.is_request() || error.is_body()
                {
                    self.circuit.record_failure();
                    TelemetrySendOutcome::Retryable {
                        reason: error.to_string(),
                    }
                } else {
                    TelemetrySendOutcome::NonRetryable {
                        reason: error.to_string(),
                    }
                }
            }
        }
    }

    fn batch_to_request(&self, batch: &TransmittedBatch) -> Result<TelemetryBatchRequest> {
        let signed = match batch {
            TransmittedBatch::Signed(signed) => signed,
            TransmittedBatch::Encrypted(_) => {
                anyhow::bail!(
                    "encrypted telemetry batches are not supported for cloud /telemetry/batch"
                )
            }
        };
        self.signed_batch_to_request(signed)
    }

    fn signed_batch_to_request(&self, signed: &SignedBatch) -> Result<TelemetryBatchRequest> {
        let events = signed.batch.events.iter().map(map_event).collect();

        let mut request = TelemetryBatchRequest {
            batch_id: signed.batch.batch_id.to_string(),
            org_id: signed.batch.org_id.clone(),
            device_id_hash: self.device_id_hash.clone(),
            proxy_version: signed.batch.proxy_version.clone(),
            timestamp: signed.batch.timestamp_utc,
            events,
            proxy_signature: String::new(),
            observation_records: signed.batch.observation_records.clone(),
        };

        let signing_payload = TelemetrySigningPayload {
            batch_id: request.batch_id.as_str(),
            org_id: request.org_id.as_str(),
            device_id_hash: request.device_id_hash.as_str(),
            proxy_version: request.proxy_version.as_str(),
            timestamp: request.timestamp,
            events: request.events.as_slice(),
        };
        let message =
            serde_json::to_vec(&signing_payload).context("serialize telemetry signing payload")?;
        let signature = self.signing_key.sign(message.as_slice()).to_bytes();
        request.proxy_signature = BASE64_STANDARD.encode(signature);
        Ok(request)
    }
}

#[derive(serde::Serialize)]
struct TelemetrySigningPayload<'a> {
    batch_id: &'a str,
    org_id: &'a str,
    device_id_hash: &'a str,
    proxy_version: &'a str,
    timestamp: i64,
    events: &'a [TelemetryEvent],
}

fn map_event(event: &soth_core::TelemetryEvent) -> TelemetryEvent {
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
        // source_class: agent_app / browser / unknown
        let source_class = match pr.app_type {
            soth_core::AppType::NonHost => "agent_app",
            soth_core::AppType::Host => "browser",
            soth_core::AppType::Unknown => "unknown",
        };
        tags.insert("source_class".to_string(), source_class.to_string());

        // tool_identity_key: resolved app_id from detect bundle (e.g. "claude-code", "cursor")
        // Fallback chain: matched_app_id → process_name → bundle_id
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

        // Unified registry resolved fields (v6+).
        // Pre-resolved at edge so cloud can use directly without catalog lookup.
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

    // Connection intelligence tags (JA4 fingerprint, TLS metadata, H2 multiplexing)
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

    // Promote a one-time WARN when historian events bypass enrichment so we
    // can spot misconfig at the egress edge (soth-core can't log here).
    if matches!(
        event.use_case_label_reason,
        UseCaseLabelReason::HistorianNotEnriched
    ) {
        tracing::warn!(
            event_id = %event.event_id,
            "shipping historian event with use_case_label_reason=historian_not_enriched; \
             ClassifyEnricher likely failed or was skipped at ingest time"
        );
    }

    TelemetryEvent {
        event_id: event.event_id.to_string(),
        timestamp: event.timestamp_epoch_ms / 1_000,
        provider: Some(event.provider.clone()),
        model: event.model.clone(),
        use_case_label: enum_name(&event.use_case),
        use_case_label_reason: enum_name(&event.use_case_label_reason),
        // Tier A: previously dropped at egress. Only emit when classify
        // produced a confidence (>0) — keeps payload size small for the
        // many heuristic-parsed events that won't have a model output.
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
        // Was hardcoded `None` here; now flows through from the in-process
        // TelemetryEvent so any future upstream computation reaches the
        // wire payload without another mapping change.
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

fn normalize_device_id_hash(raw: String) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        "local-device".to_string()
    } else {
        trimmed.to_string()
    }
}

fn build_signing_key(
    telemetry_signing_key_hex: Option<&str>,
    device_id_hash: &str,
    local_secret: &[u8],
) -> Result<SigningKey> {
    let seed: Zeroizing<[u8; 32]> = match telemetry_signing_key_hex {
        Some(raw) if !raw.trim().is_empty() => Zeroizing::new(parse_signing_key_hex(raw)?),
        _ => derive_proxy_signing_seed(device_id_hash, local_secret),
    };
    Ok(SigningKey::from_bytes(&seed))
}

fn parse_signing_key_hex(raw: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(raw.trim()).context("telemetry signing key must be hex")?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "telemetry signing key must decode to exactly 32 bytes, got {}",
            bytes.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes.as_slice());
    Ok(out)
}

fn normalize_endpoint_path(raw: String) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "/v1/edge/telemetry/batch".to_string();
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_string();
    }
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    status.is_server_error()
        || status == reqwest::StatusCode::REQUEST_TIMEOUT
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status == reqwest::StatusCode::CONFLICT
        || status == reqwest::StatusCode::TOO_EARLY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_endpoint_path_defaults_for_empty() {
        assert_eq!(
            normalize_endpoint_path(String::new()),
            "/v1/edge/telemetry/batch"
        );
    }

    #[test]
    fn normalize_endpoint_path_adds_leading_slash() {
        assert_eq!(
            normalize_endpoint_path("v1/edge/telemetry/batch".to_string()),
            "/v1/edge/telemetry/batch"
        );
    }

    #[test]
    fn retryable_status_detection_matches_expected_set() {
        assert!(is_retryable_status(reqwest::StatusCode::TOO_MANY_REQUESTS));
        assert!(is_retryable_status(reqwest::StatusCode::BAD_GATEWAY));
        assert!(!is_retryable_status(reqwest::StatusCode::BAD_REQUEST));
        assert!(!is_retryable_status(reqwest::StatusCode::UNAUTHORIZED));
    }

    #[test]
    fn normalize_device_id_hash_applies_default() {
        assert_eq!(normalize_device_id_hash("".to_string()), "local-device");
        assert_eq!(
            normalize_device_id_hash(" device-1 ".to_string()),
            "device-1"
        );
    }

    #[test]
    fn map_event_exports_rich_detection_fields() {
        let mut event = soth_core::TelemetryEvent::default();
        event.provider = "openai".to_string();
        event.languages = vec![
            soth_core::ProgrammingLanguage::Rust,
            soth_core::ProgrammingLanguage::Python,
        ];
        event.import_categories = vec![
            soth_core::ImportCategory::Network,
            soth_core::ImportCategory::Filesystem,
            soth_core::ImportCategory::Auth,
        ];
        event.anomaly_flags = vec![
            soth_core::AnomalyFlag::CredentialBurst,
            soth_core::AnomalyFlag::TopicDrift,
        ];
        event.sensitive_code_flags.credential_pattern_detected = true;
        event.sensitive_code_flags.auth_logic_detected = true;
        event.sensitive_code_flags.crypto_operations_detected = true;
        event.sensitive_code_flags.network_calls_detected = true;
        event.sensitive_code_flags.file_io_detected = true;
        event.sensitive_code_flags.private_key_detected = true;
        event.sensitive_code_flags.hardcoded_secret_detected = true;
        event.sensitive_code_flags.org_pattern_matches = vec!["0".to_string(), "4".to_string()];
        event.sensitive_code_flags.detected_secret_types = vec![
            "github_pat".to_string(),
            "postgres_connection_string".to_string(),
        ];

        let mapped = map_event(&event);

        assert_eq!(
            mapped.detected_credential_types,
            vec![
                "github_pat".to_string(),
                "postgres_connection_string".to_string()
            ]
        );
        assert_eq!(
            mapped.detected_secret_types,
            Some(vec![
                "github_pat".to_string(),
                "postgres_connection_string".to_string()
            ])
        );
        assert_eq!(
            mapped.languages,
            vec!["rust".to_string(), "python".to_string()]
        );
        assert_eq!(
            mapped.import_categories,
            vec![
                "network".to_string(),
                "filesystem".to_string(),
                "auth".to_string()
            ]
        );
        assert_eq!(mapped.auth_logic_detected, Some(true));
        assert_eq!(mapped.crypto_operations_detected, Some(true));
        assert_eq!(mapped.network_calls_detected, Some(true));
        assert_eq!(mapped.file_io_detected, Some(true));
        assert_eq!(mapped.private_key_detected, Some(true));
        assert_eq!(mapped.hardcoded_secret_detected, Some(true));
        assert_eq!(
            mapped.org_pattern_matches,
            vec!["0".to_string(), "4".to_string()]
        );
        assert_eq!(
            mapped.anomaly_flags,
            vec!["credential_burst".to_string(), "topic_drift".to_string()]
        );
    }
}
