use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use soth_core::{derive_proxy_signing_seed, ClassificationFlag, TelemetryPolicyKind};
use soth_telemetry::{SignedBatch, TransmittedBatch};
use std::collections::HashMap;

use crate::api_types::{TelemetryBatchRequest, TelemetryEvent};
use crate::http_client::SothHttpClient;

#[derive(Debug, Clone)]
pub enum TelemetrySendOutcome {
    Sent,
    Retryable { reason: String },
    NonRetryable { reason: String },
}

#[derive(Clone)]
pub struct TelemetrySender {
    cloud: SothHttpClient,
    endpoint_path: String,
    device_id_hash: String,
    signing_key: SigningKey,
}

impl TelemetrySender {
    pub fn new(
        endpoint: impl Into<String>,
        api_key: impl Into<String>,
        endpoint_path: impl Into<String>,
        device_id_hash: impl Into<String>,
        telemetry_signing_key_hex: Option<String>,
    ) -> Result<Self> {
        let endpoint_path = normalize_endpoint_path(endpoint_path.into());
        let device_id_hash = normalize_device_id_hash(device_id_hash.into());
        let signing_key = build_signing_key(
            telemetry_signing_key_hex.as_deref(),
            device_id_hash.as_str(),
        )?;
        Ok(Self {
            cloud: SothHttpClient::new(endpoint, api_key),
            endpoint_path,
            device_id_hash,
            signing_key,
        })
    }

    pub async fn send_batch(&self, batch: &TransmittedBatch) -> TelemetrySendOutcome {
        let request = match self.batch_to_request(batch) {
            Ok(request) => request,
            Err(error) => {
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
                    TelemetrySendOutcome::Sent
                } else if is_retryable_status(status) {
                    TelemetrySendOutcome::Retryable {
                        reason: format!("telemetry batch rejected with status {}", status.as_u16()),
                    }
                } else {
                    TelemetrySendOutcome::NonRetryable {
                        reason: format!("telemetry batch rejected with status {}", status.as_u16()),
                    }
                }
            }
            Err(error) => {
                if error.is_timeout() || error.is_connect() || error.is_request() || error.is_body()
                {
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

    TelemetryEvent {
        event_id: event.event_id.to_string(),
        timestamp: event.timestamp_epoch_ms / 1_000,
        provider: Some(event.provider.canonical_name().to_string()),
        model: event.model.clone(),
        use_case_label: enum_name(&event.use_case),
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
        collision_response_stability: None,
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
        is_prefix_repeat: if event.is_prefix_repeat { Some(true) } else { None },
        is_code_context_repeat: if event.is_code_context_repeat { Some(true) } else { None },
        novel_token_count: if event.novel_token_count > 0 { Some(u64::from(event.novel_token_count)) } else { None },
        repeated_token_count: if event.repeated_token_count > 0 { Some(u64::from(event.repeated_token_count)) } else { None },
        first_step_event_id: event.first_step_event_id.clone(),
        original_event_id: event.original_event_id.clone(),
        data_source: enum_name(&event.data_source),
    }
}

fn enum_name<T: serde::Serialize>(value: &T) -> Option<String> {
    match serde_json::to_value(value).ok()? {
        serde_json::Value::String(value) => Some(value),
        _ => None,
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
) -> Result<SigningKey> {
    let seed = match telemetry_signing_key_hex {
        Some(raw) if !raw.trim().is_empty() => parse_signing_key_hex(raw)?,
        _ => derive_proxy_signing_seed(device_id_hash),
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
}
