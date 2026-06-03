use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use soth_api_types::convert::map_event;
use soth_core::{derive_proxy_signing_seed, UseCaseLabelReason};
use soth_telemetry::{SignedBatch, TransmittedBatch};
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
        // Mirror the extension-not-enriched WARN that used to sit
        // inside `map_event`. It lives at the call site so the shared
        // `soth-api-types` crate stays free of a `tracing` dep.
        // Generalised from "historian event" to "extension event" once
        // soth-code became the second extension producing
        // GovernableEvents — message now identifies the source via the
        // event's data_source rather than assuming historian.
        for event in &signed.batch.events {
            if matches!(
                event.use_case_label_reason,
                UseCaseLabelReason::ExtensionNotEnriched
            ) {
                tracing::warn!(
                    event_id = %event.event_id,
                    data_source = ?event.data_source,
                    "shipping extension event with use_case_label_reason=extension_not_enriched; \
                     write-time enrichment likely failed or was skipped"
                );
            }
        }

        let events = signed.batch.events.iter().map(map_event).collect();

        // `soth-api-types::TelemetryBatchRequest.observation_records` is
        // `Option<Vec<serde_json::Value>>` so the shared crate doesn't
        // pull in `soth-telemetry`. We serialize the typed records here.
        let observation_records = signed.batch.observation_records.as_ref().map(|records| {
            records
                .iter()
                .filter_map(|r| serde_json::to_value(r).ok())
                .collect::<Vec<_>>()
        });

        let mut request = TelemetryBatchRequest {
            batch_id: signed.batch.batch_id.to_string(),
            org_id: signed.batch.org_id.clone(),
            device_id_hash: self.device_id_hash.clone(),
            proxy_version: signed.batch.proxy_version.clone(),
            timestamp: signed.batch.timestamp_utc,
            events,
            proxy_signature: String::new(),
            observation_records,
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

    // Many-field test fixture; struct-update would push this into a
    // single 30-field expression and hurt readability.
    #[allow(clippy::field_reassign_with_default)]
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
