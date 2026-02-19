//! Shared API request/response structures for edge <-> cloud communication.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeBatchRequest {
    pub agent_instance_id: String,
    pub config_version: Option<String>,
    pub batch: Vec<ExchangeMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeMetadata {
    pub exchange_id: String,
    pub schema_version: String,
    pub session_id: Option<String>,
    pub observed_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub ttfb_ms: Option<u64>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub source_class: String,
    pub transport: String,
    pub provider: Option<String>,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub endpoint: Option<String>,
    pub method: Option<String>,
    pub status_code: Option<u16>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cache_read_tokens: Option<u64>,
    pub cache_write_tokens: Option<u64>,
    pub reasoning_tokens: Option<u64>,
    pub cost_usd: Option<f64>,
    pub cost_currency: Option<String>,
    pub pricing_version: Option<String>,
    pub request_size_bytes: Option<u64>,
    pub response_size_bytes: Option<u64>,
    pub request_body_mode: Option<String>,
    pub response_body_mode: Option<String>,
    pub request_body_ref: Option<String>,
    pub response_body_ref: Option<String>,
    pub request_body_sha256: Option<String>,
    pub response_body_sha256: Option<String>,
    pub request_body_preview: Option<String>,
    pub response_body_preview: Option<String>,
    pub request_truncated_reason: Option<String>,
    pub response_truncated_reason: Option<String>,
    pub truncated: bool,
    pub metadata_only: bool,
    pub discovery_capture: bool,
    pub blacklist_match: bool,
    pub pii_detected: bool,
    pub pii_types: Vec<String>,
    pub policy_allowed: Option<bool>,
    pub policy_version: Option<String>,
    pub mcp_tool_name: Option<String>,
    pub graphql_operation: Option<String>,
    pub event_hash: Option<String>,
    pub signature: Option<String>,
    pub signature_key_id: Option<String>,
    pub parser_version: Option<String>,
    pub bundle_version: Option<String>,
    pub parse_confidence: Option<f64>,
    pub detection_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_step: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_app_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_host_origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_referrer_origin: Option<String>,
    pub tags: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_envelope: Option<EventEnvelopeMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventClientMetadata {
    pub pid: Option<u32>,
    pub bundle_id: Option<String>,
    pub process_name: Option<String>,
    pub process_executable: Option<String>,
    pub app_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referrer_origin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelopeMetadata {
    pub envelope_id: Option<String>,
    pub request_id: Option<String>,
    pub capture_source: Option<String>,
    pub source: Option<String>,
    pub captured_at: Option<String>,
    pub method: Option<String>,
    pub provider: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub model: Option<String>,
    pub agent: Option<String>,
    pub did: Option<String>,
    pub key_id: Option<String>,
    pub signature_alg: Option<String>,
    pub signed_fields_version: Option<String>,
    pub signature: Option<String>,
    pub body_hash: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub client: Option<EventClientMetadata>,
    pub collector_source: Option<String>,
    pub collector_offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeBatchResponse {
    pub accepted: u64,
    pub rejected: u64,
    pub errors: Vec<EventError>,
    #[serde(default)]
    pub retry_after_secs: Option<u64>,
    pub config_changed: bool,
    pub server_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventError {
    pub event_id: String,
    pub reason: String,
    #[serde(default)]
    pub code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyUploadResponse {
    pub stored: bool,
    pub request_key: Option<String>,
    pub response_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobUploadRequest {
    pub exchange_id: String,
    pub side: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    pub content_encoding: Option<String>,
    pub content_type: Option<String>,
    pub sha256: Option<String>,
    pub bytes_raw: Option<u64>,
    pub bytes_gzip: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_gzip_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobUploadResponse {
    pub stored: bool,
    #[serde(default)]
    pub blob_key: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigResponse {
    pub user: ConfigUser,
    pub team: ConfigTeam,
    pub org: ConfigOrg,
    pub policies: Vec<ConfigPolicy>,
    pub budget: ConfigBudget,
    pub body_sync_level: String,
    pub config_version: String,
    #[serde(default)]
    pub bundle_version: Option<String>,
    #[serde(default)]
    pub registry_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryVersionResponse {
    pub bundle_type: String,
    pub version: String,
    pub sha256: String,
    pub compiled_at: String,
    pub provider_count: u64,
    pub domain_count: u64,
    pub format_count: u64,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigUser {
    pub id: String,
    pub name: String,
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigTeam {
    pub id: String,
    pub name: String,
    pub slug: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigOrg {
    pub id: String,
    pub name: String,
    pub plan: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigPolicy {
    pub name: String,
    pub scope: String,
    pub rego: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigBudget {
    pub enforcement: String,
    pub limits: Vec<ConfigBudgetLimit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigBudgetLimit {
    pub scope: String,
    pub model: Option<String>,
    pub daily_usd: Option<f64>,
    pub weekly_usd: Option<f64>,
    pub monthly_usd: Option<f64>,
    pub remaining_usd: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub agent_instance_id: String,
    pub proxy_version: String,
    pub config_version: Option<String>,
    pub os: Option<String>,
    pub hostname: Option<String>,
    pub active_connections: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_details: Option<HeartbeatHostDetails>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry: Option<HeartbeatTelemetry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub ok: bool,
    pub config_changed: bool,
    pub server_time: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeartbeatTelemetry {
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub counters: std::collections::BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeartbeatHostDetails {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_logical_cores: Option<u64>,
}

// ============================================================================
// Edge Enrollment (Fleet bootstrap)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollExchangeRequest {
    pub enroll_token: String,
    pub machine_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<EnrollExchangeClient>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollExchangeClient {
    pub hostname: Option<String>,
    pub platform: Option<String>,
    pub arch: Option<String>,
    pub soth_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollExchangeResponse {
    pub success: bool,
    pub data: EnrollExchangeData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollExchangeData {
    pub api_key: String,
    pub endpoint: String,
    /// Workspace scope hint for edge; currently set to team_id by cloud.
    pub workspace_id: String,
    #[serde(default)]
    pub tags: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_exchange_roundtrip() {
        let request = EnrollExchangeRequest {
            enroll_token: "enroll_live_abc123".to_string(),
            machine_name: Some("devbox".to_string()),
            client: Some(EnrollExchangeClient {
                hostname: Some("devbox".to_string()),
                platform: Some("macos".to_string()),
                arch: Some("arm64".to_string()),
                soth_version: Some("0.1.0".to_string()),
                device_id: Some("device_123".to_string()),
            }),
        };

        let json = serde_json::to_string(&request).expect("serialize enroll request");
        let parsed: EnrollExchangeRequest =
            serde_json::from_str(&json).expect("deserialize enroll request");
        assert_eq!(parsed.enroll_token, "enroll_live_abc123");

        let response = EnrollExchangeResponse {
            success: true,
            data: EnrollExchangeData {
                api_key: "soth_live_team_abcdef0123456789abcdef0123456789".to_string(),
                endpoint: "https://api.soth.ai".to_string(),
                workspace_id: "team_123".to_string(),
                tags: HashMap::from([("workspace_id".to_string(), "team_123".to_string())]),
                device_id: Some("device_123".to_string()),
            },
        };

        let json = serde_json::to_string(&response).expect("serialize enroll response");
        let parsed: EnrollExchangeResponse =
            serde_json::from_str(&json).expect("deserialize enroll response");
        assert!(parsed.success);
        assert_eq!(parsed.data.workspace_id, "team_123");
    }

    #[test]
    fn exchange_batch_roundtrip() {
        let req = ExchangeBatchRequest {
            agent_instance_id: "agent-1".to_string(),
            config_version: Some("v2".to_string()),
            batch: vec![ExchangeMetadata {
                exchange_id: "ex-1".to_string(),
                schema_version: "2.0".to_string(),
                session_id: Some("sess-1".to_string()),
                observed_at: "2026-02-01T00:00:00Z".to_string(),
                started_at: Some("2026-02-01T00:00:00Z".to_string()),
                completed_at: Some("2026-02-01T00:00:01Z".to_string()),
                duration_ms: Some(1000),
                ttfb_ms: Some(120),
                trace_id: Some("trace-1".to_string()),
                span_id: Some("span-1".to_string()),
                parent_span_id: None,
                source_class: "ai_inference".to_string(),
                transport: "https".to_string(),
                provider: Some("openai".to_string()),
                agent: Some("codex".to_string()),
                model: Some("gpt-5.3-codex".to_string()),
                endpoint: Some("/v1/responses".to_string()),
                method: Some("POST".to_string()),
                status_code: Some(200),
                input_tokens: Some(12),
                output_tokens: Some(34),
                cache_read_tokens: Some(0),
                cache_write_tokens: Some(0),
                reasoning_tokens: Some(3),
                cost_usd: Some(0.02),
                cost_currency: Some("USD".to_string()),
                pricing_version: Some("bundle-1".to_string()),
                request_size_bytes: Some(1024),
                response_size_bytes: Some(4096),
                request_body_mode: Some("inline".to_string()),
                response_body_mode: Some("offloaded".to_string()),
                request_body_ref: None,
                response_body_ref: Some("blob://resp/1".to_string()),
                request_body_sha256: None,
                response_body_sha256: Some("abc".to_string()),
                request_body_preview: None,
                response_body_preview: None,
                request_truncated_reason: None,
                response_truncated_reason: None,
                truncated: false,
                metadata_only: false,
                discovery_capture: false,
                blacklist_match: false,
                pii_detected: false,
                pii_types: vec![],
                policy_allowed: None,
                policy_version: None,
                mcp_tool_name: None,
                graphql_operation: None,
                event_hash: Some("hash".to_string()),
                signature: None,
                signature_key_id: None,
                parser_version: Some("v1".to_string()),
                bundle_version: Some("bundle-1".to_string()),
                parse_confidence: Some(0.98),
                detection_reason: Some("model_marker".to_string()),
                target_entity_id: Some("agt_abc123".to_string()),
                detection_source: Some("bundle".to_string()),
                tags: None,
                event_envelope: None,
            }],
        };

        let json = serde_json::to_string(&req).expect("serialize exchange batch");
        let parsed: ExchangeBatchRequest =
            serde_json::from_str(&json).expect("deserialize exchange batch");
        assert_eq!(parsed.agent_instance_id, "agent-1");
        assert_eq!(parsed.batch.len(), 1);
        assert_eq!(parsed.batch[0].exchange_id, "ex-1");
        assert_eq!(parsed.batch[0].transport, "https");
    }
}
