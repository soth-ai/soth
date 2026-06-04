//! Shared API request/response structures for sync <-> cloud communication.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// Header used for API version negotiation between edge and cloud.
pub const API_VERSION_HEADER: &str = "X-Soth-Api-Version";

/// Current API version expected by edge and cloud.
pub const API_VERSION: &str = "2026-02-01";

/// Compatibility submodule to preserve existing call sites.
pub mod version {
    pub use super::{API_VERSION, API_VERSION_HEADER};
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_is_synthetic: Option<bool>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection_bundle_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_identity_key: Option<String>,
    pub status_code: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_device_id: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_status: Option<String>,
    pub signature: Option<String>,
    pub signature_key_id: Option<String>,
    pub parser_version: Option<String>,
    pub bundle_version: Option<String>,
    pub parse_confidence: Option<f64>,
    pub detection_reason: Option<String>,
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
    pub device_id: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_hash: Option<String>,
    pub compiled_at: String,
    #[serde(alias = "provider_count")]
    pub llm_provider_count: u64,
    pub domain_count: u64,
    pub format_count: u64,
    pub size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<RegistryBundleManifest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryBundleManifest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_from: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<RegistryBundleComponentHash>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub changed_sections: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<RegistryBundleIntegrity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryBundleComponentHash {
    pub name: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryBundleIntegrity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

#[derive(Debug, Clone)]
pub enum RegistryBundleFetchQuery {
    Full,
    Section {
        section: String,
    },
    Diff {
        from_hash: String,
        section: Option<String>,
    },
}

impl Default for RegistryBundleFetchQuery {
    fn default() -> Self {
        Self::Full
    }
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
    pub registry: Option<HeartbeatRegistryDetails>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry: Option<HeartbeatTelemetry>,
    /// Phase 4 client-side counter of consecutive failed `--apply` attempts.
    /// Reset to 0 on a successful apply. Server upserts this into
    /// `agent_instances.consecutive_update_failures`; the heartbeat
    /// resolver uses it to back off after the 3-strike cutoff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consecutive_update_failures: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub ok: bool,
    pub config_changed: bool,
    pub server_time: String,
    /// Phase 2 hot-update: server-pushed offer when this device has a
    /// new release waiting on its channel. `None` = up-to-date or no
    /// matching channel/release combo. Always `#[serde(default)]` so
    /// 0.1.1 servers (which don't emit this field) deserialize cleanly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_available: Option<UpdateAvailable>,
}

/// Hot-update offer carried on `HeartbeatResponse`. Phase 2.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateAvailable {
    /// Target version (semver, e.g. "0.1.2").
    pub version: String,
    /// Monotonic per-channel sequence — used by clients for the anti-
    /// rollback gate even when the offer arrives via heartbeat.
    pub release_seq: u64,
    /// Direct download URL for this device's platform binary.
    pub url: String,
    /// sha256 the downloaded binary must match (lowercase hex).
    pub sha256: String,
    /// How aggressive the client should be about applying. Phase 4
    /// auto-applier reads this; Phase 2/3 just persist+display.
    pub urgency: UpdateUrgency,
    /// Optional URL the client can show users for this release's notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_notes_url: Option<String>,
    /// Earliest RFC3339 instant the client should auto-apply. Honored
    /// by the Phase 4 auto-applier; ignored by manual `soth update`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply_after: Option<String>,
}

/// Urgency hint on the heartbeat offer.
/// - `Notify`: log only; user-driven update.
/// - `Recommended`: surface in `soth status`; user-driven update.
/// - `Forced`: Phase 4 auto-applies within minutes (subject to
///   `apply_after` and the per-channel update window).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateUrgency {
    Notify,
    #[default]
    Recommended,
    Forced,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeartbeatTelemetry {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub counters: BTreeMap<String, u64>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_total_mb: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeartbeatRegistryDetails {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetched_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_age_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_failed_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded_stale: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryBatchRequest {
    pub batch_id: String,
    pub org_id: String,
    pub device_id_hash: String,
    pub proxy_version: String,
    pub timestamp: i64,
    pub events: Vec<TelemetryEvent>,
    pub proxy_signature: String,
    /// Observation records from passive observer extensions.
    /// Omitted when empty for backward compatibility.
    ///
    /// Stored as raw `serde_json::Value` so this crate stays free of
    /// the `soth-telemetry` dep (and its rusqlite/tokio transitive
    /// closure). The proxy serializes its typed
    /// `soth_telemetry::ObservationTelemetryRecord` values into Values
    /// at the call site; the SDK doesn't emit observations so it
    /// always passes `None`. JSON wire shape is identical either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_records: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub event_id: String,
    pub timestamp: i64,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub use_case_label: Option<String>,
    /// Why `use_case_label` has its current value. See
    /// `soth_core::UseCaseLabelReason`. Serialized as snake_case string.
    /// Skipped when omitted to keep older receivers backwards-compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_case_label_reason: Option<String>,
    /// Top-1 model confidence in [0, 1]. None when not classified
    /// (e.g. embedding skipped, fallback bundle). Lets the cloud filter
    /// "uncertain" classifications and surface them for human review.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_case_confidence: Option<f32>,
    /// Second-most-likely label when top-1 confidence < 0.40 — surfaces
    /// multi-intent prompts the cloud can't currently see.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary_label: Option<String>,
    pub topic_cluster_id: Option<String>,
    pub semantic_hash: Option<String>,
    #[serde(default)]
    pub is_semantic_collision: bool,
    pub collision_response_stability: Option<f64>,
    pub anomaly_score: Option<f64>,
    pub volatility_class: Option<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub estimated_cost_usd: Option<f64>,
    pub policy_decision: Option<String>,
    pub policy_rule_id: Option<String>,
    pub redaction_event: Option<bool>,
    pub credential_pattern_detected: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detected_secret_types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detected_credential_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub languages: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub import_categories: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_logic_detected: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto_operations_detected: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_calls_detected: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_io_detected: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_detected: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardcoded_secret_detected: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub org_pattern_matches: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anomaly_flags: Vec<String>,
    pub endpoint_hash: Option<String>,
    pub code_fraction: Option<f64>,
    #[serde(default)]
    pub tags: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_key_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_prefix_repeat: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_code_context_repeat: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub novel_token_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repeated_token_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_step_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_source: Option<String>,

    // Caching intelligence fields
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_fraction: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_prompt_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_definition_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_repeat_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub complexity_score: Option<u8>,

    // Response-side fields (populated when response data is available)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_output_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_latency_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttfb_ms: Option<u64>,

    // Session metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_request_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_total_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_credential_alerts: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_turn: Option<u32>,

    // WebSocket turn number
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_turn_number: Option<u64>,

    // Product/Session taxonomy (v7+)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_shadow_it: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interaction_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryBatchResponse {
    pub accepted: u64,
    pub rejected: u64,
    pub errors: Vec<TelemetryBatchError>,
    pub config_changed: bool,
    pub server_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryBatchError {
    pub event_id: String,
    pub reason: String,
}
