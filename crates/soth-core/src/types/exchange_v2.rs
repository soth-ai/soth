//! Unified exchange event schema.
//!
//! This models a single finalized request/response exchange as one event.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Canonical exchange schema version.
pub const EXCHANGE_SCHEMA_VERSION: &str = "1";
/// Backward-compat alias while callsites still reference "v2" naming.
pub const EXCHANGE_SCHEMA_VERSION_V2: &str = EXCHANGE_SCHEMA_VERSION;

pub const EXCHANGE_CLIENT_APP_TYPE_HOST: &str = "host";
pub const EXCHANGE_CLIENT_APP_TYPE_NON_HOST: &str = "non_host";
pub const EXCHANGE_CLIENT_APP_TYPES: &[&str] = &[
    EXCHANGE_CLIENT_APP_TYPE_HOST,
    EXCHANGE_CLIENT_APP_TYPE_NON_HOST,
];

pub const EXCHANGE_DECISION_STEP_APP_GATE: &str = "step0_app_gate";
pub const EXCHANGE_DECISION_STEP_WHITELIST: &str = "step1_whitelist";
pub const EXCHANGE_DECISION_STEP_URL_BLACKLIST: &str = "step2_url_blacklist";
pub const EXCHANGE_DECISION_STEP_GRAPHQL_BLACKLIST: &str = "step3_graphql_blacklist";
pub const EXCHANGE_DECISION_STEP_APP_ORIGIN: &str = "step4_app_origin";
pub const EXCHANGE_DECISION_STEP_HOST_ORIGIN: &str = "step5_host_origin";
pub const EXCHANGE_DECISION_STEPS: &[&str] = &[
    EXCHANGE_DECISION_STEP_APP_GATE,
    EXCHANGE_DECISION_STEP_WHITELIST,
    EXCHANGE_DECISION_STEP_URL_BLACKLIST,
    EXCHANGE_DECISION_STEP_GRAPHQL_BLACKLIST,
    EXCHANGE_DECISION_STEP_APP_ORIGIN,
    EXCHANGE_DECISION_STEP_HOST_ORIGIN,
];

pub const EXCHANGE_DECISION_OUTCOME_CAPTURED: &str = "captured";
pub const EXCHANGE_DECISION_OUTCOME_SKIPPED: &str = "skipped";
pub const EXCHANGE_DECISION_OUTCOME_DISCOVERY_CAPTURE: &str = "discovery_capture";
pub const EXCHANGE_DECISION_OUTCOME_METADATA_ONLY: &str = "metadata_only";
pub const EXCHANGE_DECISION_OUTCOMES: &[&str] = &[
    EXCHANGE_DECISION_OUTCOME_CAPTURED,
    EXCHANGE_DECISION_OUTCOME_SKIPPED,
    EXCHANGE_DECISION_OUTCOME_DISCOVERY_CAPTURE,
    EXCHANGE_DECISION_OUTCOME_METADATA_ONLY,
];

pub const EXCHANGE_SKIP_REASON_NO_BUNDLE_ID: &str = "no_bundle_id";
pub const EXCHANGE_SKIP_REASON_APP_NOT_ALLOWED: &str = "app_not_allowed";
pub const EXCHANGE_SKIP_REASON_APP_RATE_LIMITED: &str = "app_rate_limited";
pub const EXCHANGE_SKIP_REASON_DOMAIN_RATE_LIMITED: &str = "domain_rate_limited";
pub const EXCHANGE_SKIP_REASON_NOT_WHITELISTED: &str = "not_whitelisted";
pub const EXCHANGE_SKIP_REASON_BLACKLISTED: &str = "blacklisted";
pub const EXCHANGE_SKIP_REASON_BLACKLISTED_GRAPHQL: &str = "blacklisted_graphql";
pub const EXCHANGE_SKIP_REASON_HOST_ORIGIN_NOT_ALLOWED: &str = "host_origin_not_allowed";
pub const EXCHANGE_SKIP_REASONS: &[&str] = &[
    EXCHANGE_SKIP_REASON_NO_BUNDLE_ID,
    EXCHANGE_SKIP_REASON_APP_NOT_ALLOWED,
    EXCHANGE_SKIP_REASON_APP_RATE_LIMITED,
    EXCHANGE_SKIP_REASON_DOMAIN_RATE_LIMITED,
    EXCHANGE_SKIP_REASON_NOT_WHITELISTED,
    EXCHANGE_SKIP_REASON_BLACKLISTED,
    EXCHANGE_SKIP_REASON_BLACKLISTED_GRAPHQL,
    EXCHANGE_SKIP_REASON_HOST_ORIGIN_NOT_ALLOWED,
];

pub const EXCHANGE_DISCOVERY_KIND_CATALOG: &str = "catalog";
pub const EXCHANGE_DISCOVERY_KIND_APP: &str = "app";
pub const EXCHANGE_DISCOVERY_KIND_DOMAIN: &str = "domain";
pub const EXCHANGE_DISCOVERY_KINDS: &[&str] = &[
    EXCHANGE_DISCOVERY_KIND_CATALOG,
    EXCHANGE_DISCOVERY_KIND_APP,
    EXCHANGE_DISCOVERY_KIND_DOMAIN,
];

pub const EXCHANGE_INTEGRITY_STATUS_NONE: &str = "none";
pub const EXCHANGE_INTEGRITY_STATUS_SIGNED: &str = "signed";
pub const EXCHANGE_INTEGRITY_STATUS_MERKLE_PROVEN: &str = "merkle_proven";
pub const EXCHANGE_INTEGRITY_STATUS_ANCHORED: &str = "anchored";
pub const EXCHANGE_INTEGRITY_STATUS_FAILED: &str = "failed";
pub const EXCHANGE_INTEGRITY_STATUSES: &[&str] = &[
    EXCHANGE_INTEGRITY_STATUS_NONE,
    EXCHANGE_INTEGRITY_STATUS_SIGNED,
    EXCHANGE_INTEGRITY_STATUS_MERKLE_PROVEN,
    EXCHANGE_INTEGRITY_STATUS_ANCHORED,
    EXCHANGE_INTEGRITY_STATUS_FAILED,
];

pub const EXCHANGE_INTEGRITY_ANCHOR_STATUS_PENDING: &str = "pending";
pub const EXCHANGE_INTEGRITY_ANCHOR_STATUS_CONFIRMED: &str = "confirmed";
pub const EXCHANGE_INTEGRITY_ANCHOR_STATUS_FAILED: &str = "failed";
pub const EXCHANGE_INTEGRITY_ANCHOR_STATUSES: &[&str] = &[
    EXCHANGE_INTEGRITY_ANCHOR_STATUS_PENDING,
    EXCHANGE_INTEGRITY_ANCHOR_STATUS_CONFIRMED,
    EXCHANGE_INTEGRITY_ANCHOR_STATUS_FAILED,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExchangeSourceClass {
    AiInference,
    AgentApp,
    Mcp,
    Collector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExchangeTransport {
    Http,
    Https,
    Ws,
    Sse,
    Ndjson,
    Stdio,
    Jsonrpc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExchangeBodyMode {
    Inline,
    Offloaded,
    PreviewOnly,
    MetadataOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeClient {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referrer_origin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeBody {
    pub mode: ExchangeBodyMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inline: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_raw: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_gzip: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeSide {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<BTreeMap<String, String>>,
    pub body: ExchangeBody,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExchangeUsage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_read_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_write_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_tokens: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeCost {
    pub estimated_usd: f64,
    pub currency: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pricing_version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExchangeFlags {
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub metadata_only: bool,
    #[serde(default)]
    pub discovery_capture: bool,
    #[serde(default)]
    pub blacklist_match: bool,
    #[serde(default)]
    pub pii_detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeIntegrity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_form: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_log_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub siblings: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_chain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_block_number: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_block_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_confirmed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeParse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection_bundle_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parser_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_confidence: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_step: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_kind: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeEventV2 {
    pub schema_version: String,
    pub exchange_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edge_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_is_synthetic: Option<bool>,
    pub observed_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttfb_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    pub source_class: ExchangeSourceClass,
    pub transport: ExchangeTransport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection_bundle_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_identity_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<ExchangeClient>,
    pub request: ExchangeSide,
    pub response: ExchangeSide,
    #[serde(default)]
    pub usage: ExchangeUsage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<ExchangeCost>,
    #[serde(default)]
    pub flags: ExchangeFlags,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pii_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity: Option<ExchangeIntegrity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse: Option<ExchangeParse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
}

impl ExchangeEventV2 {
    pub fn new(
        exchange_id: impl Into<String>,
        source_class: ExchangeSourceClass,
        transport: ExchangeTransport,
        request_mode: ExchangeBodyMode,
        response_mode: ExchangeBodyMode,
    ) -> Self {
        Self {
            schema_version: EXCHANGE_SCHEMA_VERSION.to_string(),
            exchange_id: exchange_id.into(),
            session_id: None,
            edge_session_id: None,
            provider_session_id: None,
            session_is_synthetic: None,
            observed_at: Utc::now(),
            started_at: None,
            completed_at: None,
            duration_ms: None,
            ttfb_ms: None,
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            source_class,
            transport,
            provider: None,
            agent: None,
            model: None,
            endpoint: None,
            method: None,
            detection_id: None,
            detection_bundle_version: None,
            tool_identity_key: None,
            status_code: None,
            client_device_id: None,
            client: None,
            request: ExchangeSide {
                headers: None,
                body: ExchangeBody {
                    mode: request_mode,
                    inline: None,
                    reference: None,
                    preview: None,
                    bytes_raw: None,
                    bytes_gzip: None,
                    sha256: None,
                    content_type: None,
                    truncated_reason: None,
                },
            },
            response: ExchangeSide {
                headers: None,
                body: ExchangeBody {
                    mode: response_mode,
                    inline: None,
                    reference: None,
                    preview: None,
                    bytes_raw: None,
                    bytes_gzip: None,
                    sha256: None,
                    content_type: None,
                    truncated_reason: None,
                },
            },
            usage: ExchangeUsage::default(),
            cost: None,
            flags: ExchangeFlags::default(),
            pii_types: Vec::new(),
            integrity: None,
            parse: None,
            tags: None,
        }
    }

    pub fn effective_detection_id(&self) -> Option<&str> {
        self.detection_id.as_deref().or_else(|| {
            self.parse
                .as_ref()
                .and_then(|parse| parse.detection_id.as_deref())
        })
    }

    pub fn effective_detection_bundle_version(&self) -> Option<&str> {
        self.detection_bundle_version.as_deref().or_else(|| {
            self.parse.as_ref().and_then(|parse| {
                parse
                    .detection_bundle_version
                    .as_deref()
                    .or(parse.bundle_version.as_deref())
            })
        })
    }

    /// Validates required detection fields for proxy-generated events.
    /// Collector-only events are exempt.
    pub fn validate_proxy_detection_contract(&self) -> Result<(), Vec<&'static str>> {
        if matches!(self.source_class, ExchangeSourceClass::Collector) {
            return Ok(());
        }
        let mut missing = Vec::new();
        if self
            .effective_detection_id()
            .map(|value| value.trim().is_empty())
            .unwrap_or(true)
        {
            missing.push("detection_id");
        }
        if self
            .effective_detection_bundle_version()
            .map(|value| value.trim().is_empty())
            .unwrap_or(true)
        {
            missing.push("detection_bundle_version");
        }
        if missing.is_empty() {
            Ok(())
        } else {
            Err(missing)
        }
    }
}

/// Canonical type name moving forward.
pub type Exchange = ExchangeEventV2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exchange_v2_roundtrip() {
        let event = ExchangeEventV2::new(
            "ex_123",
            ExchangeSourceClass::AiInference,
            ExchangeTransport::Https,
            ExchangeBodyMode::Inline,
            ExchangeBodyMode::Offloaded,
        );
        let raw = serde_json::to_string(&event).expect("serialize exchange");
        let parsed: ExchangeEventV2 = serde_json::from_str(&raw).expect("deserialize exchange");
        assert_eq!(parsed.schema_version, EXCHANGE_SCHEMA_VERSION);
        assert_eq!(parsed.exchange_id, "ex_123");
        assert_eq!(parsed.request.body.mode, ExchangeBodyMode::Inline);
        assert_eq!(parsed.response.body.mode, ExchangeBodyMode::Offloaded);
    }

    #[test]
    fn validate_proxy_detection_contract_requires_detection_fields() {
        let mut event = ExchangeEventV2::new(
            "ex_123",
            ExchangeSourceClass::AiInference,
            ExchangeTransport::Https,
            ExchangeBodyMode::MetadataOnly,
            ExchangeBodyMode::MetadataOnly,
        );
        let missing = event
            .validate_proxy_detection_contract()
            .expect_err("detection fields should be required");
        assert_eq!(missing, vec!["detection_id", "detection_bundle_version"]);

        event.detection_id = Some("claude-desktop".to_string());
        event.detection_bundle_version = Some("2026.02.19".to_string());
        event
            .validate_proxy_detection_contract()
            .expect("detection fields present");
    }

    #[test]
    fn validate_proxy_detection_contract_skips_collector_events() {
        let event = ExchangeEventV2::new(
            "ex_123",
            ExchangeSourceClass::Collector,
            ExchangeTransport::Https,
            ExchangeBodyMode::MetadataOnly,
            ExchangeBodyMode::MetadataOnly,
        );
        event
            .validate_proxy_detection_contract()
            .expect("collector events are exempt");
    }
}
