//! Unified exchange event schema (v2).
//!
//! This models a single finalized request/response exchange as one event.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const EXCHANGE_SCHEMA_VERSION_V2: &str = "2.0";

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
    pub bundle_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_type: Option<String>,
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
    pub event_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_key_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeParse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parser_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_confidence: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_entity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection_source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeEventV2 {
    pub schema_version: String,
    pub exchange_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
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
    pub status_code: Option<u16>,
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
            schema_version: EXCHANGE_SCHEMA_VERSION_V2.to_string(),
            exchange_id: exchange_id.into(),
            session_id: None,
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
            status_code: None,
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
}

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
        assert_eq!(parsed.schema_version, EXCHANGE_SCHEMA_VERSION_V2);
        assert_eq!(parsed.exchange_id, "ex_123");
        assert_eq!(parsed.request.body.mode, ExchangeBodyMode::Inline);
        assert_eq!(parsed.response.body.mode, ExchangeBodyMode::Offloaded);
    }
}
