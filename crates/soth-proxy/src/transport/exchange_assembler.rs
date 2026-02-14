//! Exchange assembler for unified `exchange.v2` events.
//!
//! This module collates request/response payload fragments into one finalized
//! `ExchangeEventV2` and supports snapshot serialization for local spool
//! persistence.

use base64::Engine as _;
use chrono::{DateTime, Utc};
use flate2::{write::GzEncoder, Compression};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use soth_core::config::types::ExchangeV2Config;
use soth_core::types::exchange_v2::{
    ExchangeBodyMode, ExchangeClient, ExchangeCost, ExchangeEventV2, ExchangeFlags,
    ExchangeIntegrity, ExchangeParse, ExchangeSourceClass, ExchangeTransport, ExchangeUsage,
};
use std::collections::BTreeMap;
use std::io::Write;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ExchangeAssemblerConfig {
    pub inline_max_bytes: usize,
    pub max_body_bytes: usize,
    pub max_stream_buffer_bytes: usize,
    pub stream_idle_timeout: Duration,
    pub stream_max_duration: Duration,
}

impl From<&ExchangeV2Config> for ExchangeAssemblerConfig {
    fn from(value: &ExchangeV2Config) -> Self {
        Self {
            inline_max_bytes: value.inline_max_bytes.max(1),
            max_body_bytes: value.max_body_bytes.max(1) as usize,
            max_stream_buffer_bytes: value.max_stream_buffer_bytes.max(1) as usize,
            stream_idle_timeout: value.stream_idle_timeout,
            stream_max_duration: value.stream_max_duration,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeAssemblerSnapshot {
    pub exchange_id: String,
    pub session_id: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub started_at: DateTime<Utc>,
    pub first_response_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub source_class: ExchangeSourceClass,
    pub transport: ExchangeTransport,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub provider: Option<String>,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub endpoint: Option<String>,
    pub method: Option<String>,
    pub status_code: Option<u16>,
    pub request_headers: Option<BTreeMap<String, String>>,
    pub response_headers: Option<BTreeMap<String, String>>,
    pub request_content_type: Option<String>,
    pub response_content_type: Option<String>,
    pub request_body: Vec<u8>,
    pub response_body: Vec<u8>,
    pub usage: ExchangeUsage,
    pub cost: Option<ExchangeCost>,
    pub flags: ExchangeFlags,
    pub parse: Option<ExchangeParse>,
    pub tags: Option<BTreeMap<String, String>>,
    pub client: Option<ExchangeClient>,
    pub truncated_reason: Option<String>,
    pub integrity_signature: Option<String>,
    pub integrity_signature_key_id: Option<String>,
}

/// Offloaded body blob material produced at finalize time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExchangeBlobPayload {
    /// `request` or `response`.
    pub side: String,
    /// Canonical blob reference URI.
    pub reference: String,
    /// Encoded content type for this blob payload (always `gzip` currently).
    pub content_encoding: String,
    /// Source content type if known.
    pub content_type: Option<String>,
    /// SHA-256 hash of the original uncompressed payload.
    pub sha256: String,
    /// Original uncompressed byte length.
    pub bytes_raw: u64,
    /// Compressed byte length.
    pub bytes_gzip: u64,
    /// Gzip payload encoded as base64.
    pub payload_gzip_b64: String,
}

/// Finalized exchange + any blob payloads that must be uploaded separately.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeFinalizeResult {
    pub event: ExchangeEventV2,
    #[serde(default)]
    pub blobs: Vec<ExchangeBlobPayload>,
}

#[derive(Debug, Clone)]
pub struct ExchangeAssembler {
    cfg: ExchangeAssemblerConfig,
    state: ExchangeAssemblerSnapshot,
}

impl ExchangeAssembler {
    pub fn new(
        cfg: ExchangeAssemblerConfig,
        exchange_id: impl Into<String>,
        source_class: ExchangeSourceClass,
        transport: ExchangeTransport,
    ) -> Self {
        let now = Utc::now();
        Self {
            cfg,
            state: ExchangeAssemblerSnapshot {
                exchange_id: exchange_id.into(),
                session_id: None,
                observed_at: now,
                started_at: now,
                first_response_at: None,
                completed_at: None,
                source_class,
                transport,
                trace_id: None,
                span_id: None,
                parent_span_id: None,
                provider: None,
                agent: None,
                model: None,
                endpoint: None,
                method: None,
                status_code: None,
                request_headers: None,
                response_headers: None,
                request_content_type: None,
                response_content_type: None,
                request_body: Vec::new(),
                response_body: Vec::new(),
                usage: ExchangeUsage::default(),
                cost: None,
                flags: ExchangeFlags::default(),
                parse: None,
                tags: None,
                client: None,
                truncated_reason: None,
                integrity_signature: None,
                integrity_signature_key_id: None,
            },
        }
    }

    pub fn from_snapshot(cfg: ExchangeAssemblerConfig, snapshot: ExchangeAssemblerSnapshot) -> Self {
        Self {
            cfg,
            state: snapshot,
        }
    }

    pub fn from_snapshot_json(
        cfg: ExchangeAssemblerConfig,
        value: &str,
    ) -> Result<Self, serde_json::Error> {
        let snapshot: ExchangeAssemblerSnapshot = serde_json::from_str(value)?;
        Ok(Self::from_snapshot(cfg, snapshot))
    }

    pub fn snapshot(&self) -> ExchangeAssemblerSnapshot {
        self.state.clone()
    }

    pub fn snapshot_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.state)
    }

    pub fn set_route(
        &mut self,
        provider: Option<String>,
        agent: Option<String>,
        model: Option<String>,
        endpoint: Option<String>,
        method: Option<String>,
    ) {
        self.state.provider = provider;
        self.state.agent = agent;
        self.state.model = model;
        self.state.endpoint = endpoint;
        self.state.method = method;
    }

    pub fn set_session_id(&mut self, session_id: impl Into<String>) {
        self.state.session_id = Some(session_id.into());
    }

    pub fn set_trace(
        &mut self,
        trace_id: Option<String>,
        span_id: Option<String>,
        parent_span_id: Option<String>,
    ) {
        self.state.trace_id = trace_id;
        self.state.span_id = span_id;
        self.state.parent_span_id = parent_span_id;
    }

    pub fn set_client(&mut self, client: Option<ExchangeClient>) {
        self.state.client = client;
    }

    pub fn set_request(
        &mut self,
        headers: Option<BTreeMap<String, String>>,
        content_type: Option<String>,
        body: &[u8],
    ) {
        self.state.request_headers = headers;
        self.state.request_content_type = content_type;
        self.state.request_body.clear();
        self.state.request_body.extend_from_slice(body);
    }

    pub fn set_response_meta(
        &mut self,
        headers: Option<BTreeMap<String, String>>,
        status_code: Option<u16>,
        content_type: Option<String>,
    ) {
        self.state.response_headers = headers;
        self.state.status_code = status_code;
        self.state.response_content_type = content_type;
    }

    pub fn append_response_chunk(&mut self, chunk: &[u8]) {
        if self.state.first_response_at.is_none() {
            self.state.first_response_at = Some(Utc::now());
        }

        let cap = self.cfg.max_stream_buffer_bytes;
        if self.state.response_body.len() >= cap {
            self.mark_truncated("stream_buffer_limit_reached");
            return;
        }

        let remaining = cap.saturating_sub(self.state.response_body.len());
        if chunk.len() <= remaining {
            self.state.response_body.extend_from_slice(chunk);
        } else {
            self.state.response_body.extend_from_slice(&chunk[..remaining]);
            self.mark_truncated("stream_buffer_limit_reached");
        }
    }

    pub fn set_usage(&mut self, usage: ExchangeUsage) {
        self.state.usage = usage;
    }

    pub fn set_cost(&mut self, cost: Option<ExchangeCost>) {
        self.state.cost = cost;
    }

    pub fn set_parse(&mut self, parse: Option<ExchangeParse>) {
        self.state.parse = parse;
    }

    pub fn set_tags(&mut self, tags: Option<BTreeMap<String, String>>) {
        self.state.tags = tags;
    }

    pub fn set_integrity_signature(
        &mut self,
        signature: Option<String>,
        signature_key_id: Option<String>,
    ) {
        self.state.integrity_signature = signature;
        self.state.integrity_signature_key_id = signature_key_id;
    }

    pub fn set_pii_detected(&mut self, detected: bool) {
        self.state.flags.pii_detected = detected;
    }

    pub fn set_blacklist_match(&mut self, matched: bool) {
        self.state.flags.blacklist_match = matched;
    }

    pub fn set_discovery_capture(&mut self, enabled: bool) {
        self.state.flags.discovery_capture = enabled;
    }

    pub fn mark_metadata_only(&mut self, reason: impl Into<String>) {
        self.state.flags.metadata_only = true;
        self.state.truncated_reason = Some(reason.into());
    }

    pub fn mark_truncated(&mut self, reason: impl Into<String>) {
        self.state.flags.truncated = true;
        self.state.truncated_reason = Some(reason.into());
    }

    pub fn finalize_complete(mut self) -> ExchangeEventV2 {
        self.state.completed_at = Some(Utc::now());
        self.build_result().event
    }

    pub fn finalize_complete_with_blobs(mut self) -> ExchangeFinalizeResult {
        self.state.completed_at = Some(Utc::now());
        self.build_result()
    }

    pub fn finalize_timeout(mut self) -> ExchangeEventV2 {
        self.state.completed_at = Some(Utc::now());
        if self.state.truncated_reason.is_none() {
            self.mark_truncated("partial_timeout");
        }
        self.build_result().event
    }

    pub fn finalize_timeout_with_blobs(mut self) -> ExchangeFinalizeResult {
        self.state.completed_at = Some(Utc::now());
        if self.state.truncated_reason.is_none() {
            self.mark_truncated("partial_timeout");
        }
        self.build_result()
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        let max_duration = chrono::Duration::from_std(self.cfg.stream_max_duration)
            .unwrap_or_else(|_| chrono::Duration::seconds(600));
        if now.signed_duration_since(self.state.started_at) > max_duration {
            return true;
        }
        if let Some(last) = self.state.first_response_at {
            let idle = chrono::Duration::from_std(self.cfg.stream_idle_timeout)
                .unwrap_or_else(|_| chrono::Duration::seconds(30));
            if now.signed_duration_since(last) > idle {
                return true;
            }
        }
        false
    }

    fn build_result(self) -> ExchangeFinalizeResult {
        let cfg = self.cfg.clone();
        let state = self.state;
        let now = Utc::now();
        let mut event = ExchangeEventV2::new(
            state.exchange_id,
            state.source_class,
            state.transport,
            ExchangeBodyMode::MetadataOnly,
            ExchangeBodyMode::MetadataOnly,
        );

        event.session_id = state.session_id;
        event.observed_at = now;
        event.started_at = Some(state.started_at);
        event.completed_at = state.completed_at;
        event.duration_ms = state
            .completed_at
            .map(|completed| (completed - state.started_at).num_milliseconds().max(0) as u64);
        event.ttfb_ms = state.first_response_at.map(|first| {
            (first - state.started_at)
                .num_milliseconds()
                .max(0) as u64
        });
        event.trace_id = state.trace_id;
        event.span_id = state.span_id;
        event.parent_span_id = state.parent_span_id;
        event.provider = state.provider;
        event.agent = state.agent;
        event.model = state.model;
        event.endpoint = state.endpoint;
        event.method = state.method;
        event.status_code = state.status_code;
        event.client = state.client;
        event.usage = state.usage;
        event.cost = state.cost;
        event.flags = state.flags.clone();
        event.parse = state.parse;
        event.tags = state.tags;

        event.request.headers = state.request_headers;
        event.response.headers = state.response_headers;

        let request = build_body_with_cfg(
            &cfg,
            &state.request_body,
            state.request_content_type,
            state.truncated_reason.clone(),
            state.flags.metadata_only,
        );
        let response = build_body_with_cfg(
            &cfg,
            &state.response_body,
            state.response_content_type,
            state.truncated_reason.clone(),
            state.flags.metadata_only,
        );

        event.request.body = request;
        event.response.body = response;
        event.integrity = Some(ExchangeIntegrity {
            event_hash: None,
            signature: state.integrity_signature,
            signature_key_id: state.integrity_signature_key_id,
        });

        let mut blobs = Vec::new();
        apply_blob_offload(
            &mut event.request.body,
            &state.request_body,
            event.exchange_id.as_str(),
            "request",
            &mut blobs,
        );
        apply_blob_offload(
            &mut event.response.body,
            &state.response_body,
            event.exchange_id.as_str(),
            "response",
            &mut blobs,
        );

        let event_hash = compute_event_hash(&event);
        if let Some(integrity) = event.integrity.as_mut() {
            integrity.event_hash = Some(event_hash);
        }
        ExchangeFinalizeResult { event, blobs }
    }
}

fn build_body_with_cfg(
    cfg: &ExchangeAssemblerConfig,
    bytes: &[u8],
    content_type: Option<String>,
    truncated_reason: Option<String>,
    force_metadata_only: bool,
) -> soth_core::types::exchange_v2::ExchangeBody {
    if force_metadata_only {
        return soth_core::types::exchange_v2::ExchangeBody {
            mode: ExchangeBodyMode::MetadataOnly,
            inline: None,
            reference: None,
            preview: None,
            bytes_raw: Some(bytes.len() as u64),
            bytes_gzip: None,
            sha256: Some(sha256_hex(bytes)),
            content_type,
            truncated_reason,
        };
    }

    let mode;
    let mut inline = None;
    let reference = None;
    let mut preview = None;
    let mut reason = truncated_reason;

    if bytes.len() > cfg.max_body_bytes {
        mode = ExchangeBodyMode::PreviewOnly;
        preview = Some(build_preview(bytes, 512));
        if reason.is_none() {
            reason = Some("max_body_bytes_exceeded".to_string());
        }
    } else if bytes.len() <= cfg.inline_max_bytes {
        mode = ExchangeBodyMode::Inline;
        inline = Some(String::from_utf8_lossy(bytes).to_string());
    } else {
        mode = ExchangeBodyMode::Offloaded;
        preview = Some(build_preview(bytes, 256));
    }

    soth_core::types::exchange_v2::ExchangeBody {
        mode,
        inline,
        reference,
        preview,
        bytes_raw: Some(bytes.len() as u64),
        bytes_gzip: None,
        sha256: Some(sha256_hex(bytes)),
        content_type,
        truncated_reason: reason,
    }
}

fn apply_blob_offload(
    body: &mut soth_core::types::exchange_v2::ExchangeBody,
    raw_bytes: &[u8],
    exchange_id: &str,
    side: &str,
    blobs: &mut Vec<ExchangeBlobPayload>,
) {
    if body.mode != ExchangeBodyMode::Offloaded {
        return;
    }

    let sha = body.sha256.clone().unwrap_or_else(|| sha256_hex(raw_bytes));
    let Some(gzip_payload) = gzip_bytes(raw_bytes) else {
        body.mode = ExchangeBodyMode::PreviewOnly;
        if body.preview.is_none() {
            body.preview = Some(build_preview(raw_bytes, 256));
        }
        if body.truncated_reason.is_none() {
            body.truncated_reason = Some("gzip_encode_failed".to_string());
        }
        body.reference = None;
        body.bytes_gzip = None;
        return;
    };

    let reference = format!("blob://exchange/{exchange_id}/{side}/{sha}.json.gz");
    let bytes_gzip = gzip_payload.len() as u64;
    body.reference = Some(reference.clone());
    body.bytes_gzip = Some(bytes_gzip);
    body.inline = None;

    blobs.push(ExchangeBlobPayload {
        side: side.to_string(),
        reference,
        content_encoding: "gzip".to_string(),
        content_type: body.content_type.clone(),
        sha256: sha,
        bytes_raw: raw_bytes.len() as u64,
        bytes_gzip,
        payload_gzip_b64: base64::engine::general_purpose::STANDARD.encode(gzip_payload),
    });
}

fn gzip_bytes(input: &[u8]) -> Option<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input).ok()?;
    encoder.finish().ok()
}

fn compute_event_hash(event: &ExchangeEventV2) -> String {
    let mut canonical = event.clone();
    if let Some(integrity) = canonical.integrity.as_mut() {
        integrity.event_hash = None;
        // Signatures may be generated from the canonical event hash; exclude them from hash input.
        integrity.signature = None;
    }
    let encoded = serde_json::to_vec(&canonical).unwrap_or_default();
    sha256_hex(&encoded)
}

fn build_preview(bytes: &[u8], max_chars: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    for ch in text.chars().take(max_chars) {
        out.push(ch);
    }
    if text.chars().count() > max_chars {
        out.push_str("...");
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    format!("{:x}", digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ExchangeAssemblerConfig {
        ExchangeAssemblerConfig {
            inline_max_bytes: 16,
            max_body_bytes: 64,
            max_stream_buffer_bytes: 64,
            stream_idle_timeout: Duration::from_secs(30),
            stream_max_duration: Duration::from_secs(600),
        }
    }

    #[test]
    fn finalize_uses_inline_for_small_payloads() {
        let mut a = ExchangeAssembler::new(
            cfg(),
            "ex1",
            ExchangeSourceClass::AiInference,
            ExchangeTransport::Https,
        );
        a.set_request(None, Some("application/json".to_string()), br#"{"x":1}"#);
        a.append_response_chunk(br#"{"ok":true}"#);
        let event = a.finalize_complete();
        assert_eq!(event.request.body.mode, ExchangeBodyMode::Inline);
        assert_eq!(event.response.body.mode, ExchangeBodyMode::Inline);
        assert_eq!(event.schema_version, "2.0");
    }

    #[test]
    fn finalize_uses_offloaded_for_medium_payloads() {
        let mut a = ExchangeAssembler::new(
            cfg(),
            "ex2",
            ExchangeSourceClass::AiInference,
            ExchangeTransport::Https,
        );
        let body = vec![b'a'; 40];
        a.set_request(None, None, &body);
        a.append_response_chunk(&body);
        let event = a.finalize_complete();
        assert_eq!(event.request.body.mode, ExchangeBodyMode::Offloaded);
        assert_eq!(event.response.body.mode, ExchangeBodyMode::Offloaded);
        assert!(
            event
                .request
                .body
                .reference
                .as_deref()
                .unwrap_or_default()
                .starts_with("blob://exchange/ex2/request/")
        );
    }

    #[test]
    fn finalize_uses_preview_for_oversized_payloads() {
        let mut a = ExchangeAssembler::new(
            cfg(),
            "ex3",
            ExchangeSourceClass::AiInference,
            ExchangeTransport::Https,
        );
        let body = vec![b'a'; 80];
        a.set_request(None, None, &body);
        a.append_response_chunk(&body);
        let event = a.finalize_complete();
        assert_eq!(event.request.body.mode, ExchangeBodyMode::PreviewOnly);
        assert_eq!(event.response.body.mode, ExchangeBodyMode::Offloaded);
        assert!(event.request.body.preview.is_some());
    }

    #[test]
    fn metadata_only_forces_metadata_mode() {
        let mut a = ExchangeAssembler::new(
            cfg(),
            "ex4",
            ExchangeSourceClass::AgentApp,
            ExchangeTransport::Https,
        );
        a.set_request(None, None, br#"{"secret":"x"}"#);
        a.append_response_chunk(br#"{"ok":true}"#);
        a.mark_metadata_only("blacklist");
        let event = a.finalize_complete();
        assert_eq!(event.request.body.mode, ExchangeBodyMode::MetadataOnly);
        assert_eq!(event.response.body.mode, ExchangeBodyMode::MetadataOnly);
        assert!(event.flags.metadata_only);
    }

    #[test]
    fn snapshot_roundtrip() {
        let mut a = ExchangeAssembler::new(
            cfg(),
            "ex5",
            ExchangeSourceClass::Mcp,
            ExchangeTransport::Jsonrpc,
        );
        a.set_request(None, None, br#"{"jsonrpc":"2.0"}"#);
        a.append_response_chunk(br#"{"result":{}}"#);
        let raw = a.snapshot_json().expect("snapshot json");
        let restored = ExchangeAssembler::from_snapshot_json(cfg(), &raw).expect("restore");
        assert_eq!(restored.snapshot().exchange_id, "ex5");
        assert_eq!(
            restored.snapshot().transport,
            ExchangeTransport::Jsonrpc
        );
    }

    #[test]
    fn finalize_with_blobs_emits_blob_payloads() {
        let mut a = ExchangeAssembler::new(
            cfg(),
            "ex6",
            ExchangeSourceClass::AiInference,
            ExchangeTransport::Https,
        );
        let body = vec![b'x'; 48];
        a.set_request(None, Some("application/json".to_string()), &body);
        a.append_response_chunk(&body);
        let result = a.finalize_complete_with_blobs();
        assert_eq!(result.event.request.body.mode, ExchangeBodyMode::Offloaded);
        assert_eq!(result.event.response.body.mode, ExchangeBodyMode::Offloaded);
        assert_eq!(result.blobs.len(), 2);
        assert!(result.blobs.iter().all(|blob| !blob.payload_gzip_b64.is_empty()));
        assert!(result
            .event
            .request
            .body
            .bytes_gzip
            .unwrap_or_default()
            > 0);
    }

    #[test]
    fn integrity_signature_propagates_to_event() {
        let mut a = ExchangeAssembler::new(
            cfg(),
            "ex7",
            ExchangeSourceClass::AiInference,
            ExchangeTransport::Https,
        );
        a.set_request(None, None, br#"{"x":1}"#);
        a.append_response_chunk(br#"{"ok":true}"#);
        a.set_integrity_signature(Some("sig-1".to_string()), Some("key-1".to_string()));
        let event = a.finalize_complete();
        let integrity = event.integrity.expect("integrity");
        assert_eq!(integrity.signature.as_deref(), Some("sig-1"));
        assert_eq!(integrity.signature_key_id.as_deref(), Some("key-1"));
        assert!(integrity.event_hash.is_some());
    }
}
