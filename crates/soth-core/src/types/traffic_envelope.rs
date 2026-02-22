//! Canonical traffic envelope used to normalize ingress traffic before enforcement.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Runtime path that captured the traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureSource {
    Proxy,
    Wrap,
}

/// Normalized ingress source type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficSource {
    ProxyHudsucker,
    McpStdio,
    McpHttp,
}

/// Canonical request envelope shared by proxy and wrap ingress paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficEnvelope {
    /// Stable envelope identifier.
    pub envelope_id: String,
    /// Session identifier for correlation.
    pub session_id: String,
    /// Optional request-level correlation key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Capture path (`proxy` vs `wrap`).
    pub capture_source: CaptureSource,
    /// Logical ingress source.
    pub source: TrafficSource,
    /// Capture timestamp.
    pub captured_at: DateTime<Utc>,
    /// HTTP/JSON-RPC method.
    pub method: String,
    /// Optional provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Optional host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Optional path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Optional model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Optional agent identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// Optional local process ID attributed to the source connection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_pid: Option<u32>,
    /// Optional local process name attributed to the source connection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    /// Optional executable/command path for the source process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_executable: Option<String>,
    /// Optional process-attribution source hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_attribution_source: Option<String>,
    /// Optional process-attribution confidence score in [0,1].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_attribution_confidence: Option<f64>,
    /// Optional identity DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    /// Optional key identifier used for envelope signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Optional signature algorithm label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_alg: Option<String>,
    /// Optional version label for signed field set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_fields_version: Option<String>,
    /// Optional signature material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Optional request body digest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_hash: Option<String>,
    /// Optional request body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<String>,
}

impl TrafficEnvelope {
    /// Create a normalized proxy envelope.
    #[allow(clippy::too_many_arguments)]
    pub fn proxy(
        session_id: impl Into<String>,
        request_id: impl Into<String>,
        provider: impl Into<String>,
        host: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
        model: Option<&str>,
        agent: Option<&str>,
        did: Option<&str>,
        signature: Option<&str>,
        request_body: Option<&str>,
    ) -> Self {
        Self {
            envelope_id: uuid::Uuid::new_v4().to_string(),
            session_id: session_id.into(),
            request_id: Some(request_id.into()),
            capture_source: CaptureSource::Proxy,
            source: TrafficSource::ProxyHudsucker,
            captured_at: Utc::now(),
            method: method.into(),
            provider: Some(provider.into()),
            host: Some(host.into()),
            path: Some(path.into()),
            model: model.map(ToString::to_string),
            agent: agent.map(ToString::to_string),
            process_pid: None,
            process_name: None,
            process_executable: None,
            process_attribution_source: None,
            process_attribution_confidence: None,
            did: did.map(ToString::to_string),
            key_id: None,
            signature_alg: None,
            signed_fields_version: None,
            signature: signature.map(ToString::to_string),
            body_hash: None,
            request_body: request_body.map(ToString::to_string),
        }
    }

    /// Create a normalized wrap envelope for MCP stdio request flow.
    pub fn mcp_stdio(
        session_id: impl Into<String>,
        request_id: Option<impl Into<String>>,
        method: impl Into<String>,
        agent: Option<&str>,
        did: Option<&str>,
        signature: Option<&str>,
        request_body: Option<&str>,
    ) -> Self {
        Self {
            envelope_id: uuid::Uuid::new_v4().to_string(),
            session_id: session_id.into(),
            request_id: request_id.map(|v| v.into()),
            capture_source: CaptureSource::Wrap,
            source: TrafficSource::McpStdio,
            captured_at: Utc::now(),
            method: method.into(),
            provider: None,
            host: None,
            path: None,
            model: None,
            agent: agent.map(ToString::to_string),
            process_pid: None,
            process_name: None,
            process_executable: None,
            process_attribution_source: None,
            process_attribution_confidence: None,
            did: did.map(ToString::to_string),
            key_id: None,
            signature_alg: None,
            signed_fields_version: None,
            signature: signature.map(ToString::to_string),
            body_hash: None,
            request_body: request_body.map(ToString::to_string),
        }
    }

    /// Create a normalized proxy envelope for MCP JSON-RPC over HTTP/WebSocket.
    #[allow(clippy::too_many_arguments)]
    pub fn mcp_http(
        session_id: impl Into<String>,
        request_id: Option<impl Into<String>>,
        method: impl Into<String>,
        host: impl Into<String>,
        path: impl Into<String>,
        agent: Option<&str>,
        did: Option<&str>,
        signature: Option<&str>,
        request_body: Option<&str>,
    ) -> Self {
        Self {
            envelope_id: uuid::Uuid::new_v4().to_string(),
            session_id: session_id.into(),
            request_id: request_id.map(|v| v.into()),
            capture_source: CaptureSource::Proxy,
            source: TrafficSource::McpHttp,
            captured_at: Utc::now(),
            method: method.into(),
            provider: None,
            host: Some(host.into()),
            path: Some(path.into()),
            model: None,
            agent: agent.map(ToString::to_string),
            process_pid: None,
            process_name: None,
            process_executable: None,
            process_attribution_source: None,
            process_attribution_confidence: None,
            did: did.map(ToString::to_string),
            key_id: None,
            signature_alg: None,
            signed_fields_version: None,
            signature: signature.map(ToString::to_string),
            body_hash: None,
            request_body: request_body.map(ToString::to_string),
        }
    }

    /// Attach signature metadata fields used by the crypto identity pipeline.
    pub fn with_signature_metadata(
        mut self,
        key_id: Option<&str>,
        signature_alg: Option<&str>,
        signed_fields_version: Option<&str>,
    ) -> Self {
        self.key_id = key_id.map(ToString::to_string);
        self.signature_alg = signature_alg.map(ToString::to_string);
        self.signed_fields_version = signed_fields_version.map(ToString::to_string);
        self
    }

    /// Attach a request-body digest (hex/base64 encoded by caller).
    pub fn with_body_hash(mut self, body_hash: impl Into<String>) -> Self {
        self.body_hash = Some(body_hash.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{CaptureSource, TrafficEnvelope, TrafficSource};

    #[test]
    fn test_mcp_stdio_envelope_shape() {
        let envelope = TrafficEnvelope::mcp_stdio(
            "session-1",
            Some("request-1"),
            "tools/list",
            Some("cursor"),
            None,
            None,
            Some("{\"jsonrpc\":\"2.0\"}"),
        );

        assert_eq!(envelope.capture_source, CaptureSource::Wrap);
        assert_eq!(envelope.source, TrafficSource::McpStdio);
        assert_eq!(envelope.host, None);
        assert_eq!(envelope.path, None);
    }

    #[test]
    fn test_mcp_http_envelope_shape() {
        let envelope = TrafficEnvelope::mcp_http(
            "session-1",
            Some("request-1"),
            "tools/list",
            "api.github.com",
            "/mcp",
            Some("cursor"),
            None,
            None,
            Some("{\"jsonrpc\":\"2.0\"}"),
        );

        assert_eq!(envelope.capture_source, CaptureSource::Proxy);
        assert_eq!(envelope.source, TrafficSource::McpHttp);
        assert_eq!(envelope.host.as_deref(), Some("api.github.com"));
        assert_eq!(envelope.path.as_deref(), Some("/mcp"));
    }

    #[test]
    fn test_signature_metadata_fields() {
        let envelope = TrafficEnvelope::proxy(
            "session-1",
            "request-1",
            "openai",
            "api.openai.com",
            "POST",
            "/v1/responses",
            Some("gpt-5"),
            Some("codex"),
            Some("did:key:z6MkExample"),
            Some("sig"),
            Some("{\"input\":\"hello\"}"),
        )
        .with_signature_metadata(Some("agent:v1"), Some("ed25519"), Some("v1"))
        .with_body_hash("abc123");

        assert_eq!(envelope.key_id.as_deref(), Some("agent:v1"));
        assert_eq!(envelope.signature_alg.as_deref(), Some("ed25519"));
        assert_eq!(envelope.signed_fields_version.as_deref(), Some("v1"));
        assert_eq!(envelope.body_hash.as_deref(), Some("abc123"));
    }
}
