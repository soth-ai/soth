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
    /// Optional identity DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    /// Optional signature material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
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
            did: did.map(ToString::to_string),
            signature: signature.map(ToString::to_string),
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
            did: did.map(ToString::to_string),
            signature: signature.map(ToString::to_string),
            request_body: request_body.map(ToString::to_string),
        }
    }
}
