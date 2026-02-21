//! Shared response event assembly for proxy observability rows.

use std::collections::BTreeMap;

use soth_core::types::{
    AgentInfo, DetectionSource, EventSource, TrafficEnvelope, WrapDirection, WrapEvent,
};

use crate::json_security::strip_json_security_prefix_text;
use crate::transport::usage_enrichment::ResponseUsageMeta;

#[derive(Debug, Clone, Copy)]
pub enum ResponseKind {
    Http,
    Stream { is_sse: bool },
}

impl ResponseKind {
    fn preview_suffix(self, status: u16) -> String {
        match self {
            Self::Http => format!("HTTP {status}"),
            Self::Stream { is_sse: true } => format!("SSE {status}"),
            Self::Stream { is_sse: false } => format!("STREAM {status}"),
        }
    }
}

pub struct ResponseEventInput<'a> {
    pub session_id: &'a str,
    pub host: &'a str,
    pub provider: &'a str,
    pub agent: Option<&'a str>,
    pub method: &'a str,
    pub path: &'a str,
    pub graphql_operation: Option<&'a str>,
    pub is_agent_app: bool,
    pub status: u16,
    pub latency_ms: u64,
    pub request_content: Option<&'a str>,
    pub response_content: Option<String>,
    pub request_size_bytes: Option<u64>,
    pub response_size_bytes: Option<u64>,
    pub headers: Option<BTreeMap<String, String>>,
    pub tags: Option<&'a BTreeMap<String, String>>,
    pub usage_meta: &'a ResponseUsageMeta,
    pub response_kind: ResponseKind,
    pub traffic_envelope: Option<TrafficEnvelope>,
}

pub fn empty_response_placeholder(method: &str, path: &str, status: u16, is_sse: bool) -> String {
    if is_sse {
        return format!(
            "[no SSE payload captured for {} {} (HTTP {})]",
            method, path, status
        );
    }
    format!(
        "[no HTTP response body captured for {} {} (HTTP {})]",
        method, path, status
    )
}

pub fn normalize_response_content(
    response_content: Option<&str>,
    request_content: Option<&str>,
    method: &str,
    path: &str,
    status: u16,
    is_sse: bool,
    always_placeholder_on_empty: bool,
) -> Option<String> {
    response_content
        .filter(|resp| !resp.trim().is_empty())
        .map(|resp| {
            let sanitized = strip_json_security_prefix_text(resp);
            if sanitized.is_empty() {
                resp.to_string()
            } else {
                sanitized.to_string()
            }
        })
        .or_else(|| {
            if always_placeholder_on_empty || request_content.is_some() || method == "POST" {
                Some(empty_response_placeholder(method, path, status, is_sse))
            } else {
                None
            }
        })
}

pub fn build_paired_response_event(input: ResponseEventInput<'_>) -> WrapEvent {
    let agent_name = input.agent.unwrap_or(input.provider);
    let agent_info = AgentInfo::new(agent_name, DetectionSource::Environment);
    let method_str = format!("{} {}", input.method, input.path);
    let method_label = input
        .graphql_operation
        .map(|op| format!("{method_str} · gql:{op}"))
        .unwrap_or(method_str);
    let source = if input.is_agent_app {
        EventSource::AgentApp
    } else {
        EventSource::AiProxy
    };

    let mut event = WrapEvent::new(input.session_id, input.host, WrapDirection::Out, agent_info)
        .with_source(source)
        .with_provider(input.provider)
        .with_method(method_label)
        .with_status_code(input.status)
        .with_latency(input.latency_ms);
    if let Some(op) = input.graphql_operation {
        event = event.with_graphql_operation(op.to_string());
    }

    if let Some(envelope) = input.traffic_envelope {
        event = event.with_traffic_envelope(envelope);
    }

    if let Some(request_body) = input.request_content {
        event = event.with_request(request_body.to_string(), "");
    }
    if let Some(response_body) = input.response_content {
        event = event.with_response(response_body, "");
    }
    event = event.with_payload_sizes(input.request_size_bytes, input.response_size_bytes);
    if let Some(headers) = input.headers {
        event = event.with_headers(headers);
    }
    if input.tags.is_some() || input.graphql_operation.is_some() {
        let mut merged = input.tags.cloned().unwrap_or_default();
        if let Some(op) = input.graphql_operation {
            merged.insert("graphql_operation".to_string(), op.to_string());
        }
        if !merged.is_empty() {
            event = event.with_tags(merged);
        }
    }

    // Keep compact row summary; full payload is in request_content/response_content.
    event = event.with_content_preview(format!(
        "→ {} {} | ← {}",
        input.method,
        input.path,
        input.response_kind.preview_suffix(input.status)
    ));

    if let Some(model) = input.usage_meta.model.as_deref() {
        event = event.with_model(model.to_string());
    }
    let input_tokens = input.usage_meta.input_tokens.unwrap_or(0);
    let output_tokens = input.usage_meta.output_tokens.unwrap_or(0);
    if input_tokens > 0 || output_tokens > 0 {
        event = event.with_usage_tokens(input_tokens, output_tokens);
    }
    event = event.with_cache_tokens(
        input.usage_meta.cache_read_tokens,
        input.usage_meta.cache_write_tokens,
    );
    if let Some(reasoning_tokens) = input.usage_meta.reasoning_tokens {
        event = event.with_reasoning_tokens(reasoning_tokens);
    }
    if let Some(cost) = input.usage_meta.cost_usd {
        event = event.with_cost(cost);
    }

    event
}

#[cfg(test)]
mod tests {
    use super::normalize_response_content;

    #[test]
    fn normalize_response_content_strips_security_prefix() {
        let content = normalize_response_content(
            Some(")]}'\n{\"ok\":true}"),
            Some("{}"),
            "POST",
            "/v1/messages",
            200,
            false,
            true,
        );
        assert_eq!(content.as_deref(), Some("{\"ok\":true}"));
    }

    #[test]
    fn normalize_response_content_uses_placeholder_when_empty() {
        let content =
            normalize_response_content(Some(""), Some("{}"), "POST", "/x", 200, false, true);
        assert!(content
            .unwrap_or_default()
            .contains("no HTTP response body captured"));
    }
}
