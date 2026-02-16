//! WebSocket handling for forward proxy transport.

use hudsucker::{tokio_tungstenite::tungstenite::Message, WebSocketContext, WebSocketHandler};
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::{debug, info};

use crate::transport::host_fingerprint;
use crate::transport::mcp_detection::{extract_mcp_request_method, is_jsonrpc_response_for_mcp};
use crate::transport::pii_enrichment::PiiEventEnricher;
use crate::transport::proxy_support::{
    append_catalog_discovery_tags, append_process_attribution_tags,
};
use soth_core::config::{HostFilterConfig, HostFilterMode};
use soth_core::types::{
    AgentInfo, DetectionSource, EventSource, TrafficEnvelope, WrapDirection, WrapEvent,
};
use soth_core::EventLogger;
use soth_oisp::OispEngine;

/// WebSocket handler for AI streaming connections.
#[derive(Clone)]
pub struct AiWebSocketHandler {
    /// Event logger for observability.
    event_logger: Option<Arc<EventLogger>>,
    /// Session ID.
    session_id: String,
    /// Host filter config for source classification.
    hosts: Arc<HostFilterConfig>,
    /// Bundle-driven classifier.
    oisp_engine: Arc<OispEngine>,
    /// User-defined tags attached to emitted events.
    event_tags: Arc<BTreeMap<String, String>>,
    /// Optional PII enrichment before events are written.
    pii_enricher: Arc<PiiEventEnricher>,
}

impl AiWebSocketHandler {
    pub fn new(
        session_id: String,
        event_logger: Option<Arc<EventLogger>>,
        hosts: Arc<HostFilterConfig>,
        oisp_engine: Arc<OispEngine>,
        event_tags: Arc<BTreeMap<String, String>>,
        pii_enricher: Arc<PiiEventEnricher>,
    ) -> Self {
        Self {
            event_logger,
            session_id,
            hosts,
            oisp_engine,
            event_tags,
            pii_enricher,
        }
    }
}

pub(crate) fn should_emit_non_mcp_ws_event(is_agent_app: bool, provider: &str) -> bool {
    is_agent_app || provider != "unknown"
}

impl WebSocketHandler for AiWebSocketHandler {
    fn handle_message(
        &mut self,
        ctx: &WebSocketContext,
        msg: Message,
    ) -> impl std::future::Future<Output = Option<Message>> + Send {
        let event_logger = self.event_logger.clone();
        let session_id = self.session_id.clone();
        let hosts = self.hosts.clone();
        let oisp_engine = self.oisp_engine.clone();
        let event_tags = self.event_tags.clone();
        let pii_enricher = self.pii_enricher.clone();

        // Extract host/path and direction from context.
        let (host, ws_path, direction) = match ctx {
            WebSocketContext::ClientToServer { dst, .. } => {
                let h = dst.host().unwrap_or("unknown").to_string();
                let p = dst.path().to_string();
                (h, p, WrapDirection::In)
            }
            WebSocketContext::ServerToClient { src, .. } => {
                let h = src.host().unwrap_or("unknown").to_string();
                let p = src.path().to_string();
                (h, p, WrapDirection::Out)
            }
        };

        let is_discovery = hosts.mode == HostFilterMode::Discovery;
        let oisp_classification = oisp_engine.classify(&host);
        let is_catalog_discovery_ws =
            is_discovery && oisp_classification.is_none() && oisp_engine.is_catalog_domain(&host);

        let (host_is_ai_target, host_is_mcp_target, host_is_agent_target, provider) =
            if let Some(classification) = oisp_classification.as_ref() {
                let (ai, mcp, agent) = match classification.entry_type_label() {
                    "ai_inference" => (true, false, false),
                    "mcp" => (false, true, false),
                    "agent_app" => (false, false, true),
                    _ => (false, false, false),
                };
                (ai, mcp, agent, classification.provider_id.clone())
            } else {
                (false, false, false, "unknown".to_string())
            };

        let is_agent_app = host_is_agent_target;
        let detected_ws_agent = host_fingerprint::detect_agent_with_context_gated(
            None,
            &host,
            &ws_path,
            None,
            host_is_agent_target || is_discovery,
        );

        async move {
            match &msg {
                Message::Text(text) => {
                    let mcp_method = if host_is_mcp_target || is_discovery {
                        extract_mcp_request_method(text, &ws_path)
                    } else {
                        None
                    };
                    let is_mcp_response = (host_is_mcp_target || is_discovery)
                        && mcp_method.is_none()
                        && is_jsonrpc_response_for_mcp(text);
                    let is_actual_mcp = mcp_method.is_some() || is_mcp_response;

                    // Keep MCP host seed list focused on JSON-RPC traffic only.
                    // Non-MCP text frames on MCP hosts (for example Intercom pubsub noise)
                    // should not be reclassified as AI inference.
                    if host_is_mcp_target && !host_is_ai_target && !is_discovery && !is_actual_mcp {
                        debug!(
                            host = %host,
                            path = %ws_path,
                            len = text.len(),
                            "Skipping non-MCP WebSocket text frame on MCP host"
                        );
                        return Some(msg);
                    }

                    let event_shape = if let Some(method) = mcp_method {
                        Some((EventSource::Mcp, method, "mcp".to_string()))
                    } else if is_mcp_response {
                        Some((EventSource::Mcp, "response".to_string(), "mcp".to_string()))
                    } else if should_emit_non_mcp_ws_event(is_agent_app, provider.as_str()) {
                        let source = if is_agent_app {
                            EventSource::AgentApp
                        } else {
                            EventSource::AiProxy
                        };
                        let method = if ws_path == "/" {
                            "WebSocket".to_string()
                        } else {
                            format!("WebSocket {}", ws_path)
                        };
                        Some((source, method, provider.clone()))
                    } else {
                        None
                    };

                    if let Some((source, ws_method, provider_for_event)) = event_shape {
                        info!(
                            host = %host,
                            path = %ws_path,
                            provider = %provider_for_event,
                            agent = detected_ws_agent.unwrap_or(provider_for_event.as_str()),
                            len = text.len(),
                            "WebSocket text message"
                        );

                        // Log WebSocket message for observability.
                        if let Some(ref logger) = event_logger {
                            let resolved_agent =
                                detected_ws_agent.unwrap_or_else(|| match source {
                                    EventSource::Mcp => "mcp",
                                    EventSource::AiProxy | EventSource::AgentApp => {
                                        if provider_for_event == "unknown" {
                                            "websocket"
                                        } else {
                                            provider_for_event.as_str()
                                        }
                                    }
                                });
                            let agent_info =
                                AgentInfo::new(resolved_agent, DetectionSource::Environment);

                            let mut event =
                                WrapEvent::new(&session_id, &host, direction, agent_info)
                                    .with_source(source)
                                    .with_provider(provider_for_event.clone())
                                    .with_method(ws_method.clone())
                                    .with_content(text.to_string());
                            let mut tags = (*event_tags).clone();
                            if is_catalog_discovery_ws {
                                append_catalog_discovery_tags(&mut tags, &host);
                            }
                            if matches!(source, EventSource::Mcp) {
                                let envelope = TrafficEnvelope::mcp_http(
                                    &session_id,
                                    None::<String>,
                                    ws_method.clone(),
                                    &host,
                                    &ws_path,
                                    Some(resolved_agent),
                                    None,
                                    None,
                                    Some(text.as_ref()),
                                );
                                append_process_attribution_tags(&mut tags, Some(&envelope));
                                event = event.with_traffic_envelope(envelope);
                            }
                            if !tags.is_empty() {
                                event = event.with_tags(tags);
                            }
                            pii_enricher.enrich(&mut event);
                            logger.log(&event);
                        }
                    } else {
                        debug!(
                            host = %host,
                            path = %ws_path,
                            "Skipping non-AI/non-MCP websocket payload from observability"
                        );
                    }
                }
                Message::Binary(data) => {
                    debug!(host = %host, len = data.len(), "WebSocket binary");
                }
                _ => {}
            }
            Some(msg)
        }
    }
}
