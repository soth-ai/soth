//! Observation/logging layer

use super::middleware::{Layer, LayerResult, RequestContext};
use crate::protocol::{JsonRpcMessage, JsonRpcRequest, JsonRpcResponse};
use soth_budget::TokenCounter;
use soth_core::types::observation::{Direction, EventType, ObservationEvent};
use soth_observe::{ObservationLogger, PiiDetector, PiiRedactor};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tracing::debug;

/// Observation layer configuration
#[derive(Debug, Clone)]
pub struct ObserveConfig {
    /// Whether to log requests
    pub log_requests: bool,
    /// Whether to log responses
    pub log_responses: bool,
    /// Whether to detect and redact PII
    pub pii_detection: bool,
    /// Whether to count tokens
    pub count_tokens: bool,
    /// Whether to log to file
    pub log_to_file: bool,
}

impl Default for ObserveConfig {
    fn default() -> Self {
        Self {
            log_requests: true,
            log_responses: true,
            pii_detection: true,
            count_tokens: true,
            log_to_file: true,
        }
    }
}

/// Observation layer for logging and monitoring
pub struct ObserveLayer {
    /// Configuration
    config: ObserveConfig,
    /// PII detector (only instantiated when pii_detection is enabled)
    pii_detector: Option<PiiDetector>,
    /// PII redactor (only instantiated when pii_detection is enabled)
    pii_redactor: Option<PiiRedactor>,
    /// Logger (optional)
    logger: Option<Arc<ObservationLogger>>,
}

impl ObserveLayer {
    /// Create a new observation layer
    pub fn new(config: ObserveConfig) -> Self {
        let (pii_detector, pii_redactor) = if config.pii_detection {
            (Some(PiiDetector::new()), Some(PiiRedactor::new()))
        } else {
            (None, None)
        };
        Self {
            config,
            pii_detector,
            pii_redactor,
            logger: None,
        }
    }

    /// Create with a logger
    pub fn with_logger(config: ObserveConfig, logger: Arc<ObservationLogger>) -> Self {
        let (pii_detector, pii_redactor) = if config.pii_detection {
            (Some(PiiDetector::new()), Some(PiiRedactor::new()))
        } else {
            (None, None)
        };
        Self {
            config,
            pii_detector,
            pii_redactor,
            logger: Some(logger),
        }
    }

    /// Create observation event from request
    fn create_request_event(&self, ctx: &RequestContext, req: &JsonRpcRequest) -> ObservationEvent {
        let event_type = if req.method.starts_with("notifications/") {
            EventType::Notification
        } else {
            EventType::Request
        };

        let mut content_str = serde_json::to_string(req).unwrap_or_default();

        // Detect PII if enabled and detector is available
        let (pii_detected, pii_types) = if let Some(ref detector) = self.pii_detector {
            let findings = detector.detect(&content_str);
            if !findings.is_empty() {
                if let Some(ref redactor) = self.pii_redactor {
                    content_str = redactor.redact(&content_str).text;
                }
                (true, findings.into_iter().map(|f| f.pii_type).collect())
            } else {
                (false, Vec::new())
            }
        } else {
            (false, Vec::new())
        };

        // Count tokens if enabled
        let token_count = if self.config.count_tokens {
            let content_value = serde_json::to_value(req).unwrap_or_default();
            TokenCounter::count_mcp_context_tokens(&content_value)
        } else {
            0
        };

        ObservationEvent::new(&ctx.session_id, Direction::In, event_type, content_str)
            .with_method(&req.method)
            .with_token_count(token_count)
            .with_pii(pii_detected, pii_types)
    }

    /// Create observation event from response
    fn create_response_event(
        &self,
        ctx: &RequestContext,
        resp: &JsonRpcResponse,
    ) -> ObservationEvent {
        let event_type = if resp.error.is_some() {
            EventType::Error
        } else {
            EventType::Response
        };

        let mut content_str = serde_json::to_string(resp).unwrap_or_default();

        // Detect PII if enabled and detector is available
        let (pii_detected, pii_types) = if let Some(ref detector) = self.pii_detector {
            let findings = detector.detect(&content_str);
            if !findings.is_empty() {
                if let Some(ref redactor) = self.pii_redactor {
                    content_str = redactor.redact(&content_str).text;
                }
                (true, findings.into_iter().map(|f| f.pii_type).collect())
            } else {
                (false, Vec::new())
            }
        } else {
            (false, Vec::new())
        };

        let token_count = if self.config.count_tokens {
            let content_value = serde_json::to_value(resp).unwrap_or_default();
            TokenCounter::count_mcp_context_tokens(&content_value)
        } else {
            0
        };

        ObservationEvent::new(&ctx.session_id, Direction::Out, event_type, content_str)
            .with_token_count(token_count)
            .with_pii(pii_detected, pii_types)
    }

    /// Log an event
    async fn log_event(&self, event: ObservationEvent) {
        debug!(
            "Observation: direction={:?} type={:?} method={:?} tokens={}",
            event.direction, event.event_type, event.method, event.token_count
        );

        if let Some(ref logger) = self.logger {
            if !logger.write(event).await {
                tracing::warn!("Failed to log observation");
            }
        }
    }
}

impl Layer for ObserveLayer {
    fn process<'a>(
        &'a self,
        ctx: &'a mut RequestContext,
        message: JsonRpcMessage,
    ) -> Pin<Box<dyn Future<Output = LayerResult> + Send + 'a>> {
        Box::pin(async move {
            match &message {
                JsonRpcMessage::Request(req) => {
                    if self.config.log_requests {
                        let event = self.create_request_event(ctx, req);

                        // Add token count to context for budget tracking
                        ctx.metadata.insert(
                            "input_tokens".to_string(),
                            serde_json::json!(event.token_count),
                        );

                        self.log_event(event).await;
                    }
                }
                JsonRpcMessage::Response(resp) => {
                    if self.config.log_responses {
                        let event = self.create_response_event(ctx, resp);

                        // Add token count to context
                        ctx.metadata.insert(
                            "output_tokens".to_string(),
                            serde_json::json!(event.token_count),
                        );

                        self.log_event(event).await;
                    }
                }
            }

            LayerResult::Continue(message)
        })
    }

    fn name(&self) -> &'static str {
        "observe"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::RequestId;

    #[tokio::test]
    async fn test_observe_layer_request() {
        let layer = ObserveLayer::new(ObserveConfig::default());

        let mut ctx = RequestContext::new("session-1");
        let msg = JsonRpcMessage::Request(JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({"name": "test"})),
            RequestId::Number(1),
        ));

        let result = layer.process(&mut ctx, msg).await;
        assert!(matches!(result, LayerResult::Continue(_)));

        // Token count should be added to context
        assert!(ctx.metadata.contains_key("input_tokens"));
    }

    #[tokio::test]
    async fn test_observe_layer_response() {
        let layer = ObserveLayer::new(ObserveConfig::default());

        let mut ctx = RequestContext::new("session-1");
        let msg = JsonRpcMessage::Response(JsonRpcResponse::success(
            RequestId::Number(1),
            serde_json::json!({"result": "ok"}),
        ));

        let result = layer.process(&mut ctx, msg).await;
        assert!(matches!(result, LayerResult::Continue(_)));
    }

    #[tokio::test]
    async fn test_observe_layer_pii_detection() {
        let layer = ObserveLayer::new(ObserveConfig {
            pii_detection: true,
            ..Default::default()
        });

        let mut ctx = RequestContext::new("session-1");
        let msg = JsonRpcMessage::Request(JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({"text": "My SSN is 123-45-6789"})),
            RequestId::Number(1),
        ));

        let result = layer.process(&mut ctx, msg).await;
        assert!(matches!(result, LayerResult::Continue(_)));
    }

    #[tokio::test]
    async fn test_observe_layer_pii_disabled() {
        // When PII detection is disabled, detector/redactor should be None
        let layer = ObserveLayer::new(ObserveConfig {
            pii_detection: false,
            ..Default::default()
        });

        // Verify internal state: pii_detector and pii_redactor should be None
        assert!(layer.pii_detector.is_none());
        assert!(layer.pii_redactor.is_none());

        // Verify processing still works
        let mut ctx = RequestContext::new("session-1");
        let msg = JsonRpcMessage::Request(JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({"text": "My SSN is 123-45-6789"})),
            RequestId::Number(1),
        ));

        let result = layer.process(&mut ctx, msg).await;
        assert!(matches!(result, LayerResult::Continue(_)));
    }

    #[tokio::test]
    async fn test_observe_layer_pii_enabled() {
        // When PII detection is enabled, detector/redactor should be Some
        let layer = ObserveLayer::new(ObserveConfig {
            pii_detection: true,
            ..Default::default()
        });

        // Verify internal state: pii_detector and pii_redactor should be Some
        assert!(layer.pii_detector.is_some());
        assert!(layer.pii_redactor.is_some());
    }
}
