//! Core pipeline middleware types and builder

use crate::error::ProxyError;
use crate::protocol::{JsonRpcMessage, JsonRpcResponse, JsonRpcError, RequestId};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Per-layer timing measurements
#[derive(Debug, Clone, Default)]
pub struct LayerTimings {
    /// Identity layer processing time in nanoseconds
    pub identity_ns: Option<u64>,
    /// Policy layer processing time in nanoseconds
    pub policy_ns: Option<u64>,
    /// Observe layer processing time in nanoseconds
    pub observe_ns: Option<u64>,
    /// Budget layer processing time in nanoseconds
    pub budget_ns: Option<u64>,
    /// Custom layer timings by name
    pub custom: std::collections::HashMap<String, u64>,
}

impl LayerTimings {
    /// Create new empty timings
    pub fn new() -> Self {
        Self::default()
    }

    /// Record timing for a layer
    pub fn record(&mut self, layer_name: &str, duration_ns: u64) {
        match layer_name {
            "identity" => self.identity_ns = Some(duration_ns),
            "policy" => self.policy_ns = Some(duration_ns),
            "observe" => self.observe_ns = Some(duration_ns),
            "budget" => self.budget_ns = Some(duration_ns),
            _ => {
                self.custom.insert(layer_name.to_string(), duration_ns);
            }
        }
    }

    /// Get total processing time in nanoseconds
    pub fn total_ns(&self) -> u64 {
        let mut total = 0u64;
        if let Some(ns) = self.identity_ns {
            total += ns;
        }
        if let Some(ns) = self.policy_ns {
            total += ns;
        }
        if let Some(ns) = self.observe_ns {
            total += ns;
        }
        if let Some(ns) = self.budget_ns {
            total += ns;
        }
        for ns in self.custom.values() {
            total += ns;
        }
        total
    }

    /// Get total processing time in microseconds
    pub fn total_us(&self) -> f64 {
        self.total_ns() as f64 / 1000.0
    }

    /// Format as a human-readable breakdown
    pub fn format_breakdown(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ns) = self.identity_ns {
            parts.push(format!("identity={:.1}us", ns as f64 / 1000.0));
        }
        if let Some(ns) = self.policy_ns {
            parts.push(format!("policy={:.1}us", ns as f64 / 1000.0));
        }
        if let Some(ns) = self.observe_ns {
            parts.push(format!("observe={:.1}us", ns as f64 / 1000.0));
        }
        if let Some(ns) = self.budget_ns {
            parts.push(format!("budget={:.1}us", ns as f64 / 1000.0));
        }
        for (name, ns) in &self.custom {
            parts.push(format!("{}={:.1}us", name, *ns as f64 / 1000.0));
        }
        if parts.is_empty() {
            "no timings".to_string()
        } else {
            parts.join(", ")
        }
    }
}

/// Request context passed through the pipeline
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Session ID
    pub session_id: String,
    /// Agent ID (if identified)
    pub agent_id: Option<String>,
    /// Request timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Request metadata
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
    /// Whether identity was verified
    pub identity_verified: bool,
    /// DID of the agent (if verified)
    pub agent_did: Option<String>,
    /// Per-layer timing measurements
    pub timings: LayerTimings,
}

impl RequestContext {
    /// Create a new request context
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            agent_id: None,
            timestamp: chrono::Utc::now(),
            metadata: std::collections::HashMap::new(),
            identity_verified: false,
            agent_did: None,
            timings: LayerTimings::new(),
        }
    }

    /// Set the agent ID
    pub fn with_agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Mark identity as verified
    pub fn with_verified_identity(mut self, did: impl Into<String>) -> Self {
        self.identity_verified = true;
        self.agent_did = Some(did.into());
        self
    }
}

/// Result of processing a message through a layer
#[derive(Debug)]
pub enum LayerResult {
    /// Continue to next layer with (possibly modified) message
    Continue(JsonRpcMessage),
    /// Return response immediately, skip remaining layers
    Response(JsonRpcResponse),
    /// Drop the message (no response)
    Drop,
    /// Error occurred
    Error(ProxyError),
}

/// Middleware layer trait
pub trait Layer: Send + Sync {
    /// Process a message through this layer
    fn process<'a>(
        &'a self,
        ctx: &'a mut RequestContext,
        message: JsonRpcMessage,
    ) -> Pin<Box<dyn Future<Output = LayerResult> + Send + 'a>>;

    /// Layer name for debugging
    fn name(&self) -> &'static str;
}

/// Pipeline that chains multiple layers
pub struct Pipeline {
    /// Layers in order of execution
    layers: Vec<Arc<dyn Layer>>,
}

impl Pipeline {
    /// Create a new empty pipeline
    pub fn new() -> Self {
        Self { layers: Vec::new() }
    }

    /// Add a layer to the pipeline
    pub fn add_layer(&mut self, layer: Arc<dyn Layer>) {
        self.layers.push(layer);
    }

    /// Process a message through all layers
    pub async fn process(
        &self,
        ctx: &mut RequestContext,
        mut message: JsonRpcMessage,
    ) -> Result<Option<JsonRpcMessage>, ProxyError> {
        for layer in &self.layers {
            let start = std::time::Instant::now();
            let result = layer.process(ctx, message).await;
            let elapsed = start.elapsed();

            // Record timing for this layer
            ctx.timings.record(layer.name(), elapsed.as_nanos() as u64);

            match result {
                LayerResult::Continue(msg) => {
                    message = msg;
                }
                LayerResult::Response(resp) => {
                    return Ok(Some(JsonRpcMessage::Response(resp)));
                }
                LayerResult::Drop => {
                    return Ok(None);
                }
                LayerResult::Error(e) => {
                    return Err(e);
                }
            }
        }

        Ok(Some(message))
    }

    /// Get the number of layers
    pub fn len(&self) -> usize {
        self.layers.len()
    }

    /// Check if pipeline is empty
    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for constructing pipelines
pub struct PipelineBuilder {
    layers: Vec<Arc<dyn Layer>>,
}

impl PipelineBuilder {
    /// Create a new pipeline builder
    pub fn new() -> Self {
        Self { layers: Vec::new() }
    }

    /// Add a layer
    pub fn layer<L: Layer + 'static>(mut self, layer: L) -> Self {
        self.layers.push(Arc::new(layer));
        self
    }

    /// Add an Arc'd layer
    pub fn layer_arc(mut self, layer: Arc<dyn Layer>) -> Self {
        self.layers.push(layer);
        self
    }

    /// Build the pipeline
    pub fn build(self) -> Pipeline {
        Pipeline {
            layers: self.layers,
        }
    }
}

impl Default for PipelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to create error responses
pub fn error_response(id: RequestId, error: JsonRpcError) -> LayerResult {
    LayerResult::Response(JsonRpcResponse::error(id, error))
}

/// Extract request ID from a message
pub fn get_request_id(message: &JsonRpcMessage) -> RequestId {
    match message {
        JsonRpcMessage::Request(req) => req.id.clone().unwrap_or(RequestId::Null),
        JsonRpcMessage::Response(resp) => resp.id.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestLayer {
        name: &'static str,
    }

    impl Layer for TestLayer {
        fn process<'a>(
            &'a self,
            _ctx: &'a mut RequestContext,
            message: JsonRpcMessage,
        ) -> Pin<Box<dyn Future<Output = LayerResult> + Send + 'a>> {
            Box::pin(async move { LayerResult::Continue(message) })
        }

        fn name(&self) -> &'static str {
            self.name
        }
    }

    #[test]
    fn test_pipeline_builder() {
        let pipeline = PipelineBuilder::new()
            .layer(TestLayer { name: "layer1" })
            .layer(TestLayer { name: "layer2" })
            .build();

        assert_eq!(pipeline.len(), 2);
    }

    #[test]
    fn test_request_context() {
        let ctx = RequestContext::new("session-1")
            .with_agent_id("agent-1")
            .with_metadata("key", serde_json::json!("value"));

        assert_eq!(ctx.session_id, "session-1");
        assert_eq!(ctx.agent_id, Some("agent-1".to_string()));
        assert!(ctx.metadata.contains_key("key"));
    }
}
