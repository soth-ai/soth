//! Budget tracking layer

use super::middleware::{error_response, get_request_id, Layer, LayerResult, RequestContext};
use crate::enforcement::core;
use crate::protocol::{methods, JsonRpcError, JsonRpcMessage, JsonRpcRequest};
use soth_budget::{BudgetTracker, CostCalculator};
use soth_dashboard::{BudgetAlert, DashboardState};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Budget layer configuration
#[derive(Debug, Clone)]
pub struct BudgetConfig {
    /// Whether budget tracking is enabled
    pub enabled: bool,
    /// Whether to block on budget exceeded
    pub block_on_exceeded: bool,
    /// Default model for cost calculation
    pub default_model: String,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_on_exceeded: true,
            default_model: "gpt-4o".to_string(),
        }
    }
}

/// Budget tracking layer
pub struct BudgetLayer {
    /// Configuration
    config: BudgetConfig,
    /// Budget tracker
    tracker: Arc<RwLock<BudgetTracker>>,
    /// Cost calculator
    calculator: CostCalculator,
    /// Dashboard state for metrics (optional)
    dashboard: Option<DashboardState>,
}

impl BudgetLayer {
    /// Create a new budget layer
    pub fn new(config: BudgetConfig) -> Self {
        Self {
            config,
            tracker: Arc::new(RwLock::new(BudgetTracker::new())),
            calculator: CostCalculator::new(),
            dashboard: None,
        }
    }

    /// Create with a budget tracker
    pub fn with_tracker(config: BudgetConfig, tracker: BudgetTracker) -> Self {
        Self {
            config,
            tracker: Arc::new(RwLock::new(tracker)),
            calculator: CostCalculator::new(),
            dashboard: None,
        }
    }

    /// Set dashboard state for metrics reporting
    pub fn with_dashboard(mut self, state: DashboardState) -> Self {
        self.dashboard = Some(state);
        self
    }

    /// Get the budget tracker
    pub fn tracker(&self) -> Arc<RwLock<BudgetTracker>> {
        Arc::clone(&self.tracker)
    }

    /// Set global budget limits
    pub async fn set_global_budget(
        &self,
        daily: Option<f64>,
        weekly: Option<f64>,
        monthly: Option<f64>,
    ) {
        let tracker = self.tracker.read().await;
        tracker.set_global_budget(daily, weekly, monthly);
    }

    /// Set agent budget limits
    pub async fn set_agent_budget(
        &self,
        agent_id: &str,
        daily: Option<f64>,
        weekly: Option<f64>,
        monthly: Option<f64>,
    ) {
        let tracker = self.tracker.read().await;
        tracker.set_agent_budget(agent_id, daily, weekly, monthly);
    }

    /// Extract model name from message or context
    fn extract_model(&self, ctx: &RequestContext, req: &JsonRpcRequest) -> String {
        // Try to extract model from sampling request
        if req.method == methods::SAMPLING_CREATE_MESSAGE {
            if let Some(ref params) = req.params {
                if let Some(model) = params.get("model").and_then(|v| v.as_str()) {
                    return model.to_string();
                }
            }
        }

        // Try to get from context metadata
        if let Some(model) = ctx.metadata.get("model").and_then(|v| v.as_str()) {
            return model.to_string();
        }

        // Use default
        self.config.default_model.clone()
    }

    /// Record spend for a request/response pair
    async fn record_spend(
        &self,
        ctx: &RequestContext,
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
    ) {
        let tracker = self.tracker.read().await;
        core::record_budget_spend(
            &tracker,
            &ctx.session_id,
            ctx.agent_id.as_deref(),
            model,
            input_tokens,
            output_tokens,
        );
        let estimated_cost =
            self.calculator
                .calculate_cost_tokens(model, input_tokens, output_tokens);

        debug!(
            "Recorded spend: session={} agent={:?} model={} cost=${:.4}",
            ctx.session_id, ctx.agent_id, model, estimated_cost
        );
    }

    /// Check if budget is exceeded
    async fn is_budget_exceeded(&self, ctx: &RequestContext) -> bool {
        let tracker = self.tracker.read().await;
        core::is_budget_exceeded(&tracker, ctx.agent_id.as_deref())
    }
}

impl Layer for BudgetLayer {
    fn process<'a>(
        &'a self,
        ctx: &'a mut RequestContext,
        message: JsonRpcMessage,
    ) -> Pin<Box<dyn Future<Output = LayerResult> + Send + 'a>> {
        Box::pin(async move {
            // Skip if disabled
            if !self.config.enabled {
                return LayerResult::Continue(message);
            }

            match &message {
                JsonRpcMessage::Request(req) => {
                    // Check budget before processing
                    if self.config.block_on_exceeded && self.is_budget_exceeded(ctx).await {
                        warn!(
                            "Budget exceeded for session={} agent={:?}",
                            ctx.session_id, ctx.agent_id
                        );

                        // Record alert to dashboard
                        if let Some(ref dash) = self.dashboard {
                            dash.set_budget_alert(BudgetAlert {
                                level: "error".to_string(),
                                message: "Budget limit exceeded - requests blocked".to_string(),
                            });
                        }

                        let id = get_request_id(&message);
                        return error_response(
                            id,
                            JsonRpcError::budget_exceeded("Budget limit reached"),
                        );
                    }

                    // Count input tokens
                    let content = serde_json::to_value(req).unwrap_or_default();
                    let input_tokens = core::estimate_mcp_tokens(&content);

                    ctx.metadata.insert(
                        "budget_input_tokens".to_string(),
                        serde_json::json!(input_tokens),
                    );

                    // Store model for later
                    let model = self.extract_model(ctx, req);
                    ctx.metadata
                        .insert("budget_model".to_string(), serde_json::json!(model));

                    LayerResult::Continue(message)
                }
                JsonRpcMessage::Response(resp) => {
                    // Count output tokens and record spend
                    let content = serde_json::to_value(resp).unwrap_or_default();
                    let output_tokens = core::estimate_mcp_tokens(&content);

                    // Get input tokens and model from context
                    let input_tokens = ctx
                        .metadata
                        .get("budget_input_tokens")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);

                    let model = ctx
                        .metadata
                        .get("budget_model")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| self.config.default_model.clone());

                    // Record the spend
                    self.record_spend(ctx, &model, input_tokens, output_tokens)
                        .await;

                    // Calculate cost for metadata
                    let cost =
                        self.calculator
                            .calculate_cost_tokens(&model, input_tokens, output_tokens);
                    ctx.metadata
                        .insert("budget_cost".to_string(), serde_json::json!(cost));

                    // Record to dashboard
                    if let Some(ref dash) = self.dashboard {
                        let total_tokens = input_tokens + output_tokens;
                        dash.record_token_usage(&model, total_tokens, cost);
                    }

                    LayerResult::Continue(message)
                }
            }
        })
    }

    fn name(&self) -> &'static str {
        "budget"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::RequestId;

    #[tokio::test]
    async fn test_budget_layer_disabled() {
        let layer = BudgetLayer::new(BudgetConfig {
            enabled: false,
            ..Default::default()
        });

        let mut ctx = RequestContext::new("session-1");
        let msg = JsonRpcMessage::Request(JsonRpcRequest::new(
            "tools/call",
            None,
            RequestId::Number(1),
        ));

        let result = layer.process(&mut ctx, msg).await;
        assert!(matches!(result, LayerResult::Continue(_)));
    }

    #[tokio::test]
    async fn test_budget_layer_tracks_tokens() {
        let layer = BudgetLayer::new(BudgetConfig::default());

        let mut ctx = RequestContext::new("session-1");
        let msg = JsonRpcMessage::Request(JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({"name": "test", "arguments": {"key": "value"}})),
            RequestId::Number(1),
        ));

        let result = layer.process(&mut ctx, msg).await;
        assert!(matches!(result, LayerResult::Continue(_)));
        assert!(ctx.metadata.contains_key("budget_input_tokens"));
    }

    #[tokio::test]
    async fn test_budget_layer_blocks_on_exceeded() {
        let layer = BudgetLayer::new(BudgetConfig {
            enabled: true,
            block_on_exceeded: true,
            ..Default::default()
        });

        // Set a very low budget
        layer.set_global_budget(Some(0.0), None, None).await;

        // Record some spend to exceed the budget
        {
            let tracker = layer.tracker.read().await;
            for _ in 0..10 {
                tracker.record_spend("session-1", None, "gpt-4o", 1_000_000, 500_000);
            }
        }

        let mut ctx = RequestContext::new("session-1");
        let msg = JsonRpcMessage::Request(JsonRpcRequest::new(
            "tools/call",
            None,
            RequestId::Number(1),
        ));

        let result = layer.process(&mut ctx, msg).await;
        assert!(matches!(result, LayerResult::Response(_)));
    }
}
