//! Policy enforcement layer

use super::middleware::{error_response, get_request_id, Layer, LayerResult, RequestContext};
use crate::protocol::{methods, JsonRpcError, JsonRpcMessage, JsonRpcRequest};
use soth_core::types::policy::{PolicyAction, PolicyDecision, PolicyInput, PolicyInputBuilder};
use soth_dashboard::{DashboardState, DenialEntry};
use soth_policy::PolicyEngine;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Policy enforcement mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMode {
    /// Policy evaluation is disabled
    Disabled,
    /// Audit mode - log violations but don't block
    Audit,
    /// Enforce mode - block policy violations
    Enforce,
}

impl Default for PolicyMode {
    fn default() -> Self {
        Self::Enforce
    }
}

/// Policy layer configuration
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    /// Enforcement mode
    pub mode: PolicyMode,
    /// Whether to log all policy evaluations
    pub log_evaluations: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            mode: PolicyMode::Enforce,
            log_evaluations: true,
        }
    }
}

/// Policy enforcement layer
pub struct PolicyLayer {
    /// Configuration
    config: PolicyConfig,
    /// Policy engine
    engine: Arc<RwLock<PolicyEngine>>,
    /// Dashboard state for metrics (optional)
    dashboard: Option<DashboardState>,
}

impl PolicyLayer {
    /// Create a new policy layer
    pub fn new(config: PolicyConfig) -> Self {
        Self {
            config,
            engine: Arc::new(RwLock::new(PolicyEngine::new())),
            dashboard: None,
        }
    }

    /// Create with a policy engine
    pub fn with_engine(config: PolicyConfig, engine: PolicyEngine) -> Self {
        Self {
            config,
            engine: Arc::new(RwLock::new(engine)),
            dashboard: None,
        }
    }

    /// Set dashboard state for metrics reporting
    pub fn with_dashboard(mut self, state: DashboardState) -> Self {
        self.dashboard = Some(state);
        self
    }

    /// Build policy input from request context and message
    fn build_policy_input(ctx: &RequestContext, req: &JsonRpcRequest) -> PolicyInput {
        let mut builder = PolicyInputBuilder::new()
            .session_id(&ctx.session_id)
            .method(&req.method)
            .timestamp(ctx.timestamp);

        // Add agent info if available
        if let Some(ref agent_id) = ctx.agent_id {
            builder = builder.agent_id(agent_id);
        }

        // Add identity info
        if ctx.identity_verified {
            builder = builder.identity_verified(true);
            if let Some(ref did) = ctx.agent_did {
                builder = builder.identity_did(did);
            }
        }

        // Extract tool/resource info from params
        if let Some(ref params) = req.params {
            // Tool call
            if req.method == methods::TOOLS_CALL {
                if let Some(name) = params.get("name").and_then(|v| v.as_str()) {
                    builder = builder.tool(name);
                }
                if let Some(args) = params.get("arguments") {
                    builder = builder.arguments_json(args.clone());
                }
            }

            // Resource read
            if req.method == methods::RESOURCES_READ {
                if let Some(uri) = params.get("uri").and_then(|v| v.as_str()) {
                    builder = builder.resource(uri);
                }
            }
        }

        builder.build()
    }

    /// Evaluate policy for a request
    async fn evaluate_policy(
        &self,
        ctx: &RequestContext,
        req: &JsonRpcRequest,
    ) -> (PolicyDecision, String) {
        let input = Self::build_policy_input(ctx, req);
        let engine = self.engine.read().await;
        match engine.evaluate(&input) {
            Ok(result) => (result.decision, result.policy_version),
            Err(e) => {
                warn!("Policy evaluation error: {}", e);
                // On error, default to deny in enforce mode, allow otherwise
                (
                    PolicyDecision::deny_with_reason(format!("Policy evaluation error: {e}")),
                    "runtime_error".to_string(),
                )
            }
        }
    }
}

impl Layer for PolicyLayer {
    fn process<'a>(
        &'a self,
        ctx: &'a mut RequestContext,
        message: JsonRpcMessage,
    ) -> Pin<Box<dyn Future<Output = LayerResult> + Send + 'a>> {
        Box::pin(async move {
            // Skip if disabled
            if self.config.mode == PolicyMode::Disabled {
                return LayerResult::Continue(message);
            }

            // Only evaluate requests (not responses)
            let req = match &message {
                JsonRpcMessage::Request(req) => req,
                JsonRpcMessage::Response(_) => {
                    return LayerResult::Continue(message);
                }
            };

            // Skip policy for certain methods
            let method = &req.method;
            if method == methods::INITIALIZE
                || method == methods::INITIALIZED
                || method == methods::PING
            {
                return LayerResult::Continue(message);
            }

            // Evaluate policy
            let (decision, policy_version) = self.evaluate_policy(ctx, req).await;

            if self.config.log_evaluations {
                debug!(
                    "Policy evaluation: method={} action={:?} reason={:?} version={}",
                    req.method, decision.action, decision.reason, policy_version
                );
            }

            // Add policy metadata to context
            ctx.metadata.insert(
                "policy_action".to_string(),
                serde_json::json!(format!("{:?}", decision.action)),
            );
            if let Some(ref reason) = decision.reason {
                ctx.metadata
                    .insert("policy_reason".to_string(), serde_json::json!(reason));
            }
            ctx.metadata.insert(
                "policy_version".to_string(),
                serde_json::json!(policy_version.clone()),
            );

            match decision.action {
                PolicyAction::Allow => {
                    // Record allowed to dashboard
                    if let Some(ref dash) = self.dashboard {
                        dash.set_policy_active_version(policy_version.clone());
                        dash.record_policy_evaluation(true, None);
                    }
                    LayerResult::Continue(message)
                }
                PolicyAction::Deny => {
                    // Use reason if set, otherwise join violations, otherwise default
                    let reason = decision
                        .reason
                        .or_else(|| {
                            if !decision.violations.is_empty() {
                                Some(decision.violations.join("; "))
                            } else {
                                None
                            }
                        })
                        .unwrap_or_else(|| "Policy denied".to_string());

                    // Record denial to dashboard
                    if let Some(ref dash) = self.dashboard {
                        dash.set_policy_active_version(policy_version.clone());
                        let tool = req
                            .params
                            .as_ref()
                            .and_then(|p| p.get("name"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        dash.record_policy_evaluation(
                            false,
                            Some(DenialEntry {
                                timestamp: chrono::Utc::now().to_rfc3339(),
                                method: req.method.clone(),
                                tool,
                                reason: reason.clone(),
                            }),
                        );
                    }

                    if self.config.mode == PolicyMode::Audit {
                        warn!("Policy violation (audit mode): {}", reason);
                        return LayerResult::Continue(message);
                    }

                    info!("Request blocked by policy: {}", reason);
                    let id = get_request_id(&message);
                    error_response(id, JsonRpcError::policy_denied(&reason))
                }
                PolicyAction::Log => {
                    // Record as allowed for logging action
                    if let Some(ref dash) = self.dashboard {
                        dash.set_policy_active_version(policy_version.clone());
                        dash.record_policy_evaluation(true, None);
                    }
                    if let Some(reason) = &decision.reason {
                        info!("Policy log: {}", reason);
                    }
                    LayerResult::Continue(message)
                }
                PolicyAction::Redact => {
                    // For redaction, we'd need to modify the message
                    // For now, just log and continue
                    if let Some(ref dash) = self.dashboard {
                        dash.set_policy_active_version(policy_version.clone());
                        dash.record_policy_evaluation(true, None);
                    }
                    warn!("Redaction requested but not implemented");
                    LayerResult::Continue(message)
                }
                PolicyAction::RateLimit => {
                    // Rate limiting would need a separate tracking mechanism
                    if let Some(ref dash) = self.dashboard {
                        dash.set_policy_active_version(policy_version.clone());
                        dash.record_policy_evaluation(true, None);
                    }
                    warn!("Rate limiting requested but not implemented");
                    LayerResult::Continue(message)
                }
            }
        })
    }

    fn name(&self) -> &'static str {
        "policy"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::RequestId;

    #[tokio::test]
    async fn test_policy_layer_disabled() {
        let layer = PolicyLayer::new(PolicyConfig {
            mode: PolicyMode::Disabled,
            ..Default::default()
        });

        let mut ctx = RequestContext::new("session-1");
        let msg = JsonRpcMessage::Request(JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({"name": "dangerous_tool"})),
            RequestId::Number(1),
        ));

        let result = layer.process(&mut ctx, msg).await;
        assert!(matches!(result, LayerResult::Continue(_)));
    }

    #[tokio::test]
    async fn test_policy_layer_skip_initialize() {
        let layer = PolicyLayer::new(PolicyConfig::default());

        let mut ctx = RequestContext::new("session-1");
        let msg = JsonRpcMessage::Request(JsonRpcRequest::new(
            methods::INITIALIZE,
            None,
            RequestId::Number(1),
        ));

        let result = layer.process(&mut ctx, msg).await;
        assert!(matches!(result, LayerResult::Continue(_)));
    }

    #[tokio::test]
    async fn test_policy_layer_responses_pass_through() {
        let layer = PolicyLayer::new(PolicyConfig::default());

        let mut ctx = RequestContext::new("session-1");
        let msg = JsonRpcMessage::Response(crate::protocol::JsonRpcResponse::success(
            RequestId::Number(1),
            serde_json::json!({"status": "ok"}),
        ));

        let result = layer.process(&mut ctx, msg).await;
        assert!(matches!(result, LayerResult::Continue(_)));
    }
}
