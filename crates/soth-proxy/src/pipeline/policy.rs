//! Policy enforcement layer

use super::middleware::{error_response, get_request_id, Layer, LayerResult, RequestContext};
use crate::enforcement::core;
use crate::metrics;
use crate::protocol::{methods, JsonRpcError, JsonRpcMessage, JsonRpcRequest};
use soth_core::types::policy::{PolicyAction, PolicyDecision};
use soth_policy::PolicyEngine;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
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
}

impl PolicyLayer {
    /// Create a new policy layer
    pub fn new(config: PolicyConfig) -> Self {
        Self {
            config,
            engine: Arc::new(RwLock::new(PolicyEngine::new())),
        }
    }

    /// Create with a policy engine
    pub fn with_engine(config: PolicyConfig, engine: PolicyEngine) -> Self {
        Self {
            config,
            engine: Arc::new(RwLock::new(engine)),
        }
    }

    /// Evaluate policy for a request
    async fn evaluate_policy(
        &self,
        ctx: &RequestContext,
        req: &JsonRpcRequest,
    ) -> Result<(PolicyDecision, String, Duration), (String, String, Duration)> {
        let input = core::build_mcp_policy_input(ctx, req);
        let start = std::time::Instant::now();
        let engine = self.engine.read().await;
        let fallback_version = engine.active_policy_version();
        match core::evaluate_policy(&engine, &input) {
            Ok((decision, policy_version)) => Ok((decision, policy_version, start.elapsed())),
            Err(e) => Err((e, fallback_version, start.elapsed())),
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
            let (decision, policy_version, eval_duration) =
                match self.evaluate_policy(ctx, req).await {
                    Ok((decision, policy_version, eval_duration)) => {
                        metrics::record_policy_evaluation("success", eval_duration);
                        metrics::set_policy_active_version(&policy_version);
                        (decision, policy_version, eval_duration)
                    }
                    Err((error, policy_version, eval_duration)) => {
                        warn!("Policy evaluation error: {}", error);
                        metrics::record_policy_evaluation("error", eval_duration);
                        metrics::set_policy_active_version(&policy_version);
                        ctx.metadata
                            .insert("policy_action".to_string(), serde_json::json!("error"));
                        ctx.metadata.insert(
                            "policy_reason".to_string(),
                            serde_json::json!(format!("Policy evaluation error: {error}")),
                        );
                        ctx.metadata.insert(
                            "policy_version".to_string(),
                            serde_json::json!(policy_version.clone()),
                        );

                        if self.config.mode == PolicyMode::Audit {
                            return LayerResult::Continue(message);
                        }

                        let id = get_request_id(&message);
                        return error_response(
                            id,
                            JsonRpcError::policy_denied("Policy evaluation failed (enforce mode)"),
                        );
                    }
                };

            if self.config.log_evaluations {
                debug!(
                    "Policy evaluation: method={} action={:?} reason={:?} version={} duration_ms={}",
                    req.method,
                    decision.action,
                    decision.reason,
                    policy_version,
                    eval_duration.as_millis()
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
                PolicyAction::Allow => LayerResult::Continue(message),
                PolicyAction::Deny => {
                    let reason = core::decision_reason(&decision, "Policy denied");

                    if self.config.mode == PolicyMode::Audit {
                        warn!("Policy violation (audit mode): {}", reason);
                        return LayerResult::Continue(message);
                    }

                    info!("Request blocked by policy: {}", reason);
                    let id = get_request_id(&message);
                    error_response(id, JsonRpcError::policy_denied(&reason))
                }
                PolicyAction::Log => {
                    if let Some(reason) = &decision.reason {
                        info!("Policy log: {}", reason);
                    }
                    LayerResult::Continue(message)
                }
                PolicyAction::Redact => {
                    // For redaction, we'd need to modify the message
                    // For now, just log and continue
                    warn!("Redaction requested but not implemented");
                    LayerResult::Continue(message)
                }
                PolicyAction::RateLimit => {
                    // Rate limiting would need a separate tracking mechanism
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
    use std::collections::HashMap;

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

    #[tokio::test]
    async fn test_policy_layer_enforce_fails_closed_on_eval_error() {
        let engine = PolicyEngine::new();
        engine
            .load_modules(HashMap::from([(
                "invalid_runtime".to_string(),
                "package mcp.policy".to_string(),
            )]))
            .unwrap();
        let layer = PolicyLayer::with_engine(
            PolicyConfig {
                mode: PolicyMode::Enforce,
                ..Default::default()
            },
            engine,
        );

        let mut ctx = RequestContext::new("session-1");
        let msg = JsonRpcMessage::Request(JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({"name": "safe_tool"})),
            RequestId::Number(1),
        ));

        let result = layer.process(&mut ctx, msg).await;
        assert!(matches!(result, LayerResult::Response(_)));
        assert_eq!(
            ctx.metadata
                .get("policy_action")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
            "error"
        );
    }

    #[tokio::test]
    async fn test_policy_layer_audit_allows_on_eval_error() {
        let engine = PolicyEngine::new();
        engine
            .load_modules(HashMap::from([(
                "invalid_runtime".to_string(),
                "package mcp.policy".to_string(),
            )]))
            .unwrap();
        let layer = PolicyLayer::with_engine(
            PolicyConfig {
                mode: PolicyMode::Audit,
                ..Default::default()
            },
            engine,
        );

        let mut ctx = RequestContext::new("session-1");
        let msg = JsonRpcMessage::Request(JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({"name": "safe_tool"})),
            RequestId::Number(1),
        ));

        let result = layer.process(&mut ctx, msg).await;
        assert!(matches!(result, LayerResult::Continue(_)));
        assert_eq!(
            ctx.metadata
                .get("policy_action")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
            "error"
        );
    }
}
