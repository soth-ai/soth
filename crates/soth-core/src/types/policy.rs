//! Policy types for SOTH
//!
//! Defines policy input and decision types for OPA evaluation.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use crate::types::identity::{AgentContext, IdentityContext};

/// Policy input structure sent to OPA for evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInput {
    /// Agent context
    pub agent: AgentContext,

    /// Request context
    pub request: RequestContext,

    /// Session context
    pub session: SessionContext,

    /// Identity context
    pub identity: IdentityContext,

    /// Environment context
    pub context: EnvironmentContext,
}

impl PolicyInput {
    /// Create a new policy input builder
    pub fn builder() -> PolicyInputBuilder {
        PolicyInputBuilder::new()
    }
}

/// Request context for policy evaluation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestContext {
    /// JSON-RPC method name
    pub method: String,

    /// Tool name (for tools/call)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,

    /// Request arguments
    #[serde(default)]
    pub arguments: HashMap<String, serde_json::Value>,

    /// Inferred intent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
}

/// Session context for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionContext {
    /// Session identifier
    pub id: String,

    /// Number of requests in this session
    pub request_count: u64,

    /// Session start time
    pub started_at: DateTime<Utc>,

    /// Cumulative read operations
    #[serde(default)]
    pub cumulative_reads: u64,

    /// Cumulative write operations
    #[serde(default)]
    pub cumulative_writes: u64,
}

impl Default for SessionContext {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            request_count: 0,
            started_at: Utc::now(),
            cumulative_reads: 0,
            cumulative_writes: 0,
        }
    }
}

/// Environment context for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentContext {
    /// Current timestamp
    pub timestamp: DateTime<Utc>,

    /// Source IP address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,

    /// Environment: development, staging, production
    pub environment: String,

    /// Proxy region
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_region: Option<String>,
}

impl Default for EnvironmentContext {
    fn default() -> Self {
        Self {
            timestamp: Utc::now(),
            source_ip: None,
            environment: "development".to_string(),
            proxy_region: None,
        }
    }
}

/// Policy action to take
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    /// Allow the request
    #[default]
    Allow,
    /// Deny the request
    Deny,
    /// Log and continue
    Log,
    /// Redact sensitive data
    Redact,
    /// Rate limit the request
    RateLimit,
}

/// Policy decision returned from OPA
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// Whether the request is allowed
    pub allow: bool,

    /// Action to take
    #[serde(default)]
    pub action: PolicyAction,

    /// Reason for the decision
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// List of policy violations
    #[serde(default)]
    pub violations: Vec<String>,

    /// The rule that matched
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,

    /// Obligations to fulfill
    #[serde(default)]
    pub obligations: Vec<PolicyObligation>,
}

impl PolicyDecision {
    /// Create an allow decision
    pub fn allow() -> Self {
        Self {
            allow: true,
            action: PolicyAction::Allow,
            ..Default::default()
        }
    }

    /// Create a deny decision
    pub fn deny(violations: Vec<String>) -> Self {
        Self {
            allow: false,
            action: PolicyAction::Deny,
            violations,
            ..Default::default()
        }
    }

    /// Create a deny decision with reason
    pub fn deny_with_reason(reason: impl Into<String>) -> Self {
        Self {
            allow: false,
            action: PolicyAction::Deny,
            reason: Some(reason.into()),
            ..Default::default()
        }
    }

    /// Create an allow decision with obligations
    pub fn allow_with_obligations(obligations: Vec<PolicyObligation>) -> Self {
        Self {
            allow: true,
            action: PolicyAction::Allow,
            obligations,
            ..Default::default()
        }
    }

    /// Create a log decision
    pub fn log(reason: impl Into<String>) -> Self {
        Self {
            allow: true,
            action: PolicyAction::Log,
            reason: Some(reason.into()),
            ..Default::default()
        }
    }
}

/// Policy obligation to be fulfilled
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyObligation {
    /// Action type: log, alert, rate_limit
    pub action: String,

    /// Action parameters
    #[serde(default)]
    pub params: HashMap<String, String>,
}

/// Policy evaluation result with metadata
#[derive(Debug, Clone)]
pub struct EvaluationResult {
    /// The policy decision
    pub decision: PolicyDecision,

    /// The input that was evaluated
    pub input: PolicyInput,

    /// Evaluation duration
    pub eval_time: std::time::Duration,

    /// Whether result was from cache
    pub cache_hit: bool,

    /// Cache tier: "L1", "L2", or empty
    pub cache_tier: String,

    /// Policy mode: "audit" or "enforce"
    pub policy_mode: String,
}

/// Builder for constructing PolicyInput
#[derive(Debug, Default)]
pub struct PolicyInputBuilder {
    agent: AgentContext,
    request: RequestContext,
    session: SessionContext,
    identity: IdentityContext,
    context: EnvironmentContext,
}

impl PolicyInputBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set agent context
    pub fn agent(mut self, agent: AgentContext) -> Self {
        self.agent = agent;
        self
    }

    /// Set agent by ID
    pub fn agent_id(mut self, id: impl Into<String>) -> Self {
        self.agent.id = id.into();
        self
    }

    /// Set request method
    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.request.method = method.into();
        self
    }

    /// Set tool name
    pub fn tool(mut self, tool: impl Into<String>) -> Self {
        self.request.tool = Some(tool.into());
        self
    }

    /// Set request arguments
    pub fn arguments(mut self, arguments: HashMap<String, serde_json::Value>) -> Self {
        self.request.arguments = arguments;
        self
    }

    /// Set session context
    pub fn session(mut self, session: SessionContext) -> Self {
        self.session = session;
        self
    }

    /// Set session ID
    pub fn session_id(mut self, id: impl Into<String>) -> Self {
        self.session.id = id.into();
        self
    }

    /// Set identity context
    pub fn identity(mut self, identity: IdentityContext) -> Self {
        self.identity = identity;
        self
    }

    /// Set environment
    pub fn environment(mut self, env: impl Into<String>) -> Self {
        self.context.environment = env.into();
        self
    }

    /// Set source IP
    pub fn source_ip(mut self, ip: impl Into<String>) -> Self {
        self.context.source_ip = Some(ip.into());
        self
    }

    /// Set timestamp
    pub fn timestamp(mut self, ts: DateTime<Utc>) -> Self {
        self.context.timestamp = ts;
        self
    }

    /// Set identity verified flag
    pub fn identity_verified(mut self, verified: bool) -> Self {
        self.identity.verified = verified;
        self
    }

    /// Set identity DID
    pub fn identity_did(mut self, did: impl Into<String>) -> Self {
        self.identity.did = Some(did.into());
        self
    }

    /// Set request arguments from JSON value
    pub fn arguments_json(mut self, args: serde_json::Value) -> Self {
        if let serde_json::Value::Object(map) = args {
            self.request.arguments = map.into_iter().collect();
        }
        self
    }

    /// Set resource URI
    pub fn resource(mut self, uri: impl Into<String>) -> Self {
        self.request.intent = Some(format!("access:{}", uri.into()));
        self
    }

    /// Build the PolicyInput
    pub fn build(self) -> PolicyInput {
        PolicyInput {
            agent: self.agent,
            request: self.request,
            session: self.session,
            identity: self.identity,
            context: self.context,
        }
    }
}

/// Runtime policy data loaded from JSON
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyData {
    /// Map of tool to required capability
    #[serde(default)]
    pub tool_capabilities: HashMap<String, String>,

    /// Rate limits per agent/tool
    #[serde(default)]
    pub rate_limits: HashMap<String, u32>,

    /// Blocked tools
    #[serde(default)]
    pub blocked_tools: Vec<String>,

    /// Blocked agents
    #[serde(default)]
    pub blocked_agents: Vec<String>,

    /// Blocked DIDs
    #[serde(default)]
    pub blocked_dids: Vec<String>,

    /// Allowed DIDs (empty = allow all)
    #[serde(default)]
    pub allowed_dids: Vec<String>,

    /// Trusted publishers
    #[serde(default)]
    pub trusted_publishers: Vec<String>,

    /// Tools that require identity verification
    #[serde(default)]
    pub identity_required_tools: Vec<String>,

    /// Tools that may handle PII
    #[serde(default)]
    pub pii_tools: Vec<String>,

    /// Models blocked from PII access
    #[serde(default)]
    pub blocked_models_for_pii: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_input_builder() {
        let input = PolicyInput::builder()
            .agent_id("agent-1")
            .method("tools/call")
            .tool("read_file")
            .session_id("session-1")
            .environment("production")
            .build();

        assert_eq!(input.agent.id, "agent-1");
        assert_eq!(input.request.method, "tools/call");
        assert_eq!(input.request.tool, Some("read_file".to_string()));
        assert_eq!(input.context.environment, "production");
    }

    #[test]
    fn test_policy_decision_allow() {
        let decision = PolicyDecision::allow();
        assert!(decision.allow);
        assert!(decision.violations.is_empty());
    }

    #[test]
    fn test_policy_decision_deny() {
        let decision = PolicyDecision::deny(vec!["blocked_tool".to_string()]);
        assert!(!decision.allow);
        assert_eq!(decision.violations, vec!["blocked_tool"]);
    }
}
