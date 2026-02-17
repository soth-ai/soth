//! Proxy enforcement model and execution helpers.

use crate::enforcement::core as enforcement_core;
use crate::metrics;
use soth_budget::BudgetTracker;
use soth_core::types::TrafficEnvelope;
use soth_policy::PolicyEngine;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

/// Identity verification mode for proxy enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyIdentityMode {
    Disabled,
    Optional,
    Required,
}

/// Policy mode for proxy enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyPolicyMode {
    Disabled,
    Audit,
    Enforce,
}

/// Request enforcement configuration for proxy transport.
#[derive(Clone)]
pub struct ProxyEnforcer {
    identity_mode: ProxyIdentityMode,
    did_header: String,
    signature_header: String,
    trusted_dids: Arc<HashSet<String>>,
    required_principals: Arc<HashSet<String>>,
    policy_mode: ProxyPolicyMode,
    policy_engine: Option<Arc<PolicyEngine>>,
    policy_fail_open: bool,
    budget_tracker: Option<Arc<BudgetTracker>>,
    budget_block_on_exceeded: bool,
    budget_fail_open: bool,
    default_model: String,
    fail_open_enabled: bool,
    enforcement_timeout: Duration,
}

type EnforcementResult = enforcement_core::IdentityResult;

impl ProxyEnforcer {
    /// Create a default no-op enforcer.
    pub fn new() -> Self {
        Self {
            identity_mode: ProxyIdentityMode::Disabled,
            did_header: "X-Agent-DID".to_string(),
            signature_header: "X-Agent-Signature".to_string(),
            trusted_dids: Arc::new(HashSet::new()),
            required_principals: Arc::new(HashSet::new()),
            policy_mode: ProxyPolicyMode::Disabled,
            policy_engine: None,
            policy_fail_open: true,
            budget_tracker: None,
            budget_block_on_exceeded: true,
            budget_fail_open: true,
            default_model: "gpt-4o".to_string(),
            fail_open_enabled: true,
            enforcement_timeout: Duration::from_millis(500),
        }
    }

    pub fn with_identity_mode(
        mut self,
        mode: ProxyIdentityMode,
        trusted_dids: HashSet<String>,
    ) -> Self {
        self.identity_mode = mode;
        self.trusted_dids = Arc::new(trusted_dids);
        self
    }

    pub fn with_required_principals(mut self, required_principals: HashSet<String>) -> Self {
        self.required_principals = Arc::new(required_principals);
        self
    }

    pub fn with_identity_headers(
        mut self,
        did_header: impl Into<String>,
        signature_header: impl Into<String>,
    ) -> Self {
        self.did_header = did_header.into();
        self.signature_header = signature_header.into();
        self
    }

    pub fn with_policy(mut self, mode: ProxyPolicyMode, engine: PolicyEngine) -> Self {
        self.policy_mode = mode;
        self.policy_engine = Some(Arc::new(engine));
        self
    }

    pub fn with_budget(
        mut self,
        tracker: BudgetTracker,
        block_on_exceeded: bool,
        default_model: impl Into<String>,
    ) -> Self {
        self.budget_tracker = Some(Arc::new(tracker));
        self.budget_block_on_exceeded = block_on_exceeded;
        self.default_model = default_model.into();
        self
    }

    pub fn with_fail_open(
        mut self,
        enabled: bool,
        enforcement_timeout: Duration,
        policy_fail_open: bool,
        budget_fail_open: bool,
    ) -> Self {
        self.fail_open_enabled = enabled;
        self.enforcement_timeout = enforcement_timeout;
        self.policy_fail_open = policy_fail_open;
        self.budget_fail_open = budget_fail_open;
        self
    }

    pub fn did_header(&self) -> &str {
        &self.did_header
    }

    pub fn signature_header(&self) -> &str {
        &self.signature_header
    }

    pub fn policy_engine(&self) -> Option<Arc<PolicyEngine>> {
        self.policy_engine.clone()
    }

    pub fn budget_tracker(&self) -> Option<Arc<BudgetTracker>> {
        self.budget_tracker.clone()
    }

    fn core_identity_mode(&self) -> enforcement_core::IdentityMode {
        match self.identity_mode {
            ProxyIdentityMode::Disabled => enforcement_core::IdentityMode::Disabled,
            ProxyIdentityMode::Optional => enforcement_core::IdentityMode::Optional,
            ProxyIdentityMode::Required => enforcement_core::IdentityMode::Required,
        }
    }

    fn core_policy_mode(&self) -> enforcement_core::PolicyMode {
        match self.policy_mode {
            ProxyPolicyMode::Disabled => enforcement_core::PolicyMode::Disabled,
            ProxyPolicyMode::Audit => enforcement_core::PolicyMode::Audit,
            ProxyPolicyMode::Enforce => enforcement_core::PolicyMode::Enforce,
        }
    }

    pub fn enforce_envelope(
        &self,
        envelope: &TrafficEnvelope,
    ) -> Result<EnforcementResult, (u16, String, Option<String>)> {
        let result = enforcement_core::enforce_proxy_request(
            enforcement_core::ProxyEnforcementConfig {
                identity_mode: self.core_identity_mode(),
                trusted_dids: self.trusted_dids.as_ref(),
                required_principals: self.required_principals.as_ref(),
                policy_mode: self.core_policy_mode(),
                policy_engine: self.policy_engine.as_deref(),
                policy_fail_open: self.policy_fail_open,
                budget_tracker: self.budget_tracker.as_deref(),
                budget_block_on_exceeded: self.budget_block_on_exceeded,
                budget_fail_open: self.budget_fail_open,
                default_model: &self.default_model,
            },
            enforcement_core::ProxyEnforcementInput { envelope },
        );
        if let Err((_, ref reason, _)) = result {
            if self.policy_mode == ProxyPolicyMode::Audit {
                warn!("Policy audit violation: {}", reason);
            }
        }
        result
    }

    pub async fn enforce_envelope_with_timeout(
        &self,
        envelope: &TrafficEnvelope,
    ) -> Result<EnforcementResult, (u16, String, Option<String>)> {
        let envelope = envelope.clone();
        let identity_mode = self.core_identity_mode();
        let trusted_dids = Arc::clone(&self.trusted_dids);
        let required_principals = Arc::clone(&self.required_principals);
        let policy_mode = self.core_policy_mode();
        let policy_engine = self.policy_engine.clone();
        let policy_fail_open = self.policy_fail_open;
        let budget_tracker = self.budget_tracker.clone();
        let budget_block_on_exceeded = self.budget_block_on_exceeded;
        let budget_fail_open = self.budget_fail_open;
        let default_model = self.default_model.clone();

        let timeout_result = tokio::time::timeout(
            self.enforcement_timeout,
            tokio::task::spawn_blocking(move || {
                let config = enforcement_core::ProxyEnforcementConfig {
                    identity_mode,
                    trusted_dids: trusted_dids.as_ref(),
                    required_principals: required_principals.as_ref(),
                    policy_mode,
                    policy_engine: policy_engine.as_deref(),
                    policy_fail_open,
                    budget_tracker: budget_tracker.as_deref(),
                    budget_block_on_exceeded,
                    budget_fail_open,
                    default_model: &default_model,
                };
                enforcement_core::enforce_proxy_request(
                    config,
                    enforcement_core::ProxyEnforcementInput {
                        envelope: &envelope,
                    },
                )
            }),
        )
        .await;

        match timeout_result {
            Ok(Ok(result)) => result,
            Ok(Err(err)) => {
                if self.fail_open_enabled {
                    metrics::record_enforcement_failopen("panic");
                    warn!(
                        error = %err,
                        "Enforcement task join failed; failing open"
                    );
                    Ok(EnforcementResult::default())
                } else {
                    Err((
                        503,
                        "Enforcement unavailable (task join failure)".to_string(),
                        None,
                    ))
                }
            }
            Err(_) => {
                if self.fail_open_enabled {
                    metrics::record_enforcement_failopen("timeout");
                    warn!(
                        timeout_ms = self.enforcement_timeout.as_millis(),
                        "Enforcement timed out; failing open"
                    );
                    Ok(EnforcementResult::default())
                } else {
                    Err((
                        503,
                        format!(
                            "Enforcement timed out after {}ms",
                            self.enforcement_timeout.as_millis()
                        ),
                        None,
                    ))
                }
            }
        }
    }

    #[allow(dead_code)]
    pub fn enforce_request(
        &self,
        session_id: &str,
        provider: &str,
        host: &str,
        http_method: &str,
        path: &str,
        model: Option<&str>,
        request_body: Option<&str>,
        agent: Option<&str>,
        did: Option<&str>,
        signature: Option<&str>,
    ) -> Result<EnforcementResult, (u16, String, Option<String>)> {
        let envelope = TrafficEnvelope::proxy(
            session_id,
            "proxy-request",
            provider,
            host,
            http_method,
            path,
            model,
            agent,
            did,
            signature,
            request_body,
        );
        self.enforce_envelope(&envelope)
    }
}

impl Default for ProxyEnforcer {
    fn default() -> Self {
        Self::new()
    }
}
