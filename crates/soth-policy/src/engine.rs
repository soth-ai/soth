//! Policy evaluation engine
//!
//! Provides policy evaluation with caching and mode support.

use crate::cache::{CacheConfig, CacheMetrics, DecisionCache};
use parking_lot::RwLock;
use soth_core::error::Result;
use soth_core::types::policy::{EvaluationResult, PolicyData, PolicyDecision, PolicyInput};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tracing::warn;

/// Policy engine configuration
#[derive(Debug, Clone)]
pub struct PolicyEngineConfig {
    /// Enable policy evaluation
    pub enabled: bool,
    /// Policy mode: "enforce" or "audit"
    pub mode: String,
    /// Evaluation timeout
    pub timeout: Duration,
    /// Cache configuration
    pub cache: CacheConfig,
}

impl Default for PolicyEngineConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: "enforce".to_string(),
            timeout: Duration::from_millis(100),
            cache: CacheConfig::default(),
        }
    }
}

/// Policy evaluation engine
pub struct PolicyEngine {
    /// Configuration
    config: PolicyEngineConfig,
    /// Active + previous artifact snapshots for versioned reload and rollback.
    artifacts: RwLock<PolicyArtifactSet>,
    /// Decision cache
    cache: Arc<DecisionCache>,
    /// Statistics
    stats: RwLock<EngineStats>,
    /// Guard to avoid spamming runtime-mismatch warnings on every evaluation.
    rego_runtime_warning_emitted: AtomicBool,
}

#[derive(Debug, Clone)]
struct PolicyArtifactSnapshot {
    modules: HashMap<String, String>,
    data: PolicyData,
    version: u64,
}

impl Default for PolicyArtifactSnapshot {
    fn default() -> Self {
        Self {
            modules: HashMap::new(),
            data: PolicyData::default(),
            version: 1,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct PolicyArtifactSet {
    active: PolicyArtifactSnapshot,
    previous: Option<PolicyArtifactSnapshot>,
}

/// Engine statistics
#[derive(Debug, Clone, Default)]
pub struct EngineStats {
    pub evaluations: u64,
    pub eval_errors: u64,
    pub avg_eval_time_ns: u64,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::with_config(PolicyEngineConfig::default())
    }
}

impl PolicyEngine {
    /// Create a new policy engine with default config
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new policy engine with config
    pub fn with_config(config: PolicyEngineConfig) -> Self {
        Self {
            cache: Arc::new(DecisionCache::new(config.cache.clone())),
            config,
            artifacts: RwLock::new(PolicyArtifactSet::default()),
            stats: RwLock::new(EngineStats::default()),
            rego_runtime_warning_emitted: AtomicBool::new(false),
        }
    }

    /// Create a new policy engine with a custom cache config
    pub fn with_cache_config(cache_config: CacheConfig) -> Self {
        Self {
            cache: Arc::new(DecisionCache::new(cache_config.clone())),
            config: PolicyEngineConfig {
                cache: cache_config,
                ..Default::default()
            },
            artifacts: RwLock::new(PolicyArtifactSet::default()),
            stats: RwLock::new(EngineStats::default()),
            rego_runtime_warning_emitted: AtomicBool::new(false),
        }
    }

    /// Check if the engine is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the policy mode
    pub fn mode(&self) -> &str {
        &self.config.mode
    }

    /// Load policy modules
    pub fn load_modules(&self, modules: HashMap<String, String>) -> Result<()> {
        let data = {
            let artifacts = self.artifacts.read();
            artifacts.active.data.clone()
        };
        self.reload_artifacts(modules, data)?;
        Ok(())
    }

    /// Set runtime policy data
    pub fn set_policy_data(&self, data: PolicyData) -> Result<()> {
        let modules = {
            let artifacts = self.artifacts.read();
            artifacts.active.modules.clone()
        };
        self.reload_artifacts(modules, data)?;
        Ok(())
    }

    /// Get current active policy version.
    pub fn active_policy_version(&self) -> String {
        let artifacts = self.artifacts.read();
        format!("v{}", artifacts.active.version)
    }

    /// Get previous policy version if rollback target exists.
    pub fn previous_policy_version(&self) -> Option<String> {
        let artifacts = self.artifacts.read();
        artifacts
            .previous
            .as_ref()
            .map(|snapshot| format!("v{}", snapshot.version))
    }

    /// Transactional artifact reload:
    /// validate -> atomically swap active snapshot -> keep rollback target.
    pub fn reload_artifacts(
        &self,
        modules: HashMap<String, String>,
        data: PolicyData,
    ) -> Result<String> {
        self.validate_artifacts(&modules)?;

        let mut artifacts = self.artifacts.write();
        let mut next_active = artifacts.active.clone();
        next_active.modules = modules;
        next_active.data = data;
        next_active.version = next_active.version.saturating_add(1);

        artifacts.previous = Some(artifacts.active.clone());
        artifacts.active = next_active;

        self.cache.invalidate();
        Ok(format!("v{}", artifacts.active.version))
    }

    /// Roll back to the previous artifact snapshot (if available).
    pub fn rollback_artifacts(&self) -> Result<Option<String>> {
        let mut artifacts = self.artifacts.write();
        let Some(previous) = artifacts.previous.clone() else {
            return Ok(None);
        };
        let current = artifacts.active.clone();
        let mut restored = previous;
        restored.version = current.version.saturating_add(1);
        artifacts.active = restored;
        artifacts.previous = Some(current);
        self.cache.invalidate();
        Ok(Some(format!("v{}", artifacts.active.version)))
    }

    fn validate_artifacts(&self, modules: &HashMap<String, String>) -> Result<()> {
        for (name, module) in modules {
            if name.trim().is_empty() {
                return Err(soth_core::error::SothError::Policy(
                    "Policy module name cannot be empty".to_string(),
                ));
            }
            if module.trim().is_empty() {
                return Err(soth_core::error::SothError::Policy(format!(
                    "Policy module '{name}' cannot be empty"
                )));
            }
        }
        Ok(())
    }

    /// Evaluate a policy decision
    pub fn evaluate(&self, input: &PolicyInput) -> Result<EvaluationResult> {
        let start = Instant::now();
        let (policy_version, has_modules, has_modules_count, policy_data) = {
            let artifacts = self.artifacts.read();
            let modules_len = artifacts.active.modules.len();
            (
                format!("v{}", artifacts.active.version),
                modules_len > 0,
                modules_len,
                artifacts.active.data.clone(),
            )
        };

        // If disabled, allow everything
        if !self.config.enabled {
            return Ok(EvaluationResult {
                decision: PolicyDecision {
                    allow: true,
                    matched_rule: Some("policy_disabled".to_string()),
                    ..Default::default()
                },
                input: input.clone(),
                eval_time: start.elapsed(),
                cache_hit: false,
                cache_tier: String::new(),
                policy_mode: self.config.mode.clone(),
                policy_version,
            });
        }

        // TODO: Wire up OpaWasmRuntime (crate::wasm) to execute loaded Rego modules.
        // Currently the wasm runtime is a placeholder and runtime evaluation remains
        // fail-open by falling through to the built-in data-based rules below. Once the
        // Rego runtime is available, this branch should call into it and merge results.
        if has_modules
            && !self
                .rego_runtime_warning_emitted
                .swap(true, Ordering::Relaxed)
        {
            warn!(
                module_count = has_modules_count,
                "Policy modules loaded but no Rego execution runtime available — \
                 falling through to built-in rule evaluation"
            );
        }

        // Check cache
        let (cached, hit, tier) = self.cache.get(input);
        if hit {
            return Ok(EvaluationResult {
                decision: cached.unwrap(),
                input: input.clone(),
                eval_time: start.elapsed(),
                cache_hit: true,
                cache_tier: tier,
                policy_mode: self.config.mode.clone(),
                policy_version,
            });
        }

        // Evaluate policy
        let decision = match self.evaluate_policy(input, &policy_data) {
            Ok(decision) => decision,
            Err(err) => {
                self.stats.write().eval_errors += 1;
                return Err(err);
            }
        };

        let eval_time = start.elapsed();

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.evaluations += 1;
            // Exponential moving average
            let alpha = 10u64;
            if stats.avg_eval_time_ns == 0 {
                stats.avg_eval_time_ns = eval_time.as_nanos() as u64;
            } else {
                stats.avg_eval_time_ns = (stats.avg_eval_time_ns * (100 - alpha)
                    + eval_time.as_nanos() as u64 * alpha)
                    / 100;
            }
        }

        // Cache the result
        self.cache.set(input, &decision);

        Ok(EvaluationResult {
            decision,
            input: input.clone(),
            eval_time,
            cache_hit: false,
            cache_tier: String::new(),
            policy_mode: self.config.mode.clone(),
            policy_version,
        })
    }

    /// Check if a request is allowed
    pub fn is_allowed(&self, input: &PolicyInput) -> Result<(bool, EvaluationResult)> {
        let result = self.evaluate(input)?;

        // In audit mode, always return true but still evaluate
        let allowed = if self.config.mode == "audit" {
            true
        } else {
            result.decision.allow
        };

        Ok((allowed, result))
    }

    /// Evaluate policy using built-in rules (simplified OPA replacement)
    fn evaluate_policy(&self, input: &PolicyInput, data: &PolicyData) -> Result<PolicyDecision> {
        // Check blocked agents
        if data.blocked_agents.contains(&input.agent.id) {
            return Ok(PolicyDecision::deny(vec![format!(
                "agent '{}' is blocked",
                input.agent.id
            )]));
        }

        // Check blocked DIDs
        if let Some(did) = &input.identity.did {
            if data.blocked_dids.contains(did) {
                return Ok(PolicyDecision::deny(vec![format!(
                    "DID '{}' is blocked",
                    did
                )]));
            }
        }

        // Check blocked tools
        if let Some(tool) = &input.request.tool {
            if data.blocked_tools.contains(tool) {
                return Ok(PolicyDecision::deny(vec![format!(
                    "tool '{}' is blocked",
                    tool
                )]));
            }

            // Check identity requirements for specific tools
            if data.identity_required_tools.contains(tool) && !input.identity.verified {
                return Ok(PolicyDecision::deny(vec![format!(
                    "tool '{}' requires identity verification",
                    tool
                )]));
            }

            // Check capability requirements
            if let Some(required_cap) = data.tool_capabilities.get(tool) {
                if !input.agent.capabilities.contains(required_cap) {
                    return Ok(PolicyDecision::deny(vec![format!(
                        "agent lacks capability '{}' required for tool '{}'",
                        required_cap, tool
                    )]));
                }
            }

            // Check PII tools with restricted models
            if data.pii_tools.contains(tool) {
                if let Some(model) = &input.agent.model {
                    if data.blocked_models_for_pii.contains(model) {
                        return Ok(PolicyDecision::deny(vec![format!(
                            "model '{}' cannot access PII tool '{}'",
                            model, tool
                        )]));
                    }
                }
            }
        }

        // Check allowed DIDs (if specified, restrict to those)
        if !data.allowed_dids.is_empty() {
            if let Some(did) = &input.identity.did {
                if !data.allowed_dids.contains(did) {
                    return Ok(PolicyDecision::deny(vec![format!(
                        "DID '{}' not in allowed list",
                        did
                    )]));
                }
            } else {
                return Ok(PolicyDecision::deny(vec![
                    "identity required (allowed_dids policy)".to_string(),
                ]));
            }
        }

        // Check rate limits (simplified - real implementation would track state)
        if let Some(tool) = &input.request.tool {
            if let Some(&limit) = data.rate_limits.get(tool) {
                // This is a simplified check - real implementation would maintain counters
                if input.session.request_count > limit as u64 {
                    return Ok(PolicyDecision::deny(vec![format!(
                        "rate limit exceeded for tool '{}' ({} > {})",
                        tool, input.session.request_count, limit
                    )]));
                }
            }
        }

        // All checks passed
        Ok(PolicyDecision::allow())
    }

    /// Check if the engine is ready
    pub fn is_ready(&self) -> bool {
        if !self.config.enabled {
            return true;
        }
        let artifacts = self.artifacts.read();
        artifacts.active.version > 0
    }

    /// Get engine statistics
    pub fn stats(&self) -> EngineStats {
        self.stats.read().clone()
    }

    /// Get cache hit rate
    pub fn cache_hit_rate(&self) -> f64 {
        self.cache.hit_rate()
    }

    /// Get cache metrics for monitoring
    pub fn cache_metrics(&self) -> CacheMetrics {
        self.cache.metrics()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soth_core::types::identity::{AgentContext, IdentityContext};
    use soth_core::types::policy::{EnvironmentContext, RequestContext, SessionContext};

    fn make_input(agent_id: &str, tool: Option<&str>) -> PolicyInput {
        PolicyInput {
            agent: AgentContext {
                id: agent_id.to_string(),
                capabilities: vec!["read".to_string()],
                ..Default::default()
            },
            request: RequestContext {
                method: "tools/call".to_string(),
                tool: tool.map(|s| s.to_string()),
                ..Default::default()
            },
            session: SessionContext::default(),
            identity: IdentityContext::default(),
            context: EnvironmentContext::default(),
        }
    }

    #[test]
    fn test_disabled_engine() {
        let engine = PolicyEngine::with_config(PolicyEngineConfig {
            enabled: false,
            ..Default::default()
        });

        let input = make_input("agent-1", Some("test_tool"));
        let result = engine.evaluate(&input).unwrap();

        assert!(result.decision.allow);
        assert_eq!(
            result.decision.matched_rule,
            Some("policy_disabled".to_string())
        );
    }

    #[test]
    fn test_allow_default() {
        let engine = PolicyEngine::new();

        let input = make_input("agent-1", Some("test_tool"));
        let result = engine.evaluate(&input).unwrap();

        assert!(result.decision.allow);
    }

    #[test]
    fn test_blocked_agent() {
        let engine = PolicyEngine::new();
        engine
            .set_policy_data(PolicyData {
                blocked_agents: vec!["bad-agent".to_string()],
                ..Default::default()
            })
            .unwrap();

        let input = make_input("bad-agent", Some("test_tool"));
        let result = engine.evaluate(&input).unwrap();

        assert!(!result.decision.allow);
        assert!(result.decision.violations[0].contains("blocked"));
    }

    #[test]
    fn test_blocked_tool() {
        let engine = PolicyEngine::new();
        engine
            .set_policy_data(PolicyData {
                blocked_tools: vec!["dangerous_tool".to_string()],
                ..Default::default()
            })
            .unwrap();

        let input = make_input("agent-1", Some("dangerous_tool"));
        let result = engine.evaluate(&input).unwrap();

        assert!(!result.decision.allow);
    }

    #[test]
    fn test_capability_requirement() {
        let engine = PolicyEngine::new();
        engine
            .set_policy_data(PolicyData {
                tool_capabilities: {
                    let mut m = HashMap::new();
                    m.insert("admin_tool".to_string(), "admin".to_string());
                    m
                },
                ..Default::default()
            })
            .unwrap();

        let input = make_input("agent-1", Some("admin_tool")); // Has "read", needs "admin"
        let result = engine.evaluate(&input).unwrap();

        assert!(!result.decision.allow);
        assert!(result.decision.violations[0].contains("capability"));
    }

    #[test]
    fn test_audit_mode() {
        let engine = PolicyEngine::with_config(PolicyEngineConfig {
            mode: "audit".to_string(),
            ..Default::default()
        });
        engine
            .set_policy_data(PolicyData {
                blocked_agents: vec!["agent-1".to_string()],
                ..Default::default()
            })
            .unwrap();

        let input = make_input("agent-1", None);
        let (allowed, result) = engine.is_allowed(&input).unwrap();

        // In audit mode, always allowed but decision shows it would be denied
        assert!(allowed);
        assert!(!result.decision.allow);
    }

    #[test]
    fn test_caching() {
        let engine = PolicyEngine::new();

        let input = make_input("agent-1", Some("test"));

        // First call - miss
        let result1 = engine.evaluate(&input).unwrap();
        assert!(!result1.cache_hit);

        // Second call - hit
        let result2 = engine.evaluate(&input).unwrap();
        assert!(result2.cache_hit);
        assert_eq!(result2.cache_tier, "L1");
    }

    #[test]
    fn test_policy_version_increments_on_data_update() {
        let engine = PolicyEngine::new();
        assert_eq!(engine.active_policy_version(), "v1");

        engine.set_policy_data(PolicyData::default()).unwrap();
        assert_eq!(engine.active_policy_version(), "v2");
    }

    #[test]
    fn test_reload_artifacts_keeps_previous_for_rollback() {
        let engine = PolicyEngine::new();
        assert_eq!(engine.active_policy_version(), "v1");
        assert_eq!(engine.previous_policy_version(), None);

        let mut modules = HashMap::new();
        modules.insert("policy".to_string(), "package mcp.policy".to_string());
        let version = engine
            .reload_artifacts(modules, PolicyData::default())
            .unwrap();
        assert_eq!(version, "v2");
        assert_eq!(engine.active_policy_version(), "v2");
        assert_eq!(engine.previous_policy_version(), Some("v1".to_string()));

        let rolled_back = engine.rollback_artifacts().unwrap();
        assert_eq!(rolled_back, Some("v3".to_string()));
        assert_eq!(engine.active_policy_version(), "v3");
        assert_eq!(engine.previous_policy_version(), Some("v2".to_string()));
    }

    #[test]
    fn test_reload_artifacts_validation_rejects_empty_module() {
        let engine = PolicyEngine::new();
        let mut modules = HashMap::new();
        modules.insert("bad".to_string(), "   ".to_string());

        let err = engine
            .reload_artifacts(modules, PolicyData::default())
            .unwrap_err();
        assert!(err.to_string().contains("cannot be empty"));
        assert_eq!(engine.active_policy_version(), "v1");
    }
}
