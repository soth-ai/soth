//! Policy evaluation engine
//!
//! Provides policy evaluation with caching and mode support.

use crate::cache::{CacheConfig, CacheMetrics, DecisionCache};
use parking_lot::RwLock;
use soth_core::error::Result;
use soth_core::types::policy::{EvaluationResult, PolicyData, PolicyDecision, PolicyInput};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    /// Policy modules (Rego source)
    modules: RwLock<HashMap<String, String>>,
    /// Runtime policy data
    policy_data: RwLock<PolicyData>,
    /// Decision cache
    cache: Arc<DecisionCache>,
    /// Statistics
    stats: RwLock<EngineStats>,
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
            modules: RwLock::new(HashMap::new()),
            policy_data: RwLock::new(PolicyData::default()),
            stats: RwLock::new(EngineStats::default()),
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
            modules: RwLock::new(HashMap::new()),
            policy_data: RwLock::new(PolicyData::default()),
            stats: RwLock::new(EngineStats::default()),
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
        let mut m = self.modules.write();
        *m = modules;
        // Invalidate cache when modules change
        self.cache.invalidate();
        Ok(())
    }

    /// Set runtime policy data
    pub fn set_policy_data(&self, data: PolicyData) -> Result<()> {
        let mut d = self.policy_data.write();
        *d = data;
        // Invalidate cache when data changes
        self.cache.invalidate();
        Ok(())
    }

    /// Evaluate a policy decision
    pub fn evaluate(&self, input: &PolicyInput) -> Result<EvaluationResult> {
        let start = Instant::now();

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
            });
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
            });
        }

        // Evaluate policy
        let decision = self.evaluate_policy(input)?;

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
    fn evaluate_policy(&self, input: &PolicyInput) -> Result<PolicyDecision> {
        let data = self.policy_data.read();

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
                    "identity required (allowed_dids policy)".to_string()
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
        !self.config.enabled || !self.modules.read().is_empty()
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
        assert_eq!(result.decision.matched_rule, Some("policy_disabled".to_string()));
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
}
