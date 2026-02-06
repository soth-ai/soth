//! Budget types for SOTH
//!
//! Defines types for token counting, cost calculation, and budget tracking.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

// ============================================================================
// Advanced Pricing Types (LiteLLM-compatible)
// ============================================================================

/// Detailed model pricing entry with full metadata (LiteLLM-compatible)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPricingEntry {
    /// Model identifier (e.g., "gpt-4o-2024-08-06")
    pub model_id: String,

    /// Display name (e.g., "GPT-4o")
    pub model_name: String,

    /// Provider (e.g., "openai", "anthropic", "google")
    pub provider: String,

    /// Input cost per million tokens (USD)
    pub input_cost_per_million: f64,

    /// Output cost per million tokens (USD)
    pub output_cost_per_million: f64,

    /// Cache read cost per million tokens (Anthropic prompt caching)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_read_cost_per_million: Option<f64>,

    /// Cache write cost per million tokens (Anthropic prompt caching)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_write_cost_per_million: Option<f64>,

    /// Whether model supports vision/images
    #[serde(default)]
    pub supports_vision: bool,

    /// Whether model supports tool/function calling
    #[serde(default)]
    pub supports_tools: bool,

    /// Context window size in tokens
    pub context_window: u32,

    /// Maximum output tokens
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,

    /// When this pricing took effect
    #[serde(default = "Utc::now")]
    pub effective_date: DateTime<Utc>,

    /// Model aliases (e.g., ["gpt-4o", "gpt-4o-latest"])
    #[serde(default)]
    pub aliases: Vec<String>,
}

impl ModelPricingEntry {
    /// Calculate cost for token usage with optional caching
    pub fn calculate_cost(
        &self,
        input_tokens: u64,
        output_tokens: u64,
        cache_read_tokens: Option<u64>,
        cache_write_tokens: Option<u64>,
    ) -> f64 {
        let mut cost = 0.0;

        // Standard input/output costs
        cost += (input_tokens as f64 / 1_000_000.0) * self.input_cost_per_million;
        cost += (output_tokens as f64 / 1_000_000.0) * self.output_cost_per_million;

        // Cache costs (Anthropic prompt caching)
        if let (Some(cache_read), Some(rate)) = (cache_read_tokens, self.cache_read_cost_per_million) {
            cost += (cache_read as f64 / 1_000_000.0) * rate;
        }
        if let (Some(cache_write), Some(rate)) = (cache_write_tokens, self.cache_write_cost_per_million) {
            cost += (cache_write as f64 / 1_000_000.0) * rate;
        }

        cost
    }
}

// ============================================================================
// Cost Tagging Types
// ============================================================================

/// Cost attribution tag for team/project allocation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CostTag {
    /// Tag key (e.g., "team", "project", "environment")
    pub key: String,

    /// Tag value (e.g., "platform", "agent-v2", "production")
    pub value: String,
}

impl CostTag {
    /// Create a new cost tag
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// Request type for cost attribution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SpendRequestType {
    /// Direct AI API call (api.openai.com, api.anthropic.com)
    #[default]
    AiInference,

    /// Inference triggered by MCP tool call
    McpInference,
}

/// Extended spend record with tagging and MCP attribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaggedSpendRecord {
    /// Base spend record
    #[serde(flatten)]
    pub record: SpendRecord,

    /// Cost attribution tags
    #[serde(default)]
    pub tags: Vec<CostTag>,

    /// MCP tool that triggered this spend (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_tool: Option<String>,

    /// MCP server that triggered this spend
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_server: Option<String>,

    /// MCP session ID for correlation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_session_id: Option<String>,

    /// Request type (AI inference or MCP-triggered)
    #[serde(default)]
    pub request_type: SpendRequestType,

    /// Provider name (openai, anthropic, google)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

// ============================================================================
// Analytics Types
// ============================================================================

/// Daily cost trend data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyTrendPoint {
    /// Date (YYYY-MM-DD)
    pub date: String,

    /// Total cost in USD
    pub cost: f64,

    /// Total tokens
    pub tokens: u64,

    /// Request count
    pub requests: u64,

    /// Cost by provider
    #[serde(default)]
    pub by_provider: HashMap<String, f64>,
}

/// Cost anomaly types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    /// Sudden cost increase
    CostSpike,
    /// Token usage spike
    UsageSpike,
    /// Previously unseen model
    NewModel,
    /// Activity outside normal hours
    UnusualTime,
    /// Approaching budget limit
    BudgetApproaching,
}

/// Anomaly severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalySeverity {
    /// Informational
    Info,
    /// Needs attention
    Warning,
    /// Urgent action required
    Critical,
}

/// Cost anomaly detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostAnomaly {
    /// Unique ID
    pub id: String,

    /// Type of anomaly
    pub anomaly_type: AnomalyType,

    /// Severity level
    pub severity: AnomalySeverity,

    /// Human-readable description
    pub description: String,

    /// When detected
    pub detected_at: DateTime<Utc>,

    /// Current observed value
    pub current_value: f64,

    /// Expected/baseline value
    pub expected_value: f64,

    /// Deviation percentage
    pub deviation_percent: f64,

    /// What entity is affected
    pub affected_entity: String,

    /// Entity type (model, tool, agent, provider)
    pub entity_type: String,
}

/// Recommendation types for cost optimization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationType {
    /// Use a cheaper model for simple tasks
    ModelDowngrade,
    /// Enable prompt caching
    PromptCaching,
    /// Combine multiple requests
    BatchRequests,
    /// Request shorter responses
    ReduceOutputTokens,
    /// Switch to local/self-hosted model
    UseLocalModel,
}

/// Implementation effort level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffortLevel {
    /// Quick fix, minimal changes
    Low,
    /// Requires some refactoring
    Medium,
    /// Significant architectural changes
    High,
}

/// Cost optimization recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostRecommendation {
    /// Unique ID
    pub id: String,

    /// Type of recommendation
    pub recommendation_type: RecommendationType,

    /// Short title
    pub title: String,

    /// Detailed description
    pub description: String,

    /// Estimated savings in USD
    pub estimated_savings: f64,

    /// Estimated savings as percentage
    pub estimated_savings_percent: f64,

    /// Implementation effort required
    pub implementation_effort: EffortLevel,

    /// Number of affected requests
    pub affected_requests: u64,
}

// ============================================================================
// Provider Breakdown Types
// ============================================================================

/// Cost breakdown for a provider
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderCostBreakdown {
    /// Total cost for this provider
    pub total_cost: f64,

    /// Total tokens (input + output)
    pub total_tokens: u64,

    /// Input tokens
    pub input_tokens: u64,

    /// Output tokens
    pub output_tokens: u64,

    /// Request count
    pub request_count: u64,

    /// Cost by model within this provider
    #[serde(default)]
    pub model_breakdown: HashMap<String, ModelCostEntry>,
}

/// Cost entry for a specific model
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelCostEntry {
    /// Model display name
    pub model_name: String,

    /// Total cost
    pub cost: f64,

    /// Input tokens
    pub input_tokens: u64,

    /// Output tokens
    pub output_tokens: u64,

    /// Request count
    pub request_count: u64,

    /// Average cost per request
    pub avg_cost_per_request: f64,
}

/// Cost entry for an MCP tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCostEntry {
    /// Tool name
    pub tool_name: String,

    /// MCP server name
    pub server_name: String,

    /// Total cost attributed to this tool
    pub total_cost: f64,

    /// Number of times this tool was called
    pub call_count: u64,

    /// Average cost per call
    pub avg_cost_per_call: f64,
}

/// Token usage for a single request/response
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenUsage {
    /// Input tokens (request)
    pub input_tokens: u64,

    /// Output tokens (response)
    pub output_tokens: u64,

    /// Total tokens
    pub total_tokens: u64,
}

impl TokenUsage {
    /// Create new token usage
    pub fn new(input: u64, output: u64) -> Self {
        Self {
            input_tokens: input,
            output_tokens: output,
            total_tokens: input + output,
        }
    }

    /// Add another usage to this one
    pub fn add(&mut self, other: &TokenUsage) {
        self.input_tokens += other.input_tokens;
        self.output_tokens += other.output_tokens;
        self.total_tokens += other.total_tokens;
    }
}

/// Budget state for an agent or session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetState {
    /// Identifier (agent ID, session ID, or "global")
    pub id: String,

    /// Scope: global, per_agent, per_session
    pub scope: BudgetScope,

    /// Current period's spend in USD
    pub current_spend: f64,

    /// Daily limit in USD
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daily_limit: Option<f64>,

    /// Weekly limit in USD
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weekly_limit: Option<f64>,

    /// Monthly limit in USD
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monthly_limit: Option<f64>,

    /// Period start time
    pub period_start: DateTime<Utc>,

    /// Total tokens used
    pub total_tokens: u64,

    /// Total requests
    pub total_requests: u64,

    /// Last updated
    pub updated_at: DateTime<Utc>,
}

impl BudgetState {
    /// Create a new budget state
    pub fn new(id: impl Into<String>, scope: BudgetScope) -> Self {
        let now = Utc::now();
        Self {
            id: id.into(),
            scope,
            current_spend: 0.0,
            daily_limit: None,
            weekly_limit: None,
            monthly_limit: None,
            period_start: now,
            total_tokens: 0,
            total_requests: 0,
            updated_at: now,
        }
    }

    /// Check if any limit is exceeded
    pub fn is_exceeded(&self) -> bool {
        if let Some(daily) = self.daily_limit {
            if self.current_spend >= daily {
                return true;
            }
        }
        if let Some(weekly) = self.weekly_limit {
            if self.current_spend >= weekly {
                return true;
            }
        }
        if let Some(monthly) = self.monthly_limit {
            if self.current_spend >= monthly {
                return true;
            }
        }
        false
    }

    /// Get percentage of limit used
    pub fn usage_percent(&self) -> Option<f64> {
        let limit = self.daily_limit.or(self.weekly_limit).or(self.monthly_limit)?;
        if limit <= 0.0 {
            return None;
        }
        Some((self.current_spend / limit) * 100.0)
    }
}

/// Budget scope
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetScope {
    /// Global across all agents
    Global,
    /// Per agent
    PerAgent,
    /// Per session
    PerSession,
    /// Per model
    PerModel,
}

impl Default for BudgetScope {
    fn default() -> Self {
        Self::Global
    }
}

/// Spend record for tracking costs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendRecord {
    /// Unique record ID
    pub id: String,

    /// Session ID
    pub session_id: String,

    /// Agent ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,

    /// Timestamp
    pub timestamp: DateTime<Utc>,

    /// Model used
    pub model: String,

    /// Token usage
    pub token_usage: TokenUsage,

    /// Cost in USD
    pub cost: f64,

    /// Method/tool called
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

/// Model pricing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPricing {
    /// Model identifier
    pub model: String,

    /// Input cost per million tokens (USD)
    pub input_per_million: f64,

    /// Output cost per million tokens (USD)
    pub output_per_million: f64,
}

impl ModelPricing {
    /// Calculate cost for token usage
    pub fn calculate_cost(&self, usage: &TokenUsage) -> f64 {
        let input_cost = (usage.input_tokens as f64 / 1_000_000.0) * self.input_per_million;
        let output_cost = (usage.output_tokens as f64 / 1_000_000.0) * self.output_per_million;
        input_cost + output_cost
    }
}

/// Default model pricing (2025)
pub fn default_model_pricing() -> HashMap<String, ModelPricing> {
    let mut pricing = HashMap::new();

    pricing.insert(
        "claude-opus-4".to_string(),
        ModelPricing {
            model: "claude-opus-4".to_string(),
            input_per_million: 15.0,
            output_per_million: 75.0,
        },
    );

    pricing.insert(
        "claude-sonnet-4".to_string(),
        ModelPricing {
            model: "claude-sonnet-4".to_string(),
            input_per_million: 3.0,
            output_per_million: 15.0,
        },
    );

    pricing.insert(
        "claude-3-5-sonnet".to_string(),
        ModelPricing {
            model: "claude-3-5-sonnet".to_string(),
            input_per_million: 3.0,
            output_per_million: 15.0,
        },
    );

    pricing.insert(
        "gpt-4o".to_string(),
        ModelPricing {
            model: "gpt-4o".to_string(),
            input_per_million: 5.0,
            output_per_million: 20.0,
        },
    );

    pricing.insert(
        "gpt-4o-mini".to_string(),
        ModelPricing {
            model: "gpt-4o-mini".to_string(),
            input_per_million: 0.15,
            output_per_million: 0.60,
        },
    );

    pricing
}

/// Alert threshold configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThreshold {
    /// Threshold percentage (0-100)
    pub threshold_percent: u8,

    /// Action to take
    pub action: AlertAction,

    /// Webhook URL for notifications
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
}

/// Alert actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertAction {
    /// Log a warning
    Notify,
    /// Log a warning
    Warn,
    /// Block further requests
    Block,
}

/// Budget alert event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetAlert {
    /// Alert ID
    pub id: String,

    /// Budget state ID
    pub budget_id: String,

    /// Threshold that was crossed
    pub threshold_percent: u8,

    /// Current spend
    pub current_spend: f64,

    /// Limit
    pub limit: f64,

    /// Action taken
    pub action: AlertAction,

    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_usage() {
        let usage = TokenUsage::new(100, 50);
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.output_tokens, 50);
        assert_eq!(usage.total_tokens, 150);
    }

    #[test]
    fn test_budget_state_exceeded() {
        let mut state = BudgetState::new("test", BudgetScope::Global);
        state.daily_limit = Some(100.0);
        state.current_spend = 50.0;
        assert!(!state.is_exceeded());

        state.current_spend = 100.0;
        assert!(state.is_exceeded());
    }

    #[test]
    fn test_usage_percent() {
        let mut state = BudgetState::new("test", BudgetScope::Global);
        state.daily_limit = Some(100.0);
        state.current_spend = 50.0;
        assert_eq!(state.usage_percent(), Some(50.0));
    }

    #[test]
    fn test_model_pricing() {
        let pricing = ModelPricing {
            model: "test".to_string(),
            input_per_million: 10.0,
            output_per_million: 30.0,
        };

        let usage = TokenUsage::new(1_000_000, 500_000);
        let cost = pricing.calculate_cost(&usage);
        assert!((cost - 25.0).abs() < 0.01); // 10 + 15 = 25
    }

    #[test]
    fn test_default_pricing() {
        let pricing = default_model_pricing();
        assert!(pricing.contains_key("claude-opus-4"));
        assert!(pricing.contains_key("gpt-4o"));
    }
}
