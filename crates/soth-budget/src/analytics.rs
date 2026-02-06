//! Cost Analytics - trends, anomaly detection, and recommendations
//!
//! Provides:
//! - Historical cost trend analysis
//! - Anomaly detection for cost spikes
//! - Optimization recommendations

use chrono::{Duration, Utc};
use soth_core::types::budget::{
    AnomalySeverity, AnomalyType, CostAnomaly, CostRecommendation,
    DailyTrendPoint, EffortLevel, ProviderCostBreakdown, ModelCostEntry,
    RecommendationType,
};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::storage::BudgetStorage;
use crate::Result;

/// Cost analytics engine
pub struct CostAnalytics {
    storage: Arc<BudgetStorage>,
}

impl CostAnalytics {
    /// Create a new cost analytics engine
    pub fn new(storage: Arc<BudgetStorage>) -> Self {
        Self { storage }
    }

    /// Get cost trend for specified number of days
    pub fn get_trend(&self, days: u32) -> Result<Vec<DailyTrendPoint>> {
        self.storage.get_daily_trend(days, None)
    }

    /// Get cost trend for a specific provider
    pub fn get_trend_by_provider(&self, days: u32, provider: &str) -> Result<Vec<DailyTrendPoint>> {
        self.storage.get_daily_trend(days, Some(provider))
    }

    /// Get cost breakdown by provider
    pub fn get_provider_breakdown(&self, days: u32) -> Result<HashMap<String, ProviderCostBreakdown>> {
        let since = Utc::now() - Duration::days(days as i64);
        let provider_data = self.storage.get_cost_by_provider(since)?;
        let model_data = self.storage.get_spend_by_model(since)?;

        let mut breakdown: HashMap<String, ProviderCostBreakdown> = HashMap::new();

        // Aggregate provider-level data
        for (provider, cost, input_tokens, output_tokens, requests) in provider_data {
            breakdown.insert(provider, ProviderCostBreakdown {
                total_cost: cost,
                total_tokens: input_tokens + output_tokens,
                input_tokens,
                output_tokens,
                request_count: requests,
                model_breakdown: HashMap::new(),
            });
        }

        // Add model breakdown
        for (model, cost, tokens) in model_data {
            let provider = self.detect_provider_from_model(&model);
            if let Some(pb) = breakdown.get_mut(&provider) {
                let requests = pb.request_count; // Approximation
                pb.model_breakdown.insert(model.clone(), ModelCostEntry {
                    model_name: model,
                    cost,
                    input_tokens: tokens / 2, // Approximation
                    output_tokens: tokens / 2,
                    request_count: requests,
                    avg_cost_per_request: if requests > 0 { cost / requests as f64 } else { 0.0 },
                });
            }
        }

        Ok(breakdown)
    }

    /// Detect anomalies in recent activity
    pub fn detect_anomalies(&self, lookback_hours: u32) -> Result<Vec<CostAnomaly>> {
        let mut anomalies = Vec::new();

        // Get recent vs historical data for comparison
        let recent_days = 1;
        let historical_days = 7;

        let recent_trend = self.storage.get_daily_trend(recent_days, None)?;
        let historical_trend = self.storage.get_daily_trend(historical_days, None)?;

        if historical_trend.is_empty() {
            return Ok(anomalies);
        }

        // Calculate historical averages
        let historical_avg_cost: f64 = historical_trend.iter().map(|d| d.cost).sum::<f64>()
            / historical_trend.len() as f64;
        let historical_avg_tokens: f64 = historical_trend.iter().map(|d| d.tokens as f64).sum::<f64>()
            / historical_trend.len() as f64;

        // Check for cost spike
        if let Some(recent) = recent_trend.last() {
            if historical_avg_cost > 0.0 {
                let deviation = ((recent.cost - historical_avg_cost) / historical_avg_cost) * 100.0;

                if deviation > 100.0 {
                    anomalies.push(CostAnomaly {
                        id: Uuid::new_v4().to_string(),
                        anomaly_type: AnomalyType::CostSpike,
                        severity: AnomalySeverity::Critical,
                        description: format!(
                            "Cost spike detected: ${:.2} today vs ${:.2} average (+{:.0}%)",
                            recent.cost, historical_avg_cost, deviation
                        ),
                        detected_at: Utc::now(),
                        current_value: recent.cost,
                        expected_value: historical_avg_cost,
                        deviation_percent: deviation,
                        affected_entity: "daily_cost".to_string(),
                        entity_type: "aggregate".to_string(),
                    });
                } else if deviation > 50.0 {
                    anomalies.push(CostAnomaly {
                        id: Uuid::new_v4().to_string(),
                        anomaly_type: AnomalyType::CostSpike,
                        severity: AnomalySeverity::Warning,
                        description: format!(
                            "Elevated cost: ${:.2} today vs ${:.2} average (+{:.0}%)",
                            recent.cost, historical_avg_cost, deviation
                        ),
                        detected_at: Utc::now(),
                        current_value: recent.cost,
                        expected_value: historical_avg_cost,
                        deviation_percent: deviation,
                        affected_entity: "daily_cost".to_string(),
                        entity_type: "aggregate".to_string(),
                    });
                }
            }

            // Check for usage spike
            if historical_avg_tokens > 0.0 {
                let token_deviation = ((recent.tokens as f64 - historical_avg_tokens) / historical_avg_tokens) * 100.0;

                if token_deviation > 200.0 {
                    anomalies.push(CostAnomaly {
                        id: Uuid::new_v4().to_string(),
                        anomaly_type: AnomalyType::UsageSpike,
                        severity: AnomalySeverity::Warning,
                        description: format!(
                            "Token usage spike: {} tokens today vs {:.0} average (+{:.0}%)",
                            recent.tokens, historical_avg_tokens, token_deviation
                        ),
                        detected_at: Utc::now(),
                        current_value: recent.tokens as f64,
                        expected_value: historical_avg_tokens,
                        deviation_percent: token_deviation,
                        affected_entity: "daily_tokens".to_string(),
                        entity_type: "aggregate".to_string(),
                    });
                }
            }
        }

        // Check for new/unusual models
        let since = Utc::now() - Duration::hours(lookback_hours as i64);
        let recent_models = self.storage.get_spend_by_model(since)?;
        let historical_since = Utc::now() - Duration::days(30);
        let historical_models = self.storage.get_spend_by_model(historical_since)?;

        let historical_model_set: std::collections::HashSet<_> = historical_models
            .iter()
            .map(|(m, _, _)| m.clone())
            .collect();

        for (model, cost, _) in &recent_models {
            if !historical_model_set.contains(model) && *cost > 1.0 {
                anomalies.push(CostAnomaly {
                    id: Uuid::new_v4().to_string(),
                    anomaly_type: AnomalyType::NewModel,
                    severity: AnomalySeverity::Info,
                    description: format!(
                        "New model detected: '{}' with ${:.2} spend",
                        model, cost
                    ),
                    detected_at: Utc::now(),
                    current_value: *cost,
                    expected_value: 0.0,
                    deviation_percent: 100.0,
                    affected_entity: model.clone(),
                    entity_type: "model".to_string(),
                });
            }
        }

        Ok(anomalies)
    }

    /// Generate cost optimization recommendations
    pub fn generate_recommendations(&self) -> Result<Vec<CostRecommendation>> {
        let mut recommendations = Vec::new();
        let since = Utc::now() - Duration::days(7);

        // Get spending data
        let model_usage = self.storage.get_spend_by_model(since)?;
        let tool_costs = self.storage.get_cost_by_mcp_tool(since)?;

        // Recommendation 1: Model downgrade opportunities
        for (model, cost, _tokens) in &model_usage {
            let model_lower = model.to_lowercase();

            // Expensive models that could potentially use cheaper alternatives
            if (model_lower.contains("opus") || model_lower.contains("gpt-4") && !model_lower.contains("mini"))
                && *cost > 10.0
            {
                let cheaper_alternative = if model_lower.contains("opus") {
                    "claude-sonnet-4 or claude-3-5-haiku"
                } else if model_lower.contains("gpt-4o") && !model_lower.contains("mini") {
                    "gpt-4o-mini"
                } else if model_lower.contains("gpt-4") {
                    "gpt-4o-mini or gpt-3.5-turbo"
                } else {
                    continue;
                };

                recommendations.push(CostRecommendation {
                    id: Uuid::new_v4().to_string(),
                    recommendation_type: RecommendationType::ModelDowngrade,
                    title: format!("Consider cheaper alternative to {}", model),
                    description: format!(
                        "You've spent ${:.2} on {} this week. For simpler tasks (classification, \
                        extraction, summarization), consider {} which is 3-10x cheaper \
                        with comparable quality for straightforward operations.",
                        cost, model, cheaper_alternative
                    ),
                    estimated_savings: cost * 0.6, // Assume 60% savings possible
                    estimated_savings_percent: 60.0,
                    implementation_effort: EffortLevel::Low,
                    affected_requests: 0,
                });
            }

            // O1/reasoning models are very expensive
            if model_lower.contains("o1") && *cost > 5.0 {
                recommendations.push(CostRecommendation {
                    id: Uuid::new_v4().to_string(),
                    recommendation_type: RecommendationType::ModelDowngrade,
                    title: format!("Evaluate {} usage", model),
                    description: format!(
                        "Reasoning models like {} cost ${:.2} this week. These are best for \
                        complex multi-step problems. For simpler tasks, gpt-4o or claude-sonnet-4 \
                        may be sufficient at 5-10x lower cost.",
                        model, cost
                    ),
                    estimated_savings: cost * 0.7,
                    estimated_savings_percent: 70.0,
                    implementation_effort: EffortLevel::Medium,
                    affected_requests: 0,
                });
            }
        }

        // Recommendation 2: Prompt caching opportunities (Anthropic)
        let anthropic_spend: f64 = model_usage
            .iter()
            .filter(|(m, _, _)| m.to_lowercase().contains("claude"))
            .map(|(_, c, _)| c)
            .sum();

        if anthropic_spend > 20.0 {
            recommendations.push(CostRecommendation {
                id: Uuid::new_v4().to_string(),
                recommendation_type: RecommendationType::PromptCaching,
                title: "Enable Anthropic prompt caching".to_string(),
                description: format!(
                    "You've spent ${:.2} on Claude models this week. Anthropic's prompt caching \
                    can reduce costs by 90% for repeated system prompts. Add cache_control blocks \
                    to static parts of your prompts.",
                    anthropic_spend
                ),
                estimated_savings: anthropic_spend * 0.3, // Conservative estimate
                estimated_savings_percent: 30.0,
                implementation_effort: EffortLevel::Low,
                affected_requests: 0,
            });
        }

        // Recommendation 3: High-cost MCP tools
        for tool in &tool_costs {
            if tool.avg_cost_per_call > 0.10 {
                recommendations.push(CostRecommendation {
                    id: Uuid::new_v4().to_string(),
                    recommendation_type: RecommendationType::ReduceOutputTokens,
                    title: format!("Optimize tool: {}", tool.tool_name),
                    description: format!(
                        "MCP tool '{}' (server: {}) averages ${:.3} per call ({} calls = ${:.2} total). \
                        Consider: (1) caching results for repeated calls, (2) reducing output verbosity, \
                        (3) using a cheaper model for this tool.",
                        tool.tool_name, tool.server_name, tool.avg_cost_per_call,
                        tool.call_count, tool.total_cost
                    ),
                    estimated_savings: tool.total_cost * 0.4,
                    estimated_savings_percent: 40.0,
                    implementation_effort: EffortLevel::Medium,
                    affected_requests: tool.call_count,
                });
            }
        }

        // Recommendation 4: Batching opportunities
        let total_requests: u64 = model_usage.iter().map(|(_, _, _)| 1u64).sum();
        if total_requests > 1000 {
            recommendations.push(CostRecommendation {
                id: Uuid::new_v4().to_string(),
                recommendation_type: RecommendationType::BatchRequests,
                title: "Consider batch API for high-volume workloads".to_string(),
                description: format!(
                    "You made approximately {} requests this week. OpenAI's Batch API offers \
                    50% cost reduction for non-time-sensitive workloads with 24-hour completion.",
                    total_requests
                ),
                estimated_savings: model_usage.iter().map(|(_, c, _)| c).sum::<f64>() * 0.25,
                estimated_savings_percent: 25.0,
                implementation_effort: EffortLevel::High,
                affected_requests: total_requests,
            });
        }

        // Sort by estimated savings (highest first)
        recommendations.sort_by(|a, b| {
            b.estimated_savings.partial_cmp(&a.estimated_savings)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(recommendations)
    }

    /// Get summary statistics
    pub fn get_summary(&self, days: u32) -> Result<AnalyticsSummary> {
        let since = Utc::now() - Duration::days(days as i64);

        let total_spend = self.storage.get_total_spend_since(since)?;
        let model_usage = self.storage.get_spend_by_model(since)?;
        let provider_data = self.storage.get_cost_by_provider(since)?;
        let trend = self.storage.get_daily_trend(days, None)?;

        let total_tokens: u64 = provider_data.iter().map(|(_, _, i, o, _)| i + o).sum();
        let total_requests: u64 = provider_data.iter().map(|(_, _, _, _, r)| r).sum();

        // Calculate week-over-week change
        let current_week: f64 = trend.iter().rev().take(7).map(|d| d.cost).sum();
        let previous_week: f64 = trend.iter().rev().skip(7).take(7).map(|d| d.cost).sum();
        let wow_change = if previous_week > 0.0 {
            ((current_week - previous_week) / previous_week) * 100.0
        } else {
            0.0
        };

        Ok(AnalyticsSummary {
            total_cost: total_spend,
            total_tokens,
            total_requests,
            model_count: model_usage.len(),
            provider_count: provider_data.len(),
            avg_cost_per_request: if total_requests > 0 {
                total_spend / total_requests as f64
            } else {
                0.0
            },
            week_over_week_change: wow_change,
        })
    }

    /// Detect provider from model name
    fn detect_provider_from_model(&self, model: &str) -> String {
        let model_lower = model.to_lowercase();
        if model_lower.contains("gpt") || model_lower.contains("o1") || model_lower.contains("o3") {
            "openai".to_string()
        } else if model_lower.contains("claude") {
            "anthropic".to_string()
        } else if model_lower.contains("gemini") {
            "google".to_string()
        } else {
            "unknown".to_string()
        }
    }
}

/// Summary statistics
#[derive(Debug, Clone)]
pub struct AnalyticsSummary {
    pub total_cost: f64,
    pub total_tokens: u64,
    pub total_requests: u64,
    pub model_count: usize,
    pub provider_count: usize,
    pub avg_cost_per_request: f64,
    pub week_over_week_change: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analytics_creation() {
        let storage = Arc::new(BudgetStorage::in_memory().unwrap());
        let analytics = CostAnalytics::new(storage);

        let trend = analytics.get_trend(7).unwrap();
        assert!(trend.is_empty()); // No data yet
    }

    #[test]
    fn test_empty_recommendations() {
        let storage = Arc::new(BudgetStorage::in_memory().unwrap());
        let analytics = CostAnalytics::new(storage);

        let recs = analytics.generate_recommendations().unwrap();
        assert!(recs.is_empty()); // No data, no recommendations
    }

    #[test]
    fn test_empty_anomalies() {
        let storage = Arc::new(BudgetStorage::in_memory().unwrap());
        let analytics = CostAnalytics::new(storage);

        let anomalies = analytics.detect_anomalies(24).unwrap();
        assert!(anomalies.is_empty()); // No data, no anomalies
    }

    #[test]
    fn test_provider_detection() {
        let storage = Arc::new(BudgetStorage::in_memory().unwrap());
        let analytics = CostAnalytics::new(storage);

        assert_eq!(analytics.detect_provider_from_model("gpt-4o"), "openai");
        assert_eq!(analytics.detect_provider_from_model("claude-sonnet-4"), "anthropic");
        assert_eq!(analytics.detect_provider_from_model("gemini-1.5-pro"), "google");
        assert_eq!(analytics.detect_provider_from_model("unknown-model"), "unknown");
    }
}
