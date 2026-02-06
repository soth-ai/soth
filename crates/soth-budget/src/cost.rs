//! Cost calculation module

use soth_core::types::budget::TokenUsage;
use std::collections::HashMap;

/// Model pricing configuration
#[derive(Debug, Clone)]
pub struct ModelPricing {
    /// Model identifier
    pub model: String,
    /// Input cost per million tokens (USD)
    pub input_per_million: f64,
    /// Output cost per million tokens (USD)
    pub output_per_million: f64,
}

impl ModelPricing {
    /// Create new model pricing
    pub fn new(model: impl Into<String>, input_per_million: f64, output_per_million: f64) -> Self {
        Self {
            model: model.into(),
            input_per_million,
            output_per_million,
        }
    }

    /// Calculate cost for token usage
    pub fn calculate_cost(&self, usage: &TokenUsage) -> f64 {
        let input_cost = (usage.input_tokens as f64 / 1_000_000.0) * self.input_per_million;
        let output_cost = (usage.output_tokens as f64 / 1_000_000.0) * self.output_per_million;
        input_cost + output_cost
    }
}

/// Cost calculator with model pricing database
pub struct CostCalculator {
    /// Pricing by model name
    pricing: HashMap<String, ModelPricing>,
    /// Default pricing for unknown models
    default_pricing: ModelPricing,
}

impl CostCalculator {
    /// Create a new cost calculator with default pricing (2025)
    pub fn new() -> Self {
        let mut pricing = HashMap::new();

        // Claude models
        pricing.insert(
            "claude-opus-4".to_string(),
            ModelPricing::new("claude-opus-4", 15.0, 75.0),
        );
        pricing.insert(
            "claude-sonnet-4".to_string(),
            ModelPricing::new("claude-sonnet-4", 3.0, 15.0),
        );
        pricing.insert(
            "claude-3-5-sonnet".to_string(),
            ModelPricing::new("claude-3-5-sonnet", 3.0, 15.0),
        );
        pricing.insert(
            "claude-3-opus".to_string(),
            ModelPricing::new("claude-3-opus", 15.0, 75.0),
        );
        pricing.insert(
            "claude-3-sonnet".to_string(),
            ModelPricing::new("claude-3-sonnet", 3.0, 15.0),
        );
        pricing.insert(
            "claude-3-haiku".to_string(),
            ModelPricing::new("claude-3-haiku", 0.25, 1.25),
        );

        // OpenAI models
        pricing.insert("gpt-4o".to_string(), ModelPricing::new("gpt-4o", 5.0, 20.0));
        pricing.insert(
            "gpt-4o-mini".to_string(),
            ModelPricing::new("gpt-4o-mini", 0.15, 0.60),
        );
        pricing.insert(
            "gpt-4-turbo".to_string(),
            ModelPricing::new("gpt-4-turbo", 10.0, 30.0),
        );
        pricing.insert("gpt-4".to_string(), ModelPricing::new("gpt-4", 30.0, 60.0));
        pricing.insert(
            "gpt-3.5-turbo".to_string(),
            ModelPricing::new("gpt-3.5-turbo", 0.50, 1.50),
        );

        // Default pricing (conservative estimate)
        let default_pricing = ModelPricing::new("unknown", 5.0, 15.0);

        Self {
            pricing,
            default_pricing,
        }
    }

    /// Add or update pricing for a model
    pub fn set_pricing(
        &mut self,
        model: impl Into<String>,
        input_per_million: f64,
        output_per_million: f64,
    ) {
        let model = model.into();
        self.pricing.insert(
            model.clone(),
            ModelPricing::new(model, input_per_million, output_per_million),
        );
    }

    /// Get pricing for a model
    pub fn get_pricing(&self, model: &str) -> &ModelPricing {
        // Try exact match
        if let Some(pricing) = self.pricing.get(model) {
            return pricing;
        }

        // Try prefix match (e.g., "claude-3-opus-20240229" -> "claude-3-opus")
        for (key, pricing) in &self.pricing {
            if model.starts_with(key) {
                return pricing;
            }
        }

        &self.default_pricing
    }

    /// Calculate cost for token usage with a specific model
    pub fn calculate_cost(&self, model: &str, usage: &TokenUsage) -> f64 {
        let pricing = self.get_pricing(model);
        pricing.calculate_cost(usage)
    }

    /// Calculate cost given input and output tokens
    pub fn calculate_cost_tokens(&self, model: &str, input_tokens: u64, output_tokens: u64) -> f64 {
        let usage = TokenUsage::new(input_tokens, output_tokens);
        self.calculate_cost(model, &usage)
    }

    /// List all known models
    pub fn list_models(&self) -> Vec<&str> {
        self.pricing.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for CostCalculator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_pricing() {
        let pricing = ModelPricing::new("test", 10.0, 30.0);
        let usage = TokenUsage::new(1_000_000, 500_000);
        let cost = pricing.calculate_cost(&usage);

        // 10 + 15 = 25
        assert!((cost - 25.0).abs() < 0.01);
    }

    #[test]
    fn test_cost_calculator() {
        let calc = CostCalculator::new();

        let cost = calc.calculate_cost_tokens("claude-opus-4", 1_000_000, 500_000);
        // 15 + 37.5 = 52.5
        assert!((cost - 52.5).abs() < 0.01);
    }

    #[test]
    fn test_unknown_model() {
        let calc = CostCalculator::new();
        let pricing = calc.get_pricing("unknown-model");
        assert_eq!(pricing.model, "unknown");
    }

    #[test]
    fn test_prefix_match() {
        let calc = CostCalculator::new();
        let pricing = calc.get_pricing("claude-3-opus-20240229");
        assert!(pricing.model.starts_with("claude-3-opus"));
    }

    #[test]
    fn test_list_models() {
        let calc = CostCalculator::new();
        let models = calc.list_models();
        assert!(models.contains(&"claude-opus-4"));
        assert!(models.contains(&"gpt-4o"));
    }
}
