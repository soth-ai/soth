//! Pricing Catalog - LiteLLM-compatible model pricing database
//!
//! Provides:
//! - Embedded default pricing for major AI providers (2025)
//! - Model alias resolution (gpt-4o -> gpt-4o-2024-08-06)
//! - Cache-aware cost calculation (Anthropic prompt caching)
//! - Model suggestions for autocomplete

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use soth_core::types::budget::{ModelPricingEntry, TokenUsage};
use std::collections::HashMap;

/// Pricing catalog with model lookup and alias resolution
pub struct PricingCatalog {
    /// Pricing entries by provider -> model_id
    entries: RwLock<HashMap<String, HashMap<String, ModelPricingEntry>>>,

    /// Alias mapping: alias -> (provider, model_id)
    aliases: RwLock<HashMap<String, (String, String)>>,

    /// Last update timestamp
    last_updated: RwLock<DateTime<Utc>>,
}

impl PricingCatalog {
    /// Create an empty pricing catalog
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            aliases: RwLock::new(HashMap::new()),
            last_updated: RwLock::new(Utc::now()),
        }
    }

    /// Create with embedded default pricing (2025)
    pub fn with_defaults() -> Self {
        let catalog = Self::new();
        catalog.load_embedded_defaults();
        catalog
    }

    /// Load embedded default pricing
    fn load_embedded_defaults(&self) {
        // OpenAI models
        for entry in default_openai_pricing() {
            self.add_entry(entry);
        }

        // Anthropic models
        for entry in default_anthropic_pricing() {
            self.add_entry(entry);
        }

        // Google models
        for entry in default_google_pricing() {
            self.add_entry(entry);
        }

        *self.last_updated.write() = Utc::now();
    }

    /// Add a pricing entry
    pub fn add_entry(&self, entry: ModelPricingEntry) {
        let provider = entry.provider.clone();
        let model_id = entry.model_id.clone();
        let aliases = entry.aliases.clone();

        // Add to entries
        {
            let mut entries = self.entries.write();
            let provider_entries = entries.entry(provider.clone()).or_default();
            provider_entries.insert(model_id.clone(), entry);
        }

        // Add aliases
        {
            let mut alias_map = self.aliases.write();
            for alias in aliases {
                alias_map.insert(alias.to_lowercase(), (provider.clone(), model_id.clone()));
            }
            // Also add the model_id itself as an alias
            alias_map.insert(
                model_id.to_lowercase(),
                (provider.clone(), model_id.clone()),
            );
        }
    }

    /// Get pricing for a model (with alias resolution)
    pub fn get_pricing(&self, model: &str) -> Option<ModelPricingEntry> {
        let model_lower = model.to_lowercase();

        // Try exact alias match first
        if let Some((provider, model_id)) = self.aliases.read().get(&model_lower).cloned() {
            let entries = self.entries.read();
            if let Some(provider_entries) = entries.get(&provider) {
                if let Some(entry) = provider_entries.get(&model_id) {
                    return Some(entry.clone());
                }
            }
        }

        // Try prefix match (e.g., "claude-3-opus-20240229" -> "claude-3-opus")
        let aliases = self.aliases.read();
        for (alias, (provider, model_id)) in aliases.iter() {
            if model_lower.starts_with(alias) || alias.starts_with(&model_lower) {
                let entries = self.entries.read();
                if let Some(provider_entries) = entries.get(provider) {
                    if let Some(entry) = provider_entries.get(model_id) {
                        return Some(entry.clone());
                    }
                }
            }
        }

        None
    }

    /// Calculate cost for token usage
    pub fn calculate_cost(&self, model: &str, usage: &TokenUsage) -> f64 {
        self.calculate_cost_with_cache(model, usage, None, None)
    }

    /// Calculate cost with optional cache tokens
    pub fn calculate_cost_with_cache(
        &self,
        model: &str,
        usage: &TokenUsage,
        cache_read_tokens: Option<u64>,
        cache_write_tokens: Option<u64>,
    ) -> f64 {
        if let Some(pricing) = self.get_pricing(model) {
            pricing.calculate_cost(
                usage.input_tokens,
                usage.output_tokens,
                cache_read_tokens,
                cache_write_tokens,
            )
        } else {
            // Default pricing for unknown models (conservative estimate)
            let default_input = 5.0; // $5 per million input
            let default_output = 15.0; // $15 per million output
            (usage.input_tokens as f64 / 1_000_000.0) * default_input
                + (usage.output_tokens as f64 / 1_000_000.0) * default_output
        }
    }

    /// List all known models for a provider
    pub fn list_models(&self, provider: &str) -> Vec<ModelPricingEntry> {
        let entries = self.entries.read();
        entries
            .get(provider)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// List all known models across all providers
    pub fn list_all_models(&self) -> Vec<ModelPricingEntry> {
        let entries = self.entries.read();
        entries.values().flat_map(|m| m.values().cloned()).collect()
    }

    /// List all providers
    pub fn list_providers(&self) -> Vec<String> {
        self.entries.read().keys().cloned().collect()
    }

    /// Suggest models based on partial query (for autocomplete)
    pub fn suggest_models(&self, query: &str, limit: usize) -> Vec<ModelPricingEntry> {
        let query_lower = query.to_lowercase();
        let entries = self.entries.read();

        let mut matches: Vec<ModelPricingEntry> = entries
            .values()
            .flat_map(|m| m.values())
            .filter(|entry| {
                entry.model_id.to_lowercase().contains(&query_lower)
                    || entry.model_name.to_lowercase().contains(&query_lower)
                    || entry.provider.to_lowercase().contains(&query_lower)
                    || entry
                        .aliases
                        .iter()
                        .any(|a| a.to_lowercase().contains(&query_lower))
            })
            .cloned()
            .collect();

        // Sort by relevance (exact prefix match first, then by name)
        matches.sort_by(|a, b| {
            let a_prefix = a.model_name.to_lowercase().starts_with(&query_lower);
            let b_prefix = b.model_name.to_lowercase().starts_with(&query_lower);
            match (a_prefix, b_prefix) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.model_name.cmp(&b.model_name),
            }
        });

        matches.truncate(limit);
        matches
    }

    /// Get the last update timestamp
    pub fn last_updated(&self) -> DateTime<Utc> {
        *self.last_updated.read()
    }

    /// Detect provider from model name
    pub fn detect_provider(&self, model: &str) -> Option<String> {
        self.get_pricing(model).map(|e| e.provider)
    }
}

impl Default for PricingCatalog {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ============================================================================
// Embedded Default Pricing (2025)
// ============================================================================

/// OpenAI model pricing (January 2025)
fn default_openai_pricing() -> Vec<ModelPricingEntry> {
    vec![
        // GPT-4o family
        ModelPricingEntry {
            model_id: "gpt-4o-2024-08-06".into(),
            model_name: "GPT-4o".into(),
            provider: "openai".into(),
            input_cost_per_million: 2.50,
            output_cost_per_million: 10.00,
            cache_read_cost_per_million: Some(1.25),
            cache_write_cost_per_million: None,
            supports_vision: true,
            supports_tools: true,
            context_window: 128_000,
            max_output_tokens: Some(16_384),
            effective_date: Utc::now(),
            aliases: vec!["gpt-4o".into(), "gpt-4o-latest".into()],
        },
        ModelPricingEntry {
            model_id: "gpt-4o-mini-2024-07-18".into(),
            model_name: "GPT-4o Mini".into(),
            provider: "openai".into(),
            input_cost_per_million: 0.15,
            output_cost_per_million: 0.60,
            cache_read_cost_per_million: Some(0.075),
            cache_write_cost_per_million: None,
            supports_vision: true,
            supports_tools: true,
            context_window: 128_000,
            max_output_tokens: Some(16_384),
            effective_date: Utc::now(),
            aliases: vec!["gpt-4o-mini".into()],
        },
        // o1 reasoning models
        ModelPricingEntry {
            model_id: "o1-2024-12-17".into(),
            model_name: "o1".into(),
            provider: "openai".into(),
            input_cost_per_million: 15.00,
            output_cost_per_million: 60.00,
            cache_read_cost_per_million: Some(7.50),
            cache_write_cost_per_million: None,
            supports_vision: true,
            supports_tools: true,
            context_window: 200_000,
            max_output_tokens: Some(100_000),
            effective_date: Utc::now(),
            aliases: vec!["o1".into(), "o1-latest".into()],
        },
        ModelPricingEntry {
            model_id: "o1-mini-2024-09-12".into(),
            model_name: "o1 Mini".into(),
            provider: "openai".into(),
            input_cost_per_million: 3.00,
            output_cost_per_million: 12.00,
            cache_read_cost_per_million: Some(1.50),
            cache_write_cost_per_million: None,
            supports_vision: false,
            supports_tools: true,
            context_window: 128_000,
            max_output_tokens: Some(65_536),
            effective_date: Utc::now(),
            aliases: vec!["o1-mini".into()],
        },
        ModelPricingEntry {
            model_id: "o3-mini-2025-01-31".into(),
            model_name: "o3 Mini".into(),
            provider: "openai".into(),
            input_cost_per_million: 1.10,
            output_cost_per_million: 4.40,
            cache_read_cost_per_million: Some(0.55),
            cache_write_cost_per_million: None,
            supports_vision: false,
            supports_tools: true,
            context_window: 200_000,
            max_output_tokens: Some(100_000),
            effective_date: Utc::now(),
            aliases: vec!["o3-mini".into(), "o3-mini-latest".into()],
        },
        // Legacy GPT-4 models
        ModelPricingEntry {
            model_id: "gpt-4-turbo-2024-04-09".into(),
            model_name: "GPT-4 Turbo".into(),
            provider: "openai".into(),
            input_cost_per_million: 10.00,
            output_cost_per_million: 30.00,
            cache_read_cost_per_million: None,
            cache_write_cost_per_million: None,
            supports_vision: true,
            supports_tools: true,
            context_window: 128_000,
            max_output_tokens: Some(4_096),
            effective_date: Utc::now(),
            aliases: vec!["gpt-4-turbo".into(), "gpt-4-turbo-preview".into()],
        },
        ModelPricingEntry {
            model_id: "gpt-4-0613".into(),
            model_name: "GPT-4".into(),
            provider: "openai".into(),
            input_cost_per_million: 30.00,
            output_cost_per_million: 60.00,
            cache_read_cost_per_million: None,
            cache_write_cost_per_million: None,
            supports_vision: false,
            supports_tools: true,
            context_window: 8_192,
            max_output_tokens: Some(8_192),
            effective_date: Utc::now(),
            aliases: vec!["gpt-4".into()],
        },
        // GPT-3.5 (legacy)
        ModelPricingEntry {
            model_id: "gpt-3.5-turbo-0125".into(),
            model_name: "GPT-3.5 Turbo".into(),
            provider: "openai".into(),
            input_cost_per_million: 0.50,
            output_cost_per_million: 1.50,
            cache_read_cost_per_million: None,
            cache_write_cost_per_million: None,
            supports_vision: false,
            supports_tools: true,
            context_window: 16_385,
            max_output_tokens: Some(4_096),
            effective_date: Utc::now(),
            aliases: vec!["gpt-3.5-turbo".into()],
        },
    ]
}

/// Anthropic model pricing (January 2025)
fn default_anthropic_pricing() -> Vec<ModelPricingEntry> {
    vec![
        // Claude 4 family
        ModelPricingEntry {
            model_id: "claude-opus-4-20250514".into(),
            model_name: "Claude Opus 4".into(),
            provider: "anthropic".into(),
            input_cost_per_million: 15.00,
            output_cost_per_million: 75.00,
            cache_read_cost_per_million: Some(1.50),
            cache_write_cost_per_million: Some(18.75),
            supports_vision: true,
            supports_tools: true,
            context_window: 200_000,
            max_output_tokens: Some(32_000),
            effective_date: Utc::now(),
            aliases: vec!["claude-opus-4".into(), "claude-4-opus".into()],
        },
        ModelPricingEntry {
            model_id: "claude-sonnet-4-20250514".into(),
            model_name: "Claude Sonnet 4".into(),
            provider: "anthropic".into(),
            input_cost_per_million: 3.00,
            output_cost_per_million: 15.00,
            cache_read_cost_per_million: Some(0.30),
            cache_write_cost_per_million: Some(3.75),
            supports_vision: true,
            supports_tools: true,
            context_window: 200_000,
            max_output_tokens: Some(64_000),
            effective_date: Utc::now(),
            aliases: vec!["claude-sonnet-4".into(), "claude-4-sonnet".into()],
        },
        // Claude 3.5 family
        ModelPricingEntry {
            model_id: "claude-3-5-sonnet-20241022".into(),
            model_name: "Claude 3.5 Sonnet".into(),
            provider: "anthropic".into(),
            input_cost_per_million: 3.00,
            output_cost_per_million: 15.00,
            cache_read_cost_per_million: Some(0.30),
            cache_write_cost_per_million: Some(3.75),
            supports_vision: true,
            supports_tools: true,
            context_window: 200_000,
            max_output_tokens: Some(8_192),
            effective_date: Utc::now(),
            aliases: vec!["claude-3-5-sonnet".into(), "claude-3.5-sonnet".into()],
        },
        ModelPricingEntry {
            model_id: "claude-3-5-haiku-20241022".into(),
            model_name: "Claude 3.5 Haiku".into(),
            provider: "anthropic".into(),
            input_cost_per_million: 0.80,
            output_cost_per_million: 4.00,
            cache_read_cost_per_million: Some(0.08),
            cache_write_cost_per_million: Some(1.00),
            supports_vision: true,
            supports_tools: true,
            context_window: 200_000,
            max_output_tokens: Some(8_192),
            effective_date: Utc::now(),
            aliases: vec!["claude-3-5-haiku".into(), "claude-3.5-haiku".into()],
        },
        // Claude 3 family (legacy)
        ModelPricingEntry {
            model_id: "claude-3-opus-20240229".into(),
            model_name: "Claude 3 Opus".into(),
            provider: "anthropic".into(),
            input_cost_per_million: 15.00,
            output_cost_per_million: 75.00,
            cache_read_cost_per_million: Some(1.50),
            cache_write_cost_per_million: Some(18.75),
            supports_vision: true,
            supports_tools: true,
            context_window: 200_000,
            max_output_tokens: Some(4_096),
            effective_date: Utc::now(),
            aliases: vec!["claude-3-opus".into()],
        },
        ModelPricingEntry {
            model_id: "claude-3-sonnet-20240229".into(),
            model_name: "Claude 3 Sonnet".into(),
            provider: "anthropic".into(),
            input_cost_per_million: 3.00,
            output_cost_per_million: 15.00,
            cache_read_cost_per_million: Some(0.30),
            cache_write_cost_per_million: Some(3.75),
            supports_vision: true,
            supports_tools: true,
            context_window: 200_000,
            max_output_tokens: Some(4_096),
            effective_date: Utc::now(),
            aliases: vec!["claude-3-sonnet".into()],
        },
        ModelPricingEntry {
            model_id: "claude-3-haiku-20240307".into(),
            model_name: "Claude 3 Haiku".into(),
            provider: "anthropic".into(),
            input_cost_per_million: 0.25,
            output_cost_per_million: 1.25,
            cache_read_cost_per_million: Some(0.03),
            cache_write_cost_per_million: Some(0.30),
            supports_vision: true,
            supports_tools: true,
            context_window: 200_000,
            max_output_tokens: Some(4_096),
            effective_date: Utc::now(),
            aliases: vec!["claude-3-haiku".into()],
        },
    ]
}

/// Google model pricing (January 2025)
fn default_google_pricing() -> Vec<ModelPricingEntry> {
    vec![
        // Gemini 2.0
        ModelPricingEntry {
            model_id: "gemini-2.0-flash".into(),
            model_name: "Gemini 2.0 Flash".into(),
            provider: "google".into(),
            input_cost_per_million: 0.10,
            output_cost_per_million: 0.40,
            cache_read_cost_per_million: Some(0.025),
            cache_write_cost_per_million: None,
            supports_vision: true,
            supports_tools: true,
            context_window: 1_000_000,
            max_output_tokens: Some(8_192),
            effective_date: Utc::now(),
            aliases: vec!["gemini-2.0-flash-exp".into()],
        },
        ModelPricingEntry {
            model_id: "gemini-2.0-flash-thinking".into(),
            model_name: "Gemini 2.0 Flash Thinking".into(),
            provider: "google".into(),
            input_cost_per_million: 0.10,
            output_cost_per_million: 0.40,
            cache_read_cost_per_million: None,
            cache_write_cost_per_million: None,
            supports_vision: true,
            supports_tools: true,
            context_window: 1_000_000,
            max_output_tokens: Some(8_192),
            effective_date: Utc::now(),
            aliases: vec!["gemini-2.0-flash-thinking-exp".into()],
        },
        // Gemini 1.5
        ModelPricingEntry {
            model_id: "gemini-1.5-pro".into(),
            model_name: "Gemini 1.5 Pro".into(),
            provider: "google".into(),
            input_cost_per_million: 1.25,
            output_cost_per_million: 5.00,
            cache_read_cost_per_million: Some(0.3125),
            cache_write_cost_per_million: None,
            supports_vision: true,
            supports_tools: true,
            context_window: 2_000_000,
            max_output_tokens: Some(8_192),
            effective_date: Utc::now(),
            aliases: vec!["gemini-1.5-pro-latest".into()],
        },
        ModelPricingEntry {
            model_id: "gemini-1.5-flash".into(),
            model_name: "Gemini 1.5 Flash".into(),
            provider: "google".into(),
            input_cost_per_million: 0.075,
            output_cost_per_million: 0.30,
            cache_read_cost_per_million: Some(0.01875),
            cache_write_cost_per_million: None,
            supports_vision: true,
            supports_tools: true,
            context_window: 1_000_000,
            max_output_tokens: Some(8_192),
            effective_date: Utc::now(),
            aliases: vec!["gemini-1.5-flash-latest".into()],
        },
        ModelPricingEntry {
            model_id: "gemini-1.5-flash-8b".into(),
            model_name: "Gemini 1.5 Flash 8B".into(),
            provider: "google".into(),
            input_cost_per_million: 0.0375,
            output_cost_per_million: 0.15,
            cache_read_cost_per_million: Some(0.01),
            cache_write_cost_per_million: None,
            supports_vision: true,
            supports_tools: true,
            context_window: 1_000_000,
            max_output_tokens: Some(8_192),
            effective_date: Utc::now(),
            aliases: vec!["gemini-1.5-flash-8b-latest".into()],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_catalog_with_defaults() {
        let catalog = PricingCatalog::with_defaults();

        // Check that we have entries for all providers
        assert!(catalog.list_providers().contains(&"openai".to_string()));
        assert!(catalog.list_providers().contains(&"anthropic".to_string()));
        assert!(catalog.list_providers().contains(&"google".to_string()));
    }

    #[test]
    fn test_get_pricing_exact() {
        let catalog = PricingCatalog::with_defaults();

        let pricing = catalog.get_pricing("gpt-4o").unwrap();
        assert_eq!(pricing.provider, "openai");
        assert!((pricing.input_cost_per_million - 2.50).abs() < 0.01);
    }

    #[test]
    fn test_get_pricing_alias() {
        let catalog = PricingCatalog::with_defaults();

        let pricing = catalog.get_pricing("claude-opus-4").unwrap();
        assert_eq!(pricing.provider, "anthropic");
        assert_eq!(pricing.model_name, "Claude Opus 4");
    }

    #[test]
    fn test_get_pricing_prefix() {
        let catalog = PricingCatalog::with_defaults();

        // Should match claude-3-opus-20240229
        let pricing = catalog.get_pricing("claude-3-opus-20240229").unwrap();
        assert_eq!(pricing.provider, "anthropic");
    }

    #[test]
    fn test_calculate_cost() {
        let catalog = PricingCatalog::with_defaults();
        let usage = TokenUsage::new(1_000_000, 500_000);

        // GPT-4o: $2.50/M input + $10/M output = $2.50 + $5 = $7.50
        let cost = catalog.calculate_cost("gpt-4o", &usage);
        assert!((cost - 7.50).abs() < 0.01);
    }

    #[test]
    fn test_calculate_cost_with_cache() {
        let catalog = PricingCatalog::with_defaults();
        let usage = TokenUsage::new(500_000, 500_000);

        // Claude Opus 4 with cache:
        // Input: $15/M * 0.5M = $7.50
        // Output: $75/M * 0.5M = $37.50
        // Cache read: $1.50/M * 0.5M = $0.75
        // Total: $45.75
        let cost = catalog.calculate_cost_with_cache(
            "claude-opus-4",
            &usage,
            Some(500_000), // cache read
            None,
        );
        assert!((cost - 45.75).abs() < 0.01);
    }

    #[test]
    fn test_unknown_model_default_pricing() {
        let catalog = PricingCatalog::with_defaults();
        let usage = TokenUsage::new(1_000_000, 1_000_000);

        // Unknown model should use conservative defaults ($5/M in, $15/M out)
        let cost = catalog.calculate_cost("unknown-model-xyz", &usage);
        assert!((cost - 20.0).abs() < 0.01);
    }

    #[test]
    fn test_suggest_models() {
        let catalog = PricingCatalog::with_defaults();

        let suggestions = catalog.suggest_models("gpt", 5);
        assert!(!suggestions.is_empty());
        assert!(suggestions.iter().any(|s| s.model_name.contains("GPT")));
    }

    #[test]
    fn test_list_models_by_provider() {
        let catalog = PricingCatalog::with_defaults();

        let openai_models = catalog.list_models("openai");
        assert!(openai_models.len() >= 5);

        let anthropic_models = catalog.list_models("anthropic");
        assert!(anthropic_models.len() >= 5);
    }

    #[test]
    fn test_detect_provider() {
        let catalog = PricingCatalog::with_defaults();

        assert_eq!(
            catalog.detect_provider("gpt-4o"),
            Some("openai".to_string())
        );
        assert_eq!(
            catalog.detect_provider("claude-sonnet-4"),
            Some("anthropic".to_string())
        );
        assert_eq!(
            catalog.detect_provider("gemini-1.5-pro"),
            Some("google".to_string())
        );
    }
}
