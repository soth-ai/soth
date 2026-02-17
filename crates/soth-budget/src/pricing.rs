//! Pricing catalog storage.
//!
//! Runtime pricing is bundle/cloud-driven. This catalog is an in-memory container
//! that can be populated from external sources; it does not ship embedded defaults.

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use soth_core::types::budget::{ModelPricingEntry, TokenUsage};
use std::collections::HashMap;

/// Pricing catalog with model lookup and alias resolution.
pub struct PricingCatalog {
    /// Pricing entries by provider -> model_id.
    entries: RwLock<HashMap<String, HashMap<String, ModelPricingEntry>>>,
    /// Alias mapping: alias -> (provider, model_id).
    aliases: RwLock<HashMap<String, (String, String)>>,
    /// Last update timestamp.
    last_updated: RwLock<DateTime<Utc>>,
}

impl PricingCatalog {
    /// Create an empty pricing catalog.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            aliases: RwLock::new(HashMap::new()),
            last_updated: RwLock::new(Utc::now()),
        }
    }

    /// Add a pricing entry.
    pub fn add_entry(&self, entry: ModelPricingEntry) {
        let provider = entry.provider.clone();
        let model_id = entry.model_id.clone();
        let aliases = entry.aliases.clone();

        {
            let mut entries = self.entries.write();
            let provider_entries = entries.entry(provider.clone()).or_default();
            provider_entries.insert(model_id.clone(), entry);
        }

        {
            let mut alias_map = self.aliases.write();
            for alias in aliases {
                alias_map.insert(alias.to_lowercase(), (provider.clone(), model_id.clone()));
            }
            alias_map.insert(
                model_id.to_lowercase(),
                (provider.clone(), model_id.clone()),
            );
        }

        *self.last_updated.write() = Utc::now();
    }

    /// Get pricing for a model (with alias resolution).
    pub fn get_pricing(&self, model: &str) -> Option<ModelPricingEntry> {
        let model_lower = model.to_lowercase();

        if let Some((provider, model_id)) = self.aliases.read().get(&model_lower).cloned() {
            let entries = self.entries.read();
            if let Some(provider_entries) = entries.get(&provider) {
                if let Some(entry) = provider_entries.get(&model_id) {
                    return Some(entry.clone());
                }
            }
        }

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

    /// Calculate cost for token usage.
    pub fn calculate_cost(&self, model: &str, usage: &TokenUsage) -> f64 {
        self.calculate_cost_with_cache(model, usage, None, None)
    }

    /// Calculate cost with optional cache tokens.
    pub fn calculate_cost_with_cache(
        &self,
        model: &str,
        usage: &TokenUsage,
        cache_read_tokens: Option<u64>,
        cache_write_tokens: Option<u64>,
    ) -> f64 {
        self.get_pricing(model)
            .map(|pricing| {
                pricing.calculate_cost(
                    usage.input_tokens,
                    usage.output_tokens,
                    cache_read_tokens,
                    cache_write_tokens,
                )
            })
            .unwrap_or(0.0)
    }

    /// List all known models for a provider.
    pub fn list_models(&self, provider: &str) -> Vec<ModelPricingEntry> {
        let entries = self.entries.read();
        entries
            .get(provider)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// List all known models across all providers.
    pub fn list_all_models(&self) -> Vec<ModelPricingEntry> {
        let entries = self.entries.read();
        entries.values().flat_map(|m| m.values().cloned()).collect()
    }

    /// List all providers.
    pub fn list_providers(&self) -> Vec<String> {
        self.entries.read().keys().cloned().collect()
    }

    /// Suggest models based on partial query.
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

    /// Get last update timestamp.
    pub fn last_updated(&self) -> DateTime<Utc> {
        *self.last_updated.read()
    }

    /// Detect provider from model name.
    pub fn detect_provider(&self, model: &str) -> Option<String> {
        self.get_pricing(model).map(|e| e.provider)
    }
}

impl Default for PricingCatalog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_catalog() -> PricingCatalog {
        let catalog = PricingCatalog::new();
        catalog.add_entry(ModelPricingEntry {
            model_id: "gpt-4o-2024-08-06".into(),
            model_name: "GPT-4o".into(),
            provider: "openai".into(),
            input_cost_per_million: 2.50,
            output_cost_per_million: 10.0,
            cache_read_cost_per_million: Some(1.25),
            cache_write_cost_per_million: None,
            supports_vision: true,
            supports_tools: true,
            context_window: 128_000,
            max_output_tokens: Some(16_384),
            effective_date: Utc::now(),
            aliases: vec!["gpt-4o".into(), "gpt-4o-latest".into()],
        });
        catalog.add_entry(ModelPricingEntry {
            model_id: "claude-opus-4-1".into(),
            model_name: "Claude Opus 4.1".into(),
            provider: "anthropic".into(),
            input_cost_per_million: 15.0,
            output_cost_per_million: 75.0,
            cache_read_cost_per_million: None,
            cache_write_cost_per_million: None,
            supports_vision: true,
            supports_tools: true,
            context_window: 200_000,
            max_output_tokens: Some(8192),
            effective_date: Utc::now(),
            aliases: vec!["claude-opus-4".into()],
        });
        catalog
    }

    #[test]
    fn test_get_pricing_by_alias() {
        let catalog = seed_catalog();
        let pricing = catalog.get_pricing("gpt-4o").unwrap();
        assert_eq!(pricing.model_name, "GPT-4o");
    }

    #[test]
    fn test_get_pricing_by_prefix_match() {
        let catalog = seed_catalog();
        let pricing = catalog.get_pricing("claude-opus-4-20260101").unwrap();
        assert_eq!(pricing.provider, "anthropic");
    }

    #[test]
    fn test_calculate_cost() {
        let catalog = seed_catalog();
        let usage = TokenUsage::new(1_000_000, 500_000);
        let cost = catalog.calculate_cost("gpt-4o", &usage);
        assert!((cost - 7.5).abs() < 0.001);
    }

    #[test]
    fn test_calculate_cost_with_cache() {
        let catalog = seed_catalog();
        let usage = TokenUsage::new(1_000_000, 500_000);
        let cost = catalog.calculate_cost_with_cache("gpt-4o", &usage, Some(500_000), None);
        assert!((cost - 8.125).abs() < 0.001);
    }

    #[test]
    fn test_unknown_model_cost_is_zero() {
        let catalog = seed_catalog();
        let usage = TokenUsage::new(1000, 500);
        let cost = catalog.calculate_cost("unknown-model-xyz", &usage);
        assert_eq!(cost, 0.0);
    }

    #[test]
    fn test_suggest_models() {
        let catalog = seed_catalog();
        let suggestions = catalog.suggest_models("gpt", 5);
        assert!(!suggestions.is_empty());
        assert!(suggestions.iter().any(|s| s.model_name.contains("GPT")));
    }

    #[test]
    fn test_list_models() {
        let catalog = seed_catalog();
        assert!(!catalog.list_models("openai").is_empty());
        assert!(!catalog.list_models("anthropic").is_empty());
    }

    #[test]
    fn test_detect_provider() {
        let catalog = seed_catalog();
        assert_eq!(
            catalog.detect_provider("gpt-4o"),
            Some("openai".to_string())
        );
        assert_eq!(
            catalog.detect_provider("claude-opus-4"),
            Some("anthropic".to_string())
        );
        assert_eq!(catalog.detect_provider("missing"), None);
    }
}
