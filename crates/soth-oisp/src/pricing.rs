use crate::types::provider::ModelPricing;
use std::collections::BTreeMap;

pub(crate) fn find_model_pricing<'a>(
    models: &'a BTreeMap<String, ModelPricing>,
    model: &str,
) -> Option<(&'a str, &'a ModelPricing)> {
    let model_lower = model.to_ascii_lowercase();

    if let Some((id, pricing)) = models
        .iter()
        .find(|(id, _)| id.eq_ignore_ascii_case(model_lower.as_str()))
    {
        return Some((id.as_str(), pricing));
    }

    models
        .iter()
        .filter(|(id, _)| {
            let id_lower = id.to_ascii_lowercase();
            model_lower.starts_with(id_lower.as_str()) || id_lower.starts_with(model_lower.as_str())
        })
        .max_by_key(|(id, _)| id.len())
        .map(|(id, pricing)| (id.as_str(), pricing))
}

pub(crate) fn calculate_cost_from_pricing(
    pricing: &ModelPricing,
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: Option<u64>,
    cache_write_tokens: Option<u64>,
) -> Option<f64> {
    let input_rate = pricing.input_per_million_usd.unwrap_or(0.0);
    let output_rate = pricing.output_per_million_usd.unwrap_or(0.0);
    let cache_read_rate = pricing.cache_read_per_million_usd.unwrap_or(0.0);
    let cache_write_rate = pricing.cache_write_per_million_usd.unwrap_or(0.0);

    if input_rate == 0.0 && output_rate == 0.0 && cache_read_rate == 0.0 && cache_write_rate == 0.0
    {
        return None;
    }

    let cost = (input_tokens as f64 / 1_000_000.0) * input_rate
        + (output_tokens as f64 / 1_000_000.0) * output_rate
        + (cache_read_tokens.unwrap_or(0) as f64 / 1_000_000.0) * cache_read_rate
        + (cache_write_tokens.unwrap_or(0) as f64 / 1_000_000.0) * cache_write_rate;
    Some(cost)
}
