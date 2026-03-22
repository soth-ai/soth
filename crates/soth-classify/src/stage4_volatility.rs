use sha2::{Digest, Sha256};
use std::time::Instant;

use soth_core::VolatilityClass;

use crate::config::VolatilityConfig;

#[derive(Debug, Clone)]
pub(crate) struct VolatilityOutput {
    pub class: VolatilityClass,
    pub dynamic_fraction: f32,
    pub prefix_repeat_signature: Option<String>,
}

impl Default for VolatilityOutput {
    fn default() -> Self {
        Self {
            class: VolatilityClass::Static,
            dynamic_fraction: 0.0,
            prefix_repeat_signature: None,
        }
    }
}

pub(crate) fn run(
    normalized: &soth_core::NormalizedRequest,
    content_for_embedding: Option<&str>,
    config: &VolatilityConfig,
    bundle_override: Option<&VolatilityConfig>,
) -> (VolatilityOutput, u64) {
    let started = Instant::now();
    let effective_config = bundle_override.unwrap_or(config);

    let dynamic_fraction =
        compute_dynamic_fraction(normalized, content_for_embedding, effective_config);
    let class = classify_dynamic_fraction(dynamic_fraction, effective_config);

    (
        VolatilityOutput {
            class,
            dynamic_fraction,
            prefix_repeat_signature: prefix_signature(normalized),
        },
        started.elapsed().as_micros() as u64,
    )
}

fn classify_dynamic_fraction(dynamic_fraction: f32, config: &VolatilityConfig) -> VolatilityClass {
    let static_threshold = config.static_threshold.clamp(0.0, 1.0);
    let low_volatile_threshold = config.low_volatile_threshold.clamp(static_threshold, 1.0);
    let dynamic_threshold = config.dynamic_threshold.clamp(low_volatile_threshold, 1.0);

    if dynamic_fraction < static_threshold {
        VolatilityClass::Static
    } else if dynamic_fraction < low_volatile_threshold {
        VolatilityClass::LowVolatile
    } else if dynamic_fraction < dynamic_threshold {
        VolatilityClass::Dynamic
    } else {
        VolatilityClass::HighlyDynamic
    }
}

fn compute_dynamic_fraction(
    normalized: &soth_core::NormalizedRequest,
    content_for_embedding: Option<&str>,
    config: &VolatilityConfig,
) -> f32 {
    let mut score = (normalized.conversation_turn.unwrap_or(0) as f32 / 10.0).clamp(0.0, 0.3);

    if normalized.has_tool_definitions && normalized.conversation_turn.unwrap_or(0) > 1 {
        score += 0.2;
    }

    // Confirmed tool results in context = live dynamic data
    if normalized.has_tool_results {
        score += 0.30;
    }

    // Deep tool cycle (many turns + tools) = agent loop with live values
    if normalized.has_tool_definitions && normalized.conversation_turn.unwrap_or(0) > 5 {
        score += 0.15;
    }

    if let Some(text) = content_for_embedding {
        let text_lc = text.to_ascii_lowercase();
        let temporal_hits = config
            .temporal_keywords
            .iter()
            .filter(|keyword| text_lc.contains(&keyword.to_ascii_lowercase()))
            .count();
        score += (temporal_hits as f32 * 0.05).clamp(0.0, 0.2);

        let pronoun_hits = config
            .pronoun_keywords
            .iter()
            .filter(|keyword| text_lc.contains(&keyword.to_ascii_lowercase()))
            .count();
        score += (pronoun_hits as f32 * 0.03).clamp(0.0, 0.15);
    }

    score.clamp(0.0, 1.0)
}

fn prefix_signature(normalized: &soth_core::NormalizedRequest) -> Option<String> {
    match (
        normalized.system_prompt_hash.as_deref(),
        normalized.tool_definition_hash.as_deref(),
    ) {
        (None, None) => None,
        (system_prompt_hash, tool_definition_hash) => {
            let input = format!(
                "{}|{}",
                system_prompt_hash.unwrap_or_default(),
                tool_definition_hash.unwrap_or_default()
            );
            let mut hasher = Sha256::new();
            hasher.update(input.as_bytes());
            let digest = hasher.finalize();
            Some(hex::encode(digest)[..16].to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soth_core::{DetectedProvider, EndpointType, FormatMetadata, ParseConfidence, ParseSource};

    fn sample_normalized() -> soth_core::NormalizedRequest {
        soth_core::NormalizedRequest {
            parse_confidence: ParseConfidence::Full,
            parser_id: "unit".to_string(),
            schema_version: "1".to_string(),
            parse_warnings: Vec::new(),
            is_ai_call: true,
            provider: "openai".to_string(),
            model: Some("gpt-4o-mini".to_string()),
            endpoint_type: EndpointType::ChatCompletion,
            api_version: None,
            system_prompt_hash: Some("sys".to_string()),
            system_prompt_token_estimate: Some(12),
            user_content_hash: "u".to_string(),
            user_content_token_estimate: 200,
            conversation_hash: "c".to_string(),
            conversation_turn: Some(2),
            has_tool_definitions: false,
            tool_definition_hash: Some("tools".to_string()),
            temperature: None,
            max_tokens: Some(256),
            stream: false,
            top_p: None,
            stop_sequences: Vec::new(),
            estimated_input_tokens: 200,
            estimated_cost_usd: 0.02,
            parse_source: ParseSource::Rest {
                provider: DetectedProvider::OpenAi,
            },
            canonical_cache_key: "key".to_string(),
            format_metadata: FormatMetadata::Unknown {
                method: String::new(),
                path: String::new(),
            },
            has_structured_output: false,
            has_tool_results: false,
            estimated_output_tokens: None,
            user_prompt: None,
        }
    }

    #[test]
    fn run_uses_bundle_override_thresholds() {
        let normalized = sample_normalized();
        let base = VolatilityConfig::default();
        let mut override_cfg = VolatilityConfig::default();
        override_cfg.static_threshold = 0.0;
        override_cfg.low_volatile_threshold = 0.1;
        override_cfg.dynamic_threshold = 0.2;
        override_cfg.temporal_keywords = vec!["today".to_string()];
        override_cfg.pronoun_keywords = vec!["my ".to_string()];

        let content = Some("today my project status");
        let (base_out, _) = run(&normalized, content, &base, None);
        let (override_out, _) = run(&normalized, content, &base, Some(&override_cfg));

        assert_ne!(base_out.class, override_out.class);
        assert!(override_out.dynamic_fraction >= base_out.dynamic_fraction);
    }

    #[test]
    fn run_emits_prefix_signature_when_prompt_or_tools_exist() {
        let normalized = sample_normalized();
        let cfg = VolatilityConfig::default();
        let (out, _) = run(&normalized, None, &cfg, None);
        assert!(out.prefix_repeat_signature.is_some());
    }
}
