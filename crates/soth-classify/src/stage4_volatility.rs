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
) -> (VolatilityOutput, u64) {
    let started = Instant::now();

    let dynamic_fraction = compute_dynamic_fraction(normalized, content_for_embedding, config);
    let class = classify_dynamic_fraction(dynamic_fraction, config);

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
