use std::time::Instant;

use soth_core::UseCaseLabel;

use crate::config::ClassifyConfig;
use crate::traits::ClassificationProvider;

#[derive(Debug, Clone)]
pub(crate) struct UsecaseOutput {
    pub label: UseCaseLabel,
    pub confidence: f32,
    pub secondary_label: Option<UseCaseLabel>,
    pub complexity_score: u8,
}

impl UsecaseOutput {
    pub fn unknown() -> Self {
        Self {
            label: UseCaseLabel::Unknown,
            confidence: 0.0,
            secondary_label: None,
            complexity_score: 1,
        }
    }
}

pub(crate) fn run(
    embedding: Option<&[f32]>,
    classifier: &dyn ClassificationProvider,
    normalized: &soth_core::NormalizedRequest,
    config: &ClassifyConfig,
) -> (UsecaseOutput, u64) {
    let started = Instant::now();
    let complexity_score = compute_complexity(normalized, &config.complexity_weights);

    let Some(embedding) = embedding else {
        return (
            UsecaseOutput {
                complexity_score,
                ..UsecaseOutput::unknown()
            },
            started.elapsed().as_micros() as u64,
        );
    };

    let classified = classifier.classify(embedding);
    let confidence = classified.confidence.clamp(0.0, 1.0);
    let secondary_label = if confidence < 0.40 {
        classified
            .secondary_label
            .filter(|secondary| *secondary != classified.label)
    } else {
        None
    };

    (
        UsecaseOutput {
            label: classified.label,
            confidence,
            secondary_label,
            complexity_score,
        },
        started.elapsed().as_micros() as u64,
    )
}

fn compute_complexity(
    normalized: &soth_core::NormalizedRequest,
    weights: &crate::config::ComplexityWeights,
) -> u8 {
    let token_score = (normalized.user_content_token_estimate as f32 / 100_000.0).clamp(0.0, 1.0);
    let tool_score = if normalized.has_tool_definitions {
        1.0
    } else {
        0.0
    };
    let turn_score = (normalized.conversation_turn.unwrap_or(0) as f32 / 20.0).clamp(0.0, 1.0);

    let weighted = token_score * weights.token_weight
        + tool_score * weights.tool_count_weight
        + turn_score * weights.turn_depth_weight;
    let total_weight =
        (weights.token_weight + weights.tool_count_weight + weights.turn_depth_weight).max(1e-6);
    let raw = (weighted / total_weight).clamp(0.0, 1.0);

    (raw.mul_add(4.0, 1.0)).round().clamp(1.0, 5.0) as u8
}
