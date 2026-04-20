use soth_core::{AnomalyFlag, InteractionMode, UseCaseLabel};

use crate::traits::{AnomalyScorer, AnomalySignals, ClassificationProvider, ClassificationResult};

pub(crate) struct KeywordClassifier;

impl ClassificationProvider for KeywordClassifier {
    fn classify(&self, _embedding: &[f32]) -> ClassificationResult {
        ClassificationResult {
            label: UseCaseLabel::Unknown,
            confidence: 0.0,
            secondary_label: None,
            interaction_mode: InteractionMode::Unknown,
        }
    }

    fn bundle_version(&self) -> &str {
        "fallback-0.0.0"
    }
}

pub(crate) struct StaticAnomalyScorer;

impl AnomalyScorer for StaticAnomalyScorer {
    fn score(&self, _signals: &AnomalySignals) -> f32 {
        0.0
    }

    fn flags(&self, _signals: &AnomalySignals) -> Vec<AnomalyFlag> {
        Vec::new()
    }
}
