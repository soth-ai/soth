use std::sync::Once;

use soth_core::{AnomalyFlag, InteractionMode, UseCaseLabel, UseCaseLabelReason};

use crate::traits::{AnomalyScorer, AnomalySignals, ClassificationProvider, ClassificationResult};

pub(crate) struct KeywordClassifier;

static FALLBACK_WARN_ONCE: Once = Once::new();

impl ClassificationProvider for KeywordClassifier {
    fn classify(&self, _embedding: &[f32]) -> ClassificationResult {
        // Log once per process: a real bundle was expected but a fallback
        // was wired. This is graceful degradation, not a per-call failure,
        // so we suppress the WARN after the first call.
        FALLBACK_WARN_ONCE.call_once(|| {
            tracing::warn!(
                "soth-classify is using KeywordClassifier fallback bundle; \
                 every event will emit use_case_label=Unknown with \
                 reason=FallbackBundle until a real bundle is loaded"
            );
        });
        ClassificationResult {
            label: UseCaseLabel::Unknown,
            confidence: 0.0,
            secondary_label: None,
            interaction_mode: InteractionMode::Unknown,
            label_reason: UseCaseLabelReason::FallbackBundle,
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
