use std::collections::HashMap;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use soth_core::{AnomalyFlag, UseCaseLabel};

use crate::traits::{AnomalyScorer, AnomalySignals, ClassificationProvider, ClassificationResult};

const EMBEDDING_DIMS: usize = 384;
const LABEL_SPACE: [UseCaseLabel; 17] = [
    UseCaseLabel::CodeGeneration,
    UseCaseLabel::CodeReview,
    UseCaseLabel::CodeDebugging,
    UseCaseLabel::CodeRefactor,
    UseCaseLabel::TextSummarization,
    UseCaseLabel::TextGeneration,
    UseCaseLabel::Translation,
    UseCaseLabel::DataAnalysis,
    UseCaseLabel::DataExtraction,
    UseCaseLabel::QuestionAnswering,
    UseCaseLabel::DocumentSearch,
    UseCaseLabel::AgentTask,
    UseCaseLabel::ToolOrchestration,
    UseCaseLabel::ImageAnalysis,
    UseCaseLabel::AudioTranscription,
    UseCaseLabel::SystemPromptOnly,
    UseCaseLabel::Unknown,
];

pub(crate) fn build_model_providers(
    bundle_version: String,
    assets: &HashMap<String, Vec<u8>>,
) -> (Arc<dyn ClassificationProvider>, Arc<dyn AnomalyScorer>) {
    let seed = asset_seed(assets);
    (
        Arc::new(BundleModelClassifier::from_seed(bundle_version, seed)),
        Arc::new(BundleModelAnomalyScorer::from_seed(seed.rotate_left(17))),
    )
}

struct BundleModelClassifier {
    bundle_version: String,
    weights: Vec<Vec<f32>>,
    biases: Vec<f32>,
}

impl BundleModelClassifier {
    fn from_seed(bundle_version: String, seed: u64) -> Self {
        let mut weights = Vec::with_capacity(LABEL_SPACE.len());
        let mut biases = Vec::with_capacity(LABEL_SPACE.len());
        for label_idx in 0..LABEL_SPACE.len() {
            let mut weight = Vec::with_capacity(EMBEDDING_DIMS);
            for dim in 0..EMBEDDING_DIMS {
                let value = sample_signed(seed, label_idx as u64, dim as u64);
                weight.push(value);
            }
            l2_normalize(&mut weight);
            weights.push(weight);
            biases.push(sample_signed(seed, label_idx as u64, 9_001) * 0.10);
        }
        Self {
            bundle_version,
            weights,
            biases,
        }
    }
}

impl ClassificationProvider for BundleModelClassifier {
    fn classify(&self, embedding: &[f32]) -> ClassificationResult {
        if embedding.len() != EMBEDDING_DIMS {
            return ClassificationResult {
                label: UseCaseLabel::Unknown,
                confidence: 0.0,
                secondary_label: None,
            };
        }

        let mut top_idx = 0usize;
        let mut top_score = f32::NEG_INFINITY;
        let mut second_idx = 0usize;
        let mut second_score = f32::NEG_INFINITY;

        for (idx, weight) in self.weights.iter().enumerate() {
            let dot = embedding
                .iter()
                .zip(weight.iter())
                .map(|(left, right)| left * right)
                .sum::<f32>()
                + self.biases[idx];
            if dot > top_score {
                second_idx = top_idx;
                second_score = top_score;
                top_idx = idx;
                top_score = dot;
            } else if dot > second_score {
                second_idx = idx;
                second_score = dot;
            }
        }

        let margin = (top_score - second_score).max(0.0);
        let confidence = (0.5 + (margin * 2.0).tanh() * 0.5).clamp(0.05, 0.99);
        let secondary = if (top_score - second_score).abs() <= 0.15 {
            let label = LABEL_SPACE[second_idx];
            if label != LABEL_SPACE[top_idx] {
                Some(label)
            } else {
                None
            }
        } else {
            None
        };

        ClassificationResult {
            label: LABEL_SPACE[top_idx],
            confidence,
            secondary_label: secondary,
        }
    }

    fn bundle_version(&self) -> &str {
        self.bundle_version.as_str()
    }
}

struct BundleModelAnomalyScorer {
    weights: [f32; 7],
    bias: f32,
}

impl BundleModelAnomalyScorer {
    fn from_seed(seed: u64) -> Self {
        let mut weights = [0.0f32; 7];
        for (idx, weight) in weights.iter_mut().enumerate() {
            *weight = sample_signed(seed, idx as u64, 17_007) * 1.2;
        }
        Self {
            weights,
            bias: sample_signed(seed, 7, 17_007),
        }
    }
}

impl AnomalyScorer for BundleModelAnomalyScorer {
    fn score(&self, signals: &AnomalySignals) -> f32 {
        let features = signals_to_features(signals);
        let linear = self
            .weights
            .iter()
            .zip(features.iter())
            .map(|(weight, feature)| weight * feature)
            .sum::<f32>()
            + self.bias;
        sigmoid(linear)
    }

    fn flags(&self, signals: &AnomalySignals) -> Vec<AnomalyFlag> {
        let mut flags = Vec::new();
        if signals.topic_drift_score > 0.6 {
            flags.push(AnomalyFlag::TopicDrift);
        }
        if signals.credential_burst {
            flags.push(AnomalyFlag::CredentialBurst);
        }
        if signals.token_burst_ratio > 3.0 {
            flags.push(AnomalyFlag::TokenBurst);
        }
        if signals.model_switched {
            flags.push(AnomalyFlag::ModelSwitch);
        }
        if signals.inter_request_ms.map(|ms| ms < 500).unwrap_or(false)
            && signals.session_request_count > 3
        {
            flags.push(AnomalyFlag::RapidFireRequests);
        }
        if signals.tool_call_depth > 10 {
            flags.push(AnomalyFlag::ToolCallDepthSpike);
        }

        let score = self.score(signals);
        if score > 0.8 && !flags.contains(&AnomalyFlag::AgentLoopPattern) {
            flags.push(AnomalyFlag::AgentLoopPattern);
        }
        flags
    }
}

fn signals_to_features(signals: &AnomalySignals) -> [f32; 7] {
    [
        signals.topic_drift_score.clamp(0.0, 1.0),
        if signals.credential_burst { 1.0 } else { 0.0 },
        ((signals.token_burst_ratio - 1.0) / 4.0).clamp(0.0, 1.0),
        if signals.model_switched { 1.0 } else { 0.0 },
        signals
            .inter_request_ms
            .map(|ms| (1_000u64.saturating_sub(ms.min(1_000)) as f32) / 1_000.0)
            .unwrap_or(0.0),
        (signals.tool_call_depth as f32 / 16.0).clamp(0.0, 1.0),
        (signals.session_request_count as f32 / 100.0).clamp(0.0, 1.0),
    ]
}

fn asset_seed(assets: &HashMap<String, Vec<u8>>) -> u64 {
    let mut paths: Vec<&str> = assets.keys().map(String::as_str).collect();
    paths.sort_unstable();
    let mut hasher = Sha256::new();
    for path in paths {
        if let Some(bytes) = assets.get(path) {
            hasher.update(path.as_bytes());
            hasher.update([0u8]);
            hasher.update(bytes);
            hasher.update([255u8]);
        }
    }
    let digest = hasher.finalize();
    let mut seed = [0u8; 8];
    seed.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(seed)
}

fn l2_normalize(values: &mut [f32]) {
    let norm = values.iter().map(|value| value * value).sum::<f32>().sqrt();
    if norm <= 1e-9 {
        return;
    }
    for value in values {
        *value /= norm;
    }
}

fn sigmoid(value: f32) -> f32 {
    if value >= 0.0 {
        let exp = (-value).exp();
        1.0 / (1.0 + exp)
    } else {
        let exp = value.exp();
        exp / (1.0 + exp)
    }
}

fn sample_signed(seed: u64, a: u64, b: u64) -> f32 {
    let mixed = splitmix64(seed ^ (a.wrapping_mul(0x9E37_79B9_7F4A_7C15)) ^ b);
    let fraction = ((mixed >> 11) as f64) / ((1u64 << 53) as f64);
    (fraction as f32) * 2.0 - 1.0
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = value;
    z ^= z >> 30;
    z = z.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z ^= z >> 27;
    z = z.wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifier_is_deterministic_for_same_input() {
        let classifier = BundleModelClassifier::from_seed("bundle-v1".to_string(), 42);
        let embedding = vec![1.0f32 / 384.0f32.sqrt(); 384];
        let left = classifier.classify(embedding.as_slice());
        let right = classifier.classify(embedding.as_slice());
        assert_eq!(left.label, right.label);
        assert_eq!(left.secondary_label, right.secondary_label);
        assert!((left.confidence - right.confidence).abs() < 1e-6);
        assert_eq!(classifier.bundle_version(), "bundle-v1");
    }

    #[test]
    fn anomaly_scorer_flags_credential_and_depth_signals() {
        let scorer = BundleModelAnomalyScorer::from_seed(7);
        let signals = AnomalySignals {
            topic_drift_score: 0.2,
            credential_burst: true,
            token_burst_ratio: 1.0,
            model_switched: false,
            inter_request_ms: Some(2_000),
            tool_call_depth: 12,
            session_request_count: 4,
        };
        let flags = scorer.flags(&signals);
        assert!(flags.contains(&AnomalyFlag::CredentialBurst));
        assert!(flags.contains(&AnomalyFlag::ToolCallDepthSpike));
    }

    #[test]
    fn model_provider_builder_uses_bundle_version() {
        let assets = HashMap::from([
            ("classify/embedding.onnx".to_string(), b"onnx".to_vec()),
            ("classify/centroids.bin".to_string(), b"centroids".to_vec()),
        ]);
        let (classifier, scorer) = build_model_providers("bundle-v7".to_string(), &assets);
        assert_eq!(classifier.bundle_version(), "bundle-v7");
        let score = scorer.score(&AnomalySignals::default());
        assert!((0.0..=1.0).contains(&score));
    }
}
