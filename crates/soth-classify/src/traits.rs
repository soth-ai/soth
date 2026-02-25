use soth_core::{AnomalyFlag, UseCaseLabel};

#[derive(Debug, Clone)]
pub struct ClassificationResult {
    pub label: UseCaseLabel,
    pub confidence: f32,
    pub secondary_label: Option<UseCaseLabel>,
}

#[derive(Debug, Clone, Default)]
pub struct AnomalySignals {
    pub topic_drift_score: f32,
    pub credential_burst: bool,
    pub token_burst_ratio: f32,
    pub model_switched: bool,
    pub inter_request_ms: Option<u64>,
    pub tool_call_depth: u32,
    pub session_request_count: u32,
}

pub trait ClassificationProvider: Send + Sync {
    fn classify(&self, embedding: &[f32]) -> ClassificationResult;
    fn bundle_version(&self) -> &str;
}

pub trait AnomalyScorer: Send + Sync {
    fn score(&self, signals: &AnomalySignals) -> f32;
    fn flags(&self, signals: &AnomalySignals) -> Vec<AnomalyFlag>;
}
