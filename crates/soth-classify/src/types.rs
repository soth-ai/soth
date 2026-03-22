use soth_core::{AnomalyFlag, PolicyDecision, TelemetryEvent, UseCaseLabel, VolatilityClass};

#[derive(Debug, Clone)]
pub struct ClassifiedResult {
    pub use_case_label: UseCaseLabel,
    pub use_case_confidence: f32,
    pub secondary_label: Option<UseCaseLabel>,
    pub topic_cluster_id: u32,
    pub semantic_hash: String,
    /// Raw embedding for local SQLite storage only.
    /// Never included in TelemetryEvent.
    pub embedding: Option<Vec<f32>>,
    pub embedding_norm: f32,
    pub complexity_score: u8,
    pub embedding_skipped: bool,

    pub volatility_class: VolatilityClass,
    pub dynamic_fraction: f32,
    pub is_semantic_collision: bool,
    pub collision_response_stability: Option<f32>,
    pub prefix_repeat_signature: Option<String>,

    pub anomaly_score: f32,
    pub anomaly_flags: Vec<AnomalyFlag>,

    pub policy_decision: PolicyDecision,
    pub policy_enforced: bool,

    pub telemetry_event: TelemetryEvent,
    pub commitment_nonce: [u8; 32],

    pub stage_latencies: StageTiming,
}

#[derive(Debug, Clone, Default)]
pub struct StageTiming {
    pub stage1_us: u64,
    pub stage2_us: u64,
    pub stage3_us: u64,
    pub stage4_us: u64,
    pub stage5_us: u64,
    pub stage6_us: u64,
    pub stage7_us: u64,
    pub total_us: u64,
}
