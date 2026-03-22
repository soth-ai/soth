use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// SessionKey — identity + time-window key for session lookup
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionKey {
    pub app_identity: SessionAppIdentity,
    pub window_start: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionAppIdentity {
    NativeApp { identity: String },
    BrowserSession { browser: String, ai_origin: String },
}

// ---------------------------------------------------------------------------
// Session — mutable state object owned by proxy SessionManager
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub key: SessionKey,
    pub code_hash_ring: VecDeque<CodeBlob>,
    pub prefix_hash_ring: VecDeque<SeenPrefixRecord>,
    pub stats: SessionStats,
    pub anomaly_baseline: AnomalyBaseline,
    pub created_at: i64,
    pub last_activity: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionStats {
    pub request_count: u32,
    pub total_tokens: u64,
    pub total_cost_usd: f32,
    pub credential_alerts: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnomalyBaseline {
    pub avg_tokens_per_request: f32,
    pub avg_requests_per_hour: f32,
    pub topic_drift_score: f32,
}

// ---------------------------------------------------------------------------
// SessionMutations — plain data carrier returned by detect; proxy applies
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionMutations {
    pub new_prefix_hash: Option<String>,
    pub new_code_hashes: Vec<CodeBlob>,
    pub token_delta: u32,
    pub cost_delta: f32,
    pub anomaly_update: Option<AnomalyDelta>,
    pub credential_alert: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnomalyDelta {
    pub token_burst: bool,
    pub topic_drift: bool,
    pub model_switch: bool,
}

// ---------------------------------------------------------------------------
// Dedup record types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeenPrefixRecord {
    pub hash: String,
    pub timestamp: i64,
    pub event_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeBlob {
    pub ast_normalized_hash: String,
    pub language: String,
    pub first_event_id: Uuid,
}

// ---------------------------------------------------------------------------
// Conversation/message fingerprinting types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConversationFingerprint {
    pub prefix_hash: String,
    pub message_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageFingerprint {
    pub hash: String,
    pub role: String,
    pub token_estimate: u32,
}
