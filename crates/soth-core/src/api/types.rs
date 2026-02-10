//! Shared API request/response structures for edge <-> cloud communication.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBatchRequest {
    pub agent_instance_id: String,
    pub config_version: Option<String>,
    pub batch: Vec<EventMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMetadata {
    pub id: String,
    pub timestamp: String,
    pub session_id: Option<String>,
    pub source: String,
    pub direction: String,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub method: Option<String>,
    pub status_code: Option<u16>,
    pub latency_ms: Option<u64>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cache_read_tokens: Option<u64>,
    pub cache_write_tokens: Option<u64>,
    pub reasoning_tokens: Option<u64>,
    pub cost_usd: Option<f64>,
    pub request_size_bytes: Option<u64>,
    pub response_size_bytes: Option<u64>,
    pub has_body: bool,
    pub pii_detected: bool,
    pub pii_types: Vec<String>,
    pub policy_allowed: Option<bool>,
    pub policy_version: Option<String>,
    pub agent_name: Option<String>,
    pub server_name: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub mcp_tool_name: Option<String>,
    pub mcp_body_truncated: bool,
    pub mcp_body_preview: Option<String>,
    pub tags: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBatchResponse {
    pub accepted: u64,
    pub rejected: u64,
    pub errors: Vec<EventError>,
    pub config_changed: bool,
    pub server_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventError {
    pub event_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyUploadResponse {
    pub stored: bool,
    pub request_key: Option<String>,
    pub response_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigResponse {
    pub user: ConfigUser,
    pub team: ConfigTeam,
    pub org: ConfigOrg,
    pub policies: Vec<ConfigPolicy>,
    pub budget: ConfigBudget,
    pub body_sync_level: String,
    pub config_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigUser {
    pub id: String,
    pub name: String,
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigTeam {
    pub id: String,
    pub name: String,
    pub slug: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigOrg {
    pub id: String,
    pub name: String,
    pub plan: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigPolicy {
    pub name: String,
    pub scope: String,
    pub rego: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigBudget {
    pub enforcement: String,
    pub limits: Vec<ConfigBudgetLimit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigBudgetLimit {
    pub scope: String,
    pub model: Option<String>,
    pub daily_usd: Option<f64>,
    pub weekly_usd: Option<f64>,
    pub monthly_usd: Option<f64>,
    pub remaining_usd: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub agent_instance_id: String,
    pub proxy_version: String,
    pub config_version: Option<String>,
    pub os: Option<String>,
    pub hostname: Option<String>,
    pub active_connections: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub ok: bool,
    pub config_changed: bool,
    pub server_time: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_batch_roundtrip() {
        let req = EventBatchRequest {
            agent_instance_id: "agent-1".to_string(),
            config_version: Some("v1".to_string()),
            batch: vec![EventMetadata {
                id: "evt-1".to_string(),
                timestamp: "2026-02-01T00:00:00Z".to_string(),
                session_id: Some("sess-1".to_string()),
                source: "ai_proxy".to_string(),
                direction: "out".to_string(),
                provider: Some("openai".to_string()),
                model: Some("gpt-5".to_string()),
                method: Some("POST /v1/responses".to_string()),
                status_code: Some(200),
                latency_ms: Some(123),
                input_tokens: Some(10),
                output_tokens: Some(20),
                cache_read_tokens: Some(3),
                cache_write_tokens: Some(2),
                reasoning_tokens: Some(1),
                cost_usd: Some(0.0123),
                request_size_bytes: Some(1024),
                response_size_bytes: Some(2048),
                has_body: true,
                pii_detected: false,
                pii_types: vec![],
                policy_allowed: Some(true),
                policy_version: Some("policy-v1".to_string()),
                agent_name: Some("codex".to_string()),
                server_name: Some("chatgpt.com".to_string()),
                headers: None,
                mcp_tool_name: None,
                mcp_body_truncated: false,
                mcp_body_preview: None,
                tags: None,
            }],
        };

        let json = serde_json::to_string(&req).expect("serialize");
        let parsed: EventBatchRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.agent_instance_id, "agent-1");
        assert_eq!(parsed.batch.len(), 1);
        assert_eq!(parsed.batch[0].provider.as_deref(), Some("openai"));
    }
}
