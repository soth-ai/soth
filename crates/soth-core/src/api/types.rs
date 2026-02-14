//! Shared API request/response structures for edge <-> cloud communication.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBatchRequest {
    pub agent_instance_id: String,
    pub config_version: Option<String>,
    pub batch: Vec<EventMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeBatchRequest {
    pub agent_instance_id: String,
    pub config_version: Option<String>,
    pub batch: Vec<ExchangeMetadata>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_envelope: Option<EventEnvelopeMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeMetadata {
    pub exchange_id: String,
    pub schema_version: String,
    pub observed_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub ttfb_ms: Option<u64>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub source_class: String,
    pub transport: String,
    pub provider: Option<String>,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub endpoint: Option<String>,
    pub method: Option<String>,
    pub status_code: Option<u16>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cache_read_tokens: Option<u64>,
    pub cache_write_tokens: Option<u64>,
    pub reasoning_tokens: Option<u64>,
    pub cost_usd: Option<f64>,
    pub cost_currency: Option<String>,
    pub pricing_version: Option<String>,
    pub request_size_bytes: Option<u64>,
    pub response_size_bytes: Option<u64>,
    pub request_body_mode: Option<String>,
    pub response_body_mode: Option<String>,
    pub request_body_ref: Option<String>,
    pub response_body_ref: Option<String>,
    pub request_body_sha256: Option<String>,
    pub response_body_sha256: Option<String>,
    pub truncated: bool,
    pub metadata_only: bool,
    pub discovery_capture: bool,
    pub blacklist_match: bool,
    pub pii_detected: bool,
    pub pii_types: Vec<String>,
    pub event_hash: Option<String>,
    pub signature: Option<String>,
    pub signature_key_id: Option<String>,
    pub parser_version: Option<String>,
    pub bundle_version: Option<String>,
    pub parse_confidence: Option<f64>,
    pub detection_reason: Option<String>,
    pub tags: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_envelope: Option<EventEnvelopeMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventClientMetadata {
    pub pid: Option<u32>,
    pub bundle_id: Option<String>,
    pub process_name: Option<String>,
    pub process_executable: Option<String>,
    pub app_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelopeMetadata {
    pub envelope_id: Option<String>,
    pub request_id: Option<String>,
    pub capture_source: Option<String>,
    pub source: Option<String>,
    pub captured_at: Option<String>,
    pub method: Option<String>,
    pub provider: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub model: Option<String>,
    pub agent: Option<String>,
    pub did: Option<String>,
    pub key_id: Option<String>,
    pub signature_alg: Option<String>,
    pub signed_fields_version: Option<String>,
    pub signature: Option<String>,
    pub body_hash: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub client: Option<EventClientMetadata>,
    pub collector_source: Option<String>,
    pub collector_offset: Option<u64>,
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
pub struct ExchangeBatchResponse {
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
pub struct BlobUploadRequest {
    pub exchange_id: String,
    pub side: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    pub content_encoding: Option<String>,
    pub content_type: Option<String>,
    pub sha256: Option<String>,
    pub bytes_raw: Option<u64>,
    pub bytes_gzip: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_gzip_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobUploadResponse {
    pub stored: bool,
    #[serde(default)]
    pub blob_key: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub sha256: Option<String>,
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
    #[serde(default)]
    pub bundle_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryVersionResponse {
    pub bundle_type: String,
    pub version: String,
    pub sha256: String,
    pub compiled_at: String,
    pub provider_count: u64,
    pub domain_count: u64,
    pub format_count: u64,
    pub size_bytes: u64,
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

// ============================================================================
// Cloud Budget Management (Layer 5a)
// ============================================================================

/// Budget alert configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetAlertConfig {
    /// Alert threshold ratio in [0, 1], e.g. 0.8, 0.95, 1.0.
    pub threshold: f64,
    /// Action at threshold: "notify" | "warn" | "block".
    pub action: String,
    /// Optional channel: "email" | "slack" | "webhook".
    pub notify_channel: Option<String>,
    /// Optional destination (email address, webhook URL, etc).
    pub notify_target: Option<String>,
}

/// Canonical budget object returned by cloud management APIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetRecord {
    pub id: String,
    pub org_id: String,
    pub team_id: Option<String>,
    pub user_id: Option<String>,
    pub model: Option<String>,
    /// "org" | "team" | "user" | "model"
    pub scope: String,
    pub daily_usd: Option<f64>,
    pub weekly_usd: Option<f64>,
    pub monthly_usd: Option<f64>,
    /// "block" | "warn" | "audit"
    pub enforcement: String,
    pub alerts: Vec<BudgetAlertConfig>,
    pub created_at: String,
    pub updated_at: String,
}

/// GET /api/v1/budgets response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetsListResponse {
    pub budgets: Vec<BudgetRecord>,
}

/// POST /api/v1/budgets request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetCreateRequest {
    pub team_id: Option<String>,
    pub user_id: Option<String>,
    pub model: Option<String>,
    /// "org" | "team" | "user" | "model"
    pub scope: String,
    pub daily_usd: Option<f64>,
    pub weekly_usd: Option<f64>,
    pub monthly_usd: Option<f64>,
    /// "block" | "warn" | "audit"
    pub enforcement: String,
    #[serde(default)]
    pub alerts: Vec<BudgetAlertConfig>,
}

/// PATCH /api/v1/budgets/{id} request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetUpdateRequest {
    pub team_id: Option<String>,
    pub user_id: Option<String>,
    pub model: Option<String>,
    /// "org" | "team" | "user" | "model"
    pub scope: Option<String>,
    pub daily_usd: Option<f64>,
    pub weekly_usd: Option<f64>,
    pub monthly_usd: Option<f64>,
    /// "block" | "warn" | "audit"
    pub enforcement: Option<String>,
    /// Replaces alert rules when present.
    pub alerts: Option<Vec<BudgetAlertConfig>>,
}

/// Response payload for create/update/read budget operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetResponse {
    pub budget: BudgetRecord,
}

/// DELETE /api/v1/budgets/{id} response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetDeleteResponse {
    pub deleted: bool,
    pub id: String,
}

// ============================================================================
// Cloud Policy Management (Layer 5c)
// ============================================================================

/// Canonical policy object returned by cloud management APIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRecord {
    pub id: String,
    pub org_id: String,
    pub team_id: Option<String>,
    /// "org" | "team"
    pub scope: String,
    pub name: String,
    pub description: Option<String>,
    pub rego_source: String,
    pub version: String,
    pub is_active: bool,
    pub has_compiled_wasm: bool,
    pub created_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// GET /api/v1/policies response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoliciesListResponse {
    pub policies: Vec<PolicyRecord>,
}

/// POST /api/v1/policies request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCreateRequest {
    /// NULL/omitted means org-scoped policy.
    pub team_id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub rego_source: String,
    pub version: String,
    /// Defaults to true when omitted.
    pub is_active: Option<bool>,
    /// If true, cloud attempts OPA WASM pre-compilation.
    #[serde(default)]
    pub compile_wasm: bool,
}

/// PATCH /api/v1/policies/{id} request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyUpdateRequest {
    /// If provided, updates policy scope to this team (team-scoped).
    pub team_id: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub rego_source: Option<String>,
    pub version: Option<String>,
    pub is_active: Option<bool>,
    /// None = keep existing compiled artifact; Some(false) clears it.
    pub compile_wasm: Option<bool>,
}

/// Response payload for create/update/read policy operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub policy: PolicyRecord,
}

/// DELETE /api/v1/policies/{id} response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDeleteResponse {
    pub deleted: bool,
    pub id: String,
}

/// POST /api/v1/policies/{id}/deploy request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDeployRequest {
    /// Optional version bump when deploying.
    pub version: Option<String>,
    /// Optional number of target agent instances.
    pub agents_targeted: Option<u64>,
    /// If true, cloud attempts OPA WASM pre-compilation before deployment.
    #[serde(default)]
    pub compile_wasm: bool,
}

/// POST /api/v1/policies/{id}/deploy response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDeployResponse {
    pub deployment_id: String,
    pub policy_id: String,
    pub version: String,
    pub status: String,
    pub agents_targeted: Option<u64>,
    pub agents_confirmed: u64,
    pub deployed_at: String,
}

/// Canonical policy deployment object for tracking rollout progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDeploymentRecord {
    pub deployment_id: String,
    pub policy_id: String,
    pub policy_name: String,
    pub policy_scope: String,
    pub policy_team_id: Option<String>,
    pub version: String,
    pub status: String,
    pub agents_targeted: Option<u64>,
    pub agents_confirmed: u64,
    pub deployed_by: Option<String>,
    pub deployed_at: String,
}

/// GET /api/v1/policies/deployments response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDeploymentsListResponse {
    pub deployments: Vec<PolicyDeploymentRecord>,
}

// ============================================================================
// Cloud SSO Management (Layer 6a)
// ============================================================================

/// Canonical SSO configuration for a tenant organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoConfiguration {
    pub enabled: bool,
    /// "saml" | "oidc"
    pub provider: Option<String>,
    /// WorkOS connection identifier.
    pub connection_id: Option<String>,
    /// Optional email domains routed through SSO.
    #[serde(default)]
    pub domains: Vec<String>,
    /// Future toggle for SCIM/directory sync rollout.
    pub directory_sync_enabled: bool,
    /// New SSO users are always placed in the org's Default team.
    pub auto_join_default_team: bool,
    pub updated_at: Option<String>,
}

/// GET /api/v1/sso response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoConfigurationResponse {
    pub sso: SsoConfiguration,
}

/// PUT /api/v1/sso request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoConfigurationUpdateRequest {
    pub enabled: bool,
    /// "saml" | "oidc"
    pub provider: Option<String>,
    pub connection_id: Option<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub directory_sync_enabled: bool,
}

// ============================================================================
// Cloud Webhook Management (Layer 6b)
// ============================================================================

/// Canonical webhook subscription object returned by management APIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookRecord {
    pub id: String,
    pub org_id: String,
    pub team_id: Option<String>,
    pub url: String,
    pub events: Vec<String>,
    pub is_active: bool,
    pub created_at: String,
}

/// GET /api/v1/webhooks response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhooksListResponse {
    pub webhooks: Vec<WebhookRecord>,
}

/// POST /api/v1/webhooks request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookCreateRequest {
    pub team_id: Option<String>,
    pub url: String,
    pub events: Vec<String>,
    pub is_active: Option<bool>,
}

/// PATCH /api/v1/webhooks/{id} request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookUpdateRequest {
    pub team_id: Option<String>,
    pub url: Option<String>,
    pub events: Option<Vec<String>>,
    pub is_active: Option<bool>,
}

/// Response payload for create/update/read webhook operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookResponse {
    pub webhook: WebhookRecord,
}

/// DELETE /api/v1/webhooks/{id} response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDeleteResponse {
    pub deleted: bool,
    pub id: String,
}

// ============================================================================
// Cloud Audit Log (Layer 6c)
// ============================================================================

/// Canonical audit log entry returned by management APIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogRecord {
    pub id: String,
    pub org_id: String,
    pub actor_user_id: String,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub details: Option<Value>,
    pub created_at: String,
}

/// GET /api/v1/audit/logs response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogsListResponse {
    pub entries: Vec<AuditLogRecord>,
}

// ============================================================================
// Cloud Compliance Reports (Layer 6d)
// ============================================================================

/// Aggregated compliance counters over a bounded reporting window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceSummary {
    pub window_start: String,
    pub window_end: String,
    pub policy_evaluations: u64,
    pub policy_denials: u64,
    pub pii_events: u64,
    pub admin_actions: u64,
    pub policy_deployments: u64,
}

/// Policy evaluation evidence row from synced events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompliancePolicyEvaluationRecord {
    pub event_id: String,
    pub timestamp: String,
    pub team_id: String,
    pub user_id: String,
    pub source: String,
    pub method: Option<String>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub allowed: bool,
    pub policy_version: Option<String>,
}

/// PII detection evidence row from synced events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompliancePiiDetectionRecord {
    pub event_id: String,
    pub timestamp: String,
    pub team_id: String,
    pub user_id: String,
    pub source: String,
    pub method: Option<String>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub pii_types: Vec<String>,
}

/// Policy deployment evidence row for rollout attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompliancePolicyDeploymentRecord {
    pub deployment_id: String,
    pub policy_id: String,
    pub policy_name: String,
    pub policy_scope: String,
    pub policy_team_id: Option<String>,
    pub version: String,
    pub status: String,
    pub agents_targeted: Option<u64>,
    pub agents_confirmed: u64,
    pub deployed_by: Option<String>,
    pub deployed_at: String,
}

/// GET /api/v1/compliance/report response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReportResponse {
    pub generated_at: String,
    pub summary: ComplianceSummary,
    pub pii_counts_by_type: HashMap<String, u64>,
    pub policy_evaluation_history: Vec<CompliancePolicyEvaluationRecord>,
    pub pii_detection_trail: Vec<CompliancePiiDetectionRecord>,
    pub admin_actions: Vec<AuditLogRecord>,
    pub policy_deployments: Vec<CompliancePolicyDeploymentRecord>,
}

// ============================================================================
// Cloud Org Administration (Layer 4b)
// ============================================================================

/// Organization metadata visible in org admin scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgAdminOrganization {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub plan: String,
    pub billing_email: Option<String>,
}

/// Billing and seat usage summary for org admin view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgAdminBillingSummary {
    pub plan: String,
    pub billing_email: Option<String>,
    pub total_members: u64,
    pub active_seats: u64,
    pub viewer_seats: u64,
    pub month_to_date_spend_usd: f64,
    pub monthly_budget_usd: Option<f64>,
}

/// Team-level aggregate shown in org admin dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgAdminTeamSummary {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub member_count: u64,
    pub admin_count: u64,
    pub active_api_keys: u64,
    pub month_to_date_spend_usd: f64,
    pub created_at: String,
    pub archived_at: Option<String>,
}

/// Member-level aggregate shown in org admin dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgAdminMemberSummary {
    pub user_id: String,
    pub email: String,
    pub name: Option<String>,
    pub org_role: String,
    pub team_count: u64,
    pub active_api_keys: u64,
    pub last_seen_at: Option<String>,
}

/// GET /api/v1/org-admin/summary response payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgAdminSummary {
    pub organization: OrgAdminOrganization,
    pub billing: OrgAdminBillingSummary,
    pub teams: Vec<OrgAdminTeamSummary>,
    pub members: Vec<OrgAdminMemberSummary>,
}

/// POST /api/v1/org-admin/teams request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgAdminCreateTeamRequest {
    pub name: String,
    pub slug: Option<String>,
}

/// Team record returned by org admin create-team APIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgAdminTeamRecord {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub created_at: String,
}

/// POST /api/v1/org-admin/teams response payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgAdminTeamResponse {
    pub team: OrgAdminTeamRecord,
}

/// PATCH /api/v1/org-admin/members/{user_id}/role request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgAdminUpdateMemberRoleRequest {
    /// "member" | "org_admin" | "org_owner"
    pub role: String,
}

/// Member role record returned by org admin member-role APIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgAdminMemberRoleRecord {
    pub user_id: String,
    pub org_role: String,
}

/// PATCH /api/v1/org-admin/members/{user_id}/role response payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgAdminMemberRoleResponse {
    pub member: OrgAdminMemberRoleRecord,
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
                event_envelope: None,
            }],
        };

        let json = serde_json::to_string(&req).expect("serialize");
        let parsed: EventBatchRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.agent_instance_id, "agent-1");
        assert_eq!(parsed.batch.len(), 1);
        assert_eq!(parsed.batch[0].provider.as_deref(), Some("openai"));
    }

    #[test]
    fn exchange_batch_roundtrip() {
        let req = ExchangeBatchRequest {
            agent_instance_id: "agent-1".to_string(),
            config_version: Some("v2".to_string()),
            batch: vec![ExchangeMetadata {
                exchange_id: "ex-1".to_string(),
                schema_version: "2.0".to_string(),
                observed_at: "2026-02-01T00:00:00Z".to_string(),
                started_at: Some("2026-02-01T00:00:00Z".to_string()),
                completed_at: Some("2026-02-01T00:00:01Z".to_string()),
                duration_ms: Some(1000),
                ttfb_ms: Some(120),
                trace_id: Some("trace-1".to_string()),
                span_id: Some("span-1".to_string()),
                parent_span_id: None,
                source_class: "ai_inference".to_string(),
                transport: "https".to_string(),
                provider: Some("openai".to_string()),
                agent: Some("codex".to_string()),
                model: Some("gpt-5.3-codex".to_string()),
                endpoint: Some("/v1/responses".to_string()),
                method: Some("POST".to_string()),
                status_code: Some(200),
                input_tokens: Some(12),
                output_tokens: Some(34),
                cache_read_tokens: Some(0),
                cache_write_tokens: Some(0),
                reasoning_tokens: Some(3),
                cost_usd: Some(0.02),
                cost_currency: Some("USD".to_string()),
                pricing_version: Some("bundle-1".to_string()),
                request_size_bytes: Some(1024),
                response_size_bytes: Some(4096),
                request_body_mode: Some("inline".to_string()),
                response_body_mode: Some("offloaded".to_string()),
                request_body_ref: None,
                response_body_ref: Some("blob://resp/1".to_string()),
                request_body_sha256: None,
                response_body_sha256: Some("abc".to_string()),
                truncated: false,
                metadata_only: false,
                discovery_capture: false,
                blacklist_match: false,
                pii_detected: false,
                pii_types: vec![],
                event_hash: Some("hash".to_string()),
                signature: None,
                signature_key_id: None,
                parser_version: Some("v1".to_string()),
                bundle_version: Some("bundle-1".to_string()),
                parse_confidence: Some(0.98),
                detection_reason: Some("model_marker".to_string()),
                tags: None,
                event_envelope: None,
            }],
        };

        let json = serde_json::to_string(&req).expect("serialize exchange batch");
        let parsed: ExchangeBatchRequest =
            serde_json::from_str(&json).expect("deserialize exchange batch");
        assert_eq!(parsed.agent_instance_id, "agent-1");
        assert_eq!(parsed.batch.len(), 1);
        assert_eq!(parsed.batch[0].exchange_id, "ex-1");
        assert_eq!(parsed.batch[0].transport, "https");
    }

    #[test]
    fn budget_create_roundtrip() {
        let request = BudgetCreateRequest {
            team_id: Some("team_123".to_string()),
            user_id: None,
            model: Some("gpt-5".to_string()),
            scope: "model".to_string(),
            daily_usd: Some(25.0),
            weekly_usd: Some(100.0),
            monthly_usd: Some(400.0),
            enforcement: "warn".to_string(),
            alerts: vec![BudgetAlertConfig {
                threshold: 0.8,
                action: "notify".to_string(),
                notify_channel: Some("email".to_string()),
                notify_target: Some("ops@example.com".to_string()),
            }],
        };

        let json = serde_json::to_string(&request).expect("serialize");
        let parsed: BudgetCreateRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.scope, "model");
        assert_eq!(parsed.alerts.len(), 1);
        assert_eq!(parsed.alerts[0].threshold, 0.8);
    }

    #[test]
    fn budget_response_roundtrip() {
        let response = BudgetResponse {
            budget: BudgetRecord {
                id: "budget_123".to_string(),
                org_id: "org_123".to_string(),
                team_id: Some("team_123".to_string()),
                user_id: None,
                model: None,
                scope: "team".to_string(),
                daily_usd: Some(50.0),
                weekly_usd: Some(300.0),
                monthly_usd: Some(1200.0),
                enforcement: "block".to_string(),
                alerts: vec![BudgetAlertConfig {
                    threshold: 1.0,
                    action: "block".to_string(),
                    notify_channel: None,
                    notify_target: None,
                }],
                created_at: "2026-02-10T00:00:00Z".to_string(),
                updated_at: "2026-02-10T00:00:00Z".to_string(),
            },
        };

        let json = serde_json::to_string(&response).expect("serialize");
        let parsed: BudgetResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.budget.id, "budget_123");
        assert_eq!(parsed.budget.scope, "team");
        assert_eq!(parsed.budget.alerts[0].action, "block");
    }

    #[test]
    fn policy_create_roundtrip() {
        let request = PolicyCreateRequest {
            team_id: Some("11111111-1111-1111-1111-111111111111".to_string()),
            name: "frontend-guardrails".to_string(),
            description: Some("Restrict risky tools".to_string()),
            rego_source: "package mcp.policy\nallow := true".to_string(),
            version: "v1.0.0".to_string(),
            is_active: Some(true),
            compile_wasm: false,
        };

        let json = serde_json::to_string(&request).expect("serialize");
        let parsed: PolicyCreateRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.name, "frontend-guardrails");
        assert_eq!(parsed.version, "v1.0.0");
        assert_eq!(
            parsed.team_id.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
    }

    #[test]
    fn policy_deploy_response_roundtrip() {
        let response = PolicyDeployResponse {
            deployment_id: "deploy_123".to_string(),
            policy_id: "policy_123".to_string(),
            version: "v2.1.0".to_string(),
            status: "deploying".to_string(),
            agents_targeted: Some(15),
            agents_confirmed: 3,
            deployed_at: "2026-02-10T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&response).expect("serialize");
        let parsed: PolicyDeployResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.policy_id, "policy_123");
        assert_eq!(parsed.status, "deploying");
        assert_eq!(parsed.agents_targeted, Some(15));
        assert_eq!(parsed.agents_confirmed, 3);
    }

    #[test]
    fn policy_deployments_list_roundtrip() {
        let response = PolicyDeploymentsListResponse {
            deployments: vec![PolicyDeploymentRecord {
                deployment_id: "deploy_123".to_string(),
                policy_id: "policy_123".to_string(),
                policy_name: "org-default".to_string(),
                policy_scope: "org".to_string(),
                policy_team_id: None,
                version: "v2.1.0".to_string(),
                status: "complete".to_string(),
                agents_targeted: Some(15),
                agents_confirmed: 15,
                deployed_by: Some("user_123".to_string()),
                deployed_at: "2026-02-10T00:00:00Z".to_string(),
            }],
        };

        let json = serde_json::to_string(&response).expect("serialize");
        let parsed: PolicyDeploymentsListResponse =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.deployments.len(), 1);
        assert_eq!(parsed.deployments[0].policy_scope, "org");
        assert_eq!(parsed.deployments[0].status, "complete");
    }

    #[test]
    fn sso_configuration_roundtrip() {
        let response = SsoConfigurationResponse {
            sso: SsoConfiguration {
                enabled: true,
                provider: Some("saml".to_string()),
                connection_id: Some("conn_123".to_string()),
                domains: vec!["acme.com".to_string(), "engineering.acme.com".to_string()],
                directory_sync_enabled: false,
                auto_join_default_team: true,
                updated_at: Some("2026-02-10T00:00:00Z".to_string()),
            },
        };

        let json = serde_json::to_string(&response).expect("serialize");
        let parsed: SsoConfigurationResponse = serde_json::from_str(&json).expect("deserialize");
        assert!(parsed.sso.enabled);
        assert_eq!(parsed.sso.provider.as_deref(), Some("saml"));
        assert_eq!(parsed.sso.domains.len(), 2);
        assert!(parsed.sso.auto_join_default_team);
    }

    #[test]
    fn webhooks_list_roundtrip() {
        let response = WebhooksListResponse {
            webhooks: vec![WebhookRecord {
                id: "webhook_123".to_string(),
                org_id: "org_123".to_string(),
                team_id: Some("team_123".to_string()),
                url: "https://example.com/webhook".to_string(),
                events: vec!["policy.violation".to_string(), "pii.detected".to_string()],
                is_active: true,
                created_at: "2026-02-10T00:00:00Z".to_string(),
            }],
        };

        let json = serde_json::to_string(&response).expect("serialize");
        let parsed: WebhooksListResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.webhooks.len(), 1);
        assert_eq!(parsed.webhooks[0].events.len(), 2);
        assert!(parsed.webhooks[0].is_active);
    }

    #[test]
    fn audit_logs_roundtrip() {
        let response = AuditLogsListResponse {
            entries: vec![AuditLogRecord {
                id: "audit_123".to_string(),
                org_id: "org_123".to_string(),
                actor_user_id: "user_123".to_string(),
                action: "policy.deploy".to_string(),
                target_type: Some("policy".to_string()),
                target_id: Some("policy_456".to_string()),
                details: Some(serde_json::json!({
                    "version": "v2.1.0",
                    "agents_targeted": 15
                })),
                created_at: "2026-02-10T00:00:00Z".to_string(),
            }],
        };

        let json = serde_json::to_string(&response).expect("serialize");
        let parsed: AuditLogsListResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].action, "policy.deploy");
        assert_eq!(parsed.entries[0].target_type.as_deref(), Some("policy"));
    }

    #[test]
    fn compliance_report_roundtrip() {
        let response = ComplianceReportResponse {
            generated_at: "2026-02-10T00:00:00Z".to_string(),
            summary: ComplianceSummary {
                window_start: "2026-02-01T00:00:00Z".to_string(),
                window_end: "2026-02-10T00:00:00Z".to_string(),
                policy_evaluations: 245,
                policy_denials: 7,
                pii_events: 3,
                admin_actions: 11,
                policy_deployments: 2,
            },
            pii_counts_by_type: HashMap::from([("email".to_string(), 2), ("phone".to_string(), 1)]),
            policy_evaluation_history: vec![CompliancePolicyEvaluationRecord {
                event_id: "evt_123".to_string(),
                timestamp: "2026-02-10T00:00:00Z".to_string(),
                team_id: "team_123".to_string(),
                user_id: "user_123".to_string(),
                source: "ai_proxy".to_string(),
                method: Some("POST /v1/responses".to_string()),
                provider: Some("openai".to_string()),
                model: Some("gpt-5".to_string()),
                allowed: false,
                policy_version: Some("v2.1.0".to_string()),
            }],
            pii_detection_trail: vec![CompliancePiiDetectionRecord {
                event_id: "evt_456".to_string(),
                timestamp: "2026-02-10T00:01:00Z".to_string(),
                team_id: "team_123".to_string(),
                user_id: "user_123".to_string(),
                source: "ai_proxy".to_string(),
                method: Some("POST /v1/responses".to_string()),
                provider: Some("openai".to_string()),
                model: Some("gpt-5".to_string()),
                pii_types: vec!["email".to_string()],
            }],
            admin_actions: vec![AuditLogRecord {
                id: "audit_123".to_string(),
                org_id: "org_123".to_string(),
                actor_user_id: "user_123".to_string(),
                action: "policy.deploy".to_string(),
                target_type: Some("policy".to_string()),
                target_id: Some("policy_456".to_string()),
                details: None,
                created_at: "2026-02-10T00:00:00Z".to_string(),
            }],
            policy_deployments: vec![CompliancePolicyDeploymentRecord {
                deployment_id: "deploy_123".to_string(),
                policy_id: "policy_456".to_string(),
                policy_name: "org-default".to_string(),
                policy_scope: "org".to_string(),
                policy_team_id: None,
                version: "v2.1.0".to_string(),
                status: "complete".to_string(),
                agents_targeted: Some(12),
                agents_confirmed: 12,
                deployed_by: Some("user_123".to_string()),
                deployed_at: "2026-02-10T00:00:00Z".to_string(),
            }],
        };

        let json = serde_json::to_string(&response).expect("serialize");
        let parsed: ComplianceReportResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.summary.policy_denials, 7);
        assert_eq!(parsed.pii_counts_by_type.get("email"), Some(&2));
        assert_eq!(parsed.policy_evaluation_history.len(), 1);
        assert_eq!(parsed.pii_detection_trail.len(), 1);
    }

    #[test]
    fn org_admin_roundtrip() {
        let summary = OrgAdminSummary {
            organization: OrgAdminOrganization {
                id: "org_123".to_string(),
                name: "Acme".to_string(),
                slug: "acme".to_string(),
                plan: "business".to_string(),
                billing_email: Some("billing@acme.com".to_string()),
            },
            billing: OrgAdminBillingSummary {
                plan: "business".to_string(),
                billing_email: Some("billing@acme.com".to_string()),
                total_members: 9,
                active_seats: 7,
                viewer_seats: 2,
                month_to_date_spend_usd: 124.75,
                monthly_budget_usd: Some(500.0),
            },
            teams: vec![OrgAdminTeamSummary {
                id: "team_123".to_string(),
                name: "Platform".to_string(),
                slug: "platform".to_string(),
                member_count: 4,
                admin_count: 1,
                active_api_keys: 3,
                month_to_date_spend_usd: 84.2,
                created_at: "2026-02-10T00:00:00Z".to_string(),
                archived_at: None,
            }],
            members: vec![OrgAdminMemberSummary {
                user_id: "user_123".to_string(),
                email: "owner@acme.com".to_string(),
                name: Some("Owner".to_string()),
                org_role: "org_owner".to_string(),
                team_count: 2,
                active_api_keys: 2,
                last_seen_at: Some("2026-02-10T00:00:00Z".to_string()),
            }],
        };

        let team_response = OrgAdminTeamResponse {
            team: OrgAdminTeamRecord {
                id: "team_456".to_string(),
                name: "Security".to_string(),
                slug: "security".to_string(),
                created_at: "2026-02-11T00:00:00Z".to_string(),
            },
        };

        let role_request = OrgAdminUpdateMemberRoleRequest {
            role: "org_admin".to_string(),
        };
        let role_response = OrgAdminMemberRoleResponse {
            member: OrgAdminMemberRoleRecord {
                user_id: "user_123".to_string(),
                org_role: "org_admin".to_string(),
            },
        };

        let summary_json = serde_json::to_string(&summary).expect("serialize summary");
        let parsed_summary: OrgAdminSummary =
            serde_json::from_str(&summary_json).expect("deserialize summary");
        assert_eq!(parsed_summary.organization.slug, "acme");
        assert_eq!(parsed_summary.teams.len(), 1);

        let team_json = serde_json::to_string(&team_response).expect("serialize team response");
        let parsed_team: OrgAdminTeamResponse =
            serde_json::from_str(&team_json).expect("deserialize team response");
        assert_eq!(parsed_team.team.slug, "security");

        let request_json = serde_json::to_string(&role_request).expect("serialize role request");
        let parsed_request: OrgAdminUpdateMemberRoleRequest =
            serde_json::from_str(&request_json).expect("deserialize role request");
        assert_eq!(parsed_request.role, "org_admin");

        let response_json = serde_json::to_string(&role_response).expect("serialize role response");
        let parsed_response: OrgAdminMemberRoleResponse =
            serde_json::from_str(&response_json).expect("deserialize role response");
        assert_eq!(parsed_response.member.org_role, "org_admin");
    }
}
