use crate::sensitive::redact_sensitive_bytes;
use crate::types::{
    DetectResult, DetectWarning, HeaderMap, ParseConfidence, ParseSource, RawRequest,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParseQualityRecord {
    pub event_uuid: String,
    pub created_at: i64,
    pub provider: String,
    pub host: Option<String>,
    pub method: String,
    pub path: String,
    pub parse_confidence: String,
    pub parse_source: String,
    pub parser_id: String,
    pub schema_version: String,
    pub canonical_hash: String,
    pub warnings: Vec<String>,
    pub detect_latency_us: u64,
    pub capture_mode: String,
    pub headers_json: String,
    pub body_redacted: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnknownGraphQLOperationRecord {
    pub parse_event_id: Option<i64>,
    pub event_uuid: String,
    pub created_at: i64,
    pub operation_name: String,
    pub host: Option<String>,
    pub provider: String,
    pub canonical_hash: String,
    pub warning_code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReparseJobRecord {
    pub id: Option<i64>,
    pub created_at: i64,
    pub reason: String,
    pub status: String,
    pub total_candidates: u64,
    pub processed: u64,
    pub upgraded: u64,
    pub unchanged: u64,
    pub failed: u64,
}

impl ReparseJobRecord {
    pub fn new(reason: impl Into<String>, total_candidates: u64) -> Self {
        Self {
            id: None,
            created_at: now_epoch_secs(),
            reason: reason.into(),
            status: "running".to_string(),
            total_candidates,
            processed: 0,
            upgraded: 0,
            unchanged: 0,
            failed: 0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReparseResultRecord {
    pub job_id: i64,
    pub parse_event_id: i64,
    pub created_at: i64,
    pub old_confidence: String,
    pub new_confidence: String,
    pub old_canonical_hash: String,
    pub new_canonical_hash: String,
    pub status: String,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplayCandidate {
    pub parse_event_id: i64,
    pub event_uuid: String,
    pub method: String,
    pub path: String,
    pub headers: HeaderMap,
    pub body_redacted: Vec<u8>,
    pub old_confidence: String,
    pub old_canonical_hash: String,
    pub provider: String,
    pub host: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ParseCoverageSummary {
    pub full_count: u64,
    pub partial_count: u64,
    pub heuristic_count: u64,
    pub by_provider: Vec<CoverageByDimension>,
    pub by_host: Vec<CoverageByDimension>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoverageByDimension {
    pub dimension: String,
    pub full_count: u64,
    pub partial_count: u64,
    pub heuristic_count: u64,
    pub total_count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnknownOperationSummary {
    pub operation_name: String,
    pub host: Option<String>,
    pub occurrence_count: u64,
    pub last_seen: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SchemaDriftWarningSummary {
    pub parser_id: String,
    pub schema_version: String,
    pub warning_count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntelligenceSignals {
    pub coverage: ParseCoverageSummary,
    pub unknown_operations: Vec<UnknownOperationSummary>,
    pub schema_drift: Vec<SchemaDriftWarningSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReparseRunSummary {
    pub job_id: i64,
    pub total_candidates: u64,
    pub processed: u64,
    pub upgraded: u64,
    pub unchanged: u64,
    pub failed: u64,
}

#[derive(Debug, Clone)]
pub struct IntelligenceError {
    pub message: String,
}

impl IntelligenceError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for IntelligenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for IntelligenceError {}

impl From<rusqlite::Error> for IntelligenceError {
    fn from(value: rusqlite::Error) -> Self {
        Self::new(value.to_string())
    }
}

impl From<serde_json::Error> for IntelligenceError {
    fn from(value: serde_json::Error) -> Self {
        Self::new(value.to_string())
    }
}

pub type IntelligenceResult<T> = Result<T, IntelligenceError>;

pub trait IntelligenceSink: Send + Sync {
    fn record_parse_event(&self, record: &ParseQualityRecord) -> IntelligenceResult<i64>;
    fn record_unknown_graphql_operation(
        &self,
        record: &UnknownGraphQLOperationRecord,
    ) -> IntelligenceResult<()>;
}

pub fn build_parse_quality_record(req: &RawRequest, result: &DetectResult) -> ParseQualityRecord {
    let created_at = now_epoch_secs();
    let host = extract_host(req);
    let headers_json = serde_json::to_string(&req.headers).unwrap_or_else(|_| "{}".to_string());

    let warnings = result
        .warnings
        .iter()
        .map(|warning| format!("{}:{}", warning.code, warning.detail))
        .chain(
            result
                .normalized
                .parse_warnings
                .iter()
                .map(|warning| format!("parse_warning:{warning:?}")),
        )
        .collect::<Vec<_>>();

    ParseQualityRecord {
        event_uuid: req.connection_meta.connection_id.to_string(),
        created_at,
        provider: result.normalized.provider.canonical_name().to_string(),
        host,
        method: req.method.clone(),
        path: req.path.clone(),
        parse_confidence: parse_confidence_label(&result.confidence).to_string(),
        parse_source: parse_source_label(&result.parse_source),
        parser_id: result.normalized.parser_id.to_string(),
        schema_version: result.normalized.schema_version.to_string(),
        canonical_hash: result.normalized.canonical_hash.clone(),
        warnings,
        detect_latency_us: result.detect_latency_us,
        capture_mode: capture_mode_label(&result.capture_mode).to_string(),
        headers_json,
        body_redacted: redact_sensitive_bytes(req.body.as_ref()),
    }
}

pub fn extract_unknown_graphql_operation_record(
    req: &RawRequest,
    result: &DetectResult,
    parse_event_id: Option<i64>,
) -> Option<UnknownGraphQLOperationRecord> {
    let has_unknown_warning = result
        .warnings
        .iter()
        .any(|warning| warning.code == "graphql_unknown_operation");

    if !has_unknown_warning {
        return None;
    }

    let operation_name = match &result.parse_source {
        ParseSource::GraphQL {
            operation_name: Some(operation_name),
        } => operation_name.clone(),
        _ => "anonymous".to_string(),
    };

    Some(UnknownGraphQLOperationRecord {
        parse_event_id,
        event_uuid: req.connection_meta.connection_id.to_string(),
        created_at: now_epoch_secs(),
        operation_name,
        host: extract_host(req),
        provider: result.normalized.provider.canonical_name().to_string(),
        canonical_hash: result.normalized.canonical_hash.clone(),
        warning_code: "graphql_unknown_operation".to_string(),
    })
}

pub fn parse_confidence_label(value: &ParseConfidence) -> &'static str {
    match value {
        ParseConfidence::Full => "full",
        ParseConfidence::Partial => "partial",
        ParseConfidence::Heuristic => "heuristic",
    }
}

pub fn parse_confidence_from_label(label: &str) -> ParseConfidence {
    match label {
        "full" => ParseConfidence::Full,
        "partial" => ParseConfidence::Partial,
        _ => ParseConfidence::Heuristic,
    }
}

pub fn confidence_rank(value: &ParseConfidence) -> u8 {
    match value {
        ParseConfidence::Heuristic => 0,
        ParseConfidence::Partial => 1,
        ParseConfidence::Full => 2,
    }
}

fn parse_source_label(value: &ParseSource) -> String {
    match value {
        ParseSource::OpenAI => "openai".to_string(),
        ParseSource::Anthropic => "anthropic".to_string(),
        ParseSource::Cohere => "cohere".to_string(),
        ParseSource::Google => "google".to_string(),
        ParseSource::Bedrock => "bedrock".to_string(),
        ParseSource::GraphQL { operation_name } => {
            format!("graphql:{}", operation_name.clone().unwrap_or_default())
        }
        ParseSource::Grpc { service, method } => format!("grpc:{service}/{method}"),
        ParseSource::AgentApp { app_id } => format!("agent_app:{app_id}"),
        ParseSource::Heuristic => "heuristic".to_string(),
        ParseSource::Filtered => "filtered".to_string(),
    }
}

fn capture_mode_label(value: &crate::types::CaptureMode) -> &'static str {
    match value {
        crate::types::CaptureMode::MetadataOnly => "metadata_only",
        crate::types::CaptureMode::Full => "full",
    }
}

fn extract_host(req: &RawRequest) -> Option<String> {
    crate::util::header_value(&req.headers, "host")
        .or_else(|| crate::util::header_value(&req.headers, ":authority"))
        .map(|host| crate::util::host_without_port(host).to_string())
}

pub fn now_epoch_secs() -> i64 {
    let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    duration.as_secs() as i64
}

pub fn warning_to_string(warning: &DetectWarning) -> String {
    format!("{}:{}", warning.code, warning.detail)
}
