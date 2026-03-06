use uuid::Uuid;

#[cfg(feature = "dev-pipeline-trace")]
use serde::Serialize;
#[cfg(feature = "dev-pipeline-trace")]
use serde_json::{json, Map, Value};
#[cfg(feature = "dev-pipeline-trace")]
use std::fs::{create_dir_all, OpenOptions};
#[cfg(feature = "dev-pipeline-trace")]
use std::io::{BufWriter, Write};
#[cfg(feature = "dev-pipeline-trace")]
use std::path::PathBuf;
#[cfg(feature = "dev-pipeline-trace")]
use std::sync::{Mutex, OnceLock};

#[cfg(feature = "dev-pipeline-trace")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraceFormat {
    Ndjson,
    Pretty,
}

#[cfg(feature = "dev-pipeline-trace")]
struct TraceRuntime {
    format: TraceFormat,
    writer: Option<Mutex<BufWriter<std::fs::File>>>,
}

#[cfg(feature = "dev-pipeline-trace")]
fn runtime() -> Option<&'static TraceRuntime> {
    static RUNTIME: OnceLock<Option<TraceRuntime>> = OnceLock::new();
    RUNTIME.get_or_init(init_runtime).as_ref()
}

#[cfg(feature = "dev-pipeline-trace")]
fn init_runtime() -> Option<TraceRuntime> {
    if !runtime_trace_enabled() {
        return None;
    }

    let format = trace_format();
    if format == TraceFormat::Pretty {
        return Some(TraceRuntime {
            format,
            writer: None,
        });
    }

    let path = trace_file_path();
    if let Some(parent) = path.parent() {
        let _ = create_dir_all(parent);
    }

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path.as_path())
        .ok()?;
    Some(TraceRuntime {
        format,
        writer: Some(Mutex::new(BufWriter::new(file))),
    })
}

#[cfg(feature = "dev-pipeline-trace")]
fn runtime_trace_enabled() -> bool {
    std::env::var("SOTH_PIPELINE_TRACE")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

#[cfg(feature = "dev-pipeline-trace")]
fn trace_format() -> TraceFormat {
    match std::env::var("SOTH_PIPELINE_TRACE_FORMAT")
        .ok()
        .unwrap_or_else(|| "ndjson".to_string())
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "pretty" => TraceFormat::Pretty,
        _ => TraceFormat::Ndjson,
    }
}

#[cfg(feature = "dev-pipeline-trace")]
fn trace_file_path() -> PathBuf {
    if let Ok(path) = std::env::var("SOTH_PIPELINE_TRACE_FILE") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    if let Ok(home) = std::env::var("SOTH_HOME_DIR") {
        let trimmed = home.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed)
                .join("logs")
                .join("pipeline-trace.ndjson");
        }
    }

    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".soth")
        .join("logs")
        .join("pipeline-trace.ndjson")
}

#[cfg(feature = "dev-pipeline-trace")]
fn serialize_json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

#[cfg(feature = "dev-pipeline-trace")]
fn emit(event: &str, payload: Value) {
    let Some(runtime) = runtime() else {
        return;
    };

    let mut map = Map::new();
    map.insert("schema_version".to_string(), json!(1));
    map.insert(
        "ts_epoch_ms".to_string(),
        json!(chrono::Utc::now().timestamp_millis()),
    );
    map.insert("event".to_string(), json!(event));

    if let Value::Object(payload_map) = payload {
        for (key, value) in payload_map {
            map.insert(key, value);
        }
    }

    let record = Value::Object(map);

    match runtime.format {
        TraceFormat::Pretty => {
            tracing::info!(
                target: "soth_proxy::pipeline_trace",
                event = event,
                payload = %record,
                "pipeline trace"
            );
        }
        TraceFormat::Ndjson => {
            let Some(writer_mutex) = runtime.writer.as_ref() else {
                return;
            };
            if let Ok(mut writer) = writer_mutex.lock() {
                if serde_json::to_writer(&mut *writer, &record).is_ok() {
                    let _ = writer.write_all(b"\n");
                    let _ = writer.flush();
                }
            }
        }
    }
}

#[cfg(feature = "dev-pipeline-trace")]
pub(crate) fn tls_gate(host: &str, decision: &soth_core::GateDecision) {
    emit(
        "tls_gate_decision",
        json!({
            "host": host,
            "decision": serialize_json(decision),
        }),
    );
}

#[cfg(not(feature = "dev-pipeline-trace"))]
#[inline(always)]
pub(crate) fn tls_gate(_host: &str, _decision: &soth_core::GateDecision) {}

#[cfg(feature = "dev-pipeline-trace")]
pub(crate) fn tls_stage(host: &str, verdict: &str, reason: soth_core::DecisionReason, note: &str) {
    emit(
        "tls_stage",
        json!({
            "host": host,
            "verdict": verdict,
            "reason": serialize_json(reason),
            "note": note,
        }),
    );
}

#[cfg(not(feature = "dev-pipeline-trace"))]
#[inline(always)]
pub(crate) fn tls_stage(
    _host: &str,
    _verdict: &str,
    _reason: soth_core::DecisionReason,
    _note: &str,
) {
}

#[cfg(feature = "dev-pipeline-trace")]
pub(crate) fn gate_stage(
    connection_id: Uuid,
    stage: soth_core::GateStage,
    verdict: &str,
    reason: Option<soth_core::DecisionReason>,
    note: &str,
) {
    emit(
        "gate_stage",
        json!({
            "connection_id": connection_id.to_string(),
            "gate": serialize_json(stage),
            "verdict": verdict,
            "reason": reason.map(serialize_json).unwrap_or(Value::Null),
            "note": note,
        }),
    );
}

#[cfg(not(feature = "dev-pipeline-trace"))]
#[inline(always)]
pub(crate) fn gate_stage(
    _connection_id: Uuid,
    _stage: soth_core::GateStage,
    _verdict: &str,
    _reason: Option<soth_core::DecisionReason>,
    _note: &str,
) {
}

#[cfg(feature = "dev-pipeline-trace")]
pub(crate) fn stage1_identity_resolution(
    connection_id: Uuid,
    host: &str,
    path: &str,
    process_info: Option<&soth_core::ProcessInfo>,
    identity: Option<&crate::gating::stage1_app_origin::IdentityMatch>,
) {
    let candidates_checked = process_info
        .map(|info| {
            [info.bundle_id.as_deref(), info.process_name.as_deref()]
                .into_iter()
                .flatten()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    emit(
        "stage1_identity_resolution",
        json!({
            "connection_id": connection_id.to_string(),
            "host": host,
            "path": path,
            "candidates_checked": candidates_checked,
            "process": process_info.map(|info| json!({
                "pid": info.pid,
                "process_name": info.process_name.as_deref(),
                "bundle_id": info.bundle_id.as_deref(),
                "parent_pid": info.parent_pid,
                "parent_process_name": info.parent_process_name.as_deref(),
                "parent_bundle_id": info.parent_bundle_id.as_deref(),
            })).unwrap_or(Value::Null),
            "identity": identity.map(|matched| json!({
                "entity_id": matched.entry.entity_id.as_str(),
                "match_kind": serialize_json(matched.match_kind),
                "app_type": serialize_json(matched.entry.app_type),
                "capture_mode": serialize_json(matched.entry.capture_mode),
                "action": serialize_json(matched.entry.action),
            })).unwrap_or(Value::Null),
        }),
    );
}

#[cfg(not(feature = "dev-pipeline-trace"))]
#[inline(always)]
pub(crate) fn stage1_identity_resolution(
    _connection_id: Uuid,
    _host: &str,
    _path: &str,
    _process_info: Option<&soth_core::ProcessInfo>,
    _identity: Option<&crate::gating::stage1_app_origin::IdentityMatch>,
) {
}

#[cfg(feature = "dev-pipeline-trace")]
pub(crate) fn http_gate(
    connection_id: Uuid,
    method: &str,
    host: &str,
    path: &str,
    outcome: &soth_core::GateOutcome,
) {
    emit(
        "http_gate_outcome",
        json!({
            "connection_id": connection_id.to_string(),
            "method": method,
            "host": host,
            "path": path,
            "decision": serialize_json(&outcome.decision),
            "reason": serialize_json(outcome.reason),
            "terminal_stage": serialize_json(outcome.terminal_stage),
            "discovery_capture": outcome.discovery_capture,
            "app_type": serialize_json(outcome.app_type),
            "capture_mode": serialize_json(outcome.capture_mode),
            "matched_provider": outcome.matched_provider,
            "matched_application": outcome.matched_application,
        }),
    );
}

#[cfg(not(feature = "dev-pipeline-trace"))]
#[inline(always)]
pub(crate) fn http_gate(
    _connection_id: Uuid,
    _method: &str,
    _host: &str,
    _path: &str,
    _outcome: &soth_core::GateOutcome,
) {
}

#[cfg(feature = "dev-pipeline-trace")]
pub(crate) fn handler_decision(connection_id: Uuid, decision: &str, note: &str) {
    emit(
        "handler_decision",
        json!({
            "connection_id": connection_id.to_string(),
            "decision": decision,
            "note": note,
        }),
    );
}

#[cfg(not(feature = "dev-pipeline-trace"))]
#[inline(always)]
pub(crate) fn handler_decision(_connection_id: Uuid, _decision: &str, _note: &str) {}

#[cfg(feature = "dev-pipeline-trace")]
pub(crate) fn detect_summary(
    connection_id: Uuid,
    body_bytes: usize,
    truncated: Option<(usize, usize)>,
    detect_result: &soth_core::DetectResult,
) {
    emit(
        "detect_summary",
        json!({
            "connection_id": connection_id.to_string(),
            "body_bytes": body_bytes,
            "truncated": truncated.map(|(actual, limit)| json!({"actual": actual, "limit": limit})).unwrap_or(Value::Null),
            "provider": serialize_json(detect_result.normalized.provider),
            "model": detect_result.normalized.model,
            "parse_confidence": serialize_json(detect_result.confidence),
            "parse_source": serialize_json(detect_result.parse_source),
            "parser_id": detect_result.normalized.parser_id,
            "warnings_count": detect_result.warnings.len(),
            "artifacts_count": detect_result.artifacts.len(),
            "is_ai_call": detect_result.normalized.is_ai_call,
        }),
    );
}

#[cfg(not(feature = "dev-pipeline-trace"))]
#[inline(always)]
pub(crate) fn detect_summary(
    _connection_id: Uuid,
    _body_bytes: usize,
    _truncated: Option<(usize, usize)>,
    _detect_result: &soth_core::DetectResult,
) {
}

#[cfg(feature = "dev-pipeline-trace")]
pub(crate) fn classify_started(
    connection_id: Uuid,
    capture_mode: soth_core::CaptureMode,
    matched_provider: Option<&str>,
    matched_application: Option<&str>,
) {
    emit(
        "classify_started",
        json!({
            "connection_id": connection_id.to_string(),
            "capture_mode": serialize_json(capture_mode),
            "matched_provider": matched_provider,
            "matched_application": matched_application,
        }),
    );
}

#[cfg(not(feature = "dev-pipeline-trace"))]
#[inline(always)]
pub(crate) fn classify_started(
    _connection_id: Uuid,
    _capture_mode: soth_core::CaptureMode,
    _matched_provider: Option<&str>,
    _matched_application: Option<&str>,
) {
}

#[cfg(feature = "dev-pipeline-trace")]
pub(crate) fn classify_fast_block(connection_id: Uuid, decision: &soth_core::PolicyDecisionKind) {
    emit(
        "classify_fast_block",
        json!({
            "connection_id": connection_id.to_string(),
            "policy_decision": serialize_json(decision),
        }),
    );
}

#[cfg(not(feature = "dev-pipeline-trace"))]
#[inline(always)]
pub(crate) fn classify_fast_block(_connection_id: Uuid, _decision: &soth_core::PolicyDecisionKind) {
}

#[cfg(feature = "dev-pipeline-trace")]
pub(crate) fn classify_result(connection_id: Uuid, result: &soth_classify::ClassifiedResult) {
    emit(
        "classify_result",
        json!({
            "connection_id": connection_id.to_string(),
            "event_id": result.telemetry_event.event_id.to_string(),
            "use_case_label": serialize_json(result.use_case_label),
            "anomaly_score": result.anomaly_score,
            "policy_decision": serialize_json(&result.policy_decision.kind),
            "policy_kind": result.telemetry_event.policy_kind.map(serialize_json).unwrap_or(Value::Null),
            "policy_enforced": result.policy_enforced,
        }),
    );
}

#[cfg(not(feature = "dev-pipeline-trace"))]
#[inline(always)]
pub(crate) fn classify_result(_connection_id: Uuid, _result: &soth_classify::ClassifiedResult) {}

#[cfg(feature = "dev-pipeline-trace")]
pub(crate) fn db_write_ok(connection_id: Uuid, event_id: Uuid) {
    emit(
        "db_write",
        json!({
            "connection_id": connection_id.to_string(),
            "event_id": event_id.to_string(),
            "status": "ok",
        }),
    );
}

#[cfg(not(feature = "dev-pipeline-trace"))]
#[inline(always)]
pub(crate) fn db_write_ok(_connection_id: Uuid, _event_id: Uuid) {}

#[cfg(feature = "dev-pipeline-trace")]
pub(crate) fn db_write_err(connection_id: Uuid, event_id: Uuid, error: &str) {
    emit(
        "db_write",
        json!({
            "connection_id": connection_id.to_string(),
            "event_id": event_id.to_string(),
            "status": "error",
            "error": error,
        }),
    );
}

#[cfg(not(feature = "dev-pipeline-trace"))]
#[inline(always)]
pub(crate) fn db_write_err(_connection_id: Uuid, _event_id: Uuid, _error: &str) {}

#[cfg(feature = "dev-pipeline-trace")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn stream_finalized_without_chunks(
    connection_id: Uuid,
    method: &str,
    host: &str,
    path: &str,
    request_body_bytes: usize,
    stored_raw_body_bytes: usize,
    pending_age_ms: u128,
    capture_mode: soth_core::CaptureMode,
    matched_provider: Option<&str>,
    matched_application: Option<&str>,
    parse_source: &soth_core::ParseSource,
    parser_id: &str,
) {
    let pending_age_ms = pending_age_ms.min(u128::from(u64::MAX)) as u64;
    emit(
        "stream_finalized_without_chunks",
        json!({
            "connection_id": connection_id.to_string(),
            "method": method,
            "host": host,
            "path": path,
            "request_body_bytes": request_body_bytes,
            "stored_raw_body_bytes": stored_raw_body_bytes,
            "pending_age_ms": pending_age_ms,
            "capture_mode": serialize_json(capture_mode),
            "matched_provider": matched_provider,
            "matched_application": matched_application,
            "parse_source": serialize_json(parse_source),
            "parser_id": parser_id,
        }),
    );
}

#[cfg(not(feature = "dev-pipeline-trace"))]
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn stream_finalized_without_chunks(
    _connection_id: Uuid,
    _method: &str,
    _host: &str,
    _path: &str,
    _request_body_bytes: usize,
    _stored_raw_body_bytes: usize,
    _pending_age_ms: u128,
    _capture_mode: soth_core::CaptureMode,
    _matched_provider: Option<&str>,
    _matched_application: Option<&str>,
    _parse_source: &soth_core::ParseSource,
    _parser_id: &str,
) {
}

#[cfg(feature = "dev-pipeline-trace")]
pub(crate) fn response_without_pending(
    connection_id: Uuid,
    status: u16,
    response_body_bytes: usize,
) {
    emit(
        "response_without_pending",
        json!({
            "connection_id": connection_id.to_string(),
            "status": status,
            "response_body_bytes": response_body_bytes,
        }),
    );
}

#[cfg(not(feature = "dev-pipeline-trace"))]
#[inline(always)]
pub(crate) fn response_without_pending(
    _connection_id: Uuid,
    _status: u16,
    _response_body_bytes: usize,
) {
}

#[cfg(feature = "dev-pipeline-trace")]
pub(crate) fn response_usage(connection_id: Uuid, usage: Option<&crate::response::UsageSummary>) {
    let (input_tokens, output_tokens, finish_reason) = if let Some(usage) = usage {
        (
            usage.input_tokens,
            usage.output_tokens,
            usage.finish_reason.as_deref().unwrap_or("-"),
        )
    } else {
        (0, 0, "-")
    };
    emit(
        "response_usage",
        json!({
            "connection_id": connection_id.to_string(),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "finish_reason": finish_reason,
        }),
    );
}

#[cfg(not(feature = "dev-pipeline-trace"))]
#[inline(always)]
pub(crate) fn response_usage(_connection_id: Uuid, _usage: Option<&crate::response::UsageSummary>) {
}
