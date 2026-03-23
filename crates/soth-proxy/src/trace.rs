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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraceLevel {
    Off,
    /// Metadata-only pipeline trace (provider, model, tokens, decisions)
    On,
    /// Full content verification: includes request/response body previews
    Verify,
}

#[cfg(feature = "dev-pipeline-trace")]
fn trace_level() -> TraceLevel {
    static LEVEL: OnceLock<TraceLevel> = OnceLock::new();
    *LEVEL.get_or_init(|| {
        match std::env::var("SOTH_PIPELINE_TRACE")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("verify" | "verbose" | "full") => TraceLevel::Verify,
            Some("1" | "true" | "yes" | "on") => TraceLevel::On,
            _ => TraceLevel::Off,
        }
    })
}

#[cfg(feature = "dev-pipeline-trace")]
fn runtime_trace_enabled() -> bool {
    trace_level() != TraceLevel::Off
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
pub(crate) fn tls_gate(host: &str, decision: &crate::gating::GateDecision) {
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
pub(crate) fn tls_gate(_host: &str, _decision: &crate::gating::GateDecision) {}

#[cfg(feature = "dev-pipeline-trace")]
pub(crate) fn tls_stage(
    host: &str,
    verdict: &str,
    reason: crate::gating::DecisionReason,
    note: &str,
) {
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
    _reason: crate::gating::DecisionReason,
    _note: &str,
) {
}

#[cfg(feature = "dev-pipeline-trace")]
pub(crate) fn gate_stage(
    connection_id: Uuid,
    stage: soth_core::GateStage,
    verdict: &str,
    reason: Option<crate::gating::DecisionReason>,
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
    _reason: Option<crate::gating::DecisionReason>,
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
    outcome: &crate::gating::GateOutcome,
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
    _outcome: &crate::gating::GateOutcome,
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
            "provider": &detect_result.normalized.provider,
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
#[allow(clippy::too_many_arguments)]
pub(crate) fn stream_completed(
    connection_id: Uuid,
    chunk_count: u64,
    elapsed_ms: u64,
    usage: Option<&crate::response::UsageSummary>,
    host: &str,
    path: &str,
    parser_id: &str,
    matched_provider: Option<&str>,
    matched_application: Option<&str>,
) {
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
        "stream_completed",
        json!({
            "connection_id": connection_id.to_string(),
            "chunk_count": chunk_count,
            "elapsed_ms": elapsed_ms,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "finish_reason": finish_reason,
            "host": host,
            "path": path,
            "parser_id": parser_id,
            "matched_provider": matched_provider,
            "matched_application": matched_application,
        }),
    );
}

#[cfg(not(feature = "dev-pipeline-trace"))]
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn stream_completed(
    _connection_id: Uuid,
    _chunk_count: u64,
    _elapsed_ms: u64,
    _usage: Option<&crate::response::UsageSummary>,
    _host: &str,
    _path: &str,
    _parser_id: &str,
    _matched_provider: Option<&str>,
    _matched_application: Option<&str>,
) {
}

#[cfg(feature = "dev-pipeline-trace")]
pub(crate) fn stream_turn_completed(
    connection_id: Uuid,
    turn_number: u64,
    model: Option<&str>,
    usage: &soth_detect::StreamUsage,
) {
    emit(
        "stream_turn_completed",
        json!({
            "connection_id": connection_id.to_string(),
            "turn": turn_number,
            "model": model.unwrap_or("unknown"),
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
        }),
    );
}

#[cfg(not(feature = "dev-pipeline-trace"))]
#[inline(always)]
pub(crate) fn stream_turn_completed(
    _connection_id: Uuid,
    _turn_number: u64,
    _model: Option<&str>,
    _usage: &soth_detect::StreamUsage,
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
pub(crate) fn response_usage(
    connection_id: Uuid,
    usage: Option<&crate::response::UsageSummary>,
    status: u16,
    response_body_bytes: usize,
    body_prefix: &str,
) {
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
            "status": status,
            "response_body_bytes": response_body_bytes,
            "body_prefix": body_prefix,
        }),
    );
}

#[cfg(not(feature = "dev-pipeline-trace"))]
#[inline(always)]
pub(crate) fn response_usage(
    _connection_id: Uuid,
    _usage: Option<&crate::response::UsageSummary>,
    _status: u16,
    _response_body_bytes: usize,
    _body_prefix: &str,
) {
}

// ---------------------------------------------------------------------------
// Dev-verify mode: content-level verification for development/debugging
// ---------------------------------------------------------------------------
//
// Enabled with SOTH_DEV_VERIFY=1 (requires dev-pipeline-trace feature).
// Logs the actual request/response content alongside soth's detected metadata
// so the developer can verify:
//   (a) passthrough integrity — the proxy isn't corrupting requests/responses
//   (b) detection accuracy — provider, model, token counts are correct

#[cfg(feature = "dev-pipeline-trace")]
fn dev_verify_enabled() -> bool {
    trace_level() == TraceLevel::Verify
}

#[cfg(feature = "dev-pipeline-trace")]
fn dev_verify_max_body() -> usize {
    static MAX: OnceLock<usize> = OnceLock::new();
    *MAX.get_or_init(|| {
        std::env::var("SOTH_PIPELINE_TRACE_MAX_BODY")
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(4096)
    })
}

#[cfg(feature = "dev-pipeline-trace")]
fn truncate_body(body: &[u8], max: usize) -> String {
    let slice = &body[..body.len().min(max)];
    let text = String::from_utf8_lossy(slice);
    if body.len() > max {
        format!("{}... ({} bytes truncated)", text, body.len() - max)
    } else {
        text.into_owned()
    }
}

#[cfg(feature = "dev-pipeline-trace")]
pub(crate) fn dev_verify_request(
    connection_id: Uuid,
    method: &str,
    host: &str,
    path: &str,
    request_body: &[u8],
    detect_result: &soth_core::DetectResult,
    capture_mode: soth_core::CaptureMode,
) {
    if !dev_verify_enabled() {
        return;
    }

    let n = &detect_result.normalized;
    let (system_prompt, mut user_prompt) = extract_prompts(request_body);
    // If the raw-body extraction failed (form-encoded, protobuf, etc.) but
    // the parser successfully extracted a prompt, use that instead.
    if user_prompt.starts_with("[non-json") || user_prompt.is_empty() {
        if let Some(ref parsed) = n.user_prompt {
            if !parsed.is_empty() {
                user_prompt = parsed.clone();
            }
        }
    }

    let summary = format!(
        "\n\
         ┌─── DEV VERIFY: REQUEST ───────────────────────────────────\n\
         │ connection:  {connection_id}\n\
         │ {method} {host}{path}\n\
         │ capture:     {capture_mode:?}\n\
         ├─── DETECTION ──────────────────────────────────────────────\n\
         │ provider:    {provider}\n\
         │ model:       {model}\n\
         │ endpoint:    {endpoint:?}\n\
         │ confidence:  {confidence:?}\n\
         │ source:      {source:?}\n\
         │ is_ai_call:  {is_ai}\n\
         │ est_tokens:  {input_tokens}\n\
         │ artifacts:   {artifacts}\n\
         │ warnings:    {warnings}\n\
         ├─── SYSTEM PROMPT ──────────────────────────────────────────\n\
         {system_lines}\
         ├─── USER PROMPT ────────────────────────────────────────────\n\
         {prompt_lines}\
         └────────────────────────────────────────────────────────────",
        provider = n.provider,
        model = n.model.as_deref().unwrap_or("-"),
        endpoint = n.endpoint_type,
        confidence = detect_result.confidence,
        source = detect_result.parse_source,
        is_ai = n.is_ai_call,
        input_tokens = n.estimated_input_tokens,
        artifacts = detect_result.artifacts.len(),
        warnings = detect_result.warnings.len(),
        system_lines = format_trace_block(&system_prompt, 500),
        prompt_lines = format_trace_block(&user_prompt, 2000),
    );

    eprintln!("{summary}");

    emit(
        "dev_verify_request",
        json!({
            "connection_id": connection_id.to_string(),
            "method": method,
            "host": host,
            "path": path,
            "provider": &n.provider,
            "model": n.model,
            "endpoint_type": serialize_json(n.endpoint_type),
            "confidence": serialize_json(detect_result.confidence),
            "parse_source": serialize_json(&detect_result.parse_source),
            "is_ai_call": n.is_ai_call,
            "estimated_input_tokens": n.estimated_input_tokens,
            "capture_mode": serialize_json(capture_mode),
            "artifacts_count": detect_result.artifacts.len(),
            "warnings_count": detect_result.warnings.len(),
            "request_body_bytes": request_body.len(),
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
        }),
    );
}

#[cfg(feature = "dev-pipeline-trace")]
fn extract_prompts(body: &[u8]) -> (String, String) {
    let Ok(json) = serde_json::from_slice::<Value>(body) else {
        return (String::new(), String::from("[non-json body]"));
    };

    // System prompt: top-level "system" field (Anthropic) or first system message
    let system = json
        .get("system")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| {
            json.get("systemInstruction")
                .and_then(|v| v.get("parts"))
                .and_then(|v| v.get(0))
                .and_then(|v| v.get("text"))
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .or_else(|| {
            json.get("messages")
                .and_then(|v| v.as_array())
                .and_then(|msgs| {
                    msgs.iter()
                        .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("system"))
                })
                .and_then(|m| extract_message_content(m))
        })
        .unwrap_or_default();

    // User prompt: last user message in messages array, or fallback fields
    let user = json
        .get("messages")
        .and_then(|v| v.as_array())
        .and_then(|msgs| {
            msgs.iter()
                .rev()
                .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))
        })
        .and_then(|m| extract_message_content(m))
        .or_else(|| {
            json.get("prompt")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .or_else(|| json.get("input").and_then(|v| v.as_str()).map(String::from))
        // Gemini: contents[last].parts[0].text
        .or_else(|| {
            json.get("contents")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.last())
                .and_then(|v| v.get("parts"))
                .and_then(|v| v.get(0))
                .and_then(|v| v.get("text"))
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        // GraphQL: variables.input.content
        .or_else(|| {
            json.get("variables")
                .and_then(|v| v.get("input"))
                .and_then(|v| v.get("content"))
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .unwrap_or_default();

    (system, user)
}

#[cfg(feature = "dev-pipeline-trace")]
fn extract_message_content(msg: &Value) -> Option<String> {
    let content = msg.get("content")?;
    // String content
    if let Some(s) = content.as_str() {
        return Some(s.to_string());
    }
    // Array of content blocks: extract text blocks
    if let Some(parts) = content.as_array() {
        let texts: Vec<&str> = parts
            .iter()
            .filter_map(|p| {
                let type_val = p.get("type").and_then(|t| t.as_str()).unwrap_or("text");
                if type_val == "text" || type_val == "input_text" {
                    p.get("text").and_then(|t| t.as_str())
                } else {
                    None
                }
            })
            .collect();
        if !texts.is_empty() {
            return Some(texts.join("\n"));
        }
    }
    None
}

#[cfg(feature = "dev-pipeline-trace")]
fn format_trace_block(text: &str, max_chars: usize) -> String {
    if text.is_empty() {
        return "│ (none)\n".to_string();
    }
    let display = if text.len() > max_chars {
        let end = text
            .char_indices()
            .nth(max_chars)
            .map(|(i, _)| i)
            .unwrap_or(text.len());
        format!("{}... ({} chars truncated)", &text[..end], text.len() - end)
    } else {
        text.to_string()
    };
    display.lines().map(|l| format!("│ {l}\n")).collect()
}

#[cfg(not(feature = "dev-pipeline-trace"))]
#[inline(always)]
pub(crate) fn dev_verify_request(
    _connection_id: Uuid,
    _method: &str,
    _host: &str,
    _path: &str,
    _request_body: &[u8],
    _detect_result: &soth_core::DetectResult,
    _capture_mode: soth_core::CaptureMode,
) {
}

#[cfg(feature = "dev-pipeline-trace")]
pub(crate) fn dev_verify_response(
    connection_id: Uuid,
    status: u16,
    response_body: &[u8],
    usage: Option<&crate::response::UsageSummary>,
    provider: &str,
    model: Option<&str>,
) {
    if !dev_verify_enabled() {
        return;
    }

    let max = dev_verify_max_body();
    let body_text = truncate_body(response_body, max);
    let (input_tokens, output_tokens, finish_reason) = if let Some(u) = usage {
        (
            u.input_tokens,
            u.output_tokens,
            u.finish_reason.as_deref().unwrap_or("-"),
        )
    } else {
        (0, 0, "-")
    };

    let summary = format!(
        "\n\
         ┌─── DEV VERIFY: RESPONSE ──────────────────────────────────\n\
         │ connection:     {connection_id}\n\
         │ status:         {status}\n\
         ├─── USAGE ──────────────────────────────────────────────────\n\
         │ provider:       {provider}\n\
         │ model:          {model}\n\
         │ input_tokens:   {input_tokens}\n\
         │ output_tokens:  {output_tokens}\n\
         │ finish_reason:  {finish_reason}\n\
         ├─── RESPONSE BODY ({body_bytes} bytes) ─────────────────────\n\
         {body_lines}\
         └────────────────────────────────────────────────────────────",
        model = model.unwrap_or("-"),
        body_bytes = response_body.len(),
        body_lines = body_text
            .lines()
            .map(|l| format!("│ {l}\n"))
            .collect::<String>(),
    );

    eprintln!("{summary}");

    emit(
        "dev_verify_response",
        json!({
            "connection_id": connection_id.to_string(),
            "status": status,
            "provider": provider,
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "finish_reason": finish_reason,
            "response_body_bytes": response_body.len(),
            "response_body_preview": body_text,
        }),
    );
}

#[cfg(not(feature = "dev-pipeline-trace"))]
#[inline(always)]
pub(crate) fn dev_verify_response(
    _connection_id: Uuid,
    _status: u16,
    _response_body: &[u8],
    _usage: Option<&crate::response::UsageSummary>,
    _provider: &str,
    _model: Option<&str>,
) {
}

#[cfg(feature = "dev-pipeline-trace")]
pub(crate) fn dev_verify_stream_complete(
    connection_id: Uuid,
    chunk_count: u64,
    elapsed_ms: u64,
    usage: Option<&crate::response::UsageSummary>,
    provider: &str,
    model: Option<&str>,
    host: &str,
    path: &str,
) {
    if !dev_verify_enabled() {
        return;
    }

    let (input_tokens, output_tokens, finish_reason) = if let Some(u) = usage {
        (
            u.input_tokens,
            u.output_tokens,
            u.finish_reason.as_deref().unwrap_or("-"),
        )
    } else {
        (0, 0, "-")
    };

    let summary = format!(
        "\n\
         ┌─── DEV VERIFY: STREAM COMPLETE ───────────────────────────\n\
         │ connection:     {connection_id}\n\
         │ {host}{path}\n\
         ├─── STREAM STATS ───────────────────────────────────────────\n\
         │ chunks:         {chunk_count}\n\
         │ elapsed_ms:     {elapsed_ms}\n\
         ├─── USAGE ──────────────────────────────────────────────────\n\
         │ provider:       {provider}\n\
         │ model:          {model}\n\
         │ input_tokens:   {input_tokens}\n\
         │ output_tokens:  {output_tokens}\n\
         │ finish_reason:  {finish_reason}\n\
         └────────────────────────────────────────────────────────────",
        model = model.unwrap_or("-"),
    );

    eprintln!("{summary}");
}

#[cfg(not(feature = "dev-pipeline-trace"))]
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn dev_verify_stream_complete(
    _connection_id: Uuid,
    _chunk_count: u64,
    _elapsed_ms: u64,
    _usage: Option<&crate::response::UsageSummary>,
    _provider: &str,
    _model: Option<&str>,
    _host: &str,
    _path: &str,
) {
}
