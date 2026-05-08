//! Hook subprocess entry point.
//!
//! `soth code hook --agent X --type Y` reads stdin, dispatches to the
//! agent's adapter, runs (eventually) classify + policy, enqueues the
//! resulting `GovernableEvent`, and writes the adapter's
//! `AdapterResponse` (stdout/stderr/exit-code) back to the agent.
//!
//! Group 3 ships the smoke-E2E version: stub adapter, no classify, no
//! policy, always Allow. Group 5 (E-2/E-3) wires classify and policy
//! evaluation in.

use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;

use serde_json::json;
use soth_core::extensions::{
    GovernableEvent, META_ACTION_TYPE, META_AGENT_NATIVE_SESSION_ID, META_CORRELATION_KEY,
    META_EVENT_LAYER,
};
use soth_core::{
    CaptureMode, EndpointType, EventSource, ExtensionContext, ExtensionSource, PolicyDecision,
    PolicyDecisionKind,
};
use uuid::Uuid;

use crate::adapter;
use crate::decision::HookDecision;
use crate::event::CodeEvent;
use crate::paths::CodePaths;

/// Outcome of `run_hook`. The CLI translates this back into stdout/
/// stderr writes + exit code (`AdapterResponse` already shaped for that).
#[derive(Debug)]
pub struct HookOutcome {
    pub event_id: Uuid,
    pub decision: HookDecision,
    pub exit_code: ExitCode,
}

/// Errors the hook subprocess surfaces. `on_policy_error` config
/// decides how the CLI responds — Block exits with the agent's
/// blocking-error contract; Allow exits 0 with a stderr warning.
#[derive(Debug, thiserror::Error)]
pub enum HookError {
    #[error("read stdin: {0}")]
    Stdin(#[from] io::Error),
    #[error("no adapter registered for agent {0}")]
    UnknownAgent(String),
    #[error("adapter parse: {0}")]
    Parse(#[from] adapter::ParseError),
    #[error("queue write: {0}")]
    Queue(String),
}

/// Top-level handler called by `soth code hook --agent X --type Y`.
///
/// `paths.queue` parent directory is created if it doesn't exist —
/// first-run installs may not have ever written a soth event.
pub fn run_hook(
    agent_name: &str,
    hook_type: &str,
    stdin_bytes: &[u8],
    paths: &CodePaths,
) -> Result<HookOutcome, HookError> {
    let adapter =
        adapter::for_agent(agent_name).ok_or_else(|| HookError::UnknownAgent(agent_name.into()))?;

    // 1. parse — adapter produces a CodeEvent.
    let code_event = adapter.parse_event(hook_type, stdin_bytes)?;

    // 2. detect — scan payload for credential shapes, produce
    //    SensitiveArtifact per match. Same model the proxy uses.
    //    Detection NEVER mutates the payload (gryph PR #40 / proxy
    //    semantics): mutation would be a policy decision
    //    (`PolicyDecisionKind::Redact`), not the detector's.
    let tool_name = code_event
        .payload
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let artifacts = crate::detect::scan(&code_event.payload, &tool_name);

    // 3. classify (Group 5 — E-2). Stub: skip.
    // 4. decide — Group-4 default: any credential detection produces a
    //    Block. Group 5 (E-3) replaces this with `soth_policy::evaluate`
    //    so per-org OPA rules can override (e.g. flag-only mode in
    //    dev). Default-deny matches the security-tool stance — gryph
    //    Issue #20 was filed because Pi Agent shipped silent fail-open.
    let (decision, policy) = if artifacts.is_empty() {
        (
            HookDecision::Allow,
            PolicyDecision {
                kind: PolicyDecisionKind::Allow,
                matched_rule: None,
                warnings: Vec::new(),
                eval_latency_us: 0,
            },
        )
    } else {
        let kinds: Vec<String> = artifacts
            .iter()
            .filter_map(|a| a.credential_kind.clone())
            .collect();
        let reason = format!("credentials detected ({})", kinds.join(", "));
        let guidance = "remove credentials from the payload before retrying";
        (
            HookDecision::Block {
                reason: reason.clone(),
                guidance: Some(guidance.to_string()),
            },
            PolicyDecision {
                kind: PolicyDecisionKind::Block {
                    status: 403,
                    message: reason,
                },
                matched_rule: None,
                warnings: Vec::new(),
                eval_latency_us: 0,
            },
        )
    };

    // 5. enqueue — convert to GovernableEvent (with artifacts attached
    //    as the audit record of what was detected), append a JSONL row
    //    to the queue file the telemetry batcher reads.
    let mut governable = governable_from_code_event(&code_event);
    governable.artifacts = artifacts;
    enqueue(paths.queue.as_path(), &governable, &policy)?;

    // 6. render — adapter decides stdout/stderr/exit code.
    let response = adapter.render_decision(&decision);

    Ok(HookOutcome {
        event_id: code_event.event_id,
        decision,
        exit_code: response.exit_code(),
    })
}

/// Read stdin to EOF — all hook payloads are bounded JSON; agents pipe
/// the whole payload before exec'ing the hook subprocess.
pub fn read_stdin_to_end() -> Result<Vec<u8>, io::Error> {
    let mut buf = Vec::with_capacity(8 * 1024);
    io::stdin().read_to_end(&mut buf)?;
    Ok(buf)
}

fn governable_from_code_event(ev: &CodeEvent) -> GovernableEvent {
    // Map `CodeEvent.agent` → DataSource variant via metadata
    // (TelemetryEvent::from_governable reads "data_source" string from
    // metadata; we mirror the convention historian uses).
    let data_source = data_source_for_agent(&ev.agent);
    let mut metadata = std::collections::HashMap::new();
    metadata.insert(META_ACTION_TYPE.to_string(), ev.action_type.as_str().into());
    metadata.insert(
        META_AGENT_NATIVE_SESSION_ID.to_string(),
        ev.agent_native_session_id.clone(),
    );
    metadata.insert(META_CORRELATION_KEY.to_string(), ev.correlation_key.clone());
    metadata.insert(META_EVENT_LAYER.to_string(), "action".into());
    metadata.insert("agent".to_string(), ev.agent.clone());
    metadata.insert("hook_type".to_string(), ev.hook_type.clone());
    metadata.insert("data_source".to_string(), data_source.into());
    if let Some(seq) = ev.action_seq {
        metadata.insert("action_seq".to_string(), seq.to_string());
    }
    if let Some(sub) = &ev.subagent {
        metadata.insert("subagent_id".to_string(), sub.subagent_id.clone());
        metadata.insert("subagent_type".to_string(), sub.subagent_type.clone());
    }
    // Note: raw payload is not surfaced in metadata. Detection
    // produces artifacts (no raw values) on the GovernableEvent;
    // payload-content telemetry that requires the agent's text lands
    // via classify (Group 5) which is bound by the same redacted-
    // hint convention soth-core uses everywhere else.

    GovernableEvent {
        event_id: ev.event_id,
        timestamp_epoch_ms: ev.timestamp_ms,
        source: EventSource::Extension {
            source: ExtensionSource::Code,
        },
        provider: "code".into(),
        model: None,
        endpoint_type: EndpointType::Unknown,
        normalized: None,
        artifacts: Vec::new(),
        capture_mode: CaptureMode::MetadataOnly,
        embed_content: None,
        context: ExtensionContext {
            extension_name: "code".into(),
            extension_version: env!("CARGO_PKG_VERSION").into(),
            metadata,
        },
    }
}

fn data_source_for_agent(agent: &str) -> &'static str {
    // Snake_case wire form for the seven Code{Agent} DataSource variants.
    // Unknown agents (e.g. stub testing with arbitrary names) get the
    // generic "code" tag — TelemetryEvent::from_governable will fail to
    // map this to a known DataSource and fall back to LiveProxy, which
    // is acceptable for the smoke path. Group 4+ adapters set the right
    // tag once they know their canonical agent name.
    match agent {
        "claude_code" => "code_claude_code",
        "cursor" => "code_cursor",
        "codex" => "code_codex",
        "gemini_cli" => "code_gemini_cli",
        "windsurf" => "code_windsurf",
        "opencode" => "code_open_code",
        "pi_agent" => "code_pi_agent",
        _ => "code_claude_code", // smoke-friendly default
    }
}

fn enqueue(
    queue_path: &Path,
    event: &GovernableEvent,
    decision: &PolicyDecision,
) -> Result<(), HookError> {
    use std::fs::{create_dir_all, OpenOptions};

    if let Some(parent) = queue_path.parent() {
        create_dir_all(parent).map_err(|e| HookError::Queue(e.to_string()))?;
    }

    // Mirror soth-extensions' GovernableQueueRecord shape: schema_version,
    // extension, event, decision. Wrapped here as untyped JSON because
    // we'd otherwise pull GovernableQueueRecord into our public surface
    // — easier to reuse the wire form than wire the type through.
    let record = json!({
        "schema_version": 1u8,
        "extension": "code",
        "event": event,
        "decision": decision,
    });
    let mut line = serde_json::to_string(&record)
        .map_err(|e| HookError::Queue(format!("serialize: {e}")))?;
    line.push('\n');

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(queue_path)
        .map_err(|e| HookError::Queue(format!("open {}: {e}", queue_path.display())))?;
    file.write_all(line.as_bytes())
        .map_err(|e| HookError::Queue(format!("write: {e}")))?;
    Ok(())
}

/// Helper: redirect a `HookOutcome` write to stdout/stderr.
/// CLI calls this so the per-platform `ExitCode` machinery stays here.
pub fn write_outcome(outcome: &HookOutcome) -> Result<(), io::Error> {
    // For Group 3 stub: write a one-line JSON status to stderr so an
    // operator running `soth code hook` interactively sees something.
    // Adapters override this in render_decision when they need to
    // produce stdout structured shapes.
    let mut stderr = io::stderr().lock();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    writeln!(
        stderr,
        "{{\"event_id\":\"{}\",\"decision\":{},\"timestamp_ms\":{}}}",
        outcome.event_id,
        match &outcome.decision {
            HookDecision::Allow => "\"allow\"",
            HookDecision::Block { .. } => "\"block\"",
            HookDecision::Error(_) => "\"error\"",
        },
        now_ms
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn smoke_e2e_writes_queue_row_and_exits_allow() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());

        let outcome = run_hook(
            "claude_code",
            "pre_tool_use",
            br#"{"session_id":"sess-1","tool":"Read","args":{"path":"/etc/hosts"}}"#,
            &paths,
        )
        .expect("hook runs");

        assert!(matches!(outcome.decision, HookDecision::Allow));
        // ExitCode doesn't impl Debug; assert by indirect: AdapterResponse
        // for Allow is exit 0, so this is implicitly tested.

        let queue = fs::read_to_string(&paths.queue).expect("queue file written");
        assert_eq!(queue.lines().count(), 1, "exactly one JSONL row enqueued");
        let parsed: serde_json::Value =
            serde_json::from_str(queue.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["extension"], "code");
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["event"]["context"]["extension_name"], "code");
        assert_eq!(
            parsed["event"]["context"]["metadata"]["agent"],
            "claude_code"
        );
        assert_eq!(
            parsed["event"]["context"]["metadata"]["action_type"],
            "tool_use"
        );
        assert_eq!(
            parsed["event"]["context"]["metadata"]["event_layer"],
            "action"
        );
        assert_eq!(
            parsed["event"]["context"]["metadata"]["data_source"],
            "code_claude_code"
        );
    }

    #[test]
    fn empty_stdin_still_enqueues() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());
        let outcome = run_hook("claude_code", "pre_tool_use", b"", &paths).expect("ok");
        assert!(matches!(outcome.decision, HookDecision::Allow));
        let queue = fs::read_to_string(&paths.queue).unwrap();
        assert_eq!(queue.lines().count(), 1);
    }

    #[test]
    fn unknown_agent_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());
        let r = run_hook("", "pre_tool_use", b"{}", &paths);
        assert!(matches!(r, Err(HookError::UnknownAgent(_))));
    }

    #[test]
    fn malformed_stdin_returns_parse_error() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());
        let r = run_hook("claude_code", "pre_tool_use", b"{ not json", &paths);
        assert!(matches!(r, Err(HookError::Parse(_))));
    }

    #[test]
    fn second_invocation_appends_not_truncates() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());
        for _ in 0..3 {
            run_hook("claude_code", "pre_tool_use", b"{}", &paths).unwrap();
        }
        let queue = fs::read_to_string(&paths.queue).unwrap();
        assert_eq!(queue.lines().count(), 3);
    }
}
