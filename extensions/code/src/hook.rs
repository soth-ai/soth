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
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Serialize};
use serde_json::json;
use soth_classify::{
    ClassifyBundle, ClassifyConfig, HookClassifyInput, HookIdentity as ClassifyIdentity,
};
use soth_core::extensions::{
    GovernableEvent, META_ACTION_TYPE, META_AGENT_NATIVE_SESSION_ID, META_CORRELATION_KEY,
    META_EVENT_LAYER,
};
use soth_core::{
    AnomalyFlag, CaptureMode, DeploymentModel, EndpointType, EventSource, ExtensionContext,
    ExtensionSource, NormalizedRequest, PolicyContext, PolicyDecision, PolicyDecisionKind,
    ProcessResolution, SemanticPolicyContext, SensitiveArtifact, SessionSnapshot,
    TrafficClassification, UseCaseLabel, VolatilityClass,
};
use soth_policy::PolicyBundle;
use uuid::Uuid;

use crate::adapter;
use crate::decision::HookDecision;
use crate::event::{ClassifySidecar, CodeCaptureMode, CodeEvent, HookCaptureConfig};
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
///
/// `capture` controls whether the raw hook payload survives into the
/// queue. Default ([`HookCaptureConfig::default`]) is `Metadata` —
/// raw payload is dropped before enqueue, only derived signals are
/// persisted. Operators set `Audit` or `Full` via `code.capture.mode`
/// in `soth.yaml` to preserve raw payload for forensics or
/// compliance; the cloud-side surface gates this further per-org.
pub fn run_hook(
    agent_name: &str,
    hook_type: &str,
    stdin_bytes: &[u8],
    paths: &CodePaths,
    capture: &HookCaptureConfig,
) -> Result<HookOutcome, HookError> {
    let total_start = std::time::Instant::now();
    let adapter =
        adapter::for_agent(agent_name).ok_or_else(|| HookError::UnknownAgent(agent_name.into()))?;

    // 1. parse — adapter produces a CodeEvent.
    let parse_start = std::time::Instant::now();
    let mut code_event = adapter.parse_event(hook_type, stdin_bytes)?;
    let parse_us = elapsed_us(parse_start);

    // 2. detect — scan payload for credential shapes, produce
    //    SensitiveArtifact per match. Same model the proxy uses.
    //    Detection NEVER mutates the payload (gryph PR #40 / proxy
    //    semantics): mutation would be a policy decision
    //    (`PolicyDecisionKind::Redact`), not the detector's.
    let detect_start = std::time::Instant::now();
    let tool_name = code_event
        .payload
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let artifacts = crate::detect::scan(&code_event.payload, &tool_name);
    let detect_us = elapsed_us(detect_start);

    // 3. classify — adapter declares which slice of the payload is
    //    classifiable (prompt text, tool args, tool result). When
    //    classify ran, attach the sidecar so the policy evaluator
    //    (step 4) can read `PolicyContext.semantic` and the dashboard
    //    can render anomaly score + use-case label per-action.
    let classify_start = std::time::Instant::now();
    if let Some(extract) = adapter.classify_input(&code_event) {
        let identity = ClassifyIdentity::default();
        let input = HookClassifyInput {
            agent_name: &code_event.agent,
            provider: provider_for_agent(&code_event.agent),
            model: None,
            content: &extract.content,
            kind: extract.kind,
            identity: &identity,
        };
        let bundle = classify_bundle();
        let config = ClassifyConfig::default();
        let result = soth_classify::classify_for_hook(input, &bundle, &config);
        code_event.classify = Some(ClassifySidecar::from(&result));
    }
    let classify_us = elapsed_us(classify_start);

    // 4. decide — when an OPA bundle is loaded (via env var
    //    SOTH_CODE_POLICY_BUNDLE or a default path), the bundle's
    //    decision is authoritative: Rego/CEL rules can Block, Allow,
    //    Redact, Reroute, Flag based on classify outputs + artifacts.
    //    When no bundle is loaded, fall through to the artifact-
    //    driven default-deny — gryph Issue #20's silent fail-open
    //    lesson, encoded as a security-tool default.
    let policy_start = std::time::Instant::now();
    let (mut decision, mut policy) = match policy_bundle() {
        Some(bundle) => {
            let normalized = build_normalized_for_policy(&code_event);
            let policy_ctx = build_policy_context(&code_event);
            let bundle_decision =
                soth_policy::evaluate(&normalized, &artifacts, &policy_ctx, bundle);
            translate_policy_decision(bundle_decision, &artifacts)
        }
        None => default_deny_from_artifacts(&artifacts),
    };
    let policy_us = elapsed_us(policy_start);

    // 4b. enforcement gate — Block decisions only halt **pre-action**
    //     hooks where blocking actually prevents the action from
    //     running. PostToolUse / Stop / SessionEnd / Notification
    //     fire AFTER the fact; returning Block from them creates a
    //     feedback loop (the Stop payload often echoes the
    //     conversation context which may contain the same credential
    //     pattern that just got blocked, leading to recursive Block
    //     on every Stop hook). The action is already done — there is
    //     nothing to halt, only to record. Surfaced live during the
    //     2026-05-08 soak with Claude Code: Bash containing an AKIA
    //     key was correctly blocked by PreToolUse, then the Stop
    //     hook saw the same pattern in the conversation and started
    //     blocking every turn.
    //
    //     Artifacts and decisions are still recorded in the queue;
    //     only the agent-facing exit code is downgraded to Allow.
    if matches!(decision, HookDecision::Block { .. }) && !adapter.is_pre_action_hook(hook_type) {
        tracing::warn!(
            hook_type = hook_type,
            artifact_count = artifacts.len(),
            "soth-code: Block produced on post-action hook; downgrading to Allow (artifacts still audited)"
        );
        decision = HookDecision::Allow;
        // Note: the queue's PolicyDecision goes to `Allow`, but the
        // GovernableEvent.artifacts list (set below) preserves the
        // detection record. Operator querying `tail -F` sees
        // `decision: allow, artifacts: [...]` — clear that something
        // was detected but not enforced. The downgrade reason lives
        // in the tracing log line above; not surfaced via
        // `PolicyWarning` because serde can't round-trip the
        // tag-newtype variant cleanly.
        policy = PolicyDecision {
            kind: PolicyDecisionKind::Allow,
            matched_rule: None,
            warnings: Vec::new(),
            eval_latency_us: 0,
        };
    }

    // 5. enqueue — convert to GovernableEvent (with artifacts attached
    //    as the audit record of what was detected), append a JSONL row
    //    to the queue file the telemetry batcher reads. When the
    //    operator has opted into raw payload capture (Audit or Full
    //    mode), the JSON-stringified payload lands in metadata
    //    alongside a `raw_capture` tag identifying which mode was
    //    active. Default Metadata mode drops the payload at this
    //    boundary — see HookCaptureConfig docstring.
    let mut governable = governable_from_code_event(&code_event);
    governable.artifacts = artifacts;
    if should_capture_raw(capture.mode, &decision) {
        attach_raw_payload(&mut governable, &code_event, capture);
    }
    let enqueue_start = std::time::Instant::now();
    enqueue(paths.queue.as_path(), &governable, &policy)?;
    let enqueue_us = elapsed_us(enqueue_start);

    // Stamp per-stage timings into the *just-written* row by
    // computing total here and re-writing the metadata. We do
    // this via a follow-up append of the timing summary
    // (in-place rewrite would race with concurrent writers).
    // The main row already carries decision/artifacts; the
    // timing sidecar is a separate JSONL row keyed by event_id
    // that the cloud ingestion / `soth code stats` can join.
    let total_us = elapsed_us(total_start);
    let timings = HookTimings {
        event_id: code_event.event_id,
        agent: code_event.agent.clone(),
        action_type: code_event.action_type.as_str().to_string(),
        decision: decision_label(&decision).to_string(),
        parse_us,
        detect_us,
        classify_us,
        policy_us,
        enqueue_us,
        total_us,
    };
    if let Err(e) = append_timing_row(timings_path(paths).as_path(), &timings) {
        // Timing telemetry is best-effort — never block the
        // hook because we couldn't write the timings sidecar.
        tracing::warn!("soth-code: failed to append hook timings: {e}");
    }

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
    // Surface classify outputs as **flat metadata keys** matching the
    // convention established by historian's ClassifyEnricher
    // (`extensions/historian/src/enrich.rs::keys`). `TelemetryEvent::
    // from_governable` reads these keys; if they're absent it sets
    // `use_case_label_reason = ExtensionNotEnriched` (formerly
    // HistorianNotEnriched, generalized once soth-code became the
    // second extension). Earlier drafts used a single JSON-stringified
    // sidecar under `metadata["classify"]`, which from_governable
    // didn't know about — every soth-code event ended up tagged
    // `ExtensionNotEnriched` and the WARN fired on every batch.
    //
    // Use-case label and reason are written as serde-serialized JSON
    // strings (e.g. `"\"Unknown\""`, `"\"fallback_bundle\""`) since
    // historian writes them via `serde_json::to_string` and
    // from_governable parses them via `serde_json::from_str`.
    if let Some(sidecar) = &ev.classify {
        // use_case label needs the JSON-quoted **snake_case** form so
        // from_governable's `serde_json::from_str::<UseCaseLabel>`
        // deserializes it. ClassifySidecar stores the Debug PascalCase
        // form (e.g. "Unknown"), so convert before writing — without
        // this conversion the use_case key was unreadable by
        // from_governable and every soth-code event fell back to
        // ExtensionNotEnriched, defeating the whole flat-keys fix.
        metadata.insert(
            "classify.use_case".into(),
            format!("\"{}\"", to_snake(&sidecar.use_case_label)),
        );
        metadata.insert(
            "classify.use_case_confidence".into(),
            sidecar.use_case_confidence.to_string(),
        );
        // FallbackBundle is the right reason while Group 5 ships with
        // KeywordClassifier (no ONNX model). When a real bundle is
        // installed, classify will produce Confident or LowConfidence
        // and we'll source the reason from the ClassifiedResult.
        metadata.insert(
            "classify.use_case_label_reason".into(),
            "\"fallback_bundle\"".into(),
        );
        metadata.insert(
            "classify.anomaly_score".into(),
            sidecar.anomaly_score.to_string(),
        );
        metadata.insert(
            "classify.complexity_score".into(),
            sidecar.complexity_score.to_string(),
        );
        metadata.insert(
            "classify.topic_cluster_id".into(),
            sidecar.topic_cluster_id.to_string(),
        );
        // Volatility / dynamic_fraction would land here too once
        // `ClassifySidecar` carries them. The JSON-string sidecar
        // (`metadata["classify"]`) is intentionally NOT written —
        // `from_governable` would ignore it and we'd carry duplicate
        // information.
    }
    // Note: raw payload is not surfaced. Detection produces artifacts
    // (no raw values) on the GovernableEvent; classify summary lives
    // in the flat keys above.

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

/// Which LLM provider sits behind each agent. Surfaces in
/// `IdentityContext::declared_provider` so cloud analytics can
/// segment by provider when classify-on-hook is the only signal.
fn provider_for_agent(agent: &str) -> Option<&'static str> {
    match agent {
        "claude_code" => Some("anthropic"),
        "codex" => Some("openai"),
        "gemini_cli" => Some("google"),
        // Cursor / Windsurf / OpenCode / Pi Agent are multi-provider —
        // the agent payload doesn't always reveal which API was hit.
        // Leave as None and let cloud-side enrichment fill in if it can.
        _ => None,
    }
}

/// Lazy-loaded policy bundle. Returns `Some(&'static PolicyBundle)` if
/// a bundle is configured at `SOTH_CODE_POLICY_BUNDLE` or
/// `~/.soth/code-policy.bundle`, otherwise `None`. Cached for the
/// lifetime of the hook process; for ephemeral subprocess invocations
/// this means one load per agent action — acceptable since the bundle
/// loader is small.
fn policy_bundle() -> Option<&'static PolicyBundle> {
    static CACHE: OnceLock<Option<PolicyBundle>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            let path = bundle_path()?;
            if !path.exists() {
                return None;
            }
            match soth_policy::load_bundle(&path) {
                Ok(bundle) => {
                    soth_policy::warm(&bundle);
                    Some(bundle)
                }
                Err(e) => {
                    tracing::warn!(
                        bundle_path = %path.display(),
                        error = ?e,
                        "soth-code: failed to load policy bundle; falling through to artifact default-deny"
                    );
                    None
                }
            }
        })
        .as_ref()
}

fn bundle_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SOTH_CODE_POLICY_BUNDLE") {
        return Some(PathBuf::from(p));
    }
    dirs::home_dir().map(|h| h.join(".soth").join("code-policy.bundle"))
}

/// Build a `NormalizedRequest` from a `CodeEvent` for policy
/// evaluation. Fields the OPA evaluator's CEL expressions read
/// (`provider`, `model`, `user_content_hash`, `user_prompt`) come
/// from the event; everything else takes a sensible default.
fn build_normalized_for_policy(ev: &CodeEvent) -> NormalizedRequest {
    let user_content = match ev.classify.as_ref() {
        Some(c) => c.semantic_hash.clone(),
        None => String::new(),
    };
    NormalizedRequest {
        parser_id: format!("code_hook:{}", ev.agent),
        is_ai_call: matches!(
            ev.action_type,
            crate::event::ActionType::UserPromptSubmit | crate::event::ActionType::Stop
        ),
        provider: provider_for_agent(&ev.agent).unwrap_or("unknown").to_string(),
        user_content_hash: user_content.clone(),
        conversation_hash: user_content,
        ..NormalizedRequest::default()
    }
}

/// Build a `PolicyContext` from a `CodeEvent`. The `semantic` field
/// carries classify outputs so OPA rules can read
/// `input.semantic.use_case_label`, `input.semantic.anomaly_score`,
/// etc. — which is the SOTH-vs-gryph capability advantage
/// (docs/gryph/plan.md §10.10).
fn build_policy_context(ev: &CodeEvent) -> PolicyContext {
    let semantic = ev.classify.as_ref().map(|c| SemanticPolicyContext {
        use_case_label: parse_use_case_label(&c.use_case_label),
        use_case_confidence: c.use_case_confidence,
        anomaly_score: c.anomaly_score,
        anomaly_flags: c
            .anomaly_flags
            .iter()
            .filter_map(|s| parse_anomaly_flag(s))
            .collect(),
        complexity_score: c.complexity_score,
        volatility_class: VolatilityClass::Static,
        topic_cluster_id: c.topic_cluster_id,
    });
    PolicyContext {
        process_resolution: ProcessResolution::default(),
        capture_mode: CaptureMode::Full,
        traffic_classification: TrafficClassification::ToolUsage,
        deployment: DeploymentModel::Sdk {
            service_name: "soth-code".to_string(),
            environment: std::env::var("SOTH_ENV").unwrap_or_else(|_| "prod".to_string()),
        },
        skip_org_rules: false,
        semantic,
        session: SessionSnapshot::default(),
        action: Some(build_action_policy_context(ev)),
    }
}

/// Pull adapter-extracted action fields out of `CodeEvent.payload`
/// for CEL policy evaluation. The payload shape varies per agent
/// (Claude Code's pre_tool_use carries `tool_name` + `tool_input`;
/// Cursor's `before_shell_execution` carries `command`); we
/// best-effort parse the common shapes and leave fields `None`
/// where extraction isn't reliable. CEL rules referencing missing
/// fields evaluate to Null, so a rule like
/// `action.command.contains("rm -rf")` is naturally a no-op when
/// `command` wasn't extracted.
fn build_action_policy_context(ev: &CodeEvent) -> soth_core::ActionPolicyContext {
    let payload = &ev.payload;
    // Tool name: Claude Code (`tool_name`), tool_use payloads
    // for OpenAI/Codex (`tool` or `name` inside an object).
    let tool_name = payload
        .get("tool_name")
        .and_then(|v| v.as_str())
        .or_else(|| payload.get("name").and_then(|v| v.as_str()))
        .map(|s| s.to_string());
    // Command: Claude Code's Bash tool encodes the command as
    // `tool_input.command`; Cursor's before_shell_execution has
    // `command` at the top level; OpenCode/Pi Agent forward
    // `tool_input.command` similarly. Probe both.
    let command = payload
        .get("tool_input")
        .and_then(|t| t.get("command"))
        .and_then(|v| v.as_str())
        .or_else(|| payload.get("command").and_then(|v| v.as_str()))
        .map(|s| s.to_string());
    // File path: same shape — `tool_input.file_path` (Claude
    // Code Edit/Read), or `path` / `file_path` at the top level
    // for other agents.
    let file_path = payload
        .get("tool_input")
        .and_then(|t| t.get("file_path"))
        .and_then(|v| v.as_str())
        .or_else(|| payload.get("file_path").and_then(|v| v.as_str()))
        .or_else(|| payload.get("path").and_then(|v| v.as_str()))
        .map(|s| s.to_string());
    soth_core::ActionPolicyContext {
        agent: ev.agent.clone(),
        action_type: ev.action_type.as_str().to_string(),
        tool_name,
        command,
        file_path,
    }
}

fn parse_use_case_label(s: &str) -> UseCaseLabel {
    // ClassifySidecar stringifies via `format!("{:?}", label)`;
    // Reverse map for the common variants. UseCaseLabel::Unknown is
    // the safe fallback.
    serde_json::from_str(&format!("\"{}\"", to_snake(s))).unwrap_or(UseCaseLabel::Unknown)
}

fn parse_anomaly_flag(s: &str) -> Option<AnomalyFlag> {
    serde_json::from_str(&format!("\"{}\"", to_snake(s))).ok()
}

fn to_snake(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for (i, ch) in s.chars().enumerate() {
        if ch.is_ascii_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(ch.to_ascii_lowercase());
    }
    out
}

/// Translate `soth_policy::evaluate`'s `PolicyDecision` into the agent-
/// facing `HookDecision`. Bundle's decision is authoritative — even
/// when the bundle Allows a credential-bearing payload, we honor it
/// (the operator opted into that policy). The only safety net is when
/// the bundle returns `Allow` *and* artifacts were detected: we still
/// surface the artifacts in the audit record, the policy decision
/// just doesn't enforce.
fn translate_policy_decision(
    pd: PolicyDecision,
    _artifacts: &[SensitiveArtifact],
) -> (HookDecision, PolicyDecision) {
    let decision = match &pd.kind {
        PolicyDecisionKind::Allow => HookDecision::Allow,
        PolicyDecisionKind::Block { message, .. } => HookDecision::Block {
            reason: message.clone(),
            guidance: pd
                .matched_rule
                .as_ref()
                .map(|r| format!("rule {}: see policy bundle", r.rule_id)),
        },
        PolicyDecisionKind::Redact { .. } => HookDecision::Block {
            reason: "policy required redaction; soth-code v0 does not support \
                     in-place hook payload redaction — action blocked"
                .to_string(),
            guidance: Some(
                "remove the sensitive content from the agent payload \
                 before retrying"
                    .to_string(),
            ),
        },
        PolicyDecisionKind::Reroute { .. } => HookDecision::Block {
            reason: "policy required rerouting; soth-code v0 does not \
                     support hook reroute — action blocked"
                .to_string(),
            guidance: None,
        },
        PolicyDecisionKind::Flag { reason } => {
            // Flag is observability-only; the action still proceeds.
            // Group 5 emits the artifact + a flag warning into the
            // queue but doesn't halt the agent.
            tracing::warn!(reason = %reason, "soth-code: policy flagged action; allowing");
            HookDecision::Allow
        }
    };
    (decision, pd)
}

/// Default-deny when no policy bundle is loaded. Mirrors the Group 4b
/// behavior — kept here as an explicit branch so the policy-loaded
/// path doesn't have to repeat the artifact-driven decision logic.
fn default_deny_from_artifacts(artifacts: &[SensitiveArtifact]) -> (HookDecision, PolicyDecision) {
    if artifacts.is_empty() {
        return (
            HookDecision::Allow,
            PolicyDecision {
                kind: PolicyDecisionKind::Allow,
                matched_rule: None,
                warnings: Vec::new(),
                eval_latency_us: 0,
            },
        );
    }
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
}

/// Lazy-loaded classify bundle. Group 5 ships with `fallback_bundle()`
/// (deterministic-hash embedding, no ONNX) — fast load per hook
/// subprocess and identical outputs across machines without the
/// model file. Real ONNX-backed bundles would require either a
/// long-running daemon (we explicitly skipped, see plan §5) or a
/// shared-memory model cache (Phase 5).
fn classify_bundle() -> Arc<ClassifyBundle> {
    static CACHE: OnceLock<Arc<ClassifyBundle>> = OnceLock::new();
    CACHE.get_or_init(soth_classify::fallback_bundle).clone()
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

/// Whether the hook handler should preserve the raw payload on the
/// outgoing queue record, given the configured capture mode and the
/// policy decision the event landed on.
///
/// `Metadata` (default) → never. `Audit` → only when the decision
/// halts an action (Block). `Full` → always.
fn should_capture_raw(mode: CodeCaptureMode, decision: &HookDecision) -> bool {
    match mode {
        CodeCaptureMode::Metadata => false,
        CodeCaptureMode::Full => true,
        CodeCaptureMode::Audit => matches!(decision, HookDecision::Block { .. }),
        // Note: `HookDecision` doesn't carry a Flag variant in v0
        // (the policy evaluator's `PolicyDecisionKind::Flag` becomes
        // Allow at the hook layer per `translate_policy_decision`).
        // When Flag rendering lands, extend this match to include it.
    }
}

/// Insert the raw payload into the GovernableEvent's metadata,
/// truncated to `capture.max_payload_bytes` so a megabyte-sized MCP
/// tool response (gryph PR #32 surfaced this in the wild) doesn't
/// blow up queue-row size. The truncation marker `…[truncated]` is
/// appended so the dashboard can render "this was cut" rather than
/// silently dropping the tail.
fn attach_raw_payload(
    governable: &mut GovernableEvent,
    code_event: &CodeEvent,
    capture: &HookCaptureConfig,
) {
    let json = match serde_json::to_string(&code_event.payload) {
        Ok(s) => s,
        Err(_) => return,
    };
    let payload = if json.len() > capture.max_payload_bytes {
        // Cut at a UTF-8 codepoint boundary; truncating mid-codepoint
        // would produce an invalid JSON string the cloud's parser
        // would reject.
        let mut cut = capture.max_payload_bytes;
        while cut > 0 && !json.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}…[truncated]", &json[..cut])
    } else {
        json
    };
    governable
        .context
        .metadata
        .insert("raw_payload".to_string(), payload);
    governable
        .context
        .metadata
        .insert("raw_capture".to_string(), capture.mode.as_str().to_string());
}

/// Per-hook timing summary written to the local timings sidecar.
/// One row per hook invocation; `soth code stats` reads the file
/// to compute p50/p95/p99 percentiles per stage. Kept separate
/// from the main GovernableEvent queue so cloud ingestion isn't
/// polluted with operational telemetry — the cloud has its own
/// per-event latency surface via the existing classify
/// `eval_latency_us` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookTimings {
    pub event_id: uuid::Uuid,
    pub agent: String,
    pub action_type: String,
    pub decision: String,
    pub parse_us: u64,
    pub detect_us: u64,
    pub classify_us: u64,
    pub policy_us: u64,
    pub enqueue_us: u64,
    pub total_us: u64,
}

fn elapsed_us(start: std::time::Instant) -> u64 {
    start.elapsed().as_micros().min(u64::MAX as u128) as u64
}

fn decision_label(d: &HookDecision) -> &'static str {
    match d {
        HookDecision::Allow => "allow",
        HookDecision::Block { .. } => "block",
        HookDecision::Error(_) => "error",
    }
}

/// Sidecar path for hook-timing JSONL — co-located with the
/// queue under `<queue-dir>/code-hook-timings.jsonl`.
pub fn timings_path(paths: &CodePaths) -> PathBuf {
    let queue_dir = paths
        .queue
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| paths.queue.clone());
    queue_dir.join("code-hook-timings.jsonl")
}

fn append_timing_row(path: &Path, timings: &HookTimings) -> std::io::Result<()> {
    use std::fs::{create_dir_all, OpenOptions};
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    let mut line = serde_json::to_string(timings)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    line.push('\n');
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(line.as_bytes())?;
    Ok(())
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
            &HookCaptureConfig::default(),
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
        let outcome = run_hook("claude_code", "pre_tool_use", b"", &paths, &HookCaptureConfig::default()).expect("ok");
        assert!(matches!(outcome.decision, HookDecision::Allow));
        let queue = fs::read_to_string(&paths.queue).unwrap();
        assert_eq!(queue.lines().count(), 1);
    }

    #[test]
    fn unknown_agent_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());
        let r = run_hook("", "pre_tool_use", b"{}", &paths, &HookCaptureConfig::default());
        assert!(matches!(r, Err(HookError::UnknownAgent(_))));
    }

    #[test]
    fn malformed_stdin_returns_parse_error() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());
        let r = run_hook("claude_code", "pre_tool_use", b"{ not json", &paths, &HookCaptureConfig::default());
        assert!(matches!(r, Err(HookError::Parse(_))));
    }

    #[test]
    fn second_invocation_appends_not_truncates() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());
        for _ in 0..3 {
            run_hook("claude_code", "pre_tool_use", b"{}", &paths, &HookCaptureConfig::default()).unwrap();
        }
        let queue = fs::read_to_string(&paths.queue).unwrap();
        assert_eq!(queue.lines().count(), 3);
    }

    #[test]
    fn default_deny_blocks_when_artifacts_present() {
        let arts = vec![SensitiveArtifact {
            kind: soth_core::ArtifactKind::AwsAccessKey,
            credential_kind: Some("aws_access_key".to_string()),
            severity: soth_core::ArtifactSeverity::Critical,
            location: soth_core::ArtifactLocation::Unknown,
            commitment: None,
            redacted_hint: None,
        }];
        let (decision, policy) = default_deny_from_artifacts(&arts);
        assert!(matches!(decision, HookDecision::Block { .. }));
        assert!(matches!(policy.kind, PolicyDecisionKind::Block { .. }));
    }

    #[test]
    fn default_deny_allows_when_no_artifacts() {
        let (decision, policy) = default_deny_from_artifacts(&[]);
        assert!(matches!(decision, HookDecision::Allow));
        assert!(matches!(policy.kind, PolicyDecisionKind::Allow));
    }

    #[test]
    fn translate_policy_block_to_hook_block() {
        let pd = PolicyDecision {
            kind: PolicyDecisionKind::Block {
                status: 403,
                message: "rule X says no".to_string(),
            },
            matched_rule: None,
            warnings: Vec::new(),
            eval_latency_us: 0,
        };
        let (decision, _) = translate_policy_decision(pd, &[]);
        match decision {
            HookDecision::Block { reason, .. } => assert_eq!(reason, "rule X says no"),
            _ => panic!("expected Block"),
        }
    }

    #[test]
    fn translate_policy_allow_passes_through() {
        let pd = PolicyDecision {
            kind: PolicyDecisionKind::Allow,
            matched_rule: None,
            warnings: Vec::new(),
            eval_latency_us: 0,
        };
        let (decision, _) = translate_policy_decision(pd, &[]);
        assert!(matches!(decision, HookDecision::Allow));
    }

    #[test]
    fn translate_policy_redact_becomes_block_in_v0() {
        // Redact requires in-place payload mutation which the hook
        // protocol doesn't support. Until SOTH supports redirecting
        // the agent's payload, redact decisions degrade to block —
        // operator gets a clear message that redaction was requested.
        let pd = PolicyDecision {
            kind: PolicyDecisionKind::Redact { targets: Vec::new() },
            matched_rule: None,
            warnings: Vec::new(),
            eval_latency_us: 0,
        };
        let (decision, _) = translate_policy_decision(pd, &[]);
        assert!(matches!(decision, HookDecision::Block { .. }));
    }

    #[test]
    fn translate_policy_flag_allows_with_warning() {
        let pd = PolicyDecision {
            kind: PolicyDecisionKind::Flag {
                reason: "watch this one".to_string(),
            },
            matched_rule: None,
            warnings: Vec::new(),
            eval_latency_us: 0,
        };
        let (decision, _) = translate_policy_decision(pd, &[]);
        assert!(matches!(decision, HookDecision::Allow));
    }

    #[test]
    fn to_snake_handles_pascal_case() {
        assert_eq!(to_snake("HelloWorld"), "hello_world");
        assert_eq!(to_snake("Lower"), "lower");
        assert_eq!(to_snake("ABC"), "a_b_c");
        assert_eq!(to_snake(""), "");
    }

    #[test]
    fn provider_for_agent_known_agents() {
        assert_eq!(provider_for_agent("claude_code"), Some("anthropic"));
        assert_eq!(provider_for_agent("codex"), Some("openai"));
        assert_eq!(provider_for_agent("gemini_cli"), Some("google"));
        assert_eq!(provider_for_agent("cursor"), None); // multi-provider
        assert_eq!(provider_for_agent("unknown_agent"), None);
    }

    #[test]
    fn build_policy_context_populates_semantic_when_classified() {
        // Verifies the wire from CodeEvent.classify → PolicyContext.semantic
        // — the hook is the load-bearing surface for plan §10.10's
        // "real-time enforcement on classify-derived signals".
        let mut ev = CodeEvent::new(
            "claude_code",
            "pre_tool_use",
            crate::event::ActionType::ToolUse,
            "s",
            serde_json::json!({}),
        );
        ev.classify = Some(ClassifySidecar {
            semantic_hash: "abc".into(),
            use_case_label: "Unknown".into(),
            use_case_confidence: 0.5,
            complexity_score: 3,
            anomaly_score: 0.7,
            anomaly_flags: vec![],
            estimated_input_tokens: 10,
            topic_cluster_id: 42,
            stage_total_us: 100,
        });
        let pctx = build_policy_context(&ev);
        let semantic = pctx.semantic.expect("semantic populated when classify ran");
        assert_eq!(semantic.use_case_confidence, 0.5);
        assert_eq!(semantic.anomaly_score, 0.7);
        assert_eq!(semantic.topic_cluster_id, 42);
    }

    #[test]
    fn build_policy_context_no_semantic_when_no_classify() {
        let ev = CodeEvent::new(
            "claude_code",
            "session_start",
            crate::event::ActionType::SessionStart,
            "s",
            serde_json::json!({}),
        );
        let pctx = build_policy_context(&ev);
        assert!(pctx.semantic.is_none());
    }

    #[test]
    fn claude_code_pre_action_hook_classification() {
        // Pre-action: blocking actually halts the action.
        let a = adapter::ClaudeCodeAdapter::new();
        use crate::adapter::Adapter;
        assert!(a.is_pre_action_hook("pre_tool_use"));
        assert!(a.is_pre_action_hook("user_prompt_submit"));
        assert!(a.is_pre_action_hook("subagent_start"));

        // Post-action: blocking would create feedback loops.
        assert!(!a.is_pre_action_hook("post_tool_use"));
        assert!(!a.is_pre_action_hook("stop"));
        assert!(!a.is_pre_action_hook("session_end"));
        assert!(!a.is_pre_action_hook("notification"));
        assert!(!a.is_pre_action_hook("subagent_stop"));

        // Lifecycle: not enforceable (refusing session start would
        // refuse to let Claude Code initialize).
        assert!(!a.is_pre_action_hook("session_start"));

        // Unknown: treat as non-enforceable for safety.
        assert!(!a.is_pre_action_hook("totally_made_up"));
    }

    #[test]
    fn stop_hook_with_credentials_in_payload_does_not_block() {
        // Surfaced live during 2026-05-08 soak: the Stop hook payload
        // sometimes echoes conversation context which may contain a
        // credential pattern that just got blocked by PreToolUse.
        // Without the enforcement gate, Stop would Block on the same
        // pattern → Claude Code can't finish its turn → feedback loop.
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());

        // Payload includes an AKIA pattern that detect() will catch.
        // Stop hook must still Allow regardless.
        let stdin = br#"{
            "session_id": "sess-stop-loop",
            "transcript_path": "/tmp/transcript.jsonl",
            "stop_hook_active": true,
            "context": "earlier the user pasted AKIAIOSFODNN7EXAMPLE in a command"
        }"#;
        let outcome = run_hook("claude_code", "stop", stdin, &paths, &HookCaptureConfig::default()).unwrap();
        assert!(
            matches!(outcome.decision, HookDecision::Allow),
            "Stop hook with credentials in payload must downgrade to Allow, got {:?}",
            outcome.decision
        );

        // The artifact is still recorded in the queue for audit —
        // operator can see *what* leaked, just doesn't get Block on
        // the wrong hook type.
        let queue = std::fs::read_to_string(&paths.queue).unwrap();
        let row: serde_json::Value =
            serde_json::from_str(queue.lines().next().unwrap()).unwrap();
        let artifacts = row["event"]["artifacts"].as_array().unwrap();
        assert!(
            !artifacts.is_empty(),
            "artifacts must still be recorded even when decision is downgraded"
        );
    }

    #[test]
    fn classify_outputs_land_in_flat_metadata_keys_not_json_blob() {
        // Regression for the production WARN: soth-code's queue rows
        // were tagged `extension_not_enriched` because they wrote a
        // JSON-stringified sidecar instead of historian's flat
        // `classify.*` key convention. After this fix,
        // `TelemetryEvent::from_governable` reads the keys directly
        // and the reason becomes `FallbackBundle` (or Confident, when
        // a real bundle ships).
        use soth_core::TelemetryEvent;

        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());
        let stdin = br#"{
            "session_id":"flat-keys-test",
            "tool_name":"Read",
            "tool_input":{"file_path":"/etc/hosts"}
        }"#;
        run_hook("claude_code", "pre_tool_use", stdin, &paths, &HookCaptureConfig::default()).unwrap();

        // Read the queue row back, deserialize the GovernableEvent,
        // and convert to TelemetryEvent the same way the batcher does.
        let queue = std::fs::read_to_string(&paths.queue).unwrap();
        let row: serde_json::Value =
            serde_json::from_str(queue.lines().next().unwrap()).unwrap();
        let governable: soth_core::GovernableEvent =
            serde_json::from_value(row["event"].clone()).unwrap();

        let meta = &governable.context.metadata;
        // Flat keys present
        assert!(
            meta.contains_key("classify.use_case"),
            "missing classify.use_case key — from_governable can't read it"
        );
        assert!(meta.contains_key("classify.use_case_confidence"));
        assert!(meta.contains_key("classify.use_case_label_reason"));
        assert!(meta.contains_key("classify.anomaly_score"));
        // JSON sidecar should be GONE (replaced by flat keys)
        assert!(
            !meta.contains_key("classify"),
            "JSON sidecar 'classify' should not be written alongside flat keys (duplicate info)"
        );

        // The actual closing-the-loop check: TelemetryEvent::from_governable
        // resolves the use_case_label_reason to FallbackBundle, NOT
        // ExtensionNotEnriched. This is what stops the production
        // WARN from firing on every batch.
        let telem = TelemetryEvent::from_governable(&governable, None);
        assert_ne!(
            telem.use_case_label_reason,
            soth_core::UseCaseLabelReason::ExtensionNotEnriched,
            "from_governable must read soth-code's flat classify keys and not fall back to ExtensionNotEnriched"
        );
        assert_eq!(
            telem.use_case_label_reason,
            soth_core::UseCaseLabelReason::FallbackBundle,
            "with the KeywordClassifier fallback bundle, reason should be FallbackBundle"
        );
    }

    #[test]
    fn historian_not_enriched_serde_alias_still_deserializes() {
        // Wire-compat regression: any in-flight events from the era
        // before this rename serialized as
        // `"historian_not_enriched"`. Cloud sinks or replay tooling
        // reading those records must still parse them — `#[serde(
        // alias = "historian_not_enriched")]` on `ExtensionNotEnriched`
        // pins this contract.
        let v: soth_core::UseCaseLabelReason =
            serde_json::from_str("\"historian_not_enriched\"").unwrap();
        assert_eq!(v, soth_core::UseCaseLabelReason::ExtensionNotEnriched);
        // New variant also round-trips.
        let v: soth_core::UseCaseLabelReason =
            serde_json::from_str("\"extension_not_enriched\"").unwrap();
        assert_eq!(v, soth_core::UseCaseLabelReason::ExtensionNotEnriched);
    }

    #[test]
    fn capture_default_is_metadata() {
        let cfg = HookCaptureConfig::default();
        assert!(matches!(cfg.mode, CodeCaptureMode::Metadata));
    }

    #[test]
    fn capture_metadata_drops_raw_payload() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());
        let stdin = br#"{"session_id":"md","tool_name":"Bash","tool_input":{"command":"echo hi"}}"#;
        run_hook(
            "claude_code",
            "pre_tool_use",
            stdin,
            &paths,
            &HookCaptureConfig::default(),
        )
        .unwrap();
        let row: serde_json::Value = serde_json::from_str(
            std::fs::read_to_string(&paths.queue).unwrap().lines().next().unwrap(),
        )
        .unwrap();
        let meta = &row["event"]["context"]["metadata"];
        assert!(meta.get("raw_payload").is_none());
        assert!(meta.get("raw_capture").is_none());
    }

    #[test]
    fn capture_full_persists_every_event() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());
        let cap = HookCaptureConfig {
            mode: CodeCaptureMode::Full,
            max_payload_bytes: 65536,
        };
        let stdin =
            br#"{"session_id":"full","tool_name":"Read","tool_input":{"file_path":"/etc/hosts"}}"#;
        run_hook("claude_code", "pre_tool_use", stdin, &paths, &cap).unwrap();
        let row: serde_json::Value = serde_json::from_str(
            std::fs::read_to_string(&paths.queue).unwrap().lines().next().unwrap(),
        )
        .unwrap();
        let meta = &row["event"]["context"]["metadata"];
        assert!(meta["raw_payload"]
            .as_str()
            .unwrap()
            .contains("/etc/hosts"));
        assert_eq!(meta["raw_capture"], "full");
    }

    #[test]
    fn capture_audit_persists_only_for_block_decisions() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());
        let cap = HookCaptureConfig {
            mode: CodeCaptureMode::Audit,
            max_payload_bytes: 65536,
        };

        // Allow event — raw_payload absent.
        let allow_stdin =
            br#"{"session_id":"audit","tool_name":"Read","tool_input":{"file_path":"/tmp/x"}}"#;
        run_hook("claude_code", "pre_tool_use", allow_stdin, &paths, &cap).unwrap();

        // Block event — credential synthesized at runtime so the
        // source file itself is free of the pattern.
        let synth = format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE");
        let block_stdin = format!(
            r#"{{"session_id":"audit","tool_name":"Bash","tool_input":{{"command":"K={synth} aws s3 ls"}}}}"#,
        );
        run_hook(
            "claude_code",
            "pre_tool_use",
            block_stdin.as_bytes(),
            &paths,
            &cap,
        )
        .unwrap();

        let lines: Vec<_> = std::fs::read_to_string(&paths.queue)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);

        let allow_meta = &lines[0]["event"]["context"]["metadata"];
        assert!(
            allow_meta.get("raw_payload").is_none(),
            "Audit must NOT capture on Allow"
        );
        let block_meta = &lines[1]["event"]["context"]["metadata"];
        assert!(
            block_meta["raw_payload"].is_string(),
            "Audit MUST capture on Block"
        );
        assert_eq!(block_meta["raw_capture"], "audit");
    }

    #[test]
    fn capture_full_truncates_at_max_payload_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());
        let cap = HookCaptureConfig {
            mode: CodeCaptureMode::Full,
            max_payload_bytes: 256,
        };
        let big = "x".repeat(2048);
        let stdin = format!(
            r#"{{"session_id":"trunc","tool_name":"Read","tool_input":{{"file_path":"/x","note":"{big}"}}}}"#,
        );
        run_hook(
            "claude_code",
            "pre_tool_use",
            stdin.as_bytes(),
            &paths,
            &cap,
        )
        .unwrap();
        let row: serde_json::Value = serde_json::from_str(
            std::fs::read_to_string(&paths.queue).unwrap().lines().next().unwrap(),
        )
        .unwrap();
        let raw = row["event"]["context"]["metadata"]["raw_payload"]
            .as_str()
            .unwrap();
        assert!(
            raw.ends_with("\u{2026}[truncated]"),
            "truncation marker must suffix oversized payloads (got tail: {})",
            &raw[raw.len().saturating_sub(40)..]
        );
        assert!(
            raw.len() < 1024,
            "truncated body must be near max_payload_bytes (256); got {} bytes",
            raw.len()
        );
    }

    #[test]
    fn pre_tool_use_with_credentials_still_blocks() {
        // Regression guard: the enforcement gate must NOT downgrade
        // Block on enforceable hook types. PreToolUse with a
        // credential remains a Block.
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());
        let stdin = br#"{
            "session_id": "sess-block-still",
            "tool_name": "Bash",
            "tool_input": { "command": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE aws s3 ls" }
        }"#;
        let outcome = run_hook("claude_code", "pre_tool_use", stdin, &paths, &HookCaptureConfig::default()).unwrap();
        assert!(
            matches!(outcome.decision, HookDecision::Block { .. }),
            "PreToolUse with AWS key must still Block, got {:?}",
            outcome.decision
        );
    }

    #[test]
    fn bundle_path_respects_env_override() {
        // Test that the env var override shape is right. We can't
        // exercise policy_bundle() directly without polluting the
        // OnceLock for other tests, but the path resolution function
        // is testable in isolation.
        let key = "SOTH_CODE_POLICY_BUNDLE";
        std::env::set_var(key, "/some/test/path");
        let p = bundle_path().unwrap();
        assert_eq!(p, std::path::PathBuf::from("/some/test/path"));
        std::env::remove_var(key);
    }

    #[test]
    fn build_action_policy_context_extracts_claude_code_bash_command() {
        // Pin the contract: a Claude Code Bash hook payload's
        // `tool_input.command` becomes `action.command` in the
        // CEL eval scope, so an org-authored rule like
        //   `action.type == "command_exec" && action.command.contains("rm -rf")`
        // can match. Without this extraction, the rule would
        // never see the command string and effectively silently
        // disable itself.
        let ev = CodeEvent::new(
            "claude_code",
            "pre_tool_use",
            crate::event::ActionType::CommandExec,
            "sess-1",
            serde_json::json!({
                "tool_name": "Bash",
                "tool_input": { "command": "rm -rf /tmp/test", "description": "cleanup" }
            }),
        );
        let action = build_action_policy_context(&ev);
        assert_eq!(action.agent, "claude_code");
        assert_eq!(action.action_type, "command_exec");
        assert_eq!(action.tool_name.as_deref(), Some("Bash"));
        assert_eq!(action.command.as_deref(), Some("rm -rf /tmp/test"));
        assert_eq!(action.file_path, None);
    }

    #[test]
    fn build_action_policy_context_extracts_file_path_from_edit_payload() {
        // Claude Code's Edit/Read tools encode the target via
        // `tool_input.file_path`. Verify that lands as
        // `action.file_path` so org rules can match
        // sensitive-glob patterns like `.ssh/` or `.aws/`.
        let ev = CodeEvent::new(
            "claude_code",
            "pre_tool_use",
            crate::event::ActionType::FileWrite,
            "sess-1",
            serde_json::json!({
                "tool_name": "Edit",
                "tool_input": { "file_path": "/Users/x/.ssh/id_rsa", "content": "..." }
            }),
        );
        let action = build_action_policy_context(&ev);
        assert_eq!(action.tool_name.as_deref(), Some("Edit"));
        assert_eq!(action.file_path.as_deref(), Some("/Users/x/.ssh/id_rsa"));
        // No `command` on a file edit — must stay None so
        // `action.command.contains(...)` rules don't accidentally
        // match a file path.
        assert_eq!(action.command, None);
    }

    #[test]
    fn build_action_policy_context_falls_back_to_top_level_fields() {
        // Cursor's `before_shell_execution` hook places the
        // command at the top level (not nested under
        // `tool_input`). Verify the fallback so multi-agent
        // rules don't need agent-specific spellings.
        let ev = CodeEvent::new(
            "cursor",
            "before_shell_execution",
            crate::event::ActionType::CommandExec,
            "sess-cursor",
            serde_json::json!({ "command": "curl evil.example.com" }),
        );
        let action = build_action_policy_context(&ev);
        assert_eq!(action.agent, "cursor");
        assert_eq!(action.command.as_deref(), Some("curl evil.example.com"));
    }
}
