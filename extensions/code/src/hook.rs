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

    // 1. parse — adapter produces a CodeEvent.  Strip a leading
    //    UTF-8 BOM defensively before handing to the adapter so
    //    every parse path benefits regardless of how stdin was
    //    sourced (the supervisor's stdin pipe, an integration
    //    test passing literal bytes, etc.).  Cursor on Windows
    //    prepends `0xEF 0xBB 0xBF` to JSON stdin — the engineer
    //    found this is the actual root cause of the "every
    //    Cursor hook rejected on Windows" symptom, even though
    //    the install-quoting fix was already in.
    let parse_start = std::time::Instant::now();
    let stripped: Vec<u8>;
    let stdin_bytes: &[u8] = if stdin_bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        stripped = stdin_bytes[3..].to_vec();
        &stripped
    } else {
        stdin_bytes
    };
    let mut code_event = adapter.parse_event(hook_type, stdin_bytes)?;
    let parse_us = elapsed_us(parse_start);

    // 2. detect — scan payload for credential shapes, produce
    //    SensitiveArtifact per match. Same model the proxy uses.
    //    Detection NEVER mutates the payload (matches proxy
    //    semantics): mutation would be a policy decision
    //    (`PolicyDecisionKind::Redact`), not the detector's.
    let detect_start = std::time::Instant::now();
    let tool_name = code_event
        .payload
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut artifacts = crate::detect::scan(&code_event.payload, &tool_name);

    // soth-detect: tree-sitter analysis on classifiable content
    // — returns import categories, language detection, function
    // count, complexity, and additional sensitive artifacts the
    // local regex scanner doesn't catch.  Run only on content
    // the adapter declared classifiable (skips bookkeeping
    // events) so we don't burn AST parsing on session_start /
    // notification noise.
    let mut code_detect_meta: Option<CodeDetectMetadata> = None;
    if let Some(extract) = adapter.classify_input(&code_event) {
        let location = match extract.kind {
            soth_classify::HookContentKind::AssistantTurn => {
                soth_core::ArtifactLocation::AssistantContent {
                    turn: 0,
                    char_offset: 0,
                }
            }
            soth_classify::HookContentKind::ToolResult => {
                soth_core::ArtifactLocation::ToolResult { tool_name: None }
            }
            _ => soth_core::ArtifactLocation::UserContent {
                turn: 0,
                char_offset: 0,
            },
        };
        let result = soth_detect::code::detect_code_artifacts(&extract.content, location);
        artifacts.extend(result.artifacts);
        code_detect_meta = Some(CodeDetectMetadata {
            language: result.detected_language,
            tree_sitter: result.tree_sitter,
        });
    }
    let detect_us = elapsed_us(detect_start);

    // 3. classify — adapter declares which slice of the payload is
    //    classifiable (prompt text, tool args, tool result). When
    //    classify ran, attach the sidecar so the policy evaluator
    //    (step 4) can read `PolicyContext.semantic` and the dashboard
    //    can render anomaly score + use-case label per-action.
    // Try the long-running classify daemon first (`soth start`
    // supervises one alongside historian).  When it's reachable
    // the per-hook ONNX cost is amortized to one Session::new for
    // the daemon's lifetime instead of one per agent action.  A
    // missing/crashed daemon falls through to the in-process
    // fallback bundle — sidecar quality degrades but the gate
    // still runs.
    // Two paths land a sidecar on `code_event.classify`:
    //
    //   1. NL events (user_prompt_submit, stop, AssistantTurn) — the
    //      adapter returns `Some(extract)` with `kind=PromptText` /
    //      `AssistantTurn`, so the full classify pipeline runs and
    //      emits real labels + anomaly + secondary head.
    //   2. Per-tool events (pre/post_tool_use) — the adapter returns
    //      `None` to skip classify entirely (JSON tool args aren't
    //      classifiable; running the pipeline burns a daemon round-
    //      trip for an Unknown).  Instead we synthesize a sidecar
    //      with a tool-name-derived label so the dashboard renders a
    //      meaningful action description per event.
    // Cross-agent gate: tool-shaped action_types skip classify
    // entirely and synthesize a tool-name sidecar instead. This
    // is normalized across all 8 agents (Claude Code, Cursor,
    // Codex, Gemini CLI, Windsurf, OpenCode, Pi Agent, OpenClaw)
    // since each adapter's `parse_event` already maps
    // agent-specific hook types to a canonical `ActionType`.
    // Using action_type means the gate works regardless of
    // whether the hook is named `pre_tool_use` (Claude Code,
    // Codex, Cursor, Pi Agent, OpenClaw), `before_tool_call`
    // (Pi Agent, Gemini), `tool_execute_before` (OpenCode), or
    // `pre_run_command` (Windsurf).
    let is_tool_action = matches!(
        code_event.action_type,
        crate::event::ActionType::FileRead
            | crate::event::ActionType::FileWrite
            | crate::event::ActionType::CommandExec
            | crate::event::ActionType::ToolUse
    );
    let classify_start = std::time::Instant::now();
    if is_tool_action {
        // Route tool events through the daemon too — even though
        // the embedding/MLP path short-circuits for non-NL kinds,
        // stage 5's deterministic anomaly rules
        // (`RapidFireRequests`, `ToolCallDepthSpike`,
        // `ModelSwitch`, `CredentialBurst`, `TokenBurst`,
        // `AgentLoopPattern`) DO run on session state regardless
        // of embedding.  Routing through the daemon updates
        // `request_count_this_hour` / `last_request_timestamp` /
        // `models_used_this_session` / `prior_semantic_hashes` so
        // the *next* event in the session sees the right priors
        // and anomaly fires when it should.
        //
        // Then we override only the use_case_label with the tool
        // name (keeping anomaly_score / anomaly_flags /
        // volatility_class / dynamic_fraction from the daemon's
        // session-aware computation) so the dashboard gets a
        // human-meaningful row.
        let phase = if adapter.is_pre_action_hook(&code_event.hook_type) {
            ToolHookPhase::Pre
        } else {
            ToolHookPhase::Post
        };
        let session_id = if code_event.agent_native_session_id.is_empty() {
            None
        } else {
            Some(code_event.agent_native_session_id.as_str())
        };
        // Use the tool name + tool_input as the daemon's content
        // for hashing only — embedding stage will skip on
        // ToolArgs kind, but the session state still updates.
        let tool_name_str = extract_tool_name(&code_event);
        let tool_input = code_event
            .payload
            .get("tool_input")
            .or_else(|| code_event.payload.get("args"))
            .or_else(|| code_event.payload.get("input"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let content = format!(
            "{tool_name_str}\n{}",
            serde_json::to_string(&tool_input).unwrap_or_default()
        );
        let req = crate::classify_daemon::build_request(
            &code_event.agent,
            provider_for_agent(&code_event.agent),
            code_event.model.as_deref(),
            &content,
            soth_classify::HookContentKind::ToolArgs,
            session_id,
        );
        let mut sidecar = crate::classify_daemon::try_classify(&req)
            .unwrap_or_else(|| synthesize_tool_call_sidecar(&code_event, phase));
        // Override the label/secondary/reason — daemon returns
        // Unknown for ToolArgs (correct, no embedding ran), but
        // we want the tool name visible.  Anomaly /
        // volatility / dynamic_fraction etc. stay as the
        // daemon's session-state-aware values.
        sidecar.use_case_label = tool_name_str;
        sidecar.use_case_secondary_label = Some(format!("{:?}", code_event.action_type));
        sidecar.use_case_label_reason = match phase {
            ToolHookPhase::Pre => "PreToolCall".to_string(),
            ToolHookPhase::Post => "PostToolCall".to_string(),
        };
        code_event.classify = Some(sidecar);
    } else if let Some(extract) = adapter.classify_input(&code_event) {
        let session_id = if code_event.agent_native_session_id.is_empty() {
            None
        } else {
            Some(code_event.agent_native_session_id.as_str())
        };
        let req = crate::classify_daemon::build_request(
            &code_event.agent,
            provider_for_agent(&code_event.agent),
            code_event.model.as_deref(),
            &extract.content,
            extract.kind,
            session_id,
        );
        let sidecar = crate::classify_daemon::try_classify(&req).or_else(|| {
            // Fallback path runs in-process when the daemon is
            // unreachable.  No session snapshot here — hook
            // subprocesses are short-lived and don't share state
            // across calls.  Volatility / anomaly will be zero;
            // that's fine for the rare daemon-down case.
            let identity = ClassifyIdentity::default();
            let input = HookClassifyInput {
                agent_name: &code_event.agent,
                provider: provider_for_agent(&code_event.agent),
                model: code_event.model.as_deref(),
                content: &extract.content,
                kind: extract.kind,
                identity: &identity,
                session_snapshot: None,
                conversation_turn: None,
                has_tool_definitions: false,
                has_tool_results: false,
            };
            let bundle = classify_bundle();
            let config = ClassifyConfig::default();
            let result = soth_classify::classify_for_hook(input, &bundle, &config);
            Some(ClassifySidecar::from(&result))
        });
        code_event.classify = sidecar;
    }
    let classify_us = elapsed_us(classify_start);

    // 4. decide — when an OPA bundle is loaded (via env var
    //    SOTH_CODE_POLICY_BUNDLE or a default path), the bundle's
    //    decision is authoritative: Rego/CEL rules can Block, Allow,
    //    Redact, Reroute, Flag based on classify outputs + artifacts.
    //    When no bundle is loaded, fall through to the artifact-
    //    driven default-deny — silent fail-open is the failure mode
    //    we explicitly avoid, encoded as a security-tool default.
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
    if let Some(meta) = code_detect_meta.as_ref() {
        attach_code_detect_metadata(&mut governable, meta);
    }
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
///
/// Strips a leading UTF-8 BOM (`0xEF 0xBB 0xBF`) before returning.
/// Cursor on Windows (Electron-based child_process.spawn) prepends a
/// BOM to JSON stdin; serde_json doesn't tolerate it and rejects the
/// payload as `expected value at line 1 column 1`.  The latent bug
/// is upstream-wide: most reporters run macOS / Linux Cursor builds
/// where the BOM doesn't appear. Strip defensively
/// here in the common entry point so every adapter benefits, not
/// just Cursor.  Costs nothing when no BOM is present.
pub fn read_stdin_to_end() -> Result<Vec<u8>, io::Error> {
    let mut buf = Vec::with_capacity(8 * 1024);
    io::stdin().read_to_end(&mut buf)?;
    Ok(strip_utf8_bom(buf))
}

fn strip_utf8_bom(buf: Vec<u8>) -> Vec<u8> {
    const BOM: &[u8] = &[0xEF, 0xBB, 0xBF];
    if buf.starts_with(BOM) {
        buf[BOM.len()..].to_vec()
    } else {
        buf
    }
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
        // Source the reason from the sidecar so the dashboard can
        // distinguish (a) `confident` real ONNX classifications,
        // (b) `low_confidence` ONNX classifications (where the
        // secondary label may matter), (c) `fallback_bundle` —
        // bundle missing model assets, KeywordClassifier wired,
        // (d) `not_ai_call` — pipeline short-circuited because
        // input was non-NL, (e) `pre_tool_call` /
        // `post_tool_call` — synthesized by hook.rs for per-tool
        // events without running classify at all.
        metadata.insert(
            "classify.use_case_label_reason".into(),
            format!("\"{}\"", to_snake(&sidecar.use_case_label_reason)),
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
        // Reach feature parity with historian's `ClassifyEnricher`:
        // volatility class + dynamic fraction drive the dashboard's
        // stable-vs-drifting indicator per row, and were the
        // remaining gap between soth-code's metadata and the
        // historian / proxy paths.
        metadata.insert(
            "classify.volatility_class".into(),
            format!("\"{}\"", to_snake(&sidecar.volatility_class)),
        );
        metadata.insert(
            "classify.dynamic_fraction".into(),
            sidecar.dynamic_fraction.to_string(),
        );
        // Secondary label = MLP head's runner-up when the primary
        // is below the ambiguity threshold.  Optional — only
        // written when the classifier emitted one — so
        // `from_governable` can read it through the same JSON
        // string convention as the primary.
        if let Some(secondary) = sidecar.use_case_secondary_label.as_deref() {
            metadata.insert(
                "classify.use_case_secondary_label".into(),
                format!("\"{}\"", to_snake(secondary)),
            );
        }
        if !sidecar.anomaly_flags.is_empty() {
            metadata.insert(
                "classify.anomaly_flags".into(),
                serde_json::to_string(&sidecar.anomaly_flags).unwrap_or_default(),
            );
        }
        // Top-level keys (NOT under `classify.`) — `from_governable`
        // reads these directly off the metadata map.  Mirrors the
        // proxy's flat-key convention so soth-code rows look
        // identical to proxy rows on the wire.
        if !sidecar.semantic_hash.is_empty()
            && sidecar.semantic_hash != "00000000000000000000000000000000"
        {
            metadata.insert("semantic_hash".into(), sidecar.semantic_hash.clone());
        }
        if sidecar.estimated_input_tokens > 0 {
            metadata.insert(
                "estimated_input_tokens".into(),
                sidecar.estimated_input_tokens.to_string(),
            );
        }
        // Top-level (NOT under `classify.`) — `from_governable`
        // reads `interaction_mode` directly off the metadata
        // map and feeds it into `TelemetryEvent.interaction_mode`,
        // which the wire converter already passes through to the
        // cloud's `intercept_events.interaction_mode` column.
        // The classifier emits `augmentative` / `directive` /
        // `expressive` / `unknown` from its second MLP head.
        if !sidecar.interaction_mode.is_empty() && sidecar.interaction_mode != "unknown" {
            metadata.insert(
                "interaction_mode".into(),
                format!("\"{}\"", sidecar.interaction_mode),
            );
        }
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
        // Provider attribution: single-provider agents (claude_code →
        // Anthropic, codex → OpenAI, etc.) map by name. IDE-agnostic
        // agents (cursor / windsurf / opencode) attribute to the IDE
        // itself, not to a backend family inferred from the model
        // string — the IDE *is* the attribution surface (the
        // dashboard already treats it as such).
        // The legacy `"code"` placeholder and the model-sniff fallback
        // both leaked through to the dashboard as misleading tiles.
        provider: resolve_provider(&ev.agent, ev.model.as_deref()).into(),
        model: ev.model.clone(),
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

/// Tree-sitter outputs from `soth_detect::code::detect_code_artifacts`
/// captured at detect time and folded into event metadata at
/// enqueue time so cloud-side `from_governable` can derive
/// `code_fraction` / `network_calls_detected` / `function_count`
/// directly off the event row.
struct CodeDetectMetadata {
    language: Option<String>,
    tree_sitter: Option<soth_detect::code::TreeSitterResult>,
}

/// Surface tree-sitter outputs as flat metadata keys.  Mirrors
/// the proxy's `derive_code_flags` convention so cloud rollups
/// see soth-code rows the same way they see proxy rows.
///
/// Keys written:
///   * `detected_language` — `"rust"`, `"python"`, … (heuristic +
///     tree-sitter confirmation)
///   * `import_categories` — JSON array of categories (`network`,
///     `filesystem`, `crypto`, `auth`, …) for cloud-side
///     `from_governable` to decode into the
///     `network_calls_detected` / `file_io_detected` / etc bool
///     bag.
///   * `function_count` — number of functions in the parsed AST
///   * `complexity_estimate` — rough cyclomatic complexity
///     estimate (0–255 scale).  Drives the dashboard's
///     "complex prompt" badge.
///   * `has_auth_logic` / `has_crypto_operations` /
///     `has_network_calls` / `has_file_io` — duplicated as
///     direct bool keys so the dashboard can render flags
///     without parsing the categories JSON.
fn attach_code_detect_metadata(gov: &mut GovernableEvent, meta: &CodeDetectMetadata) {
    let m = &mut gov.context.metadata;
    if let Some(lang) = meta.language.as_deref() {
        m.insert("detected_language".to_string(), lang.to_string());
    }
    let Some(ts) = meta.tree_sitter.as_ref() else {
        return;
    };
    if let Some(confirmed) = ts.confirmed_language.as_deref() {
        m.insert(
            "tree_sitter.confirmed_language".to_string(),
            confirmed.to_string(),
        );
    }
    if !ts.import_categories.is_empty() {
        let cats: Vec<String> = ts
            .import_categories
            .iter()
            .map(|c| {
                serde_json::to_string(c)
                    .ok()
                    .and_then(|s| serde_json::from_str::<String>(&s).ok())
                    .unwrap_or_else(|| format!("{c:?}").to_lowercase())
            })
            .collect();
        if let Ok(json) = serde_json::to_string(&cats) {
            m.insert("import_categories".to_string(), json);
        }
    }
    m.insert("function_count".to_string(), ts.function_count.to_string());
    m.insert(
        "complexity_estimate".to_string(),
        ts.complexity_estimate.to_string(),
    );
    if ts.has_auth_logic {
        m.insert("has_auth_logic".to_string(), "true".to_string());
    }
    if ts.has_crypto_operations {
        m.insert("has_crypto_operations".to_string(), "true".to_string());
    }
    if ts.has_network_calls {
        m.insert("has_network_calls".to_string(), "true".to_string());
    }
    if ts.has_file_io {
        m.insert("has_file_io".to_string(), "true".to_string());
    }
}

/// Pre vs post tool-call hook phase. Stamped as
/// `UseCaseLabelReason::PreToolCall` / `::PostToolCall` so cloud
/// rollups can split "tool calls issued" from "tool calls
/// completed" without joining on action_seq.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ToolHookPhase {
    Pre,
    Post,
}

/// Pull the tool name from the hook payload, agent-aware.
/// Each agent uses a slightly different field name for the
/// tool ID it's about to call:
///
///   - Claude Code, Codex, Cursor, Pi Agent, OpenClaw,
///     Gemini CLI, Windsurf: `tool_name` (or `command` for
///     Windsurf's `pre_run_command`)
///   - OpenCode: `tool` (sent by the JS plugin)
///
/// Falls back to the canonical `ActionType` rendering when no
/// tool name is on the payload — that way every synthesized
/// row still has a human-meaningful label.
fn extract_tool_name(ev: &CodeEvent) -> String {
    let payload = &ev.payload;
    for key in ["tool_name", "tool", "command", "cmd"] {
        if let Some(name) = payload.get(key).and_then(serde_json::Value::as_str) {
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    // Windsurf's `pre_read_code` / `pre_write_code` carry no
    // tool name field — synthesize from action_type so the
    // dashboard still gets something readable.
    format!("{:?}", ev.action_type)
}

/// Synthesize a `ClassifySidecar` for per-tool hooks.
///
/// `pre_tool_use` / `post_tool_use` payloads are tool args / tool
/// results — JSON, not natural language.  Running the classify
/// pipeline on them costs a daemon round-trip and returns Unknown
/// (`is_ai_call` short-circuits non-NL kinds in
/// `soth-classify/src/hook_entry.rs:157`).  Instead, we synthesize
/// a sidecar locally:
///
///   * `use_case_label`  — the **tool name** itself ("Bash",
///     "Read", "Edit") so the dashboard renders one row per tool
///     call with a deterministic, human-meaningful label.
///   * `use_case_secondary_label` — canonical `ActionType`
///     ("FileRead", "CommandExec", …) for grouping multiple tool
///     names that share an action category.
///   * `use_case_label_reason` — `pre_tool_call` /
///     `post_tool_call` so dashboards / rollups can distinguish
///     synthesized tool rows from real ONNX classifications and
///     filter pre vs post phase explicitly.
///   * Numeric scores zeroed (no embedding ran) — prevents
///     anomaly / complexity rollups from being polluted by
///     non-NL events.
fn synthesize_tool_call_sidecar(ev: &CodeEvent, phase: ToolHookPhase) -> ClassifySidecar {
    let tool_name = extract_tool_name(ev);
    let reason = match phase {
        ToolHookPhase::Pre => "PreToolCall",
        ToolHookPhase::Post => "PostToolCall",
    };
    ClassifySidecar {
        semantic_hash: "00000000000000000000000000000000".to_string(),
        use_case_label: tool_name,
        use_case_confidence: 1.0,
        use_case_secondary_label: Some(format!("{:?}", ev.action_type)),
        use_case_label_reason: reason.to_string(),
        complexity_score: 0,
        anomaly_score: 0.0,
        anomaly_flags: Vec::new(),
        estimated_input_tokens: 0,
        topic_cluster_id: 0,
        stage_total_us: 0,
        volatility_class: "Static".to_string(),
        dynamic_fraction: 0.0,
        interaction_mode: "unknown".to_string(),
    }
}

/// Which LLM provider sits behind each agent. Surfaces in
/// `IdentityContext::declared_provider` so cloud analytics can
/// segment by provider when classify-on-hook is the only signal,
/// and is also the primary input to `resolve_provider` (which
/// `governable_from_code_event` uses to populate the wire-level
/// `provider` field — previously hardcoded to the placeholder
/// `"code"` and surfaced as a synthetic provider tile on the
/// engineering models page).
fn provider_for_agent(agent: &str) -> Option<&'static str> {
    match agent {
        "claude_code" | "openclaw" => Some("anthropic"),
        "codex" => Some("openai"),
        "gemini_cli" => Some("google"),
        "pi_agent" => Some("inflection"),
        // Cursor / Windsurf / OpenCode are multi-provider IDEs — the
        // agent payload doesn't reveal which backend API was hit, and
        // model-string sniffing is unreliable (Cursor lifecycle hooks
        // carry no model, and even when present the model string can
        // be a custom local route that doesn't match any backend
        // family). Attribute to the IDE itself: no provider field at
        // all, only the agent name. The IDE *is* the attribution
        // surface for these tools.
        "cursor" => Some("cursor"),
        "windsurf" => Some("windsurf"),
        "opencode" => Some("opencode"),
        _ => None,
    }
}

/// Lazy-loaded policy bundle. Returns `Some(&'static PolicyBundle)` if
/// a bundle is configured at `SOTH_CODE_POLICY_BUNDLE` or
/// `~/.soth/code-policy.bundle`, otherwise `None`. Cached for the
/// lifetime of the hook process; for ephemeral subprocess invocations
/// this means one load per agent action — acceptable since the bundle
/// loader is small.
/// Resolve and load the operator's CEL policy bundle.
///
/// Resolution order:
///   1. On-disk signed bundle at `bundle_path()` (operator-installed via
///      `soth code policy install-default` or `apply`, or — once the
///      cloud publishes them — automatically synced).
///   2. **Embedded default bundle** baked into the binary at compile
///      time from `extensions/code/policies/code-default-rules.json`.
///
/// The embedded fallback is the key fix for the
/// "fresh-install + code-shaped prompt → silent block" regression:
/// without it, a missing on-disk bundle dropped the hook into the
/// artifact-default-deny path, which blocked on any CodeBlock artifact
/// (any prompt containing `{` `}` plus enough special chars). With the
/// embedded fallback, the hook always evaluates against a real CEL
/// rule set whose default rules only target genuinely risky shapes
/// (`rm -rf`, `dd of=/dev/...`, writes to `~/.ssh/` etc.).
///
/// Production path uses a process-wide `OnceLock` cache so the
/// hook subprocess only pays the bundle-load cost once per
/// invocation (subprocess is short-lived; cache lives a few ms).
/// Test path bypasses the cache: each call re-reads from disk
/// or honors the `SOTH_CODE_POLICY_BUNDLE_DISABLE` opt-out, so
/// tests aren't polluted by the first test's env var "winning
/// forever" through the cache (a real issue surfaced by
/// pre-push review — tests that expected
/// `policy_bundle() -> None` were silently picking up the
/// developer's real `~/.soth/code-policy.bundle` because the
/// OnceLock resolved against it during the first non-isolated
/// test).
fn policy_bundle() -> Option<&'static PolicyBundle> {
    #[cfg(test)]
    {
        // In tests, opt-out via `SOTH_CODE_POLICY_BUNDLE_DISABLE=1`
        // forces None — bypasses both on-disk AND embedded defaults
        // so tests that exercise the no-bundle fallback path
        // (default_deny_from_artifacts) stay deterministic.  No
        // cache — each call re-resolves so per-test env mutations
        // take effect immediately.  The intentional leak
        // (Box::leak) keeps the &'static contract; tests run for
        // milliseconds and tear down the process, so leaked
        // bundles cost nothing.
        if std::env::var("SOTH_CODE_POLICY_BUNDLE_DISABLE")
            .map(|v| !v.is_empty())
            .unwrap_or(false)
        {
            return None;
        }
        if let Some(path) = bundle_path() {
            if path.exists() {
                // Err falls through to embedded bundle below.
                if let Ok(bundle) = soth_policy::load_bundle(&path) {
                    soth_policy::warm(&bundle);
                    return Some(Box::leak(Box::new(bundle)));
                }
            }
        }
        load_embedded_bundle().map(|b| &*Box::leak(Box::new(b)))
    }
    #[cfg(not(test))]
    {
        static CACHE: OnceLock<Option<PolicyBundle>> = OnceLock::new();
        CACHE
            .get_or_init(|| {
                if let Some(path) = bundle_path() {
                    if path.exists() {
                        match soth_policy::load_bundle(&path) {
                            Ok(bundle) => {
                                soth_policy::warm(&bundle);
                                return Some(bundle);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    bundle_path = %path.display(),
                                    error = ?e,
                                    "soth-code: on-disk policy bundle failed to load; \
                                     falling through to embedded default rule pack"
                                );
                            }
                        }
                    }
                }
                load_embedded_bundle()
            })
            .as_ref()
    }
}

/// Compile the embedded default rule pack into a `PolicyBundle`.
///
/// Returns `None` only if the embedded JSON or one of its rules fails
/// to compile — both developer errors caught by `cargo test`. A
/// returned `None` drops the hook into `default_deny_from_artifacts`,
/// which itself only blocks on credential artifacts (so user prompts
/// still flow).
fn load_embedded_bundle() -> Option<PolicyBundle> {
    match crate::policy_defaults::embedded_default_bundle() {
        Ok(bundle) => {
            soth_policy::warm(&bundle);
            Some(bundle)
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "soth-code: embedded default policy bundle failed to build; \
                 hook will use credential-only default-deny — install a real \
                 bundle with `soth code policy install-default`"
            );
            None
        }
    }
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
        provider: provider_for_agent(&ev.agent)
            .unwrap_or("unknown")
            .to_string(),
        user_content_hash: user_content.clone(),
        conversation_hash: user_content,
        ..NormalizedRequest::default()
    }
}

/// Build a `PolicyContext` from a `CodeEvent`. The `semantic` field
/// carries classify outputs so OPA rules can read
/// `input.semantic.use_case_label`, `input.semantic.anomaly_score`,
/// etc.
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
    // for other agents.  Normalize backslash separators to
    // forward slashes so CEL rules using `.ssh/` /
    // `.aws/credentials` match Windows paths
    // (`C:\Users\Prabhat ACER\.ssh\id_rsa`) too — without
    // normalization the install-time-equivalent rules would
    // silently no-op on Windows and the policy gate would fail
    // open for credential-write attempts.  Forward slashes work
    // as path separators on Windows for nearly every API
    // soth-code interacts with, so the canonicalized form is
    // also functionally valid.
    let file_path = payload
        .get("tool_input")
        .and_then(|t| t.get("file_path"))
        .and_then(|v| v.as_str())
        .or_else(|| payload.get("file_path").and_then(|v| v.as_str()))
        .or_else(|| payload.get("path").and_then(|v| v.as_str()))
        .map(|s| s.replace('\\', "/"));
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

/// Fallback decision when no policy bundle is loaded — reached only
/// when *both* the on-disk signed bundle and the embedded default
/// bundle are unavailable (the embedded path failing means the binary
/// was built with a malformed `code-default-rules.json`, caught by
/// `cargo test`), or when a test explicitly forces this path via
/// `SOTH_CODE_POLICY_BUNDLE_DISABLE=1`.
///
/// **Never blocks.** The code extension's default posture is
/// observational: artifacts (credentials, code blocks, …) are still
/// recorded in the audit queue, but the agent action proceeds. Only
/// CEL rules from a loaded policy bundle can produce a Block decision.
/// This matches the "notify, don't gate" stance an operator expects
/// from a fresh install — Block on a paste-in is a worse UX than a
/// missed flag, and the audit trail still surfaces the artifact for
/// post-hoc review or alerting.
///
/// When credential artifacts are present we emit a Flag decision (the
/// dashboard renders these distinctly from a clean Allow) so an
/// operator scanning `soth code tail` still sees the credential
/// detection, just without the agent-side enforcement.
fn default_deny_from_artifacts(artifacts: &[SensitiveArtifact]) -> (HookDecision, PolicyDecision) {
    let credential_kinds: Vec<String> = artifacts
        .iter()
        .filter_map(|a| a.credential_kind.clone())
        .collect();
    let policy_kind = if credential_kinds.is_empty() {
        PolicyDecisionKind::Allow
    } else {
        PolicyDecisionKind::Flag {
            reason: format!("credentials detected ({})", credential_kinds.join(", ")),
        }
    };
    (
        HookDecision::Allow,
        PolicyDecision {
            kind: policy_kind,
            matched_rule: None,
            warnings: Vec::new(),
            eval_latency_us: 0,
        },
    )
}

/// Lazy-loaded classify bundle.  Tries the real ONNX-backed
/// bundle at `~/.soth/bundle/` (same directory the proxy loads
/// from — the bundle delivery system already keeps it
/// up-to-date via `soth-sync`).  Falls through to the
/// keyword-only `fallback_bundle()` only when the real bundle
/// is missing or fails to load.
///
/// Per-subprocess cost: ONNX session initialization is the
/// dominant term (~50-150ms cold, ~10-30ms warm via OS page
/// cache).  We accept that cost over `fallback_bundle()`'s
/// "every event labels Unknown" outcome, which made the /code
/// dashboard's classify columns useless in practice.
/// Bookkeeping hooks (Stop, Notification, SessionStart) bypass
/// classify entirely via `Adapter::classify_input` returning
/// `None`, so the cost only lands on events that actually need
/// classification.
///
/// Override path via `SOTH_CLASSIFY_BUNDLE_DIR` for tests or
/// non-default installs.
fn classify_bundle() -> Arc<ClassifyBundle> {
    static CACHE: OnceLock<Arc<ClassifyBundle>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            let dir = classify_bundle_dir();
            if let Some(path) = dir.as_ref() {
                if path.exists() {
                    match soth_classify::load_bundle(path) {
                        Ok(b) => {
                            tracing::debug!(
                                bundle_dir = %path.display(),
                                "soth-code: loaded real classify bundle"
                            );
                            return b;
                        }
                        Err(e) => {
                            tracing::warn!(
                                bundle_dir = %path.display(),
                                error = ?e,
                                "soth-code: classify bundle load failed; falling through to keyword fallback"
                            );
                        }
                    }
                }
            }
            tracing::warn!(
                "soth-code: no classify bundle on disk at ~/.soth/bundle/; \
                 use_case_label and anomaly_score will be Unknown.  Run \
                 `soth up` to fetch the bundle from the cloud."
            );
            soth_classify::fallback_bundle()
        })
        .clone()
}

fn classify_bundle_dir() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SOTH_CLASSIFY_BUNDLE_DIR") {
        return Some(PathBuf::from(p));
    }
    dirs::home_dir().map(|h| h.join(".soth").join("bundle"))
}

/// Resolve the provider for a code event. Prefers the adapter-based
/// answer; only sniffs the model id when the agent supports multiple
/// providers (or is unknown). Replaces the legacy `"code"` placeholder
/// that was leaking into the dashboard's `provider` column.
fn resolve_provider(agent: &str, model: Option<&str>) -> &'static str {
    if let Some(p) = provider_for_agent(agent) {
        return p;
    }
    infer_provider_from_model(model.unwrap_or(""))
}

/// Best-effort model → provider mapping. Only used as a fallback for
/// multi-provider IDEs whose `provider_for_agent` returns `None`.
///
/// Returns `"unknown"` for empty or unrecognized model strings rather
/// than the historical `"code"` placeholder — unmapped models surface
/// as a single auditable "unknown" bucket on the engineering models
/// page instead of inflating a fake provider tile.
fn infer_provider_from_model(model: &str) -> &'static str {
    let m = model.trim().to_ascii_lowercase();
    if m.is_empty() {
        return "unknown";
    }
    if m.starts_with("claude") {
        return "anthropic";
    }
    if m.starts_with("gpt")
        || m.starts_with("o1")
        || m.starts_with("o3")
        || m.starts_with("o4")
        || m.starts_with("text-davinci")
        || m.starts_with("chatgpt")
    {
        return "openai";
    }
    if m.starts_with("gemini") {
        return "google";
    }
    if m.starts_with("deepseek") {
        return "deepseek";
    }
    if m.starts_with("qwen") {
        return "qwen";
    }
    if m.starts_with("grok") {
        return "xai";
    }
    if m.starts_with("llama") || m.starts_with("meta-llama") {
        return "meta";
    }
    if m.starts_with("mistral") || m.starts_with("mixtral") || m.starts_with("magistral") {
        return "mistral";
    }
    if m.starts_with("command") {
        return "cohere";
    }
    "unknown"
}

fn data_source_for_agent(agent: &str) -> &'static str {
    // Snake_case wire form for the eight Code{Agent} DataSource variants.
    // Unknown agents (mistyped --agent flags, stub adapters, manual
    // experiments) map to `code_unknown` so the event lands on the
    // Action layer and surfaces as an audit-worthy "unknown" bucket.
    // The earlier smoke-friendly fallback to `code_claude_code` silently
    // mis-attributed unknown-agent events to Claude Code on the
    // dashboard, which is worse than visibly bucketing them out.
    match agent {
        "claude_code" => "code_claude_code",
        "cursor" => "code_cursor",
        "codex" => "code_codex",
        "gemini_cli" => "code_gemini_cli",
        "windsurf" => "code_windsurf",
        "opencode" => "code_open_code",
        "pi_agent" => "code_pi_agent",
        _ => "code_unknown",
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
/// tool response (observed in production at megabyte sizes) doesn't
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
        .map_err(std::io::Error::other)?;
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
    let mut line =
        serde_json::to_string(&record).map_err(|e| HookError::Queue(format!("serialize: {e}")))?;
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
    use std::sync::Mutex;

    /// Process-global lock for tests that mutate `SOTH_CODE_POLICY_BUNDLE_DISABLE`
    /// or `SOTH_CODE_POLICY_BUNDLE`. Cargo runs tests in parallel by default,
    /// so two tests poking the same env var will race — one setting `1` while
    /// another expects `unset` flips the embedded-bundle fallback off and
    /// silently breaks the second test's assertions. Acquire this lock for
    /// the entire body of any test that touches those vars.
    static POLICY_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn infer_provider_recognizes_known_prefixes() {
        assert_eq!(infer_provider_from_model("claude-opus-4-7"), "anthropic");
        assert_eq!(
            infer_provider_from_model("claude-sonnet-4-5-20251022"),
            "anthropic",
        );
        assert_eq!(infer_provider_from_model("gpt-4o-mini"), "openai");
        assert_eq!(infer_provider_from_model("gpt-5"), "openai");
        assert_eq!(infer_provider_from_model("o1-preview"), "openai");
        assert_eq!(infer_provider_from_model("o3-mini"), "openai");
        assert_eq!(infer_provider_from_model("chatgpt-4o-latest"), "openai");
        assert_eq!(infer_provider_from_model("gemini-1.5-pro"), "google");
        assert_eq!(infer_provider_from_model("deepseek-v3"), "deepseek");
        assert_eq!(infer_provider_from_model("qwen2.5-coder"), "qwen");
        assert_eq!(infer_provider_from_model("grok-2"), "xai");
        assert_eq!(infer_provider_from_model("llama-3.3-70b"), "meta");
        assert_eq!(infer_provider_from_model("mistral-large"), "mistral");
        assert_eq!(infer_provider_from_model("command-r-plus"), "cohere");
    }

    #[test]
    fn infer_provider_handles_casing_and_whitespace() {
        assert_eq!(infer_provider_from_model("  Claude-3 "), "anthropic");
        assert_eq!(infer_provider_from_model("GPT-4O"), "openai");
        assert_eq!(infer_provider_from_model("Gemini-2.0-Flash"), "google");
    }

    #[test]
    fn provider_for_agent_returns_fixed_provider_for_single_provider_agents() {
        assert_eq!(provider_for_agent("claude_code"), Some("anthropic"));
        assert_eq!(provider_for_agent("openclaw"), Some("anthropic"));
        assert_eq!(provider_for_agent("codex"), Some("openai"));
        assert_eq!(provider_for_agent("gemini_cli"), Some("google"));
        assert_eq!(provider_for_agent("pi_agent"), Some("inflection"));
    }

    #[test]
    fn provider_for_ide_agnostic_agents_is_the_ide_name() {
        // Cursor / Windsurf / Opencode let the user pick a model from
        // any provider, but the IDE *is* the attribution surface — the
        // model string is unreliable (lifecycle hooks carry no model;
        // custom routes don't match families) and the event data
        // model has no provider field at all. Attribute to the IDE
        // itself so the dashboard shows "cursor" instead of
        // model-string-inferred "anthropic" or the literal "unknown".
        assert_eq!(provider_for_agent("cursor"), Some("cursor"));
        assert_eq!(provider_for_agent("windsurf"), Some("windsurf"));
        assert_eq!(provider_for_agent("opencode"), Some("opencode"));
        // Truly unknown agents still return None so the legacy
        // model-sniff path remains the last resort.
        assert_eq!(provider_for_agent("unknown_agent"), None);
        assert_eq!(provider_for_agent(""), None);
    }

    #[test]
    fn resolve_provider_prefers_agent_over_model() {
        // Even if the model string would map to a different provider,
        // the adapter's known provider wins. (Claude Code only ever
        // talks to Anthropic, so a stray "gpt-4" in the model field
        // is either a bug or test data — should still attribute to
        // Anthropic, not OpenAI.)
        assert_eq!(resolve_provider("claude_code", Some("gpt-4o")), "anthropic");
        assert_eq!(resolve_provider("codex", Some("claude-3")), "openai");
    }

    #[test]
    fn resolve_provider_attributes_ide_agnostic_to_ide_not_model() {
        // Regression guard for the "cursor sending events with
        // anthropic" symptom: with a claude model picked inside
        // Cursor, the IDE attribution should still surface as
        // "cursor" so operators can distinguish IDE traffic from
        // direct-API traffic on the dashboard.
        assert_eq!(
            resolve_provider("cursor", Some("claude-opus-4-7")),
            "cursor"
        );
        assert_eq!(resolve_provider("windsurf", Some("gpt-4o")), "windsurf");
        assert_eq!(
            resolve_provider("opencode", Some("gemini-1.5-pro")),
            "opencode"
        );
        // Lifecycle hooks (no model) used to land on "unknown" —
        // now they correctly attribute to the IDE.
        assert_eq!(resolve_provider("cursor", None), "cursor");
        assert_eq!(resolve_provider("windsurf", None), "windsurf");
    }

    #[test]
    fn resolve_provider_returns_unknown_only_for_truly_unrecognized() {
        // Brand-new agents not yet in `provider_for_agent` + an
        // unmapped model string genuinely have nothing to attribute to.
        assert_eq!(
            resolve_provider("brand_new_agent", Some("future-model-x")),
            "unknown"
        );
        assert_eq!(resolve_provider("brand_new_agent", None), "unknown");
        // Never falls back to the legacy "code" placeholder.
        assert_ne!(resolve_provider("brand_new_agent", None), "code");
    }

    #[test]
    fn infer_provider_falls_back_to_unknown_for_unmapped_and_empty() {
        // Empty model string (rare but possible on extract_model
        // miss) must not surface as the legacy "code" placeholder.
        assert_eq!(infer_provider_from_model(""), "unknown");
        assert_eq!(infer_provider_from_model("   "), "unknown");
        // Models we don't recognize get bucketed under unknown rather
        // than guessed — wrong attribution is worse than no attribution
        // on the engineering models page.
        assert_eq!(infer_provider_from_model("some-future-model-x"), "unknown");
    }

    #[test]
    fn data_source_for_agent_maps_known_adapters() {
        // Pin the wire form per adapter so the dashboard's
        // `data_source` filtering stays stable when new adapters land.
        assert_eq!(data_source_for_agent("claude_code"), "code_claude_code");
        assert_eq!(data_source_for_agent("cursor"), "code_cursor");
        assert_eq!(data_source_for_agent("codex"), "code_codex");
        assert_eq!(data_source_for_agent("gemini_cli"), "code_gemini_cli");
        assert_eq!(data_source_for_agent("windsurf"), "code_windsurf");
        assert_eq!(data_source_for_agent("opencode"), "code_open_code");
        assert_eq!(data_source_for_agent("pi_agent"), "code_pi_agent");
    }

    #[test]
    fn data_source_for_agent_falls_back_to_code_unknown_not_claude_code() {
        // Regression guard: the historical fallback was
        // `code_claude_code`, which silently mis-attributed every
        // unrecognized agent's events to Claude Code on the
        // dashboard. Unknown agents must land in the dedicated
        // `code_unknown` bucket so operators can audit them.
        assert_eq!(data_source_for_agent(""), "code_unknown");
        assert_eq!(data_source_for_agent("mistyped_agent"), "code_unknown");
        assert_eq!(data_source_for_agent("CursorAdapter"), "code_unknown");
    }

    #[test]
    fn pre_tool_use_synthesizes_label_from_tool_name() {
        // Pin the user-facing contract: per-tool events get the
        // tool name as primary label, the canonical action_type
        // as secondary, and a reason of `pre_tool_call` —
        // distinguishing synthesized rows from real ONNX
        // classifications and pre-phase from post-phase.
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());

        let outcome = run_hook(
            "claude_code",
            "pre_tool_use",
            br#"{"session_id":"s","tool_name":"Bash","tool_input":{"command":"rg foo"}}"#,
            &paths,
            &HookCaptureConfig::default(),
        )
        .expect("hook runs");

        assert!(matches!(outcome.decision, HookDecision::Allow));
        let queue = fs::read_to_string(&paths.queue).unwrap();
        let row: serde_json::Value = serde_json::from_str(queue.lines().next().unwrap()).unwrap();
        let md = &row["event"]["context"]["metadata"];
        assert_eq!(md["classify.use_case"], "\"bash\"");
        assert_eq!(md["classify.use_case_label_reason"], "\"pre_tool_call\"");
    }

    #[test]
    fn post_tool_use_synthesizes_label_with_result_phase() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());

        let _ = run_hook(
            "claude_code",
            "post_tool_use",
            br#"{"session_id":"s","tool_name":"Read","tool_response":{"content":"ok"}}"#,
            &paths,
            &HookCaptureConfig::default(),
        )
        .unwrap();

        let queue = fs::read_to_string(&paths.queue).unwrap();
        let row: serde_json::Value = serde_json::from_str(queue.lines().next().unwrap()).unwrap();
        let md = &row["event"]["context"]["metadata"];
        assert_eq!(md["classify.use_case"], "\"read\"");
        assert_eq!(md["classify.use_case_label_reason"], "\"post_tool_call\"");
    }

    #[test]
    fn cross_agent_tool_action_synthesizes_label_for_every_adapter() {
        // The synthesis gate is `action_type` (FileRead /
        // FileWrite / CommandExec / ToolUse), not hook-type
        // strings — so it works across all 8 agents whose hook
        // taxonomies use different names (claude_code uses
        // pre_tool_use; opencode uses tool_execute_before;
        // gemini uses before_tool_call; windsurf uses
        // pre_run_command; etc.).  Pin: every agent's
        // tool-shape hook produces a synthesized sidecar with
        // a non-Unknown label.
        struct Case {
            agent: &'static str,
            hook_type: &'static str,
            payload: &'static [u8],
            expected_label_contains: &'static str,
        }
        let cases = [
            Case {
                agent: "claude_code",
                hook_type: "pre_tool_use",
                payload: br#"{"session_id":"s","tool_name":"Bash","tool_input":{"command":"ls"}}"#,
                expected_label_contains: "bash",
            },
            Case {
                agent: "cursor",
                hook_type: "before_shell_execution",
                payload: br#"{"conversation_id":"c","command":"ls"}"#,
                expected_label_contains: "ls",
            },
            Case {
                agent: "codex",
                hook_type: "pre_tool_use",
                payload: br#"{"session_id":"s","tool_name":"shell","tool_input":{"command":"ls"}}"#,
                expected_label_contains: "shell",
            },
            Case {
                agent: "gemini_cli",
                hook_type: "before_tool_call",
                payload: br#"{"session_id":"s","tool_name":"shell","tool_input":{"command":"ls"}}"#,
                expected_label_contains: "shell",
            },
            Case {
                agent: "opencode",
                hook_type: "tool_execute_before",
                payload: br#"{"session_id":"s","tool":"bash","args":{"command":"ls"}}"#,
                expected_label_contains: "bash",
            },
            Case {
                agent: "pi_agent",
                hook_type: "pre_tool_use",
                payload: br#"{"session_id":"s","tool_name":"shell","input":{"command":"ls"}}"#,
                expected_label_contains: "shell",
            },
            Case {
                agent: "openclaw",
                hook_type: "pre_tool_use",
                payload: br#"{"session_id":"s","tool_name":"bash","tool_input":{"command":"ls"}}"#,
                expected_label_contains: "bash",
            },
        ];
        for case in cases {
            let tmp = tempfile::tempdir().unwrap();
            let paths = CodePaths::from_root(tmp.path());
            run_hook(
                case.agent,
                case.hook_type,
                case.payload,
                &paths,
                &HookCaptureConfig::default(),
            )
            .unwrap_or_else(|e| panic!("agent={} hook err: {e:#}", case.agent));
            let queue = fs::read_to_string(&paths.queue).unwrap();
            let row: serde_json::Value =
                serde_json::from_str(queue.lines().next().unwrap()).unwrap();
            let md = &row["event"]["context"]["metadata"];
            let label = md
                .get("classify.use_case")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            assert!(
                label.contains(case.expected_label_contains),
                "agent={} hook_type={}: expected label to contain '{}', got '{}'",
                case.agent,
                case.hook_type,
                case.expected_label_contains,
                label
            );
            let reason = md
                .get("classify.use_case_label_reason")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            assert!(
                reason.contains("tool_call"),
                "agent={} should report a tool_call reason, got '{}'",
                case.agent,
                reason
            );
        }
    }

    #[test]
    fn run_hook_strips_utf8_bom_from_cursor_stdin() {
        // Cursor on Windows (Electron child_process.spawn) prepends
        // a UTF-8 BOM (0xEF 0xBB 0xBF) to JSON stdin — serde_json
        // doesn't tolerate it and the parse step fails with
        // `expected value at line 1 column 1`.  Engineer's
        // discovery: this is THE root cause of "every Cursor hook
        // rejected on Windows", masked by the earlier install-
        // quoting fix.  Pin the strip so a future refactor can't
        // regress it for any agent's parse path.
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());

        let bom_payload: Vec<u8> = b"\xEF\xBB\xBF{\"conversation_id\":\"c1\",\"hook_event_name\":\"beforeSubmitPrompt\",\"prompt\":\"refactor auth\"}"
            .to_vec();

        let outcome = run_hook(
            "cursor",
            "before_submit_prompt",
            &bom_payload,
            &paths,
            &HookCaptureConfig::default(),
        )
        .expect("BOM-prefixed stdin must parse");
        assert!(matches!(outcome.decision, HookDecision::Allow));
    }

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
        let outcome = run_hook(
            "claude_code",
            "pre_tool_use",
            b"",
            &paths,
            &HookCaptureConfig::default(),
        )
        .expect("ok");
        assert!(matches!(outcome.decision, HookDecision::Allow));
        let queue = fs::read_to_string(&paths.queue).unwrap();
        assert_eq!(queue.lines().count(), 1);
    }

    #[test]
    fn unknown_agent_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());
        let r = run_hook(
            "",
            "pre_tool_use",
            b"{}",
            &paths,
            &HookCaptureConfig::default(),
        );
        assert!(matches!(r, Err(HookError::UnknownAgent(_))));
    }

    #[test]
    fn malformed_stdin_returns_parse_error() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());
        let r = run_hook(
            "claude_code",
            "pre_tool_use",
            b"{ not json",
            &paths,
            &HookCaptureConfig::default(),
        );
        assert!(matches!(r, Err(HookError::Parse(_))));
    }

    #[test]
    fn second_invocation_appends_not_truncates() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());
        for _ in 0..3 {
            run_hook(
                "claude_code",
                "pre_tool_use",
                b"{}",
                &paths,
                &HookCaptureConfig::default(),
            )
            .unwrap();
        }
        let queue = fs::read_to_string(&paths.queue).unwrap();
        assert_eq!(queue.lines().count(), 3);
    }

    #[test]
    fn default_deny_flags_but_does_not_block_on_credentials() {
        // Code-extension stance: the fallback path is observational.
        // A credential artifact produces a Flag (visible in `soth code
        // tail` and the dashboard) but the action proceeds. Blocking
        // only happens via explicit CEL rules from a loaded policy
        // bundle (embedded default or operator-installed).
        let arts = vec![SensitiveArtifact {
            kind: soth_core::ArtifactKind::AwsAccessKey,
            credential_kind: Some("aws_access_key".to_string()),
            severity: soth_core::ArtifactSeverity::Critical,
            location: soth_core::ArtifactLocation::Unknown,
            commitment: None,
            redacted_hint: None,
        }];
        let (decision, policy) = default_deny_from_artifacts(&arts);
        assert!(matches!(decision, HookDecision::Allow));
        match policy.kind {
            PolicyDecisionKind::Flag { ref reason } => {
                assert!(reason.contains("aws_access_key"), "got: {reason}");
            }
            other => panic!("expected Flag, got {other:?}"),
        }
    }

    #[test]
    fn default_deny_allows_when_no_artifacts() {
        let (decision, policy) = default_deny_from_artifacts(&[]);
        assert!(matches!(decision, HookDecision::Allow));
        assert!(matches!(policy.kind, PolicyDecisionKind::Allow));
    }

    #[test]
    fn default_deny_allows_when_only_code_block_artifacts() {
        // The original Windows regression: a CodeBlock artifact (emitted
        // by soth-detect when the payload looks code-shaped) used to
        // trigger a silent Block via the default-deny path. The fix
        // requires Allow.
        let arts = vec![SensitiveArtifact {
            kind: soth_core::ArtifactKind::CodeBlock {
                language: "unknown".to_string(),
            },
            credential_kind: None,
            severity: soth_core::ArtifactSeverity::Low,
            location: soth_core::ArtifactLocation::Unknown,
            commitment: None,
            redacted_hint: None,
        }];
        let (decision, policy) = default_deny_from_artifacts(&arts);
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
            kind: PolicyDecisionKind::Redact {
                targets: Vec::new(),
            },
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
        // IDE-agnostic — attribute to the IDE itself, not to a backend
        // family inferred from the model string.
        assert_eq!(provider_for_agent("cursor"), Some("cursor"));
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
            use_case_secondary_label: None,
            use_case_label_reason: "Confident".into(),
            complexity_score: 3,
            anomaly_score: 0.7,
            anomaly_flags: vec![],
            estimated_input_tokens: 10,
            topic_cluster_id: 42,
            stage_total_us: 100,
            volatility_class: "Static".into(),
            dynamic_fraction: 0.0,
            interaction_mode: "unknown".into(),
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
        let outcome = run_hook(
            "claude_code",
            "stop",
            stdin,
            &paths,
            &HookCaptureConfig::default(),
        )
        .unwrap();
        assert!(
            matches!(outcome.decision, HookDecision::Allow),
            "Stop hook with credentials in payload must downgrade to Allow, got {:?}",
            outcome.decision
        );

        // The artifact is still recorded in the queue for audit —
        // operator can see *what* leaked, just doesn't get Block on
        // the wrong hook type.
        let queue = std::fs::read_to_string(&paths.queue).unwrap();
        let row: serde_json::Value = serde_json::from_str(queue.lines().next().unwrap()).unwrap();
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
        run_hook(
            "claude_code",
            "pre_tool_use",
            stdin,
            &paths,
            &HookCaptureConfig::default(),
        )
        .unwrap();

        // Read the queue row back, deserialize the GovernableEvent,
        // and convert to TelemetryEvent the same way the batcher does.
        let queue = std::fs::read_to_string(&paths.queue).unwrap();
        let row: serde_json::Value = serde_json::from_str(queue.lines().next().unwrap()).unwrap();
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
        // pre_tool_use is now synthesized (no classify runs), so
        // the reason is `pre_tool_call` — pinning the new
        // contract.  Real classify runs only on prompt/turn
        // events; per-tool rows get the deterministic synthesized
        // tag so cloud rollups can split them out.
        assert_eq!(
            telem.use_case_label_reason,
            soth_core::UseCaseLabelReason::PreToolCall,
            "pre_tool_use should report PreToolCall reason now that hook.rs synthesizes the sidecar"
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
            std::fs::read_to_string(&paths.queue)
                .unwrap()
                .lines()
                .next()
                .unwrap(),
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
            std::fs::read_to_string(&paths.queue)
                .unwrap()
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        let meta = &row["event"]["context"]["metadata"];
        assert!(meta["raw_payload"].as_str().unwrap().contains("/etc/hosts"));
        assert_eq!(meta["raw_capture"], "full");
    }

    #[test]
    fn capture_audit_persists_only_for_block_decisions() {
        // Exercises the Audit capture mode's contract: raw_payload is
        // attached *only* when the policy decision was Block. Uses the
        // embedded default rule pack's `code_block_destructive_rm_rf`
        // rule (active by default without any on-disk bundle) to
        // produce a deterministic Block — credentials alone no longer
        // block under the code extension's notify-don't-gate stance,
        // so we trigger the block via an explicit CEL rule match.
        let _guard = POLICY_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("SOTH_CODE_POLICY_BUNDLE_DISABLE");
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

        // Block event — `rm -rf` matches the embedded default rule
        // `code_block_destructive_rm_rf` (block action).
        let block_stdin =
            br#"{"session_id":"audit","tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x"}}"#;
        run_hook("claude_code", "pre_tool_use", block_stdin, &paths, &cap).unwrap();

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
            "Audit MUST capture on Block (rm -rf rule)"
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
            std::fs::read_to_string(&paths.queue)
                .unwrap()
                .lines()
                .next()
                .unwrap(),
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
    fn pre_tool_use_with_credentials_does_not_block_by_default() {
        // Contract for the code extension's default stance: credential
        // detection alone never produces a Block. The artifact is
        // recorded (audit trail) and surfaced as a Flag, but the
        // agent's action proceeds. Operators who *do* want to block on
        // credentials install an explicit CEL rule via
        // `soth code policy apply` — the embedded default pack ships
        // with notify-only behavior for credentials.
        let _guard = POLICY_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("SOTH_CODE_POLICY_BUNDLE_DISABLE", "1");
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());
        let stdin = br#"{
            "session_id": "sess-creds-allow",
            "tool_name": "Bash",
            "tool_input": { "command": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE aws s3 ls" }
        }"#;
        let outcome = run_hook(
            "claude_code",
            "pre_tool_use",
            stdin,
            &paths,
            &HookCaptureConfig::default(),
        )
        .unwrap();
        assert!(
            matches!(outcome.decision, HookDecision::Allow),
            "PreToolUse with AWS key must Allow under default-deny fallback, got {:?}",
            outcome.decision
        );
        // The artifact must still land in the queue — audit trail
        // matters even when enforcement doesn't.
        let row: serde_json::Value = serde_json::from_str(
            std::fs::read_to_string(&paths.queue)
                .unwrap()
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        let artifacts = row["event"]["artifacts"]
            .as_array()
            .expect("artifacts array");
        assert!(
            !artifacts.is_empty(),
            "credential artifact must be recorded even though decision is Allow"
        );
    }

    #[test]
    fn pre_tool_use_blocks_when_embedded_rule_matches() {
        // Counterpart to the credential test above: the embedded
        // default rule pack DOES block on explicit destructive
        // patterns (rm -rf, dd of=/dev/, …). Verifies the
        // embedded-bundle fallback wires through to enforcement when a
        // CEL rule matches.
        let _guard = POLICY_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("SOTH_CODE_POLICY_BUNDLE_DISABLE");
        let tmp = tempfile::tempdir().unwrap();
        let paths = CodePaths::from_root(tmp.path());
        let stdin = br#"{
            "session_id": "sess-rmrf-block",
            "tool_name": "Bash",
            "tool_input": { "command": "rm -rf /tmp/anything" }
        }"#;
        let outcome = run_hook(
            "claude_code",
            "pre_tool_use",
            stdin,
            &paths,
            &HookCaptureConfig::default(),
        )
        .unwrap();
        assert!(
            matches!(outcome.decision, HookDecision::Block { .. }),
            "embedded `rm -rf` rule must produce a Block, got {:?}",
            outcome.decision
        );
    }

    #[test]
    fn bundle_path_respects_env_override() {
        // Test that the env var override shape is right. We can't
        // exercise policy_bundle() directly without polluting the
        // OnceLock for other tests, but the path resolution function
        // is testable in isolation.
        let _guard = POLICY_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    fn build_action_policy_context_normalizes_windows_backslash_paths() {
        // Windows paths use backslashes
        // (`C:\Users\Prabhat ACER\.ssh\id_rsa`) but org policy
        // rules are authored with forward-slash patterns
        // (`.ssh/`, `.aws/credentials`) since most engineers
        // write rules on macOS / Linux first.  Without
        // normalization at the policy-context build step, the
        // CEL `action.file_path.contains(".ssh/")` rule never
        // matches on Windows and the policy gate fails open for
        // credential-write attempts.  Pin the normalization so
        // the same rule pack works on all 3 platforms.
        let ev = CodeEvent::new(
            "cursor",
            "pre_write_file",
            crate::event::ActionType::FileWrite,
            "sess-win",
            serde_json::json!({
                "tool_input": {
                    "file_path": r"C:\Users\Prabhat ACER\.ssh\id_rsa",
                    "content": "fake-key"
                }
            }),
        );
        let action = build_action_policy_context(&ev);
        assert_eq!(
            action.file_path.as_deref(),
            Some("C:/Users/Prabhat ACER/.ssh/id_rsa"),
            "Windows backslash paths must normalize to forward slashes \
             so `action.file_path.contains(\".ssh/\")` rules match"
        );
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
