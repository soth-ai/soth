//! `soth-node` — napi-rs binding for the SOTH SDK.
//!
//! The user-facing TypeScript surface lives in `index.d.ts` + `index.js`;
//! this crate exposes the napi-rs entry points the JS shim wraps.
//!
//! Decision API contract from `SDK_DECISION_API_SPEC.md` §6.3 lives
//! partly here (the FFI boundary returning a typed `Decision` JS object)
//! and partly in the JS shim (`SothBlocked extends Error`).

#![deny(clippy::all)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use napi::bindgen_prelude::*;
use napi_derive::napi;
use soth_sdk_core::{
    BlockReason as CoreBlockReason, Decision as CoreDecision, DecisionToken, FlagSeverity,
    HmacKey, LlmCall, LlmChunk, LlmResponse, Message, SdkConfigBuilder, SothSdk as CoreSothSdk,
    StreamObservation as CoreStreamObservation, Tool,
};
use soth_core::EndpointType;
use zeroize::Zeroizing;

// ── napi-exposed types ────────────────────────────────────────────────

#[napi(object)]
pub struct JsBlockReason {
    pub kind: String,
    pub artifact: Option<String>,
    pub severity: Option<String>,
    pub budget_kind: Option<String>,
    pub observed: Option<u32>,
    pub limit: Option<u32>,
    pub rule_id: Option<String>,
    pub rule_name: Option<String>,
    pub suggested_provider: Option<String>,
    pub suggested_model: Option<String>,
}

#[napi(object)]
pub struct JsDecision {
    /// "allow" | "block" | "redact" | "flag"
    pub kind: String,
    /// `DecisionToken.inner` as a stringified u64 (JS numbers can't
    /// safely hold the full u64 range; we use a string and round-trip
    /// it exactly through the FFI).
    pub token: String,
    pub reason: Option<JsBlockReason>,
    pub redactions: Option<Vec<JsRedaction>>,
    pub severity: Option<String>,
}

#[napi(object)]
pub struct JsRedaction {
    pub message_idx: u32,
    pub redacted_content: String,
}

#[napi(object)]
pub struct JsMessage {
    pub role: String,
    pub content: String,
}

#[napi(object)]
pub struct JsTool {
    pub name: String,
    pub description: Option<String>,
    pub parameters_json: Option<String>,
}

#[napi(object)]
pub struct JsLlmCall {
    pub provider: String,
    pub model: String,
    pub messages: Vec<JsMessage>,
    pub system: Option<String>,
    pub tools: Option<Vec<JsTool>>,
    pub stream: Option<bool>,
}

#[napi(object)]
pub struct JsTelemetryEvent {
    pub provider: String,
    pub model: Option<String>,
    pub endpoint_type: String,
    pub capture_mode: String,
    pub use_case: String,
    pub volatility_class: String,
}

// ── SothSdk wrapper ──────────────────────────────────────────────────

#[napi]
pub struct SothSdk {
    inner: Arc<CoreSothSdk>,
    /// In-flight stream observations indexed by their `DecisionToken`'s
    /// raw u64 (stringified across the FFI boundary). The JS shim's
    /// `guardStream` looks observations up by token rather than holding
    /// a napi class reference, which keeps the FFI boundary scalar-only.
    streams: Arc<Mutex<HashMap<u64, CoreStreamObservation>>>,
}

#[napi]
impl SothSdk {
    /// Construct a new SDK instance. Mirrors `SdkConfigBuilder` for the
    /// minimum-required field set; richer config (capture_mode,
    /// classification_mode, etc.) lands in a follow-up commit.
    #[napi(factory)]
    pub fn create(
        api_key: String,
        org_id: String,
        hmac_key_env: Option<String>,
        hmac_key_static: Option<Buffer>,
        telemetry_endpoint: Option<String>,
    ) -> Result<Self> {
        let hmac_key = match (hmac_key_env, hmac_key_static) {
            (Some(env), None) => HmacKey::FromEnv(env),
            (None, Some(buf)) => HmacKey::Static(Zeroizing::new(buf.as_ref().to_vec())),
            (Some(_), Some(_)) => {
                return Err(Error::new(
                    Status::InvalidArg,
                    "specify either hmac_key_env OR hmac_key_static, not both",
                ));
            }
            (None, None) => {
                return Err(Error::new(
                    Status::InvalidArg,
                    "hmac_key_env or hmac_key_static is required",
                ));
            }
        };

        let mut builder = SdkConfigBuilder::new()
            .api_key(api_key)
            .org_id(org_id)
            .hmac_key(hmac_key);
        if let Some(endpoint) = telemetry_endpoint {
            builder = builder.telemetry_endpoint(endpoint);
        }
        let config = builder
            .build()
            .map_err(|e| Error::new(Status::InvalidArg, format!("{e}")))?;

        let sdk = CoreSothSdk::init(config)
            .map_err(|e| Error::new(Status::GenericFailure, format!("{e}")))?;

        Ok(Self {
            inner: Arc::new(sdk),
            streams: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Synchronous decision path. Returns a typed `JsDecision` that the
    /// JS shim translates into either a token (Allow / Flag) or a
    /// thrown `SothBlocked` (Block / Redact).
    #[napi]
    pub fn pre_call(&self, call: JsLlmCall) -> Result<JsDecision> {
        let llm_call = build_llm_call(call);
        let decision = self.inner.pre_call(&llm_call);
        Ok(decision_to_js(&decision))
    }

    /// Consume a token after the host call completes. Bindings should
    /// call this from a worker thread (napi-rs's threadpool) so the
    /// host event loop doesn't block on classify enrichment.
    #[napi]
    pub fn post_call(&self, token: String, _response: Option<serde_json::Value>) -> Result<()> {
        let inner: u64 = token.parse().map_err(|_| {
            Error::new(Status::InvalidArg, "decision token must be a numeric string")
        })?;
        let token = DecisionToken::from_raw(inner);
        let response = LlmResponse::new(EndpointType::ChatCompletion);
        self.inner.post_call(token, &response);
        Ok(())
    }

    /// Streaming counterpart to `pre_call`. Returns the decision; the
    /// JS shim feeds chunks via `streamChunk(token, ...)` and finalizes
    /// with `streamEnd(token)`. The observation lives inside the SDK
    /// keyed by token, so the FFI boundary stays scalar-only.
    #[napi]
    pub fn stream_begin(&self, call: JsLlmCall) -> Result<JsDecision> {
        let llm_call = build_llm_call(call);
        let (decision, observation) = self.inner.stream_begin(&llm_call);
        let token_raw = decision.token().raw();
        // Sentinel tokens (SLAB_FULL / SENTINEL_FAIL_OPEN) skip slab
        // bookkeeping — there's no observation to stash because pre_call
        // itself didn't allocate one. Phase-1 telemetry records this.
        if !is_sentinel_raw(token_raw) {
            let mut guard = self.streams.lock().map_err(|_| {
                Error::new(Status::GenericFailure, "stream slot lock poisoned")
            })?;
            guard.insert(token_raw, observation);
        }
        Ok(decision_to_js(&decision))
    }

    /// Feed a delta chunk. Returns silently if the token is unknown
    /// (treated as a binding bug — same semantic as the slab's
    /// stale-token handling).
    #[napi]
    pub fn stream_chunk(
        &self,
        token: String,
        sequence: u32,
        delta_content: Option<String>,
        finish_reason: Option<String>,
    ) -> Result<()> {
        let raw: u64 = token.parse().map_err(|_| {
            Error::new(Status::InvalidArg, "stream token must be a numeric string")
        })?;
        let mut guard = self
            .streams
            .lock()
            .map_err(|_| Error::new(Status::GenericFailure, "stream slot lock poisoned"))?;
        let Some(obs) = guard.get_mut(&raw) else {
            return Ok(());
        };
        let mut chunk = LlmChunk::new(sequence);
        chunk.delta_content = delta_content;
        chunk.finish_reason = finish_reason;
        self.inner.stream_chunk(obs, &chunk);
        Ok(())
    }

    /// Finalize the stream. Idempotent — second call is a no-op.
    #[napi]
    pub fn stream_end(&self, token: String) -> Result<()> {
        let raw: u64 = token.parse().map_err(|_| {
            Error::new(Status::InvalidArg, "stream token must be a numeric string")
        })?;
        let mut guard = self
            .streams
            .lock()
            .map_err(|_| Error::new(Status::GenericFailure, "stream slot lock poisoned"))?;
        if let Some(obs) = guard.remove(&raw) {
            drop(guard);
            self.inner.stream_end(obs);
        }
        Ok(())
    }

    /// Stop the background HTTPS telemetry shipper (if configured) and
    /// flush pending events. Customers SHOULD call this at process exit
    /// so the last batch window's events aren't lost. Idempotent.
    #[napi]
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }

    /// Test helper — number of in-flight decisions.
    #[napi]
    pub fn in_flight_decisions(&self) -> u32 {
        self.inner.in_flight_decisions() as u32
    }

    /// Test-only — drain the in-memory telemetry queue.
    #[napi]
    pub fn drain_telemetry_for_test(&self) -> Vec<JsTelemetryEvent> {
        self.inner
            .drain_telemetry_for_test()
            .into_iter()
            .map(|e| JsTelemetryEvent {
                provider: e.provider,
                model: e.model,
                endpoint_type: format!("{:?}", e.endpoint_type),
                capture_mode: format!("{:?}", e.capture_mode),
                use_case: format!("{:?}", e.use_case),
                volatility_class: format!("{:?}", e.volatility_class),
            })
            .collect()
    }
}

// ── helpers ──────────────────────────────────────────────────────────

fn is_sentinel_raw(raw: u64) -> bool {
    raw == DecisionToken::SLAB_FULL.raw() || raw == DecisionToken::SENTINEL_FAIL_OPEN.raw()
}

// ── conversions ──────────────────────────────────────────────────────

fn build_llm_call(call: JsLlmCall) -> LlmCall {
    LlmCall {
        provider: call.provider,
        model: call.model,
        messages: call
            .messages
            .into_iter()
            .map(|m| Message {
                role: m.role,
                content: m.content,
            })
            .collect(),
        system: call.system,
        tools: call
            .tools
            .unwrap_or_default()
            .into_iter()
            .map(|t| Tool {
                name: t.name,
                description: t.description,
                parameters_json: t.parameters_json.unwrap_or_default(),
            })
            .collect(),
        stream: call.stream.unwrap_or(false),
        temperature: None,
        top_p: None,
        max_tokens: None,
        stop_sequences: Vec::new(),
        endpoint_type: EndpointType::ChatCompletion,
    }
}

fn decision_to_js(decision: &CoreDecision) -> JsDecision {
    let token = decision.token().raw().to_string();
    match decision {
        CoreDecision::Allow { .. } => JsDecision {
            kind: "allow".into(),
            token,
            reason: None,
            redactions: None,
            severity: None,
        },
        CoreDecision::Block { reason, .. } => JsDecision {
            kind: "block".into(),
            token,
            reason: Some(block_reason_to_js(reason)),
            redactions: None,
            severity: None,
        },
        CoreDecision::Redact { redactions, .. } => JsDecision {
            kind: "redact".into(),
            token,
            reason: None,
            redactions: Some(
                redactions
                    .replacements
                    .iter()
                    .map(|r| JsRedaction {
                        message_idx: r.message_idx as u32,
                        redacted_content: r.redacted_content.clone(),
                    })
                    .collect(),
            ),
            severity: None,
        },
        CoreDecision::Flag { severity, .. } => JsDecision {
            kind: "flag".into(),
            token,
            reason: None,
            redactions: None,
            severity: Some(flag_severity_label(*severity).to_string()),
        },
        // Decision is #[non_exhaustive] — future variants surface as
        // "unknown" so the JS shim has a deterministic default.
        _ => JsDecision {
            kind: "unknown".into(),
            token,
            reason: None,
            redactions: None,
            severity: None,
        },
    }
}

fn block_reason_to_js(reason: &CoreBlockReason) -> JsBlockReason {
    let mut out = JsBlockReason {
        kind: String::new(),
        artifact: None,
        severity: None,
        budget_kind: None,
        observed: None,
        limit: None,
        rule_id: None,
        rule_name: None,
        suggested_provider: None,
        suggested_model: None,
    };
    match reason {
        CoreBlockReason::SensitiveArtifact { artifact, severity } => {
            out.kind = "sensitive_artifact".into();
            out.artifact = Some(format!("{artifact:?}"));
            out.severity = Some(format!("{severity:?}"));
        }
        CoreBlockReason::BudgetExceeded {
            budget_kind,
            observed,
            limit,
        } => {
            out.kind = "budget_exceeded".into();
            out.budget_kind = Some(format!("{budget_kind:?}"));
            out.observed = Some(*observed as u32);
            out.limit = Some(*limit as u32);
        }
        CoreBlockReason::PolicyRule { rule_id, rule_name } => {
            out.kind = "policy_rule".into();
            out.rule_id = Some(rule_id.clone());
            out.rule_name = rule_name.clone();
        }
        CoreBlockReason::UseAlternative {
            suggested_provider,
            suggested_model,
            rule_id,
        } => {
            out.kind = "use_alternative".into();
            out.suggested_provider = suggested_provider.clone();
            out.suggested_model = suggested_model.clone();
            out.rule_id = Some(rule_id.clone());
        }
        // BlockReason is #[non_exhaustive] — fall back to a generic
        // shape if soth-sdk-core adds a new variant before this binding
        // catches up.
        _ => {
            out.kind = "unknown".into();
        }
    }
    out
}

fn flag_severity_label(severity: FlagSeverity) -> &'static str {
    match severity {
        FlagSeverity::Info => "info",
        FlagSeverity::Warning => "warning",
        FlagSeverity::Critical => "critical",
        // FlagSeverity is #[non_exhaustive] — future variants surface
        // as "unknown" so the JS shim keeps working.
        _ => "unknown",
    }
}
