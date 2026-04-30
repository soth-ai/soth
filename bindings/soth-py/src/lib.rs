//! `soth-py` — PyO3 binding for the SOTH SDK.
//!
//! The Rust-level extension exposes a small surface; the user-facing
//! Python API lives in `python/soth/__init__.py`, which wraps this
//! extension with native Python helpers (`SothBlocked` exception,
//! context manager, auto-instrumentation).
//!
//! Decision API contract from `SDK_DECISION_API_SPEC.md` §6 lives
//! partly here (the FFI boundary) and partly in `python/soth/exceptions.py`
//! (the `SothBlocked` exception + propagation tests).

use std::sync::Arc;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use soth_sdk_core::{
    BlockReason as CoreBlockReason, Decision as CoreDecision, DecisionToken, FlagSeverity,
    HmacKey, LlmCall, LlmResponse, Message, SdkConfigBuilder, SothSdk as CoreSothSdk, Tool,
};
use soth_core::EndpointType;
use zeroize::Zeroizing;

/// PyO3 wrapper around `SothSdk`. Stored as `Arc<SothSdk>` so it can be
/// freely cloned across Python's threaded callers — the underlying
/// SothSdk is `Send + Sync` (compile-time asserted in soth-sdk-core).
#[pyclass(name = "SothSdk", module = "soth._soth_native")]
struct PySothSdk {
    inner: Arc<CoreSothSdk>,
}

#[pymethods]
impl PySothSdk {
    /// Construct a new SDK instance. Per the spec, `init` failures
    /// (bundle pull, HMAC key resolution) raise a Python exception
    /// with a descriptive message; bindings' wrappers SHOULD catch
    /// these and fall back to a no-op SDK rather than crashing the
    /// host process.
    #[new]
    #[pyo3(signature = (api_key, org_id, hmac_key_env=None, hmac_key_static=None))]
    fn new(
        api_key: String,
        org_id: String,
        hmac_key_env: Option<String>,
        hmac_key_static: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let hmac_key = match (hmac_key_env, hmac_key_static) {
            (Some(env), None) => HmacKey::FromEnv(env),
            (None, Some(bytes)) => HmacKey::Static(Zeroizing::new(bytes)),
            (Some(_), Some(_)) => {
                return Err(PyValueError::new_err(
                    "specify either hmac_key_env OR hmac_key_static, not both",
                ));
            }
            (None, None) => {
                return Err(PyValueError::new_err(
                    "hmac_key_env or hmac_key_static is required",
                ));
            }
        };

        let config = SdkConfigBuilder::new()
            .api_key(api_key)
            .org_id(org_id)
            .hmac_key(hmac_key)
            .build()
            .map_err(|error| PyValueError::new_err(format!("{error}")))?;

        let sdk = CoreSothSdk::init(config)
            .map_err(|error| PyRuntimeError::new_err(format!("{error}")))?;

        Ok(Self {
            inner: Arc::new(sdk),
        })
    }

    /// Synchronous decision path.
    ///
    /// Returns a `dict` describing the decision; the Python wrapper in
    /// `soth/__init__.py` translates this into either a token (`Allow` /
    /// `Flag`) or a raised `SothBlocked` exception (`Block` /
    /// `Redact` paths).
    #[pyo3(signature = (call_dict))]
    fn pre_call<'py>(&self, py: Python<'py>, call_dict: &Bound<'py, PyDict>) -> PyResult<Bound<'py, PyDict>> {
        let call = build_llm_call(call_dict)?;
        let decision = self.inner.pre_call(&call);
        decision_to_pydict(py, &decision)
    }

    /// Consume a `DecisionToken` after the host call completes.
    /// Bindings spawn this off the host's critical path.
    #[pyo3(signature = (token, response_dict=None))]
    fn post_call(&self, token: u64, response_dict: Option<&Bound<'_, PyDict>>) -> PyResult<()> {
        let token = DecisionToken::from_raw(token);
        let response = response_from_pydict(response_dict)?;
        self.inner.post_call(token, &response);
        Ok(())
    }

    /// Return the in-flight DecisionToken count. Test helper —
    /// bindings expose it for parity assertions.
    fn in_flight_decisions(&self) -> usize {
        self.inner.in_flight_decisions()
    }

    /// Drain the in-memory telemetry queue. Test-only — production
    /// shippers will pull batches via the Phase-1 transport API.
    fn drain_telemetry_for_test<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Bound<'py, PyList>> {
        let events = self.inner.drain_telemetry_for_test();
        let result = PyList::empty_bound(py);
        for event in events {
            let event_dict = PyDict::new_bound(py);
            event_dict.set_item("provider", event.provider)?;
            if let Some(model) = event.model {
                event_dict.set_item("model", model)?;
            }
            event_dict.set_item("endpoint_type", format!("{:?}", event.endpoint_type))?;
            event_dict.set_item("capture_mode", format!("{:?}", event.capture_mode))?;
            event_dict.set_item("use_case", format!("{:?}", event.use_case))?;
            event_dict.set_item(
                "volatility_class",
                format!("{:?}", event.volatility_class),
            )?;
            result.append(event_dict)?;
        }
        Ok(result)
    }
}

/// Decision API constants exposed at the module level so the Python
/// wrapper can reference them without a string match.
const DECISION_KIND_ALLOW: &str = "allow";
const DECISION_KIND_BLOCK: &str = "block";
const DECISION_KIND_REDACT: &str = "redact";
const DECISION_KIND_FLAG: &str = "flag";

fn decision_to_pydict<'py>(
    py: Python<'py>,
    decision: &CoreDecision,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new_bound(py);
    dict.set_item("token", decision.token().raw())?;
    match decision {
        CoreDecision::Allow { .. } => {
            dict.set_item("kind", DECISION_KIND_ALLOW)?;
        }
        CoreDecision::Block { reason, .. } => {
            dict.set_item("kind", DECISION_KIND_BLOCK)?;
            dict.set_item("reason", block_reason_to_pydict(py, reason)?)?;
        }
        CoreDecision::Redact { redactions, .. } => {
            dict.set_item("kind", DECISION_KIND_REDACT)?;
            let list = PyList::empty_bound(py);
            for r in &redactions.replacements {
                let item = PyDict::new_bound(py);
                item.set_item("message_idx", r.message_idx)?;
                item.set_item("redacted_content", r.redacted_content.clone())?;
                list.append(item)?;
            }
            dict.set_item("redactions", list)?;
        }
        CoreDecision::Flag { severity, .. } => {
            dict.set_item("kind", DECISION_KIND_FLAG)?;
            dict.set_item("severity", flag_severity_label(*severity))?;
        }
        // Decision is #[non_exhaustive] — future variants surface as
        // "unknown" so existing bindings keep emitting *something* for
        // the host's wrapper to consume rather than throwing FFI errors.
        _ => {
            dict.set_item("kind", "unknown")?;
        }
    }
    Ok(dict)
}

fn block_reason_to_pydict<'py>(
    py: Python<'py>,
    reason: &CoreBlockReason,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new_bound(py);
    match reason {
        CoreBlockReason::SensitiveArtifact { artifact, severity } => {
            dict.set_item("kind", "sensitive_artifact")?;
            dict.set_item("artifact", format!("{artifact:?}"))?;
            dict.set_item("severity", format!("{severity:?}"))?;
        }
        CoreBlockReason::BudgetExceeded {
            budget_kind,
            observed,
            limit,
        } => {
            dict.set_item("kind", "budget_exceeded")?;
            dict.set_item("budget_kind", format!("{budget_kind:?}"))?;
            dict.set_item("observed", *observed)?;
            dict.set_item("limit", *limit)?;
        }
        CoreBlockReason::PolicyRule { rule_id, rule_name } => {
            dict.set_item("kind", "policy_rule")?;
            dict.set_item("rule_id", rule_id.clone())?;
            if let Some(name) = rule_name {
                dict.set_item("rule_name", name.clone())?;
            }
        }
        CoreBlockReason::UseAlternative {
            suggested_provider,
            suggested_model,
            rule_id,
        } => {
            dict.set_item("kind", "use_alternative")?;
            if let Some(p) = suggested_provider {
                dict.set_item("suggested_provider", p.clone())?;
            }
            if let Some(m) = suggested_model {
                dict.set_item("suggested_model", m.clone())?;
            }
            dict.set_item("rule_id", rule_id.clone())?;
        }
        // BlockReason is #[non_exhaustive] — fall back to a generic
        // shape if soth-sdk-core adds a new variant before this binding
        // catches up.
        _ => {
            dict.set_item("kind", "unknown")?;
        }
    }
    Ok(dict)
}

fn flag_severity_label(severity: FlagSeverity) -> &'static str {
    match severity {
        FlagSeverity::Info => "info",
        FlagSeverity::Warning => "warning",
        FlagSeverity::Critical => "critical",
        // FlagSeverity is #[non_exhaustive] — future variants surface
        // as "unknown" so the binding keeps working.
        _ => "unknown",
    }
}

fn build_llm_call(dict: &Bound<'_, PyDict>) -> PyResult<LlmCall> {
    let provider: String = dict
        .get_item("provider")?
        .ok_or_else(|| PyValueError::new_err("call.provider required"))?
        .extract()?;
    let model: String = dict
        .get_item("model")?
        .ok_or_else(|| PyValueError::new_err("call.model required"))?
        .extract()?;
    let messages_obj = dict
        .get_item("messages")?
        .ok_or_else(|| PyValueError::new_err("call.messages required"))?;
    let messages_list: &Bound<'_, PyList> = messages_obj.downcast()?;

    let mut messages = Vec::with_capacity(messages_list.len());
    for item in messages_list.iter() {
        let item_dict: &Bound<'_, PyDict> = item.downcast()?;
        let role: String = item_dict
            .get_item("role")?
            .ok_or_else(|| PyValueError::new_err("message.role required"))?
            .extract()?;
        let content: String = item_dict
            .get_item("content")?
            .ok_or_else(|| PyValueError::new_err("message.content required"))?
            .extract()?;
        messages.push(Message { role, content });
    }

    let system: Option<String> = match dict.get_item("system")? {
        Some(v) if !v.is_none() => Some(v.extract()?),
        _ => None,
    };
    let stream: bool = match dict.get_item("stream")? {
        Some(v) if !v.is_none() => v.extract()?,
        _ => false,
    };

    let tools: Vec<Tool> = match dict.get_item("tools")? {
        Some(v) if !v.is_none() => {
            let list: &Bound<'_, PyList> = v.downcast()?;
            let mut out = Vec::with_capacity(list.len());
            for item in list.iter() {
                let item_dict: &Bound<'_, PyDict> = item.downcast()?;
                let name: String = item_dict
                    .get_item("name")?
                    .ok_or_else(|| PyValueError::new_err("tool.name required"))?
                    .extract()?;
                let description: Option<String> = match item_dict.get_item("description")? {
                    Some(v) if !v.is_none() => Some(v.extract()?),
                    _ => None,
                };
                let parameters_json: String = match item_dict.get_item("parameters_json")? {
                    Some(v) if !v.is_none() => v.extract()?,
                    _ => String::new(),
                };
                out.push(Tool {
                    name,
                    description,
                    parameters_json,
                });
            }
            out
        }
        _ => Vec::new(),
    };

    Ok(LlmCall {
        provider,
        model,
        messages,
        system,
        tools,
        stream,
        temperature: None,
        top_p: None,
        max_tokens: None,
        stop_sequences: Vec::new(),
        endpoint_type: EndpointType::ChatCompletion,
    })
}

fn response_from_pydict(_dict: Option<&Bound<'_, PyDict>>) -> PyResult<LlmResponse> {
    // V0: response details are not yet consumed by post_call. Phase-1
    // wires response-side artifact scanning + usage stats from the
    // typed response dict.
    Ok(LlmResponse::new(EndpointType::ChatCompletion))
}

#[pymodule]
fn _soth_native(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PySothSdk>()?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("DECISION_KIND_ALLOW", DECISION_KIND_ALLOW)?;
    m.add("DECISION_KIND_BLOCK", DECISION_KIND_BLOCK)?;
    m.add("DECISION_KIND_REDACT", DECISION_KIND_REDACT)?;
    m.add("DECISION_KIND_FLAG", DECISION_KIND_FLAG)?;
    Ok(())
}
