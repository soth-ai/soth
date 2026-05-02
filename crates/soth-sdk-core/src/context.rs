//! Per-call `CallContext` — overrides identity fields for a single
//! `pre_call` / `stream_begin` invocation.
//!
//! Bindings layer language-native context propagation on top
//! (Python's `contextvars` so it survives async tasks; Node's
//! `AsyncLocalStorage` for the same reason). The Rust core stays
//! sync at the boundary — bindings stash the current context into
//! the language's async-aware container and pass it explicitly per
//! call.
//!
//! Defaults come from `SdkConfig.default_team_id` /
//! `SdkConfig.default_device_id_hash`; callers override per-call to
//! attribute traffic to specific users / teams / sessions.

use serde::{Deserialize, Serialize};

/// Per-call identity overrides. All fields are optional — anything
/// left as `None` falls back to the corresponding `SdkConfig` default
/// (or to the SDK-level "anonymous" sentinel when neither is set).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CallContext {
    /// Customer's end-user identifier, HMAC'd by the binding before
    /// it reaches this struct. The SDK never sees plaintext user IDs;
    /// the HMAC is computed inside the binding using the
    /// `SdkConfig.hmac_key`.
    pub user_id_hmac: Option<String>,
    pub team_id: Option<String>,
    pub device_id_hash: Option<String>,
    pub session_id: Option<String>,
    /// Customer-supplied request correlation ID (e.g. their HTTP
    /// request ID). Carried through telemetry events so they can
    /// correlate SOTH events with their own logs.
    pub request_id: Option<String>,
}

impl CallContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_user_id_hmac(mut self, user_id_hmac: impl Into<String>) -> Self {
        self.user_id_hmac = Some(user_id_hmac.into());
        self
    }

    pub fn with_team_id(mut self, team_id: impl Into<String>) -> Self {
        self.team_id = Some(team_id.into());
        self
    }

    pub fn with_device_id_hash(mut self, device_id_hash: impl Into<String>) -> Self {
        self.device_id_hash = Some(device_id_hash.into());
        self
    }

    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }
}
