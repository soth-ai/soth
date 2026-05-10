//! Decision API public types.
//!
//! Locked by `docs/common/SDK_DECISION_API_SPEC.md`. Adding a new
//! variant to any of these enums is a minor bump (they are all
//! `#[non_exhaustive]`); changing a field is a breaking change.

use serde::{Deserialize, Serialize};
use soth_core::{ArtifactKind, ArtifactSeverity};

/// Output of `SothSdk::pre_call` and `stream_begin`. Cooperative
/// enforcement: the binding's wrapper translates each variant into a
/// host-language action — `Block` becomes a `SothBlocked` exception,
/// `Redact` substitutes redacted message content before forwarding,
/// `Flag` logs a structured event without affecting the call.
///
/// `Reroute` is intentionally absent — it is a proxy/sidecar capability;
/// reroute-shaped policies surface here as
/// [`BlockReason::UseAlternative`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Decision {
    Allow {
        token: DecisionToken,
    },
    Block {
        token: DecisionToken,
        reason: BlockReason,
    },
    Redact {
        token: DecisionToken,
        redactions: MessageRedactions,
    },
    Flag {
        token: DecisionToken,
        severity: FlagSeverity,
    },
}

impl Decision {
    /// Token consumed by `post_call` / `stream_end` regardless of variant.
    pub fn token(&self) -> DecisionToken {
        match self {
            Decision::Allow { token }
            | Decision::Block { token, .. }
            | Decision::Redact { token, .. }
            | Decision::Flag { token, .. } => *token,
        }
    }

    pub fn is_block(&self) -> bool {
        matches!(self, Decision::Block { .. })
    }
}

/// Why a `Decision::Block` fired. Bindings surface this as a field on
/// `SothBlocked`; customers can branch on `kind` for graceful degradation
/// (e.g. retry-with-alternative when `UseAlternative` is set).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BlockReason {
    SensitiveArtifact {
        artifact: ArtifactKind,
        severity: ArtifactSeverity,
    },
    BudgetExceeded {
        budget_kind: BudgetKind,
        observed: u64,
        limit: u64,
    },
    PolicyRule {
        rule_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule_name: Option<String>,
    },
    /// Reroute-shaped policy: customer app may retry against the
    /// suggested provider/model.
    UseAlternative {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        suggested_provider: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        suggested_model: Option<String>,
        rule_id: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum BudgetKind {
    Tokens,
    CostUsd,
    Requests,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum FlagSeverity {
    Info,
    Warning,
    Critical,
}

/// List of message-level replacements produced by `Decision::Redact`.
/// Within-message surgical edits are deliberately out of scope —
/// customers wanting that fidelity use the proxy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MessageRedactions {
    pub replacements: Vec<MessageRedaction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageRedaction {
    /// Index into `LlmCall.messages`. Bindings' provider adapters use
    /// this to locate the message in the typed call object before
    /// substitution.
    pub message_idx: usize,
    /// Replacement content. Always set; the SDK never deletes a message
    /// outright — the placeholder preserves conversation turn structure.
    pub redacted_content: String,
    /// Telemetry tag — what triggered the redaction.
    pub reason: RedactReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RedactReason {
    SensitiveArtifact { artifact: ArtifactKind },
    PolicyRule { rule_id: String },
}

/// Opaque per-call handle. Created by `pre_call` / `stream_begin` and
/// consumed exactly once by `post_call` / `stream_end`. Bindings MUST
/// NOT inspect `inner` — its layout is internal and may change.
///
/// Lifecycle, slab-full handling, and orphan sweep are specified in
/// `SDK_DECISION_API_SPEC.md` §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DecisionToken {
    pub(crate) inner: u64,
}

impl DecisionToken {
    /// Sentinel token returned when the decision slab is at capacity.
    /// `post_call(SLAB_FULL, ...)` is a documented no-op that emits a
    /// `slab_full_no_enrichment` telemetry event so cluster operators
    /// know to size up.
    pub const SLAB_FULL: DecisionToken = DecisionToken { inner: u64::MAX };

    /// Test/binding-failure sentinel. Used when an FFI panic was caught
    /// at the boundary and a fail-open `Decision::Allow` was emitted.
    pub const SENTINEL_FAIL_OPEN: DecisionToken = DecisionToken {
        inner: u64::MAX - 1,
    };

    /// Opaque round-trip handle for FFI bindings. Bindings serialize
    /// the token across the language boundary as the returned u64;
    /// they MUST NOT interpret the bits or attempt to construct a
    /// `DecisionToken` from arbitrary values.
    pub fn raw(self) -> u64 {
        self.inner
    }

    /// Reconstruct a `DecisionToken` from a value previously obtained
    /// via [`raw`]. Bindings use this to round-trip the token across
    /// the FFI boundary; passing values not previously emitted by the
    /// SDK is undefined behavior at the slab level (the slab will
    /// reject the token as stale and emit a `decision_orphaned`
    /// telemetry event).
    pub fn from_raw(raw: u64) -> Self {
        Self { inner: raw }
    }

    pub(crate) fn is_sentinel(self) -> bool {
        self == Self::SLAB_FULL || self == Self::SENTINEL_FAIL_OPEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_token_is_copy_and_eq() {
        let t = DecisionToken { inner: 42 };
        let u = t;
        assert_eq!(t, u);
    }

    #[test]
    fn sentinels_are_distinct() {
        assert_ne!(DecisionToken::SLAB_FULL, DecisionToken::SENTINEL_FAIL_OPEN);
        assert!(DecisionToken::SLAB_FULL.is_sentinel());
        assert!(DecisionToken::SENTINEL_FAIL_OPEN.is_sentinel());
    }

    #[test]
    fn decision_token_method_works_for_every_variant() {
        let t = DecisionToken { inner: 1 };
        assert_eq!(Decision::Allow { token: t }.token(), t);
        assert_eq!(
            Decision::Block {
                token: t,
                reason: BlockReason::PolicyRule {
                    rule_id: "r".into(),
                    rule_name: None
                },
            }
            .token(),
            t
        );
        assert_eq!(
            Decision::Redact {
                token: t,
                redactions: MessageRedactions::default(),
            }
            .token(),
            t
        );
        assert_eq!(
            Decision::Flag {
                token: t,
                severity: FlagSeverity::Info,
            }
            .token(),
            t
        );
    }
}
