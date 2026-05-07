//! Hook-layer entry point for `soth-classify`.
//!
//! The proxy's classify pipeline takes a `DetectResult` + `ProxyContext`
//! produced by HTTP-layer parsers and gating stages. Hook-driven callers
//! (notably the `soth-code` extension) have **structured** payloads —
//! prompt text, tool args, etc. — but no HTTP/TLS context.
//!
//! [`classify_for_hook`] synthesizes the inputs the existing 7-stage
//! pipeline expects and delegates to it. Outputs are identical to the
//! proxy path for the same content; the wrapper exists only to keep
//! classify callable from outside the proxy crate without exposing
//! private internals.

use soth_core::{
    sha256_hex, CaptureMode, ClassificationSource, DetectResult, IdentityContext,
    NormalizedRequest, ParseConfidence, ParseSource, ProxyContext, TrafficClassification,
};

use crate::{classify, ClassifiedResult, ClassifyBundle, ClassifyConfig};

/// What kind of content is being classified at the hook layer. Drives
/// `traffic_classification` and a small set of downstream stage hints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookContentKind {
    /// User prompt text (e.g. from a `user_prompt_submit` hook).
    PromptText,
    /// Tool name + serialized arguments (e.g. from a `pre_tool_use` hook).
    ToolArgs,
    /// Tool result / output (e.g. from a `post_tool_use` hook).
    ToolResult,
    /// Assistant turn (model output) when the hook payload includes it.
    AssistantTurn,
}

impl HookContentKind {
    fn traffic_classification(self) -> TrafficClassification {
        match self {
            Self::PromptText => TrafficClassification::ApplicationUsage,
            Self::ToolArgs | Self::ToolResult | Self::AssistantTurn => {
                TrafficClassification::ToolUsage
            }
        }
    }
}

/// Caller identity attached to a hook-driven classify call. Mirrors the
/// SDK pattern (`ProxyContext::sdk_only`): hook handlers have no
/// HTTP/TLS/process-resolution context, so transport and attribution
/// stay at default; only identity is populated.
#[derive(Debug, Clone)]
pub struct HookIdentity {
    pub org_id: String,
    pub team_id: String,
    pub user_id_hmac: String,
    pub device_id_hash: String,
    pub endpoint_hash: String,
}

impl Default for HookIdentity {
    fn default() -> Self {
        Self {
            org_id: "unknown".to_string(),
            team_id: "unknown".to_string(),
            user_id_hmac: "unknown".to_string(),
            device_id_hash: "unknown".to_string(),
            endpoint_hash: "code_hook".to_string(),
        }
    }
}

/// Input to [`classify_for_hook`].
#[derive(Debug, Clone)]
pub struct HookClassifyInput<'a> {
    /// Agent identifier (e.g. `"claude_code"`, `"cursor"`). Surfaces in
    /// `IdentityContext::declared_application` so cloud analytics can
    /// segment by agent.
    pub agent_name: &'a str,
    /// LLM provider behind the agent, when known (e.g. `"anthropic"` for
    /// Claude Code, `"openai"` for Codex). `None` if undetermined.
    pub provider: Option<&'a str>,
    /// The model the agent is using, when the hook payload reveals it.
    pub model: Option<&'a str>,
    /// The hook payload's content (prompt text, tool args JSON, etc.).
    pub content: &'a str,
    /// What kind of content `content` is.
    pub kind: HookContentKind,
    /// Caller identity. Hook handler resolves these from SOTH config
    /// at process startup.
    pub identity: &'a HookIdentity,
}

/// Synchronous hook-layer classify entry point.
///
/// Synthesizes a `DetectResult` and `ProxyContext` from `input`, then
/// delegates to the existing 7-stage [`classify`] pipeline. The result
/// is consumed by `soth-code`'s hook handler to populate a
/// `ClassifySidecar` on a `GovernableEvent` and to feed the OPA
/// evaluator via `PolicyContext.semantic` before returning the
/// synchronous Allow/Block/Redact decision.
///
/// Reuses the same ONNX embedding model, centroids, classifier, and
/// volatility/anomaly stages as the proxy path — outputs are identical
/// for identical content.
pub fn classify_for_hook(
    input: HookClassifyInput<'_>,
    bundle: &ClassifyBundle,
    config: &ClassifyConfig,
) -> ClassifiedResult {
    let normalized = build_normalized(&input);
    let detect_result = DetectResult::from_typed_call(
        normalized,
        Vec::new(), // artifacts: redact happens upstream of classify
        // in the soth-code pipeline, so nothing needs to surface here.
        CaptureMode::Full,
    );
    let identity = IdentityContext {
        org_id: input.identity.org_id.clone(),
        user_id_hmac: input.identity.user_id_hmac.clone(),
        team_id: input.identity.team_id.clone(),
        device_id_hash: input.identity.device_id_hash.clone(),
        endpoint_hash: input.identity.endpoint_hash.clone(),
        capture_mode: CaptureMode::Full,
        traffic_classification: input.kind.traffic_classification(),
        classification_source: ClassificationSource::Sdk,
        session_snapshot: None,
        declared_provider: input.provider.map(|s| s.to_string()),
        declared_application: Some(input.agent_name.to_string()),
        session_id: None,
        deployment_context: None,
        bundle_trust_level: None,
        precomputed_commitment_nonce: None,
        precomputed_commitment_hash: None,
    };
    let proxy_ctx = ProxyContext::sdk_only(identity);

    classify(
        &detect_result,
        Some(input.content),
        &proxy_ctx,
        bundle,
        config,
    )
}

fn build_normalized(input: &HookClassifyInput<'_>) -> NormalizedRequest {
    let user_content_hash = sha256_hex(input.content);
    let token_estimate = estimate_tokens(input.content);
    let canonical_cache_key = format!(
        "code:{}:{}",
        input.agent_name,
        &user_content_hash[..user_content_hash.len().min(16)]
    );
    NormalizedRequest {
        parse_confidence: ParseConfidence::Full,
        parser_id: format!("code_hook:{}", input.agent_name),
        schema_version: "1".to_string(),
        is_ai_call: matches!(
            input.kind,
            HookContentKind::PromptText | HookContentKind::AssistantTurn
        ),
        provider: input.provider.unwrap_or("unknown").to_string(),
        model: input.model.map(|s| s.to_string()),
        user_content_hash: user_content_hash.clone(),
        user_content_token_estimate: token_estimate,
        conversation_hash: user_content_hash,
        estimated_input_tokens: token_estimate,
        canonical_cache_key,
        user_prompt: Some(input.content.to_string()),
        parse_source: ParseSource::Sdk,
        ..NormalizedRequest::default()
    }
}

/// Coarse 4-chars-per-token heuristic. Matches the proxy's fallback
/// estimator when no model-specific tokenizer is available; close
/// enough for v0 and avoids zero-token edge cases that confuse
/// downstream stages.
fn estimate_tokens(content: &str) -> u32 {
    ((content.chars().count() as f32 / 4.0).ceil() as u32).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fallback_bundle;

    fn classify_prompt(content: &str, kind: HookContentKind) -> ClassifiedResult {
        let identity = HookIdentity::default();
        let input = HookClassifyInput {
            agent_name: "claude_code",
            provider: Some("anthropic"),
            model: Some("claude-3-5-sonnet"),
            content,
            kind,
            identity: &identity,
        };
        let bundle = fallback_bundle();
        let config = ClassifyConfig::default();
        classify_for_hook(input, &bundle, &config)
    }

    #[test]
    fn produces_semantic_hash() {
        let result = classify_prompt(
            "write a function to reverse a string",
            HookContentKind::PromptText,
        );
        assert!(
            !result.semantic_hash.is_empty(),
            "semantic_hash should be populated"
        );
    }

    #[test]
    fn deterministic_for_identical_input() {
        let a = classify_prompt("identical content", HookContentKind::ToolArgs);
        let b = classify_prompt("identical content", HookContentKind::ToolArgs);
        assert_eq!(a.semantic_hash, b.semantic_hash);
    }

    #[test]
    fn distinct_for_distinct_input() {
        let a = classify_prompt("first prompt content", HookContentKind::PromptText);
        let b = classify_prompt("second prompt content", HookContentKind::PromptText);
        assert_ne!(a.semantic_hash, b.semantic_hash);
    }

    #[test]
    fn token_estimate_basic() {
        assert_eq!(estimate_tokens("abcd"), 1);
        assert_eq!(estimate_tokens("abcdefgh"), 2);
        assert_eq!(estimate_tokens("a"), 1);
        // empty content still floors at 1 to avoid div-by-zero downstream
        assert_eq!(estimate_tokens(""), 1);
    }

    #[test]
    fn traffic_classification_mapping() {
        assert_eq!(
            HookContentKind::PromptText.traffic_classification(),
            TrafficClassification::ApplicationUsage
        );
        assert_eq!(
            HookContentKind::ToolArgs.traffic_classification(),
            TrafficClassification::ToolUsage
        );
        assert_eq!(
            HookContentKind::ToolResult.traffic_classification(),
            TrafficClassification::ToolUsage
        );
        assert_eq!(
            HookContentKind::AssistantTurn.traffic_classification(),
            TrafficClassification::ToolUsage
        );
    }
}
