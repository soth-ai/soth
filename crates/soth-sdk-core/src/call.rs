//! `LlmCall` / `LlmResponse` / `LlmChunk` — typed inputs and outputs.
//!
//! `LlmCall` mirrors `soth_core::TypedLlmCall` exactly so the SDK
//! re-exports that type rather than introducing a parallel one.
//! Bindings see `soth_sdk_core::LlmCall` and don't need to depend
//! on `soth_core` directly.

use serde::{Deserialize, Serialize};
use soth_core::EndpointType;

/// Pre-parsed LLM call. SDK consumers populate this from typed provider
/// SDK objects (OpenAI / Anthropic / Cohere / Google / Mistral); the
/// proxy's HTTP fingerprint+parse phase is skipped.
pub use soth_core::TypedLlmCall as LlmCall;
pub use soth_core::TypedMessage as Message;
pub use soth_core::TypedTool as Tool;

/// Provider response. Bindings populate this from the typed provider
/// response object before calling [`SothSdk::post_call`].
///
/// Fields are intentionally minimal for v0; new fields can be added
/// non-breakingly because the struct is `#[non_exhaustive]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct LlmResponse {
    /// Model that actually served the request (may differ from the
    /// requested model on routing fallbacks).
    pub model: Option<String>,
    /// Best-effort assistant content extracted from the response.
    /// Used for output redaction triggers and response-side telemetry
    /// fields. May be `None` for tool-only responses or content arrays
    /// the binding doesn't flatten.
    pub assistant_content: Option<String>,
    pub finish_reason: Option<String>,
    pub usage: Option<UsageStats>,
    pub endpoint_type: EndpointType,
}

impl LlmResponse {
    pub fn new(endpoint_type: EndpointType) -> Self {
        Self {
            model: None,
            assistant_content: None,
            finish_reason: None,
            usage: None,
            endpoint_type,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UsageStats {
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    pub total_tokens: Option<u32>,
    pub estimated_cost_usd: Option<f64>,
}

/// Streaming chunk. Bindings call [`SothSdk::stream_chunk`] once per
/// chunk emitted by the provider stream. The SDK accumulates chunks
/// into the same `StreamObservation` for telemetry on `stream_end`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct LlmChunk {
    /// Sequence number within the stream (binding-assigned). Used by
    /// the SDK for ordering checks; not customer-facing.
    pub sequence: u32,
    /// Best-effort delta text from this chunk. May be empty for
    /// non-content chunks (tool-call metadata, role headers).
    pub delta_content: Option<String>,
    pub finish_reason: Option<String>,
    /// Final usage block if the provider sends one in the last chunk.
    /// Most providers only populate this on the terminal chunk.
    pub usage: Option<UsageStats>,
}

impl LlmChunk {
    pub fn new(sequence: u32) -> Self {
        Self {
            sequence,
            delta_content: None,
            finish_reason: None,
            usage: None,
        }
    }
}
