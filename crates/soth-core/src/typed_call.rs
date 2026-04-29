//! Pre-parsed LLM call shape used by SDK consumers.
//!
//! `TypedLlmCall` is the input that an in-process SDK binding (PyO3 / napi-rs
//! / WASM) constructs from typed provider SDK objects (OpenAI, Anthropic,
//! Cohere, Google, Mistral, ...). The proxy's HTTP fingerprint/parse phase
//! is not applicable — the caller already knows the provider and has typed
//! access to the message list, system prompt, tools, and streaming flag.
//!
//! `soth_detect::process_normalized` consumes this type, runs the existing
//! sensitive-artifact scan + session prefix-repeat phases, and returns a
//! `DetectResult` with `parse_source = ParseSource::Sdk` and
//! `confidence = ParseConfidence::Full`.

use serde::{Deserialize, Serialize};

use crate::EndpointType;

/// A single message in the conversation. `role` follows the OpenAI convention
/// (`"system"` | `"user"` | `"assistant"` | `"tool"`); other providers map
/// onto this taxonomy at SDK-binding time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedMessage {
    pub role: String,
    pub content: String,
}

/// A tool/function definition exposed to the model. The exact JSON schema of
/// `parameters` is opaque to detect — only `name` (and optionally `description`)
/// participate in artifact / dedup scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedTool {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON-encoded parameter schema, or empty string when absent. Stored as
    /// a string so SDK callers don't have to re-serialize a `serde_json::Value`
    /// across the FFI boundary.
    #[serde(default)]
    pub parameters_json: String,
}

/// Pre-parsed LLM call. SDK consumers populate this from typed provider SDK
/// objects; soth-detect's `process_normalized` accepts it directly without
/// re-parsing an HTTP body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedLlmCall {
    /// Provider entity slug. Conventional slugs: `"openai"`, `"anthropic"`,
    /// `"cohere"`, `"google_vertex"`, `"google_genai"`, `"mistralai"`,
    /// `"azure_openai"`. Bindings are responsible for picking the slug.
    pub provider: String,
    pub model: String,
    pub messages: Vec<TypedMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<TypedTool>,
    #[serde(default)]
    pub stream: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stop_sequences: Vec<String>,
    /// Endpoint type. Defaults to `ChatCompletion` since that's the dominant
    /// SDK use case, but bindings can override for embeddings, image generation,
    /// audio transcription, etc.
    #[serde(default = "default_endpoint_type")]
    pub endpoint_type: EndpointType,
}

fn default_endpoint_type() -> EndpointType {
    EndpointType::ChatCompletion
}

impl TypedLlmCall {
    /// Construct a minimal chat-completion call. Bindings can use this as a
    /// builder seed and mutate fields before passing into `process_normalized`.
    pub fn chat(provider: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            model: model.into(),
            messages: Vec::new(),
            system: None,
            tools: Vec::new(),
            stream: false,
            temperature: None,
            top_p: None,
            max_tokens: None,
            stop_sequences: Vec::new(),
            endpoint_type: EndpointType::ChatCompletion,
        }
    }

    /// The user's *current* prompt: the content of the **last** message with
    /// role `"user"`. Mirrors the proxy REST parser's `last_user_content`
    /// semantics — for multi-turn agentic conversations, the last user
    /// message is the actual current task instruction; earlier user turns
    /// are context. If no `user` message exists, falls back to the last
    /// message of any role; if `messages` is empty, returns `""`.
    ///
    /// Content is `trim()`-ed to match the proxy's `normalize_unicodeish`.
    pub fn user_content(&self) -> String {
        let chosen = self
            .messages
            .iter()
            .rev()
            .find(|m| m.role.eq_ignore_ascii_case("user"))
            .or_else(|| self.messages.last());
        chosen.map(|m| m.content.trim().to_string()).unwrap_or_default()
    }

    /// Conversation serialization for the `conversation_hash`. Format
    /// matches the proxy REST parser: `role:content` per message, joined
    /// by `\n`, no trailing newline. System prompt — when carried in the
    /// dedicated `system` field rather than as a "system" message — is
    /// **not** included here, mirroring providers like Anthropic where
    /// the proxy reads `$.system` separately.
    ///
    /// SDK callers whose typed call surface includes the system prompt in
    /// the messages array (OpenAI convention) should prepend it as a
    /// `{role:"system",content:...}` entry rather than using the dedicated
    /// `system` field, so the hash matches the proxy lane.
    pub fn conversation_text(&self) -> String {
        self.messages
            .iter()
            .map(|m| format!("{}:{}", m.role, m.content.trim()))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Stable serialization of tool definitions for `tool_definition_hash`.
    /// Returns `None` when `tools` is empty so the caller can leave the field
    /// unset on the normalized request.
    pub fn tool_definitions_text(&self) -> Option<String> {
        if self.tools.is_empty() {
            return None;
        }
        let mut out = String::new();
        for tool in &self.tools {
            out.push_str(&tool.name);
            out.push('\u{1f}');
            if let Some(desc) = &tool.description {
                out.push_str(desc);
            }
            out.push('\u{1f}');
            out.push_str(&tool.parameters_json);
            out.push('\n');
        }
        Some(out)
    }
}
