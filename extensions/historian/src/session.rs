use std::collections::HashMap;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use soth_core::artifacts::CaptureMode;
use soth_core::extensions::{EventSource, ExtensionContext, ExtensionType, GovernableEvent};
use soth_core::normalized::{EndpointType, FormatMetadata};
use soth_core::providers::DetectedProvider;

use crate::types::{AiTool, HistoricalSession};

/// Convert a `HistoricalSession` into a `GovernableEvent` for the extension pipeline.
///
/// The event carries metadata-only fields (hashes, token estimates) and sets
/// `embed_content` to the concatenated conversation text for local-only
/// embedding. Raw content never leaves the device.
pub fn reconstruct_event(session: &HistoricalSession) -> GovernableEvent {
    let provider = tool_to_provider(&session.tool);

    // Concatenate all messages for hashing and embedding.
    let mut user_parts = Vec::new();
    let mut all_parts = Vec::new();
    let mut system_prompt: Option<String> = None;
    let mut total_input_tokens: u32 = 0;
    let mut _total_output_tokens: u32 = 0;

    for msg in &session.messages {
        all_parts.push(format!("{}:{}", msg.role, msg.content));

        match msg.role.as_str() {
            "system" => {
                if system_prompt.is_none() {
                    system_prompt = Some(msg.content.clone());
                }
            }
            "user" | "human" => {
                user_parts.push(msg.content.as_str());
                total_input_tokens += msg.token_estimate;
            }
            "assistant" | "model" => {
                _total_output_tokens += msg.token_estimate;
            }
            _ => {
                total_input_tokens += msg.token_estimate;
            }
        }
    }

    let user_content = user_parts.join("\n");
    let full_conversation = all_parts.join("\n");

    let user_content_hash = sha256_hex(&user_content);
    let conversation_hash = sha256_hex(&full_conversation);
    let system_prompt_hash = system_prompt.as_deref().map(sha256_hex);
    let semantic_hash = compute_semantic_hash(&user_content);

    let timestamp = session
        .started_at
        .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());

    let mut metadata = HashMap::new();
    metadata.insert("tool".to_string(), session.tool.key().to_string());
    metadata.insert("session_id".to_string(), session.session_id.clone());
    metadata.insert(
        "message_count".to_string(),
        session.messages.len().to_string(),
    );
    metadata.insert(
        "user_content_hash".to_string(),
        user_content_hash.clone(),
    );
    metadata.insert(
        "conversation_hash".to_string(),
        conversation_hash.clone(),
    );
    metadata.insert("semantic_hash".to_string(), semantic_hash);
    if let Some(ref h) = system_prompt_hash {
        metadata.insert("system_prompt_hash".to_string(), h.clone());
    }

    // Historical markers — the extension manager reads these to set
    // TelemetryEvent.data_source, is_historical, and original_timestamp.
    metadata.insert(
        "data_source".to_string(),
        format!("{:?}", session.tool.data_source()),
    );
    metadata.insert("is_historical".to_string(), "true".to_string());
    if let Some(ts) = session.started_at {
        metadata.insert("original_timestamp".to_string(), ts.to_string());
    }

    let normalized = soth_core::normalized::NormalizedRequest {
        parse_confidence: soth_core::artifacts::ParseConfidence::Heuristic,
        parser_id: "historian".to_string(),
        schema_version: "1".to_string(),
        parse_warnings: Vec::new(),
        is_ai_call: true,
        provider,
        model: None,
        endpoint_type: EndpointType::ChatCompletion,
        api_version: None,
        system_prompt_hash,
        system_prompt_token_estimate: system_prompt
            .as_ref()
            .map(|s| estimate_tokens(s)),
        user_content_hash,
        user_content_token_estimate: total_input_tokens,
        conversation_hash,
        conversation_turn: Some(session.messages.len() as u32),
        has_tool_definitions: false,
        tool_definition_hash: None,
        temperature: None,
        max_tokens: None,
        stream: false,
        top_p: None,
        stop_sequences: Vec::new(),
        estimated_input_tokens: total_input_tokens,
        estimated_cost_usd: 0.0,
        parse_source: soth_core::artifacts::ParseSource::JsonRpc,
        canonical_cache_key: String::new(),
        format_metadata: FormatMetadata::Unknown,
        has_structured_output: false,
        has_tool_results: false,
        estimated_output_tokens: None,
    };

    GovernableEvent {
        event_id: Uuid::new_v4(),
        timestamp_epoch_ms: timestamp,
        source: EventSource::Extension {
            ext_type: ExtensionType::Historian,
        },
        provider,
        model: None,
        endpoint_type: EndpointType::ChatCompletion,
        normalized: Some(normalized),
        artifacts: Vec::new(),
        capture_mode: CaptureMode::MetadataOnly,
        embed_content: Some(full_conversation),
        context: ExtensionContext {
            extension_name: "historian".to_string(),
            extension_version: env!("CARGO_PKG_VERSION").to_string(),
            metadata,
        },
    }
}

fn tool_to_provider(tool: &AiTool) -> DetectedProvider {
    match tool {
        AiTool::ClaudeCode => DetectedProvider::Anthropic,
        AiTool::GeminiCli => DetectedProvider::Gemini,
        AiTool::OpenAiCodex => DetectedProvider::OpenAi,
        AiTool::GithubCopilot => DetectedProvider::OpenAi,
        // Cursor IDE uses OpenAI-compatible models by default.
        AiTool::Cursor => DetectedProvider::OpenAi,
        AiTool::Continue | AiTool::OpenClaw => DetectedProvider::Unknown,
        AiTool::Unknown(_) => DetectedProvider::Unknown,
    }
}

/// Rough token estimate: ~4 chars per token.
pub fn estimate_tokens(text: &str) -> u32 {
    if text.is_empty() {
        return 0;
    }
    let chars = text.chars().count();
    ((chars as f32) / 4.0).ceil() as u32
}

/// Compute a semantic hash by normalizing the user content: lowercase,
/// collapse whitespace, then SHA-256. Catches near-duplicate prompts that
/// differ only in casing or spacing.
fn compute_semantic_hash(user_content: &str) -> String {
    let normalized: String = user_content
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    sha256_hex(&normalized)
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::HistoricalMessage;

    fn sample_session() -> HistoricalSession {
        HistoricalSession {
            tool: AiTool::ClaudeCode,
            session_id: "test-session-1".to_string(),
            messages: vec![
                HistoricalMessage {
                    role: "user".to_string(),
                    content: "write a function".to_string(),
                    timestamp: Some(1700000000000),
                    token_estimate: 4,
                },
                HistoricalMessage {
                    role: "assistant".to_string(),
                    content: "fn hello() {}".to_string(),
                    timestamp: Some(1700000001000),
                    token_estimate: 4,
                },
            ],
            started_at: Some(1700000000000),
            ended_at: Some(1700000001000),
        }
    }

    #[test]
    fn reconstruct_sets_correct_source() {
        let event = reconstruct_event(&sample_session());
        assert_eq!(
            event.source,
            EventSource::Extension {
                ext_type: ExtensionType::Historian
            }
        );
    }

    #[test]
    fn reconstruct_sets_provider_from_tool() {
        let event = reconstruct_event(&sample_session());
        assert_eq!(event.provider, DetectedProvider::Anthropic);
    }

    #[test]
    fn reconstruct_sets_metadata_only() {
        let event = reconstruct_event(&sample_session());
        assert_eq!(event.capture_mode, CaptureMode::MetadataOnly);
    }

    #[test]
    fn reconstruct_sets_embed_content() {
        let event = reconstruct_event(&sample_session());
        assert!(event.embed_content.is_some());
        let embed = event.embed_content.unwrap();
        assert!(embed.contains("write a function"));
        assert!(embed.contains("fn hello()"));
    }

    #[test]
    fn reconstruct_populates_normalized() {
        let event = reconstruct_event(&sample_session());
        let nr = event.normalized.unwrap();
        assert!(nr.is_ai_call);
        assert_eq!(nr.endpoint_type, EndpointType::ChatCompletion);
        assert!(!nr.user_content_hash.is_empty());
        assert!(!nr.conversation_hash.is_empty());
        assert_eq!(nr.conversation_turn, Some(2));
    }

    #[test]
    fn reconstruct_metadata_contains_tool_info() {
        let event = reconstruct_event(&sample_session());
        assert_eq!(event.context.metadata.get("tool").unwrap(), "claude_code");
        assert_eq!(
            event.context.metadata.get("session_id").unwrap(),
            "test-session-1"
        );
    }

    #[test]
    fn reconstruct_sets_historical_markers() {
        let event = reconstruct_event(&sample_session());
        let meta = &event.context.metadata;
        assert_eq!(meta.get("is_historical").unwrap(), "true");
        assert_eq!(meta.get("data_source").unwrap(), "HistorianClaudeCode");
        assert_eq!(meta.get("original_timestamp").unwrap(), "1700000000000");
    }

    #[test]
    fn reconstruct_sets_semantic_hash() {
        let event = reconstruct_event(&sample_session());
        let hash = event.context.metadata.get("semantic_hash").unwrap();
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA-256 hex length
    }

    #[test]
    fn semantic_hash_normalizes_whitespace_and_case() {
        let session1 = HistoricalSession {
            tool: AiTool::ClaudeCode,
            session_id: "s1".to_string(),
            messages: vec![HistoricalMessage {
                role: "user".to_string(),
                content: "Write  A  Function".to_string(),
                timestamp: Some(1700000000000),
                token_estimate: 4,
            }],
            started_at: Some(1700000000000),
            ended_at: Some(1700000000000),
        };
        let session2 = HistoricalSession {
            tool: AiTool::ClaudeCode,
            session_id: "s2".to_string(),
            messages: vec![HistoricalMessage {
                role: "user".to_string(),
                content: "write a function".to_string(),
                timestamp: Some(1700000000000),
                token_estimate: 4,
            }],
            started_at: Some(1700000000000),
            ended_at: Some(1700000000000),
        };
        let e1 = reconstruct_event(&session1);
        let e2 = reconstruct_event(&session2);
        assert_eq!(
            e1.context.metadata.get("semantic_hash"),
            e2.context.metadata.get("semantic_hash"),
            "semantic hash should match despite different casing/spacing"
        );
        // But conversation hashes should differ (they preserve original text)
        assert_ne!(
            e1.context.metadata.get("conversation_hash"),
            e2.context.metadata.get("conversation_hash"),
        );
    }

    #[test]
    fn gemini_session_sets_correct_data_source() {
        let session = HistoricalSession {
            tool: AiTool::GeminiCli,
            session_id: "gem1".to_string(),
            messages: vec![HistoricalMessage {
                role: "user".to_string(),
                content: "hello".to_string(),
                timestamp: Some(1700000000000),
                token_estimate: 2,
            }],
            started_at: Some(1700000000000),
            ended_at: Some(1700000000000),
        };
        let event = reconstruct_event(&session);
        assert_eq!(
            event.context.metadata.get("data_source").unwrap(),
            "HistorianGemini"
        );
    }
}
