//! SSE (Server-Sent Events) stream parser
//!
//! Provides utilities for parsing SSE streams from AI providers.

use super::{AiProvider, ProviderUsage, SseEvent};
use std::sync::Arc;

/// SSE line state for incremental parsing
#[derive(Debug, Default)]
struct SseLineState {
    /// Current event type
    event_type: Option<String>,
    /// Current data lines
    data_lines: Vec<String>,
}

impl SseLineState {
    fn reset(&mut self) {
        self.event_type = None;
        self.data_lines.clear();
    }

    fn is_empty(&self) -> bool {
        self.event_type.is_none() && self.data_lines.is_empty()
    }
}

/// SSE stream parser that accumulates usage from streaming responses
pub struct SseStreamParser {
    /// Provider for parsing SSE chunks
    provider: Arc<dyn AiProvider>,
    /// Buffer for incomplete lines
    buffer: String,
    /// Current SSE line state
    state: SseLineState,
    /// Accumulated usage
    usage: ProviderUsage,
    /// Whether stream is done
    done: bool,
}

impl SseStreamParser {
    /// Create a new SSE stream parser
    pub fn new(provider: Arc<dyn AiProvider>) -> Self {
        Self {
            provider,
            buffer: String::new(),
            state: SseLineState::default(),
            usage: ProviderUsage::default(),
            done: false,
        }
    }

    /// Process incoming chunk of data
    ///
    /// Returns events extracted from this chunk
    pub fn process(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        if self.done {
            return vec![];
        }

        // Append to buffer
        if let Ok(text) = std::str::from_utf8(chunk) {
            self.buffer.push_str(text);
        } else {
            return vec![];
        }

        let mut events = Vec::new();

        // Process complete lines
        while let Some(newline_pos) = self.buffer.find('\n') {
            let line = self.buffer[..newline_pos].to_string();
            self.buffer = self.buffer[newline_pos + 1..].to_string();

            let line = line.trim_end_matches('\r');

            if line.is_empty() {
                // Empty line = end of event
                if !self.state.is_empty() {
                    if let Some(event) = self.process_event() {
                        events.push(event);
                    }
                    self.state.reset();
                }
            } else if let Some(event_type) = line.strip_prefix("event: ") {
                self.state.event_type = Some(event_type.to_string());
            } else if let Some(data) = line.strip_prefix("data: ") {
                self.state.data_lines.push(data.to_string());
            } else if line.starts_with(':') {
                // Comment, ignore
            }
        }

        events
    }

    /// Process accumulated event state
    fn process_event(&mut self) -> Option<SseEvent> {
        let data = self.state.data_lines.join("\n");

        // Build the chunk to pass to provider
        let chunk = if let Some(ref event_type) = self.state.event_type {
            format!("event: {}\ndata: {}", event_type, data)
        } else {
            format!("data: {}", data)
        };

        let event = self.provider.parse_sse_chunk(&chunk)?;

        // Accumulate usage
        match &event {
            SseEvent::Usage(usage) => {
                // Add to accumulated usage
                if usage.input_tokens > 0 {
                    self.usage.input_tokens = usage.input_tokens;
                }
                if usage.output_tokens > 0 {
                    self.usage.output_tokens = usage.output_tokens;
                }
                if usage.cached_tokens.is_some() {
                    self.usage.cached_tokens = usage.cached_tokens;
                }
                if usage.model.is_some() {
                    self.usage.model.clone_from(&usage.model);
                }
            }
            SseEvent::Done => {
                self.done = true;
            }
            _ => {}
        }

        Some(event)
    }

    /// Get accumulated usage
    pub fn usage(&self) -> &ProviderUsage {
        &self.usage
    }

    /// Check if stream is done
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Consume parser and return final usage
    pub fn into_usage(self) -> ProviderUsage {
        self.usage
    }
}

/// Parse a complete SSE response body (non-streaming)
pub fn parse_sse_body(provider: Arc<dyn AiProvider>, body: &[u8]) -> ProviderUsage {
    let mut parser = SseStreamParser::new(provider);
    parser.process(body);
    parser.into_usage()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::openai::OpenAiProvider;

    #[test]
    fn test_sse_parser_single_chunk() {
        let provider = Arc::new(OpenAiProvider::new());
        let mut parser = SseStreamParser::new(provider);

        let chunk = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n";
        let events = parser.process(chunk);

        assert_eq!(events.len(), 1);
        match &events[0] {
            SseEvent::Content(text) => assert_eq!(text, "Hello"),
            _ => panic!("Expected Content event"),
        }
    }

    #[test]
    fn test_sse_parser_multiple_events() {
        let provider = Arc::new(OpenAiProvider::new());
        let mut parser = SseStreamParser::new(provider);

        let chunk = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\" there\"}}]}\n\n";
        let events = parser.process(chunk);

        assert_eq!(events.len(), 2);
    }

    #[test]
    fn test_sse_parser_split_chunks() {
        let provider = Arc::new(OpenAiProvider::new());
        let mut parser = SseStreamParser::new(provider);

        // First chunk - incomplete
        let events1 = parser.process(b"data: {\"choices\":[{\"delta\":");
        assert!(events1.is_empty());

        // Second chunk - completes the event
        let events2 = parser.process(b"{\"content\":\"Hello\"}}]}\n\n");
        assert_eq!(events2.len(), 1);
    }

    #[test]
    fn test_sse_parser_usage_accumulation() {
        let provider = Arc::new(OpenAiProvider::new());
        let mut parser = SseStreamParser::new(provider);

        let chunk = b"data: {\"model\":\"gpt-4o\",\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":50}}\n\n";
        parser.process(chunk);

        let usage = parser.usage();
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.output_tokens, 50);
    }

    #[test]
    fn test_sse_parser_done() {
        let provider = Arc::new(OpenAiProvider::new());
        let mut parser = SseStreamParser::new(provider);

        assert!(!parser.is_done());

        let chunk = b"data: [DONE]\n\n";
        parser.process(chunk);

        assert!(parser.is_done());
    }
}
