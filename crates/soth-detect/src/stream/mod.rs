use crate::graphql::parse_graphql_payload_text;
use crate::grpc::parse_grpc_chunk_payload;
use crate::hash::hash_content;
// JSON-RPC streaming fallback removed — no real-world AI provider uses
// JSON-RPC for streaming responses. The jsonrpc parser is still available
// for request-side detection via DetectedFormat::JsonRpc.
use crate::sensitive::credential_scan;
use crate::types::{
    ArtifactLocation, CaptureMode, ChunkArtifact, DetectBundleSlice, DetectWarning, FrameDirection,
    FrameKind, ParseConfidence, ParseDetectResult, ParseSource, StreamChunk, StreamSession,
    StreamSummary,
};
use bytes::Bytes;

mod gemini;
mod multipart;
pub mod rules;
mod socketio;
mod sse;
mod usage;
mod websocket;

pub(crate) use gemini::extract_gemini_length_prefixed;

use crate::types::RestFormatDescriptor;
use multipart::parse_multipart_payload_text;
use soth_core::bundle::detect::FeatureResponseSpec;
use sse::extract_sse_rest_delta;
use websocket::process_websocket_turn;

/// Result of processing a single stream chunk.
#[derive(Clone, Debug)]
pub enum ChunkEvent {
    /// A sensitive artifact was found in the chunk payload.
    Artifact(ChunkArtifact),
    /// A WebSocket turn completed (response.completed detected).
    TurnCompleted(crate::types::StreamTurn),
    /// A client→server WebSocket frame delivered a new user prompt.
    /// Fires BEFORE the server streams the response so dev verify can
    /// show the prompt immediately.
    TurnRequest(crate::types::StreamTurnRequest),
}

/// Maximum bytes of assembled prompt or response content carried on a
/// single `StreamTurn`. Anything past this is truncated to keep
/// `intercept_records.telemetry_json` rows bounded.  This is independent
/// of `MAX_ACCUMULATED_BYTES` (16 KB on `StreamSession`) which limits
/// in-flight memory; this constant limits *persisted* per-turn payload.
pub(crate) const MAX_TURN_PAYLOAD_BYTES: usize = 8 * 1024;

/// Set `session.stream_prompt` and simultaneously stage a
/// `StreamTurnRequest` event to be emitted at the end of the current
/// `process_chunk_with_bundle` call.  The pending event is drained AFTER
/// credential_scan so both can be reported for one chunk.
fn set_stream_prompt_and_signal(session: &mut crate::types::StreamSession, mut prompt: String) {
    if prompt.len() > MAX_TURN_PAYLOAD_BYTES {
        let mut cut = MAX_TURN_PAYLOAD_BYTES;
        while cut > 0 && !prompt.is_char_boundary(cut) {
            cut -= 1;
        }
        prompt.truncate(cut);
    }
    let request_event = crate::types::StreamTurnRequest {
        connection_id: session.connection_id,
        model: session.model.clone(),
        turn_number: session.turns_emitted + 1,
        prompt: prompt.clone(),
    };
    session.stream_prompt = Some(prompt);
    session.pending_request_event = Some(request_event);
}

/// Drain the session's accumulated text into a (prompt, content) pair for
/// emission on a finished `StreamTurn`.  Truncates each side to
/// `max_bytes` so per-turn rows stay bounded on long conversations.
///
/// Capture-mode aware: in `MetadataOnly` / `Disabled` modes the buffers
/// are still drained (memory hygiene) but the returned values are `None`
/// so no content is ever persisted.
pub(crate) fn take_session_turn_payload(
    session: &mut crate::types::StreamSession,
    max_bytes: usize,
) -> (Option<String>, Option<String>) {
    let capture_mode = session.capture_mode;

    // Always drain the buffers so the next turn on a long-lived WS
    // connection starts clean and we don't accumulate memory.
    let drained_buffer: Vec<String> = std::mem::take(&mut session.delta_buffer);
    let drained_prompt: Option<String> = session.stream_prompt.take();
    session.accumulated_bytes = 0;

    // Privacy modes: drained but not surfaced.  Only Full / FullContent
    // capture modes opt-in to persisting prompt/response text.
    if !matches!(capture_mode, CaptureMode::Full | CaptureMode::FullContent) {
        return (None, None);
    }

    let mut assembled = drained_buffer.join("");
    if assembled.len() > max_bytes {
        // Truncate at a UTF-8 char boundary to avoid producing invalid UTF-8.
        let mut cut = max_bytes;
        while cut > 0 && !assembled.is_char_boundary(cut) {
            cut -= 1;
        }
        assembled.truncate(cut);
    }

    let prompt = drained_prompt.map(|mut p| {
        if p.len() > max_bytes {
            let mut cut = max_bytes;
            while cut > 0 && !p.is_char_boundary(cut) {
                cut -= 1;
            }
            p.truncate(cut);
        }
        p
    });

    let content = if assembled.is_empty() {
        None
    } else {
        Some(assembled)
    };

    (prompt, content)
}

pub fn process_chunk_with_bundle(
    chunk: &StreamChunk,
    session: &mut StreamSession,
    bundle: &DetectBundleSlice<'_>,
) -> Option<ChunkEvent> {
    session.chunk_count += 1;

    // Resolve the format descriptor for this session's web app format (if any).
    let descriptor = session
        .format_name
        .as_deref()
        .and_then(|name| bundle.rest_formats.get(name));

    match chunk.frame_kind {
        FrameKind::SseData | FrameKind::NdjsonLine => {
            // Single-pass: parse JSON once, extract model + usage + finish_reason + delta.
            let sse =
                extract_all_from_sse_lines(&chunk.payload, session.model.is_none(), descriptor);
            if let Some(model) = sse.model {
                session.model = Some(model);
            }
            if let Some(usage) = sse.usage {
                session.last_usage = Some(usage);
            }
            let got_finish = sse.finish_reason.is_some();
            if let Some(fr) = sse.finish_reason {
                session.last_finish_reason = Some(fr);
            }
            if session.stream_prompt.is_none() {
                if let Some(prompt) = sse.prompt {
                    set_stream_prompt_and_signal(session, prompt);
                }
            }
            // Prefer the SSE-extracted delta; fall back to GraphQL/Gemini parsers.
            if let Some(delta) = sse
                .delta
                .or_else(|| parse_graphql_payload_text(&chunk.payload))
                .or_else(|| extract_gemini_length_prefixed(&chunk.payload))
            {
                session.accumulate(delta);
            }

            // For long-lived SSE connections (e.g. Copilot), the `done` event
            // signals the end of a response turn but the connection stays open.
            // Emit a TurnCompleted so the proxy writes a per-turn record
            // immediately instead of waiting for connection close (which may
            // never happen).
            if got_finish
                && descriptor.is_some_and(|d| d.features.iter().any(|f| f.protocol == "websocket"))
            {
                let usage = session.last_usage.take().unwrap_or_default();
                let model = session.model.clone();
                session.turns_emitted += 1;
                let turn_number = session.turns_emitted;
                let connection_id = session.connection_id;
                let (prompt, content) = take_session_turn_payload(session, MAX_TURN_PAYLOAD_BYTES);
                return Some(ChunkEvent::TurnCompleted(crate::types::StreamTurn {
                    connection_id,
                    model,
                    usage,
                    turn_number,
                    prompt,
                    content,
                }));
            }
        }
        FrameKind::WebSocketText => {
            // Check if payload is binary-encoded (protobuf/msgpack) despite
            // being sent as a WebSocket text frame.
            let is_binary_encoded =
                !chunk.payload.is_empty() && std::str::from_utf8(&chunk.payload).is_err();

            if is_binary_encoded {
                // Binary-encoded WebSocket frame (e.g. Codex protobuf, Meta
                // AI protobuf-wrapped JSON).  If the format has stream
                // rules, run them against embedded JSON extracted from the
                // binary envelope — this is the PROTO_INSIDE_JSON path.
                if let Some(event) =
                    process_binary_ws_payload(&chunk.payload, session, descriptor, chunk.direction)
                {
                    return Some(event);
                }
                // Fallback for pure protobuf formats without stream rules.
                if descriptor.is_none() && looks_like_protobuf_payload(&chunk.payload) {
                    if let Some(delta) = parse_grpc_chunk_payload(
                        &chunk.payload,
                        bundle,
                        session.grpc_service.as_deref(),
                        session.grpc_method.as_deref(),
                    ) {
                        session.accumulate(delta);
                    }
                }
            } else {
                // Socket.IO framing: if the payload starts with a Socket.IO
                // packet prefix (e.g. `42["event", ...]`), unwrap it first
                // and process only the inner JSON data.
                if socketio::looks_like_socketio(&chunk.payload) {
                    let direction_is_client =
                        chunk.direction == Some(FrameDirection::ClientToServer);
                    if let Some(socketio::SocketIoFrame::Event { data_json, .. }) =
                        socketio::decode_socketio_frame(&chunk.payload)
                    {
                        let data_bytes = data_json.as_bytes();
                        let sse = extract_all_from_sse_lines(
                            data_bytes,
                            session.model.is_none(),
                            descriptor,
                        );
                        if let Some(model) = sse.model {
                            session.model = Some(model);
                        }
                        if let Some(usage) = sse.usage {
                            session.last_usage = Some(usage);
                        }
                        let got_finish = sse.finish_reason.is_some();
                        if let Some(fr) = sse.finish_reason {
                            session.last_finish_reason = Some(fr);
                        }
                        if direction_is_client {
                            if session.stream_prompt.is_none() {
                                if let Some(prompt) = sse.prompt {
                                    set_stream_prompt_and_signal(session, prompt);
                                }
                            }
                            // Drain the pending TurnRequest so dev-verify shows
                            // the STREAM TURN REQUEST block when the user sends
                            // a message.  Without this, the signal is staged but
                            // never surfaces because the socketio branch exits
                            // before the bottom-of-function fallthrough.
                            if let Some(req) = session.pending_request_event.take() {
                                return Some(ChunkEvent::TurnRequest(req));
                            }
                        } else {
                            if let Some(delta) = sse.delta {
                                session.accumulate(delta);
                            }
                            if got_finish
                                && descriptor.is_some_and(|d| {
                                    d.features.iter().any(|f| f.protocol == "websocket")
                                })
                            {
                                let usage = session.last_usage.take().unwrap_or_default();
                                let model = session.model.clone();
                                session.turns_emitted += 1;
                                let turn_number = session.turns_emitted;
                                let connection_id = session.connection_id;
                                let (prompt, content) =
                                    take_session_turn_payload(session, MAX_TURN_PAYLOAD_BYTES);
                                return Some(ChunkEvent::TurnCompleted(crate::types::StreamTurn {
                                    connection_id,
                                    model,
                                    usage,
                                    turn_number,
                                    prompt,
                                    content,
                                }));
                            }
                        }
                    }
                    // Non-EVENT Socket.IO frames (PING, PONG, ACK) are ignored.
                    return None;
                }

                // JSON WebSocket frame — split by direction.
                let is_client_frame = chunk.direction == Some(FrameDirection::ClientToServer);

                let is_server_frame = chunk.direction == Some(FrameDirection::ServerToClient);

                if is_client_frame {
                    // CLIENT → SERVER: extract model and prompt from request frames.
                    if let Some(turn) = process_websocket_turn(&chunk.payload, session) {
                        return Some(ChunkEvent::TurnCompleted(turn));
                    }
                    let sse = extract_all_from_sse_lines(
                        &chunk.payload,
                        session.model.is_none(),
                        descriptor,
                    );
                    if let Some(model) = sse.model {
                        session.model = Some(model);
                    }
                    if session.stream_prompt.is_none() {
                        if let Some(prompt) = sse.prompt {
                            set_stream_prompt_and_signal(session, prompt);
                        }
                    }
                } else {
                    // SERVER → CLIENT (or direction unknown): extract response data.
                    let sse = extract_all_from_sse_lines(
                        &chunk.payload,
                        session.model.is_none(),
                        descriptor,
                    );
                    if let Some(model) = sse.model {
                        session.model = Some(model);
                    }
                    if let Some(usage) = sse.usage {
                        session.last_usage = Some(usage);
                    }
                    let got_finish = sse.finish_reason.is_some();
                    if let Some(fr) = sse.finish_reason {
                        session.last_finish_reason = Some(fr);
                    }
                    if session.stream_prompt.is_none() {
                        if let Some(prompt) = sse.prompt {
                            set_stream_prompt_and_signal(session, prompt);
                        }
                    }

                    // For long-lived WebSocket connections (e.g. Copilot), the
                    // `done` event signals the end of a response turn. Emit
                    // TurnCompleted so the proxy writes a per-turn record
                    // immediately.
                    if got_finish
                        && descriptor
                            .is_some_and(|d| d.features.iter().any(|f| f.protocol == "websocket"))
                    {
                        let usage = session.last_usage.take().unwrap_or_default();
                        let model = session.model.clone();
                        session.turns_emitted += 1;
                        let turn_number = session.turns_emitted;
                        let connection_id = session.connection_id;
                        let (prompt, content) =
                            take_session_turn_payload(session, MAX_TURN_PAYLOAD_BYTES);
                        return Some(ChunkEvent::TurnCompleted(crate::types::StreamTurn {
                            connection_id,
                            model,
                            usage,
                            turn_number,
                            prompt,
                            content,
                        }));
                    }

                    if session.is_websocket {
                        if let Some(turn) = process_websocket_turn(&chunk.payload, session) {
                            return Some(ChunkEvent::TurnCompleted(turn));
                        }
                    }

                    // Only accumulate content when we KNOW it's a server frame.
                    // With direction=None (old mitm), skip accumulation to avoid
                    // treating client prompts as response content.
                    if is_server_frame {
                        if let Some(delta) = sse
                            .delta
                            .or_else(|| parse_multipart_payload_text(&chunk.payload))
                        {
                            session.accumulate(delta);
                        } else if descriptor.is_none() {
                            // Raw-text fallback: only used when there is NO
                            // parser descriptor. Providers with rules (Poe,
                            // Manus, HubSpot, Meta AI) deliberately return
                            // no delta on non-terminal frames so the rules
                            // engine can filter them out — don't pollute the
                            // session with raw JSON frames in that case.
                            if let Ok(text) = std::str::from_utf8(&chunk.payload) {
                                if !text.trim().is_empty() {
                                    session.accumulate(text.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        FrameKind::GrpcMessage => {
            if let Some(delta) = parse_grpc_chunk_payload(
                &chunk.payload,
                bundle,
                session.grpc_service.as_deref(),
                session.grpc_method.as_deref(),
            ) {
                session.accumulate(delta);
            }
        }
        FrameKind::WebSocketBinary => {
            // For formats with stream rules (e.g. Meta AI), run the unified
            // binary-ws helper which handles PROTO_INSIDE_JSON and pure
            // protobuf via the rules engine.
            if descriptor.is_some_and(|d| !d.features.is_empty()) {
                if let Some(event) =
                    process_binary_ws_payload(&chunk.payload, session, descriptor, chunk.direction)
                {
                    return Some(event);
                }
            } else if looks_like_protobuf_payload(&chunk.payload) {
                if let Some(delta) = parse_grpc_chunk_payload(
                    &chunk.payload,
                    bundle,
                    session.grpc_service.as_deref(),
                    session.grpc_method.as_deref(),
                ) {
                    session.accumulate(delta);
                }
            } else if let Ok(text) = std::str::from_utf8(&chunk.payload) {
                if let Some(delta) = extract_structured_text(text.as_bytes())
                    .or_else(|| parse_multipart_payload_text(text.as_bytes()))
                {
                    session.accumulate(delta);
                } else if !text.trim().is_empty() {
                    session.accumulate(text.to_string());
                }
            }
        }
        FrameKind::MultipartMixed => {
            if let Some(delta) = parse_multipart_payload_text(&chunk.payload) {
                session.accumulate(delta);
            }
        }
        FrameKind::WebSocketClose => {}
    }

    if matches!(
        session.capture_mode,
        CaptureMode::Full | CaptureMode::SensitiveArtifacts | CaptureMode::FullContent
    ) {
        let artifacts = credential_scan(
            &chunk.payload,
            ArtifactLocation::StreamChunk {
                sequence: chunk.sequence,
            },
        );
        if !artifacts.is_empty() {
            // Credential wins over request event — safety trumps dev verify.
            session.pending_request_event.take();
            return Some(ChunkEvent::Artifact(ChunkArtifact {
                sequence: chunk.sequence,
                artifacts,
            }));
        }
    }

    // Drain any pending request event staged by a client-frame prompt
    // extraction earlier in this chunk.
    if let Some(req) = session.pending_request_event.take() {
        return Some(ChunkEvent::TurnRequest(req));
    }

    None
}

pub fn finalize_stream_summary(session: StreamSession) -> StreamSummary {
    let assembled = session.finalize_response_content();
    StreamSummary {
        response_hash: hash_content(&assembled),
        chunk_count: session.chunk_count,
        elapsed_ms: session.start_time.elapsed().as_millis(),
    }
}

pub fn finalize_stream_detect(session: StreamSession) -> ParseDetectResult {
    let summary = finalize_stream_summary(session.clone());
    let assembled = session.finalize_response_content();

    let mut normalized = crate::types::empty_heuristic_request("STREAM", "/stream");

    // Carry through request context if available
    if let Some(provider) = &session.provider {
        normalized.provider = provider.clone();
    }
    if session.model.is_some() {
        normalized.model = session.model.clone();
    }
    if let Some(format) = &session.request_format {
        normalized.format_metadata = format.clone();
    }
    normalized.estimated_input_tokens = session.estimated_input_tokens;

    let token_estimate = ((assembled.len() as f32) / 4.0).ceil() as u32;
    normalized.is_ai_call = !assembled.is_empty();
    normalized.user_content_hash = summary.response_hash.clone();
    normalized.user_content_token_estimate = token_estimate;
    normalized.conversation_hash = summary.response_hash.clone();
    normalized.canonical_cache_key = summary.response_hash.clone();
    let capture_mode = session.capture_mode;
    // Always run credential scan — capture mode controls downstream storage,
    // not detection. Policy rules like `detect.private_key_detected → Block`
    // must fire regardless of capture mode.
    let artifacts = credential_scan(assembled.as_bytes(), ArtifactLocation::Unknown);

    let warnings = vec![DetectWarning {
        code: "stream_finalize_heuristic",
        detail: "stream finalized using heuristic normalization".to_string(),
    }];

    ParseDetectResult {
        normalized,
        artifacts,
        capture_mode,
        parse_source: ParseSource::Heuristic,
        confidence: ParseConfidence::Heuristic,
        detect_latency_us: session.start_time.elapsed().as_micros() as u64,
        warnings,
        raw_body_bytes: Some(Bytes::from(assembled)),
        session_mutations: soth_core::SessionMutations::default(),
        is_prefix_repeat: false,
        novel_token_count: 0,
        repeated_token_count: 0,
        novel_tail_start_idx: None,
        prefix_hash: None,
        is_repeated_code_context: false,
        ast_normalized_hash: None,
        first_blob_event_id: None,
        import_categories: Vec::new(),
    }
}

/// Result of single-pass extraction from SSE/NDJSON/JSON lines.
struct SseExtracted {
    model: Option<String>,
    usage: Option<crate::types::StreamUsage>,
    finish_reason: Option<String>,
    delta: Option<String>,
    prompt: Option<String>,
}

/// Parse JSON lines once and extract model, usage, finish_reason, and delta
/// content in a single pass. Eliminates the previous 2-3x redundant
/// `serde_json::from_str` per chunk.
fn extract_all_from_sse_lines(
    payload: &[u8],
    need_model: bool,
    descriptor: Option<&RestFormatDescriptor>,
) -> SseExtracted {
    // If the descriptor has a chat feature with stream rules, use the
    // data-driven rules engine instead of the hardcoded extraction below.
    if let Some(desc) = descriptor {
        if let Some(feature) = desc.features.iter().find(|f| f.feature_type == "chat") {
            if let FeatureResponseSpec::Stream { ref stream } = feature.response {
                let mut acc = rules::RulesAccumulator::new(&stream.accumulate);
                let extracted = rules::extract_with_stream_rules(payload, stream, &mut acc);
                // Also try to extract usage from the payload (rules don't cover usage yet)
                let usage_result = std::str::from_utf8(payload).ok().and_then(|text| {
                    text.lines().find_map(|line| {
                        let json_str = line
                            .trim()
                            .strip_prefix("data:")
                            .map(str::trim)
                            .unwrap_or(line.trim());
                        if json_str.is_empty() {
                            return None;
                        }
                        let v: serde_json::Value = serde_json::from_str(json_str).ok()?;
                        usage::usage_from_json_value(&v)
                    })
                });
                return SseExtracted {
                    model: extracted.model,
                    usage: usage_result,
                    finish_reason: extracted.finish_reason,
                    delta: extracted.content,
                    prompt: extracted.prompt,
                };
            }
        }
    }

    let mut result = SseExtracted {
        model: None,
        usage: None,
        finish_reason: None,
        delta: None,
        prompt: None,
    };

    let Ok(text) = std::str::from_utf8(payload) else {
        return result;
    };

    let mut delta_buf = String::new();

    for line in text.lines() {
        let trimmed = line.trim();
        let json_str = if let Some(rest) = trimmed.strip_prefix("data:") {
            rest.trim()
        } else if trimmed.starts_with('{') {
            trimmed
        } else {
            continue;
        };

        if json_str.is_empty() || json_str == "[DONE]" {
            continue;
        }

        let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) else {
            continue;
        };

        // Model (only while unknown)
        if need_model && result.model.is_none() {
            result.model = sse::model_from_value(&value)
                .or_else(|| sse::model_from_value_with_descriptor(&value, descriptor));
        }

        // Usage
        if let Some(u) = usage::usage_from_json_value(&value) {
            result.usage = Some(u);
        }
        if let Some(fr) = usage::finish_reason_from_json_value(&value) {
            result.finish_reason = Some(fr);
        }

        // Delta — try standard SSE patterns, then descriptor
        if !sse::accumulate_delta_from_value(&value, &mut delta_buf) {
            sse::accumulate_delta_from_value_with_descriptor(&value, descriptor, &mut delta_buf);
        }
    }

    result.delta = if delta_buf.is_empty() {
        None
    } else {
        Some(delta_buf)
    };
    result
}

/// Run stream rules against a binary-encoded WebSocket frame.  Handles two
/// shapes: (a) pure protobuf — the rules engine calls `scan_proto_strings`
/// via its `is_protobuf` branch; (b) PROTO_INSIDE_JSON (Meta AI) — the
/// rules engine extracts embedded JSON and applies the configured rules.
///
/// Called from both `FrameKind::WebSocketBinary` and from
/// `FrameKind::WebSocketText` when the payload fails UTF-8 (some servers
/// send binary data on text opcodes).  Returns a `ChunkEvent::TurnCompleted`
/// when a `finish_reason` rule fires on a websocket feature.
fn process_binary_ws_payload(
    payload: &[u8],
    session: &mut crate::types::StreamSession,
    descriptor: Option<&RestFormatDescriptor>,
    direction: Option<FrameDirection>,
) -> Option<ChunkEvent> {
    // ── CLIENT → SERVER ─────────────────────────────────────────────────
    // Client frames carry the user prompt.  Apps like Meta AI don't
    // declare request-side rules in the bundle, so run the rules engine
    // *and* a field-name heuristic to find a prompt string and stage a
    // STREAM TURN REQUEST event.  Always re-stage on each client frame so
    // multi-turn conversations update the prompt per turn.
    if direction == Some(FrameDirection::ClientToServer) {
        let sse = extract_all_from_sse_lines(payload, session.model.is_none(), descriptor);
        let prompt = sse
            .prompt
            .or_else(|| heuristic_client_prompt_from_binary(payload));
        if let Some(p) = prompt {
            set_stream_prompt_and_signal(session, p);
        }
        return None;
    }

    // ── SERVER → CLIENT (or unknown direction) ──────────────────────────
    let sse = extract_all_from_sse_lines(payload, session.model.is_none(), descriptor);
    if let Some(model) = sse.model {
        session.model = Some(model);
    }
    if let Some(usage) = sse.usage {
        session.last_usage = Some(usage);
    }
    let got_finish = sse.finish_reason.is_some();
    if let Some(fr) = sse.finish_reason {
        session.last_finish_reason = Some(fr);
    }
    if session.stream_prompt.is_none() {
        if let Some(prompt) = sse.prompt {
            set_stream_prompt_and_signal(session, prompt);
        }
    }
    if let Some(delta) = sse.delta {
        session.accumulate(delta);
    }
    if got_finish
        && descriptor.is_some_and(|d| d.features.iter().any(|f| f.protocol == "websocket"))
    {
        let usage = session.last_usage.take().unwrap_or_default();
        let model = session.model.clone();
        session.turns_emitted += 1;
        let turn_number = session.turns_emitted;
        let connection_id = session.connection_id;
        let (prompt, content) = take_session_turn_payload(session, MAX_TURN_PAYLOAD_BYTES);
        return Some(ChunkEvent::TurnCompleted(crate::types::StreamTurn {
            connection_id,
            model,
            usage,
            turn_number,
            prompt,
            content,
        }));
    }
    None
}

/// Heuristic: find a user prompt inside the embedded JSON of a binary
/// client frame.  Used as a fallback when the format has no request-side
/// prompt rule (e.g. Meta AI's Clippy WS).  Walks each embedded JSON object
/// and returns the first non-empty string at a field name commonly used
/// for user input.
fn heuristic_client_prompt_from_binary(payload: &[u8]) -> Option<String> {
    const PROMPT_FIELDS: &[&str] = &[
        "message",
        "prompt",
        "text",
        "query",
        "input",
        "content",
        "user_input",
        "user_message",
        "question",
    ];

    // Pass 1: look inside embedded JSON for a likely prompt field by name.
    // Also handle the Meta AI envelope `{"req-id":..., "payload":"<b64>"}`
    // where the real prompt lives inside a base64-encoded protobuf blob.
    for json_str in extract_json_from_binary(payload) {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&json_str) else {
            continue;
        };
        if let Some(found) = find_prompt_in_value(&value, PROMPT_FIELDS) {
            return Some(found);
        }
        // Meta AI envelope: base64-decode `payload` and filter proto strings.
        if let Some(serde_json::Value::String(b64_payload)) = value.get("payload") {
            if let Some(found) = prompt_from_meta_ai_payload(b64_payload) {
                return Some(found);
            }
        }
    }
    // Pass 2: pure-protobuf fallback — scan length-delimited string fields
    // and pick the longest readable one, filtering out noise.
    let strings = soth_parse::proto::scan_proto_strings(payload);
    pick_user_prompt_from_proto_strings(&strings)
}

/// Meta AI Clippy wraps the client-side request as
/// `{"req-id": "...", "payload": "<base64 protobuf>"}`.  Base64-decode the
/// payload and pull the user's typed message out of the inner protobuf by
/// scanning length-delimited string fields and filtering noise.
fn prompt_from_meta_ai_payload(b64: &str) -> Option<String> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let strings = soth_parse::proto::scan_proto_strings(&decoded);
    pick_user_prompt_from_proto_strings(&strings)
}

/// Noise filter for proto-scanned strings.  Strips UUIDs, pure numerics,
/// user agents, locale / timezone strings, file hashes, and known Meta AI
/// system enum values so the remaining short strings surface the actual
/// user prompt.
fn pick_user_prompt_from_proto_strings(strings: &[(u32, String)]) -> Option<String> {
    fn looks_like_uuid(s: &str) -> bool {
        let s = s.trim_start_matches('$');
        let bytes = s.as_bytes();
        bytes.len() >= 32
            && bytes.iter().filter(|b| **b == b'-').count() >= 4
            && bytes.iter().all(|b| b.is_ascii_hexdigit() || *b == b'-')
    }
    fn looks_like_hash(s: &str) -> bool {
        s.len() >= 32 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
    fn looks_like_numeric_id(s: &str) -> bool {
        s.len() >= 6 && s.chars().all(|c| c.is_ascii_digit())
    }
    fn is_all_caps_enum(s: &str) -> bool {
        // Matches strings like KADABRA__CHAT__UNIFIED_INPUT_BAR, HUMAN_AGENT, ECTO1.
        s.len() >= 3
            && s.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    }
    const BLACKLIST_SUBSTRINGS: &[&str] = &[
        "Mozilla",
        "AppleWebKit",
        "Mac OS",
        "Windows NT",
        "Linux",
        "Chrome/",
        "Safari/",
        "Firefox/",
        "user_input",
        "desktop_web",
        "mobile_web",
        "Asia/",
        "America/",
        "Europe/",
        "Africa/",
        "en-GB",
        "en-US",
        "meta_knowledge",
        "meta_catalog",
        "media_gallery",
        "Abra Web",
        "stocks",
        "weather",
    ];

    // Collect candidates that survive the filters.  Meta AI places the
    // actual prompt near the end of the protobuf, so walk in reverse and
    // return the first survivor — that's almost always the user text.
    for (_field, s) in strings.iter().rev() {
        let trimmed = s.trim().trim_matches('"').trim_matches('$');
        if trimmed.len() < 2 {
            continue;
        }
        if looks_like_uuid(trimmed) || looks_like_hash(trimmed) || looks_like_numeric_id(trimmed) {
            continue;
        }
        if is_all_caps_enum(trimmed) {
            continue;
        }
        if BLACKLIST_SUBSTRINGS
            .iter()
            .any(|needle| trimmed.contains(needle))
        {
            continue;
        }
        // Skip strings that look like base64/nonces (mixed alnum, no spaces,
        // long, no punctuation).  User prompts typically have spaces or are
        // short and printable; fingerprint hashes are 20+ chars of mixed
        // alnum with no spaces.
        if trimmed.len() >= 20
            && !trimmed.contains(' ')
            && trimmed
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.')
        {
            continue;
        }
        return Some(trimmed.to_string());
    }
    None
}

/// Recursive DFS looking for `PROMPT_FIELDS` keys with a non-empty string
/// value.  Bounded by depth to avoid pathological payloads.
fn find_prompt_in_value(value: &serde_json::Value, fields: &[&str]) -> Option<String> {
    fn recurse(v: &serde_json::Value, fields: &[&str], depth: u32) -> Option<String> {
        if depth > 8 {
            return None;
        }
        match v {
            serde_json::Value::Object(map) => {
                for key in fields {
                    if let Some(serde_json::Value::String(s)) = map.get(*key) {
                        if !s.trim().is_empty() {
                            return Some(s.clone());
                        }
                    }
                }
                for (_, child) in map {
                    if let Some(found) = recurse(child, fields, depth + 1) {
                        return Some(found);
                    }
                }
                None
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    if let Some(found) = recurse(item, fields, depth + 1) {
                        return Some(found);
                    }
                }
                None
            }
            _ => None,
        }
    }
    recurse(value, fields, 0)
}

/// Extract JSON objects from a binary frame by scanning for `{` and
/// attempting to parse balanced brace-delimited substrings as JSON.
/// Used for protocols that wrap JSON inside binary envelopes (e.g. Meta AI's
/// PROTO_INSIDE_JSON format).
pub(crate) fn extract_json_from_binary(payload: &[u8]) -> Vec<String> {
    let mut results = Vec::new();
    let mut i = 0;
    while i < payload.len() {
        if payload[i] == b'{' {
            // Try to find matching closing brace
            let mut depth = 0i32;
            let mut in_string = false;
            let mut escape = false;
            let mut end = i;
            for j in i..payload.len() {
                let b = payload[j];
                if escape {
                    escape = false;
                    continue;
                }
                if b == b'\\' && in_string {
                    escape = true;
                    continue;
                }
                if b == b'"' {
                    in_string = !in_string;
                    continue;
                }
                if !in_string {
                    if b == b'{' {
                        depth += 1;
                    } else if b == b'}' {
                        depth -= 1;
                        if depth == 0 {
                            end = j + 1;
                            break;
                        }
                    }
                }
            }
            if depth == 0 && end > i {
                if let Ok(text) = std::str::from_utf8(&payload[i..end]) {
                    // Validate it's actual JSON by checking for common keys
                    if text.contains("\"seq\"")
                        || text.contains("\"type\"")
                        || text.contains("\"event\"")
                        || text.contains("\"code\"")
                        || text.contains("\"response\"")
                        || text.contains("\"operations\"")
                    {
                        results.push(text.to_string());
                    }
                }
                i = end;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    results
}

fn looks_like_protobuf_payload(payload: &[u8]) -> bool {
    if payload.len() < 2 {
        return false;
    }

    let first = payload[0];
    // gRPC framing: 0x00 (uncompressed) or 0x01 (compressed) followed by 4-byte length
    if (first == 0 || first == 1) && payload.len() >= 5 {
        return true;
    }

    // Protobuf varint tag: require a small field number (1-15) with a common
    // wire type (0=varint, 1=fixed64, 2=length-delimited). This avoids
    // matching most ASCII text which the previous `wire <= 5` caught.
    let wire = first & 0x07;
    let field_number = first >> 3;
    wire <= 2 && (1..=15).contains(&field_number)
}

fn extract_structured_text(payload: &[u8]) -> Option<String> {
    parse_graphql_payload_text(payload)
        .or_else(|| extract_sse_rest_delta(payload))
        .or_else(|| extract_gemini_length_prefixed(payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::OwnedDetectBundle;
    use soth_core::ArtifactKind;
    use soth_parse::proto::scan_proto_strings;
    use uuid::Uuid;

    #[test]
    fn full_capture_chunk_emits_credential_artifacts() {
        let bundle = OwnedDetectBundle::default();
        let mut session = StreamSession::new(Uuid::new_v4(), CaptureMode::Full);
        let chunk = StreamChunk {
            connection_id: session.connection_id,
            sequence: 7,
            payload: Bytes::from_static(
                b"data: {\"delta\":{\"content\":\"token sk-abcdefghijklmnopqrstuvwxyz1234\"}}\n\n",
            ),
            frame_kind: FrameKind::SseData,
            direction: None,
        };

        let event = process_chunk_with_bundle(&chunk, &mut session, &bundle.as_slice());
        let event = event.expect("full capture should emit artifact on credential pattern");
        match event {
            ChunkEvent::Artifact(out) => {
                assert_eq!(out.sequence, 7);
                assert!(out
                    .artifacts
                    .iter()
                    .any(|a| matches!(a.kind, ArtifactKind::ApiKey { .. })));
            }
            ChunkEvent::TurnCompleted(_) => panic!("expected Artifact, got TurnCompleted"),
            ChunkEvent::TurnRequest(_) => panic!("expected Artifact, got TurnRequest"),
        }
    }

    #[test]
    fn metadata_only_chunk_does_not_emit_credential_artifacts() {
        let bundle = OwnedDetectBundle::default();
        let mut session = StreamSession::new(Uuid::new_v4(), CaptureMode::MetadataOnly);
        let chunk = StreamChunk {
            connection_id: session.connection_id,
            sequence: 1,
            payload: Bytes::from_static(
                b"data: {\"delta\":{\"content\":\"token sk-abcdefghijklmnopqrstuvwxyz1234\"}}\n\n",
            ),
            frame_kind: FrameKind::SseData,
            direction: None,
        };

        let out = process_chunk_with_bundle(&chunk, &mut session, &bundle.as_slice());
        assert!(out.is_none());
    }

    #[test]
    fn finalize_stream_detect_honors_capture_mode_and_content() {
        let mut session = StreamSession::new(Uuid::new_v4(), CaptureMode::SensitiveArtifacts);
        session.accumulate("hello ");
        session.accumulate("sk-abcdefghijklmnopqrstuvwxyz1234");

        let out = finalize_stream_detect(session);
        assert_eq!(out.confidence, ParseConfidence::Heuristic);
        assert!(matches!(out.parse_source, ParseSource::Heuristic));
        assert_eq!(out.capture_mode, CaptureMode::SensitiveArtifacts);
        assert!(!out.artifacts.is_empty());
    }

    #[test]
    fn scan_proto_strings_extracts_length_delimited_fields() {
        let payload = encode_proto_string_fields(&[(1, "abc"), (2, "hello grpc response")]);
        let extracted = scan_proto_strings(payload.as_slice());

        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].0, 2);
        assert_eq!(extracted[0].1, "hello grpc response");
    }

    fn encode_proto_string_fields(entries: &[(u32, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (field_number, text) in entries {
            let tag = ((*field_number as u64) << 3) | 2;
            encode_varint(tag, &mut out);
            encode_varint(text.len() as u64, &mut out);
            out.extend_from_slice(text.as_bytes());
        }
        out
    }

    fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
        loop {
            if value < 0x80 {
                out.push(value as u8);
                break;
            }
            out.push(((value & 0x7f) as u8) | 0x80);
            value >>= 7;
        }
    }

    #[test]
    fn extract_sse_rest_delta_openai_format() {
        let payload = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\n";
        let result = super::sse::extract_sse_rest_delta(payload);
        assert_eq!(result.as_deref(), Some("Hello world"));
    }

    #[test]
    fn extract_sse_rest_delta_anthropic_format() {
        let payload = b"data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"Hello\"}}\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\" world\"}}\n";
        let result = super::sse::extract_sse_rest_delta(payload);
        assert_eq!(result.as_deref(), Some("Hello world"));
    }

    #[test]
    fn extract_sse_rest_delta_skips_done() {
        let payload = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\ndata: [DONE]\n";
        let result = super::sse::extract_sse_rest_delta(payload);
        assert_eq!(result.as_deref(), Some("Hi"));
    }

    #[test]
    fn extract_structured_text_handles_bare_json_delta() {
        // A bare JSON object without data: prefix should still be extracted
        let payload = br#"{"choices":[{"delta":{"content":"bare json"}}]}"#;
        let result = super::extract_structured_text(payload);
        assert!(result.is_some(), "bare JSON delta should be extracted");
    }

    #[test]
    fn extract_sse_model_anthropic_message_start() {
        let payload = b"data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-6\",\"role\":\"assistant\"}}\n";
        let model = super::sse::extract_sse_model(payload);
        assert_eq!(model.as_deref(), Some("claude-sonnet-4-6"));
    }

    #[test]
    fn extract_sse_model_openai_top_level() {
        let payload =
            b"data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n";
        let model = super::sse::extract_sse_model(payload);
        assert_eq!(model.as_deref(), Some("gpt-4o"));
    }

    #[test]
    fn extract_sse_model_chatgpt_metadata_slug() {
        let payload = b"data: {\"metadata\":{\"model_slug\":\"gpt-4o\",\"finish_details\":{}}}\n";
        let model = super::sse::extract_sse_model(payload);
        assert_eq!(model.as_deref(), Some("gpt-4o"));
    }

    #[test]
    fn extract_sse_model_grok_ndjson() {
        let payload = b"{\"result\":{\"modelResponse\":{\"model\":\"grok-3\"}}}\n";
        let model = super::sse::extract_sse_model(payload);
        assert_eq!(model.as_deref(), Some("grok-3"));
    }

    #[test]
    fn extract_sse_model_perplexity_display_model() {
        let payload = b"data: {\"display_model\":\"sonar-pro\",\"answer\":\"...\"}\n";
        let model = super::sse::extract_sse_model(payload);
        assert_eq!(model.as_deref(), Some("sonar-pro"));
    }

    #[test]
    fn extract_sse_model_none_for_content_only() {
        let payload = b"data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hello\"}}\n";
        let model = super::sse::extract_sse_model(payload);
        assert!(model.is_none());
    }

    #[test]
    fn sse_model_populates_session() {
        let bundle = OwnedDetectBundle::default();
        let mut session = StreamSession::new(Uuid::new_v4(), CaptureMode::MetadataOnly);
        assert!(session.model.is_none());

        let chunk = StreamChunk {
            connection_id: session.connection_id,
            sequence: 1,
            payload: Bytes::from_static(
                b"data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-6\"}}\n",
            ),
            frame_kind: FrameKind::SseData,
            direction: None,
        };
        process_chunk_with_bundle(&chunk, &mut session, &bundle.as_slice());
        assert_eq!(session.model.as_deref(), Some("claude-sonnet-4-6"));
    }

    #[test]
    fn sse_model_first_wins() {
        let bundle = OwnedDetectBundle::default();
        let mut session = StreamSession::new(Uuid::new_v4(), CaptureMode::MetadataOnly);

        // First chunk sets model
        let chunk1 = StreamChunk {
            connection_id: session.connection_id,
            sequence: 1,
            payload: Bytes::from_static(
                b"data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n",
            ),
            frame_kind: FrameKind::SseData,
            direction: None,
        };
        process_chunk_with_bundle(&chunk1, &mut session, &bundle.as_slice());
        assert_eq!(session.model.as_deref(), Some("gpt-4o"));

        // Second chunk with different model is ignored
        let chunk2 = StreamChunk {
            connection_id: session.connection_id,
            sequence: 2,
            payload: Bytes::from_static(
                b"data: {\"model\":\"gpt-4o-mini\",\"choices\":[{\"delta\":{\"content\":\" there\"}}]}\n",
            ),
            frame_kind: FrameKind::SseData,
            direction: None,
        };
        process_chunk_with_bundle(&chunk2, &mut session, &bundle.as_slice());
        assert_eq!(
            session.model.as_deref(),
            Some("gpt-4o"),
            "first model should win"
        );
    }

    #[test]
    fn sse_chunk_accumulates_in_session() {
        let bundle = OwnedDetectBundle::default();
        let mut session = StreamSession::new(Uuid::new_v4(), CaptureMode::MetadataOnly);
        let chunk = StreamChunk {
            connection_id: session.connection_id,
            sequence: 1,
            payload: Bytes::from_static(
                b"data: {\"choices\":[{\"delta\":{\"content\":\"streaming content\"}}]}\n\n",
            ),
            frame_kind: FrameKind::SseData,
            direction: None,
        };

        process_chunk_with_bundle(&chunk, &mut session, &bundle.as_slice());
        let content = session.finalize_response_content();
        assert!(
            content.contains("streaming content"),
            "SSE content should be accumulated, got: {content}"
        );
    }

    // --- Web app streaming tests ---

    #[test]
    fn extract_chatgpt_web_content() {
        let payload = br#"data: {"message":{"content":{"parts":["Hello from ChatGPT"]}}}"#;
        let result = super::sse::extract_sse_rest_delta(payload);
        assert_eq!(result.as_deref(), Some("Hello from ChatGPT"));
    }

    #[test]
    fn extract_chatgpt_web_replaces_content() {
        // ChatGPT web sends full accumulated content, last one wins
        let payload = b"data: {\"message\":{\"content\":{\"parts\":[\"Hello\"]}}}\ndata: {\"message\":{\"content\":{\"parts\":[\"Hello world\"]}}}\n";
        let result = super::sse::extract_sse_rest_delta(payload);
        assert_eq!(result.as_deref(), Some("Hello world"));
    }

    #[test]
    fn extract_chatgpt_web_model_slug() {
        let payload = b"data: {\"message\":{\"metadata\":{\"model_slug\":\"gpt-4o\"},\"content\":{\"parts\":[\"Hi\"]}}}\n";
        let model = super::sse::extract_sse_model(payload);
        assert_eq!(model.as_deref(), Some("gpt-4o"));
    }

    #[test]
    fn extract_grok_web_content() {
        let payload = br#"{"result":{"response":{"text":"Hello from Grok"}}}"#;
        let result = super::sse::extract_sse_rest_delta(payload);
        assert_eq!(result.as_deref(), Some("Hello from Grok"));
    }

    #[test]
    fn extract_grok_web_replaces_content() {
        let payload = b"{\"result\":{\"response\":{\"text\":\"Hello\"}}}\n{\"result\":{\"response\":{\"text\":\"Hello from Grok\"}}}\n";
        let result = super::sse::extract_sse_rest_delta(payload);
        assert_eq!(result.as_deref(), Some("Hello from Grok"));
    }

    #[test]
    fn extract_claude_web_completion() {
        let payload = b"data: {\"completion\":\"Hello\"}\ndata: {\"completion\":\" Claude\"}\n";
        let result = super::sse::extract_sse_rest_delta(payload);
        assert_eq!(result.as_deref(), Some("Hello Claude"));
    }

    #[test]
    fn extract_perplexity_web_text() {
        let payload = b"data: {\"text\":\"Search result\",\"display_model\":\"sonar-pro\"}\n";
        let result = super::sse::extract_sse_rest_delta(payload);
        assert_eq!(result.as_deref(), Some("Search result"));
    }

    #[test]
    fn extract_perplexity_web_model() {
        let payload = b"data: {\"display_model\":\"sonar-pro\",\"text\":\"answer\"}\n";
        let model = super::sse::extract_sse_model(payload);
        assert_eq!(model.as_deref(), Some("sonar-pro"));
    }

    #[test]
    fn extract_deepseek_web_delta() {
        let payload = b"data: {\"choices\":[{\"delta\":{\"content\":\"Deep\"}}]}\ndata: {\"choices\":[{\"delta\":{\"content\":\"Seek\"}}]}\n";
        let result = super::sse::extract_sse_rest_delta(payload);
        assert_eq!(result.as_deref(), Some("DeepSeek"));
    }

    #[test]
    fn gemini_length_prefixed_extracts_content_at_0_2() {
        let payload = b")]}'\n[null,null,\"Hello from Gemini via path zero-two\"]";
        let result = super::gemini::extract_gemini_length_prefixed(payload);
        assert_eq!(
            result.as_deref(),
            Some("Hello from Gemini via path zero-two")
        );
    }

    #[test]
    fn gemini_length_prefixed_extracts_at_4_0_1_0() {
        let payload = br#")]}'
[null,null,null,null,[["unused","This is the full Gemini response content for testing"]]]"#;
        let result = super::gemini::extract_gemini_length_prefixed(payload);
        assert_eq!(
            result.as_deref(),
            Some("This is the full Gemini response content for testing")
        );
    }

    #[test]
    fn gemini_length_prefixed_fallback_longest_string() {
        let payload = br#")]}'
{"some_field": "short", "nested": {"deep": "This is a long enough response from Gemini web app streaming format"}}"#;
        let result = super::gemini::extract_gemini_length_prefixed(payload);
        assert!(result.is_some(), "should find longest string in JSON tree");
        assert!(result.unwrap().contains("long enough response"));
    }

    #[test]
    fn gemini_length_prefixed_not_triggered_without_header() {
        // Without )]}'  prefix, should return None
        let payload = b"[null,null,\"some content\"]";
        let result = super::gemini::extract_gemini_length_prefixed(payload);
        assert!(result.is_none(), "should not match without header prefix");
    }

    #[test]
    fn descriptor_driven_content_extraction() {
        use crate::types::{RestFormatDescriptor, RestResponsePaths};

        let desc = RestFormatDescriptor {
            response: RestResponsePaths {
                content: Some("$.result.response.text".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let payload = br#"{"result":{"response":{"text":"descriptor-driven content"}}}"#;
        let result = super::sse::extract_delta_with_descriptor(payload, Some(&desc));
        assert_eq!(result.as_deref(), Some("descriptor-driven content"));
    }

    #[test]
    fn descriptor_driven_model_extraction() {
        use crate::types::{RestFormatDescriptor, RestResponsePaths};

        let desc = RestFormatDescriptor {
            response: RestResponsePaths {
                model: Some("$.result.modelResponse.model".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let payload = br#"{"result":{"modelResponse":{"model":"grok-3"}}}"#;
        let result = super::sse::extract_model_with_descriptor(payload, Some(&desc));
        assert_eq!(result.as_deref(), Some("grok-3"));
    }

    #[test]
    fn descriptor_driven_sse_content() {
        use crate::types::{RestFormatDescriptor, RestResponsePaths};

        let desc = RestFormatDescriptor {
            response: RestResponsePaths {
                content: Some("$.message.content.parts[0]".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let payload = b"data: {\"message\":{\"content\":{\"parts\":[\"SSE via descriptor\"]}}}\n";
        let result = super::sse::extract_delta_with_descriptor(payload, Some(&desc));
        assert_eq!(result.as_deref(), Some("SSE via descriptor"));
    }

    // --- OpenAI Responses API (Codex) streaming tests ---

    #[test]
    fn extract_responses_api_delta_sse() {
        let payload =
            b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hello world\"}\n";
        let result = super::sse::extract_sse_rest_delta(payload);
        assert_eq!(result.as_deref(), Some("Hello world"));
    }

    #[test]
    fn extract_responses_api_delta_bare_json() {
        // WebSocket mode: bare JSON without data: prefix
        let payload = br#"{"type":"response.output_text.delta","delta":"from websocket"}"#;
        let result = super::sse::extract_sse_rest_delta(payload);
        assert_eq!(result.as_deref(), Some("from websocket"));
    }

    #[test]
    fn extract_responses_api_model_from_created() {
        let payload = b"data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_123\",\"model\":\"o3-pro\"}}\n";
        let model = super::sse::extract_sse_model(payload);
        assert_eq!(model.as_deref(), Some("o3-pro"));
    }

    #[test]
    fn extract_responses_api_model_bare_json() {
        // WebSocket mode
        let payload =
            br#"{"type":"response.created","response":{"id":"resp_123","model":"o3-pro"}}"#;
        let model = super::sse::extract_sse_model(payload);
        assert_eq!(model.as_deref(), Some("o3-pro"));
    }

    #[test]
    fn websocket_frame_extracts_model() {
        let bundle = OwnedDetectBundle::default();
        let mut session = StreamSession::new(Uuid::new_v4(), CaptureMode::MetadataOnly);

        let chunk = StreamChunk {
            connection_id: session.connection_id,
            sequence: 1,
            payload: Bytes::from_static(
                br#"{"type":"response.created","response":{"id":"resp_1","model":"o3-pro"}}"#,
            ),
            frame_kind: FrameKind::WebSocketText,
            direction: None,
        };
        process_chunk_with_bundle(&chunk, &mut session, &bundle.as_slice());
        assert_eq!(session.model.as_deref(), Some("o3-pro"));
    }

    #[test]
    fn websocket_frame_accumulates_responses_api_delta() {
        let bundle = OwnedDetectBundle::default();
        let mut session = StreamSession::new(Uuid::new_v4(), CaptureMode::MetadataOnly);

        for (seq, text) in [(1, "Hello"), (2, " world")] {
            let payload = format!(r#"{{"type":"response.output_text.delta","delta":"{text}"}}"#,);
            let chunk = StreamChunk {
                connection_id: session.connection_id,
                sequence: seq,
                payload: Bytes::from(payload),
                frame_kind: FrameKind::WebSocketText,
                direction: Some(FrameDirection::ServerToClient),
            };
            process_chunk_with_bundle(&chunk, &mut session, &bundle.as_slice());
        }

        let content = session.finalize_response_content();
        assert_eq!(content, "Hello world");
    }
}
