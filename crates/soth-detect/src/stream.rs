use crate::graphql::parse_graphql_payload_text;
use crate::grpc::parse_grpc_chunk_payload;
use crate::hash::hash_content;
use crate::jsonrpc::parse_jsonrpc_payload_text;
use crate::sensitive::credential_scan;
use crate::types::{
    ArtifactLocation, CaptureMode, ChunkArtifact, DetectBundleSlice, DetectResult, DetectWarning,
    FrameKind, ParseConfidence, ParseSource, StreamChunk, StreamSession, StreamSummary,
};
use bytes::Bytes;

pub fn process_chunk_with_bundle(
    chunk: &StreamChunk,
    session: &mut StreamSession,
    bundle: &DetectBundleSlice<'_>,
) -> Option<ChunkArtifact> {
    session.chunk_count += 1;

    match chunk.frame_kind {
        FrameKind::SseData | FrameKind::NdjsonLine => {
            if let Some(delta) = extract_structured_text(&chunk.payload) {
                session.accumulate(delta);
            }
        }
        FrameKind::WebSocketText => {
            if let Some(delta) = extract_structured_text(&chunk.payload)
                .or_else(|| parse_multipart_payload_text(&chunk.payload))
            {
                session.accumulate(delta);
            } else if let Ok(text) = std::str::from_utf8(&chunk.payload) {
                if !text.trim().is_empty() {
                    session.accumulate(text.to_string());
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
            if looks_like_protobuf_payload(&chunk.payload) {
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
            return Some(ChunkArtifact {
                sequence: chunk.sequence,
                artifacts,
            });
        }
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

pub fn finalize_stream_detect(session: StreamSession) -> DetectResult {
    let summary = finalize_stream_summary(session.clone());
    let assembled = session.finalize_response_content();

    let mut normalized = crate::types::NormalizedRequest::empty_heuristic("STREAM", "/stream");

    // Carry through request context if available
    if let Some(provider) = &session.provider {
        normalized.provider = crate::types::Provider::new(provider.clone());
    }
    if session.model.is_some() {
        normalized.model = session.model.clone();
    }
    if let Some(format) = &session.request_format {
        normalized.format_meta = format.clone();
    }
    normalized.estimated_input_tokens = session.estimated_input_tokens;

    let token_estimate = ((assembled.len() as f32) / 4.0).ceil() as u32;
    normalized.is_ai_call = !assembled.is_empty();
    normalized.user_content_hash = summary.response_hash.clone();
    normalized.user_content_token_estimate = token_estimate;
    normalized.conversation_hash = summary.response_hash.clone();
    normalized.canonical_hash = summary.response_hash.clone();
    normalized.content_sample = if assembled.is_empty() {
        None
    } else {
        Some(assembled.clone())
    };

    let capture_mode = session.capture_mode;
    let full_like = matches!(
        capture_mode,
        CaptureMode::Full | CaptureMode::SensitiveArtifacts | CaptureMode::FullContent
    );
    let artifacts = if full_like {
        credential_scan(assembled.as_bytes(), ArtifactLocation::Unknown)
    } else {
        Vec::new()
    };

    let mut warnings = Vec::new();
    warnings.push(DetectWarning {
        code: "stream_finalize_heuristic",
        detail: "stream finalized using heuristic normalization".to_string(),
    });

    DetectResult {
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

pub fn scan_proto_strings(payload: &[u8]) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let mut cursor = 0usize;

    while cursor < payload.len() {
        let (tag, wire_type, advance) = match read_varint_tag(&payload[cursor..]) {
            Some(data) => data,
            None => break,
        };
        cursor += advance;

        if wire_type == 2 {
            let (len, len_advance) = match read_varint_len(&payload[cursor..]) {
                Some(data) => data,
                None => break,
            };
            cursor += len_advance;

            if cursor + len > payload.len() {
                break;
            }

            let bytes = &payload[cursor..cursor + len];
            if let Ok(text) = std::str::from_utf8(bytes) {
                if text.len() > 5 {
                    out.push((tag >> 3, text.to_string()));
                }
            }
            cursor += len;
        } else {
            let skip = skip_wire_type(wire_type, &payload[cursor..]);
            if skip == 0 {
                break;
            }
            cursor += skip;
        }
    }

    out
}

fn read_varint_tag(bytes: &[u8]) -> Option<(u32, u8, usize)> {
    let (value, advance) = read_varint(bytes)?;
    if value == 0 {
        return None;
    }
    let wire_type = (value & 0x07) as u8;
    Some((value as u32, wire_type, advance))
}

fn read_varint_len(bytes: &[u8]) -> Option<(usize, usize)> {
    let (value, advance) = read_varint(bytes)?;
    Some((value as usize, advance))
}

fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;

    for (index, byte) in bytes.iter().enumerate() {
        let part = (byte & 0x7f) as u64;
        value |= part << shift;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }

    None
}

fn skip_wire_type(wire_type: u8, bytes: &[u8]) -> usize {
    match wire_type {
        0 => read_varint(bytes).map(|(_, n)| n).unwrap_or(0),
        1 => 8,
        2 => {
            if let Some((len, adv)) = read_varint_len(bytes) {
                adv.saturating_add(len)
            } else {
                0
            }
        }
        5 => 4,
        _ => 0,
    }
}

fn looks_like_protobuf_payload(payload: &[u8]) -> bool {
    if payload.is_empty() {
        return false;
    }

    let first = payload[0];
    if first == 0 || first == 1 {
        return true;
    }

    // For unknown WS binary frames, we probe protobuf-like varint tag layout.
    // Lower 3 bits are wire type and should typically be <= 5.
    let wire = first & 0x07;
    wire <= 5
}

fn extract_structured_text(payload: &[u8]) -> Option<String> {
    parse_graphql_payload_text(payload).or_else(|| parse_jsonrpc_payload_text(payload))
}

fn parse_multipart_payload_text(payload: &[u8]) -> Option<String> {
    if let Some(delta) = extract_structured_text(payload) {
        return Some(delta);
    }

    let text = std::str::from_utf8(payload).ok()?;
    let boundary = text.lines().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.starts_with("--") && trimmed.len() > 2 {
            Some(trimmed.to_string())
        } else {
            None
        }
    })?;

    for part in text.split(&boundary).skip(1) {
        let trimmed = part.trim();
        if trimmed.is_empty() || trimmed == "--" {
            continue;
        }

        let body = part
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .or_else(|| part.split_once("\n\n").map(|(_, body)| body));
        let Some(body) = body else {
            continue;
        };

        let body = body.trim().trim_end_matches("--").trim();
        if body.is_empty() {
            continue;
        }

        if let Some(delta) = extract_structured_text(body.as_bytes()) {
            return Some(delta);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ArtifactType, OwnedDetectBundle};
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
        };

        let out = process_chunk_with_bundle(&chunk, &mut session, &bundle.as_slice());
        let out = out.expect("full capture should emit artifact on credential pattern");
        assert_eq!(out.sequence, 7);
        assert!(out
            .artifacts
            .iter()
            .any(|a| matches!(a.artifact_type, ArtifactType::OpenAIKey)));
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
}
