use crate::graphql::parse_graphql_payload_text;
use crate::grpc::parse_grpc_chunk_payload;
use crate::hash::hash_content;
use crate::sensitive::credential_scan;
use crate::types::{
    ArtifactLocation, CaptureMode, ChunkArtifact, DetectBundleSlice, FrameKind, StreamChunk,
    StreamSession, StreamSummary,
};

pub fn process_chunk(
    chunk: &StreamChunk,
    session: &mut StreamSession,
    bundle: &DetectBundleSlice<'_>,
) -> Option<ChunkArtifact> {
    session.chunk_count += 1;

    match chunk.frame_kind {
        FrameKind::SseData | FrameKind::NdjsonLine => {
            if let Some(delta) = parse_graphql_payload_text(&chunk.payload) {
                session.accumulate(delta);
            }
        }
        FrameKind::WebSocketText => {
            if let Some(delta) = parse_graphql_payload_text(&chunk.payload) {
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
                if !text.trim().is_empty() {
                    session.accumulate(text.to_string());
                }
            }
        }
        FrameKind::WebSocketClose => {}
    }

    if session.capture_mode == CaptureMode::Full {
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

pub fn finalize_stream(session: StreamSession) -> StreamSummary {
    let assembled = session.finalize_response_content();
    StreamSummary {
        response_hash: hash_content(&assembled),
        chunk_count: session.chunk_count,
        elapsed_ms: session.start_time.elapsed().as_millis(),
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
