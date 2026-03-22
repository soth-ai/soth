use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::identity::ConnectionMeta;

pub type RequestHeaders = BTreeMap<String, String>;

#[derive(Debug, Clone)]
pub struct RawRequest {
    pub method: String,
    pub path: String,
    pub headers: RequestHeaders,
    pub body: Bytes,
    pub connection_meta: ConnectionMeta,
}

#[derive(Debug, Clone)]
pub struct RawResponse {
    pub status: u16,
    pub headers: RequestHeaders,
    pub body: Bytes,
    pub connection_meta: ConnectionMeta,
}

#[derive(Debug, Clone)]
pub struct StreamChunk {
    pub connection_id: Uuid,
    pub payload: Bytes,
    pub sequence: u64,
    pub frame_kind: FrameKind,
    /// WebSocket frame direction. `None` for SSE/NDJSON/gRPC (always server→client).
    pub direction: Option<FrameDirection>,
}

/// Direction of a WebSocket frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameDirection {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameKind {
    SseData,
    NdjsonLine,
    GrpcMessage,
    WebSocketText,
    WebSocketBinary,
    MultipartMixed,
    WebSocketClose,
}
