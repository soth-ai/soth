pub mod code;
mod engine;
#[cfg(feature = "intelligence")]
mod intelligence;
#[cfg(feature = "intelligence")]
mod intelligence_backends;
#[cfg(feature = "intelligence-sqlite")]
mod intelligence_store;
#[cfg(feature = "intelligence-sqlite")]
mod replay;
pub mod sensitive;
mod stream;
mod types;
mod util;

// Crate-visible module aliases so internal modules can keep using
// `crate::X::item` paths without modification.
//
// `fingerprint_mod` is the alias for `soth_parse::fingerprint`; `engine.rs`
// and `lib.rs` use this name to avoid a name clash with the public `fingerprint`
// function re-exported into the crate root below.
pub(crate) use soth_parse::fingerprint as fingerprint_mod;
pub(crate) use soth_parse::graphql;
pub(crate) use soth_parse::grpc;
pub(crate) use soth_parse::hash;
pub(crate) use soth_parse::heuristic;
pub(crate) use soth_parse::jsonrpc;
pub(crate) use soth_parse::rest;

use once_cell::sync::Lazy;

pub use engine::{process, process_with_registry, to_core_detect_result, ParserRegistry};
#[cfg(feature = "intelligence")]
pub use intelligence::*;
#[cfg(feature = "intelligence")]
pub use intelligence_backends::{InMemoryBackend, NoopBackend};
#[cfg(feature = "intelligence-sqlite")]
pub use intelligence_store::IntelligenceStore;
#[cfg(feature = "intelligence-sqlite")]
pub use replay::replay_heuristic_events;
pub use soth_parse::fingerprint::{
    classify_request, classify_request_pair, fingerprint, ClassifyPairResult, ClassifyResult,
};
pub use soth_parse::proto::scan_proto_strings;
pub use stream::{finalize_stream_summary, process_chunk_with_bundle, ChunkEvent};
pub use types::*;

#[cfg(feature = "intelligence")]
pub use engine::{process_with_intelligence, process_with_registry_and_intelligence};

/// Trait alias for the SDK-facing intelligence backend abstraction.
///
/// The proxy uses the SQLite-backed [`IntelligenceStore`] (gated behind
/// `intelligence-sqlite`); the SDK and tests use [`NoopBackend`] or
/// [`InMemoryBackend`]. Anything implementing [`IntelligenceSink`] works.
#[cfg(feature = "intelligence")]
pub use intelligence::IntelligenceSink as IntelligenceBackend;

// Re-export soth_core::SessionSnapshot so callers can reference it without
// directly depending on soth_core for this type.
pub use soth_core::SessionSnapshot;

pub type StreamDetectState = StreamSession;
pub type PartialDetectResult = ChunkArtifact;

#[derive(Debug, Clone)]
pub struct DetectError {
    detail: String,
}

impl DetectError {
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for DetectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.detail)
    }
}

impl std::error::Error for DetectError {}

pub fn build_registry(bundle: &DetectBundleSlice<'_>) -> Result<ParserRegistry, DetectError> {
    let apq_cache_capacity = bundle.graphql_operations.operations.len().clamp(512, 4096);
    Ok(ParserRegistry::with_org_patterns(
        apq_cache_capacity,
        bundle.org_patterns,
    ))
}

pub fn process_chunk(chunk: &StreamChunk, state: &mut StreamDetectState) -> Option<ChunkEvent> {
    static EMPTY_BUNDLE: Lazy<OwnedDetectBundle> = Lazy::new(OwnedDetectBundle::default);
    stream::process_chunk_with_bundle(chunk, state, &EMPTY_BUNDLE.as_slice())
}

pub fn finalize_stream(state: StreamDetectState) -> soth_core::DetectResult {
    to_core_detect_result(&stream::finalize_stream_detect(state))
}

/// Resolve the `api_format` for a request by matching host + path against
/// entity matching rules in the bundle. Used by WebSocket stream sessions
/// where the initial GET has no body and format can't be fingerprinted.
pub fn classify_request_format(
    host: &str,
    path: &str,
    bundle: &DetectBundleSlice<'_>,
) -> Option<String> {
    let empty_headers = std::collections::BTreeMap::new();
    let pair = fingerprint_mod::classify_request_pair(
        Some(host),
        path,
        &empty_headers,
        None,
        None,
        None,
        bundle,
    );
    // Prefer application match (more specific path rules) over provider
    if let Some(app) = &pair.application {
        if let Some(entry) = bundle.products.get(&app.entity_id) {
            if let Some(fmt) = entry.api_format.as_deref() {
                return Some(fmt.to_string());
            }
        }
    }
    if let Some(prov) = &pair.provider {
        if let Some(entry) = bundle.llm_providers.get(&prov.entity_id) {
            if let Some(fmt) = entry.api_format.as_deref() {
                return Some(fmt.to_string());
            }
        }
        // Provider might be in applications (product entities)
        if let Some(entry) = bundle.products.get(&prov.entity_id) {
            if let Some(fmt) = entry.api_format.as_deref() {
                return Some(fmt.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use soth_core::{
        CaptureRules, GraphQLOperationRegistry, GraphQLOperationSpec, GrpcServiceRegistry,
        OwnedDetectBundle, ProviderEntry, RestFormatDescriptor, RestRequestPaths,
    };
    use std::collections::{BTreeMap, HashMap};
    use std::net::{Ipv4Addr, SocketAddrV4};
    use uuid::Uuid;

    #[test]
    fn filtered_request_short_circuits() {
        let mut bundle = bundle_fixture();
        bundle.filters.path_keywords = vec!["/health".to_string()];

        let request = RawRequest {
            method: "GET".to_string(),
            path: "/health".to_string(),
            headers: BTreeMap::new(),
            body: Bytes::new(),
            connection_meta: connection_meta_tcp(),
        };

        let out = process(
            &request,
            &bundle.as_slice(),
            &soth_core::SessionSnapshot::default(),
        );
        assert!(matches!(out.parse_source, soth_core::ParseSource::Filtered));
        assert!(!out.normalized.is_ai_call);
    }

    #[test]
    fn canonical_hash_ignores_socket_family() {
        let bundle = bundle_fixture();
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        let body = Bytes::from_static(
            br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello world"}],"temperature":0.2}"#,
        );

        let request_tcp = RawRequest {
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: headers.clone(),
            body: body.clone(),
            connection_meta: connection_meta_tcp(),
        };

        let mut request_uds = request_tcp.clone();
        request_uds.connection_meta.socket_family = SocketFamily::UnixDomain { path: None };

        let left = process(
            &request_tcp,
            &bundle.as_slice(),
            &soth_core::SessionSnapshot::default(),
        );
        let right = process(
            &request_uds,
            &bundle.as_slice(),
            &soth_core::SessionSnapshot::default(),
        );

        assert_eq!(
            left.normalized.canonical_cache_key,
            right.normalized.canonical_cache_key
        );
    }

    #[test]
    fn metadata_only_still_extracts_artifacts() {
        // metadata_only runs the full pipeline including artifact extraction.
        // The `full` mode will additionally surface secrets via extraction API (future).
        let mut bundle = bundle_fixture();
        bundle.capture_rules.default_mode = CaptureMode::MetadataOnly;

        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        let request = RawRequest {
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers,
            body: Bytes::from_static(
                br#"{"model":"gpt-4o","messages":[{"role":"user","content":"token sk-test-1234567890ABCDEF"}]}"#,
            ),
            connection_meta: connection_meta_tcp(),
        };

        let out = process(
            &request,
            &bundle.as_slice(),
            &soth_core::SessionSnapshot::default(),
        );
        assert!(!out.artifacts.is_empty());
    }

    #[test]
    fn full_capture_finds_credentials() {
        let mut bundle = bundle_fixture();
        bundle.capture_rules.default_mode = CaptureMode::Full;

        let request = RawRequest {
            method: "POST".to_string(),
            path: "/v1/messages".to_string(),
            headers: {
                let mut headers = BTreeMap::new();
                headers.insert("content-type".to_string(), "application/json".to_string());
                headers
            },
            body: Bytes::from_static(
                br#"{"model":"claude-3","messages":[{"role":"user","content":"key sk-ant-1234567890ABCDEF12345"}]}"#,
            ),
            connection_meta: connection_meta_tcp(),
        };

        let out = process(
            &request,
            &bundle.as_slice(),
            &soth_core::SessionSnapshot::default(),
        );
        assert!(!out.artifacts.is_empty());
    }

    #[test]
    fn stream_finalize_is_deterministic() {
        let connection_id = Uuid::new_v4();
        let mut session = StreamSession::new(connection_id, CaptureMode::MetadataOnly);

        session.accumulate("hello ");
        session.accumulate("world");

        let summary1 = finalize_stream_summary(session.clone());
        let summary2 = finalize_stream_summary(session);

        assert_eq!(summary1.response_hash, summary2.response_hash);
    }

    #[test]
    fn websocket_text_chunk_extracts_graphql_variables_content() {
        let bundle = bundle_fixture();
        let mut session = StreamSession::new(Uuid::new_v4(), CaptureMode::MetadataOnly);
        let chunk = StreamChunk {
            connection_id: session.connection_id,
            sequence: 1,
            payload: Bytes::from_static(
                br#"{"operationName":"SendAIMessage","variables":{"input":{"content":"chunk hello"}}}"#,
            ),
            frame_kind: FrameKind::WebSocketText,
            direction: None,
        };

        let out = process_chunk_with_bundle(&chunk, &mut session, &bundle.as_slice());
        assert!(out.is_none());
        let summary = finalize_stream_summary(session);
        assert!(!summary.response_hash.is_empty());
    }

    #[test]
    fn websocket_text_chunk_accumulates_jsonrpc_raw() {
        // JSON-RPC streaming extraction was removed (no AI provider uses it).
        // The raw JSON is still accumulated as a server WebSocket frame.
        let bundle = bundle_fixture();
        let mut session = StreamSession::new(Uuid::new_v4(), CaptureMode::MetadataOnly);
        let chunk = StreamChunk {
            connection_id: session.connection_id,
            sequence: 1,
            payload: Bytes::from_static(
                br#"{"jsonrpc":"2.0","method":"responses.delta","params":{"delta":{"content":"jsonrpc delta hello"}}}"#,
            ),
            frame_kind: FrameKind::WebSocketText,
            direction: Some(soth_core::FrameDirection::ServerToClient),
        };

        let out = process_chunk_with_bundle(&chunk, &mut session, &bundle.as_slice());
        assert!(out.is_none());
        assert_eq!(session.delta_buffer.len(), 1);
        // Raw JSON accumulated (no JSON-RPC-specific extraction)
        assert!(session.delta_buffer[0].contains("jsonrpc"));
    }

    #[test]
    fn multipart_chunk_extracts_json_delta_content() {
        let bundle = bundle_fixture();
        let mut session = StreamSession::new(Uuid::new_v4(), CaptureMode::MetadataOnly);
        let chunk = StreamChunk {
            connection_id: session.connection_id,
            sequence: 1,
            payload: Bytes::from_static(
                b"--chunk-boundary\r\nContent-Type: application/json\r\n\r\n{\"choices\":[{\"delta\":{\"content\":\"multipart chunk hello\"}}]}\r\n--chunk-boundary--\r\n",
            ),
            frame_kind: FrameKind::MultipartMixed,
            direction: None,
        };

        let out = process_chunk_with_bundle(&chunk, &mut session, &bundle.as_slice());
        assert!(out.is_none());
        assert_eq!(session.delta_buffer.len(), 1);
        assert_eq!(session.delta_buffer[0], "multipart chunk hello");
    }

    #[test]
    fn jsonrpc_request_parses_full() {
        let bundle = bundle_fixture();

        let request = RawRequest {
            method: "POST".to_string(),
            path: "/rpc".to_string(),
            headers: {
                let mut headers = BTreeMap::new();
                headers.insert(
                    "content-type".to_string(),
                    "application/json-rpc".to_string(),
                );
                headers
            },
            body: Bytes::from_static(
                br#"{
                    "jsonrpc":"2.0",
                    "id":"req-1",
                    "method":"chat.completions",
                    "params":{
                        "model":"gpt-4o-mini",
                        "messages":[{"role":"user","content":"hello from jsonrpc"}],
                        "stream":true
                    }
                }"#,
            ),
            connection_meta: connection_meta_tcp(),
        };

        let out = process(
            &request,
            &bundle.as_slice(),
            &soth_core::SessionSnapshot::default(),
        );
        assert_eq!(out.confidence, ParseConfidence::Full);
        assert!(matches!(out.parse_source, soth_core::ParseSource::JsonRpc));
        assert_eq!(out.normalized.model.as_deref(), Some("gpt-4o-mini"));
        if let soth_core::FormatMetadata::JsonRpc { method, is_batch } =
            &out.normalized.format_metadata
        {
            assert_eq!(method.as_str(), "chat.completions");
            assert!(!is_batch);
        } else {
            panic!("expected jsonrpc format metadata");
        }
    }

    #[test]
    fn graphql_known_operation_parses_full() {
        let mut bundle = bundle_fixture();
        bundle.graphql_operations = GraphQLOperationRegistry::with_default_operations();

        let request = RawRequest {
            method: "POST".to_string(),
            path: "/graphql".to_string(),
            headers: {
                let mut headers = BTreeMap::new();
                headers.insert("content-type".to_string(), "application/json".to_string());
                headers
            },
            body: Bytes::from_static(
                br#"{
                    "operationName":"SendAIMessage",
                    "query":"mutation SendAIMessage($input: AIMessageInput!) { sendAIMessage(input: $input) { id content model } }",
                    "variables":{"input":{"content":"explain async in rust","model":"gpt-4o","stream":true,"sessionId":"abc123"}}
                }"#,
            ),
            connection_meta: connection_meta_tcp(),
        };

        let out = process(
            &request,
            &bundle.as_slice(),
            &soth_core::SessionSnapshot::default(),
        );
        assert!(matches!(out.parse_source, soth_core::ParseSource::GraphQl));
        assert_eq!(out.confidence, ParseConfidence::Full);
    }

    #[test]
    fn graphql_apq_cache_round_trip_with_registry() {
        let mut bundle = bundle_fixture();
        bundle.graphql_operations = GraphQLOperationRegistry::with_default_operations();
        let registry = ParserRegistry::default();

        let full = RawRequest {
            method: "POST".to_string(),
            path: "/graphql".to_string(),
            headers: {
                let mut headers = BTreeMap::new();
                headers.insert("content-type".to_string(), "application/json".to_string());
                headers
            },
            body: Bytes::from_static(
                br#"{
                    "operationName":"SendAIMessage",
                    "query":"mutation SendAIMessage($input: AIMessageInput!) { sendAIMessage(input: $input) { id content model } }",
                    "variables":{"input":{"content":"hello","model":"gpt-4o"}},
                    "extensions":{"persistedQuery":{"sha256Hash":"abc123"}}
                }"#,
            ),
            connection_meta: connection_meta_tcp(),
        };

        let hash_only = RawRequest {
            method: "POST".to_string(),
            path: "/graphql".to_string(),
            headers: {
                let mut headers = BTreeMap::new();
                headers.insert("content-type".to_string(), "application/json".to_string());
                headers
            },
            body: Bytes::from_static(
                br#"{
                    "operationName":"SendAIMessage",
                    "variables":{"input":{"content":"hello","model":"gpt-4o"}},
                    "extensions":{"persistedQuery":{"sha256Hash":"abc123"}}
                }"#,
            ),
            connection_meta: connection_meta_tcp(),
        };

        let first = process_with_registry(
            &registry,
            &full,
            &bundle.as_slice(),
            &soth_core::SessionSnapshot::default(),
        );
        let second = process_with_registry(
            &registry,
            &hash_only,
            &bundle.as_slice(),
            &soth_core::SessionSnapshot::default(),
        );
        assert_eq!(first.confidence, ParseConfidence::Full);
        assert_eq!(second.confidence, ParseConfidence::Full);
        assert_eq!(
            first.normalized.canonical_cache_key,
            second.normalized.canonical_cache_key
        );
    }

    #[test]
    fn grpc_vertex_descriptor_parses_full() {
        let mut bundle = bundle_fixture();
        bundle.grpc_services = GrpcServiceRegistry::with_default_services();

        let payload = encode_proto_string_fields(&[
            (1, "projects/demo/models/gemini-1.5-pro"),
            (2, "Explain Rust ownership in simple terms."),
        ]);

        let request = RawRequest {
            method: "POST".to_string(),
            path: "/not-used-by-grpc-parser".to_string(),
            headers: {
                let mut headers = BTreeMap::new();
                headers.insert(
                    "content-type".to_string(),
                    "application/grpc+proto".to_string(),
                );
                headers.insert(
                    ":path".to_string(),
                    "/google.cloud.aiplatform.v1.PredictionService/Predict".to_string(),
                );
                headers
            },
            body: Bytes::from(payload),
            connection_meta: connection_meta_tcp(),
        };

        let out = process(
            &request,
            &bundle.as_slice(),
            &soth_core::SessionSnapshot::default(),
        );
        assert_eq!(out.confidence, ParseConfidence::Full);
        assert!(matches!(out.parse_source, soth_core::ParseSource::Grpc));
        assert_eq!(
            out.normalized.model.as_deref(),
            Some("projects/demo/models/gemini-1.5-pro")
        );
        if let soth_core::FormatMetadata::Grpc {
            service, method, ..
        } = &out.normalized.format_metadata
        {
            assert_eq!(service, "google.cloud.aiplatform.v1.PredictionService");
            assert_eq!(method, "Predict");
        } else {
            panic!("expected gRPC format metadata");
        }
    }

    #[test]
    fn grpc_unknown_service_falls_back_to_heuristic_with_metadata() {
        let bundle = bundle_fixture();
        let payload =
            encode_proto_string_fields(&[(7, "this is a long unknown grpc prompt payload")]);

        let request = RawRequest {
            method: "POST".to_string(),
            path: "/ignored".to_string(),
            headers: {
                let mut headers = BTreeMap::new();
                headers.insert("content-type".to_string(), "application/grpc".to_string());
                headers.insert(
                    ":path".to_string(),
                    "/com.example.UnknownService/Generate".to_string(),
                );
                headers
            },
            body: Bytes::from(payload),
            connection_meta: connection_meta_tcp(),
        };

        let out = process(
            &request,
            &bundle.as_slice(),
            &soth_core::SessionSnapshot::default(),
        );
        assert_eq!(out.confidence, ParseConfidence::Heuristic);
        if let soth_core::FormatMetadata::Grpc {
            service, method, ..
        } = &out.normalized.format_metadata
        {
            assert_eq!(service, "com.example.UnknownService");
            assert_eq!(method, "Generate");
        } else {
            panic!("expected gRPC format metadata");
        }
    }

    #[test]
    fn grpc_stream_chunk_uses_session_context_descriptor_path() {
        let bundle = bundle_fixture();
        let mut session = StreamSession::new(Uuid::new_v4(), CaptureMode::MetadataOnly);
        session.set_grpc_context("google.cloud.aiplatform.v1.PredictionService", "Predict");

        let payload = encode_proto_string_fields(&[(2, "chunk response from grpc")]);
        let chunk = StreamChunk {
            connection_id: session.connection_id,
            sequence: 1,
            payload: Bytes::from(payload),
            frame_kind: FrameKind::GrpcMessage,
            direction: None,
        };

        let out = process_chunk_with_bundle(&chunk, &mut session, &bundle.as_slice());
        assert!(out.is_none());
        assert_eq!(session.delta_buffer.len(), 1);
        assert_eq!(session.delta_buffer[0], "chunk response from grpc");
    }

    #[cfg(feature = "intelligence-sqlite")]
    #[test]
    fn intelligence_logging_records_parse_events() {
        let bundle = bundle_fixture();
        let store = match IntelligenceStore::in_memory() {
            Ok(store) => store,
            Err(error) => panic!("failed to create in-memory intelligence store: {error}"),
        };
        let registry = ParserRegistry::default();

        let request = RawRequest {
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: {
                let mut headers = BTreeMap::new();
                headers.insert("host".to_string(), "api.openai.com".to_string());
                headers.insert("content-type".to_string(), "application/json".to_string());
                headers
            },
            body: Bytes::from_static(
                br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello from intelligence"}]}"#,
            ),
            connection_meta: connection_meta_tcp(),
        };

        let _ = process_with_registry_and_intelligence(
            &registry,
            &request,
            &bundle.as_slice(),
            &soth_core::SessionSnapshot::default(),
            &store,
        );

        let coverage = match store.parse_coverage_since(0) {
            Ok(coverage) => coverage,
            Err(error) => panic!("failed to query coverage: {error}"),
        };
        assert_eq!(
            coverage.full_count + coverage.partial_count + coverage.heuristic_count,
            1
        );
    }

    #[cfg(feature = "intelligence-sqlite")]
    #[test]
    fn unknown_graphql_operation_is_aggregated_and_replay_upgrades_after_registry_update() {
        let mut bundle = bundle_fixture();
        let store = match IntelligenceStore::in_memory() {
            Ok(store) => store,
            Err(error) => panic!("failed to create in-memory intelligence store: {error}"),
        };
        let registry = ParserRegistry::default();

        let unknown_request = RawRequest {
            method: "POST".to_string(),
            path: "/graphql".to_string(),
            headers: {
                let mut headers = BTreeMap::new();
                headers.insert("host".to_string(), "warp.dev".to_string());
                headers.insert("content-type".to_string(), "application/json".to_string());
                headers
            },
            body: Bytes::from_static(
                br#"{
                    "operationName":"CustomPrompt",
                    "query":"mutation CustomPrompt($input: PromptInput!) { customPrompt(input: $input) { id response } }",
                    "variables":{"input":{"promptText":"describe rust lifetimes","model":"gpt-4o-mini","sessionId":"x-1"}}
                }"#,
            ),
            connection_meta: connection_meta_tcp(),
        };

        let first = process_with_registry_and_intelligence(
            &registry,
            &unknown_request,
            &bundle.as_slice(),
            &soth_core::SessionSnapshot::default(),
            &store,
        );
        assert_eq!(first.confidence, ParseConfidence::Heuristic);

        let unknown_ops = match store.unknown_graphql_operations_since(0, 1, 20) {
            Ok(rows) => rows,
            Err(error) => panic!("failed to query unknown graphql operations: {error}"),
        };
        assert!(!unknown_ops.is_empty());

        bundle
            .graphql_operations
            .operations
            .push(GraphQLOperationSpec {
                operation_name: "CustomPrompt".to_string(),
                provider_hint: Some("warp".to_string()),
                is_ai_call: true,
                content_path: Some(vec!["input".to_string(), "promptText".to_string()]),
                model_path: Some(vec!["input".to_string(), "model".to_string()]),
                system_prompt_path: None,
                stream_path: None,
                ephemeral_paths: vec![vec!["input".to_string(), "sessionId".to_string()]],
            });

        let replay = match replay_heuristic_events(&registry, &bundle.as_slice(), &store, 50) {
            Ok(summary) => summary,
            Err(error) => panic!("failed running replay: {error}"),
        };

        assert!(replay.total_candidates >= 1);
        assert!(replay.upgraded >= 1);
    }

    #[test]
    fn capture_mode_from_connection_meta_overrides_bundle_default_to_full() {
        let mut bundle = bundle_fixture();
        bundle.capture_rules.default_mode = CaptureMode::MetadataOnly;

        let mut request = RawRequest {
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: {
                let mut headers = BTreeMap::new();
                headers.insert("content-type".to_string(), "application/json".to_string());
                headers
            },
            body: Bytes::from_static(
                br#"{"model":"gpt-4o","messages":[{"role":"user","content":"token sk-abcdefghijklmnopqrstuvwxyz1234"}]}"#,
            ),
            connection_meta: connection_meta_tcp(),
        };
        request.connection_meta.capture_mode = Some(CaptureMode::Full);

        let out = process(
            &request,
            &bundle.as_slice(),
            &soth_core::SessionSnapshot::default(),
        );
        assert_eq!(out.capture_mode, CaptureMode::Full);
        assert!(out.artifacts.iter().any(|a| matches!(
            a.kind,
            soth_core::ArtifactKind::ApiKey {
                provider: Some(soth_core::DetectedProvider::OpenAi)
            }
        )));
    }

    #[test]
    fn capture_mode_from_connection_meta_overrides_bundle_default_to_metadata_only() {
        let mut bundle = bundle_fixture();
        bundle.capture_rules.default_mode = CaptureMode::Full;

        let mut request = RawRequest {
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: {
                let mut headers = BTreeMap::new();
                headers.insert("content-type".to_string(), "application/json".to_string());
                headers
            },
            body: Bytes::from_static(
                br#"{"model":"gpt-4o","messages":[{"role":"user","content":"token sk-abcdefghijklmnopqrstuvwxyz1234"}]}"#,
            ),
            connection_meta: connection_meta_tcp(),
        };
        request.connection_meta.capture_mode = Some(CaptureMode::MetadataOnly);

        let out = process(
            &request,
            &bundle.as_slice(),
            &soth_core::SessionSnapshot::default(),
        );
        assert_eq!(out.capture_mode, CaptureMode::MetadataOnly);
        // metadata_only still extracts artifacts; only the future extraction API is gated by `full`
        assert!(!out.artifacts.is_empty());
    }

    #[test]
    fn malformed_rest_body_falls_back_to_heuristic_with_parser_warning() {
        let bundle = bundle_fixture();

        let request = RawRequest {
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: {
                let mut headers = BTreeMap::new();
                headers.insert("content-type".to_string(), "application/json".to_string());
                headers
            },
            body: Bytes::from_static(br#"{"model":"gpt-4o","messages":[{"role":"user"}"#),
            connection_meta: connection_meta_tcp(),
        };

        let out = process(
            &request,
            &bundle.as_slice(),
            &soth_core::SessionSnapshot::default(),
        );
        assert_eq!(out.confidence, ParseConfidence::Heuristic);
        assert!(matches!(
            out.parse_source,
            soth_core::ParseSource::Heuristic
        ));
        assert!(out
            .warnings
            .iter()
            .any(|w| matches!(w, soth_core::ParseWarning::PartialBodyParse { .. })));
        assert!(out
            .normalized
            .parse_warnings
            .iter()
            .any(|w| matches!(w, soth_core::ParseWarning::ParserError { .. })));
    }

    #[test]
    fn matched_provider_hint_promotes_unknown_path_to_rest_parser() {
        let bundle = bundle_fixture();

        let base = RawRequest {
            method: "POST".to_string(),
            path: "/internal/proxy".to_string(),
            headers: {
                let mut headers = BTreeMap::new();
                headers.insert("content-type".to_string(), "application/json".to_string());
                headers
            },
            body: Bytes::from_static(
                br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello hint"}]}"#,
            ),
            connection_meta: connection_meta_tcp(),
        };

        let without_hint = process(
            &base,
            &bundle.as_slice(),
            &soth_core::SessionSnapshot::default(),
        );
        assert!(matches!(
            without_hint.parse_source,
            soth_core::ParseSource::Heuristic
        ));

        let mut with_hint_req = base.clone();
        with_hint_req.connection_meta.matched_provider = Some("openai".to_string());
        let with_hint = process(
            &with_hint_req,
            &bundle.as_slice(),
            &soth_core::SessionSnapshot::default(),
        );
        assert!(matches!(
            with_hint.parse_source,
            soth_core::ParseSource::Rest {
                provider: soth_core::DetectedProvider::OpenAi
            }
        ));
        assert_eq!(with_hint.confidence, ParseConfidence::Full);
        assert_eq!(with_hint.normalized.model.as_deref(), Some("gpt-4o-mini"));
    }

    #[test]
    fn jsonrpc_batch_request_sets_format_meta_batch_true() {
        let bundle = bundle_fixture();
        let request = RawRequest {
            method: "POST".to_string(),
            path: "/rpc".to_string(),
            headers: {
                let mut headers = BTreeMap::new();
                headers.insert(
                    "content-type".to_string(),
                    "application/json-rpc".to_string(),
                );
                headers
            },
            body: Bytes::from_static(
                br#"[
                    {
                        "jsonrpc":"2.0",
                        "id":"1",
                        "method":"health.ping",
                        "params":{"ping":"ok"}
                    },
                    {
                        "jsonrpc":"2.0",
                        "id":"2",
                        "method":"chat.completions",
                        "params":{
                            "model":"gpt-4o-mini",
                            "messages":[{"role":"user","content":"hello batch"}]
                        }
                    }
                ]"#,
            ),
            connection_meta: connection_meta_tcp(),
        };

        let out = process(
            &request,
            &bundle.as_slice(),
            &soth_core::SessionSnapshot::default(),
        );
        assert_eq!(out.confidence, ParseConfidence::Full);
        if let soth_core::FormatMetadata::JsonRpc { method, is_batch } =
            &out.normalized.format_metadata
        {
            assert_eq!(method.as_str(), "chat.completions");
            assert!(*is_batch);
        } else {
            panic!("expected jsonrpc format metadata");
        }
    }

    #[test]
    fn empty_snapshot_never_reports_prefix_repeat() {
        let bundle = bundle_fixture();
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        let request = RawRequest {
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers,
            body: Bytes::from_static(
                br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello world"}]}"#,
            ),
            connection_meta: connection_meta_tcp(),
        };
        let out = process(
            &request,
            &bundle.as_slice(),
            &soth_core::SessionSnapshot::default(),
        );
        assert!(!out.is_prefix_repeat);
        assert!(!out.is_repeated_code_context);
        assert_eq!(out.repeated_token_count, 0);
    }

    fn bundle_fixture() -> OwnedDetectBundle {
        let mut rest_formats = HashMap::new();
        rest_formats.insert(
            "openai".to_string(),
            RestFormatDescriptor {
                request: RestRequestPaths {
                    model: Some("$.model".to_string()),
                    messages: Some("$.messages".to_string()),
                    tools: Some("$.tools".to_string()),
                    temperature: Some("$.temperature".to_string()),
                    max_tokens: Some("$.max_tokens".to_string()),
                    stream: Some("$.stream".to_string()),
                    stop: Some("$.stop".to_string()),
                    ..RestRequestPaths::default()
                },
                system_in_messages: true,
                ..RestFormatDescriptor::default()
            },
        );

        rest_formats.insert(
            "anthropic".to_string(),
            RestFormatDescriptor {
                request: RestRequestPaths {
                    model: Some("$.model".to_string()),
                    messages: Some("$.messages".to_string()),
                    system: Some("$.system".to_string()),
                    ..RestRequestPaths::default()
                },
                system_in_messages: false,
                ..RestFormatDescriptor::default()
            },
        );

        let mut domain_index = HashMap::new();
        domain_index.insert("api.openai.com".to_string(), "openai".to_string());

        let mut providers = HashMap::new();
        providers.insert(
            "openai".to_string(),
            ProviderEntry {
                provider_id: Some("openai".to_string()),
                name: Some("OpenAI".to_string()),
                api_format: Some("openai".to_string()),
                ..ProviderEntry::default()
            },
        );
        providers.insert(
            "anthropic".to_string(),
            ProviderEntry {
                provider_id: Some("anthropic".to_string()),
                name: Some("Anthropic".to_string()),
                api_format: Some("anthropic".to_string()),
                ..ProviderEntry::default()
            },
        );
        providers.insert(
            "google_vertex".to_string(),
            ProviderEntry {
                provider_id: Some("google_vertex".to_string()),
                name: Some("Google Vertex".to_string()),
                api_format: Some("grpc".to_string()),
                ..ProviderEntry::default()
            },
        );

        OwnedDetectBundle {
            rest_formats,
            domain_index,
            llm_providers: providers,
            graphql_operations: GraphQLOperationRegistry::with_default_operations(),
            grpc_services: GrpcServiceRegistry::with_default_services(),
            capture_rules: CaptureRules::default(),
            ..OwnedDetectBundle::default()
        }
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

    fn connection_meta_tcp() -> ConnectionMeta {
        ConnectionMeta {
            connection_id: Uuid::new_v4(),
            socket_family: SocketFamily::TcpV4 {
                local: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080),
                remote: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443),
            },
            process_info: None,
            tls_info: None,
            app_identity: None,
            capture_mode: None,
            matched_provider: None,
            matched_application: None,
            h2_connection_id: None,
            h2_stream_id: None,
        }
    }
}
