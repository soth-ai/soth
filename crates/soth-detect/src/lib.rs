mod code;
mod engine;
mod fingerprint;
mod graphql;
mod grpc;
mod hash;
mod heuristic;
mod identity;
mod intelligence;
mod intelligence_store;
mod replay;
mod rest;
mod sensitive;
mod stream;
mod types;
mod util;

pub use engine::{
    process, process_with_intelligence, process_with_registry,
    process_with_registry_and_intelligence, ParserRegistry,
};
pub use identity::resolve_app_identity;
pub use intelligence::*;
pub use intelligence_store::IntelligenceStore;
pub use replay::replay_heuristic_events;
pub use stream::{finalize_stream, process_chunk, scan_proto_strings};
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
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

        let out = process(&request, &bundle.as_slice());
        assert!(matches!(out.parse_source, ParseSource::Filtered));
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

        let left = process(&request_tcp, &bundle.as_slice());
        let right = process(&request_uds, &bundle.as_slice());

        assert_eq!(
            left.normalized.canonical_hash,
            right.normalized.canonical_hash
        );
    }

    #[test]
    fn metadata_only_skips_credentials() {
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

        let out = process(&request, &bundle.as_slice());
        assert!(out.artifacts.is_empty());
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

        let out = process(&request, &bundle.as_slice());
        assert!(!out.artifacts.is_empty());
    }

    #[test]
    fn stream_finalize_is_deterministic() {
        let connection_id = Uuid::new_v4();
        let mut session = StreamSession::new(connection_id, CaptureMode::MetadataOnly);

        session.accumulate("hello ");
        session.accumulate("world");

        let summary1 = finalize_stream(session.clone());
        let summary2 = finalize_stream(session);

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
        };

        let out = process_chunk(&chunk, &mut session, &bundle.as_slice());
        assert!(out.is_none());
        let summary = finalize_stream(session);
        assert!(!summary.response_hash.is_empty());
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

        let out = process(&request, &bundle.as_slice());
        assert!(matches!(out.parse_source, ParseSource::GraphQL { .. }));
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

        let first = process_with_registry(&registry, &full, &bundle.as_slice());
        let second = process_with_registry(&registry, &hash_only, &bundle.as_slice());
        assert_eq!(first.confidence, ParseConfidence::Full);
        assert_eq!(second.confidence, ParseConfidence::Full);
        assert_eq!(
            first.normalized.canonical_hash,
            second.normalized.canonical_hash
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

        let out = process(&request, &bundle.as_slice());
        assert_eq!(out.confidence, ParseConfidence::Full);
        assert!(matches!(out.parse_source, ParseSource::Grpc { .. }));
        assert_eq!(
            out.normalized.model.as_deref(),
            Some("projects/demo/models/gemini-1.5-pro")
        );
        if let FormatMeta::Grpc {
            service, method, ..
        } = &out.normalized.format_meta
        {
            assert_eq!(service, "google.cloud.aiplatform.v1.PredictionService");
            assert_eq!(method, "Predict");
        } else {
            panic!("expected gRPC format meta");
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

        let out = process(&request, &bundle.as_slice());
        assert_eq!(out.confidence, ParseConfidence::Heuristic);
        if let FormatMeta::Grpc {
            service, method, ..
        } = &out.normalized.format_meta
        {
            assert_eq!(service, "com.example.UnknownService");
            assert_eq!(method, "Generate");
        } else {
            panic!("expected gRPC format meta");
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
        };

        let out = process_chunk(&chunk, &mut session, &bundle.as_slice());
        assert!(out.is_none());
        assert_eq!(session.delta_buffer.len(), 1);
        assert_eq!(session.delta_buffer[0], "chunk response from grpc");
    }

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

        let _ =
            process_with_registry_and_intelligence(&registry, &request, &bundle.as_slice(), &store);

        let coverage = match store.parse_coverage_since(0) {
            Ok(coverage) => coverage,
            Err(error) => panic!("failed to query coverage: {error}"),
        };
        assert_eq!(
            coverage.full_count + coverage.partial_count + coverage.heuristic_count,
            1
        );
    }

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
            },
        );
        providers.insert(
            "anthropic".to_string(),
            ProviderEntry {
                provider_id: Some("anthropic".to_string()),
                name: Some("Anthropic".to_string()),
                api_format: Some("anthropic".to_string()),
            },
        );
        providers.insert(
            "google_vertex".to_string(),
            ProviderEntry {
                provider_id: Some("google_vertex".to_string()),
                name: Some("Google Vertex".to_string()),
                api_format: Some("grpc".to_string()),
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
        }
    }
}
