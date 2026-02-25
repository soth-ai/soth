use bytes::Bytes;
use serde::Deserialize;
use soth_core::{
    ArtifactKind, CaptureMode, DetectResult, EndpointType, FormatMetadata, ParseConfidence,
    ParseSource, SocketFamily,
};
use soth_detect::{
    build_registry, process_with_registry, CaptureRules, ConnectionMeta, GraphQLOperationRegistry,
    GrpcServiceRegistry, OwnedDetectBundle, ProviderEntry, RawRequest, RestFormatDescriptor,
    RestRequestPaths,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct CorpusCase {
    id: String,
    request: CorpusRequest,
    expect: CorpusExpect,
}

#[derive(Debug, Deserialize)]
struct CorpusRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Option<String>,
    proto_string_fields: Option<Vec<ProtoStringField>>,
    capture_mode: Option<String>,
    matched_provider: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProtoStringField {
    field: u32,
    value: String,
}

#[derive(Debug, Deserialize)]
struct CorpusExpect {
    parse_source: String,
    confidence: String,
    capture_mode: String,
    provider: String,
    model: Option<String>,
    endpoint_type: String,
    format_kind: String,
    is_ai_call: bool,
    min_artifacts: usize,
    max_artifacts: Option<usize>,
    warnings_min: usize,
    require_non_empty_user_hash: bool,
    require_non_empty_cache_key: bool,
    required_artifact_kinds: Vec<String>,
}

#[test]
fn detect_output_corpus_matches_expected_contract() {
    let corpus_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join("detect_output_corpus.json");
    if !corpus_path.exists() {
        eprintln!(
            "Skipping detect_output_corpus_matches_expected_contract: corpus fixture not found at {}",
            corpus_path.display()
        );
        return;
    }

    let corpus_bytes =
        std::fs::read_to_string(&corpus_path).expect("read detect output corpus fixture");
    let corpus: Vec<CorpusCase> =
        serde_json::from_str(&corpus_bytes).expect("parse corpus fixture");

    let bundle = bundle_fixture();
    let registry = build_registry(&bundle.as_slice()).expect("build parser registry");

    for case in corpus {
        let request = build_request(&case.request);
        let out = process_with_registry(&registry, &request, &bundle.as_slice());
        assert_case(&case.id, &case.expect, &out);
    }
}

fn assert_case(case_id: &str, expect: &CorpusExpect, out: &DetectResult) {
    assert_eq!(
        parse_source_label(&out.parse_source),
        expect.parse_source,
        "case {case_id}: parse_source mismatch"
    );
    assert_eq!(
        confidence_label(out.confidence),
        expect.confidence,
        "case {case_id}: confidence mismatch"
    );
    assert_eq!(
        capture_mode_label(out.capture_mode),
        expect.capture_mode,
        "case {case_id}: capture_mode mismatch"
    );
    assert_eq!(
        out.normalized.provider.canonical_name(),
        expect.provider,
        "case {case_id}: provider mismatch"
    );
    assert_eq!(
        out.normalized.model, expect.model,
        "case {case_id}: model mismatch"
    );
    assert_eq!(
        endpoint_type_label(out.normalized.endpoint_type),
        expect.endpoint_type,
        "case {case_id}: endpoint_type mismatch"
    );
    assert_eq!(
        format_kind_label(&out.normalized.format_metadata),
        expect.format_kind,
        "case {case_id}: format_kind mismatch"
    );
    assert_eq!(
        out.normalized.is_ai_call, expect.is_ai_call,
        "case {case_id}: is_ai_call mismatch"
    );
    assert!(
        out.artifacts.len() >= expect.min_artifacts,
        "case {case_id}: artifacts fewer than expected min (got {}, min {})",
        out.artifacts.len(),
        expect.min_artifacts
    );
    if let Some(max_artifacts) = expect.max_artifacts {
        assert!(
            out.artifacts.len() <= max_artifacts,
            "case {case_id}: artifacts greater than expected max (got {}, max {})",
            out.artifacts.len(),
            max_artifacts
        );
    }
    assert!(
        out.warnings.len() >= expect.warnings_min,
        "case {case_id}: warnings fewer than expected min (got {}, min {})",
        out.warnings.len(),
        expect.warnings_min
    );
    if expect.require_non_empty_user_hash {
        assert!(
            !out.normalized.user_content_hash.is_empty(),
            "case {case_id}: expected non-empty user_content_hash"
        );
    }
    if expect.require_non_empty_cache_key {
        assert!(
            !out.normalized.canonical_cache_key.is_empty(),
            "case {case_id}: expected non-empty canonical_cache_key"
        );
    }

    let artifact_labels: HashSet<String> = out
        .artifacts
        .iter()
        .map(|artifact| artifact_kind_label(&artifact.kind))
        .collect();
    for required in &expect.required_artifact_kinds {
        assert!(
            artifact_labels.contains(required),
            "case {case_id}: missing expected artifact kind '{required}', got {:?}",
            artifact_labels
        );
    }
}

fn parse_source_label(value: &ParseSource) -> String {
    match value {
        ParseSource::Rest { provider } => format!("rest:{}", provider.canonical_name()),
        ParseSource::GraphQl => "graphql".to_string(),
        ParseSource::Grpc => "grpc".to_string(),
        ParseSource::JsonRpc => "jsonrpc".to_string(),
        ParseSource::AgentApp => "agent_app".to_string(),
        ParseSource::Heuristic => "heuristic".to_string(),
        ParseSource::Filtered => "filtered".to_string(),
    }
}

fn confidence_label(value: ParseConfidence) -> &'static str {
    match value {
        ParseConfidence::Full => "full",
        ParseConfidence::Partial => "partial",
        ParseConfidence::Heuristic => "heuristic",
    }
}

fn capture_mode_label(value: CaptureMode) -> &'static str {
    match value {
        CaptureMode::MetadataOnly => "metadata_only",
        CaptureMode::Full => "full",
        CaptureMode::SensitiveArtifacts => "sensitive_artifacts",
        CaptureMode::FullContent => "full_content",
    }
}

fn endpoint_type_label(value: EndpointType) -> &'static str {
    match value {
        EndpointType::ChatCompletion => "chat_completion",
        EndpointType::TextCompletion => "text_completion",
        EndpointType::Embedding => "embedding",
        EndpointType::ImageGeneration => "image_generation",
        EndpointType::AudioTranscription => "audio_transcription",
        EndpointType::FunctionCall => "function_call",
        EndpointType::Streaming => "streaming",
        EndpointType::Unknown => "unknown",
    }
}

fn format_kind_label(value: &FormatMetadata) -> &'static str {
    match value {
        FormatMetadata::Rest { .. } => "rest",
        FormatMetadata::GraphQl { .. } => "graphql",
        FormatMetadata::Grpc { .. } => "grpc",
        FormatMetadata::JsonRpc { .. } => "jsonrpc",
        FormatMetadata::Unknown => "unknown",
    }
}

fn artifact_kind_label(value: &ArtifactKind) -> String {
    match value {
        ArtifactKind::PrivateKey => "private_key".to_string(),
        ArtifactKind::ApiKey { provider } => match provider {
            Some(provider) => format!("api_key:{}", provider.canonical_name()),
            None => "api_key".to_string(),
        },
        ArtifactKind::Jwt => "jwt".to_string(),
        ArtifactKind::HexKey => "hex_key".to_string(),
        ArtifactKind::ConnectionString => "connection_string".to_string(),
        ArtifactKind::CodeBlock { .. } => "code_block".to_string(),
        ArtifactKind::UnknownCredential => "unknown_credential".to_string(),
        ArtifactKind::OrgPattern { .. } => "org_pattern".to_string(),
        ArtifactKind::AuthLogic => "auth_logic".to_string(),
        ArtifactKind::CryptoOperation => "crypto_operation".to_string(),
    }
}

fn build_request(fixture: &CorpusRequest) -> RawRequest {
    let body = if let Some(fields) = fixture.proto_string_fields.as_ref() {
        encode_proto_string_fields(fields)
    } else {
        fixture.body.clone().unwrap_or_default().into_bytes()
    };

    let mut meta = ConnectionMeta::from_transport(
        Uuid::new_v4(),
        SocketFamily::TcpV4 {
            local: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8_080),
            remote: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443),
        },
        None,
        None,
    );
    meta.capture_mode = fixture.capture_mode.as_deref().map(parse_capture_mode);
    meta.matched_provider = fixture.matched_provider.clone();

    RawRequest {
        method: fixture.method.clone(),
        path: fixture.path.clone(),
        headers: fixture.headers.clone(),
        body: Bytes::from(body),
        connection_meta: meta,
    }
}

fn parse_capture_mode(raw: &str) -> CaptureMode {
    match raw {
        "metadata_only" => CaptureMode::MetadataOnly,
        "full" => CaptureMode::Full,
        "sensitive_artifacts" => CaptureMode::SensitiveArtifacts,
        "full_content" => CaptureMode::FullContent,
        other => panic!("unsupported capture_mode in corpus fixture: {other}"),
    }
}

fn encode_proto_string_fields(entries: &[ProtoStringField]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        let tag = (u64::from(entry.field) << 3) | 2;
        encode_varint(tag, &mut out);
        encode_varint(entry.value.len() as u64, &mut out);
        out.extend_from_slice(entry.value.as_bytes());
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
    domain_index.insert("api.anthropic.com".to_string(), "anthropic".to_string());

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

    let mut bundle = OwnedDetectBundle {
        rest_formats,
        domain_index,
        llm_providers: providers,
        graphql_operations: GraphQLOperationRegistry::with_default_operations(),
        grpc_services: GrpcServiceRegistry::with_default_services(),
        capture_rules: CaptureRules::default(),
        ..OwnedDetectBundle::default()
    };
    bundle.filters.path_keywords = vec!["/healthz".to_string()];
    bundle
}
