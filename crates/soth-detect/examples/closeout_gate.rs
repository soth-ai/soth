use bytes::Bytes;
use soth_detect::{
    process_with_registry, CaptureMode, CaptureRules, ConnectionMeta, DetectResult,
    GraphQLOperationRegistry, GrpcServiceRegistry, OwnedDetectBundle, ParseSource, ParserRegistry,
    ProviderEntry, RawRequest, RestFormatDescriptor, RestRequestPaths, SocketFamily,
};
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;
use std::time::Instant;
use uuid::Uuid;

const AC01_CASES: usize = 50_000;
const AC14_FIXTURES: usize = 1_000;
const AC15_CALLS: usize = 10_000;

#[derive(Clone, Copy)]
enum SocketKind {
    TcpV4,
    TcpV6,
    UnixDomain,
}

fn main() {
    let mode = env::args().nth(1);
    let exit_code = match mode.as_deref() {
        Some("ac01") => run_ac01(),
        Some("ac14") => run_ac14(),
        Some("ac15") => run_ac15(),
        _ => {
            eprintln!(
                "usage: cargo run -p soth-detect --example closeout_gate -- <ac01|ac14|ac15>"
            );
            2
        }
    };
    std::process::exit(exit_code);
}

fn run_ac01() -> i32 {
    let bundle = build_bundle();
    let bundle_slice = bundle.as_slice();
    let registry = ParserRegistry::default();
    let mut rng = XorShift64::new(0x5EED_A11C_0010_0001);
    let mut panic_count = 0usize;

    for case_idx in 0..AC01_CASES {
        let socket = match case_idx % 3 {
            0 => SocketKind::TcpV4,
            1 => SocketKind::TcpV6,
            _ => SocketKind::UnixDomain,
        };
        let request = random_request(case_idx, socket, &mut rng);
        let result = std::panic::catch_unwind(|| {
            let _ = process_with_registry(&registry, &request, &bundle_slice);
        });
        if result.is_err() {
            panic_count += 1;
        }
    }

    println!("AC-01 fuzz cases: {}", AC01_CASES);
    println!("AC-01 panic count: {}", panic_count);
    println!("AC-01 allocation audit: not covered by this runner (heaptrack required)");

    if panic_count == 0 {
        println!("AC-01 panic gate: PASS");
        0
    } else {
        println!("AC-01 panic gate: FAIL");
        1
    }
}

fn run_ac14() -> i32 {
    let bundle = build_bundle();
    let bundle_slice = bundle.as_slice();
    let registry = ParserRegistry::default();
    let fixtures = build_fixtures(AC14_FIXTURES);
    let mut latencies_ms = Vec::with_capacity(fixtures.len());
    let mut parse_counts = BTreeMap::<String, usize>::new();
    let mut full_capture_count = 0usize;
    let mut metadata_capture_count = 0usize;

    for request in &fixtures {
        let started = Instant::now();
        let out = process_with_registry(&registry, request, &bundle_slice);
        latencies_ms.push(started.elapsed().as_secs_f64() * 1000.0);

        let key = parse_source_name(&out);
        let counter = parse_counts.entry(key).or_insert(0);
        *counter += 1;

        match out.capture_mode {
            CaptureMode::Full => full_capture_count += 1,
            CaptureMode::MetadataOnly => metadata_capture_count += 1,
        }
    }

    latencies_ms.sort_by(|a, b| a.total_cmp(b));
    let p95 = percentile(&latencies_ms, 0.95);
    let p99 = percentile(&latencies_ms, 0.99);
    let max = latencies_ms.last().copied().unwrap_or(0.0);

    println!("AC-14 fixture count: {}", fixtures.len());
    println!("AC-14 p95_ms: {:.3}", p95);
    println!("AC-14 p99_ms: {:.3}", p99);
    println!("AC-14 max_ms: {:.3}", max);
    println!(
        "AC-14 capture modes: full={}, metadata_only={}",
        full_capture_count, metadata_capture_count
    );
    println!("AC-14 parse source distribution:");
    for (source, count) in &parse_counts {
        println!("  {}: {}", source, count);
    }

    let pass = p95 < 25.0 && p99 < 45.0 && max < 90.0;
    if pass {
        println!("AC-14 latency gate: PASS");
        0
    } else {
        println!("AC-14 latency gate: FAIL");
        1
    }
}

fn run_ac15() -> i32 {
    let bundle = build_bundle();
    let bundle_slice = bundle.as_slice();
    let registry = ParserRegistry::default();
    let mut checksum = 0u64;

    for idx in 0..AC15_CALLS {
        let socket = match idx % 3 {
            0 => SocketKind::TcpV4,
            1 => SocketKind::TcpV6,
            _ => SocketKind::UnixDomain,
        };
        let request = benchmark_request(idx, socket);
        let out = process_with_registry(&registry, &request, &bundle_slice);
        checksum = checksum
            .wrapping_add(out.detect_latency_us)
            .wrapping_add(out.normalized.user_content_token_estimate as u64);
    }

    std::hint::black_box(checksum);
    0
}

fn parse_source_name(out: &DetectResult) -> String {
    match &out.parse_source {
        ParseSource::OpenAI => "openai".to_string(),
        ParseSource::Anthropic => "anthropic".to_string(),
        ParseSource::Cohere => "cohere".to_string(),
        ParseSource::Google => "google".to_string(),
        ParseSource::Bedrock => "bedrock".to_string(),
        ParseSource::GraphQL { .. } => "graphql".to_string(),
        ParseSource::Grpc { .. } => "grpc".to_string(),
        ParseSource::AgentApp { .. } => "agent_app".to_string(),
        ParseSource::Heuristic => "heuristic".to_string(),
        ParseSource::Filtered => "filtered".to_string(),
    }
}

fn percentile(samples: &[f64], quantile: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let max_index = samples.len() - 1;
    let rank = (max_index as f64 * quantile).ceil() as usize;
    samples[rank.min(max_index)]
}

fn build_fixtures(count: usize) -> Vec<RawRequest> {
    let mut fixtures = Vec::with_capacity(count);
    for idx in 0..count {
        let socket = match idx % 3 {
            0 => SocketKind::TcpV4,
            1 => SocketKind::TcpV6,
            _ => SocketKind::UnixDomain,
        };
        fixtures.push(benchmark_request(idx, socket));
    }
    fixtures
}

fn benchmark_request(idx: usize, socket: SocketKind) -> RawRequest {
    let content = format!("closeout fixture {}", idx);
    match idx % 7 {
        0 => rest_openai_request(&content, socket),
        1 => rest_anthropic_request(&content, socket),
        2 => graphql_known_request(&content, socket),
        3 => graphql_unknown_request(&content, socket),
        4 => grpc_known_request(&content, socket),
        5 => grpc_unknown_request(&content, socket),
        _ => heuristic_request(&content, socket),
    }
}

fn random_request(case_idx: usize, socket: SocketKind, rng: &mut XorShift64) -> RawRequest {
    let method = match rng.next_u64() % 4 {
        0 => "GET",
        1 => "POST",
        2 => "PUT",
        _ => "PATCH",
    };
    let path = match rng.next_u64() % 5 {
        0 => "/v1/chat/completions".to_string(),
        1 => "/v1/messages".to_string(),
        2 => "/graphql".to_string(),
        3 => "/google.cloud.aiplatform.v1.PredictionService/Predict".to_string(),
        _ => format!("/opaque/{case_idx}"),
    };

    let host = match rng.next_u64() % 5 {
        0 => "api.openai.com",
        1 => "api.anthropic.com",
        2 => "warp.dev",
        3 => "aiplatform.googleapis.com",
        _ => "unknown.local",
    };

    let content_type = match rng.next_u64() % 4 {
        0 => "application/json",
        1 => "application/graphql-response+json",
        2 => "application/grpc+proto",
        _ => "application/octet-stream",
    };

    let body_len = (rng.next_u64() % 2048) as usize;
    let mut body = Vec::with_capacity(body_len);
    for _ in 0..body_len {
        body.push((rng.next_u64() & 0xFF) as u8);
    }

    let mut headers = BTreeMap::new();
    headers.insert("host".to_string(), host.to_string());
    headers.insert("content-type".to_string(), content_type.to_string());

    if content_type.starts_with("application/grpc") {
        headers.insert(":path".to_string(), path.clone());
    }

    RawRequest {
        method: method.to_string(),
        path,
        headers,
        body: Bytes::from(body),
        connection_meta: connection_meta(socket, case_idx),
    }
}

fn rest_openai_request(content: &str, socket: SocketKind) -> RawRequest {
    let mut headers = BTreeMap::new();
    headers.insert("host".to_string(), "api.openai.com".to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());

    RawRequest {
        method: "POST".to_string(),
        path: "/v1/chat/completions".to_string(),
        headers,
        body: Bytes::from(format!(
            "{{\"model\":\"gpt-4o\",\"messages\":[{{\"role\":\"user\",\"content\":\"{}\"}}],\"temperature\":0.2}}",
            content
        )),
        connection_meta: connection_meta(socket, 1),
    }
}

fn rest_anthropic_request(content: &str, socket: SocketKind) -> RawRequest {
    let mut headers = BTreeMap::new();
    headers.insert("host".to_string(), "api.anthropic.com".to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());

    RawRequest {
        method: "POST".to_string(),
        path: "/v1/messages".to_string(),
        headers,
        body: Bytes::from(format!(
            "{{\"model\":\"claude-3-7-sonnet\",\"messages\":[{{\"role\":\"user\",\"content\":\"{}\"}}]}}",
            content
        )),
        connection_meta: connection_meta(socket, 2),
    }
}

fn graphql_known_request(content: &str, socket: SocketKind) -> RawRequest {
    let mut headers = BTreeMap::new();
    headers.insert("host".to_string(), "warp.dev".to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());

    RawRequest {
        method: "POST".to_string(),
        path: "/graphql".to_string(),
        headers,
        body: Bytes::from(format!(
            "{{\"operationName\":\"SendAIMessage\",\"query\":\"mutation SendAIMessage($input: AIMessageInput!) {{ sendAIMessage(input: $input) {{ id content model }} }}\",\"variables\":{{\"input\":{{\"content\":\"{}\",\"model\":\"gpt-4o-mini\",\"sessionId\":\"sess-1\"}}}}}}",
            content
        )),
        connection_meta: connection_meta(socket, 3),
    }
}

fn graphql_unknown_request(content: &str, socket: SocketKind) -> RawRequest {
    let mut headers = BTreeMap::new();
    headers.insert("host".to_string(), "warp.dev".to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());

    RawRequest {
        method: "POST".to_string(),
        path: "/graphql".to_string(),
        headers,
        body: Bytes::from(format!(
            "{{\"operationName\":\"CustomPrompt\",\"query\":\"mutation CustomPrompt($input: PromptInput!) {{ customPrompt(input: $input) {{ id response }} }}\",\"variables\":{{\"input\":{{\"promptText\":\"{}\",\"model\":\"gpt-4o-mini\",\"sessionId\":\"sess-2\"}}}}}}",
            content
        )),
        connection_meta: connection_meta(socket, 4),
    }
}

fn grpc_known_request(content: &str, socket: SocketKind) -> RawRequest {
    let mut headers = BTreeMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/grpc+proto".to_string(),
    );
    headers.insert("host".to_string(), "aiplatform.googleapis.com".to_string());
    headers.insert(
        ":path".to_string(),
        "/google.cloud.aiplatform.v1.PredictionService/Predict".to_string(),
    );
    let payload =
        encode_proto_string_fields(&[(1, "projects/demo/models/gemini-1.5-pro"), (2, content)]);

    RawRequest {
        method: "POST".to_string(),
        path: "/google.cloud.aiplatform.v1.PredictionService/Predict".to_string(),
        headers,
        body: Bytes::from(payload),
        connection_meta: connection_meta(socket, 5),
    }
}

fn grpc_unknown_request(content: &str, socket: SocketKind) -> RawRequest {
    let mut headers = BTreeMap::new();
    headers.insert("content-type".to_string(), "application/grpc".to_string());
    headers.insert("host".to_string(), "unknown.local".to_string());
    headers.insert(
        ":path".to_string(),
        "/com.example.UnknownService/Generate".to_string(),
    );
    let payload = encode_proto_string_fields(&[(7, content)]);

    RawRequest {
        method: "POST".to_string(),
        path: "/com.example.UnknownService/Generate".to_string(),
        headers,
        body: Bytes::from(payload),
        connection_meta: connection_meta(socket, 6),
    }
}

fn heuristic_request(content: &str, socket: SocketKind) -> RawRequest {
    let mut headers = BTreeMap::new();
    headers.insert("host".to_string(), "mystery.local".to_string());
    headers.insert("content-type".to_string(), "text/plain".to_string());

    RawRequest {
        method: "POST".to_string(),
        path: "/opaque/raw".to_string(),
        headers,
        body: Bytes::from(format!("opaque bytes {} {}", content, "x".repeat(80))),
        connection_meta: connection_meta(socket, 7),
    }
}

fn connection_meta(socket: SocketKind, salt: usize) -> ConnectionMeta {
    let socket_family = match socket {
        SocketKind::TcpV4 => SocketFamily::TcpV4 {
            local: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 18080 + salt as u16 % 1000),
            remote: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443),
        },
        SocketKind::TcpV6 => SocketFamily::TcpV6 {
            local: SocketAddrV6::new(Ipv6Addr::LOCALHOST, 28080 + salt as u16 % 1000, 0, 0),
            remote: SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0),
        },
        SocketKind::UnixDomain => SocketFamily::UnixDomain {
            path: Some(PathBuf::from(format!("/tmp/soth-closeout-{}.sock", salt))),
        },
    };

    ConnectionMeta {
        connection_id: Uuid::new_v4(),
        socket_family,
        process_info: None,
        tls_info: None,
        app_identity: None,
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
        out.push(((value & 0x7F) as u8) | 0x80);
        value >>= 7;
    }
}

fn build_bundle() -> OwnedDetectBundle {
    let mut rest_formats = HashMap::new();
    rest_formats.insert(
        "openai".to_string(),
        RestFormatDescriptor {
            request: RestRequestPaths {
                model: Some("$.model".to_string()),
                messages: Some("$.messages".to_string()),
                temperature: Some("$.temperature".to_string()),
                stream: Some("$.stream".to_string()),
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
    domain_index.insert(
        "aiplatform.googleapis.com".to_string(),
        "google_vertex".to_string(),
    );
    domain_index.insert("warp.dev".to_string(), "warp".to_string());

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
    providers.insert(
        "warp".to_string(),
        ProviderEntry {
            provider_id: Some("warp".to_string()),
            name: Some("Warp".to_string()),
            api_format: Some("graphql".to_string()),
        },
    );

    OwnedDetectBundle {
        rest_formats,
        domain_index,
        llm_providers: providers,
        graphql_operations: GraphQLOperationRegistry::with_default_operations(),
        grpc_services: GrpcServiceRegistry::with_default_services(),
        capture_rules: CaptureRules {
            default_mode: CaptureMode::MetadataOnly,
            full_capture_providers: vec!["openai".to_string(), "google_vertex".to_string()],
            ..CaptureRules::default()
        },
        ..OwnedDetectBundle::default()
    }
}

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}
