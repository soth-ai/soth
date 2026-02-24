use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use soth_detect::{
    process_with_registry_and_intelligence, CaptureRules, ConnectionMeta, GraphQLOperationRegistry,
    GrpcServiceRegistry, IntelligenceStore, OwnedDetectBundle, ParserRegistry, RawRequest,
    RestFormatDescriptor, RestRequestPaths, SocketFamily,
};
use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddrV4};
use uuid::Uuid;

fn bench_process_with_intelligence(c: &mut Criterion) {
    let bundle = build_bundle();
    let bundle_slice = bundle.as_slice();
    let registry = ParserRegistry::default();
    let store = match IntelligenceStore::in_memory() {
        Ok(store) => store,
        Err(_) => return,
    };

    c.bench_function("detect_process_with_intelligence", |b| {
        b.iter(|| {
            let request = build_request(black_box("hello benchmark"));
            let _ =
                process_with_registry_and_intelligence(&registry, &request, &bundle_slice, &store);
        })
    });
}

fn bench_intelligence_signals_query(c: &mut Criterion) {
    let bundle = build_bundle();
    let bundle_slice = bundle.as_slice();
    let registry = ParserRegistry::default();
    let store = match IntelligenceStore::in_memory() {
        Ok(store) => store,
        Err(_) => return,
    };

    for _ in 0..200 {
        let request = build_request("seed event");
        let _ = process_with_registry_and_intelligence(&registry, &request, &bundle_slice, &store);
    }

    c.bench_function("detect_intelligence_signals", |b| {
        b.iter(|| {
            let _ = store.intelligence_signals(black_box(0), black_box(1), black_box(50));
        })
    });
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
                ..RestRequestPaths::default()
            },
            system_in_messages: true,
            ..RestFormatDescriptor::default()
        },
    );

    let mut domain_index = HashMap::new();
    domain_index.insert("api.openai.com".to_string(), "openai".to_string());

    OwnedDetectBundle {
        rest_formats,
        domain_index,
        graphql_operations: GraphQLOperationRegistry::with_default_operations(),
        grpc_services: GrpcServiceRegistry::with_default_services(),
        capture_rules: CaptureRules::default(),
        ..OwnedDetectBundle::default()
    }
}

fn build_request(content: &str) -> RawRequest {
    let mut headers = BTreeMap::new();
    headers.insert("host".to_string(), "api.openai.com".to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());

    RawRequest {
        method: "POST".to_string(),
        path: "/v1/chat/completions".to_string(),
        headers,
        body: Bytes::from(format!(
            "{{\"model\":\"gpt-4o\",\"messages\":[{{\"role\":\"user\",\"content\":\"{}\"}}]}}",
            content
        )),
        connection_meta: ConnectionMeta {
            connection_id: Uuid::new_v4(),
            socket_family: SocketFamily::TcpV4 {
                local: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080),
                remote: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443),
            },
            process_info: None,
            tls_info: None,
            app_identity: None,
        },
    }
}

criterion_group!(
    benches,
    bench_process_with_intelligence,
    bench_intelligence_signals_query
);
criterion_main!(benches);
