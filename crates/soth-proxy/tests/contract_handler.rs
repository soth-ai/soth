use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
use http::{HeaderMap, HeaderValue};
use rusqlite::Connection;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::time::sleep;
use uuid::Uuid;

use soth_bundle::{AssetEntry, BundleManifest, BundleScope, OrgSignedConfig};
use soth_proxy::config::{GateAction, PipelineConfig};
use soth_proxy::{db, ProxyHandler};

#[derive(Serialize)]
struct CanonicalManifest<'a> {
    version: &'a str,
    created_at: i64,
    vendor_sig: &'a str,
    org_approval_sig: Option<&'a str>,
    assets: Vec<&'a AssetEntry>,
    scope: &'a BundleScope,
}

fn canonical_manifest_bytes(manifest: &BundleManifest) -> Vec<u8> {
    let mut assets: Vec<&AssetEntry> = manifest.assets.iter().collect();
    assets.sort_by(|left, right| left.path.cmp(&right.path));
    serde_json::to_vec(&CanonicalManifest {
        version: &manifest.version,
        created_at: manifest.created_at,
        vendor_sig: "",
        org_approval_sig: manifest.org_approval_sig.as_deref(),
        assets,
        scope: &manifest.scope,
    })
    .expect("serialize canonical manifest")
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(format!("{:02x}", byte).as_str());
    }
    out
}

fn signed_manifest_bytes(
    version: &str,
    assets: &HashMap<String, Vec<u8>>,
    vendor_signing_key: &SigningKey,
) -> Vec<u8> {
    let mut entries: Vec<AssetEntry> = assets
        .iter()
        .map(|(path, bytes)| AssetEntry {
            path: path.clone(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
            size_bytes: bytes.len() as u64,
        })
        .collect();
    entries.sort_by(|left, right| left.path.cmp(&right.path));

    let mut manifest = BundleManifest {
        version: version.to_string(),
        created_at: 1_772_000_010,
        vendor_sig: String::new(),
        org_approval_sig: None,
        assets: entries,
        scope: BundleScope::default(),
    };

    let signature = vendor_signing_key.sign(canonical_manifest_bytes(&manifest).as_slice());
    manifest.vendor_sig = hex_encode(signature.to_bytes().as_slice());
    serde_json::to_vec(&manifest).expect("serialize signed manifest")
}

fn detect_bundle_with_openai_catalog() -> soth_detect::OwnedDetectBundle {
    let mut detect = soth_detect::OwnedDetectBundle::default();
    detect
        .domain_index
        .insert("api.openai.com".to_string(), "openai".to_string());
    detect.llm_providers.insert(
        "openai".to_string(),
        soth_detect::ProviderEntry {
            provider_id: Some("openai".to_string()),
            name: Some("openai".to_string()),
            api_format: Some("openai_rest".to_string()),
        },
    );
    detect
}

fn build_handler(
    db_path: &Path,
    pipeline_config: PipelineConfig,
    detect_bundle: soth_detect::OwnedDetectBundle,
) -> ProxyHandler {
    let vendor = SigningKey::from_bytes(&[47u8; 32]);
    let vendor_pubkey = vendor.verifying_key().to_bytes();

    let mut assets = HashMap::new();
    assets.insert(
        "detect/bundle.json".to_string(),
        serde_json::to_vec(&detect_bundle).expect("serialize detect bundle"),
    );
    let manifest = signed_manifest_bytes("bundle-v1", &assets, &vendor);
    let loaded = soth_bundle::load_from_bytes(
        manifest.as_slice(),
        assets,
        &vendor_pubkey,
        &OrgSignedConfig::default(),
    )
    .expect("load bundle");

    let bundle_db = Arc::new(Mutex::new(
        Connection::open(db_path).expect("open bundle db"),
    ));
    let (_watcher, handle) = soth_bundle::BundleWatcher::new(
        loaded,
        vendor_pubkey,
        Arc::new(OrgSignedConfig::default()),
        bundle_db,
        soth_bundle::VerificationOptions::default(),
    )
    .expect("create bundle watcher");

    let proxy_db = Arc::new(Mutex::new(db::open(db_path).expect("open proxy db")));
    ProxyHandler::new(
        handle,
        None,
        proxy_db,
        pipeline_config,
        soth_classify::ClassifyConfig::default(),
        soth_proxy::classify_task::RuntimeConfig::default(),
        "org-test".to_string(),
        "team-test".to_string(),
        "device-test".to_string(),
        "secret-test".to_string(),
    )
}

fn sample_connection_meta(connection_id: Uuid) -> Arc<soth_mitm::ConnectionMeta> {
    Arc::new(soth_mitm::ConnectionMeta {
        connection_id,
        socket_family: soth_mitm::SocketFamily::TcpV4 {
            local: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10_001),
            remote: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443),
        },
        process_info: None,
        tls_info: None,
    })
}

fn sample_request(connection_id: Uuid, host: &str, body: &'static [u8]) -> soth_mitm::RawRequest {
    let mut headers = HeaderMap::new();
    headers.insert(
        "host",
        HeaderValue::from_str(host).expect("valid host header"),
    );
    headers.insert("content-type", HeaderValue::from_static("application/json"));

    soth_mitm::RawRequest {
        method: "POST".to_string(),
        path: "/v1/chat/completions".to_string(),
        headers,
        body: Bytes::from_static(body),
        connection_meta: sample_connection_meta(connection_id),
    }
}

fn sample_response(connection_id: Uuid, body: &'static [u8]) -> soth_mitm::RawResponse {
    soth_mitm::RawResponse {
        status: 200,
        headers: HeaderMap::new(),
        body: Bytes::from_static(body),
        connection_meta: sample_connection_meta(connection_id),
    }
}

fn intercept_row_count(db_path: &Path) -> i64 {
    let conn = Connection::open(db_path).expect("open db for query");
    conn.query_row("SELECT COUNT(*) FROM intercept_records", [], |row| {
        row.get(0)
    })
    .expect("count intercept rows")
}

fn intercept_columns(db_path: &Path) -> HashSet<String> {
    let conn = Connection::open(db_path).expect("open db for schema query");
    let mut stmt = conn
        .prepare("PRAGMA table_info(intercept_records)")
        .expect("prepare table_info");
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .expect("query table_info");
    let mut out = HashSet::new();
    for row in rows {
        out.insert(row.expect("column name"));
    }
    out
}

async fn wait_for_intercept_rows(db_path: &Path, min_rows: i64) {
    for _ in 0..120 {
        if intercept_row_count(db_path) >= min_rows {
            return;
        }
        sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for intercept row count >= {min_rows}");
}

#[tokio::test]
async fn handler_contract_skips_non_cataloged_host_by_default() {
    let db_path = std::env::temp_dir().join(format!("soth-proxy-handler-{}.db", Uuid::new_v4()));
    let handler = build_handler(
        db_path.as_path(),
        PipelineConfig::default(),
        soth_detect::OwnedDetectBundle::default(),
    );

    let request = sample_request(
        Uuid::new_v4(),
        "example.invalid",
        br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}"#,
    );

    use soth_mitm::InterceptHandler;
    let decision = handler.on_request(&request).await;
    assert_eq!(decision, soth_mitm::HandlerDecision::Allow);
    assert_eq!(intercept_row_count(db_path.as_path()), 0);

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn handler_contract_connect_gate_skips_non_catalog_tls() {
    let db_path = std::env::temp_dir().join(format!("soth-proxy-handler-{}.db", Uuid::new_v4()));
    let handler = build_handler(
        db_path.as_path(),
        PipelineConfig::default(),
        soth_detect::OwnedDetectBundle::default(),
    );

    use soth_mitm::InterceptHandler;
    assert!(!handler.should_intercept_tls("example.invalid:443", None));

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn handler_contract_connect_gate_intercepts_catalog_tls() {
    let db_path = std::env::temp_dir().join(format!("soth-proxy-handler-{}.db", Uuid::new_v4()));
    let mut pipeline = PipelineConfig::default();
    pipeline.unknown_app_action = Some(GateAction::Intercept);

    let handler = build_handler(
        db_path.as_path(),
        pipeline,
        detect_bundle_with_openai_catalog(),
    );

    use soth_mitm::InterceptHandler;
    assert!(handler.should_intercept_tls("api.openai.com:443", None));

    let _ = std::fs::remove_file(db_path);
}

#[tokio::test]
async fn handler_contract_intercepts_and_records_request_response_flow() {
    let db_path = std::env::temp_dir().join(format!("soth-proxy-handler-{}.db", Uuid::new_v4()));
    let mut pipeline = PipelineConfig::default();
    pipeline.unknown_app_action = Some(GateAction::Intercept);

    let handler = build_handler(
        db_path.as_path(),
        pipeline,
        detect_bundle_with_openai_catalog(),
    );

    let connection_id = Uuid::new_v4();
    let request = sample_request(
        connection_id,
        "api.openai.com",
        br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"contract-test"}]}"#,
    );

    use soth_mitm::InterceptHandler;
    let decision = handler.on_request(&request).await;
    assert_eq!(decision, soth_mitm::HandlerDecision::Allow);

    let response = sample_response(
        connection_id,
        br#"{"usage":{"prompt_tokens":10,"completion_tokens":20}}"#,
    );
    handler.on_response(&response).await;

    wait_for_intercept_rows(db_path.as_path(), 1).await;
    assert!(intercept_row_count(db_path.as_path()) >= 1);

    let _ = std::fs::remove_file(db_path);
}

#[tokio::test]
async fn handler_contract_streaming_callbacks_complete() {
    let db_path = std::env::temp_dir().join(format!("soth-proxy-handler-{}.db", Uuid::new_v4()));
    let mut pipeline = PipelineConfig::default();
    pipeline.unknown_app_action = Some(GateAction::Intercept);

    let handler = build_handler(
        db_path.as_path(),
        pipeline,
        detect_bundle_with_openai_catalog(),
    );

    let connection_id = Uuid::new_v4();
    let request = sample_request(
        connection_id,
        "api.openai.com",
        br#"{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"stream me"}]}"#,
    );

    use soth_mitm::InterceptHandler;
    let decision = handler.on_request(&request).await;
    assert_eq!(decision, soth_mitm::HandlerDecision::Allow);

    let chunk = soth_mitm::StreamChunk {
        connection_id,
        payload: Bytes::from_static(
            br#"data: {"usage":{"input_tokens":1,"output_tokens":2}}

"#,
        ),
        sequence: 1,
        frame_kind: soth_mitm::FrameKind::SseData,
    };
    handler.on_stream_chunk(&chunk).await;
    handler.on_stream_end(connection_id).await;

    let response = sample_response(connection_id, br#"{}"#);
    handler.on_response(&response).await;

    wait_for_intercept_rows(db_path.as_path(), 1).await;
    assert!(intercept_row_count(db_path.as_path()) >= 1);

    let _ = std::fs::remove_file(db_path);
}

#[tokio::test]
async fn handler_contract_stream_end_without_chunks_is_safe() {
    let db_path = std::env::temp_dir().join(format!("soth-proxy-handler-{}.db", Uuid::new_v4()));
    let mut pipeline = PipelineConfig::default();
    pipeline.unknown_app_action = Some(GateAction::Intercept);

    let handler = build_handler(
        db_path.as_path(),
        pipeline,
        detect_bundle_with_openai_catalog(),
    );

    let connection_id = Uuid::new_v4();
    let request = sample_request(
        connection_id,
        "api.openai.com",
        br#"{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"stream-no-chunk"}]}"#,
    );

    use soth_mitm::InterceptHandler;
    let decision = handler.on_request(&request).await;
    assert_eq!(decision, soth_mitm::HandlerDecision::Allow);

    // Validate no-chunk stream shutdown path: flow can finalize without any stream data.
    handler.on_stream_end(connection_id).await;
    handler.on_connection_close(connection_id);

    let response = sample_response(connection_id, br#"{}"#);
    handler.on_response(&response).await;

    wait_for_intercept_rows(db_path.as_path(), 1).await;
    assert!(intercept_row_count(db_path.as_path()) >= 1);

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn handler_contract_intercept_schema_contains_reference_columns() {
    let db_path = std::env::temp_dir().join(format!("soth-proxy-handler-{}.db", Uuid::new_v4()));
    let _handler = build_handler(
        db_path.as_path(),
        PipelineConfig::default(),
        soth_detect::OwnedDetectBundle::default(),
    );
    let columns = intercept_columns(db_path.as_path());

    let expected = [
        "event_id",
        "timestamp_utc",
        "provider",
        "model",
        "endpoint_hash",
        "api_version",
        "is_multi_turn",
        "conversation_turn",
        "input_tokens",
        "output_tokens",
        "estimated_cost_usd",
        "latency_ms",
        "ttfb_ms",
        "policy_decision",
        "policy_rule_id",
        "classification_flags",
        "redaction_event",
        "redaction_count",
        "commitment_hash",
        "commitment_nonce",
        "embedding",
        "topic_cluster_id",
        "semantic_hash",
        "use_case_label",
        "use_case_confidence",
        "secondary_label",
        "complexity_score",
        "volatility_class",
        "is_semantic_collision",
        "collision_response_stability",
        "system_prompt_hash",
        "dynamic_fraction",
        "code_present",
        "detected_languages",
        "credential_detected",
        "private_key_detected",
        "org_pattern_matches",
        "anomaly_score",
        "anomaly_signals",
        "model_was_rerouted",
        "original_model",
        "parse_confidence",
        "parser_id",
        "is_ai_call",
    ];

    for name in expected {
        assert!(
            columns.contains(name),
            "missing column in intercept_records: {name}"
        );
    }

    let _ = std::fs::remove_file(db_path);
}

#[tokio::test]
async fn handler_contract_intercept_row_persists_reference_fields() {
    let db_path = std::env::temp_dir().join(format!("soth-proxy-handler-{}.db", Uuid::new_v4()));
    let mut pipeline = PipelineConfig::default();
    pipeline.unknown_app_action = Some(GateAction::Intercept);

    let handler = build_handler(
        db_path.as_path(),
        pipeline,
        detect_bundle_with_openai_catalog(),
    );

    let connection_id = Uuid::new_v4();
    let request = sample_request(
        connection_id,
        "api.openai.com",
        br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"schema-persistence-check"}]}"#,
    );

    use soth_mitm::InterceptHandler;
    let decision = handler.on_request(&request).await;
    assert_eq!(decision, soth_mitm::HandlerDecision::Allow);

    let response = sample_response(
        connection_id,
        br#"{"usage":{"prompt_tokens":9,"completion_tokens":21}}"#,
    );
    handler.on_response(&response).await;
    wait_for_intercept_rows(db_path.as_path(), 1).await;

    let conn = Connection::open(db_path.as_path()).expect("open db");
    let row = conn
        .query_row(
            "SELECT
                provider,
                model,
                endpoint_hash,
                policy_decision,
                commitment_hash,
                commitment_nonce,
                parse_confidence,
                parser_id,
                is_ai_call,
                classification_flags,
                detected_languages,
                anomaly_signals
             FROM intercept_records
             ORDER BY timestamp_utc DESC
             LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                ))
            },
        )
        .expect("read intercept row");

    assert_eq!(row.0, "openai");
    assert!(!row.1.is_empty());
    assert!(!row.2.is_empty());
    assert!(!row.3.is_empty());
    assert_eq!(row.4.len(), 64);
    assert_eq!(row.5.len(), 32);
    assert!(matches!(row.6.as_str(), "FULL" | "PARTIAL" | "HEURISTIC"));
    assert!(!row.7.is_empty());
    assert!(matches!(row.8, 0 | 1));
    assert!(
        serde_json::from_str::<Vec<String>>(row.9.as_str()).is_ok(),
        "classification_flags should be valid JSON array"
    );
    assert!(
        serde_json::from_str::<Vec<String>>(row.10.as_str()).is_ok(),
        "detected_languages should be valid JSON array"
    );
    assert!(
        serde_json::from_str::<Vec<String>>(row.11.as_str()).is_ok(),
        "anomaly_signals should be valid JSON array"
    );

    let _ = std::fs::remove_file(db_path);
}
