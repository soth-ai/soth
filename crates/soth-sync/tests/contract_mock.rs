use axum::body::Bytes;
use axum::extract::{Path as AxumPath, State};
use axum::http::{
    header::{CONTENT_TYPE, ETAG},
    HeaderMap, HeaderValue, StatusCode,
};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use flate2::read::GzDecoder;
use rusqlite::Connection;
use serde_json::json;
use sha2::{Digest, Sha256};
use soth_core::api::{
    version::{API_VERSION, API_VERSION_HEADER},
    BodyUploadResponse, ConfigBudget, ConfigBudgetLimit, ConfigOrg, ConfigPolicy, ConfigResponse,
    ConfigTeam, ConfigUser, EventBatchRequest, EventBatchResponse, HeartbeatRequest,
    HeartbeatResponse, RegistryVersionResponse,
};
use soth_core::types::{AgentInfo, DetectionSource, EventSource, WrapDirection, WrapEvent};
use soth_sync::agent::{SyncAgent, SyncAgentConfig};
use soth_sync::config_puller::ConfigPuller;
use soth_sync::registry_puller::RegistryPuller;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

const TEST_BUNDLE_VERSION: &str = "bundle-v1";
const TEST_BUNDLE_JSON: &str = r#"{
  "version":"bundle-v1",
  "compiled_at":"2026-02-13T00:00:00Z",
  "bundle_type":"local",
  "domain_index":[],
  "providers":{
    "openai":{
      "id":"openai",
      "name":"OpenAI",
      "type":"ai-inference",
      "domains":["api.openai.com"]
    }
  },
  "filters":{},
  "pricing":{},
  "stats":{"providers":1,"domains":1,"formats":1}
}"#;

fn test_bundle_sha() -> String {
    format!("{:x}", Sha256::digest(TEST_BUNDLE_JSON.as_bytes()))
}

#[derive(Debug, Clone, Default)]
struct CapturedState {
    metadata_requests: Vec<EventBatchRequest>,
    body_upload_payloads: Vec<String>,
    heartbeat_requests: Vec<HeartbeatRequest>,
    registry_version_requests: usize,
    registry_bundle_requests: usize,
    saw_version_headers: Vec<String>,
    saw_authorization_headers: Vec<String>,
    body_failures_remaining: usize,
}

type SharedState = Arc<Mutex<CapturedState>>;

#[tokio::test]
async fn contract_sync_endpoints_and_cursors() {
    let state = Arc::new(Mutex::new(CapturedState::default()));
    let Some(server_url) = start_mock_server(state.clone()).await else {
        eprintln!("Skipping contract_sync_endpoints_and_cursors: cannot bind localhost listener");
        return;
    };

    let temp = TempDir::new().unwrap();
    let db_path = temp.path().join("events.db");
    create_test_db(&db_path, false);
    let cache_path = temp.path().join("cloud_cache.json");
    let registry_cache_path = temp.path().join("registry_cache.json");
    let retry_queue_dir = temp.path().join("retry");

    let registry_puller =
        RegistryPuller::new(server_url.clone(), "test-key", registry_cache_path.clone());
    let puller = ConfigPuller::new(server_url.clone(), "test-key", cache_path.clone())
        .with_registry_puller(registry_puller);
    let pulled = puller.pull_once().await.unwrap();
    assert!(pulled.is_some());

    let config = SyncAgentConfig {
        endpoint: server_url,
        api_key: "test-key".to_string(),
        event_db_path: db_path.clone(),
        cache_path,
        agent_instance_id: "agent-instance-test".to_string(),
        proxy_version: "0.1.0-test".to_string(),
        retry_queue_dir,
        retry_queue_max_bytes: 10 * 1024 * 1024,
        sync_interval: Duration::from_secs(1),
        batch_size: 100,
        body_batch_size: 100,
        body_upload_enabled: true,
        metadata_max_events_per_batch: 200,
        metadata_max_compressed_batch_bytes: 5 * 1024 * 1024,
        body_upload_max_bytes: 15 * 1024 * 1024,
        global_tags: BTreeMap::from([("project".to_string(), "sync-test".to_string())]),
    };
    let agent = SyncAgent::new(config, Some(puller)).unwrap();

    let summary = agent.tick().await.unwrap();
    assert_eq!(summary.metadata_sent, 1);
    assert_eq!(summary.body_uploaded, 1);
    assert_eq!(summary.retry_uploaded, 0);

    let heartbeat_ok = agent.send_heartbeat().await.unwrap();
    assert!(heartbeat_ok);

    let conn = Connection::open(&db_path).unwrap();
    let metadata_cursor: String = conn
        .query_row(
            "SELECT value FROM sync_state WHERE key = 'last_synced_seq'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let body_cursor: String = conn
        .query_row(
            "SELECT value FROM sync_state WHERE key = 'last_body_synced_seq'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(metadata_cursor, "1");
    assert_eq!(body_cursor, "1");

    let captured = state.lock().unwrap().clone();
    assert_eq!(captured.metadata_requests.len(), 1);
    assert_eq!(captured.heartbeat_requests.len(), 1);
    assert_eq!(captured.body_upload_payloads.len(), 1);
    assert_eq!(captured.registry_version_requests, 1);
    assert_eq!(captured.registry_bundle_requests, 1);
    assert!(
        registry_cache_path.exists(),
        "registry bundle cache should be materialized"
    );

    let metadata = &captured.metadata_requests[0];
    assert_eq!(metadata.batch.len(), 1);
    assert_eq!(
        metadata.batch[0].tags.as_ref().unwrap().get("project"),
        Some(&"sync-test".to_string())
    );

    let upload_body = &captured.body_upload_payloads[0];
    assert!(
        !upload_body.contains("alice@example.com"),
        "request body upload leaked email PII"
    );
    assert!(
        !upload_body.contains("123-45-6789"),
        "request body upload leaked SSN PII"
    );

    assert!(
        captured
            .saw_version_headers
            .iter()
            .all(|header| header == API_VERSION),
        "all requests must send API version header"
    );
    assert!(
        captured
            .saw_authorization_headers
            .iter()
            .all(|header| header == "Bearer test-key"),
        "all requests must send bearer key"
    );
}

#[tokio::test]
async fn contract_retry_queue_on_body_upload_failure() {
    let state = Arc::new(Mutex::new(CapturedState {
        body_failures_remaining: 1,
        ..CapturedState::default()
    }));
    let Some(server_url) = start_mock_server(state.clone()).await else {
        eprintln!(
            "Skipping contract_retry_queue_on_body_upload_failure: cannot bind localhost listener"
        );
        return;
    };

    let temp = TempDir::new().unwrap();
    let db_path = temp.path().join("events.db");
    create_test_db(&db_path, false);
    let cache_path = temp.path().join("cloud_cache.json");
    let registry_cache_path = temp.path().join("registry_cache.json");
    let retry_queue_dir = temp.path().join("retry");

    let registry_puller =
        RegistryPuller::new(server_url.clone(), "test-key", registry_cache_path.clone());
    let puller = ConfigPuller::new(server_url.clone(), "test-key", cache_path.clone())
        .with_registry_puller(registry_puller);
    let _ = puller.pull_once().await.unwrap();

    let config = SyncAgentConfig {
        endpoint: server_url,
        api_key: "test-key".to_string(),
        event_db_path: db_path,
        cache_path,
        agent_instance_id: "agent-instance-retry".to_string(),
        proxy_version: "0.1.0-test".to_string(),
        retry_queue_dir: retry_queue_dir.clone(),
        retry_queue_max_bytes: 10 * 1024 * 1024,
        sync_interval: Duration::from_secs(1),
        batch_size: 100,
        body_batch_size: 100,
        body_upload_enabled: true,
        metadata_max_events_per_batch: 200,
        metadata_max_compressed_batch_bytes: 5 * 1024 * 1024,
        body_upload_max_bytes: 15 * 1024 * 1024,
        global_tags: BTreeMap::new(),
    };
    let agent = SyncAgent::new(config, Some(puller)).unwrap();

    let first = agent.tick().await.unwrap();
    assert_eq!(first.metadata_sent, 1);
    assert_eq!(first.body_uploaded, 0);
    assert_eq!(first.retry_uploaded, 0);

    let queued_files = std::fs::read_dir(&retry_queue_dir)
        .unwrap()
        .filter_map(Result::ok)
        .count();
    assert!(
        queued_files > 0,
        "retry queue should persist failed body upload"
    );

    let second = agent.tick().await.unwrap();
    assert_eq!(second.metadata_sent, 0);
    assert_eq!(second.retry_uploaded, 1);
}

#[tokio::test]
async fn contract_shutdown_flush_drains_multiple_rounds() {
    let state = Arc::new(Mutex::new(CapturedState::default()));
    let Some(server_url) = start_mock_server(state.clone()).await else {
        eprintln!(
            "Skipping contract_shutdown_flush_drains_multiple_rounds: cannot bind localhost listener"
        );
        return;
    };

    let temp = TempDir::new().unwrap();
    let db_path = temp.path().join("events.db");
    create_test_db(&db_path, true);
    let cache_path = temp.path().join("cloud_cache.json");
    let registry_cache_path = temp.path().join("registry_cache.json");
    let retry_queue_dir = temp.path().join("retry");

    let registry_puller =
        RegistryPuller::new(server_url.clone(), "test-key", registry_cache_path.clone());
    let puller = ConfigPuller::new(server_url.clone(), "test-key", cache_path.clone())
        .with_registry_puller(registry_puller);
    let _ = puller.pull_once().await.unwrap();

    let config = SyncAgentConfig {
        endpoint: server_url,
        api_key: "test-key".to_string(),
        event_db_path: db_path.clone(),
        cache_path,
        agent_instance_id: "agent-instance-shutdown".to_string(),
        proxy_version: "0.1.0-test".to_string(),
        retry_queue_dir,
        retry_queue_max_bytes: 10 * 1024 * 1024,
        sync_interval: Duration::from_secs(1),
        batch_size: 1,
        body_batch_size: 1,
        body_upload_enabled: true,
        metadata_max_events_per_batch: 200,
        metadata_max_compressed_batch_bytes: 5 * 1024 * 1024,
        body_upload_max_bytes: 15 * 1024 * 1024,
        global_tags: BTreeMap::new(),
    };
    let agent = SyncAgent::new(config, Some(puller)).unwrap();

    let summary = agent.flush_for_shutdown(5).await.unwrap();
    assert_eq!(summary.metadata_sent, 2);
    assert_eq!(summary.body_uploaded, 1);

    let conn = Connection::open(&db_path).unwrap();
    let metadata_cursor: String = conn
        .query_row(
            "SELECT value FROM sync_state WHERE key = 'last_synced_seq'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(metadata_cursor, "2");
}

#[tokio::test]
async fn contract_shutdown_flush_surfaces_sync_failure() {
    let temp = TempDir::new().unwrap();
    let db_path = temp.path().join("events.db");
    create_test_db(&db_path, false);

    let config = SyncAgentConfig {
        endpoint: "http://127.0.0.1:1".to_string(),
        api_key: "test-key".to_string(),
        event_db_path: db_path,
        cache_path: temp.path().join("cloud_cache.json"),
        agent_instance_id: "agent-instance-failure".to_string(),
        proxy_version: "0.1.0-test".to_string(),
        retry_queue_dir: temp.path().join("retry"),
        retry_queue_max_bytes: 10 * 1024 * 1024,
        sync_interval: Duration::from_secs(1),
        batch_size: 10,
        body_batch_size: 10,
        body_upload_enabled: true,
        metadata_max_events_per_batch: 200,
        metadata_max_compressed_batch_bytes: 5 * 1024 * 1024,
        body_upload_max_bytes: 15 * 1024 * 1024,
        global_tags: BTreeMap::new(),
    };
    let agent = SyncAgent::new(config, None).unwrap();
    let error = agent.flush_for_shutdown(2).await.unwrap_err();
    assert!(
        !error.to_string().is_empty(),
        "expected non-empty sync failure error"
    );
}

async fn start_mock_server(state: SharedState) -> Option<String> {
    let app = Router::new()
        .route("/api/v1/events/batch", post(events_batch_handler))
        .route("/api/v1/events/:id/body", post(body_upload_handler))
        .route("/api/v1/config", get(config_handler))
        .route("/api/v1/heartbeat", post(heartbeat_handler))
        .route("/api/v1/registry/version", get(registry_version_handler))
        .route("/api/v1/registry/bundle", get(registry_bundle_handler))
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(error) => {
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                return None;
            }
            panic!("Failed to bind mock server listener: {error}");
        }
    };
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Some(format!("http://{}", addr))
}

async fn events_batch_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<EventBatchResponse>) {
    record_headers(&state, &headers);
    let request = match decode_event_batch_request(&headers, body.as_ref()) {
        Ok(request) => request,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(EventBatchResponse {
                    accepted: 0,
                    rejected: 1,
                    errors: vec![soth_core::api::EventError {
                        event_id: "decode".to_string(),
                        reason: error,
                    }],
                    config_changed: false,
                    server_time: Utc::now().to_rfc3339(),
                }),
            );
        }
    };
    state
        .lock()
        .unwrap()
        .metadata_requests
        .push(request.clone());
    (
        StatusCode::OK,
        Json(EventBatchResponse {
            accepted: request.batch.len() as u64,
            rejected: 0,
            errors: Vec::new(),
            config_changed: false,
            server_time: Utc::now().to_rfc3339(),
        }),
    )
}

fn decode_event_batch_request(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<EventBatchRequest, String> {
    let is_gzip = headers
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("gzip"))
        .unwrap_or(false);
    if !is_gzip {
        return serde_json::from_slice::<EventBatchRequest>(body).map_err(|e| e.to_string());
    }

    let mut decoder = GzDecoder::new(body);
    let mut decoded = Vec::new();
    std::io::Read::read_to_end(&mut decoder, &mut decoded).map_err(|error| error.to_string())?;
    serde_json::from_slice::<EventBatchRequest>(&decoded).map_err(|e| e.to_string())
}

async fn body_upload_handler(
    State(state): State<SharedState>,
    AxumPath(_event_id): AxumPath<String>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<BodyUploadResponse>) {
    record_headers(&state, &headers);
    let mut guard = state.lock().unwrap();
    if guard.body_failures_remaining > 0 {
        guard.body_failures_remaining -= 1;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(BodyUploadResponse {
                stored: false,
                request_key: None,
                response_key: None,
            }),
        );
    }
    guard
        .body_upload_payloads
        .push(String::from_utf8_lossy(&body).to_string());
    (
        StatusCode::OK,
        Json(BodyUploadResponse {
            stored: true,
            request_key: Some("r2/request".to_string()),
            response_key: Some("r2/response".to_string()),
        }),
    )
}

async fn config_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> (StatusCode, Json<ConfigResponse>) {
    record_headers(&state, &headers);
    (
        StatusCode::OK,
        Json(ConfigResponse {
            user: ConfigUser {
                id: "u_1".to_string(),
                name: "Test User".to_string(),
                email: "test@example.com".to_string(),
            },
            team: ConfigTeam {
                id: "t_1".to_string(),
                name: "Team".to_string(),
                slug: "team".to_string(),
            },
            org: ConfigOrg {
                id: "o_1".to_string(),
                name: "Org".to_string(),
                plan: "free".to_string(),
            },
            policies: vec![ConfigPolicy {
                name: "deny-x".to_string(),
                scope: "team".to_string(),
                rego: "package mcp.policy\n default decision := {\"allow\": true}".to_string(),
                version: "v1".to_string(),
            }],
            budget: ConfigBudget {
                enforcement: "warn".to_string(),
                limits: vec![ConfigBudgetLimit {
                    scope: "org".to_string(),
                    model: None,
                    daily_usd: Some(100.0),
                    weekly_usd: None,
                    monthly_usd: None,
                    remaining_usd: Some(50.0),
                }],
            },
            body_sync_level: "bodies_redacted".to_string(),
            config_version: "cfg_v1".to_string(),
            bundle_version: Some(TEST_BUNDLE_VERSION.to_string()),
        }),
    )
}

async fn heartbeat_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<HeartbeatRequest>,
) -> (StatusCode, Json<HeartbeatResponse>) {
    record_headers(&state, &headers);
    state.lock().unwrap().heartbeat_requests.push(request);
    (
        StatusCode::OK,
        Json(HeartbeatResponse {
            ok: true,
            config_changed: false,
            server_time: Utc::now().to_rfc3339(),
        }),
    )
}

async fn registry_version_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> (StatusCode, Json<RegistryVersionResponse>) {
    record_headers(&state, &headers);
    state.lock().unwrap().registry_version_requests += 1;
    (
        StatusCode::OK,
        Json(RegistryVersionResponse {
            bundle_type: "local".to_string(),
            version: TEST_BUNDLE_VERSION.to_string(),
            sha256: test_bundle_sha(),
            compiled_at: Utc::now().to_rfc3339(),
            provider_count: 3,
            domain_count: 10,
            format_count: 5,
            size_bytes: TEST_BUNDLE_JSON.as_bytes().len() as u64,
        }),
    )
}

async fn registry_bundle_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    record_headers(&state, &headers);
    state.lock().unwrap().registry_bundle_requests += 1;

    let mut response_headers = HeaderMap::new();
    response_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response_headers.insert(
        ETAG,
        HeaderValue::from_str(test_bundle_sha().as_str()).unwrap(),
    );
    response_headers.insert(
        "x-soth-bundle-version",
        HeaderValue::from_static(TEST_BUNDLE_VERSION),
    );

    (StatusCode::OK, response_headers, TEST_BUNDLE_JSON)
}

fn record_headers(state: &SharedState, headers: &HeaderMap) {
    let mut guard = state.lock().unwrap();
    guard.saw_version_headers.push(
        headers
            .get(API_VERSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string(),
    );
    guard.saw_authorization_headers.push(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string(),
    );
}

fn create_test_db(path: &Path, with_second_event: bool) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        CREATE TABLE wrap_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            session_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            event_json TEXT NOT NULL
        );
        CREATE TABLE wrap_event_payloads (
            event_id TEXT NOT NULL,
            payload_kind TEXT NOT NULL,
            payload BLOB NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (event_id, payload_kind)
        );
        CREATE TABLE sync_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        "#,
    )
    .unwrap();

    let event = make_event("evt-1");
    conn.execute(
        "INSERT INTO wrap_events (id, session_id, timestamp, event_json) VALUES (?1, ?2, ?3, ?4)",
        (
            &event.id,
            &event.session_id,
            event.timestamp.to_rfc3339(),
            serde_json::to_string(&event).unwrap(),
        ),
    )
    .unwrap();
    conn.execute(
        "INSERT INTO wrap_event_payloads (event_id, payload_kind, payload, created_at) VALUES (?1, 'request', ?2, ?3)",
        (
            &event.id,
            json!({
                "input":"hello",
                "email":"alice@example.com",
                "ssn":"123-45-6789"
            })
            .to_string()
            .into_bytes(),
            Utc::now().to_rfc3339(),
        ),
    )
    .unwrap();

    if with_second_event {
        let second = make_event("evt-2");
        conn.execute(
            "INSERT INTO wrap_events (id, session_id, timestamp, event_json) VALUES (?1, ?2, ?3, ?4)",
            (
                &second.id,
                &second.session_id,
                second.timestamp.to_rfc3339(),
                serde_json::to_string(&second).unwrap(),
            ),
        )
        .unwrap();
    }
}

fn make_event(id: &str) -> WrapEvent {
    let mut event = WrapEvent::new(
        "session-1",
        "api.openai.com",
        WrapDirection::Out,
        AgentInfo::new("codex", DetectionSource::CommandLine),
    )
    .with_source(EventSource::AiProxy)
    .with_provider("openai")
    .with_model("gpt-5")
    .with_method("POST /v1/responses")
    .with_usage_tokens(10, 20)
    .with_payload_sizes(Some(128), Some(512))
    .with_latency(42)
    .with_cost(0.1234);
    event.id = id.to_string();
    event.request_content_ref = Some(format!("sqlite://wrap_event_payloads/{id}/request"));
    event.content_preview = Some("{\"input\":\"hello\"}".to_string());
    event.tags = Some(BTreeMap::from([("source".to_string(), "test".to_string())]));
    event.headers = Some(BTreeMap::from([(
        "x-request-id".to_string(),
        "req_123".to_string(),
    )]));
    event
}
