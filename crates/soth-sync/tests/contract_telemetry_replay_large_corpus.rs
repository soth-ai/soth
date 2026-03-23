use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use chrono::Utc;
use rusqlite::{params, Connection};
use tempfile::TempDir;
use tokio::sync::mpsc;
use uuid::Uuid;

use soth_core::DetectedProvider;
use soth_core::{
    CaptureMode, EndpointType, ParseConfidence, ParseSource, RequestMethod, SensitiveCodeFlags,
    SurfaceType, TelemetryEvent, TelemetryPolicyKind, UseCaseLabel, VolatilityClass,
};
use soth_sync::api_types::TelemetryBatchRequest;
use soth_sync::telemetry::{TelemetryOutbox, TelemetryRuntimeConfig, TelemetrySyncRuntime};
use soth_sync::TelemetrySyncConfig;
use soth_telemetry::{SignedBatch, TelemetryBatch, TransmittedBatch};

#[derive(Clone)]
struct RoutedTelemetryServerState {
    calls: Arc<AtomicUsize>,
}

async fn routed_telemetry_handler(
    State(state): State<RoutedTelemetryServerState>,
    payload: Bytes,
) -> StatusCode {
    state.calls.fetch_add(1, Ordering::SeqCst);

    let Ok(batch) = serde_json::from_slice::<TelemetryBatchRequest>(payload.as_ref()) else {
        return StatusCode::BAD_REQUEST;
    };

    if batch.org_id.starts_with("ok-") {
        StatusCode::OK
    } else if batch.org_id.starts_with("retry-") {
        StatusCode::SERVICE_UNAVAILABLE
    } else if batch.org_id.starts_with("bad-") {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

async fn start_telemetry_server(state: RoutedTelemetryServerState) -> Option<String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.ok()?;
    let addr = listener.local_addr().ok()?;
    let app = Router::new()
        .route("/v1/edge/telemetry/batch", post(routed_telemetry_handler))
        .with_state(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Some(format!("http://{addr}"))
}

fn sample_event(event_id: Uuid) -> TelemetryEvent {
    TelemetryEvent {
        event_id,
        timestamp_epoch_ms: 1_700_000_001_000,
        connection_id: None,
        provider: "openai".to_string(),
        model: Some("gpt-4o-mini".to_string()),
        endpoint_type: EndpointType::ChatCompletion,
        parse_confidence: ParseConfidence::Full,
        parse_source: ParseSource::Rest {
            provider: DetectedProvider::OpenAi,
        },
        capture_mode: CaptureMode::MetadataOnly,
        use_case: UseCaseLabel::Unknown,
        volatility_class: VolatilityClass::Static,
        cache_level: None,
        routing_reason: None,
        request_method: RequestMethod::Post,
        estimated_input_tokens: Some(12),
        estimated_output_tokens: Some(34),
        estimated_cost_usd: Some(0.001),
        process_resolution: None,
        traffic_classification: None,
        languages: Vec::new(),
        import_categories: Vec::new(),
        classification_flags: Vec::new(),
        anomaly_flags: Vec::new(),
        anomaly_score: Some(0.1),
        policy_kind: Some(TelemetryPolicyKind::Allow),
        bundle_trust_level: Some(soth_core::BundleTrustLevel::Verified),
        sensitive_code_flags: SensitiveCodeFlags::default(),
        session_key_hash: String::new(),
        is_prefix_repeat: false,
        is_code_context_repeat: false,
        novel_token_count: 0,
        repeated_token_count: 0,
        first_step_event_id: None,
        original_event_id: None,
        prefix_hash: None,
        agent_step_number: None,
        is_historical: false,
        data_source: soth_core::DataSource::LiveProxy,
        original_timestamp: None,
        topic_cluster_id: 0,
        semantic_hash: String::new(),
        is_semantic_collision: false,
        endpoint_hash: String::new(),
        policy_rule_id: None,
        use_case_confidence: 0.0,
        secondary_label: None,
        complexity_score: 0,
        embedding_norm: 0.0,
        system_prompt_hash: None,
        system_prompt_token_length: None,
        dynamic_fraction: 0.0,
        prefix_repeat_signature: None,
        tool_definition_hash: None,
        collision_response_stability: None,
        commitment_hash: String::new(),
        code_fraction: 0.0,
        actual_output_tokens: None,
        finish_reason: None,
        response_latency_ms: None,
        ttfb_ms: None,
        session_request_count: None,
        session_total_tokens: None,
        session_credential_alerts: None,
        conversation_turn: None,
        ws_turn_number: None,
        session_id: None,
        product_id: None,
        surface_type: SurfaceType::Unknown,
        is_shadow_it: false,
    }
}

fn sample_batch(batch_id: Uuid, event_id: Uuid, org_id: String) -> TransmittedBatch {
    TransmittedBatch::Signed(SignedBatch {
        batch: TelemetryBatch {
            batch_id,
            org_id,
            proxy_version: "proxy-v1".to_string(),
            bundle_version: "bundle-v1".to_string(),
            events: vec![sample_event(event_id)],
            event_count: 1,
            timestamp_utc: 1_700_000_001,
            observation_records: None,
        },
        proxy_signature: [0u8; 64],
        proxy_pubkey: [1u8; 32],
        canonical_hash: "signed-hash-test".to_string(),
    })
}

fn ensure_outbox_schema(db_path: &Path) {
    let (tx, _rx) = mpsc::unbounded_channel::<String>();
    let _ = TelemetryOutbox::new(db_path, tx).expect("create outbox schema");
}

fn seed_outbox_row(
    conn: &Connection,
    batch: &TransmittedBatch,
    status: &str,
    attempts: u8,
    first_queued_at: i64,
    next_attempt_at: Option<i64>,
) {
    conn.execute(
        "INSERT INTO telemetry_outbox
         (batch_id, org_id, payload_json, payload_hash, encrypted, status, attempts, first_queued_at, last_attempt_at, next_attempt_at, last_error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9, NULL)",
        params![
            batch.batch_id().to_string(),
            batch.org_id(),
            serde_json::to_string(batch).expect("serialize batch payload"),
            batch.payload_hash(),
            if batch.is_encrypted() { 1i64 } else { 0i64 },
            status,
            i64::from(attempts),
            first_queued_at,
            next_attempt_at
        ],
    )
    .expect("seed telemetry_outbox row");
}

fn seed_transmitted_row(conn: &Connection, batch: &TransmittedBatch, status: &str, now: i64) {
    let event_id = match batch {
        TransmittedBatch::Signed(signed) => signed.batch.events[0].event_id,
        TransmittedBatch::Encrypted(_) => panic!("test fixtures seed signed batches only"),
    };
    conn.execute(
        "INSERT INTO transmitted_events
         (event_id, transmitted_at, batch_id, payload_hash, transmission_status, encrypted)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            event_id.to_string(),
            now,
            batch.batch_id().to_string(),
            batch.payload_hash(),
            status,
            if batch.is_encrypted() { 1i64 } else { 0i64 }
        ],
    )
    .expect("seed transmitted_events row");
}

fn outbox_status_count(db_path: &Path, status: &str) -> i64 {
    let conn = Connection::open(db_path).expect("open sqlite for outbox count");
    conn.query_row(
        "SELECT COUNT(*) FROM telemetry_outbox WHERE status = ?1",
        params![status],
        |row| row.get(0),
    )
    .expect("count outbox status")
}

fn transmitted_status_count(db_path: &Path, status: &str) -> i64 {
    let conn = Connection::open(db_path).expect("open sqlite for transmitted count");
    conn.query_row(
        "SELECT COUNT(*) FROM transmitted_events WHERE transmission_status = ?1",
        params![status],
        |row| row.get(0),
    )
    .expect("count transmitted status")
}

fn outbox_dead_non_unit_attempts(db_path: &Path) -> i64 {
    let conn = Connection::open(db_path).expect("open sqlite for attempts query");
    conn.query_row(
        "SELECT COUNT(*) FROM telemetry_outbox WHERE status = 'DEAD' AND attempts != 1",
        [],
        |row| row.get(0),
    )
    .expect("query dead attempt distribution")
}

async fn wait_for_outbox_status(db_path: &Path, status: &str, expected: i64, max_wait: Duration) {
    let steps = (max_wait.as_millis() / 25).max(1);
    for _ in 0..steps {
        if outbox_status_count(db_path, status) == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "timed out waiting for outbox status={status} expected={expected}, got={}",
        outbox_status_count(db_path, status)
    );
}

#[tokio::test]
async fn telemetry_replay_large_corpus_startup_drain_matrix() {
    let temp = TempDir::new().expect("temp dir");
    let db_path = temp.path().join("events.db");
    ensure_outbox_schema(db_path.as_path());

    let now = Utc::now().timestamp();
    let conn = Connection::open(&db_path).expect("open db for seeding");
    let queued_due = 120usize;
    let failed_due = 80usize;
    let failed_future = 40usize;
    let sent_existing = 20usize;

    for idx in 0..queued_due {
        let batch = sample_batch(
            Uuid::from_u128(0x1111_0000_0000_0000_0000_0000_0000_0000u128 + idx as u128),
            Uuid::from_u128(0xaaaa_0000_0000_0000_0000_0000_0000_0000u128 + idx as u128),
            format!("ok-q-{idx}"),
        );
        seed_outbox_row(&conn, &batch, "QUEUED", 0, now - 60, Some(now - 1));
        seed_transmitted_row(&conn, &batch, "QUEUED", now);
    }
    for idx in 0..failed_due {
        let batch = sample_batch(
            Uuid::from_u128(0x2222_0000_0000_0000_0000_0000_0000_0000u128 + idx as u128),
            Uuid::from_u128(0xbbbb_0000_0000_0000_0000_0000_0000_0000u128 + idx as u128),
            format!("ok-f-{idx}"),
        );
        seed_outbox_row(&conn, &batch, "FAILED", 1, now - 120, Some(now - 1));
        seed_transmitted_row(&conn, &batch, "FAILED", now);
    }
    for idx in 0..failed_future {
        let batch = sample_batch(
            Uuid::from_u128(0x3333_0000_0000_0000_0000_0000_0000_0000u128 + idx as u128),
            Uuid::from_u128(0xcccc_0000_0000_0000_0000_0000_0000_0000u128 + idx as u128),
            format!("ok-future-{idx}"),
        );
        seed_outbox_row(&conn, &batch, "FAILED", 2, now - 120, Some(now + 3600));
        seed_transmitted_row(&conn, &batch, "FAILED", now);
    }
    for idx in 0..sent_existing {
        let batch = sample_batch(
            Uuid::from_u128(0x4444_0000_0000_0000_0000_0000_0000_0000u128 + idx as u128),
            Uuid::from_u128(0xdddd_0000_0000_0000_0000_0000_0000_0000u128 + idx as u128),
            format!("ok-sent-{idx}"),
        );
        seed_outbox_row(&conn, &batch, "SENT", 0, now - 120, None);
        seed_transmitted_row(&conn, &batch, "SENT", now);
    }
    drop(conn);

    let calls = Arc::new(AtomicUsize::new(0));
    let Some(endpoint) = start_telemetry_server(RoutedTelemetryServerState {
        calls: calls.clone(),
    })
    .await
    else {
        eprintln!(
            "Skipping telemetry_replay_large_corpus_startup_drain_matrix: cannot bind localhost listener"
        );
        return;
    };

    let runtime = TelemetrySyncRuntime::start(TelemetryRuntimeConfig {
        endpoint,
        api_key: "test-key".to_string(),
        device_id_hash: "device-hash-test".to_string(),
        telemetry_signing_key_hex: None,
        db: Arc::new(Mutex::new(
            Connection::open(&db_path).expect("open runtime db"),
        )),
        telemetry: TelemetrySyncConfig::default(),
        local_secret: vec![],
    })
    .expect("start telemetry runtime");

    let expected_sent_total = (queued_due + failed_due + sent_existing) as i64;
    wait_for_outbox_status(
        db_path.as_path(),
        "SENT",
        expected_sent_total,
        Duration::from_secs(8),
    )
    .await;
    assert_eq!(
        outbox_status_count(db_path.as_path(), "FAILED"),
        failed_future as i64
    );
    assert_eq!(outbox_status_count(db_path.as_path(), "DEAD"), 0);
    assert_eq!(
        outbox_status_count(db_path.as_path(), "QUEUED")
            + outbox_status_count(db_path.as_path(), "SENDING"),
        0
    );

    assert_eq!(calls.load(Ordering::SeqCst), queued_due + failed_due);
    assert_eq!(
        transmitted_status_count(db_path.as_path(), "SENT"),
        expected_sent_total
    );
    assert_eq!(
        transmitted_status_count(db_path.as_path(), "FAILED"),
        failed_future as i64
    );

    runtime.shutdown().await.expect("shutdown runtime");
}

#[tokio::test]
async fn telemetry_replay_large_corpus_retry_deadletter_matrix() {
    let temp = TempDir::new().expect("temp dir");
    let db_path = temp.path().join("events.db");
    ensure_outbox_schema(db_path.as_path());

    let now = Utc::now().timestamp();
    let conn = Connection::open(&db_path).expect("open db for seeding");
    let total = 240usize;
    let mut expected_sent = 0usize;
    let mut expected_dead = 0usize;

    for idx in 0..total {
        let (org, base_batch, base_event) = match idx % 3 {
            0 => {
                expected_sent += 1;
                ("ok", 0x5555u128, 0xeeeeu128)
            }
            1 => {
                expected_dead += 1;
                ("retry", 0x6666u128, 0xffffu128)
            }
            _ => {
                expected_dead += 1;
                ("bad", 0x7777u128, 0x9999u128)
            }
        };

        let batch = sample_batch(
            Uuid::from_u128((base_batch << 112) + idx as u128),
            Uuid::from_u128((base_event << 112) + idx as u128),
            format!("{org}-{idx}"),
        );
        seed_outbox_row(&conn, &batch, "QUEUED", 0, now - 30, Some(now - 1));
        seed_transmitted_row(&conn, &batch, "QUEUED", now);
    }
    drop(conn);

    let calls = Arc::new(AtomicUsize::new(0));
    let Some(endpoint) = start_telemetry_server(RoutedTelemetryServerState {
        calls: calls.clone(),
    })
    .await
    else {
        eprintln!(
            "Skipping telemetry_replay_large_corpus_retry_deadletter_matrix: cannot bind localhost listener"
        );
        return;
    };

    let runtime = TelemetrySyncRuntime::start(TelemetryRuntimeConfig {
        endpoint,
        api_key: "test-key".to_string(),
        device_id_hash: "device-hash-test".to_string(),
        telemetry_signing_key_hex: None,
        db: Arc::new(Mutex::new(
            Connection::open(&db_path).expect("open runtime db"),
        )),
        telemetry: TelemetrySyncConfig {
            enabled: true,
            endpoint_path: "/v1/edge/telemetry/batch".to_string(),
            max_retry_attempts: 1,
            backoff_base_ms: 10,
            backoff_max_ms: 10,
            dead_letter_after_hours: 72,
        },
        local_secret: vec![],
    })
    .expect("start telemetry runtime");

    wait_for_outbox_status(
        db_path.as_path(),
        "SENT",
        expected_sent as i64,
        Duration::from_secs(8),
    )
    .await;
    wait_for_outbox_status(
        db_path.as_path(),
        "DEAD",
        expected_dead as i64,
        Duration::from_secs(8),
    )
    .await;

    assert_eq!(
        outbox_status_count(db_path.as_path(), "QUEUED")
            + outbox_status_count(db_path.as_path(), "FAILED")
            + outbox_status_count(db_path.as_path(), "SENDING"),
        0
    );
    assert_eq!(outbox_dead_non_unit_attempts(db_path.as_path()), 0);

    assert_eq!(calls.load(Ordering::SeqCst), total);
    assert_eq!(
        transmitted_status_count(db_path.as_path(), "SENT"),
        expected_sent as i64
    );
    assert_eq!(
        transmitted_status_count(db_path.as_path(), "DEAD"),
        expected_dead as i64
    );

    runtime.shutdown().await.expect("shutdown runtime");
}
