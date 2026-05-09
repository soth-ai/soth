use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use rusqlite::{params, Connection};
use tempfile::TempDir;
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

use soth_core::DetectedProvider;
use soth_core::{
    CaptureMode, EndpointType, ParseConfidence, ParseSource, RequestMethod, SensitiveCodeFlags,
    SurfaceType, TelemetryEvent, TelemetryPolicyKind, UseCaseLabel, VolatilityClass,
};
use soth_sync::telemetry::{TelemetryOutbox, TelemetryReplayWorker, TelemetrySender};
use soth_sync::TelemetrySyncConfig;
use soth_telemetry::{SignedBatch, TelemetryBatch, TransmittedBatch};

#[derive(Clone)]
struct TelemetryServerState {
    status: StatusCode,
    calls: Arc<AtomicUsize>,
}

async fn telemetry_batch_handler(
    State(state): State<TelemetryServerState>,
    _payload: Bytes,
) -> StatusCode {
    state.calls.fetch_add(1, Ordering::SeqCst);
    state.status
}

async fn start_telemetry_server(state: TelemetryServerState) -> Option<String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.ok()?;
    let addr = listener.local_addr().ok()?;
    let app = Router::new()
        .route("/v1/edge/telemetry/batch", post(telemetry_batch_handler))
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
        use_case_label_override: None,
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
        use_case_label_reason: soth_core::UseCaseLabelReason::UninitializedDefault,
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
        event_layer: None,
        raw_payload: None,
        raw_capture_mode: None,
        ja4_hash: None,
        tls_version: None,
        alpn_protocol: None,
        h2_connection_id: None,
        h2_stream_id: None,
        interaction_mode: soth_core::InteractionMode::Unknown,
    }
}

fn sample_batch(batch_id: Uuid, event_id: Uuid) -> TransmittedBatch {
    TransmittedBatch::Signed(SignedBatch {
        batch: TelemetryBatch {
            batch_id,
            org_id: "org-test".to_string(),
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

fn seed_transmitted_rows(db_path: &Path, batch: &TransmittedBatch) {
    let TransmittedBatch::Signed(signed) = batch else {
        panic!("this test expects signed batches only");
    };
    let conn = Connection::open(db_path).expect("open sqlite for seed");
    let now = chrono::Utc::now().timestamp();
    for event in &signed.batch.events {
        conn.execute(
            "INSERT INTO transmitted_events
             (event_id, transmitted_at, batch_id, payload_hash, transmission_status, encrypted)
             VALUES (?1, ?2, ?3, ?4, 'QUEUED', 0)",
            params![
                event.event_id.to_string(),
                now,
                signed.batch.batch_id.to_string(),
                batch.payload_hash()
            ],
        )
        .expect("seed transmitted row");
    }
}

fn outbox_status(db_path: &Path, batch_id: Uuid) -> Option<String> {
    let conn = Connection::open(db_path).ok()?;
    conn.query_row(
        "SELECT status FROM telemetry_outbox WHERE batch_id = ?1",
        [batch_id.to_string()],
        |row| row.get(0),
    )
    .ok()
}

fn transmitted_status(db_path: &Path, batch_id: Uuid) -> Option<String> {
    let conn = Connection::open(db_path).ok()?;
    conn.query_row(
        "SELECT transmission_status FROM transmitted_events WHERE batch_id = ?1 LIMIT 1",
        [batch_id.to_string()],
        |row| row.get(0),
    )
    .ok()
}

async fn wait_for_status<F>(mut read_status: F, expected: &str)
where
    F: FnMut() -> Option<String>,
{
    for _ in 0..120 {
        if read_status().as_deref() == Some(expected) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for status {expected}");
}

#[tokio::test]
async fn telemetry_replay_contract_transitions_to_sent() {
    let temp = TempDir::new().expect("temp dir");
    let db_path = temp.path().join("events.db");

    let calls = Arc::new(AtomicUsize::new(0));
    let Some(endpoint) = start_telemetry_server(TelemetryServerState {
        status: StatusCode::OK,
        calls: calls.clone(),
    })
    .await
    else {
        eprintln!(
            "Skipping telemetry_replay_contract_transitions_to_sent: cannot bind localhost listener"
        );
        return;
    };

    let (tx, rx) = mpsc::unbounded_channel::<String>();
    let outbox = Arc::new(TelemetryOutbox::new(&db_path, tx.clone()).expect("create outbox"));
    let batch_id = Uuid::from_u128(0x11111111111111111111111111111111);
    let event_id = Uuid::from_u128(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa);
    let batch = sample_batch(batch_id, event_id);
    seed_transmitted_rows(&db_path, &batch);
    outbox.enqueue(batch).expect("enqueue batch");

    let sender = TelemetrySender::new(
        endpoint,
        "test-key",
        "/v1/edge/telemetry/batch",
        "device-hash-test",
        None,
        &[],
    )
    .expect("sender");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let worker = TelemetryReplayWorker::new(
        outbox,
        sender,
        TelemetrySyncConfig::default(),
        rx,
        tx,
        shutdown_rx,
    );
    let join = tokio::spawn(worker.run());

    wait_for_status(|| outbox_status(&db_path, batch_id), "SENT").await;
    wait_for_status(|| transmitted_status(&db_path, batch_id), "SENT").await;
    assert!(calls.load(Ordering::SeqCst) >= 1);

    let _ = shutdown_tx.send(true);
    let _ = join.await;
}

#[tokio::test]
async fn telemetry_replay_contract_transitions_to_dead_after_retry_cap() {
    let temp = TempDir::new().expect("temp dir");
    let db_path = temp.path().join("events.db");

    let calls = Arc::new(AtomicUsize::new(0));
    let Some(endpoint) = start_telemetry_server(TelemetryServerState {
        status: StatusCode::SERVICE_UNAVAILABLE,
        calls: calls.clone(),
    })
    .await
    else {
        eprintln!(
            "Skipping telemetry_replay_contract_transitions_to_dead_after_retry_cap: cannot bind localhost listener"
        );
        return;
    };

    let (tx, rx) = mpsc::unbounded_channel::<String>();
    let outbox = Arc::new(TelemetryOutbox::new(&db_path, tx.clone()).expect("create outbox"));
    let batch_id = Uuid::from_u128(0x22222222222222222222222222222222);
    let event_id = Uuid::from_u128(0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb);
    let batch = sample_batch(batch_id, event_id);
    seed_transmitted_rows(&db_path, &batch);
    outbox.enqueue(batch).expect("enqueue batch");

    let sender = TelemetrySender::new(
        endpoint,
        "test-key",
        "/v1/edge/telemetry/batch",
        "device-hash-test",
        None,
        &[],
    )
    .expect("sender");
    let cfg = TelemetrySyncConfig {
        enabled: true,
        endpoint_path: "/v1/edge/telemetry/batch".to_string(),
        max_retry_attempts: 1,
        backoff_base_ms: 10,
        backoff_max_ms: 10,
        dead_letter_after_hours: 72,
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let worker = TelemetryReplayWorker::new(outbox, sender, cfg, rx, tx, shutdown_rx);
    let join = tokio::spawn(worker.run());

    wait_for_status(|| outbox_status(&db_path, batch_id), "DEAD").await;
    wait_for_status(|| transmitted_status(&db_path, batch_id), "DEAD").await;
    assert!(calls.load(Ordering::SeqCst) >= 1);

    let _ = shutdown_tx.send(true);
    let _ = join.await;
}
