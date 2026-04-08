use std::collections::HashSet;
use std::sync::Arc;

use chrono::Utc;
use rusqlite::{params, Connection};
use tempfile::TempDir;
use tokio::sync::mpsc;
use uuid::Uuid;

use soth_core::{
    CaptureMode, DetectedProvider, EndpointType, ParseConfidence, ParseSource, RequestMethod,
    SensitiveCodeFlags, SurfaceType, TelemetryEvent, TelemetryPolicyKind, UseCaseLabel,
    VolatilityClass,
};
use soth_sync::telemetry::{SyncTelemetrySink, TelemetryOutbox};
use soth_telemetry::{SignedBatch, TelemetryBatch, TelemetrySink, TransmittedBatch};

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
        estimated_input_tokens: Some(5),
        estimated_output_tokens: Some(8),
        estimated_cost_usd: Some(0.0001),
        process_resolution: None,
        traffic_classification: None,
        languages: Vec::new(),
        import_categories: Vec::new(),
        classification_flags: Vec::new(),
        anomaly_flags: Vec::new(),
        anomaly_score: Some(0.05),
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
        ja4_hash: None,
        tls_version: None,
        alpn_protocol: None,
        h2_connection_id: None,
        h2_stream_id: None,
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

fn transmitted_status(db_path: &std::path::Path, batch_id: Uuid) -> Option<String> {
    let conn = Connection::open(db_path).ok()?;
    conn.query_row(
        "SELECT transmission_status
         FROM transmitted_events
         WHERE batch_id = ?1
         LIMIT 1",
        [batch_id.to_string()],
        |row| row.get(0),
    )
    .ok()
}

fn outbox_status(db_path: &std::path::Path, batch_id: Uuid) -> Option<String> {
    let conn = Connection::open(db_path).ok()?;
    conn.query_row(
        "SELECT status
         FROM telemetry_outbox
         WHERE batch_id = ?1
         LIMIT 1",
        [batch_id.to_string()],
        |row| row.get(0),
    )
    .ok()
}

fn seed_transmitted_queued_row(db_path: &std::path::Path, batch: &TransmittedBatch) {
    let TransmittedBatch::Signed(signed) = batch else {
        panic!("test expects signed batches");
    };
    let conn = Connection::open(db_path).expect("open sqlite");
    let now = Utc::now().timestamp();
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
        .expect("insert transmitted row");
    }
}

fn insert_outbox_row(
    conn: &Connection,
    batch: &TransmittedBatch,
    status: &str,
    first_queued_at: i64,
    next_attempt_at: i64,
) {
    let payload = serde_json::to_string(batch).expect("serialize transmitted batch");
    conn.execute(
        "INSERT INTO telemetry_outbox
         (batch_id, org_id, payload_json, payload_hash, encrypted, status, attempts, first_queued_at, next_attempt_at, last_error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, NULL)",
        params![
            batch.batch_id().to_string(),
            batch.org_id(),
            payload,
            batch.payload_hash(),
            if batch.is_encrypted() { 1i64 } else { 0i64 },
            status,
            first_queued_at,
            next_attempt_at
        ],
    )
    .expect("insert outbox row");
}

#[tokio::test]
async fn telemetry_sink_send_returns_after_durable_queue_write() {
    let temp = TempDir::new().expect("temp dir");
    let db_path = temp.path().join("events.db");
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let outbox = Arc::new(TelemetryOutbox::new(&db_path, tx).expect("create outbox"));
    let sink = SyncTelemetrySink::new(outbox);

    let batch_id = Uuid::from_u128(0x11111111111111111111111111111111);
    let event_id = Uuid::from_u128(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa);
    let batch = sample_batch(batch_id, event_id);
    seed_transmitted_queued_row(&db_path, &batch);

    TelemetrySink::send(&sink, batch)
        .await
        .expect("sink send should queue");

    assert_eq!(outbox_status(&db_path, batch_id).as_deref(), Some("QUEUED"));
    assert_eq!(
        transmitted_status(&db_path, batch_id).as_deref(),
        Some("QUEUED")
    );

    let queued_batch_id = rx.try_recv().expect("worker signal should be enqueued");
    assert_eq!(queued_batch_id, batch_id.to_string());
}

#[tokio::test]
async fn telemetry_outbox_drain_on_startup_requeues_due_rows_only() {
    let temp = TempDir::new().expect("temp dir");
    let db_path = temp.path().join("events.db");
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let outbox = TelemetryOutbox::new(&db_path, tx).expect("create outbox");
    let conn = Connection::open(&db_path).expect("open sqlite");
    let now = Utc::now().timestamp();

    let queued_due = sample_batch(
        Uuid::from_u128(0x22222222222222222222222222222222),
        Uuid::from_u128(0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb),
    );
    let failed_due = sample_batch(
        Uuid::from_u128(0x33333333333333333333333333333333),
        Uuid::from_u128(0xcccccccccccccccccccccccccccccccc),
    );
    let failed_future = sample_batch(
        Uuid::from_u128(0x44444444444444444444444444444444),
        Uuid::from_u128(0xdddddddddddddddddddddddddddddddd),
    );
    let sending_stale = sample_batch(
        Uuid::from_u128(0x55555555555555555555555555555555),
        Uuid::from_u128(0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee),
    );
    let sending_fresh = sample_batch(
        Uuid::from_u128(0x66666666666666666666666666666666),
        Uuid::from_u128(0xffffffffffffffffffffffffffffffff),
    );

    insert_outbox_row(
        &conn,
        &queued_due,
        "QUEUED",
        now.saturating_sub(60),
        now.saturating_sub(1),
    );
    insert_outbox_row(
        &conn,
        &failed_due,
        "FAILED",
        now.saturating_sub(120),
        now.saturating_sub(1),
    );
    insert_outbox_row(
        &conn,
        &failed_future,
        "FAILED",
        now.saturating_sub(120),
        now.saturating_add(3_600),
    );
    insert_outbox_row(
        &conn,
        &sending_stale,
        "SENDING",
        now.saturating_sub(600),
        now.saturating_sub(1),
    );
    insert_outbox_row(
        &conn,
        &sending_fresh,
        "SENDING",
        now.saturating_sub(10),
        now.saturating_sub(1),
    );

    let replayed = outbox
        .drain_on_startup()
        .expect("drain on startup should succeed");
    assert_eq!(replayed, 3);

    let mut seen = HashSet::new();
    while let Ok(id) = rx.try_recv() {
        seen.insert(id);
    }

    assert!(seen.contains(queued_due.batch_id().to_string().as_str()));
    assert!(seen.contains(failed_due.batch_id().to_string().as_str()));
    assert!(seen.contains(sending_stale.batch_id().to_string().as_str()));
    assert!(!seen.contains(failed_future.batch_id().to_string().as_str()));
    assert!(!seen.contains(sending_fresh.batch_id().to_string().as_str()));
}

#[tokio::test]
async fn telemetry_outbox_recovers_stale_sending_after_lock_failure() {
    let temp = TempDir::new().expect("temp dir");
    let db_path = temp.path().join("events.db");
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let outbox = TelemetryOutbox::new(&db_path, tx).expect("create outbox");
    let conn = Connection::open(&db_path).expect("open sqlite");
    let now = Utc::now().timestamp();

    let batch = sample_batch(
        Uuid::from_u128(0x77777777777777777777777777777777),
        Uuid::from_u128(0xabababababababababababababababab),
    );
    seed_transmitted_queued_row(&db_path, &batch);
    insert_outbox_row(
        &conn,
        &batch,
        "SENDING",
        now.saturating_sub(600),
        now.saturating_sub(1),
    );
    drop(conn);

    let locker = Connection::open(&db_path).expect("open sqlite locker");
    locker
        .execute_batch("BEGIN EXCLUSIVE")
        .expect("acquire sqlite exclusive lock");
    let result = outbox.mark_sent(batch.batch_id());
    assert!(
        result.is_err(),
        "mark_sent should fail under an exclusive external lock"
    );
    locker
        .execute_batch("ROLLBACK")
        .expect("release sqlite exclusive lock");

    assert_eq!(
        outbox_status(&db_path, batch.batch_id()).as_deref(),
        Some("SENDING")
    );

    let replayed = outbox
        .drain_on_startup()
        .expect("drain on startup should recover stale SENDING rows");
    assert_eq!(replayed, 1);

    let recovered_batch_id = rx
        .try_recv()
        .expect("recovered stale SENDING row should be enqueued");
    assert_eq!(recovered_batch_id, batch.batch_id().to_string());
}
