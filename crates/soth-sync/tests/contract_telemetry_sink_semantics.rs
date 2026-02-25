use std::collections::HashSet;
use std::sync::Arc;

use chrono::Utc;
use rusqlite::{params, Connection};
use tempfile::TempDir;
use tokio::sync::mpsc;
use uuid::Uuid;

use soth_core::{
    CaptureMode, DetectedProvider, EndpointType, ParseConfidence, ParseSource, RequestMethod,
    SensitiveCodeFlags, TelemetryEvent, TelemetryPolicyKind, UseCaseLabel, VolatilityClass,
};
use soth_sync::telemetry::{SyncTelemetrySink, TelemetryOutbox};
use soth_telemetry::{SignedBatch, TelemetryBatch, TelemetrySink, TransmittedBatch};

fn sample_event(event_id: Uuid) -> TelemetryEvent {
    TelemetryEvent {
        event_id,
        timestamp_epoch_ms: 1_700_000_001_000,
        connection_id: None,
        provider: DetectedProvider::OpenAi,
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
        sensitive_code_flags: SensitiveCodeFlags::default(),
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
    next_attempt_at: i64,
) {
    let payload = serde_json::to_string(batch).expect("serialize transmitted batch");
    let now = Utc::now().timestamp();
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
            now,
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

    insert_outbox_row(&conn, &queued_due, "QUEUED", now.saturating_sub(1));
    insert_outbox_row(&conn, &failed_due, "FAILED", now.saturating_sub(1));
    insert_outbox_row(&conn, &failed_future, "FAILED", now.saturating_add(3_600));

    let replayed = outbox
        .drain_on_startup()
        .expect("drain on startup should succeed");
    assert_eq!(replayed, 2);

    let mut seen = HashSet::new();
    while let Ok(id) = rx.try_recv() {
        seen.insert(id);
    }

    assert!(seen.contains(queued_due.batch_id().to_string().as_str()));
    assert!(seen.contains(failed_due.batch_id().to_string().as_str()));
    assert!(!seen.contains(failed_future.batch_id().to_string().as_str()));
}
