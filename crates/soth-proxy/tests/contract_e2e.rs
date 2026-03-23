#![allow(clippy::field_reassign_with_default)]
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use uuid::Uuid;

use soth_core::{
    AppType, CaptureMode, ClassificationSource, ConnectionMeta, ParseConfidence,
    PolicyDecisionKind, ProcessMatchKind, ProcessResolution, ProxyContext, RawRequest,
    SessionSnapshot, SocketFamily, SurfaceType, TrafficClassification,
};
use soth_telemetry::{EncryptionMode, SinkError, TelemetrySink, TransmittedBatch};

#[derive(Clone, Default)]
struct CaptureSink {
    batches: Arc<Mutex<Vec<TransmittedBatch>>>,
}

#[async_trait]
impl TelemetrySink for CaptureSink {
    async fn send(&self, batch: TransmittedBatch) -> Result<(), SinkError> {
        self.batches
            .lock()
            .expect("capture sink mutex poisoned")
            .push(batch);
        Ok(())
    }
}

fn sample_connection_meta(
    capture_mode: Option<CaptureMode>,
    matched_provider: Option<&str>,
) -> ConnectionMeta {
    let mut meta = ConnectionMeta::from_transport(
        Uuid::new_v4(),
        SocketFamily::TcpV4 {
            local: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 10_000),
            remote: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443),
        },
        None,
        None,
    );
    meta.capture_mode = capture_mode;
    meta.matched_provider = matched_provider.map(str::to_string);
    meta
}

fn sample_request(
    capture_mode: Option<CaptureMode>,
    matched_provider: Option<&str>,
    body: &'static [u8],
) -> RawRequest {
    let mut headers = BTreeMap::new();
    headers.insert("host".to_string(), "api.openai.com".to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());

    RawRequest {
        method: "POST".to_string(),
        path: "/v1/chat/completions".to_string(),
        headers,
        body: Bytes::from_static(body),
        connection_meta: sample_connection_meta(capture_mode, matched_provider),
    }
}

fn sample_proxy_context(capture_mode: CaptureMode, timestamp_epoch_ms: i64) -> ProxyContext {
    ProxyContext {
        org_id: "org-test".to_string(),
        user_id_hmac: "user-hmac".to_string(),
        team_id: "team-test".to_string(),
        device_id_hash: "device-hash".to_string(),
        endpoint_hash: "endpoint-hash".to_string(),
        process_resolution: ProcessResolution {
            match_kind: ProcessMatchKind::Unknown,
            app_type: AppType::Unknown,
            capture_mode: Some(capture_mode),
            process_name: Some("test-proc".to_string()),
            bundle_id: None,
            matched_app_id: None,
            ..Default::default()
        },
        capture_mode,
        matched_provider: Some("openai".to_string()),
        matched_application: None,
        traffic_classification: TrafficClassification::ToolUsage,
        classification_source: ClassificationSource::Proxy,
        session_snapshot: Some(SessionSnapshot {
            current_request_timestamp: timestamp_epoch_ms,
            ..SessionSnapshot::default()
        }),
        request_method: None,
        deployment_context: None,
        precomputed_commitment_nonce: None,
        precomputed_commitment_hash: None,
        connection_id: None,
        bundle_trust_level: None,
        session_id: None,
        product_id: None,
        surface_type: SurfaceType::Unknown,
        is_shadow_it: false,
    }
}

fn run_detect(capture_mode: CaptureMode) -> soth_core::DetectResult {
    let bundle = soth_core::OwnedDetectBundle::default();
    let registry = soth_detect::build_registry(&bundle.as_slice()).expect("build registry");
    let request = sample_request(
        Some(capture_mode),
        Some("openai"),
        br#"{
            "model":"gpt-4o-mini",
            "messages":[{"role":"user","content":"explain rust ownership quickly"}],
            "stream":false
        }"#,
    );
    soth_detect::process_with_registry(
        &registry,
        &request,
        &bundle.as_slice(),
        &soth_core::SessionSnapshot::default(),
    )
}

#[test]
fn detect_contract_input_output() {
    let out = run_detect(CaptureMode::MetadataOnly);

    assert_eq!(out.capture_mode, CaptureMode::MetadataOnly);
    assert!(matches!(
        out.confidence,
        ParseConfidence::Full | ParseConfidence::Partial | ParseConfidence::Heuristic
    ));
    assert!(!out.normalized.user_content_hash.is_empty());
    assert!(!out.normalized.canonical_cache_key.is_empty());
}

#[test]
fn classify_contract_input_output() {
    let detect_result = run_detect(CaptureMode::SensitiveArtifacts);
    let proxy_ctx = sample_proxy_context(CaptureMode::SensitiveArtifacts, 1_700_000_000_111);

    let bundle = soth_classify::fallback_bundle();
    let config = soth_classify::ClassifyConfig::default();
    let out = soth_classify::classify(
        &detect_result,
        Some("explain rust ownership quickly"),
        &proxy_ctx,
        bundle.as_ref(),
        &config,
    );

    assert!(out.use_case_confidence >= 0.0 && out.use_case_confidence <= 1.0);
    assert!(out.embedding_norm >= 0.0);
    assert!(out.stage_latencies.total_us >= out.stage_latencies.stage7_us);
    assert_eq!(
        out.telemetry_event.timestamp_epoch_ms,
        proxy_ctx
            .session_snapshot
            .as_ref()
            .expect("session snapshot")
            .current_request_timestamp
    );
    assert_eq!(
        out.telemetry_event.capture_mode,
        CaptureMode::SensitiveArtifacts
    );
    assert!(matches!(
        out.policy_decision.kind,
        PolicyDecisionKind::Allow
            | PolicyDecisionKind::Block { .. }
            | PolicyDecisionKind::Redact { .. }
            | PolicyDecisionKind::Reroute { .. }
            | PolicyDecisionKind::Flag { .. }
    ));
}

#[tokio::test]
async fn telemetry_contract_input_output() {
    let detect_result = run_detect(CaptureMode::MetadataOnly);
    let proxy_ctx = sample_proxy_context(CaptureMode::MetadataOnly, 1_700_000_000_222);
    let classify_bundle = soth_classify::fallback_bundle();
    let classify = soth_classify::classify(
        &detect_result,
        Some("explain rust ownership quickly"),
        &proxy_ctx,
        classify_bundle.as_ref(),
        &soth_classify::ClassifyConfig::default(),
    );

    let sink = CaptureSink::default();
    let db_path = std::env::temp_dir().join(format!("soth-contract-{}.db", Uuid::new_v4()));
    let telemetry = soth_telemetry::TelemetryPipeline::new(
        soth_telemetry::TelemetryConfig {
            batch_window: Duration::from_secs(30),
            max_batch_size: 500,
            anomaly_threshold: 0.8,
            signing_key: SigningKey::from_bytes(&[9u8; 32]),
            encryption: EncryptionMode::None,
            proxy_version: "proxy-test".to_string(),
            bundle_version: "bundle-test".to_string(),
            org_id: "org-test".to_string(),
            observation_queue_dir: None,
            governance_queue_dir: None,
        },
        Arc::new(soth_telemetry::SqlitePool::new(db_path.clone())),
        Arc::new(sink.clone()),
    );

    telemetry.push(classify.telemetry_event.clone());
    telemetry.flush().await.expect("flush telemetry");
    telemetry.shutdown().await.expect("shutdown telemetry");

    let batches = sink.batches.lock().expect("capture sink lock");
    assert_eq!(batches.len(), 1);
    match &batches[0] {
        TransmittedBatch::Signed(batch) => {
            assert_eq!(batch.batch.event_count, 1);
            assert_eq!(
                batch.batch.events[0].event_id,
                classify.telemetry_event.event_id
            );
            assert_eq!(batch.batch.org_id, "org-test");
        }
        TransmittedBatch::Encrypted(_) => {
            panic!("expected signed batch for EncryptionMode::None")
        }
    }

    let _ = std::fs::remove_file(db_path);
}
