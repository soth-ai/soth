use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rusqlite::Connection;
use sha2::Digest;
use soth_core::{
    AnomalyFlag, AppType, CaptureMode, ClassificationFlag, DetectedProvider, EndpointType,
    ParseConfidence, ParseSource, ProcessMatchKind, ProcessResolution, RequestMethod,
    SensitiveCodeFlags, TelemetryEvent, TelemetryPolicyKind, TrafficClassification, UseCaseLabel,
    VolatilityClass,
};
use soth_telemetry::{
    EncryptedBatch, EncryptionMode, SignedBatch, SqlitePool, TelemetryConfig, TelemetryPipeline,
    TelemetrySink, TransmittedBatch,
};
use tokio::sync::Mutex;
use uuid::Uuid;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

#[derive(Clone, Default)]
struct CollectSink {
    batches: Arc<Mutex<Vec<TransmittedBatch>>>,
}

impl CollectSink {
    async fn batches(&self) -> Vec<TransmittedBatch> {
        self.batches.lock().await.clone()
    }
}

#[async_trait]
impl TelemetrySink for CollectSink {
    async fn send(&self, batch: TransmittedBatch) -> Result<(), soth_telemetry::SinkError> {
        self.batches.lock().await.push(batch);
        Ok(())
    }
}

fn make_db_path(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{prefix}-{}.db", Uuid::new_v4()))
}

fn make_pool(prefix: &str) -> Arc<SqlitePool> {
    Arc::new(SqlitePool::new(make_db_path(prefix)))
}

fn config(encryption: EncryptionMode, max_batch_size: usize) -> TelemetryConfig {
    TelemetryConfig {
        batch_window: Duration::from_secs(300),
        max_batch_size,
        anomaly_threshold: 0.8,
        signing_key: ed25519_dalek::SigningKey::from_bytes(&[61u8; 32]),
        encryption,
        proxy_version: "proxy-v1".to_string(),
        bundle_version: "bundle-v1".to_string(),
        org_id: "org-test".to_string(),
    }
}

fn corpus_event(index: usize, threshold_mode: bool) -> TelemetryEvent {
    let providers = [
        DetectedProvider::OpenAi,
        DetectedProvider::Anthropic,
        DetectedProvider::Gemini,
        DetectedProvider::Cohere,
        DetectedProvider::Bedrock,
        DetectedProvider::Mistral,
        DetectedProvider::Groq,
        DetectedProvider::VertexAi,
    ];
    let endpoints = [
        EndpointType::ChatCompletion,
        EndpointType::TextCompletion,
        EndpointType::Embedding,
        EndpointType::FunctionCall,
        EndpointType::Streaming,
    ];
    let provider = providers[index % providers.len()];
    let endpoint = endpoints[index % endpoints.len()];
    let parse_source = match index % 4 {
        0 => ParseSource::Rest { provider },
        1 => ParseSource::JsonRpc,
        2 => ParseSource::Grpc,
        _ => ParseSource::GraphQl,
    };

    let mut classification_flags = Vec::new();
    let mut anomaly_score = Some(((index % 6) as f32) * 0.1);
    let mut policy_kind = Some(TelemetryPolicyKind::Allow);
    if threshold_mode && index % 37 == 0 {
        anomaly_score = Some(0.92);
        classification_flags.push(ClassificationFlag::HighAnomaly);
    }
    if threshold_mode && index % 53 == 0 {
        policy_kind = Some(TelemetryPolicyKind::Block);
        classification_flags.push(ClassificationFlag::PolicyTriggered);
    }

    TelemetryEvent {
        event_id: Uuid::from_u128(0x1000_0000_0000_0000_0000_0000_0000_0000u128 + index as u128),
        timestamp_epoch_ms: 1_700_000_000_000 + index as i64,
        connection_id: Some(Uuid::from_u128(
            0x2000_0000_0000_0000_0000_0000_0000_0000u128 + index as u128,
        )),
        provider,
        model: Some(format!("model-{}", index % 11)),
        endpoint_type: endpoint,
        parse_confidence: if index % 5 == 0 {
            ParseConfidence::Partial
        } else {
            ParseConfidence::Full
        },
        parse_source,
        capture_mode: if index % 9 == 0 {
            CaptureMode::SensitiveArtifacts
        } else {
            CaptureMode::MetadataOnly
        },
        use_case: if index % 2 == 0 {
            UseCaseLabel::CodeGeneration
        } else {
            UseCaseLabel::QuestionAnswering
        },
        volatility_class: if index % 3 == 0 {
            VolatilityClass::Dynamic
        } else {
            VolatilityClass::LowVolatile
        },
        cache_level: None,
        routing_reason: None,
        request_method: RequestMethod::Post,
        estimated_input_tokens: Some(150 + (index % 50) as u32),
        estimated_output_tokens: Some(75 + (index % 20) as u32),
        estimated_cost_usd: Some(0.001 + (index as f32 / 10_000.0)),
        process_resolution: Some(ProcessResolution {
            match_kind: if index % 4 == 0 {
                ProcessMatchKind::Exact
            } else {
                ProcessMatchKind::Pattern
            },
            app_type: if index % 5 == 0 {
                AppType::Host
            } else {
                AppType::NonHost
            },
            capture_mode: Some(CaptureMode::MetadataOnly),
            process_name: Some(format!("proc-{index}")),
            bundle_id: Some(format!("com.example.app{}", index % 17)),
        }),
        traffic_classification: Some(if index % 2 == 0 {
            TrafficClassification::ToolUsage
        } else {
            TrafficClassification::ApplicationUsage
        }),
        languages: Vec::new(),
        import_categories: Vec::new(),
        classification_flags,
        anomaly_flags: if index % 11 == 0 {
            vec![AnomalyFlag::TokenBurst]
        } else {
            vec![AnomalyFlag::TopicDrift]
        },
        anomaly_score,
        policy_kind,
        sensitive_code_flags: SensitiveCodeFlags::default(),
    }
}

fn signing_message(batch: &soth_telemetry::TelemetryBatch) -> Vec<u8> {
    let mut out = batch.batch_id.as_bytes().to_vec();
    let mut ids = batch
        .events
        .iter()
        .map(|event| event.event_id)
        .collect::<Vec<_>>();
    ids.sort_unstable();
    for id in ids {
        out.extend_from_slice(id.as_bytes());
    }
    out
}

fn canonical_signed_hash(signed: &SignedBatch) -> String {
    #[derive(serde::Serialize)]
    struct CanonicalSignedBatch {
        batch: soth_telemetry::TelemetryBatch,
        proxy_signature: Vec<u8>,
        proxy_pubkey: [u8; 32],
    }

    let encoded = rmp_serde::to_vec(&CanonicalSignedBatch {
        batch: signed.batch.clone(),
        proxy_signature: signed.proxy_signature.to_vec(),
        proxy_pubkey: signed.proxy_pubkey,
    })
    .expect("serialize canonical signed batch");
    let mut hasher = sha2::Sha256::new();
    hasher.update(encoded);
    hex::encode(hasher.finalize())
}

fn verify_signed_batch(signed: &SignedBatch) {
    let verify_key = VerifyingKey::from_bytes(&signed.proxy_pubkey).expect("valid pubkey");
    let signature = Signature::from_bytes(&signed.proxy_signature);
    verify_key
        .verify(signing_message(&signed.batch).as_slice(), &signature)
        .expect("batch signature should verify");
    assert_eq!(
        signed.canonical_hash,
        canonical_signed_hash(signed),
        "canonical hash should match deterministic msgpack payload"
    );
    assert_eq!(
        signed.batch.event_count as usize,
        signed.batch.events.len(),
        "event_count must match event vector length"
    );
}

fn decrypt_signed_batch(encrypted: &EncryptedBatch, vendor_secret: &[u8; 32]) -> SignedBatch {
    let shared_secret = x25519(*vendor_secret, encrypted.ephemeral_pubkey);
    let hkdf = Hkdf::<sha2::Sha256>::new(None, &shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(b"soth-telemetry-v1", &mut key)
        .expect("expand hkdf key");
    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("init cipher");
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&encrypted.nonce),
            encrypted.ciphertext.as_slice(),
        )
        .expect("decrypt batch");
    rmp_serde::from_slice::<SignedBatch>(plaintext.as_slice()).expect("decode signed batch")
}

fn db_count(path: &Path, sql: &str) -> i64 {
    let conn = Connection::open(path).expect("open telemetry sqlite");
    conn.query_row(sql, [], |row| row.get(0))
        .expect("count query succeeds")
}

#[tokio::test]
async fn telemetry_signed_mode_e2e_contract() {
    let db = make_pool("soth-telemetry-signed");
    let sink = CollectSink::default();
    let pipeline = TelemetryPipeline::new(
        config(EncryptionMode::None, 64),
        db.clone(),
        Arc::new(sink.clone()),
    );

    let total_events = 257usize;
    for idx in 0..total_events {
        pipeline.push(corpus_event(idx, false));
    }

    pipeline.flush().await.expect("flush");
    pipeline.shutdown().await.expect("shutdown");

    let batches = sink.batches().await;
    assert_eq!(batches.len(), 5, "64+64+64+64+1 expected in signed mode");

    let mut seen = HashSet::new();
    for batch in &batches {
        match batch {
            TransmittedBatch::Signed(signed) => {
                verify_signed_batch(signed);
                for event in &signed.batch.events {
                    seen.insert(event.event_id);
                }
            }
            other => panic!("expected signed batch, got {:?}", other),
        }
    }
    assert_eq!(seen.len(), total_events);

    let total_rows = db_count(db.path(), "SELECT COUNT(*) FROM transmitted_events");
    let queued_rows = db_count(
        db.path(),
        "SELECT COUNT(*) FROM transmitted_events WHERE transmission_status = 'QUEUED'",
    );
    let encrypted_rows = db_count(
        db.path(),
        "SELECT COUNT(*) FROM transmitted_events WHERE encrypted = 1",
    );
    assert_eq!(total_rows, total_events as i64);
    assert_eq!(queued_rows, total_events as i64);
    assert_eq!(encrypted_rows, 0);
}

#[tokio::test]
async fn telemetry_large_realworld_corpus_encrypted_e2e() {
    let db = make_pool("soth-telemetry-encrypted");
    let sink = CollectSink::default();
    let vendor_secret = [77u8; 32];
    let vendor_pubkey = x25519(vendor_secret, X25519_BASEPOINT_BYTES);

    let pipeline = TelemetryPipeline::new(
        config(EncryptionMode::Ecies { vendor_pubkey }, 80),
        db.clone(),
        Arc::new(sink.clone()),
    );

    let total_events = 720usize;
    for idx in 0..total_events {
        pipeline.push(corpus_event(idx, true));
    }

    pipeline.flush().await.expect("flush");
    pipeline.shutdown().await.expect("shutdown");

    let batches = sink.batches().await;
    assert!(
        batches.len() >= 10,
        "expected at least 10 encrypted batches for large corpus, got {}",
        batches.len()
    );

    let mut seen = HashSet::new();
    for batch in &batches {
        match batch {
            TransmittedBatch::Encrypted(encrypted) => {
                let signed = decrypt_signed_batch(encrypted, &vendor_secret);
                verify_signed_batch(&signed);
                assert_eq!(encrypted.batch_id, signed.batch.batch_id);
                assert_eq!(encrypted.org_id, signed.batch.org_id);
                for event in &signed.batch.events {
                    seen.insert(event.event_id);
                }
            }
            other => panic!("expected encrypted batch, got {:?}", other),
        }
    }
    assert_eq!(seen.len(), total_events);

    let total_rows = db_count(db.path(), "SELECT COUNT(*) FROM transmitted_events");
    let queued_rows = db_count(
        db.path(),
        "SELECT COUNT(*) FROM transmitted_events WHERE transmission_status = 'QUEUED'",
    );
    let encrypted_rows = db_count(
        db.path(),
        "SELECT COUNT(*) FROM transmitted_events WHERE encrypted = 1",
    );
    assert_eq!(total_rows, total_events as i64);
    assert_eq!(queued_rows, total_events as i64);
    assert_eq!(encrypted_rows, total_events as i64);
}
