//! Concurrent stress test for the detect pipeline.
//!
//! Validates the `Send + Sync` story for SDK bindings: a single
//! `Arc<ParserRegistry>` and a shared `OwnedDetectBundle` must produce
//! deterministic `DetectResult`s for the same input across many host
//! threads, with no deadlock or data race.
//!
//! Specifically guards `process_normalized` — the SDK's pre-parsed entry
//! point — since that's where future SDK bindings will route every
//! in-process call.

use std::sync::Arc;
use std::thread;

use soth_core::{
    CaptureMode, EndpointType, OwnedDetectBundle, SessionSnapshot, TypedLlmCall, TypedMessage,
};
use soth_detect::{process_normalized, ParserRegistry};

const THREADS: usize = 16;
const CALLS_PER_THREAD: usize = 1_000;

fn sample_call() -> TypedLlmCall {
    TypedLlmCall {
        provider: "openai".into(),
        model: "gpt-4o-mini".into(),
        messages: vec![TypedMessage {
            role: "user".into(),
            content: "deterministic concurrent input".into(),
        }],
        system: None,
        tools: Vec::new(),
        stream: false,
        temperature: None,
        top_p: None,
        max_tokens: None,
        stop_sequences: Vec::new(),
        endpoint_type: EndpointType::ChatCompletion,
    }
}

#[test]
fn process_normalized_is_send_sync_and_deterministic_under_concurrency() {
    let registry: Arc<ParserRegistry> = Arc::new(ParserRegistry::default());
    let bundle: Arc<OwnedDetectBundle> = Arc::new(OwnedDetectBundle::default());

    let baseline = process_normalized(
        registry.as_ref(),
        &sample_call(),
        &bundle.as_slice(),
        &SessionSnapshot::default(),
        CaptureMode::MetadataOnly,
    );

    let mut handles = Vec::with_capacity(THREADS);
    for tid in 0..THREADS {
        let registry = Arc::clone(&registry);
        let bundle = Arc::clone(&bundle);
        let expected_cache_key = baseline.normalized.canonical_cache_key.clone();
        let expected_user_hash = baseline.normalized.user_content_hash.clone();
        handles.push(thread::spawn(move || {
            for i in 0..CALLS_PER_THREAD {
                let out = process_normalized(
                    registry.as_ref(),
                    &sample_call(),
                    &bundle.as_slice(),
                    &SessionSnapshot::default(),
                    CaptureMode::MetadataOnly,
                );
                assert_eq!(
                    out.normalized.canonical_cache_key, expected_cache_key,
                    "thread {tid} call {i}: canonical_cache_key drifted"
                );
                assert_eq!(
                    out.normalized.user_content_hash, expected_user_hash,
                    "thread {tid} call {i}: user_content_hash drifted"
                );
                assert_eq!(out.parse_source, soth_core::ParseSource::Sdk);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("worker thread panicked");
    }
}
