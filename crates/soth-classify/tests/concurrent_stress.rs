//! Concurrent stress test for the classify pipeline.
//!
//! Validates the `Send + Sync` story for SDK bindings: a single
//! `Arc<ClassifyBundle>` shared across many host threads must produce
//! deterministic, identical `ClassifiedResult`s for the same input, with no
//! deadlock or data race.
//!
//! This test runs against the fallback bundle (no ONNX), so it exercises
//! the lock-free deterministic-hash path. The Mutex<Session> path is
//! exercised by `integration_pipeline.rs` when ONNX models are present;
//! the safety property here applies equally to both.

use std::sync::Arc;
use std::thread;

mod common;
use common::{make_detect_result, make_proxy_ctx};

const THREADS: usize = 16;
const CALLS_PER_THREAD: usize = 1_000;

#[test]
fn classify_pipeline_is_send_sync_and_deterministic_under_concurrency() {
    let bundle: Arc<soth_classify::ClassifyBundle> = soth_classify::fallback_bundle();
    let config = Arc::new(soth_classify::ClassifyConfig::default());
    let detect = Arc::new(make_detect_result());
    let proxy_ctx = Arc::new(make_proxy_ctx(None));

    let baseline = soth_classify::classify(
        detect.as_ref(),
        Some("hello world from a deterministic test"),
        proxy_ctx.as_ref(),
        bundle.as_ref(),
        config.as_ref(),
    );

    let mut handles = Vec::with_capacity(THREADS);
    for tid in 0..THREADS {
        let bundle = Arc::clone(&bundle);
        let config = Arc::clone(&config);
        let detect = Arc::clone(&detect);
        let proxy_ctx = Arc::clone(&proxy_ctx);
        let expected_hash = baseline.semantic_hash.clone();
        handles.push(thread::spawn(move || {
            for i in 0..CALLS_PER_THREAD {
                let out = soth_classify::classify(
                    detect.as_ref(),
                    Some("hello world from a deterministic test"),
                    proxy_ctx.as_ref(),
                    bundle.as_ref(),
                    config.as_ref(),
                );
                assert_eq!(
                    out.semantic_hash, expected_hash,
                    "thread {tid} call {i}: semantic_hash drifted"
                );
            }
        }));
    }

    for handle in handles {
        handle.join().expect("worker thread panicked");
    }
}
