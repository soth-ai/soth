//! Background telemetry shipper.
//!
//! Drains the in-memory `TelemetryQueue` on a fixed cadence and POSTs
//! batches to the configured cloud endpoint via reqwest blocking. The
//! shipper is gated behind the `http-telemetry` feature so default
//! builds stay light; bindings flip it on for production.
//!
//! V0 deliberately ships a minimal shipper: bounded batches, fixed
//! window, no retry/circuit-breaker. Phase 2 ports the full retry
//! semantics from `soth-sync` (5 attempts with exp backoff, 72-hour
//! dead-letter, circuit breaker after 5 consecutive failures).

#![cfg(feature = "http-telemetry")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::telemetry_queue::TelemetryQueue;

const BATCH_WINDOW: Duration = Duration::from_secs(5);
const MAX_BATCH_SIZE: usize = 100;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct TelemetryShipper {
    handle: Option<JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
}

impl TelemetryShipper {
    pub fn spawn(
        queue: Arc<TelemetryQueue>,
        endpoint: String,
        api_key: String,
        org_id: String,
    ) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);

        let handle = std::thread::Builder::new()
            .name("soth-telemetry-shipper".into())
            .spawn(move || run_loop(queue, endpoint, api_key, org_id, shutdown_clone))
            .expect("spawn telemetry shipper thread");

        Self {
            handle: Some(handle),
            shutdown,
        }
    }

    pub fn shutdown(&mut self) {
        if !self.shutdown.swap(true, Ordering::Release) {
            if let Some(handle) = self.handle.take() {
                // Best-effort join; ignore poisoned panics.
                let _ = handle.join();
            }
        }
    }
}

impl Drop for TelemetryShipper {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn run_loop(
    queue: Arc<TelemetryQueue>,
    endpoint: String,
    api_key: String,
    org_id: String,
    shutdown: Arc<AtomicBool>,
) {
    let client = match reqwest::blocking::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent(format!("soth-sdk-core/{}", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "telemetry shipper failed to build HTTP client; events will accumulate");
            return;
        }
    };

    while !shutdown.load(Ordering::Acquire) {
        // Polling loop with shutdown-aware wait. We wake every 100ms
        // to check the shutdown flag so process exit doesn't stall on
        // the full BATCH_WINDOW. Phase 2 will use a condvar.
        let deadline = std::time::Instant::now() + BATCH_WINDOW;
        while std::time::Instant::now() < deadline {
            if shutdown.load(Ordering::Acquire) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        let batch = queue.drain_batch(MAX_BATCH_SIZE);
        if batch.is_empty() {
            continue;
        }

        // Wire envelope is intentionally minimal; cloud-side ingestion
        // accepts the same shape soth-sync uses for the proxy.
        let body = serde_json::json!({
            "org_id": &org_id,
            "events": batch,
        });

        match client
            .post(&endpoint)
            .bearer_auth(&api_key)
            .json(&body)
            .send()
        {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!(
                    target: "soth_sdk_core::shipper",
                    status = resp.status().as_u16(),
                    "telemetry batch posted"
                );
            }
            Ok(resp) => {
                tracing::warn!(
                    target: "soth_sdk_core::shipper",
                    status = resp.status().as_u16(),
                    "telemetry POST returned non-success; events dropped (Phase-2 retry not yet wired)"
                );
            }
            Err(error) => {
                tracing::warn!(
                    target: "soth_sdk_core::shipper",
                    error = %error,
                    "telemetry POST error; events dropped"
                );
            }
        }
    }

    // Final drain on shutdown so events buffered during the last
    // BATCH_WINDOW aren't lost on graceful exit.
    let final_batch = queue.drain_batch(MAX_BATCH_SIZE);
    if !final_batch.is_empty() {
        let body = serde_json::json!({
            "org_id": &org_id,
            "events": final_batch,
        });
        let _ = client
            .post(&endpoint)
            .bearer_auth(&api_key)
            .json(&body)
            .send();
    }
}
