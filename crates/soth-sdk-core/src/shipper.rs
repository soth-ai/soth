//! Background telemetry shipper.
//!
//! Drains the in-memory `TelemetryQueue` on a fixed cadence and POSTs
//! batches to the configured cloud endpoint via reqwest blocking. The
//! shipper is gated behind the `http-telemetry` feature so default
//! builds stay light; bindings flip it on for production.
//!
//! Wire format is the cloud-facing `soth_api_types::TelemetryBatchRequest`,
//! the same envelope the proxy ships via `soth-sync`. The SDK and the
//! proxy share a single source of truth for the cloud contract so
//! they cannot silently drift.
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

use soth_api_types::api_types::{TelemetryBatchRequest, API_VERSION, API_VERSION_HEADER};
use soth_api_types::convert::map_event;
use soth_core::TelemetryEvent as CoreTelemetryEvent;

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

        post_batch(
            &client, &endpoint, &api_key, &org_id, batch, /*final*/ false,
        );
    }

    // Final drain on shutdown so events buffered during the last
    // BATCH_WINDOW aren't lost on graceful exit.
    let final_batch = queue.drain_batch(MAX_BATCH_SIZE);
    if !final_batch.is_empty() {
        post_batch(
            &client,
            &endpoint,
            &api_key,
            &org_id,
            final_batch,
            /*final*/ true,
        );
    }
}

fn post_batch(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    api_key: &str,
    org_id: &str,
    batch: Vec<CoreTelemetryEvent>,
    is_final: bool,
) {
    let batch_size = batch.len();
    let request = build_request(org_id, batch);
    let label = if is_final { "FINAL POST" } else { "POST" };

    match client
        .post(endpoint)
        .header(API_VERSION_HEADER, API_VERSION)
        .bearer_auth(api_key)
        .json(&request)
        .send()
    {
        Ok(resp) if resp.status().is_success() => {
            tracing::debug!(
                target: "soth_sdk_core::shipper",
                status = resp.status().as_u16(),
                "telemetry batch posted"
            );
            if std::env::var("SOTH_SHIPPER_VERBOSE").is_ok() {
                eprintln!(
                    "[soth-sdk-core::shipper] {} {} -> {} ({} events)",
                    label,
                    endpoint,
                    resp.status().as_u16(),
                    batch_size
                );
            }
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body_text = resp.text().unwrap_or_default();
            tracing::warn!(
                target: "soth_sdk_core::shipper",
                status,
                "telemetry POST returned non-success; events dropped (Phase-2 retry not yet wired)"
            );
            if std::env::var("SOTH_SHIPPER_VERBOSE").is_ok() {
                eprintln!(
                    "[soth-sdk-core::shipper] {label} {endpoint} -> {status} ({batch_size} events dropped): {body_text}"
                );
            }
        }
        Err(error) => {
            tracing::warn!(
                target: "soth_sdk_core::shipper",
                error = %error,
                "telemetry POST error; events dropped"
            );
            if std::env::var("SOTH_SHIPPER_VERBOSE").is_ok() {
                eprintln!(
                    "[soth-sdk-core::shipper] {label} {endpoint} -> ERROR ({batch_size} events dropped): {error}"
                );
            }
        }
    }
}

fn build_request(org_id: &str, batch: Vec<CoreTelemetryEvent>) -> TelemetryBatchRequest {
    let timestamp = batch.first().map(|e| e.timestamp_epoch_ms).unwrap_or(0);
    let batch_id = uuid::Uuid::new_v4().to_string();
    let events = batch.iter().map(map_event).collect();

    TelemetryBatchRequest {
        batch_id,
        org_id: org_id.to_string(),
        // SDK has no signed device-id-hash flow; cloud accepts the
        // bearer token + org_id alone for SDK-class telemetry.
        device_id_hash: format!("sdk:{org_id}"),
        proxy_version: format!("soth-sdk-core/{}", env!("CARGO_PKG_VERSION")),
        timestamp,
        events,
        // Cloud requires a non-empty signature field but accepts the
        // sentinel below for SDK-class submissions; full ed25519
        // signing is a Phase-2 deliverable.
        proxy_signature: String::from("sdk-unsigned"),
        observation_records: None,
    }
}
