//! Honeycomb (OTLP/HTTP) exporter setup.
//!
//! Builds an `opentelemetry_sdk::trace::TracerProvider` that batches spans
//! and ships them to `https://api.honeycomb.io/v1/traces` over OTLP/HTTP
//! protobuf. The tracer is installed as the global OTel tracer provider so
//! `tracing-opentelemetry::layer().with_tracer(...)` (assembled in
//! [`super::init`]) can pull from it.
//!
//! Disabled silently when `HONEYCOMB_API_KEY` is unset — the proxy must run
//! cleanly without observability configured. Errors during exporter
//! construction are logged once at WARN and otherwise swallowed; we never
//! fail proxy startup over telemetry.

use std::collections::HashMap;
use std::time::Duration;

use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::{
    runtime,
    trace::{Sampler, TracerProvider as SdkTracerProvider},
    Resource,
};
use opentelemetry_semantic_conventions::resource as semconv;
use tracing::warn;

const DEFAULT_ENDPOINT: &str = "https://api.honeycomb.io/v1/traces";
const DEFAULT_DATASET: &str = "soth-edge-proxy";
const DEFAULT_SERVICE_NAME: &str = "soth-edge-proxy";

/// Build and install the Honeycomb-backed OTel tracer provider.
///
/// Returns:
/// - `Some((provider, tracer))` when the env is configured. The caller
///   keeps the provider for graceful shutdown (`provider.shutdown()` on
///   drop) and uses the tracer to construct a `tracing-opentelemetry`
///   layer.
/// - `None` when `HONEYCOMB_API_KEY` is unset/empty — observability is
///   opt-in so the proxy stays usable in tests, offline dev, and on hosts
///   that haven't been configured yet.
pub fn init() -> Option<(SdkTracerProvider, opentelemetry_sdk::trace::Tracer)> {
    let api_key = std::env::var("HONEYCOMB_API_KEY").ok()?;
    if api_key.trim().is_empty() {
        return None;
    }

    let dataset =
        std::env::var("HONEYCOMB_DATASET").unwrap_or_else(|_| DEFAULT_DATASET.to_string());
    let endpoint =
        std::env::var("HONEYCOMB_OTLP_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string());
    let service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| DEFAULT_SERVICE_NAME.to_string());
    let sample_rate = std::env::var("SOTH_OTEL_SAMPLE_RATE")
        .ok()
        .and_then(|raw| raw.parse::<f64>().ok())
        .map(|raw| raw.clamp(0.0, 1.0))
        .unwrap_or(1.0);
    let environment = std::env::var("SOTH_ENVIRONMENT")
        .or_else(|_| std::env::var("ENVIRONMENT"))
        .unwrap_or_else(|_| "unknown".to_string());

    // OTLP/HTTP wants the API key in `x-honeycomb-team` and the dataset in
    // `x-honeycomb-dataset` (since traces share the OTLP path with logs).
    let mut headers = HashMap::new();
    headers.insert("x-honeycomb-team".to_string(), api_key);
    headers.insert("x-honeycomb-dataset".to_string(), dataset);

    let exporter_result = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint)
        .with_protocol(Protocol::HttpBinary)
        .with_headers(headers)
        .with_timeout(Duration::from_secs(10))
        .build();

    let exporter = match exporter_result {
        Ok(exporter) => exporter,
        Err(error) => {
            warn!(
                error = %error,
                "honeycomb OTLP exporter could not be constructed; tracing telemetry disabled"
            );
            return None;
        }
    };

    // Use a stable constant for service.name / service.version (both are
    // stable in semconv 1.27). `deployment.environment.name` is currently
    // gated behind the `semconv_experimental` feature, so we just emit
    // the canonical attribute name as a string to avoid pulling in the
    // experimental flag.
    let resource = Resource::new(vec![
        KeyValue::new(semconv::SERVICE_NAME, service_name.clone()),
        KeyValue::new(
            semconv::SERVICE_VERSION,
            env!("CARGO_PKG_VERSION").to_string(),
        ),
        KeyValue::new("deployment.environment.name", environment),
    ]);

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter, runtime::Tokio)
        .with_resource(resource)
        .with_sampler(Sampler::TraceIdRatioBased(sample_rate))
        .build();

    // Install as the global tracer provider so any OTel-aware crate that
    // calls `global::tracer(...)` ends up here too.
    global::set_tracer_provider(provider.clone());

    let tracer = opentelemetry::trace::TracerProvider::tracer(&provider, service_name);

    Some((provider, tracer))
}
