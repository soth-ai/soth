//! Observability stack for the SOTH edge proxy.
//!
//! Phase 1 wires `tracing` → `tracing-opentelemetry` → Honeycomb (OTLP/HTTP)
//! plus a `sentry` panic + ERROR-level capture path. Both are gated on
//! environment variables so the proxy runs cleanly without them (tests,
//! offline dev, distros that haven't been configured yet).
//!
//! See `docs/common/observability.md` for the full design and the redaction
//! policy this module enforces.

pub mod honeycomb;
pub mod redaction;
pub mod sentry;

use opentelemetry::global;
use opentelemetry_sdk::trace::TracerProvider as SdkTracerProvider;
use tracing::Level;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

/// Hold-for-process-lifetime guard returned by [`init`].
///
/// Drops in reverse order: OTel tracer provider first (graceful flush of
/// any in-flight batches), then the Sentry init guard (also flushes).
/// Callers that don't care about graceful shutdown can `Box::leak` it.
#[must_use = "drop the ObservabilityGuard at end of process to flush in-flight telemetry"]
pub struct ObservabilityGuard {
    tracer_provider: Option<SdkTracerProvider>,
    _sentry: Option<::sentry::ClientInitGuard>,
}

impl Drop for ObservabilityGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.tracer_provider.take() {
            // shutdown() is best-effort — under tokio it currently posts the
            // batch to the runtime then returns immediately. Logging a final
            // warn is fine; we never let an export hiccup propagate.
            if let Err(error) = provider.shutdown() {
                eprintln!("opentelemetry tracer provider shutdown error: {error}");
            }
            // Reset the global so a subsequent re-init in the same process
            // (e.g. integration test) doesn't reference a dropped provider.
            global::shutdown_tracer_provider();
        }
        // _sentry drops itself.
    }
}

/// Initialise the SOTH edge-proxy observability subscriber.
///
/// Layers, in order of execution against each event:
///
/// 1. `EnvFilter` — same `RUST_LOG`/default-spec contract as before.
/// 2. `tracing_subscriber::fmt` — preserves existing stdout/log-file output.
/// 3. `tracing_opentelemetry::layer` — exports spans/events to Honeycomb
///    (only attached when `HONEYCOMB_API_KEY` is configured).
/// 4. `sentry::integrations::tracing::layer` — captures ERROR-level events
///    + panics (only attached when `SENTRY_DSN` is configured).
///
/// `extension_targets` is forwarded to [`build_env_filter`] so soth's
/// extension crates inherit the proxy's default verbosity.
///
/// Hard kill switch: setting `SOTH_OBSERVABILITY_ENABLED=false` (any case)
/// suppresses BOTH the Honeycomb exporter and Sentry init regardless of
/// the underlying credentials being present. The fmt layer always installs.
pub fn init(extension_targets: &[&str]) -> ObservabilityGuard {
    let observability_enabled = std::env::var("SOTH_OBSERVABILITY_ENABLED")
        .map(|value| !value.trim().eq_ignore_ascii_case("false"))
        .unwrap_or(true);

    let filter = build_env_filter(extension_targets);
    let fmt_layer = tracing_subscriber::fmt::layer();

    // Optional honeycomb / OTel layer.
    let (tracer_provider, otel_layer) = if observability_enabled {
        match honeycomb::init() {
            Some((provider, tracer)) => {
                let layer = tracing_opentelemetry::layer().with_tracer(tracer).boxed();
                (Some(provider), Some(layer))
            }
            None => (None, None),
        }
    } else {
        (None, None)
    };

    // Optional sentry init + tracing layer. We attach the layer only when
    // Sentry is initialised so its overhead is zero on test/offline runs.
    let sentry_guard = if observability_enabled {
        sentry::init()
    } else {
        None
    };
    let sentry_layer = sentry_guard.as_ref().map(|_| {
        ::sentry::integrations::tracing::layer()
            // Map tracing levels to sentry kinds:
            // ERROR → captured as Sentry events (with stack)
            // WARN  → recorded as breadcrumbs
            // INFO and below → ignored entirely
            .event_filter(|md| match *md.level() {
                Level::ERROR => ::sentry::integrations::tracing::EventFilter::Event,
                Level::WARN => ::sentry::integrations::tracing::EventFilter::Breadcrumb,
                _ => ::sentry::integrations::tracing::EventFilter::Ignore,
            })
            .boxed()
    });

    let result = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .with(sentry_layer)
        .try_init();

    if let Err(error) = result {
        // try_init fails if a subscriber is already installed (typical in
        // test contexts). That's fine — the existing subscriber stays put
        // and the OTel/Sentry guards we built drop unused.
        eprintln!("observability subscriber install failed (already initialised?): {error}");
    }

    ObservabilityGuard {
        tracer_provider,
        _sentry: sentry_guard,
    }
}

/// Build the same default `RUST_LOG` filter the proxy used before
/// observability was layered in. Extension crates passed in by name get
/// added at `info` level.
fn build_env_filter(extension_targets: &[&str]) -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let mut base = String::from(
            "warn,\
             soth_proxy=info,\
             soth_detect=info,\
             soth_bundle=info,\
             soth_sync=info,\
             soth_classify=info,\
             soth_telemetry=info,\
             soth_core=info,\
             soth_mitm=info,\
             soth_extensions=info,\
             mitm_sidecar=info,\
             soth_mitm::proxy::internal=off,\
             hyper_util=warn,\
             hyper=warn,\
             rustls=warn,\
             reqwest=warn",
        );
        for target in extension_targets {
            base.push(',');
            base.push_str(target);
            base.push_str("=info");
        }
        EnvFilter::new(base)
    })
}
