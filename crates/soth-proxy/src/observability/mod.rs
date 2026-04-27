//! Observability stack for the SOTH edge proxy.
//!
//! Phase 1 wires `tracing` → `tracing-opentelemetry` → Honeycomb (OTLP/HTTP)
//! plus a `sentry` panic + ERROR-level capture path. Both are gated on
//! environment variables so the proxy runs cleanly without them (tests,
//! offline dev, distros that haven't been configured yet).
//!
//! See `docs/common/observability.md` for the full design and the
//! redaction policy this module enforces.
//!
//! ## Module layout
//!
//! - [`redaction`] — pure deny-list helpers used by every export path.
//! - [`sentry`] — Sentry SDK init + the `before_send` hook that scrubs
//!   events using [`redaction`].
//! - (`honeycomb` and the toplevel [`init`] entry point land in the next
//!   commit on this branch — kept separate so the redaction policy can be
//!   reviewed in isolation.)

pub mod redaction;
pub mod sentry;
