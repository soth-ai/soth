//! `soth-sdk-core` — public-API facade consumed by SOTH SDK bindings.
//!
//! Bindings (PyO3 / napi-rs / WASM) depend ONLY on this crate. The internal
//! `soth-detect` / `soth-classify` / `soth-telemetry` crates are not
//! re-exported, so swapping their internals does not ripple to bindings.
//!
//! Public-API contracts:
//! - [`docs/common/SDK_DECISION_API_SPEC.md`](../../../docs/common/SDK_DECISION_API_SPEC.md)
//! - [`docs/common/SDK_WASM_TRUST_BOUNDARY_SPEC.md`](../../../docs/common/SDK_WASM_TRUST_BOUNDARY_SPEC.md)
//!
//! Once a public type in this crate is committed, every change is breaking
//! for downstream bindings and customers. The conformance harness in
//! `soth-conformance-tests` is the keystone — every binding must pass it
//! before shipping.

#![forbid(unsafe_code)]

pub mod call;
pub mod config;
pub mod decision;
pub mod error;

mod sdk;
mod slab;
mod telemetry_queue;

pub use call::{LlmCall, LlmChunk, LlmResponse, Message, Tool};
pub use config::{
    BundleSource, ClassificationMode, HmacKey, SdkConfig, SdkConfigBuilder, StorageMode,
};
pub use decision::{
    BlockReason, BudgetKind, Decision, DecisionToken, FlagSeverity, MessageRedaction,
    MessageRedactions, RedactReason,
};
pub use error::SdkError;
pub use sdk::{Observation, SothSdk, StreamObservation};

// Re-exports of soth-core types that appear in the public API. Bindings
// see these as `soth_sdk_core::ArtifactKind` etc. and don't need to depend
// on `soth-core` directly.
pub use soth_core::{
    AnomalyFlag, ArtifactKind, ArtifactSeverity, CaptureMode, EndpointType, PolicyDecisionKind,
    UseCaseLabel, VolatilityClass,
};
