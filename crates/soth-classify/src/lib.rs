#![forbid(unsafe_code)]

mod bundle;
mod config;
mod fallback;
mod model;
mod onnx_embed;
mod pipeline;
mod stage1_embed;
mod stage2_cluster;
mod stage3_usecase;
mod stage4_volatility;
mod stage5_anomaly;
mod stage6_policy;
mod stage7_telemetry;
mod traits;
mod types;

pub const INTERFACE_VERSION: &str = "1.0.0";
pub const API_CONTRACT_VERSION: &str = "2026-02-26";

pub use bundle::{
    BundleLoadError, ClassifyBundle, ModelAssetStatus, CLASSIFY_REQUIRED_MODEL_ASSETS,
};
pub use config::{ClassifyConfig, ComplexityWeights, VolatilityConfig};
pub use traits::{AnomalyScorer, ClassificationProvider};
pub use types::{ClassifiedResult, StageTiming};

pub use soth_core::{
    AnomalyFlag, CaptureMode, ClassificationSource, ProxyContext, TelemetryEvent, UseCaseLabel,
    VolatilityClass,
};

pub fn classify(
    detect_result: &soth_core::DetectResult,
    content_for_embedding: Option<&str>,
    proxy_ctx: &ProxyContext,
    bundle: &ClassifyBundle,
    config: &ClassifyConfig,
) -> ClassifiedResult {
    pipeline::run(
        detect_result,
        content_for_embedding,
        proxy_ctx,
        bundle,
        config,
    )
}

pub fn load_bundle(
    bundle_dir: &std::path::Path,
) -> Result<std::sync::Arc<ClassifyBundle>, BundleLoadError> {
    ClassifyBundle::load(bundle_dir)
}

pub fn load_bundle_from_bytes(
    manifest: &[u8],
    assets: std::collections::HashMap<String, Vec<u8>>,
) -> Result<std::sync::Arc<ClassifyBundle>, BundleLoadError> {
    ClassifyBundle::load_from_bytes(manifest, assets)
}

pub fn fallback_bundle() -> std::sync::Arc<ClassifyBundle> {
    ClassifyBundle::fallback()
}
