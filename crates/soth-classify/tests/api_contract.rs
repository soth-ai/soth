use soth_classify::{ClassifiedResult, ClassifyBundle, ClassifyConfig, ProxyContext};
use soth_core::DetectResult;

type ClassifyFn = fn(
    &DetectResult,
    Option<&str>,
    &ProxyContext,
    &ClassifyBundle,
    &ClassifyConfig,
) -> ClassifiedResult;

#[test]
fn classify_entrypoint_signature_is_stable() {
    let _: ClassifyFn = soth_classify::classify;
}

#[test]
fn required_model_assets_contract_is_stable() {
    assert_eq!(
        soth_classify::CLASSIFY_REQUIRED_MODEL_ASSETS,
        [
            "classify/embedding.onnx",
            "classify/centroids.bin",
            "classify/lsh_projection.bin",
            "classify/use_case_mlp.bin",
        ]
    );
}

#[test]
fn fallback_model_asset_status_is_explicit() {
    let bundle = soth_classify::fallback_bundle();
    let status = bundle.model_asset_status();
    assert!(!status.has_embedding_onnx);
    assert!(!status.has_use_case_mlp);
}

#[test]
fn classify_bundle_trait_contract_is_send_sync_clone() {
    fn assert_bundle_traits<T: Send + Sync + Clone>() {}
    assert_bundle_traits::<ClassifyBundle>();
}
