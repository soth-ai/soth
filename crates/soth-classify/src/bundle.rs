use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Arc;

use thiserror::Error;

use crate::fallback::{KeywordClassifier, StaticAnomalyScorer};
use crate::traits::{AnomalyScorer, ClassificationProvider};

pub struct ClassifyBundle {
    pub(crate) classifier: Arc<dyn ClassificationProvider>,
    pub(crate) anomaly_scorer: Arc<dyn AnomalyScorer>,
    pub(crate) policy_bundle: Arc<soth_policy::PolicyBundle>,
    pub bundle_version: String,
    pub has_real_models: bool,
}

impl ClassifyBundle {
    pub fn load(_bundle_dir: &Path) -> Result<Arc<Self>, BundleLoadError> {
        Err(BundleLoadError::Unsupported(
            "bundle file loading is not implemented yet".to_string(),
        ))
    }

    pub fn load_from_bytes(
        _manifest_bytes: &[u8],
        _assets: HashMap<String, Vec<u8>>,
    ) -> Result<Arc<Self>, BundleLoadError> {
        Err(BundleLoadError::Unsupported(
            "bundle byte loading is not implemented yet".to_string(),
        ))
    }

    pub fn fallback() -> Arc<Self> {
        Self::fallback_with_policy_bundle(
            Arc::new(fallback_policy_bundle()),
            "fallback-0.0.0".to_string(),
        )
    }

    pub fn fallback_with_policy_bundle(
        policy_bundle: Arc<soth_policy::PolicyBundle>,
        bundle_version: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            classifier: Arc::new(KeywordClassifier),
            anomaly_scorer: Arc::new(StaticAnomalyScorer),
            policy_bundle,
            bundle_version,
            has_real_models: false,
        })
    }
}

fn fallback_policy_bundle() -> soth_policy::PolicyBundle {
    use soth_policy::{
        sync_policy::{BudgetLimits, CompiledRuleSet, OrgPatterns, PolicyBundleMetadata},
        PolicyBundle,
    };

    PolicyBundle {
        metadata: PolicyBundleMetadata {
            bundle_version: "fallback-0.0.0".to_string(),
            schema_version: "1".to_string(),
            org_id: "unknown".to_string(),
            signed_at: 0,
        },
        system_rules: Arc::new(CompiledRuleSet::default()),
        org_rules: Arc::new(CompiledRuleSet::default()),
        org_patterns: Arc::new(OrgPatterns::default()),
        budget_limits: BudgetLimits::default(),
    }
}

#[derive(Debug, Error)]
pub enum BundleLoadError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid vendor signature")]
    InvalidSignature,
    #[error("asset hash mismatch: {asset}")]
    AssetHashMismatch { asset: String },
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
    #[error("onnx session error: {0}")]
    OnnxSession(String),
    #[error("invalid centroid shape: expected (K, 384), got ({rows}, {cols})")]
    InvalidCentroidShape { rows: usize, cols: usize },
    #[error("policy bundle error: {0}")]
    PolicyBundle(#[from] soth_policy::PolicyError),
    #[error("unsupported: {0}")]
    Unsupported(String),
}
