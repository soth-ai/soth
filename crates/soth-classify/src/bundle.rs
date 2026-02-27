use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Arc;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::fallback::{KeywordClassifier, StaticAnomalyScorer};
use crate::model::build_model_providers;
use crate::onnx_embed::OnnxEmbeddingRuntime;
use crate::traits::{AnomalyScorer, ClassificationProvider};

const MANIFEST_CANDIDATES: [&str; 2] = ["manifest.json", "classify/manifest.json"];
const POLICY_BUNDLE_CANDIDATES: [&str; 3] = [
    "policy/policy_bundle.json",
    "policy/bundle.json",
    "policy_bundle.json",
];
pub const CLASSIFY_REQUIRED_MODEL_ASSETS: [&str; 4] = [
    "classify/embedding.onnx",
    "classify/centroids.bin",
    "classify/lsh_projection.bin",
    "classify/use_case_mlp.bin",
];
const CLASSIFY_OPTIONAL_MODEL_ASSETS: [&str; 2] =
    ["classify/tokenizer.json", "classify/volatility_config.toml"];

pub(crate) const EMBEDDING_DIM: usize = 384;
pub(crate) const LSH_PROJECTION_ROWS: usize = 128;

pub struct ClassifyBundle {
    pub(crate) classifier: Arc<dyn ClassificationProvider>,
    pub(crate) anomaly_scorer: Arc<dyn AnomalyScorer>,
    pub(crate) policy_bundle: Arc<soth_policy::PolicyBundle>,
    pub(crate) embedding_onnx: Option<Arc<Vec<u8>>>,
    pub(crate) tokenizer_json: Option<Arc<Vec<u8>>>,
    pub(crate) use_case_mlp: Option<Arc<Vec<u8>>>,
    pub(crate) centroids: Arc<Vec<Vec<f32>>>,
    pub(crate) lsh_projection: Arc<Vec<Vec<f32>>>,
    pub(crate) volatility_config_toml: Option<Arc<Vec<u8>>>,
    pub(crate) onnx_runtime: Option<Arc<OnnxEmbeddingRuntime>>,
    pub bundle_version: String,
    pub has_real_models: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelAssetStatus {
    pub has_embedding_onnx: bool,
    pub has_tokenizer_json: bool,
    pub has_use_case_mlp: bool,
    pub has_volatility_config_toml: bool,
    pub has_onnx_runtime: bool,
}

impl ClassifyBundle {
    pub fn load(bundle_dir: &Path) -> Result<Arc<Self>, BundleLoadError> {
        let manifest_path = find_manifest_path(bundle_dir)?;
        let manifest_bytes = std::fs::read(manifest_path.as_path())?;
        let manifest = parse_manifest(manifest_bytes.as_slice())?;

        let mut assets = HashMap::new();
        if manifest.assets.is_empty() {
            collect_known_assets(bundle_dir, &mut assets)?;
        } else {
            let manifest_dir = manifest_path.parent().unwrap_or(bundle_dir);
            for entry in &manifest.assets {
                let bytes = read_asset_bytes(bundle_dir, manifest_dir, entry.path.as_str())?;
                assets.insert(entry.path.clone(), bytes);
            }
        }

        Self::load_verified(manifest, assets)
    }

    pub fn load_from_bytes(
        manifest_bytes: &[u8],
        assets: HashMap<String, Vec<u8>>,
    ) -> Result<Arc<Self>, BundleLoadError> {
        let manifest = parse_manifest(manifest_bytes)?;
        Self::load_verified(manifest, assets)
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
            embedding_onnx: None,
            tokenizer_json: None,
            use_case_mlp: None,
            centroids: Arc::new(Vec::new()),
            lsh_projection: Arc::new(Vec::new()),
            volatility_config_toml: None,
            onnx_runtime: None,
            bundle_version,
            has_real_models: false,
        })
    }

    pub fn model_asset_status(&self) -> ModelAssetStatus {
        ModelAssetStatus {
            has_embedding_onnx: self.embedding_onnx.is_some(),
            has_tokenizer_json: self.tokenizer_json.is_some(),
            has_use_case_mlp: self.use_case_mlp.is_some(),
            has_volatility_config_toml: self.volatility_config_toml.is_some(),
            has_onnx_runtime: self.onnx_runtime.is_some(),
        }
    }

    fn load_verified(
        manifest: BundleManifest,
        assets: HashMap<String, Vec<u8>>,
    ) -> Result<Arc<Self>, BundleLoadError> {
        verify_assets(&manifest, &assets)?;
        let policy_bundle = load_policy_bundle(&assets)?;
        let embedding_onnx = load_embedding_onnx(&assets)?;
        let centroids = load_centroids(&assets)?;
        let lsh_projection = load_lsh_projection(&assets)?;
        let use_case_mlp = load_use_case_mlp(&assets)?;
        let tokenizer_json = load_optional_asset(&assets, "classify/tokenizer.json");
        let volatility_config_toml =
            load_optional_asset(&assets, "classify/volatility_config.toml");
        let onnx_runtime = build_onnx_runtime(embedding_onnx.as_deref(), tokenizer_json.as_deref());
        let has_real_models = CLASSIFY_REQUIRED_MODEL_ASSETS
            .iter()
            .all(|path| asset_bytes_for_path(&assets, path).is_some());
        let version = if manifest.version.trim().is_empty() {
            "unknown".to_string()
        } else {
            manifest.version
        };
        let (classifier, anomaly_scorer): (
            Arc<dyn ClassificationProvider>,
            Arc<dyn AnomalyScorer>,
        ) = if has_real_models {
            build_model_providers(version.clone(), &assets)
        } else {
            (Arc::new(KeywordClassifier), Arc::new(StaticAnomalyScorer))
        };

        Ok(Arc::new(Self {
            classifier,
            anomaly_scorer,
            policy_bundle,
            embedding_onnx,
            tokenizer_json,
            use_case_mlp,
            centroids: Arc::new(centroids),
            lsh_projection: Arc::new(lsh_projection),
            volatility_config_toml,
            onnx_runtime,
            bundle_version: version,
            has_real_models,
        }))
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

#[derive(Debug, Clone, Deserialize)]
struct BundleManifest {
    #[serde(default, alias = "bundle_version")]
    version: String,
    #[serde(default)]
    assets: Vec<ManifestAsset>,
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestAsset {
    path: String,
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    size_bytes: u64,
}

fn parse_manifest(bytes: &[u8]) -> Result<BundleManifest, BundleLoadError> {
    serde_json::from_slice(bytes)
        .map_err(|error| BundleLoadError::InvalidManifest(error.to_string()))
}

fn find_manifest_path(bundle_dir: &Path) -> Result<std::path::PathBuf, BundleLoadError> {
    for candidate in MANIFEST_CANDIDATES {
        let path = bundle_dir.join(candidate);
        if path.exists() {
            return Ok(path);
        }
    }
    Err(BundleLoadError::InvalidManifest(format!(
        "no manifest found under {} (expected one of: {})",
        bundle_dir.display(),
        MANIFEST_CANDIDATES.join(", ")
    )))
}

fn read_asset_bytes(
    bundle_dir: &Path,
    manifest_dir: &Path,
    relative_path: &str,
) -> Result<Vec<u8>, BundleLoadError> {
    let direct = bundle_dir.join(relative_path);
    if direct.exists() {
        return std::fs::read(direct).map_err(BundleLoadError::from);
    }

    let from_manifest_dir = manifest_dir.join(relative_path);
    if from_manifest_dir.exists() {
        return std::fs::read(from_manifest_dir).map_err(BundleLoadError::from);
    }

    Err(BundleLoadError::InvalidManifest(format!(
        "asset missing on disk: {relative_path}"
    )))
}

fn collect_known_assets(
    bundle_dir: &Path,
    out: &mut HashMap<String, Vec<u8>>,
) -> Result<(), BundleLoadError> {
    for candidate in POLICY_BUNDLE_CANDIDATES {
        let path = bundle_dir.join(candidate);
        if path.exists() {
            let bytes = std::fs::read(path)?;
            out.insert(candidate.to_string(), bytes);
            break;
        }
    }

    for asset in CLASSIFY_REQUIRED_MODEL_ASSETS
        .iter()
        .chain(CLASSIFY_OPTIONAL_MODEL_ASSETS.iter())
    {
        let path = bundle_dir.join(asset);
        if path.exists() {
            out.insert((*asset).to_string(), std::fs::read(path)?);
        } else if let Some(stripped) = asset.strip_prefix("classify/") {
            let stripped_path = bundle_dir.join(stripped);
            if stripped_path.exists() {
                out.insert(stripped.to_string(), std::fs::read(stripped_path)?);
            }
        }
    }

    Ok(())
}

fn verify_assets(
    manifest: &BundleManifest,
    assets: &HashMap<String, Vec<u8>>,
) -> Result<(), BundleLoadError> {
    for entry in &manifest.assets {
        let Some(bytes) = asset_bytes_for_path(assets, entry.path.as_str()) else {
            return Err(BundleLoadError::InvalidManifest(format!(
                "missing asset in payload: {}",
                entry.path
            )));
        };

        if entry.size_bytes > 0 && bytes.len() as u64 != entry.size_bytes {
            return Err(BundleLoadError::AssetHashMismatch {
                asset: entry.path.clone(),
            });
        }

        if !entry.sha256.is_empty() {
            let actual = sha256_hex(bytes);
            if !actual.eq_ignore_ascii_case(entry.sha256.as_str()) {
                return Err(BundleLoadError::AssetHashMismatch {
                    asset: entry.path.clone(),
                });
            }
        }
    }

    Ok(())
}

fn load_policy_bundle(
    assets: &HashMap<String, Vec<u8>>,
) -> Result<Arc<soth_policy::PolicyBundle>, BundleLoadError> {
    for candidate in POLICY_BUNDLE_CANDIDATES {
        if let Some(bytes) = asset_bytes_for_path(assets, candidate) {
            let loaded = soth_policy::load_bundle_from_bytes(bytes)?;
            return Ok(Arc::new(loaded));
        }
    }

    Ok(Arc::new(fallback_policy_bundle()))
}

fn load_optional_asset(assets: &HashMap<String, Vec<u8>>, path: &str) -> Option<Arc<Vec<u8>>> {
    asset_bytes_for_path(assets, path).map(|bytes| Arc::new(bytes.to_vec()))
}

fn build_onnx_runtime(
    embedding_onnx: Option<&Vec<u8>>,
    tokenizer_json: Option<&Vec<u8>>,
) -> Option<Arc<OnnxEmbeddingRuntime>> {
    let model = embedding_onnx?;
    let tokenizer = tokenizer_json?;
    match OnnxEmbeddingRuntime::new(model.as_slice(), tokenizer.as_slice()) {
        Ok(runtime) => Some(Arc::new(runtime)),
        Err(_) => None,
    }
}

fn load_embedding_onnx(
    assets: &HashMap<String, Vec<u8>>,
) -> Result<Option<Arc<Vec<u8>>>, BundleLoadError> {
    let Some(bytes) = asset_bytes_for_path(assets, "classify/embedding.onnx") else {
        return Ok(None);
    };
    if bytes.is_empty() {
        return Err(BundleLoadError::EmptyModelAsset {
            asset: "classify/embedding.onnx".to_string(),
        });
    }
    Ok(Some(Arc::new(bytes.to_vec())))
}

fn load_use_case_mlp(
    assets: &HashMap<String, Vec<u8>>,
) -> Result<Option<Arc<Vec<u8>>>, BundleLoadError> {
    let Some(bytes) = asset_bytes_for_path(assets, "classify/use_case_mlp.bin") else {
        return Ok(None);
    };
    if bytes.is_empty() {
        return Err(BundleLoadError::EmptyModelAsset {
            asset: "classify/use_case_mlp.bin".to_string(),
        });
    }
    Ok(Some(Arc::new(bytes.to_vec())))
}

fn load_centroids(assets: &HashMap<String, Vec<u8>>) -> Result<Vec<Vec<f32>>, BundleLoadError> {
    let Some(bytes) = asset_bytes_for_path(assets, "classify/centroids.bin") else {
        return Ok(Vec::new());
    };
    parse_f32_matrix(bytes, EMBEDDING_DIM, BundleLoadErrorKind::Centroids, true)
}

fn load_lsh_projection(
    assets: &HashMap<String, Vec<u8>>,
) -> Result<Vec<Vec<f32>>, BundleLoadError> {
    let Some(bytes) = asset_bytes_for_path(assets, "classify/lsh_projection.bin") else {
        return Ok(Vec::new());
    };
    let rows = parse_f32_matrix(
        bytes,
        EMBEDDING_DIM,
        BundleLoadErrorKind::LshProjection,
        false,
    )?;
    if rows.len() != LSH_PROJECTION_ROWS {
        return Err(BundleLoadError::InvalidLshProjectionShape {
            rows: rows.len(),
            cols: EMBEDDING_DIM,
        });
    }
    Ok(rows)
}

enum BundleLoadErrorKind {
    Centroids,
    LshProjection,
}

fn parse_f32_matrix(
    bytes: &[u8],
    cols: usize,
    kind: BundleLoadErrorKind,
    normalize_rows: bool,
) -> Result<Vec<Vec<f32>>, BundleLoadError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    let row_bytes = cols * std::mem::size_of::<f32>();
    if bytes.len() % row_bytes != 0 {
        let floats = bytes.len() / std::mem::size_of::<f32>();
        let rows = if floats == 0 { 0 } else { 1 };
        let cols = if rows == 0 { 0 } else { floats };
        return match kind {
            BundleLoadErrorKind::Centroids => {
                Err(BundleLoadError::InvalidCentroidShape { rows, cols })
            }
            BundleLoadErrorKind::LshProjection => {
                Err(BundleLoadError::InvalidLshProjectionShape { rows, cols })
            }
        };
    }

    let rows = bytes.len() / row_bytes;
    if rows == 0 {
        return match kind {
            BundleLoadErrorKind::Centroids => {
                Err(BundleLoadError::InvalidCentroidShape { rows: 0, cols })
            }
            BundleLoadErrorKind::LshProjection => {
                Err(BundleLoadError::InvalidLshProjectionShape { rows: 0, cols })
            }
        };
    }

    let mut centroids = Vec::with_capacity(rows);
    for row in 0..rows {
        let start = row * row_bytes;
        let mut centroid = Vec::with_capacity(cols);
        for col in 0..cols {
            let offset = start + col * 4;
            let value = f32::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
            centroid.push(value);
        }
        if normalize_rows {
            l2_normalize(&mut centroid);
        }
        centroids.push(centroid);
    }

    Ok(centroids)
}

fn asset_bytes_for_path<'a>(assets: &'a HashMap<String, Vec<u8>>, path: &str) -> Option<&'a [u8]> {
    if let Some(bytes) = assets.get(path) {
        return Some(bytes.as_slice());
    }
    if let Some(stripped) = path.strip_prefix("./") {
        if let Some(bytes) = assets.get(stripped) {
            return Some(bytes.as_slice());
        }
    }
    if let Some(stripped) = path.strip_prefix("classify/") {
        if let Some(bytes) = assets.get(stripped) {
            return Some(bytes.as_slice());
        }
    }
    if let Some(stripped) = path.strip_prefix("policy/") {
        if let Some(bytes) = assets.get(stripped) {
            return Some(bytes.as_slice());
        }
    }
    None
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn l2_normalize(values: &mut [f32]) {
    let norm = values.iter().map(|value| value * value).sum::<f32>().sqrt();
    if norm <= 1e-9 {
        return;
    }
    for value in values {
        *value /= norm;
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
    #[error("empty model asset: {asset}")]
    EmptyModelAsset { asset: String },
    #[error("invalid centroid shape: expected (K, 384), got ({rows}, {cols})")]
    InvalidCentroidShape { rows: usize, cols: usize },
    #[error("invalid lsh projection shape: expected (128, 384), got ({rows}, {cols})")]
    InvalidLshProjectionShape { rows: usize, cols: usize },
    #[error("policy bundle error: {0}")]
    PolicyBundle(#[from] soth_policy::PolicyError),
    #[error("unsupported: {0}")]
    Unsupported(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use soth_policy::sync_policy::{
        BudgetLimits, OrgPatterns, PolicyBundleMetadata, PolicyBundlePayload, RuleAction,
        RuleDefinition, SignedPolicyBundle,
    };

    fn signed_policy_bundle_bytes() -> Vec<u8> {
        let payload = PolicyBundlePayload {
            metadata: PolicyBundleMetadata {
                bundle_version: "policy-test-v1".to_string(),
                schema_version: "1".to_string(),
                org_id: "test-org".to_string(),
                signed_at: 1_772_300_000,
            },
            system_rules: vec![RuleDefinition {
                rule_id: "sys_test".to_string(),
                rule_name: "sys_test".to_string(),
                cel_expr: "false".to_string(),
                action: RuleAction::Flag {
                    reason: "test".to_string(),
                },
            }],
            org_rules: Vec::new(),
            org_patterns: OrgPatterns::default(),
            budget_limits: BudgetLimits::default(),
        };
        let key = SigningKey::from_bytes(&[17u8; 32]);
        let payload_bytes = serde_json::to_vec(&payload).expect("serialize payload");
        let signature = key.sign(payload_bytes.as_slice());
        let envelope = SignedPolicyBundle {
            payload,
            signature: B64.encode(signature.to_bytes()),
            public_key: B64.encode(key.verifying_key().to_bytes()),
        };
        serde_json::to_vec(&envelope).expect("serialize signed policy")
    }

    fn model_assets() -> HashMap<String, Vec<u8>> {
        HashMap::from([
            ("classify/embedding.onnx".to_string(), b"onnx".to_vec()),
            ("classify/centroids.bin".to_string(), centroid_asset_bytes()),
            (
                "classify/lsh_projection.bin".to_string(),
                lsh_projection_asset_bytes(),
            ),
            ("classify/use_case_mlp.bin".to_string(), b"mlp".to_vec()),
        ])
    }

    fn centroid_asset_bytes() -> Vec<u8> {
        let mut out = Vec::new();
        for row in 0..2usize {
            for col in 0..EMBEDDING_DIM {
                let value = if row == 0 && col == 0 {
                    1.0f32
                } else if row == 1 && col == 1 {
                    1.0f32
                } else {
                    0.0f32
                };
                out.extend_from_slice(value.to_le_bytes().as_slice());
            }
        }
        out
    }

    fn lsh_projection_asset_bytes() -> Vec<u8> {
        let mut out = Vec::new();
        for row in 0..LSH_PROJECTION_ROWS {
            for col in 0..EMBEDDING_DIM {
                let value = ((row + col) as f32 / 10_000.0) - 0.5;
                out.extend_from_slice(value.to_le_bytes().as_slice());
            }
        }
        out
    }

    fn manifest_bytes(version: &str, assets: &HashMap<String, Vec<u8>>) -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct Manifest<'a> {
            version: &'a str,
            assets: Vec<Entry<'a>>,
        }
        #[derive(serde::Serialize)]
        struct Entry<'a> {
            path: &'a str,
            sha256: String,
            size_bytes: u64,
        }

        let mut entries = assets
            .iter()
            .map(|(path, bytes)| Entry {
                path: path.as_str(),
                sha256: sha256_hex(bytes.as_slice()),
                size_bytes: bytes.len() as u64,
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.path.cmp(right.path));
        serde_json::to_vec(&Manifest {
            version,
            assets: entries,
        })
        .expect("serialize manifest")
    }

    #[test]
    fn load_from_bytes_with_manifest_and_assets() {
        let mut assets = model_assets();
        assets.insert(
            "policy/policy_bundle.json".to_string(),
            signed_policy_bundle_bytes(),
        );
        let manifest = manifest_bytes("bundle-test-v1", &assets);

        let bundle = ClassifyBundle::load_from_bytes(manifest.as_slice(), assets)
            .expect("bundle should load");

        assert_eq!(bundle.bundle_version, "bundle-test-v1");
        assert!(bundle.has_real_models);
        assert!(bundle.embedding_onnx.is_some());
        assert!(bundle.use_case_mlp.is_some());
        let model_status = bundle.model_asset_status();
        assert!(model_status.has_embedding_onnx);
        assert!(model_status.has_use_case_mlp);
        assert_eq!(bundle.centroids.len(), 2);
        assert_eq!(bundle.centroids[0].len(), 384);
        assert_eq!(bundle.lsh_projection.len(), LSH_PROJECTION_ROWS);
        assert_eq!(bundle.lsh_projection[0].len(), EMBEDDING_DIM);
        assert_eq!(bundle.classifier.bundle_version(), "bundle-test-v1");
        let embedding = vec![1.0f32 / 384.0f32.sqrt(); 384];
        let classified = bundle.classifier.classify(embedding.as_slice());
        assert!((0.0..=1.0).contains(&classified.confidence));
        assert_eq!(
            bundle.policy_bundle.metadata.bundle_version,
            "policy-test-v1"
        );
    }

    #[test]
    fn load_from_bytes_detects_hash_mismatch() {
        let mut assets = model_assets();
        assets.insert(
            "policy/policy_bundle.json".to_string(),
            signed_policy_bundle_bytes(),
        );
        let manifest = manifest_bytes("bundle-test-v1", &assets);
        assets.insert("classify/embedding.onnx".to_string(), b"tampered".to_vec());

        let err = match ClassifyBundle::load_from_bytes(manifest.as_slice(), assets) {
            Ok(_) => panic!("mismatch should fail"),
            Err(error) => error,
        };
        assert!(matches!(err, BundleLoadError::AssetHashMismatch { .. }));
    }

    #[test]
    fn load_from_dir_reads_manifest_and_assets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut assets = model_assets();
        assets.insert(
            "policy/policy_bundle.json".to_string(),
            signed_policy_bundle_bytes(),
        );
        let manifest = manifest_bytes("bundle-disk-v1", &assets);

        for (path, bytes) in &assets {
            let disk_path = dir.path().join(path);
            if let Some(parent) = disk_path.parent() {
                std::fs::create_dir_all(parent).expect("create parent");
            }
            std::fs::write(disk_path, bytes).expect("write asset");
        }
        std::fs::write(dir.path().join("manifest.json"), manifest).expect("write manifest");

        let bundle = ClassifyBundle::load(dir.path()).expect("bundle should load");
        assert_eq!(bundle.bundle_version, "bundle-disk-v1");
        assert!(bundle.has_real_models);
        assert_eq!(bundle.centroids.len(), 2);
        assert_eq!(bundle.lsh_projection.len(), LSH_PROJECTION_ROWS);
        assert_eq!(bundle.classifier.bundle_version(), "bundle-disk-v1");
        assert_eq!(
            bundle.policy_bundle.metadata.bundle_version,
            "policy-test-v1"
        );
    }

    #[test]
    fn load_without_policy_falls_back_to_empty_policy_bundle() {
        let assets = model_assets();
        let manifest = manifest_bytes("bundle-no-policy-v1", &assets);

        let bundle = ClassifyBundle::load_from_bytes(manifest.as_slice(), assets)
            .expect("bundle should load");
        assert_eq!(bundle.classifier.bundle_version(), "bundle-no-policy-v1");
        assert_eq!(
            bundle.policy_bundle.metadata.bundle_version,
            "fallback-0.0.0"
        );
    }
}
