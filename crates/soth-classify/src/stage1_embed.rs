use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::bundle::{ClassifyBundle, EMBEDDING_DIM};
use crate::config::ClassifyConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EmbedSkipReason {
    Disabled,
    NotAiCall,
    HeuristicNoModel,
    CodeContextRepeat,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct EmbedOutput {
    pub vector: Option<Vec<f32>>,
    pub norm: f32,
    pub latency_us: u64,
    #[allow(dead_code)] // read in tests
    pub skipped_reason: Option<EmbedSkipReason>,
}

pub(crate) fn run(
    content_for_embedding: Option<&str>,
    detect_result: &soth_core::DetectResult,
    bundle: &ClassifyBundle,
    config: &ClassifyConfig,
) -> EmbedOutput {
    let started = Instant::now();

    // 1) Config-level kill switch
    if !config.embedding_enabled {
        return EmbedOutput {
            vector: None,
            norm: 0.0,
            latency_us: started.elapsed().as_micros() as u64,
            skipped_reason: Some(EmbedSkipReason::Disabled),
        };
    }

    // 2) Not an AI call
    if !detect_result.normalized.is_ai_call {
        return EmbedOutput {
            vector: None,
            norm: 0.0,
            latency_us: started.elapsed().as_micros() as u64,
            skipped_reason: Some(EmbedSkipReason::NotAiCall),
        };
    }

    // 3) Heuristic confidence with no model
    if matches!(
        detect_result.confidence,
        soth_core::ParseConfidence::Heuristic
    ) && detect_result.normalized.model.is_none()
    {
        return EmbedOutput {
            vector: None,
            norm: 0.0,
            latency_us: started.elapsed().as_micros() as u64,
            skipped_reason: Some(EmbedSkipReason::HeuristicNoModel),
        };
    }

    // 4) Lane: CodeContextRepeat — skip embedding, use cached cluster from session
    if detect_result.is_repeated_code_context {
        return EmbedOutput {
            vector: None,
            norm: 0.0,
            latency_us: started.elapsed().as_micros() as u64,
            skipped_reason: Some(EmbedSkipReason::CodeContextRepeat),
        };
    }

    // No content to embed
    let Some(text) = content_for_embedding else {
        return EmbedOutput {
            vector: None,
            norm: 0.0,
            latency_us: started.elapsed().as_micros() as u64,
            skipped_reason: None,
        };
    };

    let embedded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if let Some(runtime) = bundle.onnx_runtime.as_ref() {
            let vector = runtime.embed(text).ok()?;
            let mut vector = normalize_embedding_dims(vector, EMBEDDING_DIM)?;
            // Compute L2 norm from the raw (pre-normalization) vector.
            // This is the fleet health signal exposed as embedding_norm in
            // telemetry. Near-zero = ONNX failure or degenerate input.
            // TODO(retraining): after validation run, record observed p5/p95
            // norm range here for use as intelligence-layer anomaly threshold.
            let norm_sq = vector.iter().map(|value| value * value).sum::<f32>();
            let norm = norm_sq.sqrt();
            if norm <= 1e-9 {
                return None;
            }
            for value in &mut vector {
                *value /= norm;
            }
            Some((vector, norm))
        } else {
            embed_text(
                text,
                bundle.embedding_onnx.as_deref(),
                bundle.tokenizer_json.as_deref(),
            )
        }
    }))
    .ok()
    .unwrap_or_default();
    let (vector, norm) = embedded.unwrap_or((Vec::new(), 0.0));

    EmbedOutput {
        vector: if vector.is_empty() {
            None
        } else {
            Some(vector)
        },
        norm,
        latency_us: started.elapsed().as_micros() as u64,
        skipped_reason: None,
    }
}

fn embed_text(
    text: &str,
    embedding_onnx: Option<&Vec<u8>>,
    tokenizer_json: Option<&Vec<u8>>,
) -> Option<(Vec<f32>, f32)> {
    let Some(model_bytes) = embedding_onnx else {
        return embed_text_legacy(text);
    };
    if model_bytes.is_empty() {
        return embed_text_legacy(text);
    }

    let mut vec = vec![0.0f32; EMBEDDING_DIM];
    let model_seed = model_seed(model_bytes.as_slice());
    let token_salt = tokenizer_salt(tokenizer_json);

    for (idx, token) in tokenize(text).into_iter().enumerate() {
        let mut hasher = Sha256::new();
        hasher.update(model_seed.to_le_bytes());
        hasher.update(token_salt.to_le_bytes());
        hasher.update((idx as u64).to_le_bytes());
        hasher.update(token.as_bytes());
        let digest = hasher.finalize();

        for (byte_idx, byte) in digest.iter().enumerate() {
            let dim = (idx * digest.len() + byte_idx) % EMBEDDING_DIM;
            let signed = (*byte as f32 / 127.5) - 1.0;
            vec[dim] += signed;
        }
    }

    if text.len() > EMBEDDING_DIM {
        for (idx, window) in text.as_bytes().windows(3).take(1024).enumerate() {
            let mut hasher = Sha256::new();
            hasher.update(model_seed.to_le_bytes());
            hasher.update((idx as u64).to_le_bytes());
            hasher.update(window);
            let digest = hasher.finalize();
            let dim = (digest[0] as usize + idx) % EMBEDDING_DIM;
            let signed = (digest[1] as f32 / 127.5) - 1.0;
            vec[dim] += signed * 0.5;
        }
    }

    let norm_sq = vec.iter().map(|value| value * value).sum::<f32>();
    let norm = norm_sq.sqrt();
    if norm <= 1e-9 {
        return None;
    }

    for value in &mut vec {
        *value /= norm;
    }

    Some((vec, norm))
}

fn normalize_embedding_dims(mut vector: Vec<f32>, target: usize) -> Option<Vec<f32>> {
    if vector.is_empty() {
        return None;
    }
    if vector.len() == target {
        return Some(vector);
    }
    if vector.len() > target {
        vector.truncate(target);
        return Some(vector);
    }
    vector.resize(target, 0.0);
    Some(vector)
}

fn embed_text_legacy(text: &str) -> Option<(Vec<f32>, f32)> {
    let mut vec = vec![0.0f32; EMBEDDING_DIM];
    for (idx, byte) in text.as_bytes().iter().enumerate() {
        let pos = idx % EMBEDDING_DIM;
        vec[pos] += *byte as f32 / 255.0;
    }

    let norm_sq = vec.iter().map(|value| value * value).sum::<f32>();
    let norm = norm_sq.sqrt();
    if norm <= 1e-9 {
        return None;
    }

    for value in &mut vec {
        *value /= norm;
    }

    Some((vec, norm))
}

fn tokenize(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut token = String::new();
    for ch in text.chars().flat_map(|value| value.to_lowercase()) {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            token.push(ch);
            continue;
        }
        if !token.is_empty() {
            out.push(std::mem::take(&mut token));
        }
    }
    if !token.is_empty() {
        out.push(token);
    }
    out
}

fn model_seed(model_bytes: &[u8]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(model_bytes);
    let digest = hasher.finalize();
    let mut seed = [0u8; 8];
    seed.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(seed)
}

fn tokenizer_salt(tokenizer_json: Option<&Vec<u8>>) -> u64 {
    let Some(tokenizer_bytes) = tokenizer_json else {
        return 0;
    };
    if tokenizer_bytes.is_empty() {
        return 0;
    }
    let mut hasher = Sha256::new();
    hasher.update(tokenizer_bytes);
    let digest = hasher.finalize();
    let mut salt = [0u8; 8];
    salt.copy_from_slice(&digest[8..16]);
    u64::from_le_bytes(salt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn test_bundle() -> ClassifyBundle {
        use crate::fallback::{KeywordClassifier, StaticAnomalyScorer};
        ClassifyBundle {
            classifier: Arc::new(KeywordClassifier),
            anomaly_scorer: Arc::new(StaticAnomalyScorer),
            policy_bundle: Arc::new(crate::bundle::build_fallback_policy_bundle_ref()),
            embedding_onnx: Some(Arc::new(b"model-v1".to_vec())),
            tokenizer_json: Some(Arc::new(b"{\"type\":\"bpe\"}".to_vec())),
            use_case_mlp: None,
            centroids: Arc::new(Vec::new()),
            lsh_projection: Arc::new(Vec::new()),
            volatility_config_toml: None,
            bundle_volatility_config: None,
            onnx_runtime: None,
            bundle_version: "test".to_string(),
            has_real_models: false,
        }
    }

    #[test]
    fn embedding_without_model_bytes_uses_legacy_path() {
        let out = embed_text("hello world", None, None);
        assert!(out.is_some());
    }

    #[test]
    fn embedding_is_deterministic_for_same_inputs() {
        let model = b"model-v1".to_vec();
        let tokenizer = b"{\"type\":\"bpe\"}".to_vec();
        let left = embed_text("hello world", Some(&model), Some(&tokenizer))
            .expect("embedding should exist");
        let right = embed_text("hello world", Some(&model), Some(&tokenizer))
            .expect("embedding should exist");
        assert_eq!(left.0, right.0);
        assert!((left.1 - right.1).abs() < 1e-6);
    }

    #[test]
    fn test_lane_code_context_repeat_skips_embedding() {
        let bundle = test_bundle();
        let config = ClassifyConfig::default();
        let mut detect = soth_core::DetectResult::default();
        detect.normalized.is_ai_call = true;
        detect.normalized.model = Some("gpt-4o".to_string());
        detect.is_repeated_code_context = true;

        let out = run(Some("hello world"), &detect, &bundle, &config);
        assert!(out.vector.is_none());
        assert_eq!(out.skipped_reason, Some(EmbedSkipReason::CodeContextRepeat));
    }

    #[test]
    fn test_lane_code_context_repeat_does_not_affect_non_repeat() {
        let bundle = test_bundle();
        let config = ClassifyConfig::default();
        let mut detect = soth_core::DetectResult::default();
        detect.normalized.is_ai_call = true;
        detect.normalized.model = Some("gpt-4o".to_string());
        detect.is_repeated_code_context = false;

        let out = run(Some("hello world test content"), &detect, &bundle, &config);
        assert!(out.vector.is_some());
        assert_eq!(out.skipped_reason, None);
    }

    #[test]
    fn test_skip_reason_disabled() {
        let bundle = test_bundle();
        let mut config = ClassifyConfig::default();
        config.embedding_enabled = false;
        let detect = soth_core::DetectResult::default();

        let out = run(Some("hello"), &detect, &bundle, &config);
        assert_eq!(out.skipped_reason, Some(EmbedSkipReason::Disabled));
    }

    #[test]
    fn test_skip_reason_heuristic_no_model() {
        let bundle = test_bundle();
        let config = ClassifyConfig::default();
        let mut detect = soth_core::DetectResult::default();
        detect.normalized.is_ai_call = true;
        detect.confidence = soth_core::ParseConfidence::Heuristic;
        detect.normalized.model = None;

        let out = run(Some("hello"), &detect, &bundle, &config);
        assert_eq!(out.skipped_reason, Some(EmbedSkipReason::HeuristicNoModel));
    }
}
