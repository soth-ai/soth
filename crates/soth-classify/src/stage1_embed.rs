use std::time::Instant;

use crate::bundle::ClassifyBundle;
use crate::config::ClassifyConfig;

#[derive(Debug, Clone, Default)]
pub(crate) struct EmbedOutput {
    pub vector: Option<Vec<f32>>,
    pub norm: f32,
    pub latency_us: u64,
}

pub(crate) fn run(
    content_for_embedding: Option<&str>,
    detect_result: &soth_core::DetectResult,
    _bundle: &ClassifyBundle,
    config: &ClassifyConfig,
) -> EmbedOutput {
    let started = Instant::now();

    if !config.embedding_enabled
        || content_for_embedding.is_none()
        || !detect_result.normalized.is_ai_call
        || (matches!(
            detect_result.confidence,
            soth_core::ParseConfidence::Heuristic
        ) && detect_result.normalized.model.is_none())
    {
        return EmbedOutput {
            vector: None,
            norm: 0.0,
            latency_us: started.elapsed().as_micros() as u64,
        };
    }

    let Some(text) = content_for_embedding else {
        return EmbedOutput {
            vector: None,
            norm: 0.0,
            latency_us: started.elapsed().as_micros() as u64,
        };
    };

    let embedded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| embed_text(text)))
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
    }
}

fn embed_text(text: &str) -> Option<(Vec<f32>, f32)> {
    let mut vec = vec![0.0f32; 384];
    for (idx, byte) in text.as_bytes().iter().enumerate() {
        let pos = idx % 384;
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
