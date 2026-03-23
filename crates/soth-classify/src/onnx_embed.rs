use std::sync::Mutex;

use ort::session::Session;
use ort::value::Tensor;
use tokenizers::tokenizer::TruncationDirection;
use tokenizers::Tokenizer;

/// Maximum token sequence length for the ONNX embedding model. Inputs
/// longer than this are truncated from the right. Must match the
/// `max_length` declared in the tokenizer config (currently 128); the
/// tokenizer pads to this value regardless of what the constant says,
/// so keeping them in sync avoids wasted processing on phantom tokens.
const TOKENIZER_MAX_LENGTH: usize = 128;

pub(crate) struct OnnxEmbeddingRuntime {
    session: Mutex<Session>,
    tokenizer: Tokenizer,
}

impl OnnxEmbeddingRuntime {
    pub(crate) fn new(model_bytes: &[u8], tokenizer_json: &[u8]) -> Result<Self, String> {
        let tokenizer =
            Tokenizer::from_bytes(tokenizer_json).map_err(|error| format!("tokenizer: {error}"))?;
        let session = Session::builder()
            .map_err(|error| format!("ort builder: {error}"))?
            .with_intra_threads(1)
            .map_err(|error| format!("ort intra_threads: {error}"))?
            .with_inter_threads(1)
            .map_err(|error| format!("ort inter_threads: {error}"))?
            .commit_from_memory(model_bytes)
            .map_err(|error| format!("ort session: {error}"))?;
        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
        })
    }

    pub(crate) fn embed(&self, text: &str) -> Result<Vec<f32>, String> {
        let mut encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|error| format!("tokenize: {error}"))?;
        encoding.truncate(TOKENIZER_MAX_LENGTH, 0, TruncationDirection::Right);

        let input_ids = encoding
            .get_ids()
            .iter()
            .map(|value| *value as i64)
            .collect::<Vec<_>>();
        let attention_mask = encoding
            .get_attention_mask()
            .iter()
            .map(|value| *value as i64)
            .collect::<Vec<_>>();

        if input_ids.is_empty() || attention_mask.is_empty() {
            return Err("empty tokenized sequence".to_string());
        }

        let input_ids_tensor =
            Tensor::<i64>::from_array((vec![1i64, input_ids.len() as i64], input_ids))
                .map_err(|error| format!("input_ids tensor: {error}"))?;
        let attention_mask_tensor =
            Tensor::<i64>::from_array((vec![1i64, attention_mask.len() as i64], attention_mask))
                .map_err(|error| format!("attention_mask tensor: {error}"))?;

        let mut session = self
            .session
            .lock()
            .map_err(|error| format!("session lock poisoned: {error}"))?;
        let outputs = session
            .run(ort::inputs![
                "input_ids" => input_ids_tensor,
                "attention_mask" => attention_mask_tensor,
            ])
            .map_err(|error| format!("ort run: {error}"))?;

        if outputs.len() == 0 {
            return Err("missing ONNX output tensor".to_string());
        }
        let (shape, data) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|error| format!("extract tensor: {error}"))?;
        if shape.len() < 3 {
            return Err(format!("unexpected output rank: {shape:?}"));
        }
        let token_count = shape[1] as usize;
        let hidden_size = shape[2] as usize;
        if hidden_size == 0 {
            return Err("hidden size is zero".to_string());
        }
        let mut pooled = vec![0.0f32; hidden_size];
        let mut active = 0usize;
        for token_idx in 0..token_count {
            let mask = encoding
                .get_attention_mask()
                .get(token_idx)
                .copied()
                .unwrap_or(0);
            if mask == 0 {
                continue;
            }
            active += 1;
            let base = token_idx * hidden_size;
            for (dim, slot) in pooled.iter_mut().enumerate() {
                *slot += data[base + dim];
            }
        }

        if active == 0 {
            return Err("all tokens masked".to_string());
        }
        let scale = 1.0 / active as f32;
        for slot in &mut pooled {
            *slot *= scale;
        }
        // Return the raw mean-pooled vector WITHOUT L2 normalization.
        // Normalization and norm computation happen in stage1_embed.rs
        // so that embedding_norm reflects the true pre-normalization
        // magnitude (a fleet health signal).
        Ok(pooled)
    }
}
