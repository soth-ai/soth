// Local ONNX embedding runtime.
//
// Gated behind the `onnx-models` feature (default ON for proxy + native SDK
// bindings). When disabled (e.g. WASM / size-constrained targets) the stub
// type at the bottom of this file keeps `Option<Arc<OnnxEmbeddingRuntime>>`
// in `ClassifyBundle` compilable; `bundle::build_onnx_runtime` always returns
// `None` and stage1 takes the hash-embedding fallback path.
//
// ── Concurrency rationale ──────────────────────────────────────────────────
// `ort::session::Session::run` takes `&mut self` in ort 2.0.0-rc.x (verified
// against `~/.cargo/registry/.../ort-2.0.0-rc.11/src/session/mod.rs:206`).
// Concurrent calls from multiple host threads — Python via PyO3, Node via
// napi-rs worker pool, the proxy classify task pool — therefore require
// exclusive access for the duration of each inference call.
//
// We wrap the session in a `std::sync::Mutex`. `RwLock` would not help: every
// inference call is a writer under the `&mut self` signature. ort 2.x is
// `Send + Sync` for the `Session` type itself (the underlying ONNX runtime is
// thread-safe), but the Rust binding's signature is the binding constraint.
//
// Performance: ONNX Runtime parallelizes inference internally via its own
// threadpool (`with_intra_threads` / `with_inter_threads`). The Mutex
// serializes *Rust-level callers*, but each held call still uses the
// configured ORT threadpool. Bench `classify_bench` measures the steady-state
// cost; if Mutex contention becomes the bottleneck under high QPS, the next
// step is a session pool (multiple `OnnxEmbeddingRuntime` instances behind
// `crossbeam-queue::ArrayQueue`), not lock-free single-session access.

#[cfg(feature = "onnx-models")]
use std::sync::Mutex;

#[cfg(feature = "onnx-models")]
use ort::session::Session;
#[cfg(feature = "onnx-models")]
use ort::value::Tensor;
#[cfg(feature = "onnx-models")]
use tokenizers::tokenizer::TruncationDirection;
#[cfg(feature = "onnx-models")]
use tokenizers::{PaddingParams, PaddingStrategy, Tokenizer, TruncationParams, TruncationStrategy};

/// Maximum token sequence length for the ONNX embedding model.
///
/// MiniLM-L6-v2 was trained with a 256-token context window.  The tokenizer
/// JSON bundled from HuggingFace ships with `max_length: 128` as a
/// conservative default; we override both truncation and padding in code so
/// that the full 256-token window is used regardless of what the JSON config
/// says.  Longer inputs are truncated from the LEFT (keeping the LAST 256
/// tokens) because for agentic coding prompts the user's actual instruction
/// is at the end, while pasted context/code is at the beginning.  Shorter
/// inputs are right-padded to exactly 256 tokens for fixed-size tensors.
#[cfg(feature = "onnx-models")]
const TOKENIZER_MAX_LENGTH: usize = 256;

#[cfg(feature = "onnx-models")]
pub(crate) struct OnnxEmbeddingRuntime {
    session: Mutex<Session>,
    tokenizer: Tokenizer,
}

// Compile-time assertion: `OnnxEmbeddingRuntime` MUST stay `Send + Sync` so
// it can sit inside `Arc<...>` in `ClassifyBundle` and be shared across
// host language thread pools (PyO3 / napi-rs). If a future change adds a
// non-`Send`/non-`Sync` field this fails to compile.
#[cfg(feature = "onnx-models")]
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<OnnxEmbeddingRuntime>();
};

#[cfg(feature = "onnx-models")]
impl OnnxEmbeddingRuntime {
    pub(crate) fn new(model_bytes: &[u8], tokenizer_json: &[u8]) -> Result<Self, String> {
        let mut tokenizer =
            Tokenizer::from_bytes(tokenizer_json).map_err(|error| format!("tokenizer: {error}"))?;

        // Override any max_length baked into tokenizer.json.  The bundled file
        // ships with max_length=128; we want the full 256-token MiniLM window.
        tokenizer
            .with_truncation(Some(TruncationParams {
                max_length: TOKENIZER_MAX_LENGTH,
                strategy: TruncationStrategy::LongestFirst,
                stride: 0,
                direction: TruncationDirection::Left,
            }))
            .map_err(|error| format!("tokenizer truncation: {error}"))?;
        tokenizer.with_padding(Some(PaddingParams {
            strategy: PaddingStrategy::Fixed(TOKENIZER_MAX_LENGTH),
            pad_id: 0,
            pad_token: "[PAD]".to_string(),
            ..Default::default()
        }));

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
        // Defensive guard — tokenizer-level truncation (Left, set in new()) already
        // caps to TOKENIZER_MAX_LENGTH, but re-apply here as a safety net.
        encoding.truncate(TOKENIZER_MAX_LENGTH, 0, TruncationDirection::Left);

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

// ---------------------------------------------------------------------------
// Stub used when `onnx-models` is disabled.
//
// Keeps `Option<Arc<OnnxEmbeddingRuntime>>` in `ClassifyBundle` compilable
// without dragging `ort` / `tokenizers` into the build. `new()` returns
// `EmbedUnavailable::DelegatedToCloud` rather than producing a fake embedding
// — callers must explicitly handle the `None` runtime case (see stage1).
// ---------------------------------------------------------------------------

#[cfg(not(feature = "onnx-models"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // surfaced via `OnnxEmbeddingRuntime::new` errors in stub mode
pub(crate) enum EmbedUnavailable {
    /// `onnx-models` feature is disabled — local embedding is unavailable.
    /// SDK / WASM consumers route through the cloud-classify path; the proxy
    /// always builds with this feature on, so this variant should never be
    /// observed in proxy code.
    DelegatedToCloud,
}

#[cfg(not(feature = "onnx-models"))]
pub(crate) struct OnnxEmbeddingRuntime {
    _private: (),
}

#[cfg(not(feature = "onnx-models"))]
impl OnnxEmbeddingRuntime {
    /// Always fails with `DelegatedToCloud` — the runtime is intentionally
    /// uninstantiable when the feature is disabled. `bundle::build_onnx_runtime`
    /// short-circuits before reaching this and returns `None`.
    #[allow(dead_code)]
    pub(crate) fn new(_model_bytes: &[u8], _tokenizer_json: &[u8]) -> Result<Self, String> {
        Err("onnx-models feature disabled".to_string())
    }

    /// Stub `embed` exists only so that any accidental call site type-checks.
    /// In practice this is unreachable: the `Option<Arc<OnnxEmbeddingRuntime>>`
    /// in `ClassifyBundle` is always `None` when the feature is off, so stage1
    /// never dispatches into this method.
    #[allow(dead_code)]
    pub(crate) fn embed(&self, _text: &str) -> Result<Vec<f32>, String> {
        Err("onnx-models feature disabled".to_string())
    }
}
