use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use soth_core::{AnomalyFlag, InteractionMode, UseCaseLabel, UseCaseLabelReason};

use crate::traits::{AnomalyScorer, AnomalySignals, ClassificationProvider, ClassificationResult};

use crate::bundle::EMBEDDING_DIM;
const MLP_ASSET_CANDIDATES: [&str; 2] = ["classify/use_case_mlp.bin", "use_case_mlp.bin"];
const SOTH_MLP_MAGIC: u32 = 0x534F_5448;
// Order MUST stay backward-compatible with raw-weights bundles (no embedded
// labels). `parse_classifier_raw` walks the float matrix and assigns each
// row to LABEL_SPACE[i], so reordering existing entries silently rewires
// every legacy bundle to the wrong label. New variants from the 400k
// retrain are appended *after* the legacy 16 (positions 0–15 unchanged)
// and before `Unknown` so the catch-all stays last. Bundles built with
// the SOTH binary header carry their own label strings and ignore this
// array — see `parse_classifier_soth_binary` and `map_bundle_label`.
const LABEL_SPACE: [UseCaseLabel; 22] = [
    UseCaseLabel::CodeGeneration,     // 0
    UseCaseLabel::CodeReview,         // 1
    UseCaseLabel::CodeDebugging,      // 2
    UseCaseLabel::CodeRefactor,       // 3
    UseCaseLabel::TextSummarization,  // 4
    UseCaseLabel::TextGeneration,     // 5
    UseCaseLabel::Translation,        // 6
    UseCaseLabel::DataAnalysis,       // 7
    UseCaseLabel::DataExtraction,     // 8
    UseCaseLabel::QuestionAnswering,  // 9
    UseCaseLabel::DocumentSearch,     // 10
    UseCaseLabel::AgentTask,          // 11
    UseCaseLabel::ToolOrchestration,  // 12
    UseCaseLabel::ImageAnalysis,      // 13
    UseCaseLabel::AudioTranscription, // 14
    UseCaseLabel::SystemPromptOnly,   // 15
    UseCaseLabel::InfraDevops,        // 16 (new — 400k retrain)
    UseCaseLabel::LegalContract,      // 17 (new)
    UseCaseLabel::ResearchSynthesis,  // 18 (new)
    UseCaseLabel::SecurityAnalysis,   // 19 (new)
    UseCaseLabel::ContentEditing,     // 20 (new)
    UseCaseLabel::Unknown,            // 21 (catch-all stays last)
];

pub(crate) fn build_model_providers(
    bundle_version: String,
    assets: &HashMap<String, Vec<u8>>,
) -> (Arc<dyn ClassificationProvider>, Arc<dyn AnomalyScorer>) {
    let seed = asset_seed(assets);
    let classifier = parse_classifier_from_assets(bundle_version.clone(), assets)
        .unwrap_or_else(|| BundleModelClassifier::from_seed(bundle_version, seed));
    (
        Arc::new(classifier),
        Arc::new(BundleModelAnomalyScorer::from_seed(seed.rotate_left(17))),
    )
}

struct BundleModelClassifier {
    bundle_version: String,
    model: ClassifierModel,
}

enum ClassifierModel {
    Linear(LinearClassifier),
    SothBinary(SothBinaryClassifier),
}

struct LinearClassifier {
    labels: Vec<UseCaseLabel>,
    weights: Vec<Vec<f32>>,
    biases: Vec<f32>,
}

struct LayerNormParams {
    gamma: Vec<f32>,
    beta: Vec<f32>,
}

struct SothBinaryClassifier {
    hidden1_weights: Vec<Vec<f32>>,
    hidden1_biases: Vec<f32>,
    hidden2_weights: Vec<Vec<f32>>,
    hidden2_biases: Vec<f32>,
    norm1: LayerNormParams,
    norm2: LayerNormParams,
    usecase_weights: Vec<Vec<f32>>,
    usecase_biases: Vec<f32>,
    usecase_labels: Vec<UseCaseLabel>,
    auxiliary_weights: Vec<Vec<f32>>,
    auxiliary_biases: Vec<f32>,
    auxiliary_labels: Vec<String>,
}

impl BundleModelClassifier {
    fn from_seed(bundle_version: String, seed: u64) -> Self {
        let mut weights = Vec::with_capacity(LABEL_SPACE.len());
        let mut biases = Vec::with_capacity(LABEL_SPACE.len());
        for label_idx in 0..LABEL_SPACE.len() {
            let mut weight = Vec::with_capacity(EMBEDDING_DIM);
            for dim in 0..EMBEDDING_DIM {
                let value = sample_signed(seed, label_idx as u64, dim as u64);
                weight.push(value);
            }
            l2_normalize(&mut weight);
            weights.push(weight);
            biases.push(sample_signed(seed, label_idx as u64, 9_001) * 0.10);
        }

        Self {
            bundle_version,
            model: ClassifierModel::Linear(LinearClassifier {
                labels: LABEL_SPACE.to_vec(),
                weights,
                biases,
            }),
        }
    }
}

impl ClassificationProvider for BundleModelClassifier {
    fn classify(&self, embedding: &[f32]) -> ClassificationResult {
        match &self.model {
            ClassifierModel::Linear(model) => classify_linear(model, embedding),
            ClassifierModel::SothBinary(model) => classify_soth_binary(model, embedding),
        }
    }

    fn bundle_version(&self) -> &str {
        self.bundle_version.as_str()
    }
}

fn classify_linear(model: &LinearClassifier, embedding: &[f32]) -> ClassificationResult {
    if embedding.len() != EMBEDDING_DIM {
        tracing::warn!(
            actual = embedding.len(),
            expected = EMBEDDING_DIM,
            "classify_linear: embedding dim mismatch; emitting Unknown/ModelShapeError"
        );
        return shape_error_result();
    }

    let logits = affine_logits(embedding, &model.weights, &model.biases);
    if logits.is_empty() || logits.len() != model.labels.len() {
        tracing::warn!(
            logits_len = logits.len(),
            labels_len = model.labels.len(),
            "classify_linear: logits/labels length mismatch; emitting Unknown/ModelShapeError"
        );
        return shape_error_result();
    }

    classify_from_probs(
        model.labels.as_slice(),
        softmax(logits.as_slice()).as_slice(),
    )
}

fn classify_soth_binary(model: &SothBinaryClassifier, embedding: &[f32]) -> ClassificationResult {
    if embedding.len() != EMBEDDING_DIM {
        tracing::warn!(
            actual = embedding.len(),
            expected = EMBEDDING_DIM,
            "classify_soth_binary: embedding dim mismatch; emitting Unknown/ModelShapeError"
        );
        return shape_error_result();
    }

    let mut hidden1 = affine_logits(embedding, &model.hidden1_weights, &model.hidden1_biases);
    relu_in_place(hidden1.as_mut_slice());
    layer_norm_in_place(hidden1.as_mut_slice(), &model.norm1);

    let mut hidden2 = affine_logits(
        hidden1.as_slice(),
        &model.hidden2_weights,
        &model.hidden2_biases,
    );
    relu_in_place(hidden2.as_mut_slice());
    layer_norm_in_place(hidden2.as_mut_slice(), &model.norm2);

    let logits = affine_logits(
        hidden2.as_slice(),
        &model.usecase_weights,
        &model.usecase_biases,
    );
    if logits.is_empty() || logits.len() != model.usecase_labels.len() {
        tracing::warn!(
            logits_len = logits.len(),
            labels_len = model.usecase_labels.len(),
            "classify_soth_binary: usecase logits/labels length mismatch; \
             emitting Unknown/ModelShapeError"
        );
        return shape_error_result();
    }

    let probs = softmax(logits.as_slice());
    let aggregated =
        aggregate_probs_to_public_labels(model.usecase_labels.as_slice(), probs.as_slice());
    let mut result = classify_from_probs(LABEL_SPACE.as_slice(), aggregated.as_slice());

    // Auxiliary head: interaction mode (AUGMENTATIVE / DIRECTIVE / EXPRESSIVE)
    if !model.auxiliary_weights.is_empty() && !model.auxiliary_labels.is_empty() {
        let aux_logits = affine_logits(
            hidden2.as_slice(),
            &model.auxiliary_weights,
            &model.auxiliary_biases,
        );
        if !aux_logits.is_empty() && aux_logits.len() == model.auxiliary_labels.len() {
            let aux_probs = softmax(aux_logits.as_slice());
            let (top_idx, _) = top1(aux_probs.as_slice());
            result.interaction_mode =
                map_auxiliary_label(model.auxiliary_labels.get(top_idx).map(String::as_str));
        }
    }

    result
}

fn map_auxiliary_label(label: Option<&str>) -> InteractionMode {
    match label {
        Some("AUGMENTATIVE") => InteractionMode::Augmentative,
        Some("DIRECTIVE") => InteractionMode::Directive,
        Some("EXPRESSIVE") => InteractionMode::Expressive,
        _ => InteractionMode::Unknown,
    }
}

fn classify_from_probs(labels: &[UseCaseLabel], probs: &[f32]) -> ClassificationResult {
    if labels.is_empty() || labels.len() != probs.len() {
        tracing::warn!(
            labels_len = labels.len(),
            probs_len = probs.len(),
            "classify_from_probs: labels/probs length mismatch; \
             emitting Unknown/ModelShapeError"
        );
        return shape_error_result();
    }

    let (top_idx, top_prob) = top1(probs);
    let secondary = if top_prob < 0.40 {
        top2(probs)
            .filter(|(_, prob)| *prob > 0.25)
            .and_then(|(idx, _)| {
                let label = labels[idx];
                if label != labels[top_idx] {
                    Some(label)
                } else {
                    None
                }
            })
    } else {
        None
    };

    let confidence = top_prob.clamp(0.0, 1.0);
    let top_label = labels[top_idx];
    // Reason: Confident when top-1 ≥ 0.40 (also the threshold used to suppress
    // the secondary label); LowConfidence below that. Unknown lands in the
    // `Unknown` bucket only when the model was trained with `Unknown` as a
    // class — preserve `Confident` in that case so the dashboard can tell
    // "model confident this is unclassifiable" from "no signal at all".
    let label_reason = if confidence < 0.40 {
        UseCaseLabelReason::LowConfidence
    } else {
        UseCaseLabelReason::Confident
    };

    ClassificationResult {
        label: top_label,
        confidence,
        secondary_label: secondary,
        interaction_mode: InteractionMode::Unknown, // set by caller for soth_binary
        label_reason,
    }
}

/// Shared defensive-error result used by `classify_linear`, `classify_soth_binary`,
/// and `classify_from_probs` when input shapes don't match expectations.
/// Carries `ModelShapeError` so the cloud can distinguish a corrupt model
/// from a legitimate "no signal available" Unknown.
fn shape_error_result() -> ClassificationResult {
    ClassificationResult {
        label: UseCaseLabel::Unknown,
        confidence: 0.0,
        secondary_label: None,
        interaction_mode: InteractionMode::Unknown,
        label_reason: UseCaseLabelReason::ModelShapeError,
    }
}

fn aggregate_probs_to_public_labels(source_labels: &[UseCaseLabel], probs: &[f32]) -> Vec<f32> {
    let mut buckets = vec![0.0f32; LABEL_SPACE.len()];
    for (idx, prob) in probs.iter().copied().enumerate() {
        let label = source_labels
            .get(idx)
            .copied()
            .unwrap_or(UseCaseLabel::Unknown);
        let target_idx = public_label_index(label);
        buckets[target_idx] += prob.max(0.0);
    }
    buckets
}

fn public_label_index(label: UseCaseLabel) -> usize {
    // Inverse of LABEL_SPACE — keep in lockstep with that array. New
    // variants from the 400k retrain occupy 16–20 so legacy variants
    // 0–15 keep their indices and Unknown stays the last position.
    match label {
        UseCaseLabel::CodeGeneration => 0,
        UseCaseLabel::CodeReview => 1,
        UseCaseLabel::CodeDebugging => 2,
        UseCaseLabel::CodeRefactor => 3,
        UseCaseLabel::TextSummarization => 4,
        UseCaseLabel::TextGeneration => 5,
        UseCaseLabel::Translation => 6,
        UseCaseLabel::DataAnalysis => 7,
        UseCaseLabel::DataExtraction => 8,
        UseCaseLabel::QuestionAnswering => 9,
        UseCaseLabel::DocumentSearch => 10,
        UseCaseLabel::AgentTask => 11,
        UseCaseLabel::ToolOrchestration => 12,
        UseCaseLabel::ImageAnalysis => 13,
        UseCaseLabel::AudioTranscription => 14,
        UseCaseLabel::SystemPromptOnly => 15,
        UseCaseLabel::InfraDevops => 16,
        UseCaseLabel::LegalContract => 17,
        UseCaseLabel::ResearchSynthesis => 18,
        UseCaseLabel::SecurityAnalysis => 19,
        UseCaseLabel::ContentEditing => 20,
        UseCaseLabel::Unknown => 21,
    }
}

fn affine_logits(input: &[f32], weights: &[Vec<f32>], biases: &[f32]) -> Vec<f32> {
    if weights.is_empty() || biases.len() != weights.len() {
        return Vec::new();
    }

    let mut logits = Vec::with_capacity(weights.len());
    for (idx, weight) in weights.iter().enumerate() {
        if weight.len() != input.len() {
            return Vec::new();
        }
        let score = input
            .iter()
            .zip(weight.iter())
            .map(|(left, right)| left * right)
            .sum::<f32>()
            + biases[idx];
        logits.push(score);
    }
    logits
}

fn relu_in_place(values: &mut [f32]) {
    for value in values {
        if *value < 0.0 {
            *value = 0.0;
        }
    }
}

fn layer_norm_in_place(values: &mut [f32], params: &LayerNormParams) {
    if values.is_empty() || params.gamma.len() != values.len() || params.beta.len() != values.len()
    {
        return;
    }

    let mean = values.iter().copied().sum::<f32>() / values.len() as f32;
    let variance = values
        .iter()
        .map(|value| {
            let centered = *value - mean;
            centered * centered
        })
        .sum::<f32>()
        / values.len() as f32;

    let inv_std = (variance + 1e-5).sqrt().recip();

    for (idx, value) in values.iter_mut().enumerate() {
        let normalized = (*value - mean) * inv_std;
        *value = normalized * params.gamma[idx] + params.beta[idx];
    }
}

struct BundleModelAnomalyScorer {
    weights: [f32; 7],
    bias: f32,
}

impl BundleModelAnomalyScorer {
    fn from_seed(seed: u64) -> Self {
        let mut weights = [0.0f32; 7];
        for (idx, weight) in weights.iter_mut().enumerate() {
            *weight = sample_signed(seed, idx as u64, 17_007) * 1.2;
        }
        Self {
            weights,
            bias: sample_signed(seed, 7, 17_007),
        }
    }
}

impl AnomalyScorer for BundleModelAnomalyScorer {
    fn score(&self, signals: &AnomalySignals) -> f32 {
        let features = signals_to_features(signals);
        let linear = self
            .weights
            .iter()
            .zip(features.iter())
            .map(|(weight, feature)| weight * feature)
            .sum::<f32>()
            + self.bias;
        sigmoid(linear)
    }

    fn flags(&self, signals: &AnomalySignals) -> Vec<AnomalyFlag> {
        let mut flags = Vec::new();
        if signals.topic_drift_score > 0.6 {
            flags.push(AnomalyFlag::TopicDrift);
        }
        if signals.credential_burst {
            flags.push(AnomalyFlag::CredentialBurst);
        }
        if signals.token_burst_ratio > 3.0 {
            flags.push(AnomalyFlag::TokenBurst);
        }
        if signals.model_switched {
            flags.push(AnomalyFlag::ModelSwitch);
        }
        if signals.inter_request_ms.map(|ms| ms < 500).unwrap_or(false)
            && signals.session_request_count > 3
        {
            flags.push(AnomalyFlag::RapidFireRequests);
        }
        if signals.tool_call_depth > 10 {
            flags.push(AnomalyFlag::ToolCallDepthSpike);
        }

        let score = self.score(signals);
        if score > 0.8 && !flags.contains(&AnomalyFlag::AgentLoopPattern) {
            flags.push(AnomalyFlag::AgentLoopPattern);
        }
        flags
    }
}

fn signals_to_features(signals: &AnomalySignals) -> [f32; 7] {
    [
        signals.topic_drift_score.clamp(0.0, 1.0),
        if signals.credential_burst { 1.0 } else { 0.0 },
        ((signals.token_burst_ratio - 1.0) / 4.0).clamp(0.0, 1.0),
        if signals.model_switched { 1.0 } else { 0.0 },
        signals
            .inter_request_ms
            .map(|ms| (1_000u64.saturating_sub(ms.min(1_000)) as f32) / 1_000.0)
            .unwrap_or(0.0),
        (signals.tool_call_depth as f32 / 16.0).clamp(0.0, 1.0),
        (signals.session_request_count as f32 / 100.0).clamp(0.0, 1.0),
    ]
}

#[derive(Debug, Deserialize)]
struct JsonMlpAsset {
    weights: Vec<Vec<f32>>,
    #[serde(default)]
    biases: Vec<f32>,
}

fn parse_classifier_from_assets(
    bundle_version: String,
    assets: &HashMap<String, Vec<u8>>,
) -> Option<BundleModelClassifier> {
    let bytes = MLP_ASSET_CANDIDATES
        .iter()
        .find_map(|candidate| asset_bytes_for_path(assets, candidate))?;

    if let Some(parsed) = parse_classifier_json(bundle_version.clone(), bytes) {
        return Some(parsed);
    }
    if let Some(parsed) = parse_classifier_soth_binary(bundle_version.clone(), bytes) {
        return Some(parsed);
    }
    parse_classifier_raw(bundle_version, bytes)
}

fn parse_classifier_json(bundle_version: String, bytes: &[u8]) -> Option<BundleModelClassifier> {
    let parsed: JsonMlpAsset = serde_json::from_slice(bytes).ok()?;
    build_classifier_from_parts(bundle_version, parsed.weights, parsed.biases)
}

fn parse_classifier_soth_binary(
    bundle_version: String,
    bytes: &[u8],
) -> Option<BundleModelClassifier> {
    let mut cursor = ByteCursor::new(bytes);

    if cursor.read_u32()? != SOTH_MLP_MAGIC {
        return None;
    }

    let _format_major = cursor.read_u32()?;
    let _format_minor = cursor.read_u32()?;
    let _format_patch = cursor.read_u32()?;

    let usecase_count = usize::try_from(cursor.read_u32()?).ok()?;
    let auxiliary_count = usize::try_from(cursor.read_u32()?).ok()?;
    let hidden1_dim = usize::try_from(cursor.read_u32()?).ok()?;
    let input_dim = usize::try_from(cursor.read_u32()?).ok()?;

    if input_dim != EMBEDDING_DIM || usecase_count == 0 || hidden1_dim == 0 {
        return None;
    }

    let hidden1_weights = cursor.read_matrix(hidden1_dim, input_dim)?;
    let hidden1_biases = cursor.read_len_prefixed_vector(hidden1_dim)?;

    let hidden2_dim = usize::try_from(cursor.read_u32()?).ok()?;
    let hidden2_input_dim = usize::try_from(cursor.read_u32()?).ok()?;
    if hidden2_dim == 0 || hidden2_input_dim != hidden1_dim {
        return None;
    }

    let hidden2_weights = cursor.read_matrix(hidden2_dim, hidden1_dim)?;
    let hidden2_biases = cursor.read_len_prefixed_vector(hidden2_dim)?;

    let norm1 = cursor.read_layer_norm(hidden1_dim)?;
    let norm2 = cursor.read_layer_norm(hidden2_dim)?;

    let usecase_rows = usize::try_from(cursor.read_u32()?).ok()?;
    let usecase_cols = usize::try_from(cursor.read_u32()?).ok()?;
    if usecase_rows != usecase_count || usecase_cols != hidden2_dim {
        return None;
    }
    let usecase_weights = cursor.read_matrix(usecase_rows, usecase_cols)?;
    let usecase_biases = cursor.read_len_prefixed_vector(usecase_count)?;

    let auxiliary_rows = usize::try_from(cursor.read_u32()?).ok()?;
    let auxiliary_cols = usize::try_from(cursor.read_u32()?).ok()?;
    if auxiliary_rows != auxiliary_count || auxiliary_cols != hidden2_dim {
        return None;
    }
    let auxiliary_weights = cursor.read_matrix(auxiliary_rows, auxiliary_cols)?;
    let auxiliary_biases = cursor.read_len_prefixed_vector(auxiliary_rows)?;

    let raw_labels = cursor.read_label_block(usecase_count)?;
    // Log any vendor labels that don't match our canonical taxonomy — they
    // get bucketed into UseCaseLabel::Unknown at parse time. Without this
    // log, "vendor introduced a new label we should add to our enum" was
    // indistinguishable from a legitimate model Unknown at runtime.
    for raw in &raw_labels {
        if matches!(map_bundle_label(raw.as_str()), UseCaseLabel::Unknown)
            && !raw.trim().eq_ignore_ascii_case("UNKNOWN")
        {
            tracing::warn!(
                bundle_label = %raw,
                "bundle declared use-case label not in canonical UseCaseLabel enum; \
                 bucketed as Unknown (UnmappedBundleLabel)"
            );
        }
    }
    let usecase_labels = raw_labels
        .into_iter()
        .map(|label| map_bundle_label(label.as_str()))
        .collect::<Vec<_>>();
    let auxiliary_labels = cursor.read_label_block(auxiliary_count)?;

    if usecase_labels.is_empty() {
        return None;
    }

    Some(BundleModelClassifier {
        bundle_version,
        model: ClassifierModel::SothBinary(SothBinaryClassifier {
            hidden1_weights,
            hidden1_biases,
            hidden2_weights,
            hidden2_biases,
            norm1,
            norm2,
            usecase_weights,
            usecase_biases,
            usecase_labels,
            auxiliary_weights,
            auxiliary_biases,
            auxiliary_labels,
        }),
    })
}

fn parse_classifier_raw(bundle_version: String, bytes: &[u8]) -> Option<BundleModelClassifier> {
    if bytes.len() % std::mem::size_of::<f32>() != 0 {
        return None;
    }
    let floats = bytes
        .chunks_exact(std::mem::size_of::<f32>())
        .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect::<Vec<_>>();

    let label_count = LABEL_SPACE.len();
    let weight_len = label_count * EMBEDDING_DIM;
    if floats.len() < weight_len {
        return None;
    }

    let mut weights = Vec::with_capacity(label_count);
    let mut offset = 0usize;
    for _ in 0..label_count {
        let end = offset + EMBEDDING_DIM;
        weights.push(floats[offset..end].to_vec());
        offset = end;
    }

    let biases = if floats.len() >= weight_len + label_count {
        floats[offset..(offset + label_count)].to_vec()
    } else {
        vec![0.0; label_count]
    };

    build_classifier_from_parts(bundle_version, weights, biases)
}

fn build_classifier_from_parts(
    bundle_version: String,
    mut weights: Vec<Vec<f32>>,
    biases: Vec<f32>,
) -> Option<BundleModelClassifier> {
    let label_count = LABEL_SPACE.len();
    if weights.len() != label_count || biases.len() != label_count {
        return None;
    }
    if !weights.iter().all(|row| row.len() == EMBEDDING_DIM) {
        return None;
    }

    for row in &mut weights {
        l2_normalize(row.as_mut_slice());
    }

    Some(BundleModelClassifier {
        bundle_version,
        model: ClassifierModel::Linear(LinearClassifier {
            labels: LABEL_SPACE.to_vec(),
            weights,
            biases,
        }),
    })
}

struct ByteCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u32(&mut self) -> Option<u32> {
        if self.offset + 4 > self.bytes.len() {
            return None;
        }
        let value = u32::from_le_bytes([
            self.bytes[self.offset],
            self.bytes[self.offset + 1],
            self.bytes[self.offset + 2],
            self.bytes[self.offset + 3],
        ]);
        self.offset += 4;
        Some(value)
    }

    fn read_f32_vec(&mut self, len: usize) -> Option<Vec<f32>> {
        let bytes_len = len.checked_mul(std::mem::size_of::<f32>())?;
        if self.offset + bytes_len > self.bytes.len() {
            return None;
        }

        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            let value = f32::from_le_bytes([
                self.bytes[self.offset],
                self.bytes[self.offset + 1],
                self.bytes[self.offset + 2],
                self.bytes[self.offset + 3],
            ]);
            out.push(value);
            self.offset += 4;
        }
        Some(out)
    }

    fn read_matrix(&mut self, rows: usize, cols: usize) -> Option<Vec<Vec<f32>>> {
        let total = rows.checked_mul(cols)?;
        let data = self.read_f32_vec(total)?;
        let mut matrix = Vec::with_capacity(rows);
        for row_idx in 0..rows {
            let start = row_idx.checked_mul(cols)?;
            let end = start + cols;
            matrix.push(data[start..end].to_vec());
        }
        Some(matrix)
    }

    fn read_len_prefixed_vector(&mut self, expected_len: usize) -> Option<Vec<f32>> {
        let len = usize::try_from(self.read_u32()?).ok()?;
        if len != expected_len {
            return None;
        }
        self.read_f32_vec(len)
    }

    fn read_layer_norm(&mut self, expected_len: usize) -> Option<LayerNormParams> {
        let len = usize::try_from(self.read_u32()?).ok()?;
        if len != expected_len {
            return None;
        }
        let gamma = self.read_f32_vec(len)?;
        let beta = self.read_f32_vec(len)?;
        Some(LayerNormParams { gamma, beta })
    }

    fn read_label_block(&mut self, expected_count: usize) -> Option<Vec<String>> {
        let count = usize::try_from(self.read_u32()?).ok()?;
        if count != expected_count {
            return None;
        }

        let mut labels = Vec::with_capacity(count);
        for _ in 0..count {
            let len = usize::try_from(self.read_u32()?).ok()?;
            if self.offset + len > self.bytes.len() {
                return None;
            }
            let raw = std::str::from_utf8(&self.bytes[self.offset..self.offset + len]).ok()?;
            labels.push(raw.to_string());
            self.offset += len;
        }

        Some(labels)
    }
}

fn map_bundle_label(label: &str) -> UseCaseLabel {
    let normalized = label.trim().to_ascii_uppercase().replace(['-', ' '], "_");

    match normalized.as_str() {
        "CODE_GENERATION" | "TEST_GENERATION" => UseCaseLabel::CodeGeneration,
        "CODE_REVIEW" => UseCaseLabel::CodeReview,
        "CODE_DEBUGGING" => UseCaseLabel::CodeDebugging,
        "CODE_REFACTOR" => UseCaseLabel::CodeRefactor,
        "TEXT_SUMMARIZATION" | "DOCUMENT_SUMMARISATION" => UseCaseLabel::TextSummarization,
        // CONTENT_DRAFTING stays under TextGeneration — drafting net-new
        // content is the canonical "text generation" task. CONTENT_EDITING
        // (revising existing content) gets its own variant below since
        // edit operations have different sensitivity / governance needs.
        "TEXT_GENERATION" | "CONTENT_DRAFTING" => UseCaseLabel::TextGeneration,
        "TRANSLATION" => UseCaseLabel::Translation,
        // REGULATORY_COMPLIANCE stays under DataAnalysis — the corpus
        // examples are predominantly analytical reads of existing rules.
        // RESEARCH_SYNTHESIS gets its own variant below.
        "DATA_ANALYSIS" | "REGULATORY_COMPLIANCE" => UseCaseLabel::DataAnalysis,
        // SQL_DATA_QUERY stays under DataExtraction — it's just a more
        // specific phrasing of the same task.
        "DATA_EXTRACTION" | "SQL_DATA_QUERY" => UseCaseLabel::DataExtraction,
        "QUESTION_ANSWERING" | "DOCUMENT_QA" | "FACT_QA" => UseCaseLabel::QuestionAnswering,
        "DOCUMENT_SEARCH" => UseCaseLabel::DocumentSearch,
        "AGENT_TASK" => UseCaseLabel::AgentTask,
        "TOOL_ORCHESTRATION" => UseCaseLabel::ToolOrchestration,
        "IMAGE_ANALYSIS" => UseCaseLabel::ImageAnalysis,
        "AUDIO_TRANSCRIPTION" => UseCaseLabel::AudioTranscription,
        "SYSTEM_PROMPT_ONLY" => UseCaseLabel::SystemPromptOnly,
        // ── Variants introduced when the use-case MLP was retrained on
        // the 400k corpus. Promoted from collapsed arms above so the
        // dashboard can surface them as first-class buckets.
        "INFRA_DEVOPS" => UseCaseLabel::InfraDevops,
        "LEGAL_CONTRACT" => UseCaseLabel::LegalContract,
        "RESEARCH_SYNTHESIS" => UseCaseLabel::ResearchSynthesis,
        "SECURITY_ANALYSIS" => UseCaseLabel::SecurityAnalysis,
        "CONTENT_EDITING" => UseCaseLabel::ContentEditing,
        _ => UseCaseLabel::Unknown,
    }
}

fn top1(values: &[f32]) -> (usize, f32) {
    let mut best_idx = 0usize;
    let mut best = f32::NEG_INFINITY;
    for (idx, value) in values.iter().enumerate() {
        if *value > best {
            best = *value;
            best_idx = idx;
        }
    }
    (best_idx, best)
}

fn top2(values: &[f32]) -> Option<(usize, f32)> {
    if values.len() < 2 {
        return None;
    }
    let mut top_idx = 0usize;
    let mut top_val = f32::NEG_INFINITY;
    let mut second_idx = 0usize;
    let mut second_val = f32::NEG_INFINITY;
    for (idx, value) in values.iter().enumerate() {
        if *value > top_val {
            second_idx = top_idx;
            second_val = top_val;
            top_idx = idx;
            top_val = *value;
        } else if *value > second_val {
            second_idx = idx;
            second_val = *value;
        }
    }
    Some((second_idx, second_val))
}

fn softmax(logits: &[f32]) -> Vec<f32> {
    if logits.is_empty() {
        return Vec::new();
    }
    let max = logits
        .iter()
        .copied()
        .fold(f32::NEG_INFINITY, |left, right| left.max(right));
    let exps = logits
        .iter()
        .map(|value| (value - max).exp())
        .collect::<Vec<_>>();
    let sum = exps.iter().sum::<f32>();
    if sum <= 1e-9 {
        return vec![0.0; logits.len()];
    }
    exps.into_iter().map(|value| value / sum).collect()
}

fn asset_seed(assets: &HashMap<String, Vec<u8>>) -> u64 {
    let mut paths: Vec<&str> = assets.keys().map(String::as_str).collect();
    paths.sort_unstable();
    let mut hasher = Sha256::new();
    for path in paths {
        if let Some(bytes) = assets.get(path) {
            hasher.update(path.as_bytes());
            hasher.update([0u8]);
            hasher.update(bytes);
            hasher.update([255u8]);
        }
    }
    let digest = hasher.finalize();
    let mut seed = [0u8; 8];
    seed.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(seed)
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

fn sigmoid(value: f32) -> f32 {
    if value >= 0.0 {
        let exp = (-value).exp();
        1.0 / (1.0 + exp)
    } else {
        let exp = value.exp();
        exp / (1.0 + exp)
    }
}

fn sample_signed(seed: u64, a: u64, b: u64) -> f32 {
    let mixed = splitmix64(seed ^ (a.wrapping_mul(0x9E37_79B9_7F4A_7C15)) ^ b);
    let fraction = ((mixed >> 11) as f64) / ((1u64 << 53) as f64);
    (fraction as f32) * 2.0 - 1.0
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = value;
    z ^= z >> 30;
    z = z.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z ^= z >> 27;
    z = z.wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
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
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifier_is_deterministic_for_same_input() {
        let classifier = BundleModelClassifier::from_seed("bundle-v1".to_string(), 42);
        let embedding = vec![1.0f32 / 384.0f32.sqrt(); 384];
        let left = classifier.classify(embedding.as_slice());
        let right = classifier.classify(embedding.as_slice());
        assert_eq!(left.label, right.label);
        assert_eq!(left.secondary_label, right.secondary_label);
        assert!((left.confidence - right.confidence).abs() < 1e-6);
        assert_eq!(classifier.bundle_version(), "bundle-v1");
    }

    #[test]
    fn anomaly_scorer_flags_credential_and_depth_signals() {
        let scorer = BundleModelAnomalyScorer::from_seed(7);
        let signals = AnomalySignals {
            topic_drift_score: 0.2,
            credential_burst: true,
            token_burst_ratio: 1.0,
            model_switched: false,
            inter_request_ms: Some(2_000),
            tool_call_depth: 12,
            session_request_count: 4,
        };
        let flags = scorer.flags(&signals);
        assert!(flags.contains(&AnomalyFlag::CredentialBurst));
        assert!(flags.contains(&AnomalyFlag::ToolCallDepthSpike));
    }

    #[test]
    fn model_provider_builder_uses_bundle_version() {
        let assets = HashMap::from([
            ("classify/embedding.onnx".to_string(), b"onnx".to_vec()),
            ("classify/centroids.bin".to_string(), b"centroids".to_vec()),
        ]);
        let (classifier, scorer) = build_model_providers("bundle-v7".to_string(), &assets);
        assert_eq!(classifier.bundle_version(), "bundle-v7");
        let score = scorer.score(&AnomalySignals::default());
        assert!((0.0..=1.0).contains(&score));
    }

    #[test]
    fn classifier_can_load_raw_mlp_asset() {
        let mut floats = vec![0.0f32; LABEL_SPACE.len() * EMBEDDING_DIM + LABEL_SPACE.len()];
        floats[0] = 5.0;
        floats[(EMBEDDING_DIM) + 1] = 5.0;
        let mut bytes = Vec::with_capacity(floats.len() * 4);
        for value in floats {
            bytes.extend_from_slice(value.to_le_bytes().as_slice());
        }

        let assets = HashMap::from([("classify/use_case_mlp.bin".to_string(), bytes)]);
        let (classifier, _) = build_model_providers("bundle-v9".to_string(), &assets);

        let mut embedding = vec![0.0f32; EMBEDDING_DIM];
        embedding[0] = 1.0;
        let out = classifier.classify(embedding.as_slice());
        assert_eq!(out.label, UseCaseLabel::CodeGeneration);
    }

    #[test]
    fn classifier_can_load_soth_binary_mlp_asset() {
        let bytes = synthetic_soth_binary_mlp();
        let assets = HashMap::from([("classify/use_case_mlp.bin".to_string(), bytes)]);
        let (classifier, _) = build_model_providers("bundle-v10".to_string(), &assets);

        let embedding = vec![0.0f32; EMBEDDING_DIM];
        let out = classifier.classify(embedding.as_slice());
        assert_eq!(out.label, UseCaseLabel::CodeGeneration);
        assert!(out.confidence > 0.7);
    }

    #[test]
    fn bundle_label_mapping_maps_vendor_taxonomy() {
        assert_eq!(
            map_bundle_label("TEST_GENERATION"),
            UseCaseLabel::CodeGeneration
        );
        assert_eq!(
            map_bundle_label("SQL_DATA_QUERY"),
            UseCaseLabel::DataExtraction
        );
        assert_eq!(
            map_bundle_label("CONTENT_DRAFTING"),
            UseCaseLabel::TextGeneration
        );
        assert_eq!(
            map_bundle_label("DOCUMENT_QA"),
            UseCaseLabel::QuestionAnswering
        );

        // 400k-corpus retrain promotes these from collapsed arms to
        // their own first-class variants. See `UseCaseLabel` doc comments
        // for why each was split out (sensitivity, governance needs,
        // dashboard granularity).
        assert_eq!(map_bundle_label("INFRA_DEVOPS"), UseCaseLabel::InfraDevops);
        assert_eq!(
            map_bundle_label("LEGAL_CONTRACT"),
            UseCaseLabel::LegalContract
        );
        assert_eq!(
            map_bundle_label("RESEARCH_SYNTHESIS"),
            UseCaseLabel::ResearchSynthesis
        );
        assert_eq!(
            map_bundle_label("SECURITY_ANALYSIS"),
            UseCaseLabel::SecurityAnalysis
        );
        assert_eq!(
            map_bundle_label("CONTENT_EDITING"),
            UseCaseLabel::ContentEditing
        );
        // Variants intentionally NOT split — verify they still collapse:
        // CONTENT_DRAFTING → TextGeneration (drafting net-new content)
        // SQL_DATA_QUERY → DataExtraction (just a specific phrasing)
        // REGULATORY_COMPLIANCE → DataAnalysis (analytical reads)
        assert_eq!(
            map_bundle_label("REGULATORY_COMPLIANCE"),
            UseCaseLabel::DataAnalysis
        );
    }

    fn synthetic_soth_binary_mlp() -> Vec<u8> {
        let usecase_count = 3u32;
        let aux_count = 2u32;
        let hidden1_dim = 4u32;
        let hidden2_dim = 3u32;

        let mut out = Vec::new();

        push_u32(&mut out, SOTH_MLP_MAGIC);
        push_u32(&mut out, 2);
        push_u32(&mut out, 2);
        push_u32(&mut out, 2);
        push_u32(&mut out, usecase_count);
        push_u32(&mut out, aux_count);
        push_u32(&mut out, hidden1_dim);
        push_u32(&mut out, EMBEDDING_DIM as u32);

        for _ in 0..(hidden1_dim as usize * EMBEDDING_DIM) {
            push_f32(&mut out, 0.0);
        }

        push_u32(&mut out, hidden1_dim);
        for _ in 0..hidden1_dim {
            push_f32(&mut out, 0.0);
        }

        push_u32(&mut out, hidden2_dim);
        push_u32(&mut out, hidden1_dim);
        for _ in 0..(hidden2_dim as usize * hidden1_dim as usize) {
            push_f32(&mut out, 0.0);
        }

        push_u32(&mut out, hidden2_dim);
        for _ in 0..hidden2_dim {
            push_f32(&mut out, 0.0);
        }

        push_u32(&mut out, hidden1_dim);
        for _ in 0..hidden1_dim {
            push_f32(&mut out, 1.0);
        }
        for _ in 0..hidden1_dim {
            push_f32(&mut out, 0.0);
        }

        push_u32(&mut out, hidden2_dim);
        for _ in 0..hidden2_dim {
            push_f32(&mut out, 1.0);
        }
        for _ in 0..hidden2_dim {
            push_f32(&mut out, 0.0);
        }

        push_u32(&mut out, usecase_count);
        push_u32(&mut out, hidden2_dim);
        for _ in 0..(usecase_count as usize * hidden2_dim as usize) {
            push_f32(&mut out, 0.0);
        }

        push_u32(&mut out, usecase_count);
        push_f32(&mut out, 2.0);
        push_f32(&mut out, 0.0);
        push_f32(&mut out, -1.0);

        push_u32(&mut out, aux_count);
        push_u32(&mut out, hidden2_dim);
        for _ in 0..(aux_count as usize * hidden2_dim as usize) {
            push_f32(&mut out, 0.0);
        }

        push_u32(&mut out, aux_count);
        push_f32(&mut out, 0.0);
        push_f32(&mut out, 0.0);

        push_u32(&mut out, usecase_count);
        push_string(&mut out, "CODE_GENERATION");
        push_string(&mut out, "FACT_QA");
        push_string(&mut out, "AGENT_TASK");

        push_u32(&mut out, aux_count);
        push_string(&mut out, "AUGMENTATIVE");
        push_string(&mut out, "DIRECTIVE");

        out
    }

    fn push_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(value.to_le_bytes().as_slice());
    }

    fn push_f32(out: &mut Vec<u8>, value: f32) {
        out.extend_from_slice(value.to_le_bytes().as_slice());
    }

    fn push_string(out: &mut Vec<u8>, value: &str) {
        push_u32(out, value.len() as u32);
        out.extend_from_slice(value.as_bytes());
    }
}
