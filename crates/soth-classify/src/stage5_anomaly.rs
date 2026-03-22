use std::collections::HashSet;
use std::time::Instant;

use soth_core::{AnomalyFlag, SessionSnapshot};

use crate::stage2_cluster::ClusterOutput;

#[derive(Debug, Clone, Default)]
pub(crate) struct AnomalyOutput {
    pub score: f32,
    pub flags: Vec<AnomalyFlag>,
}

#[derive(Debug, Clone)]
struct PreEmitEvent<'a> {
    timestamp_utc: i64,
    input_tokens: u32,
    output_tokens: Option<u32>,
    system_prompt_hash: Option<&'a str>,
    tool_call_depth: u8,
    has_tool_definitions: bool,
    embedding: Option<&'a [f32]>,
}

pub(crate) fn run(
    embedding: Option<&[f32]>,
    _cluster: &ClusterOutput,
    normalized: &soth_core::NormalizedRequest,
    artifacts: &[soth_core::SensitiveArtifact],
    session: Option<&SessionSnapshot>,
) -> (AnomalyOutput, u64) {
    let started = Instant::now();

    let Some(snapshot) = session else {
        return (
            AnomalyOutput::default(),
            started.elapsed().as_micros() as u64,
        );
    };

    let pre_emit = PreEmitEvent {
        timestamp_utc: snapshot.current_request_timestamp,
        input_tokens: normalized.estimated_input_tokens,
        output_tokens: normalized.estimated_output_tokens,
        system_prompt_hash: normalized.system_prompt_hash.as_deref(),
        tool_call_depth: normalized
            .conversation_turn
            .unwrap_or(0)
            .min(u32::from(u8::MAX)) as u8,
        has_tool_definitions: normalized.has_tool_definitions,
        embedding,
    };

    let credential_hits = artifacts
        .iter()
        .filter(|artifact| artifact.is_credential())
        .count()
        .min(usize::from(u8::MAX)) as u8;

    let output = score_rule_based(snapshot, &pre_emit, credential_hits);
    (output, started.elapsed().as_micros() as u64)
}

fn score_rule_based(
    snapshot: &SessionSnapshot,
    current: &PreEmitEvent,
    credential_hits_current_request: u8,
) -> AnomalyOutput {
    let mut flags = Vec::new();
    let mut score = 0.0f32;

    let token_baseline = if snapshot.session_token_p14d_avg > 0.0 {
        snapshot.session_token_p14d_avg
    } else if snapshot.request_count > 0 {
        snapshot.total_tokens as f32 / snapshot.request_count as f32
    } else {
        0.0
    };

    // 1) Token burst
    if token_baseline > 0.0 {
        let burst_ratio = current.input_tokens as f32 / token_baseline;
        if burst_ratio > 5.0 {
            flags.push(AnomalyFlag::TokenBurst);
            score += 0.30;
        } else if burst_ratio > 3.0 {
            flags.push(AnomalyFlag::TokenBurst);
            score += 0.15;
        }
    }

    // 2) Credential burst
    let historical_credential_alerts = u32::max(
        u32::from(snapshot.credential_alerts_24h),
        snapshot.credential_alerts,
    );
    let credential_alerts_24h =
        historical_credential_alerts.saturating_add(u32::from(credential_hits_current_request));

    if credential_alerts_24h >= 3 {
        flags.push(AnomalyFlag::CredentialBurst);
        score += 0.40;
    } else if credential_alerts_24h >= 1 {
        score += 0.10;
    }

    // 3) Rapid-fire requests
    let request_count_this_hour =
        u32::max(snapshot.request_count_this_hour, snapshot.request_count);
    if let Some(last_request_ts) = snapshot.last_request_timestamp {
        let ms_since_last = (current.timestamp_utc - last_request_ts).unsigned_abs();
        if ms_since_last < 500 && request_count_this_hour > 20 {
            flags.push(AnomalyFlag::RapidFireRequests);
            score += 0.20;
        }
    }

    // 4) Topic drift
    if let (Some(centroid), Some(embedding)) =
        (snapshot.embedding_centroid.as_ref(), current.embedding)
    {
        let drift = cosine_distance(centroid.as_slice(), embedding);
        if drift > 0.6 {
            flags.push(AnomalyFlag::TopicDrift);
            score += drift * 0.25;
        }
    }

    // 5) Model switching within session
    if snapshot.models_used_this_session.len() >= 3 {
        let unique_models = snapshot
            .models_used_this_session
            .iter()
            .collect::<HashSet<_>>();
        if unique_models.len() >= 3 {
            flags.push(AnomalyFlag::ModelSwitch);
            score += 0.15;
        }
    }

    // 6) System prompt change mid-session
    if let (Some(prev_hash), Some(curr_hash)) = (
        snapshot.last_system_prompt_hash.as_deref(),
        current.system_prompt_hash,
    ) {
        if prev_hash != curr_hash && request_count_this_hour > 3 {
            flags.push(AnomalyFlag::UnusualSystemPromptChange);
            score += 0.20;
        }
    }

    // 7) Exfiltration-like shape — only when actual output tokens are known
    if let Some(output_tokens) = current.output_tokens {
        if current.input_tokens < 50 && output_tokens > 2_000 {
            score += 0.25;
        }
    }

    // 8) Tool depth spike
    if current.tool_call_depth > snapshot.max_tool_depth_seen.saturating_add(3) {
        flags.push(AnomalyFlag::ToolCallDepthSpike);
        score += 0.15;
    }

    // 9) Agent loop pattern
    let has_rapid_fire = flags.contains(&AnomalyFlag::RapidFireRequests);
    let high_volume = request_count_this_hour > 50;
    let has_tools = current.tool_call_depth > 0 || current.has_tool_definitions;
    let multi_model = snapshot.models_used_this_session.len() >= 2;

    if (has_rapid_fire || high_volume) && has_tools && multi_model {
        flags.push(AnomalyFlag::AgentLoopPattern);
    }

    dedupe_flags(&mut flags);

    AnomalyOutput {
        score: score.min(1.0),
        flags,
    }
}

fn cosine_distance(left: &[f32], right: &[f32]) -> f32 {
    if left.is_empty() || left.len() != right.len() {
        return 0.0;
    }

    let mut dot = 0.0f32;
    let mut left_norm = 0.0f32;
    let mut right_norm = 0.0f32;

    for (l, r) in left.iter().zip(right.iter()) {
        dot += l * r;
        left_norm += l * l;
        right_norm += r * r;
    }

    if left_norm <= 1e-9 || right_norm <= 1e-9 {
        return 0.0;
    }

    let cosine = dot / (left_norm.sqrt() * right_norm.sqrt());
    (1.0 - cosine).clamp(0.0, 1.0)
}

fn dedupe_flags(flags: &mut Vec<AnomalyFlag>) {
    let mut unique = Vec::new();
    flags.retain(|flag| {
        if unique.contains(flag) {
            false
        } else {
            unique.push(*flag);
            true
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline_session() -> SessionSnapshot {
        SessionSnapshot {
            session_token_total: 10_000,
            session_token_p14d_avg: 100.0,
            request_count_this_hour: 8,
            credential_alerts_24h: 0,
            topic_cluster_ids_seen: vec![1, 2],
            models_used_this_session: vec!["gpt-4o-mini".to_string()],
            last_system_prompt_hash: Some("sys-prev".to_string()),
            max_tool_depth_seen: 2,
            request_count: 8,
            total_tokens: 10_000,
            total_cost_usd: 0.5,
            credential_alerts: 0,
            embedding_centroid: Some(vec![1.0, 0.0]),
            prior_semantic_hashes: Vec::new(),
            last_model: Some("gpt-4o-mini".to_string()),
            current_request_timestamp: 10_000,
            last_request_timestamp: Some(9_000),
            ..SessionSnapshot::default()
        }
    }

    fn baseline_normalized() -> soth_core::NormalizedRequest {
        soth_core::NormalizedRequest {
            parse_confidence: soth_core::ParseConfidence::Full,
            parser_id: "test-parser".to_string(),
            schema_version: "1".to_string(),
            parse_warnings: Vec::new(),
            is_ai_call: true,
            provider: "openai".to_string(),
            model: Some("gpt-4o-mini".to_string()),
            endpoint_type: soth_core::EndpointType::ChatCompletion,
            api_version: None,
            system_prompt_hash: Some("sys-prev".to_string()),
            system_prompt_token_estimate: None,
            user_content_hash: "u-hash".to_string(),
            user_content_token_estimate: 100,
            conversation_hash: "c-hash".to_string(),
            conversation_turn: Some(2),
            has_tool_definitions: false,
            tool_definition_hash: None,
            temperature: None,
            max_tokens: Some(128),
            stream: false,
            top_p: None,
            stop_sequences: Vec::new(),
            estimated_input_tokens: 100,
            estimated_cost_usd: 0.01,
            parse_source: soth_core::ParseSource::Rest {
                provider: soth_core::DetectedProvider::OpenAi,
            },
            canonical_cache_key: "cache-key".to_string(),
            format_metadata: soth_core::FormatMetadata::Unknown { method: String::new(), path: String::new() },
            has_structured_output: false,
            has_tool_results: false,
            estimated_output_tokens: None,
            user_prompt: None,
        }
    }

    fn credential_artifact() -> soth_core::SensitiveArtifact {
        soth_core::SensitiveArtifact {
            kind: soth_core::ArtifactKind::ApiKey {
                provider: Some(soth_core::DetectedProvider::OpenAi),
            },
            severity: soth_core::ArtifactSeverity::High,
            location: soth_core::ArtifactLocation::UserContent {
                turn: 0,
                char_offset: 0,
            },
            commitment: None,
            redacted_hint: None,
        }
    }

    fn run_stage(
        embedding: Option<Vec<f32>>,
        normalized: soth_core::NormalizedRequest,
        artifacts: Vec<soth_core::SensitiveArtifact>,
        session: Option<SessionSnapshot>,
    ) -> AnomalyOutput {
        let cluster = ClusterOutput::default();
        let (output, _) = run(
            embedding.as_deref(),
            &cluster,
            &normalized,
            &artifacts,
            session.as_ref(),
        );
        output
    }

    #[test]
    fn no_session_returns_default_output() {
        let output = run_stage(
            Some(vec![1.0, 0.0]),
            baseline_normalized(),
            Vec::new(),
            None,
        );
        assert_eq!(output.score, 0.0);
        assert!(output.flags.is_empty());
    }

    #[test]
    fn token_burst_high_ratio_scores_and_flags() {
        let mut normalized = baseline_normalized();
        normalized.estimated_input_tokens = 700;

        let output = run_stage(
            Some(vec![1.0, 0.0]),
            normalized,
            Vec::new(),
            Some(baseline_session()),
        );

        assert!(output.flags.contains(&AnomalyFlag::TokenBurst));
        assert!(output.score >= 0.30);
    }

    #[test]
    fn credential_burst_scores_and_flags() {
        let mut session = baseline_session();
        session.credential_alerts_24h = 2;

        let output = run_stage(
            Some(vec![1.0, 0.0]),
            baseline_normalized(),
            vec![credential_artifact()],
            Some(session),
        );

        assert!(output.flags.contains(&AnomalyFlag::CredentialBurst));
        assert!(output.score >= 0.40);
    }

    #[test]
    fn rapid_fire_scores_and_flags() {
        let mut session = baseline_session();
        session.request_count_this_hour = 42;
        session.last_request_timestamp = Some(9_700);
        session.current_request_timestamp = 10_000;

        let output = run_stage(
            Some(vec![1.0, 0.0]),
            baseline_normalized(),
            Vec::new(),
            Some(session),
        );

        assert!(output.flags.contains(&AnomalyFlag::RapidFireRequests));
        assert!(output.score >= 0.20);
    }

    #[test]
    fn topic_drift_scores_and_flags() {
        let session = baseline_session();
        let output = run_stage(
            Some(vec![0.0, 1.0]),
            baseline_normalized(),
            Vec::new(),
            Some(session),
        );

        assert!(output.flags.contains(&AnomalyFlag::TopicDrift));
        assert!(output.score > 0.0);
    }

    #[test]
    fn model_switch_scores_and_flags() {
        let mut session = baseline_session();
        session.models_used_this_session = vec![
            "gpt-4o-mini".to_string(),
            "claude-3-haiku-20240307".to_string(),
            "gemini-1.5-pro".to_string(),
        ];

        let output = run_stage(
            Some(vec![1.0, 0.0]),
            baseline_normalized(),
            Vec::new(),
            Some(session),
        );

        assert!(output.flags.contains(&AnomalyFlag::ModelSwitch));
        assert!(output.score >= 0.15);
    }

    #[test]
    fn unusual_system_prompt_change_scores_and_flags() {
        let mut session = baseline_session();
        session.request_count_this_hour = 10;
        session.last_system_prompt_hash = Some("sys-old".to_string());

        let mut normalized = baseline_normalized();
        normalized.system_prompt_hash = Some("sys-new".to_string());

        let output = run_stage(Some(vec![1.0, 0.0]), normalized, Vec::new(), Some(session));

        assert!(output
            .flags
            .contains(&AnomalyFlag::UnusualSystemPromptChange));
        assert!(output.score >= 0.20);
    }

    #[test]
    fn exfiltration_shape_adds_score_without_new_flag() {
        let mut normalized = baseline_normalized();
        normalized.estimated_input_tokens = 30;
        normalized.estimated_output_tokens = Some(3_500);

        let output = run_stage(
            Some(vec![1.0, 0.0]),
            normalized,
            Vec::new(),
            Some(baseline_session()),
        );

        assert_eq!(output.flags.len(), 0);
        assert!(output.score >= 0.25);
    }

    #[test]
    fn tool_depth_spike_scores_and_flags() {
        let mut session = baseline_session();
        session.max_tool_depth_seen = 2;

        let mut normalized = baseline_normalized();
        normalized.conversation_turn = Some(7);

        let output = run_stage(Some(vec![1.0, 0.0]), normalized, Vec::new(), Some(session));

        assert!(output.flags.contains(&AnomalyFlag::ToolCallDepthSpike));
        assert!(output.score >= 0.15);
    }

    #[test]
    fn score_clamps_to_one() {
        let mut session = baseline_session();
        session.credential_alerts_24h = 5;
        session.request_count_this_hour = 99;
        session.last_request_timestamp = Some(9_900);
        session.current_request_timestamp = 10_000;
        session.models_used_this_session = vec!["a".to_string(), "b".to_string(), "c".to_string()];

        let mut normalized = baseline_normalized();
        normalized.estimated_input_tokens = 2_000;
        normalized.conversation_turn = Some(20);
        normalized.max_tokens = Some(5_000);
        normalized.system_prompt_hash = Some("other".to_string());

        let output = run_stage(
            Some(vec![0.0, 1.0]),
            normalized,
            vec![credential_artifact()],
            Some(session),
        );

        assert!((output.score - 1.0).abs() < f32::EPSILON);
    }
}
