use std::time::Instant;

use soth_core::{AnomalyFlag, SessionSnapshot};

use crate::stage2_cluster::ClusterOutput;
use crate::traits::{AnomalyScorer, AnomalySignals};

#[derive(Debug, Clone, Default)]
pub(crate) struct AnomalyOutput {
    pub score: f32,
    pub flags: Vec<AnomalyFlag>,
}

pub(crate) fn run(
    embedding: Option<&[f32]>,
    _cluster: &ClusterOutput,
    normalized: &soth_core::NormalizedRequest,
    artifacts: &[soth_core::SensitiveArtifact],
    session: Option<&SessionSnapshot>,
    scorer: &dyn AnomalyScorer,
) -> (AnomalyOutput, u64) {
    let started = Instant::now();

    let Some(session) = session else {
        return (
            AnomalyOutput::default(),
            started.elapsed().as_micros() as u64,
        );
    };

    let signals = derive_signals(embedding, normalized, artifacts, session);
    let model_score = scorer.score(&signals).clamp(0.0, 1.0);
    let model_flags = scorer.flags(&signals);

    let (heuristic_score, heuristic_flags) = heuristic_score(&signals);

    let mut flags = Vec::new();
    for flag in model_flags.into_iter().chain(heuristic_flags.into_iter()) {
        if !flags.contains(&flag) {
            flags.push(flag);
        }
    }

    (
        AnomalyOutput {
            score: model_score.max(heuristic_score).clamp(0.0, 1.0),
            flags,
        },
        started.elapsed().as_micros() as u64,
    )
}

fn derive_signals(
    embedding: Option<&[f32]>,
    normalized: &soth_core::NormalizedRequest,
    artifacts: &[soth_core::SensitiveArtifact],
    session: &SessionSnapshot,
) -> AnomalySignals {
    let topic_drift_score = match (embedding, session.embedding_centroid.as_ref()) {
        (Some(vec), Some(centroid)) if vec.len() == centroid.len() => {
            let dot = vec
                .iter()
                .zip(centroid.iter())
                .map(|(left, right)| left * right)
                .sum::<f32>();
            (1.0 - dot).clamp(0.0, 1.0)
        }
        _ => 0.0,
    };

    let credential_hits = artifacts
        .iter()
        .filter(|artifact| artifact.is_credential())
        .count() as u32;
    let credential_burst = session.credential_alerts + credential_hits >= 3;

    let avg_tokens = if session.request_count > 5 {
        session.total_tokens as f32 / session.request_count as f32
    } else {
        0.0
    };
    let token_burst_ratio = if avg_tokens > 0.0 {
        normalized.user_content_token_estimate as f32 / avg_tokens
    } else {
        1.0
    };

    let model_switched = normalized
        .model
        .as_deref()
        .zip(session.last_model.as_deref())
        .map(|(current, last)| current != last)
        .unwrap_or(false);

    let inter_request_ms = session
        .last_request_timestamp
        .map(|last| (session.current_request_timestamp - last).unsigned_abs());

    AnomalySignals {
        topic_drift_score,
        credential_burst,
        token_burst_ratio,
        model_switched,
        inter_request_ms,
        tool_call_depth: normalized.conversation_turn.unwrap_or(0),
        session_request_count: session.request_count,
    }
}

fn heuristic_score(signals: &AnomalySignals) -> (f32, Vec<AnomalyFlag>) {
    let mut score = 0.0f32;
    let mut flags = Vec::new();

    if signals.topic_drift_score > 0.6 {
        flags.push(AnomalyFlag::TopicDrift);
        score += signals.topic_drift_score * 0.3;
    }
    if signals.credential_burst {
        flags.push(AnomalyFlag::CredentialBurst);
        score += 0.4;
    }
    if signals.token_burst_ratio > 3.0 {
        flags.push(AnomalyFlag::TokenBurst);
        score += 0.2;
    }
    if signals.model_switched && signals.session_request_count > 0 {
        flags.push(AnomalyFlag::ModelSwitch);
        score += 0.1;
    }
    if signals.inter_request_ms.map(|ms| ms < 500).unwrap_or(false)
        && signals.session_request_count > 3
    {
        flags.push(AnomalyFlag::AgentLoopPattern);
        score += 0.15;
    }
    if signals.tool_call_depth > 10 {
        flags.push(AnomalyFlag::ToolCallDepthSpike);
        score += 0.1;
    }

    (score.clamp(0.0, 1.0), flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedScorer {
        score: f32,
        flags: Vec<AnomalyFlag>,
    }

    impl AnomalyScorer for FixedScorer {
        fn score(&self, _signals: &AnomalySignals) -> f32 {
            self.score
        }

        fn flags(&self, _signals: &AnomalySignals) -> Vec<AnomalyFlag> {
            self.flags.clone()
        }
    }

    fn baseline_session() -> SessionSnapshot {
        SessionSnapshot {
            total_tokens: 1_000,
            total_cost_usd: 0.1,
            request_count: 10,
            credential_alerts: 0,
            topic_cluster_ids_seen: Vec::new(),
            embedding_centroid: Some(vec![1.0, 0.0]),
            prior_semantic_hashes: Vec::new(),
            last_model: Some("gpt-4o-mini".to_string()),
            current_request_timestamp: 10_000,
            last_request_timestamp: Some(9_000),
            session_start: Some(1_000),
        }
    }

    fn baseline_normalized() -> soth_core::NormalizedRequest {
        soth_core::NormalizedRequest {
            parse_confidence: soth_core::ParseConfidence::Full,
            parser_id: "test-parser".to_string(),
            schema_version: "1".to_string(),
            parse_warnings: Vec::new(),
            is_ai_call: true,
            provider: soth_core::DetectedProvider::OpenAi,
            model: Some("gpt-4o-mini".to_string()),
            endpoint_type: soth_core::EndpointType::ChatCompletion,
            api_version: None,
            system_prompt_hash: None,
            system_prompt_token_estimate: None,
            user_content_hash: "u-hash".to_string(),
            user_content_token_estimate: 100,
            conversation_hash: "c-hash".to_string(),
            conversation_turn: Some(1),
            has_tool_definitions: false,
            tool_definition_hash: None,
            temperature: None,
            max_tokens: None,
            stream: false,
            top_p: None,
            stop_sequences: Vec::new(),
            estimated_input_tokens: 100,
            estimated_cost_usd: 0.01,
            parse_source: soth_core::ParseSource::Rest {
                provider: soth_core::DetectedProvider::OpenAi,
            },
            canonical_cache_key: "cache-key".to_string(),
            format_metadata: soth_core::FormatMetadata::Unknown,
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
        }
    }

    fn run_flags(
        embedding: Option<Vec<f32>>,
        normalized: soth_core::NormalizedRequest,
        artifacts: Vec<soth_core::SensitiveArtifact>,
        session: SessionSnapshot,
        scorer: &dyn AnomalyScorer,
    ) -> AnomalyOutput {
        let cluster = ClusterOutput::default();
        let (output, _) = run(
            embedding.as_deref(),
            &cluster,
            &normalized,
            &artifacts,
            Some(&session),
            scorer,
        );
        output
    }

    #[test]
    fn topic_drift_triggers_in_isolation() {
        let session = baseline_session();
        let normalized = baseline_normalized();
        let scorer = FixedScorer {
            score: 0.0,
            flags: Vec::new(),
        };

        let out = run_flags(
            Some(vec![0.0, 1.0]),
            normalized,
            Vec::new(),
            session,
            &scorer,
        );

        assert_eq!(out.flags, vec![AnomalyFlag::TopicDrift]);
    }

    #[test]
    fn credential_burst_triggers_in_isolation() {
        let mut session = baseline_session();
        session.credential_alerts = 2;
        let normalized = baseline_normalized();
        let scorer = FixedScorer {
            score: 0.0,
            flags: Vec::new(),
        };

        let out = run_flags(
            Some(vec![1.0, 0.0]),
            normalized,
            vec![credential_artifact()],
            session,
            &scorer,
        );

        assert_eq!(out.flags, vec![AnomalyFlag::CredentialBurst]);
    }

    #[test]
    fn token_burst_triggers_in_isolation() {
        let session = baseline_session();
        let mut normalized = baseline_normalized();
        normalized.user_content_token_estimate = 400;
        let scorer = FixedScorer {
            score: 0.0,
            flags: Vec::new(),
        };

        let out = run_flags(
            Some(vec![1.0, 0.0]),
            normalized,
            Vec::new(),
            session,
            &scorer,
        );

        assert_eq!(out.flags, vec![AnomalyFlag::TokenBurst]);
    }

    #[test]
    fn model_switch_triggers_in_isolation() {
        let session = baseline_session();
        let mut normalized = baseline_normalized();
        normalized.model = Some("claude-3-5-sonnet".to_string());
        let scorer = FixedScorer {
            score: 0.0,
            flags: Vec::new(),
        };

        let out = run_flags(
            Some(vec![1.0, 0.0]),
            normalized,
            Vec::new(),
            session,
            &scorer,
        );

        assert_eq!(out.flags, vec![AnomalyFlag::ModelSwitch]);
    }

    #[test]
    fn agent_loop_pattern_triggers_in_isolation() {
        let mut session = baseline_session();
        session.request_count = 4;
        session.total_tokens = 400;
        session.last_request_timestamp = Some(9_900);
        let normalized = baseline_normalized();
        let scorer = FixedScorer {
            score: 0.0,
            flags: Vec::new(),
        };

        let out = run_flags(
            Some(vec![1.0, 0.0]),
            normalized,
            Vec::new(),
            session,
            &scorer,
        );

        assert_eq!(out.flags, vec![AnomalyFlag::AgentLoopPattern]);
    }

    #[test]
    fn tool_call_depth_spike_triggers_in_isolation() {
        let session = baseline_session();
        let mut normalized = baseline_normalized();
        normalized.conversation_turn = Some(11);
        let scorer = FixedScorer {
            score: 0.0,
            flags: Vec::new(),
        };

        let out = run_flags(
            Some(vec![1.0, 0.0]),
            normalized,
            Vec::new(),
            session,
            &scorer,
        );

        assert_eq!(out.flags, vec![AnomalyFlag::ToolCallDepthSpike]);
    }

    #[test]
    fn score_is_clamped_and_flags_are_deduplicated() {
        let session = baseline_session();
        let mut normalized = baseline_normalized();
        normalized.user_content_token_estimate = 400;
        let scorer = FixedScorer {
            score: 10.0,
            flags: vec![AnomalyFlag::TokenBurst],
        };

        let out = run_flags(
            Some(vec![1.0, 0.0]),
            normalized,
            Vec::new(),
            session,
            &scorer,
        );

        assert_eq!(out.score, 1.0);
        assert_eq!(out.flags, vec![AnomalyFlag::TokenBurst]);
    }
}
