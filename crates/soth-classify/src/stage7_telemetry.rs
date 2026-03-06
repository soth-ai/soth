use rand::RngCore;
use std::time::Instant;
use uuid::Uuid;

use soth_core::{
    ArtifactKind, ClassificationFlag, DataSource, ImportCategory, ProgrammingLanguage,
    RequestMethod, RoutingReason, SensitiveCodeFlags, TelemetryEvent, TelemetryPolicyKind,
};

use crate::stage2_cluster::ClusterOutput;
use crate::stage3_usecase::UsecaseOutput;
use crate::stage4_volatility::VolatilityOutput;
use crate::stage5_anomaly::AnomalyOutput;
use crate::stage6_policy::PolicyOutput;

#[derive(Debug, Clone)]
pub(crate) struct TelemetryOutput {
    pub event: TelemetryEvent,
    pub nonce: [u8; 32],
    pub latency_us: u64,
}

pub(crate) fn run(
    detect_result: &soth_core::DetectResult,
    proxy_ctx: &soth_core::ProxyContext,
    cluster: &ClusterOutput,
    usecase: &UsecaseOutput,
    volatility: &VolatilityOutput,
    anomaly: &AnomalyOutput,
    policy: &PolicyOutput,
) -> TelemetryOutput {
    let started = Instant::now();

    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);

    let classifications = build_classification_flags(detect_result, anomaly, policy);
    let languages = extract_languages(&detect_result.artifacts);

    let event = TelemetryEvent {
        event_id: Uuid::new_v4(),
        timestamp_epoch_ms: proxy_ctx
            .session_snapshot
            .as_ref()
            .map(|session| session.current_request_timestamp)
            .unwrap_or(0),
        connection_id: None,
        provider: detect_result.normalized.provider,
        model: detect_result.normalized.model.clone(),
        endpoint_type: detect_result.normalized.endpoint_type,
        parse_confidence: detect_result.confidence,
        parse_source: detect_result.parse_source,
        capture_mode: detect_result.capture_mode,
        use_case: usecase.label,
        volatility_class: volatility.class,
        cache_level: None,
        routing_reason: derive_routing_reason(&policy.decision.kind),
        request_method: proxy_ctx.request_method.unwrap_or(RequestMethod::Post),
        estimated_input_tokens: Some(detect_result.normalized.estimated_input_tokens),
        estimated_output_tokens: None,
        estimated_cost_usd: Some(detect_result.normalized.estimated_cost_usd as f32),
        process_resolution: Some(proxy_ctx.process_resolution.clone()),
        traffic_classification: Some(proxy_ctx.traffic_classification),
        languages,
        import_categories: Vec::<ImportCategory>::new(),
        classification_flags: classifications,
        anomaly_flags: anomaly.flags.clone(),
        anomaly_score: Some(anomaly.score),
        policy_kind: Some(map_policy_kind(&policy.decision.kind)),
        policy_rule_id: policy.decision.matched_rule.as_ref().map(|r| r.rule_id.clone()),
        bundle_trust_level: None,
        sensitive_code_flags: build_sensitive_code_flags(&detect_result.artifacts),
        session_key_hash: proxy_ctx
            .session_snapshot
            .as_ref()
            .map(|s| s.session_key_hash.clone())
            .unwrap_or_default(),
        is_prefix_repeat: detect_result.is_prefix_repeat,
        is_code_context_repeat: detect_result.is_repeated_code_context,
        novel_token_count: detect_result.novel_token_count,
        repeated_token_count: detect_result.repeated_token_count,
        first_step_event_id: None,
        original_event_id: None,
        prefix_hash: detect_result.prefix_hash.clone(),
        agent_step_number: None,
        is_historical: false,
        data_source: DataSource::LiveProxy,
        original_timestamp: None,
        topic_cluster_id: cluster.topic_cluster_id,
        semantic_hash: cluster.semantic_hash.clone(),
        is_semantic_collision: cluster.is_semantic_collision,
        endpoint_hash: proxy_ctx.endpoint_hash.clone(),
    };

    TelemetryOutput {
        event,
        nonce,
        latency_us: started.elapsed().as_micros() as u64,
    }
}

fn build_classification_flags(
    detect_result: &soth_core::DetectResult,
    anomaly: &AnomalyOutput,
    policy: &PolicyOutput,
) -> Vec<ClassificationFlag> {
    let mut flags = Vec::new();

    let has_code = detect_result
        .artifacts
        .iter()
        .any(|artifact| matches!(artifact.kind, ArtifactKind::CodeBlock { .. }));
    if has_code {
        flags.push(ClassificationFlag::CodeDetected);
    }

    let has_credentials = detect_result
        .artifacts
        .iter()
        .any(|artifact| artifact.is_credential());
    if has_credentials {
        flags.push(ClassificationFlag::CredentialDetected);
    }

    if anomaly.score > 0.7 {
        flags.push(ClassificationFlag::HighAnomaly);
    }

    if !matches!(policy.decision.kind, soth_core::PolicyDecisionKind::Allow) {
        flags.push(ClassificationFlag::PolicyTriggered);
    }

    flags
}

fn build_sensitive_code_flags(artifacts: &[soth_core::SensitiveArtifact]) -> SensitiveCodeFlags {
    let mut flags = SensitiveCodeFlags::default();
    for artifact in artifacts {
        match &artifact.kind {
            ArtifactKind::PrivateKey => {
                flags.private_key_detected = true;
                flags.hardcoded_secret_detected = true;
                flags.credential_pattern_detected = true;
            }
            ArtifactKind::CodeBlock { .. } => {
                flags.auth_logic_detected = true;
            }
            ArtifactKind::ApiKey { .. }
            | ArtifactKind::Jwt
            | ArtifactKind::HexKey
            | ArtifactKind::ConnectionString
            | ArtifactKind::UnknownCredential => {
                flags.credential_pattern_detected = true;
                flags.hardcoded_secret_detected = true;
            }
            ArtifactKind::OrgPattern { pattern_id } => {
                flags.org_pattern_matches.push(pattern_id.to_string());
            }
            ArtifactKind::AuthLogic => {
                flags.auth_logic_detected = true;
            }
            ArtifactKind::CryptoOperation => {
                flags.crypto_operations_detected = true;
            }
        }
    }
    flags
}

fn derive_routing_reason(kind: &soth_core::PolicyDecisionKind) -> Option<RoutingReason> {
    match kind {
        soth_core::PolicyDecisionKind::Reroute { .. } => Some(RoutingReason::PolicyReroute),
        _ => None,
    }
}

fn map_policy_kind(kind: &soth_core::PolicyDecisionKind) -> TelemetryPolicyKind {
    match kind {
        soth_core::PolicyDecisionKind::Allow => TelemetryPolicyKind::Allow,
        soth_core::PolicyDecisionKind::Block { .. } => TelemetryPolicyKind::Block,
        soth_core::PolicyDecisionKind::Redact { .. } => TelemetryPolicyKind::Redact,
        soth_core::PolicyDecisionKind::Reroute { .. } => TelemetryPolicyKind::Reroute,
        soth_core::PolicyDecisionKind::Flag { .. } => TelemetryPolicyKind::Flag,
    }
}

fn extract_languages(artifacts: &[soth_core::SensitiveArtifact]) -> Vec<ProgrammingLanguage> {
    let mut out = Vec::new();

    for artifact in artifacts {
        if let ArtifactKind::CodeBlock { language } = &artifact.kind {
            let mapped = match language.to_ascii_lowercase().as_str() {
                "python" => ProgrammingLanguage::Python,
                "javascript" => ProgrammingLanguage::JavaScript,
                "typescript" => ProgrammingLanguage::TypeScript,
                "rust" => ProgrammingLanguage::Rust,
                "go" => ProgrammingLanguage::Go,
                "java" => ProgrammingLanguage::Java,
                "cpp" | "c++" => ProgrammingLanguage::Cpp,
                "c" => ProgrammingLanguage::C,
                "csharp" | "c#" => ProgrammingLanguage::CSharp,
                "ruby" => ProgrammingLanguage::Ruby,
                "php" => ProgrammingLanguage::Php,
                "swift" => ProgrammingLanguage::Swift,
                "kotlin" => ProgrammingLanguage::Kotlin,
                "sql" => ProgrammingLanguage::Sql,
                "shell" | "bash" | "zsh" => ProgrammingLanguage::Shell,
                "terraform" => ProgrammingLanguage::Terraform,
                "solidity" => ProgrammingLanguage::Solidity,
                "yaml" | "yml" => ProgrammingLanguage::Yaml,
                "json" => ProgrammingLanguage::Json,
                _ => ProgrammingLanguage::Unknown,
            };

            if !out.contains(&mapped) {
                out.push(mapped);
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stage2_cluster::ClusterOutput;
    use crate::stage3_usecase::UsecaseOutput;
    use crate::stage4_volatility::VolatilityOutput;
    use crate::stage5_anomaly::AnomalyOutput;
    use crate::stage6_policy::PolicyOutput;

    fn detect_result() -> soth_core::DetectResult {
        soth_core::DetectResult {
            normalized: soth_core::NormalizedRequest {
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
                user_content_token_estimate: 321,
                conversation_hash: "c-hash".to_string(),
                conversation_turn: Some(1),
                has_tool_definitions: false,
                tool_definition_hash: None,
                temperature: None,
                max_tokens: None,
                stream: false,
                top_p: None,
                stop_sequences: Vec::new(),
                estimated_input_tokens: 321,
                estimated_cost_usd: 0.045,
                parse_source: soth_core::ParseSource::Rest {
                    provider: soth_core::DetectedProvider::OpenAi,
                },
                canonical_cache_key: "cache-key".to_string(),
                format_metadata: soth_core::FormatMetadata::Unknown,
            },
            artifacts: Vec::new(),
            capture_mode: soth_core::CaptureMode::MetadataOnly,
            parse_source: soth_core::ParseSource::Rest {
                provider: soth_core::DetectedProvider::OpenAi,
            },
            confidence: soth_core::ParseConfidence::Full,
            detect_latency_us: 0,
            warnings: Vec::new(),
            session_mutations: soth_core::SessionMutations::default(),
            is_prefix_repeat: false,
            novel_token_count: 0,
            repeated_token_count: 0,
            novel_tail_start_idx: None,
            prefix_hash: None,
            is_repeated_code_context: false,
            ast_normalized_hash: None,
            first_blob_event_id: None,
        }
    }

    fn proxy_ctx_with_time(timestamp: i64) -> soth_core::ProxyContext {
        let mut session = soth_core::SessionSnapshot::default();
        session.current_request_timestamp = timestamp;
        soth_core::ProxyContext {
            org_id: "org".to_string(),
            user_id_hmac: "user".to_string(),
            team_id: "team".to_string(),
            device_id_hash: "device".to_string(),
            endpoint_hash: "endpoint".to_string(),
            process_resolution: soth_core::ProcessResolution {
                match_kind: soth_core::ProcessMatchKind::Unknown,
                app_type: soth_core::AppType::Unknown,
                capture_mode: Some(soth_core::CaptureMode::MetadataOnly),
                process_name: None,
                bundle_id: None,
            },
            capture_mode: soth_core::CaptureMode::MetadataOnly,
            matched_provider: Some("openai".to_string()),
            matched_application: None,
            traffic_classification: soth_core::TrafficClassification::Other,
            classification_source: soth_core::ClassificationSource::Proxy,
            session_snapshot: Some(session),
            request_method: None,
        }
    }

    fn usecase_output() -> UsecaseOutput {
        UsecaseOutput {
            label: soth_core::UseCaseLabel::CodeGeneration,
            confidence: 0.8,
            secondary_label: Some(soth_core::UseCaseLabel::CodeReview),
            complexity_score: 4,
        }
    }

    fn policy_allow() -> PolicyOutput {
        PolicyOutput {
            decision: soth_core::PolicyDecision {
                kind: soth_core::PolicyDecisionKind::Allow,
                matched_rule: None,
                warnings: Vec::new(),
                eval_latency_us: 0,
            },
        }
    }

    #[test]
    fn telemetry_maps_core_fields_and_timestamp() {
        let detect = detect_result();
        let proxy = proxy_ctx_with_time(1_700_000_000_111);
        let cluster = ClusterOutput::default();
        let usecase = usecase_output();
        let volatility = VolatilityOutput {
            class: soth_core::VolatilityClass::Dynamic,
            dynamic_fraction: 0.45,
            prefix_repeat_signature: Some("abc123".to_string()),
        };
        let anomaly = AnomalyOutput {
            score: 0.2,
            flags: Vec::new(),
        };
        let policy = policy_allow();

        let out = run(
            &detect,
            &proxy,
            &cluster,
            &usecase,
            &volatility,
            &anomaly,
            &policy,
        );

        assert_eq!(out.event.timestamp_epoch_ms, 1_700_000_000_111);
        assert_eq!(out.event.provider, soth_core::DetectedProvider::OpenAi);
        assert_eq!(
            out.event.endpoint_type,
            soth_core::EndpointType::ChatCompletion
        );
        assert_eq!(out.event.use_case, soth_core::UseCaseLabel::CodeGeneration);
        assert_eq!(
            out.event.volatility_class,
            soth_core::VolatilityClass::Dynamic
        );
        assert_eq!(out.event.estimated_input_tokens, Some(321));
        assert_eq!(out.event.estimated_cost_usd, Some(0.045));
        assert_eq!(out.event.request_method, soth_core::RequestMethod::Post);
        assert!(out.nonce.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn telemetry_sets_classification_flags_for_anomaly_policy_code_and_credentials() {
        let mut detect = detect_result();
        detect.artifacts = vec![
            soth_core::SensitiveArtifact {
                kind: soth_core::ArtifactKind::CodeBlock {
                    language: "rust".to_string(),
                },
                severity: soth_core::ArtifactSeverity::Low,
                location: soth_core::ArtifactLocation::UserContent {
                    turn: 0,
                    char_offset: 0,
                },
            },
            soth_core::SensitiveArtifact {
                kind: soth_core::ArtifactKind::ApiKey {
                    provider: Some(soth_core::DetectedProvider::OpenAi),
                },
                severity: soth_core::ArtifactSeverity::High,
                location: soth_core::ArtifactLocation::UserContent {
                    turn: 0,
                    char_offset: 0,
                },
            },
        ];

        let proxy = proxy_ctx_with_time(1);
        let cluster = ClusterOutput::default();
        let usecase = usecase_output();
        let volatility = VolatilityOutput::default();
        let anomaly = AnomalyOutput {
            score: 0.9,
            flags: vec![soth_core::AnomalyFlag::TopicDrift],
        };
        let policy = PolicyOutput {
            decision: soth_core::PolicyDecision {
                kind: soth_core::PolicyDecisionKind::Block {
                    status: 403,
                    message: "blocked".to_string(),
                },
                matched_rule: None,
                warnings: Vec::new(),
                eval_latency_us: 0,
            },
        };

        let out = run(
            &detect,
            &proxy,
            &cluster,
            &usecase,
            &volatility,
            &anomaly,
            &policy,
        );

        assert!(out
            .event
            .classification_flags
            .contains(&ClassificationFlag::CodeDetected));
        assert!(out
            .event
            .classification_flags
            .contains(&ClassificationFlag::CredentialDetected));
        assert!(out
            .event
            .classification_flags
            .contains(&ClassificationFlag::HighAnomaly));
        assert!(out
            .event
            .classification_flags
            .contains(&ClassificationFlag::PolicyTriggered));
    }

    #[test]
    fn telemetry_deduplicates_detected_languages() {
        let mut detect = detect_result();
        detect.artifacts = vec![
            soth_core::SensitiveArtifact {
                kind: soth_core::ArtifactKind::CodeBlock {
                    language: "rust".to_string(),
                },
                severity: soth_core::ArtifactSeverity::Low,
                location: soth_core::ArtifactLocation::UserContent {
                    turn: 0,
                    char_offset: 0,
                },
            },
            soth_core::SensitiveArtifact {
                kind: soth_core::ArtifactKind::CodeBlock {
                    language: "Rust".to_string(),
                },
                severity: soth_core::ArtifactSeverity::Low,
                location: soth_core::ArtifactLocation::UserContent {
                    turn: 1,
                    char_offset: 0,
                },
            },
        ];

        let out = run(
            &detect,
            &proxy_ctx_with_time(2),
            &ClusterOutput::default(),
            &usecase_output(),
            &VolatilityOutput::default(),
            &AnomalyOutput::default(),
            &policy_allow(),
        );

        let rust_count = out
            .event
            .languages
            .iter()
            .filter(|lang| **lang == ProgrammingLanguage::Rust)
            .count();
        assert_eq!(rust_count, 1);
    }

    #[test]
    fn telemetry_sensitive_code_flags_mark_private_key() {
        let mut detect = detect_result();
        detect.artifacts = vec![soth_core::SensitiveArtifact {
            kind: soth_core::ArtifactKind::PrivateKey,
            severity: soth_core::ArtifactSeverity::Critical,
            location: soth_core::ArtifactLocation::SystemPrompt { char_offset: 0 },
        }];

        let out = run(
            &detect,
            &proxy_ctx_with_time(3),
            &ClusterOutput::default(),
            &usecase_output(),
            &VolatilityOutput::default(),
            &AnomalyOutput::default(),
            &policy_allow(),
        );

        assert!(out.event.sensitive_code_flags.private_key_detected);
        assert!(out.event.sensitive_code_flags.hardcoded_secret_detected);
        assert!(out.event.sensitive_code_flags.credential_pattern_detected);
    }
}
