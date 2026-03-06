use std::time::Instant;

use soth_core::{
    ClassificationSource, DeploymentModel, PolicyContext, PolicyDecision, SemanticPolicyContext,
};

use crate::stage2_cluster::ClusterOutput;
use crate::stage3_usecase::UsecaseOutput;
use crate::stage4_volatility::VolatilityOutput;
use crate::stage5_anomaly::AnomalyOutput;

#[derive(Debug, Clone)]
pub(crate) struct PolicyOutput {
    pub decision: PolicyDecision,
}

pub(crate) fn run(
    detect_result: &soth_core::DetectResult,
    proxy_ctx: &soth_core::ProxyContext,
    usecase: &UsecaseOutput,
    anomaly: &AnomalyOutput,
    volatility: &VolatilityOutput,
    cluster: &ClusterOutput,
    policy_bundle: &soth_policy::PolicyBundle,
) -> (PolicyOutput, u64) {
    let started = Instant::now();

    let skip_org_rules = matches!(
        detect_result.confidence,
        soth_core::ParseConfidence::Heuristic
    );

    let context = PolicyContext {
        process_resolution: proxy_ctx.process_resolution.clone(),
        capture_mode: proxy_ctx.capture_mode,
        traffic_classification: proxy_ctx.traffic_classification,
        deployment: deployment_from_source(proxy_ctx.classification_source),
        skip_org_rules,
        semantic: Some(SemanticPolicyContext {
            use_case_label: usecase.label,
            use_case_confidence: usecase.confidence,
            anomaly_score: anomaly.score,
            anomaly_flags: anomaly.flags.clone(),
            complexity_score: usecase.complexity_score,
            volatility_class: volatility.class,
            topic_cluster_id: cluster.topic_cluster_id,
        }),
        session: proxy_ctx.session_snapshot.clone().unwrap_or_default(),
    };

    let decision = soth_policy::evaluate(
        &detect_result.normalized,
        &detect_result.artifacts,
        &context,
        policy_bundle,
    );

    (
        PolicyOutput { decision },
        started.elapsed().as_micros() as u64,
    )
}

fn deployment_from_source(source: ClassificationSource) -> DeploymentModel {
    match source {
        ClassificationSource::Proxy => DeploymentModel::Proxy,
        ClassificationSource::Sidecar => DeploymentModel::Sidecar {
            service_name: "unknown".to_string(),
            environment: "unknown".to_string(),
        },
        ClassificationSource::Sdk => DeploymentModel::Sdk {
            service_name: "unknown".to_string(),
            environment: "unknown".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use soth_policy::sync_policy::{
        BudgetLimits, OrgPatterns, PolicyBundle, PolicyBundleMetadata, PolicyBundlePayload,
        RuleAction, RuleDefinition, SignedPolicyBundle,
    };

    fn signed_policy_bytes(payload: PolicyBundlePayload) -> Vec<u8> {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let payload_bytes = match serde_json::to_vec(&payload) {
            Ok(bytes) => bytes,
            Err(error) => panic!("serialize payload failed: {error}"),
        };
        let signature = key.sign(&payload_bytes);
        let envelope = SignedPolicyBundle {
            payload,
            signature: B64.encode(signature.to_bytes()),
            public_key: B64.encode(key.verifying_key().to_bytes()),
        };
        match serde_json::to_vec(&envelope) {
            Ok(bytes) => bytes,
            Err(error) => panic!("serialize signed bundle failed: {error}"),
        }
    }

    fn policy_bundle_with_org_block() -> PolicyBundle {
        let payload = PolicyBundlePayload {
            metadata: PolicyBundleMetadata {
                bundle_version: "test-v1".to_string(),
                schema_version: "1".to_string(),
                org_id: "org-test".to_string(),
                signed_at: 0,
            },
            system_rules: Vec::new(),
            org_rules: vec![RuleDefinition {
                rule_id: "org_block_openai".to_string(),
                rule_name: "block openai".to_string(),
                cel_expr: "request.provider == \"openai\"".to_string(),
                action: RuleAction::Block {
                    status: 451,
                    message: "org blocked".to_string(),
                },
            }],
            org_patterns: OrgPatterns::default(),
            budget_limits: BudgetLimits::default(),
        };
        let bytes = signed_policy_bytes(payload);
        match soth_policy::load_bundle_from_bytes(&bytes) {
            Ok(bundle) => bundle,
            Err(error) => panic!("failed to load signed bundle: {error}"),
        }
    }

    fn proxy_ctx() -> soth_core::ProxyContext {
        soth_core::ProxyContext {
            org_id: "org-test".to_string(),
            user_id_hmac: "user-hmac".to_string(),
            team_id: "team-test".to_string(),
            device_id_hash: "device-hash".to_string(),
            endpoint_hash: "endpoint-hash".to_string(),
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
            session_snapshot: None,
            request_method: None,
        }
    }

    fn detect_result(confidence: soth_core::ParseConfidence) -> soth_core::DetectResult {
        soth_core::DetectResult {
            normalized: soth_core::NormalizedRequest {
                parse_confidence: confidence,
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
                user_content_token_estimate: 10,
                conversation_hash: "c-hash".to_string(),
                conversation_turn: Some(1),
                has_tool_definitions: false,
                tool_definition_hash: None,
                temperature: None,
                max_tokens: None,
                stream: false,
                top_p: None,
                stop_sequences: Vec::new(),
                estimated_input_tokens: 10,
                estimated_cost_usd: 0.01,
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
            confidence,
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

    fn private_key_artifact() -> soth_core::SensitiveArtifact {
        soth_core::SensitiveArtifact {
            kind: soth_core::ArtifactKind::PrivateKey,
            severity: soth_core::ArtifactSeverity::Critical,
            location: soth_core::ArtifactLocation::SystemPrompt { char_offset: 0 },
        }
    }

    #[test]
    fn full_confidence_evaluates_org_rules() {
        let bundle = policy_bundle_with_org_block();
        let detect = detect_result(soth_core::ParseConfidence::Full);
        let proxy = proxy_ctx();
        let usecase = UsecaseOutput::unknown();
        let anomaly = AnomalyOutput::default();
        let volatility = VolatilityOutput::default();
        let cluster = ClusterOutput::default();

        let (out, _) = run(
            &detect,
            &proxy,
            &usecase,
            &anomaly,
            &volatility,
            &cluster,
            &bundle,
        );

        assert!(matches!(
            out.decision.kind,
            soth_core::PolicyDecisionKind::Block {
                status: 451,
                message: _
            }
        ));
        match out.decision.matched_rule {
            Some(rule) => assert_eq!(rule.rule_kind, soth_core::RuleKind::Org),
            None => panic!("expected matched org rule"),
        }
    }

    #[test]
    fn heuristic_confidence_skips_org_rules() {
        let bundle = policy_bundle_with_org_block();
        let detect = detect_result(soth_core::ParseConfidence::Heuristic);
        let proxy = proxy_ctx();
        let usecase = UsecaseOutput::unknown();
        let anomaly = AnomalyOutput::default();
        let volatility = VolatilityOutput::default();
        let cluster = ClusterOutput::default();

        let (out, _) = run(
            &detect,
            &proxy,
            &usecase,
            &anomaly,
            &volatility,
            &cluster,
            &bundle,
        );

        assert!(matches!(
            out.decision.kind,
            soth_core::PolicyDecisionKind::Allow
        ));
        assert!(out.decision.matched_rule.is_none());
    }

    #[test]
    fn heuristic_confidence_still_applies_system_rules() {
        let bundle = policy_bundle_with_org_block();
        let mut detect = detect_result(soth_core::ParseConfidence::Heuristic);
        detect.artifacts = vec![private_key_artifact()];
        let proxy = proxy_ctx();
        let usecase = UsecaseOutput::unknown();
        let anomaly = AnomalyOutput::default();
        let volatility = VolatilityOutput::default();
        let cluster = ClusterOutput::default();

        let (out, _) = run(
            &detect,
            &proxy,
            &usecase,
            &anomaly,
            &volatility,
            &cluster,
            &bundle,
        );

        assert!(matches!(
            out.decision.kind,
            soth_core::PolicyDecisionKind::Block {
                status: 403,
                message: _
            }
        ));
        match out.decision.matched_rule {
            Some(rule) => assert_eq!(rule.rule_kind, soth_core::RuleKind::System),
            None => panic!("expected matched system rule"),
        }
    }
}
