use std::time::Instant;

use crate::bundle::ClassifyBundle;
use crate::config::ClassifyConfig;
use crate::stage1_embed;
use crate::stage2_cluster;
use crate::stage2_cluster::ClusterOutput;
use crate::stage3_usecase;
use crate::stage3_usecase::UsecaseOutput;
use crate::stage5_anomaly::AnomalyOutput;
use crate::stage6_policy::PolicyOutput;
use crate::types::{ClassifiedResult, StageTiming};

pub(crate) fn run(
    detect_result: &soth_core::DetectResult,
    content_for_embedding: Option<&str>,
    proxy_ctx: &soth_core::ProxyContext,
    bundle: &ClassifyBundle,
    config: &ClassifyConfig,
) -> ClassifiedResult {
    let started = Instant::now();

    let embed = stage1_embed::run(content_for_embedding, detect_result, bundle, config);

    let (cluster, stage2_us) = if embed.vector.is_some() {
        stage2_cluster::run(
            embed.vector.as_deref(),
            bundle.centroids.as_slice(),
            bundle.lsh_projection.as_slice(),
            proxy_ctx.session_snapshot.as_ref(),
            config,
        )
    } else {
        (ClusterOutput::default(), 0)
    };

    let (usecase, stage3_us) = stage3_usecase::run(
        embed.vector.as_deref(),
        bundle.classifier.as_ref(),
        &detect_result.normalized,
        config,
    );

    let (volatility, stage4_us) = crate::stage4_volatility::run(
        &detect_result.normalized,
        content_for_embedding,
        &config.volatility,
    );

    let (anomaly, stage5_us) = if config.anomaly_enabled {
        crate::stage5_anomaly::run(
            embed.vector.as_deref(),
            &cluster,
            &detect_result.normalized,
            &detect_result.artifacts,
            proxy_ctx.session_snapshot.as_ref(),
            bundle.anomaly_scorer.as_ref(),
        )
    } else {
        (AnomalyOutput::default(), 0)
    };

    let (policy, stage6_us) = crate::stage6_policy::run(
        detect_result,
        proxy_ctx,
        &usecase,
        &anomaly,
        &volatility,
        &cluster,
        &bundle.policy_bundle,
    );

    let telemetry = crate::stage7_telemetry::run(
        detect_result,
        proxy_ctx,
        &cluster,
        &usecase,
        &volatility,
        &anomaly,
        &policy,
    );

    let stage_latencies = StageTiming {
        stage1_us: embed.latency_us,
        stage2_us,
        stage3_us,
        stage4_us,
        stage5_us,
        stage6_us,
        stage7_us: telemetry.latency_us,
        total_us: started.elapsed().as_micros() as u64,
    };

    assemble_result(
        detect_result,
        embed,
        cluster,
        usecase,
        volatility,
        anomaly,
        policy,
        telemetry,
        stage_latencies,
    )
}

fn assemble_result(
    _detect_result: &soth_core::DetectResult,
    embed: stage1_embed::EmbedOutput,
    cluster: ClusterOutput,
    usecase: UsecaseOutput,
    volatility: crate::stage4_volatility::VolatilityOutput,
    anomaly: AnomalyOutput,
    policy: PolicyOutput,
    telemetry: crate::stage7_telemetry::TelemetryOutput,
    stage_latencies: StageTiming,
) -> ClassifiedResult {
    ClassifiedResult {
        use_case_label: usecase.label,
        use_case_confidence: usecase.confidence,
        secondary_label: usecase.secondary_label,
        topic_cluster_id: cluster.topic_cluster_id,
        semantic_hash: cluster.semantic_hash,
        embedding_norm: embed.norm,
        complexity_score: usecase.complexity_score,
        embedding_skipped: embed.vector.is_none(),
        volatility_class: volatility.class,
        dynamic_fraction: volatility.dynamic_fraction,
        is_semantic_collision: cluster.is_semantic_collision,
        collision_response_stability: None,
        prefix_repeat_signature: volatility.prefix_repeat_signature,
        anomaly_score: anomaly.score,
        anomaly_flags: anomaly.flags,
        policy_decision: policy.decision,
        policy_enforced: true,
        telemetry_event: telemetry.event,
        commitment_nonce: telemetry.nonce,
        stage_latencies,
    }
}
