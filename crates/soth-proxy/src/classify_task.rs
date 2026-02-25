use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use bytes::Bytes;
use tokio::sync::oneshot;
use tracing::warn;
use uuid::Uuid;

use crate::db;
use crate::session::SessionStore;

pub fn spawn_classify_task(
    connection_id: Uuid,
    detect_result: soth_core::DetectResult,
    content_for_embedding: Option<String>,
    proxy_ctx: soth_core::ProxyContext,
    capture_mode: soth_core::CaptureMode,
    matched_provider: Option<String>,
    matched_application: Option<String>,
    raw_body_for_commitment: Option<Bytes>,
    classify_bundle: Arc<soth_classify::ClassifyBundle>,
    policy_bundle: Arc<soth_policy::PolicyBundle>,
    classify_config: Arc<soth_classify::ClassifyConfig>,
    policy_block_enforced: Arc<AtomicBool>,
    session_store: Arc<SessionStore>,
    telemetry: Option<Arc<soth_telemetry::TelemetryPipeline>>,
    db_conn: Arc<Mutex<rusqlite::Connection>>,
) -> oneshot::Receiver<soth_core::PolicyDecisionKind> {
    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut block_signal_tx = Some(tx);

        if let Some(kind) = fast_block_decision(&detect_result, &proxy_ctx, policy_bundle.as_ref())
        {
            emit_block_signal(&mut block_signal_tx, kind);
        }

        let mut result = soth_classify::classify(
            &detect_result,
            content_for_embedding.as_deref(),
            &proxy_ctx,
            classify_bundle.as_ref(),
            classify_config.as_ref(),
        );

        if let soth_core::PolicyDecisionKind::Block { .. } = &result.policy_decision.kind {
            emit_block_signal(&mut block_signal_tx, result.policy_decision.kind.clone());
            if !policy_block_enforced.load(Ordering::Relaxed) {
                result.policy_enforced = false;
            }
        }

        session_store.apply_classification(connection_id, &result);

        if let Some(pipeline) = telemetry {
            pipeline.push(result.telemetry_event.clone());
        }

        if let Err(error) = db::write_intercept_record(
            &db_conn,
            connection_id,
            &result,
            &detect_result,
            &proxy_ctx,
            raw_body_for_commitment.as_deref(),
            capture_mode,
            matched_provider.as_deref(),
            matched_application.as_deref(),
        ) {
            warn!(
                connection_id = %connection_id,
                error = %error,
                "failed writing intercept record"
            );
        }
    });

    rx
}

fn fast_block_decision(
    detect_result: &soth_core::DetectResult,
    proxy_ctx: &soth_core::ProxyContext,
    policy_bundle: &soth_policy::PolicyBundle,
) -> Option<soth_core::PolicyDecisionKind> {
    let context = soth_core::PolicyContext {
        process_resolution: proxy_ctx.process_resolution.clone(),
        capture_mode: proxy_ctx.capture_mode,
        traffic_classification: proxy_ctx.traffic_classification,
        deployment: deployment_from_source(proxy_ctx.classification_source),
        skip_org_rules: true,
        semantic: None,
        session: proxy_ctx.session_snapshot.clone().unwrap_or_default(),
    };

    let decision = soth_policy::evaluate(
        &detect_result.normalized,
        &detect_result.artifacts,
        &context,
        policy_bundle,
    );

    if let kind @ soth_core::PolicyDecisionKind::Block { .. } = decision.kind {
        Some(kind)
    } else {
        None
    }
}

fn deployment_from_source(source: soth_core::ClassificationSource) -> soth_core::DeploymentModel {
    match source {
        soth_core::ClassificationSource::Proxy => soth_core::DeploymentModel::Proxy,
        soth_core::ClassificationSource::Sidecar => soth_core::DeploymentModel::Sidecar {
            service_name: "unknown".to_string(),
            environment: "unknown".to_string(),
        },
        soth_core::ClassificationSource::Sdk => soth_core::DeploymentModel::Sdk {
            service_name: "unknown".to_string(),
            environment: "unknown".to_string(),
        },
    }
}

fn emit_block_signal(
    tx: &mut Option<oneshot::Sender<soth_core::PolicyDecisionKind>>,
    kind: soth_core::PolicyDecisionKind,
) {
    if let Some(sender) = tx.take() {
        let _ = sender.send(kind);
    }
}
