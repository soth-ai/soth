use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;
use tracing::warn;
use uuid::Uuid;

use crate::db;
use crate::session::SessionStore;

pub fn spawn_classify_task(
    connection_id: Uuid,
    detect_result: soth_detect::DetectResult,
    content_for_embedding: Option<String>,
    proxy_ctx: soth_core::ProxyContext,
    capture_mode: soth_core::CaptureMode,
    matched_provider: Option<String>,
    matched_application: Option<String>,
    classify_bundle: Arc<soth_classify::ClassifyBundle>,
    classify_config: Arc<soth_classify::ClassifyConfig>,
    session_store: Arc<SessionStore>,
    telemetry: Option<Arc<soth_telemetry::TelemetryPipeline>>,
    db_conn: Arc<Mutex<rusqlite::Connection>>,
) -> oneshot::Receiver<soth_core::PolicyDecisionKind> {
    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        let core_detect_result = soth_detect::to_core_detect_result(&detect_result);
        let result = soth_classify::classify(
            &core_detect_result,
            content_for_embedding.as_deref(),
            &proxy_ctx,
            classify_bundle.as_ref(),
            classify_config.as_ref(),
        );

        if let soth_core::PolicyDecisionKind::Block { .. } = &result.policy_decision.kind {
            let _ = tx.send(result.policy_decision.kind.clone());
        }

        session_store.apply_classification(connection_id, &result);

        if let Some(pipeline) = telemetry {
            pipeline.push(result.telemetry_event.clone());
        }

        if let Err(error) = db::write_intercept_record(
            &db_conn,
            connection_id,
            &result,
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
