//! Forward-error handling helpers for proxy transport.

use hudsucker::{hyper::Response, hyper_util::client::legacy::Error as LegacyClientError, Body};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, error, warn};

use crate::metrics;
use crate::transport::exchange_assembler::ExchangeAssemblerConfig;
use crate::transport::pii_enrichment::PiiEventEnricher;
use crate::transport::proxy::PendingRequests;
use crate::transport::proxy_exchange::{append_detection_tags, finalize_and_enqueue_exchange};
use crate::transport::proxy_support::{
    append_catalog_discovery_tags, append_process_attribution_tags, is_benign_proxy_forward_error,
    is_emfile_proxy_forward_error,
};
use crate::transport::usage_enrichment::ResponseUsageMeta;
use soth_core::EventLogger;

pub(crate) async fn handle_forward_error(
    client_addr: SocketAddr,
    request_id: u64,
    err: LegacyClientError,
    pending_requests: PendingRequests,
    event_logger: Option<Arc<EventLogger>>,
    event_tags: Arc<BTreeMap<String, String>>,
    pii_enricher: Arc<PiiEventEnricher>,
    session_id: String,
    exchange_cfg: Option<ExchangeAssemblerConfig>,
    exchange_bundle_version: Option<String>,
) -> Response<Body> {
    let benign = is_benign_proxy_forward_error(&err);
    let emfile_like = is_emfile_proxy_forward_error(&err);
    let error = err.to_string();

    let pending = {
        let mut requests = pending_requests.lock();
        requests.remove(&request_id)
    };

    if emfile_like {
        metrics::record_emfile_forward_error();
    }

    if let (Some(logger), Some(pending_req)) = (event_logger.as_ref(), pending.as_ref()) {
        let failure_status = hyper::StatusCode::BAD_GATEWAY.as_u16();
        let mut tags = (*event_tags).clone();
        tags.insert("transport_forward_error".to_string(), "true".to_string());
        if benign {
            tags.insert(
                "transport_forward_error_kind".to_string(),
                "transient_disconnect".to_string(),
            );
        }
        if pending_req.catalog_discovery {
            append_catalog_discovery_tags(&mut tags, &pending_req.host);
        }
        append_process_attribution_tags(&mut tags, pending_req.envelope.as_ref());
        append_detection_tags(&mut tags, pending_req);
        let usage_meta = ResponseUsageMeta::default();
        if let Some(exchange_cfg) = exchange_cfg.as_ref() {
            let error_content = format!("[forward error] {error}");
            finalize_and_enqueue_exchange(
                logger,
                exchange_cfg,
                &pii_enricher,
                pending_req,
                &session_id,
                failure_status,
                false,
                false,
                None,
                None,
                Some(error_content.as_str()),
                &usage_meta,
                Some(&tags),
                true,
                Some("transport_forward_error"),
                exchange_bundle_version.as_deref(),
            );
        }
    }

    if benign {
        debug!(
            client_addr = %client_addr,
            error = %error,
            "Transient proxy forward failure (client/upstream disconnect)"
        );
    } else if emfile_like {
        error!(
            client_addr = %client_addr,
            error = %error,
            "Forward request failed due to file descriptor exhaustion (EMFILE)"
        );
    } else {
        warn!(
            client_addr = %client_addr,
            error = %error,
            "Failed to forward request"
        );
    }

    Response::builder()
        .status(hyper::StatusCode::BAD_GATEWAY)
        .body(Body::empty())
        .expect("Failed to build proxy error response")
}
