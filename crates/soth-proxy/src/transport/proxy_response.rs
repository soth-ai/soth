//! Response-side helpers for proxy transport.

use http_body_util::{BodyExt, Full};
use hudsucker::{hyper::Response, Body};
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::transport::exchange_assembler::ExchangeAssemblerConfig;
use crate::transport::pii_enrichment::PiiEventEnricher;
use crate::transport::proxy::PendingRequest;
use crate::transport::proxy_exchange::{append_detection_tags, finalize_and_enqueue_exchange_v2};
use crate::transport::proxy_payload::decode_payload_for_logging;
use crate::transport::proxy_support::{
    append_capture_tags, append_catalog_discovery_tags, append_process_attribution_tags,
};
use crate::transport::response_event_builder::normalize_response_content;
use crate::transport::tier_enrichment::extract_subscription_tags;
use crate::transport::usage_enrichment::ResponseUsageMeta;
use soth_core::EventLogger;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_mcp_jsonrpc_response(
    res: Response<Body>,
    pending: &PendingRequest,
    status: u16,
    is_json: bool,
    content_type: Option<&str>,
    content_encoding: Option<&str>,
    response_headers: &BTreeMap<String, String>,
    event_logger: Option<&Arc<EventLogger>>,
    event_tags: &BTreeMap<String, String>,
    pii_enricher: &Arc<PiiEventEnricher>,
    exchange_v2_cfg: Option<&ExchangeAssemblerConfig>,
    exchange_bundle_version: Option<&str>,
    session_id: &str,
    capture_max_body_bytes: u64,
) -> Response<Body> {
    let (body_content, res) = if is_json {
        let (parts, body) = res.into_parts();
        match body.collect().await {
            Ok(collected) => {
                let bytes = collected.to_bytes();
                let (_, body_str) = decode_payload_for_logging(&bytes, content_encoding);
                let new_body = Body::from(Full::new(bytes));
                let res = Response::from_parts(parts, new_body);
                (Some(body_str), res)
            }
            Err(_) => {
                let res = Response::from_parts(parts, Body::empty());
                (None, res)
            }
        }
    } else {
        (None, res)
    };

    if let Some(logger) = event_logger {
        let response_payload = body_content.unwrap_or_else(|| {
            format!(
                "[no JSON-RPC response body captured for {} {} (HTTP {})]",
                pending.method, pending.path, status
            )
        });

        let mut tags = event_tags.clone();
        if pending.catalog_discovery {
            append_catalog_discovery_tags(&mut tags, &pending.host);
        }
        append_process_attribution_tags(&mut tags, pending.envelope.as_ref());
        append_detection_tags(&mut tags, pending);
        append_capture_tags(
            &mut tags,
            pending.request_body_truncated,
            false,
            None,
            if pending.request_body_truncated {
                Some(capture_max_body_bytes)
            } else {
                None
            },
        );
        let exchange_tags = tags;

        if let Some(exchange_cfg) = exchange_v2_cfg {
            finalize_and_enqueue_exchange_v2(
                logger,
                exchange_cfg,
                pii_enricher,
                pending,
                session_id,
                status,
                false,
                false,
                content_type,
                Some(response_headers.clone()),
                Some(response_payload.as_str()),
                &ResponseUsageMeta::default(),
                Some(&exchange_tags),
                false,
                None,
                exchange_bundle_version,
            );
        }
    }

    res
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_non_stream_response_event(
    logger: &Arc<EventLogger>,
    exchange_v2_cfg: Option<&ExchangeAssemblerConfig>,
    pii_enricher: &Arc<PiiEventEnricher>,
    pending: &PendingRequest,
    session_id: &str,
    status: u16,
    is_stream_response: bool,
    is_sse: bool,
    content_type: Option<&str>,
    response_headers: &BTreeMap<String, String>,
    body_content: Option<&str>,
    response_usage: &ResponseUsageMeta,
    event_tags: &BTreeMap<String, String>,
    response_body_truncated: bool,
    response_capture_reason: Option<&'static str>,
    capture_max_body_bytes: u64,
    exchange_bundle_version: Option<&str>,
) {
    let normalized_response = normalize_response_content(
        body_content,
        pending.request_content.as_deref(),
        &pending.method,
        &pending.path,
        status,
        is_sse,
        false,
    );
    let normalized_response_for_exchange = normalized_response.clone();
    let mut enriched_tags = event_tags.clone();
    if pending.catalog_discovery {
        append_catalog_discovery_tags(&mut enriched_tags, &pending.host);
    }
    append_process_attribution_tags(&mut enriched_tags, pending.envelope.as_ref());
    append_detection_tags(&mut enriched_tags, pending);
    append_capture_tags(
        &mut enriched_tags,
        pending.request_body_truncated,
        response_body_truncated,
        response_capture_reason,
        if pending.request_body_truncated || response_body_truncated {
            Some(capture_max_body_bytes)
        } else {
            None
        },
    );
    if let Some(response_body) = normalized_response.as_deref() {
        let subscription_tags = extract_subscription_tags(
            pending.provider.as_deref().unwrap_or("unknown"),
            &pending.host,
            &pending.path,
            response_body,
        );
        if !subscription_tags.is_empty() {
            enriched_tags.extend(subscription_tags);
        }
    }
    if let Some(exchange_cfg) = exchange_v2_cfg {
        finalize_and_enqueue_exchange_v2(
            logger,
            exchange_cfg,
            pii_enricher,
            pending,
            session_id,
            status,
            is_stream_response,
            is_sse,
            content_type,
            Some(response_headers.clone()),
            normalized_response_for_exchange.as_deref(),
            response_usage,
            Some(&enriched_tags),
            response_body_truncated,
            response_capture_reason,
            exchange_bundle_version,
        );
    }
}
