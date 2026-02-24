use crate::engine::{process_with_registry, ParserRegistry};
use crate::intelligence::{
    confidence_rank, now_epoch_secs, parse_confidence_from_label, warning_to_string,
    IntelligenceResult, ReparseJobRecord, ReparseResultRecord, ReparseRunSummary,
};
use crate::intelligence_store::IntelligenceStore;
use crate::types::{ConnectionMeta, DetectBundleSlice, RawRequest, SocketFamily};
use bytes::Bytes;
use std::net::{Ipv4Addr, SocketAddrV4};
use uuid::Uuid;

pub fn replay_heuristic_events(
    registry: &ParserRegistry,
    bundle: &DetectBundleSlice<'_>,
    store: &IntelligenceStore,
    limit: usize,
) -> IntelligenceResult<ReparseRunSummary> {
    let candidates = store.load_reparse_candidates(limit)?;
    let mut job = ReparseJobRecord::new("heuristic_replay", candidates.len() as u64);
    let job_id = store.create_reparse_job(&job)?;

    let mut processed = 0u64;
    let mut upgraded = 0u64;
    let mut unchanged = 0u64;
    let mut failed = 0u64;

    for candidate in candidates {
        let request = RawRequest {
            method: candidate.method.clone(),
            path: candidate.path.clone(),
            headers: candidate.headers.clone(),
            body: Bytes::from(candidate.body_redacted.clone()),
            connection_meta: build_replay_connection_meta(&candidate.event_uuid),
        };

        let old_confidence = parse_confidence_from_label(&candidate.old_confidence);
        let old_rank = confidence_rank(&old_confidence);

        let new_result = process_with_registry(registry, &request, bundle);
        let new_rank = confidence_rank(&new_result.confidence);

        let status = if new_rank > old_rank {
            upgraded = upgraded.saturating_add(1);
            "upgraded"
        } else {
            unchanged = unchanged.saturating_add(1);
            "unchanged"
        };

        let reparse_result = ReparseResultRecord {
            job_id,
            parse_event_id: candidate.parse_event_id,
            created_at: now_epoch_secs(),
            old_confidence: candidate.old_confidence,
            new_confidence: crate::intelligence::parse_confidence_label(&new_result.confidence)
                .to_string(),
            old_canonical_hash: candidate.old_canonical_hash,
            new_canonical_hash: new_result.normalized.canonical_hash,
            status: status.to_string(),
            warnings: new_result
                .warnings
                .iter()
                .map(warning_to_string)
                .collect::<Vec<_>>(),
        };

        if store.record_reparse_result(&reparse_result).is_err() {
            failed = failed.saturating_add(1);
            let _ = store.update_parse_event_reparse_state(candidate.parse_event_id, "failed");
        } else {
            let _ = store.update_parse_event_reparse_state(candidate.parse_event_id, status);
        }

        processed = processed.saturating_add(1);
    }

    job.id = Some(job_id);
    job.processed = processed;
    job.upgraded = upgraded;
    job.unchanged = unchanged;
    job.failed = failed;
    job.status = "completed".to_string();

    let summary = ReparseRunSummary {
        job_id,
        total_candidates: job.total_candidates,
        processed,
        upgraded,
        unchanged,
        failed,
    };

    store.complete_reparse_job(&summary)?;
    Ok(summary)
}

fn build_replay_connection_meta(event_uuid: &str) -> ConnectionMeta {
    let parsed = Uuid::parse_str(event_uuid).ok();
    let connection_id = parsed.unwrap_or_else(Uuid::new_v4);

    ConnectionMeta {
        connection_id,
        socket_family: SocketFamily::TcpV4 {
            local: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
            remote: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        },
        process_info: None,
        tls_info: None,
        app_identity: None,
    }
}
