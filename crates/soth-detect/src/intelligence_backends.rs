//! Pluggable [`IntelligenceSink`] implementations that don't require SQLite.
//!
//! - [`NoopBackend`]: drops every record. Use when intelligence telemetry is
//!   not wanted (lightweight SDK builds, fire-and-forget pipelines).
//! - [`InMemoryBackend`]: keeps records in memory. Use for tests, ephemeral
//!   processes, or when shipping records to a remote sink later.
//!
//! For persistent SQLite-backed storage, enable the `intelligence-sqlite`
//! feature and use `IntelligenceStore`.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;

use crate::intelligence::{
    IntelligenceResult, IntelligenceSink, ParseQualityRecord, UnknownGraphQLOperationRecord,
};

/// `IntelligenceSink` that discards every record. Cheap; safe for hot paths
/// where the caller has not configured intelligence persistence.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopBackend;

impl IntelligenceSink for NoopBackend {
    fn record_parse_event(&self, _record: &ParseQualityRecord) -> IntelligenceResult<i64> {
        Ok(0)
    }

    fn record_unknown_graphql_operation(
        &self,
        _record: &UnknownGraphQLOperationRecord,
    ) -> IntelligenceResult<()> {
        Ok(())
    }
}

/// `IntelligenceSink` that buffers records in memory. Intended for tests and
/// short-lived processes that hand records off to a remote sink later.
#[derive(Debug, Default)]
pub struct InMemoryBackend {
    parse_events: Mutex<Vec<ParseQualityRecord>>,
    unknown_ops: Mutex<Vec<UnknownGraphQLOperationRecord>>,
    next_id: AtomicI64,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of every recorded parse event in insertion order.
    pub fn parse_events(&self) -> Vec<ParseQualityRecord> {
        self.parse_events
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// Snapshot of every recorded unknown-GraphQL-operation record.
    pub fn unknown_graphql_operations(&self) -> Vec<UnknownGraphQLOperationRecord> {
        self.unknown_ops
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// Total number of parse events buffered.
    pub fn parse_event_count(&self) -> usize {
        self.parse_events
            .lock()
            .map(|guard| guard.len())
            .unwrap_or(0)
    }
}

impl IntelligenceSink for InMemoryBackend {
    fn record_parse_event(&self, record: &ParseQualityRecord) -> IntelligenceResult<i64> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        if let Ok(mut guard) = self.parse_events.lock() {
            guard.push(record.clone());
        }
        Ok(id)
    }

    fn record_unknown_graphql_operation(
        &self,
        record: &UnknownGraphQLOperationRecord,
    ) -> IntelligenceResult<()> {
        if let Ok(mut guard) = self.unknown_ops.lock() {
            guard.push(record.clone());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intelligence::ParseQualityRecord;

    fn sample_record() -> ParseQualityRecord {
        ParseQualityRecord {
            event_uuid: "evt-1".to_string(),
            created_at: 0,
            provider: "openai".to_string(),
            host: Some("api.openai.com".to_string()),
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            parse_confidence: "full".to_string(),
            parse_source: "rest:openai".to_string(),
            parser_id: "openai".to_string(),
            schema_version: "2024-01".to_string(),
            canonical_hash: "deadbeef".to_string(),
            warnings: Vec::new(),
            detect_latency_us: 0,
            capture_mode: "metadata_only".to_string(),
            headers_json: "{}".to_string(),
            body_redacted: Vec::new(),
        }
    }

    #[test]
    fn noop_backend_returns_ok_and_drops_records() {
        let backend = NoopBackend;
        let id = backend.record_parse_event(&sample_record()).unwrap();
        assert_eq!(id, 0);
    }

    #[test]
    fn in_memory_backend_buffers_records_in_order() {
        let backend = InMemoryBackend::new();
        let id1 = backend.record_parse_event(&sample_record()).unwrap();
        let id2 = backend.record_parse_event(&sample_record()).unwrap();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(backend.parse_event_count(), 2);
        assert_eq!(backend.parse_events().len(), 2);
    }
}
