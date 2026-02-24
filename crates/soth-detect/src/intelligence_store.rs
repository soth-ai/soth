use crate::intelligence::{
    CoverageByDimension, IntelligenceError, IntelligenceResult, IntelligenceSignals,
    IntelligenceSink, ParseCoverageSummary, ParseQualityRecord, ReparseJobRecord,
    ReparseResultRecord, ReparseRunSummary, ReplayCandidate, SchemaDriftWarningSummary,
    UnknownGraphQLOperationRecord, UnknownOperationSummary,
};
use crate::types::HeaderMap;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct IntelligenceStore {
    conn: Arc<Mutex<Connection>>,
}

impl IntelligenceStore {
    pub fn open(path: impl AsRef<Path>) -> IntelligenceResult<Self> {
        let connection = Connection::open(path).map_err(IntelligenceError::from)?;
        let store = Self {
            conn: Arc::new(Mutex::new(connection)),
        };
        store.init_schema()?;
        Ok(store)
    }

    pub fn in_memory() -> IntelligenceResult<Self> {
        let connection = Connection::open_in_memory().map_err(IntelligenceError::from)?;
        let store = Self {
            conn: Arc::new(Mutex::new(connection)),
        };
        store.init_schema()?;
        Ok(store)
    }

    pub fn init_schema(&self) -> IntelligenceResult<()> {
        self.with_conn(|conn| {
            conn.execute_batch(
                r#"
                PRAGMA foreign_keys = ON;

                CREATE TABLE IF NOT EXISTS detect_parse_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_uuid TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    provider TEXT NOT NULL,
                    host TEXT,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    parse_confidence TEXT NOT NULL,
                    parse_source TEXT NOT NULL,
                    parser_id TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    canonical_hash TEXT NOT NULL,
                    warnings_json TEXT NOT NULL,
                    detect_latency_us INTEGER NOT NULL,
                    capture_mode TEXT NOT NULL,
                    headers_json TEXT NOT NULL,
                    body_redacted BLOB NOT NULL,
                    reparse_state TEXT NOT NULL DEFAULT 'pending'
                );

                CREATE INDEX IF NOT EXISTS idx_detect_parse_events_created_at
                    ON detect_parse_events(created_at);
                CREATE INDEX IF NOT EXISTS idx_detect_parse_events_confidence
                    ON detect_parse_events(parse_confidence);
                CREATE INDEX IF NOT EXISTS idx_detect_parse_events_provider
                    ON detect_parse_events(provider);
                CREATE INDEX IF NOT EXISTS idx_detect_parse_events_host
                    ON detect_parse_events(host);

                CREATE TABLE IF NOT EXISTS unknown_graphql_operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    parse_event_id INTEGER,
                    event_uuid TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    operation_name TEXT NOT NULL,
                    host TEXT,
                    provider TEXT NOT NULL,
                    canonical_hash TEXT NOT NULL,
                    warning_code TEXT NOT NULL,
                    FOREIGN KEY(parse_event_id) REFERENCES detect_parse_events(id)
                );

                CREATE INDEX IF NOT EXISTS idx_unknown_graphql_operations_created_at
                    ON unknown_graphql_operations(created_at);
                CREATE INDEX IF NOT EXISTS idx_unknown_graphql_operations_operation_host
                    ON unknown_graphql_operations(operation_name, host);

                CREATE TABLE IF NOT EXISTS reparse_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL,
                    total_candidates INTEGER NOT NULL,
                    processed INTEGER NOT NULL,
                    upgraded INTEGER NOT NULL,
                    unchanged INTEGER NOT NULL,
                    failed INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS reparse_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id INTEGER NOT NULL,
                    parse_event_id INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    old_confidence TEXT NOT NULL,
                    new_confidence TEXT NOT NULL,
                    old_canonical_hash TEXT NOT NULL,
                    new_canonical_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    warnings_json TEXT NOT NULL,
                    FOREIGN KEY(job_id) REFERENCES reparse_jobs(id),
                    FOREIGN KEY(parse_event_id) REFERENCES detect_parse_events(id)
                );

                CREATE INDEX IF NOT EXISTS idx_reparse_results_job
                    ON reparse_results(job_id);
                "#,
            )
            .map_err(IntelligenceError::from)
        })
    }

    pub fn parse_coverage_since(
        &self,
        since_epoch_secs: i64,
    ) -> IntelligenceResult<ParseCoverageSummary> {
        let mut summary = ParseCoverageSummary::default();

        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT parse_confidence, COUNT(*) FROM detect_parse_events
                     WHERE created_at >= ?1 GROUP BY parse_confidence",
                )
                .map_err(IntelligenceError::from)?;

            let rows = stmt
                .query_map(params![since_epoch_secs], |row| {
                    let confidence: String = row.get(0)?;
                    let count: i64 = row.get(1)?;
                    Ok((confidence, count))
                })
                .map_err(IntelligenceError::from)?;

            for row in rows {
                let (confidence, count) = row.map_err(IntelligenceError::from)?;
                let count = count.max(0) as u64;
                match confidence.as_str() {
                    "full" => summary.full_count = count,
                    "partial" => summary.partial_count = count,
                    _ => summary.heuristic_count = count,
                }
            }

            summary.by_provider = query_dimension_coverage(conn, since_epoch_secs, "provider")?;
            summary.by_host = query_dimension_coverage(conn, since_epoch_secs, "host")?;

            Ok(summary)
        })
    }

    pub fn unknown_graphql_operations_since(
        &self,
        since_epoch_secs: i64,
        min_count: u64,
        limit: usize,
    ) -> IntelligenceResult<Vec<UnknownOperationSummary>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT operation_name, host, COUNT(*) AS occurrence_count, MAX(created_at) AS last_seen
                     FROM unknown_graphql_operations
                     WHERE created_at >= ?1
                     GROUP BY operation_name, host
                     HAVING COUNT(*) >= ?2
                     ORDER BY occurrence_count DESC, last_seen DESC
                     LIMIT ?3",
                )
                .map_err(IntelligenceError::from)?;

            let rows = stmt
                .query_map(
                    params![since_epoch_secs, min_count as i64, limit as i64],
                    |row| {
                        let operation_name: String = row.get(0)?;
                        let host: Option<String> = row.get(1)?;
                        let occurrence_count: i64 = row.get(2)?;
                        let last_seen: i64 = row.get(3)?;
                        Ok(UnknownOperationSummary {
                            operation_name,
                            host,
                            occurrence_count: occurrence_count.max(0) as u64,
                            last_seen,
                        })
                    },
                )
                .map_err(IntelligenceError::from)?;

            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(IntelligenceError::from)?);
            }
            Ok(out)
        })
    }

    pub fn schema_drift_warnings_since(
        &self,
        since_epoch_secs: i64,
    ) -> IntelligenceResult<Vec<SchemaDriftWarningSummary>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT parser_id, schema_version, COUNT(*)
                     FROM detect_parse_events
                     WHERE created_at >= ?1 AND warnings_json LIKE '%SchemaVersionMismatch%'
                     GROUP BY parser_id, schema_version
                     ORDER BY COUNT(*) DESC",
                )
                .map_err(IntelligenceError::from)?;

            let rows = stmt
                .query_map(params![since_epoch_secs], |row| {
                    let parser_id: String = row.get(0)?;
                    let schema_version: String = row.get(1)?;
                    let warning_count: i64 = row.get(2)?;
                    Ok(SchemaDriftWarningSummary {
                        parser_id,
                        schema_version,
                        warning_count: warning_count.max(0) as u64,
                    })
                })
                .map_err(IntelligenceError::from)?;

            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(IntelligenceError::from)?);
            }
            Ok(out)
        })
    }

    pub fn intelligence_signals(
        &self,
        since_epoch_secs: i64,
        min_unknown_count: u64,
        limit: usize,
    ) -> IntelligenceResult<IntelligenceSignals> {
        let coverage = self.parse_coverage_since(since_epoch_secs)?;
        let unknown_operations =
            self.unknown_graphql_operations_since(since_epoch_secs, min_unknown_count, limit)?;
        let schema_drift = self.schema_drift_warnings_since(since_epoch_secs)?;

        Ok(IntelligenceSignals {
            coverage,
            unknown_operations,
            schema_drift,
        })
    }

    pub fn load_reparse_candidates(
        &self,
        limit: usize,
    ) -> IntelligenceResult<Vec<ReplayCandidate>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, event_uuid, method, path, headers_json, body_redacted,
                            parse_confidence, canonical_hash, provider, host
                     FROM detect_parse_events
                     WHERE parse_confidence IN ('heuristic', 'partial')
                       AND reparse_state IN ('pending', 'unchanged')
                     ORDER BY created_at ASC
                     LIMIT ?1",
                )
                .map_err(IntelligenceError::from)?;

            let rows = stmt
                .query_map(params![limit as i64], |row| {
                    let parse_event_id: i64 = row.get(0)?;
                    let event_uuid: String = row.get(1)?;
                    let method: String = row.get(2)?;
                    let path: String = row.get(3)?;
                    let headers_json: String = row.get(4)?;
                    let body_redacted: Vec<u8> = row.get(5)?;
                    let old_confidence: String = row.get(6)?;
                    let old_canonical_hash: String = row.get(7)?;
                    let provider: String = row.get(8)?;
                    let host: Option<String> = row.get(9)?;

                    let headers = match serde_json::from_str::<HeaderMap>(&headers_json) {
                        Ok(value) => value,
                        Err(_) => HeaderMap::new(),
                    };

                    Ok(ReplayCandidate {
                        parse_event_id,
                        event_uuid,
                        method,
                        path,
                        headers,
                        body_redacted,
                        old_confidence,
                        old_canonical_hash,
                        provider,
                        host,
                    })
                })
                .map_err(IntelligenceError::from)?;

            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(IntelligenceError::from)?);
            }
            Ok(out)
        })
    }

    pub fn create_reparse_job(&self, job: &ReparseJobRecord) -> IntelligenceResult<i64> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO reparse_jobs (
                    created_at, reason, status, total_candidates,
                    processed, upgraded, unchanged, failed
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    job.created_at,
                    job.reason,
                    job.status,
                    job.total_candidates as i64,
                    job.processed as i64,
                    job.upgraded as i64,
                    job.unchanged as i64,
                    job.failed as i64,
                ],
            )
            .map_err(IntelligenceError::from)?;

            Ok(conn.last_insert_rowid())
        })
    }

    pub fn complete_reparse_job(&self, summary: &ReparseRunSummary) -> IntelligenceResult<()> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE reparse_jobs
                 SET status = 'completed',
                     processed = ?2,
                     upgraded = ?3,
                     unchanged = ?4,
                     failed = ?5
                 WHERE id = ?1",
                params![
                    summary.job_id,
                    summary.processed as i64,
                    summary.upgraded as i64,
                    summary.unchanged as i64,
                    summary.failed as i64,
                ],
            )
            .map_err(IntelligenceError::from)?;
            Ok(())
        })
    }

    pub fn record_reparse_result(&self, record: &ReparseResultRecord) -> IntelligenceResult<()> {
        self.with_conn(|conn| {
            let warnings_json =
                serde_json::to_string(&record.warnings).map_err(IntelligenceError::from)?;
            conn.execute(
                "INSERT INTO reparse_results (
                    job_id, parse_event_id, created_at,
                    old_confidence, new_confidence,
                    old_canonical_hash, new_canonical_hash,
                    status, warnings_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    record.job_id,
                    record.parse_event_id,
                    record.created_at,
                    record.old_confidence,
                    record.new_confidence,
                    record.old_canonical_hash,
                    record.new_canonical_hash,
                    record.status,
                    warnings_json,
                ],
            )
            .map_err(IntelligenceError::from)?;
            Ok(())
        })
    }

    pub fn update_parse_event_reparse_state(
        &self,
        parse_event_id: i64,
        state: &str,
    ) -> IntelligenceResult<()> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE detect_parse_events SET reparse_state = ?2 WHERE id = ?1",
                params![parse_event_id, state],
            )
            .map_err(IntelligenceError::from)?;
            Ok(())
        })
    }

    fn with_conn<T>(
        &self,
        f: impl FnOnce(&Connection) -> IntelligenceResult<T>,
    ) -> IntelligenceResult<T> {
        let lock = match self.conn.lock() {
            Ok(lock) => lock,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(&lock)
    }
}

impl IntelligenceSink for IntelligenceStore {
    fn record_parse_event(&self, record: &ParseQualityRecord) -> IntelligenceResult<i64> {
        self.with_conn(|conn| {
            let warnings_json =
                serde_json::to_string(&record.warnings).map_err(IntelligenceError::from)?;
            conn.execute(
                "INSERT INTO detect_parse_events (
                    event_uuid, created_at, provider, host, method, path,
                    parse_confidence, parse_source, parser_id, schema_version,
                    canonical_hash, warnings_json, detect_latency_us, capture_mode,
                    headers_json, body_redacted
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                params![
                    record.event_uuid,
                    record.created_at,
                    record.provider,
                    record.host,
                    record.method,
                    record.path,
                    record.parse_confidence,
                    record.parse_source,
                    record.parser_id,
                    record.schema_version,
                    record.canonical_hash,
                    warnings_json,
                    record.detect_latency_us as i64,
                    record.capture_mode,
                    record.headers_json,
                    record.body_redacted,
                ],
            )
            .map_err(IntelligenceError::from)?;
            Ok(conn.last_insert_rowid())
        })
    }

    fn record_unknown_graphql_operation(
        &self,
        record: &UnknownGraphQLOperationRecord,
    ) -> IntelligenceResult<()> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO unknown_graphql_operations (
                    parse_event_id, event_uuid, created_at, operation_name,
                    host, provider, canonical_hash, warning_code
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    record.parse_event_id,
                    record.event_uuid,
                    record.created_at,
                    record.operation_name,
                    record.host,
                    record.provider,
                    record.canonical_hash,
                    record.warning_code,
                ],
            )
            .map_err(IntelligenceError::from)?;
            Ok(())
        })
    }
}

fn query_dimension_coverage(
    conn: &Connection,
    since_epoch_secs: i64,
    dimension: &str,
) -> IntelligenceResult<Vec<CoverageByDimension>> {
    let sql = format!(
        "SELECT COALESCE({dimension}, ''), parse_confidence, COUNT(*)
         FROM detect_parse_events
         WHERE created_at >= ?1
         GROUP BY {dimension}, parse_confidence"
    );

    let mut stmt = conn.prepare(&sql).map_err(IntelligenceError::from)?;
    let rows = stmt
        .query_map(params![since_epoch_secs], |row| {
            let dimension_value: String = row.get(0)?;
            let confidence: String = row.get(1)?;
            let count: i64 = row.get(2)?;
            Ok((dimension_value, confidence, count.max(0) as u64))
        })
        .map_err(IntelligenceError::from)?;

    let mut map = std::collections::BTreeMap::<String, CoverageByDimension>::new();

    for row in rows {
        let (dimension_value, confidence, count) = row.map_err(IntelligenceError::from)?;
        let entry = map
            .entry(dimension_value.clone())
            .or_insert(CoverageByDimension {
                dimension: dimension_value,
                full_count: 0,
                partial_count: 0,
                heuristic_count: 0,
                total_count: 0,
            });

        match confidence.as_str() {
            "full" => entry.full_count = entry.full_count.saturating_add(count),
            "partial" => entry.partial_count = entry.partial_count.saturating_add(count),
            _ => entry.heuristic_count = entry.heuristic_count.saturating_add(count),
        }
        entry.total_count = entry.total_count.saturating_add(count);
    }

    Ok(map.into_values().collect())
}
