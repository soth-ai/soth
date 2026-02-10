use crate::cli_config;
use chrono::{Duration as ChronoDuration, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use soth_budget::BudgetStorage;
use soth_core::config::{RetentionConfig, SothConfig};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

const RETENTION_INTERVAL_SECS: u64 = 6 * 60 * 60;
const SQLITE_BUSY_TIMEOUT_MS: u64 = 2_000;
const VACUUM_MIN_DELETED_ROWS: usize = 512;
const BUDGET_VACUUM_MIN_DELETED_ROWS: usize = 128;
const VACUUM_MIN_INTERVAL_HOURS: i64 = 24;
const EVENTS_VACUUM_META_KEY: &str = "last_vacuum_at_events";
const BUDGET_VACUUM_META_KEY: &str = "last_vacuum_at_budget";

pub struct RetentionRuntime {
    pub shutdown_tx: tokio::sync::oneshot::Sender<()>,
    pub task: JoinHandle<()>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RetentionSummary {
    pub events_deleted: usize,
    pub payloads_deleted: usize,
    pub pending_deleted: usize,
    pub pairs_deleted: usize,
    pub clusters_deleted: usize,
    pub rollups_deleted: usize,
    pub budget_records_deleted: usize,
    pub event_vacuum_ran: bool,
    pub budget_vacuum_ran: bool,
}

impl RetentionSummary {
    fn total_deleted(self) -> usize {
        self.events_deleted
            + self.payloads_deleted
            + self.pending_deleted
            + self.pairs_deleted
            + self.clusters_deleted
            + self.rollups_deleted
            + self.budget_records_deleted
    }

    fn merge(&mut self, other: RetentionSummary) {
        self.events_deleted += other.events_deleted;
        self.payloads_deleted += other.payloads_deleted;
        self.pending_deleted += other.pending_deleted;
        self.pairs_deleted += other.pairs_deleted;
        self.clusters_deleted += other.clusters_deleted;
        self.rollups_deleted += other.rollups_deleted;
        self.budget_records_deleted += other.budget_records_deleted;
        self.event_vacuum_ran = self.event_vacuum_ran || other.event_vacuum_ran;
        self.budget_vacuum_ran = self.budget_vacuum_ran || other.budget_vacuum_ran;
    }
}

pub fn spawn_retention_runtime(
    config: &SothConfig,
    event_db_path: Option<PathBuf>,
) -> Option<RetentionRuntime> {
    let retention = config.observe.storage.retention.clone();
    let budget_db_path = resolve_budget_db_path(config);

    if event_db_path.is_none() && budget_db_path.is_none() {
        return None;
    }

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        run_pass_and_log(
            retention.clone(),
            event_db_path.clone(),
            budget_db_path.clone(),
        )
        .await;

        let mut interval = tokio::time::interval(Duration::from_secs(RETENTION_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                _ = interval.tick() => {
                    run_pass_and_log(retention.clone(), event_db_path.clone(), budget_db_path.clone()).await;
                }
            }
        }
    });

    Some(RetentionRuntime { shutdown_tx, task })
}

async fn run_pass_and_log(
    retention: RetentionConfig,
    event_db_path: Option<PathBuf>,
    budget_db_path: Option<PathBuf>,
) {
    let result = tokio::task::spawn_blocking(move || {
        run_retention_pass(
            &retention,
            event_db_path.as_deref(),
            budget_db_path.as_deref(),
        )
    })
    .await;

    let Ok(summary) = result else {
        warn!("Retention cleanup task failed: {}", result.unwrap_err());
        return;
    };

    if summary.total_deleted() > 0 {
        info!(
            events_deleted = summary.events_deleted,
            payloads_deleted = summary.payloads_deleted,
            pending_deleted = summary.pending_deleted,
            pairs_deleted = summary.pairs_deleted,
            clusters_deleted = summary.clusters_deleted,
            rollups_deleted = summary.rollups_deleted,
            budget_deleted = summary.budget_records_deleted,
            event_vacuum_ran = summary.event_vacuum_ran,
            budget_vacuum_ran = summary.budget_vacuum_ran,
            "Retention cleanup completed"
        );
    } else {
        debug!("Retention cleanup pass completed with no deletions");
    }
}

fn run_retention_pass(
    retention: &RetentionConfig,
    event_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
) -> RetentionSummary {
    let mut summary = RetentionSummary::default();

    if let Some(path) = event_db_path {
        match cleanup_event_db(path, retention) {
            Ok(delta) => summary.merge(delta),
            Err(error) => warn!(
                "Retention cleanup failed for events db {}: {}",
                path.display(),
                error
            ),
        }
    }

    if let Some(path) = budget_db_path {
        match cleanup_budget_db(path, retention) {
            Ok(delta) => {
                summary.budget_records_deleted += delta.records_deleted;
                summary.budget_vacuum_ran = delta.vacuum_ran;
            }
            Err(error) => warn!(
                "Retention cleanup failed for budget db {}: {}",
                path.display(),
                error
            ),
        }
    }

    summary
}

fn cleanup_event_db(
    db_path: &Path,
    retention: &RetentionConfig,
) -> anyhow::Result<RetentionSummary> {
    if !db_path.exists() {
        return Ok(RetentionSummary::default());
    }

    let mut conn = Connection::open(db_path)?;
    conn.busy_timeout(Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS))?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;

    let has_wrap_events = table_exists(&conn, "wrap_events")?;
    let has_payloads = table_exists(&conn, "wrap_event_payloads")?;
    let has_pending = table_exists(&conn, "event_pending_requests")?;
    let has_pairs = table_exists(&conn, "event_pairs")?;
    let has_clusters = table_exists(&conn, "event_clusters")?;
    let has_rollups = table_exists(&conn, "rollups_1m")?;

    let mut summary = RetentionSummary::default();
    let tx = conn.transaction()?;

    if let Some(cutoff) = cutoff_rfc3339(retention.ai_proxy_days) {
        if has_wrap_events {
            summary.events_deleted += tx.execute(
                "DELETE FROM wrap_events
                 WHERE timestamp < ?1
                   AND json_extract(event_json, '$.source') = 'ai_proxy'",
                params![cutoff],
            )?;
        }
    }

    if let Some(cutoff) = cutoff_rfc3339(retention.mcp_days) {
        if has_wrap_events {
            summary.events_deleted += tx.execute(
                "DELETE FROM wrap_events
                 WHERE timestamp < ?1
                   AND json_extract(event_json, '$.source') = 'mcp'",
                params![cutoff],
            )?;
        }
    }

    if let Some(cutoff) = cutoff_rfc3339(retention.agent_app_days) {
        if has_wrap_events {
            summary.events_deleted += tx.execute(
                "DELETE FROM wrap_events
                 WHERE timestamp < ?1
                   AND json_extract(event_json, '$.source') = 'agent_app'",
                params![cutoff],
            )?;
        }
    }

    if has_payloads {
        summary.payloads_deleted += tx.execute(
            "DELETE FROM wrap_event_payloads
             WHERE NOT EXISTS (
                SELECT 1 FROM wrap_events we
                WHERE we.id = wrap_event_payloads.event_id
             )",
            [],
        )?;
    }

    if let Some(cutoff) = cutoff_rfc3339(retention.clusters_days) {
        if has_pending {
            summary.pending_deleted += tx.execute(
                "DELETE FROM event_pending_requests WHERE timestamp < ?1",
                params![cutoff],
            )?;
        }
        if has_pairs {
            summary.pairs_deleted += tx.execute(
                "DELETE FROM event_pairs WHERE timestamp < ?1",
                params![cutoff],
            )?;
        }
        if has_clusters {
            summary.clusters_deleted += tx.execute(
                "DELETE FROM event_clusters WHERE timestamp < ?1",
                params![cutoff],
            )?;
        }
    }

    if let Some(cutoff) = cutoff_rollup(retention.rollups_days) {
        if has_rollups {
            summary.rollups_deleted += tx.execute(
                "DELETE FROM rollups_1m WHERE bucket_start < ?1",
                params![cutoff],
            )?;
        }
    }

    tx.commit()?;

    summary.event_vacuum_ran = maybe_vacuum_event_db(&mut conn, retention, summary)?;
    Ok(summary)
}

fn cleanup_budget_db(
    db_path: &Path,
    retention: &RetentionConfig,
) -> anyhow::Result<BudgetCleanupSummary> {
    if !db_path.exists() {
        return Ok(BudgetCleanupSummary::default());
    }

    let days = retention
        .ai_proxy_days
        .max(retention.mcp_days)
        .max(retention.agent_app_days);
    let Some(before) = cutoff_datetime(days) else {
        return Ok(BudgetCleanupSummary::default());
    };

    let storage = BudgetStorage::new(db_path)?;
    let deleted = storage.cleanup_old_records(before)?;
    drop(storage);

    let vacuum_ran = maybe_vacuum_budget_db(db_path, retention, deleted)?;
    Ok(BudgetCleanupSummary {
        records_deleted: deleted,
        vacuum_ran,
    })
}

fn maybe_vacuum_event_db(
    conn: &mut Connection,
    retention: &RetentionConfig,
    summary: RetentionSummary,
) -> anyhow::Result<bool> {
    if !retention.vacuum_after_cleanup {
        return Ok(false);
    }

    if summary.total_deleted() < VACUUM_MIN_DELETED_ROWS {
        debug!(
            deleted_rows = summary.total_deleted(),
            threshold = VACUUM_MIN_DELETED_ROWS,
            "Skipping VACUUM (below deletion threshold)"
        );
        return Ok(false);
    }

    ensure_retention_meta_table(conn)?;
    if !vacuum_due(conn, EVENTS_VACUUM_META_KEY)? {
        debug!(
            min_interval_hours = VACUUM_MIN_INTERVAL_HOURS,
            "Skipping VACUUM (minimum interval not reached)"
        );
        return Ok(false);
    }

    conn.execute_batch("VACUUM;")?;
    record_vacuum_run(conn, EVENTS_VACUUM_META_KEY)?;
    info!(
        deleted_rows = summary.total_deleted(),
        "Retention VACUUM completed for events database"
    );
    Ok(true)
}

fn maybe_vacuum_budget_db(
    db_path: &Path,
    retention: &RetentionConfig,
    deleted_rows: usize,
) -> anyhow::Result<bool> {
    if !retention.vacuum_after_cleanup {
        return Ok(false);
    }

    if deleted_rows < BUDGET_VACUUM_MIN_DELETED_ROWS {
        debug!(
            deleted_rows,
            threshold = BUDGET_VACUUM_MIN_DELETED_ROWS,
            "Skipping budget VACUUM (below deletion threshold)"
        );
        return Ok(false);
    }

    let conn = Connection::open(db_path)?;
    conn.busy_timeout(Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS))?;
    ensure_retention_meta_table(&conn)?;
    if !vacuum_due(&conn, BUDGET_VACUUM_META_KEY)? {
        debug!(
            min_interval_hours = VACUUM_MIN_INTERVAL_HOURS,
            "Skipping budget VACUUM (minimum interval not reached)"
        );
        return Ok(false);
    }

    conn.execute_batch("VACUUM;")?;
    record_vacuum_run(&conn, BUDGET_VACUUM_META_KEY)?;
    info!(
        deleted_rows,
        "Retention VACUUM completed for budget database"
    );
    Ok(true)
}

fn ensure_retention_meta_table(conn: &Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS retention_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        "#,
    )?;
    Ok(())
}

fn vacuum_due(conn: &Connection, marker_key: &str) -> anyhow::Result<bool> {
    let last_vacuum: Option<String> = conn
        .query_row(
            "SELECT value FROM retention_meta WHERE key = ?1",
            params![marker_key],
            |row| row.get(0),
        )
        .optional()?;

    let Some(last_vacuum) = last_vacuum else {
        return Ok(true);
    };

    let last_vacuum = chrono::DateTime::parse_from_rfc3339(&last_vacuum)
        .map(|value| value.with_timezone(&Utc))
        .ok();
    let Some(last_vacuum) = last_vacuum else {
        return Ok(true);
    };

    Ok(Utc::now() - last_vacuum >= ChronoDuration::hours(VACUUM_MIN_INTERVAL_HOURS))
}

fn record_vacuum_run(conn: &Connection, marker_key: &str) -> anyhow::Result<()> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        r#"
        INSERT INTO retention_meta (key, value, updated_at)
        VALUES (?1, ?2, ?2)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        "#,
        params![marker_key, now],
    )?;
    Ok(())
}

#[derive(Debug, Default, Clone, Copy)]
struct BudgetCleanupSummary {
    records_deleted: usize,
    vacuum_ran: bool,
}

fn cutoff_datetime(days: u32) -> Option<chrono::DateTime<Utc>> {
    if days == 0 {
        return None;
    }
    Some(Utc::now() - ChronoDuration::days(days as i64))
}

fn cutoff_rfc3339(days: u32) -> Option<String> {
    cutoff_datetime(days).map(|value| value.to_rfc3339())
}

fn cutoff_rollup(days: u32) -> Option<String> {
    cutoff_datetime(days).map(|value| value.format("%Y-%m-%dT%H:%M:00Z").to_string())
}

fn table_exists(conn: &Connection, table: &str) -> anyhow::Result<bool> {
    let exists = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1 LIMIT 1",
            [table],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some();
    Ok(exists)
}

fn resolve_budget_db_path(config: &SothConfig) -> Option<PathBuf> {
    if !config.budget.enabled {
        return None;
    }

    let raw_path = config
        .budget
        .db_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("~/.soth/budget.db"));
    Some(cli_config::expand_tilde(raw_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;
    use soth_budget::TokenUsage;
    use soth_core::types::budget::SpendRecord;
    use tempfile::tempdir;

    #[test]
    fn test_retention_pass_cleans_source_scoped_data_and_budget_records() {
        let dir = tempdir().unwrap();
        let events_db = dir.path().join("events.db");
        let budget_db = dir.path().join("budget.db");

        let conn = Connection::open(&events_db).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE wrap_events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                id TEXT NOT NULL UNIQUE,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                event_json TEXT NOT NULL
            );
            CREATE TABLE wrap_event_payloads (
                event_id TEXT NOT NULL,
                payload_kind TEXT NOT NULL,
                payload BLOB NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (event_id, payload_kind)
            );
            CREATE TABLE event_pending_requests (
                request_key TEXT PRIMARY KEY,
                request_event_id TEXT NOT NULL,
                request_seq INTEGER NOT NULL,
                session_id TEXT NOT NULL,
                source TEXT NOT NULL,
                server_name TEXT NOT NULL,
                method TEXT,
                tool_name TEXT,
                provider TEXT,
                agent TEXT,
                timestamp TEXT NOT NULL
            );
            CREATE TABLE event_pairs (
                pair_id TEXT PRIMARY KEY,
                request_event_id TEXT NOT NULL,
                response_event_id TEXT,
                request_seq INTEGER NOT NULL,
                response_seq INTEGER,
                session_id TEXT NOT NULL,
                source TEXT NOT NULL,
                server_name TEXT NOT NULL,
                method TEXT,
                tool_name TEXT,
                provider TEXT,
                agent TEXT,
                status_code INTEGER,
                latency_ms INTEGER,
                pii_detected INTEGER NOT NULL DEFAULT 0,
                policy_allowed INTEGER,
                timestamp TEXT NOT NULL
            );
            CREATE TABLE event_clusters (
                cluster_id TEXT PRIMARY KEY,
                request_event_id TEXT NOT NULL,
                response_event_id TEXT,
                request_seq INTEGER NOT NULL,
                response_seq INTEGER,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                provider TEXT,
                agent TEXT,
                method TEXT,
                status_code INTEGER,
                latency_ms INTEGER,
                policy_allowed INTEGER,
                pii_detected INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE rollups_1m (
                bucket_start TEXT NOT NULL,
                source TEXT NOT NULL,
                provider TEXT NOT NULL,
                agent TEXT NOT NULL,
                total_events INTEGER NOT NULL DEFAULT 0,
                requests INTEGER NOT NULL DEFAULT 0,
                responses INTEGER NOT NULL DEFAULT 0,
                error_events INTEGER NOT NULL DEFAULT 0,
                pii_events INTEGER NOT NULL DEFAULT 0,
                total_tokens INTEGER NOT NULL DEFAULT 0,
                total_cost_usd REAL NOT NULL DEFAULT 0.0,
                PRIMARY KEY (bucket_start, source, provider, agent)
            );
            "#,
        )
        .unwrap();

        let now = Utc::now();
        let old_10d = (now - ChronoDuration::days(10)).to_rfc3339();
        let old_2d = (now - ChronoDuration::days(2)).to_rfc3339();
        let old_20d = (now - ChronoDuration::days(20)).to_rfc3339();
        let recent = (now - ChronoDuration::hours(8)).to_rfc3339();

        insert_event(&conn, "e-ai-old", &old_10d, "ai_proxy");
        insert_event(&conn, "e-mcp-old", &old_2d, "mcp");
        insert_event(&conn, "e-agent-old", &old_2d, "agent_app");
        insert_event(&conn, "e-ai-new", &recent, "ai_proxy");

        conn.execute(
            "INSERT INTO event_pending_requests (request_key, request_event_id, request_seq, session_id, source, server_name, timestamp)
             VALUES (?1, ?2, 1, 's', 'ai_proxy', 'api.openai.com', ?3)",
            params!["pending-old", "e-ai-old", old_20d],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO event_pending_requests (request_key, request_event_id, request_seq, session_id, source, server_name, timestamp)
             VALUES (?1, ?2, 2, 's', 'ai_proxy', 'api.openai.com', ?3)",
            params!["pending-new", "e-ai-new", recent],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO event_pairs (pair_id, request_event_id, request_seq, session_id, source, server_name, timestamp)
             VALUES (?1, ?2, 1, 's', 'ai_proxy', 'api.openai.com', ?3)",
            params!["pair-old", "e-ai-old", old_20d],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO event_pairs (pair_id, request_event_id, request_seq, session_id, source, server_name, timestamp)
             VALUES (?1, ?2, 2, 's', 'ai_proxy', 'api.openai.com', ?3)",
            params!["pair-new", "e-ai-new", recent],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO event_clusters (cluster_id, request_event_id, request_seq, timestamp, source)
             VALUES (?1, ?2, 1, ?3, 'ai_proxy')",
            params!["cluster-old", "e-ai-old", old_20d],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO event_clusters (cluster_id, request_event_id, request_seq, timestamp, source)
             VALUES (?1, ?2, 2, ?3, 'ai_proxy')",
            params!["cluster-new", "e-ai-new", recent],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO rollups_1m (bucket_start, source, provider, agent, total_events)
             VALUES (?1, 'ai_proxy', 'openai', 'codex', 1)",
            params![(now - ChronoDuration::days(120))
                .format("%Y-%m-%dT%H:%M:00Z")
                .to_string()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO rollups_1m (bucket_start, source, provider, agent, total_events)
             VALUES (?1, 'ai_proxy', 'openai', 'codex', 1)",
            params![(now - ChronoDuration::days(1))
                .format("%Y-%m-%dT%H:%M:00Z")
                .to_string()],
        )
        .unwrap();

        let budget_storage = BudgetStorage::new(&budget_db).unwrap();
        budget_storage
            .save_spend_record(&SpendRecord {
                id: "r-old".to_string(),
                session_id: "s1".to_string(),
                agent_id: None,
                timestamp: now - ChronoDuration::days(20),
                model: "gpt-4o".to_string(),
                token_usage: TokenUsage::new(100, 40),
                cost: 1.2,
                method: Some("POST /v1/messages".to_string()),
            })
            .unwrap();
        budget_storage
            .save_spend_record(&SpendRecord {
                id: "r-new".to_string(),
                session_id: "s2".to_string(),
                agent_id: None,
                timestamp: now - ChronoDuration::days(1),
                model: "gpt-4o".to_string(),
                token_usage: TokenUsage::new(10, 4),
                cost: 0.2,
                method: Some("POST /v1/messages".to_string()),
            })
            .unwrap();

        let retention = RetentionConfig {
            ai_proxy_days: 7,
            mcp_days: 1,
            agent_app_days: 1,
            clusters_days: 14,
            rollups_days: 90,
            vacuum_after_cleanup: false,
        };

        let summary = run_retention_pass(&retention, Some(&events_db), Some(&budget_db));
        assert_eq!(summary.events_deleted, 3);
        assert_eq!(summary.payloads_deleted, 3);
        assert_eq!(summary.pending_deleted, 1);
        assert_eq!(summary.pairs_deleted, 1);
        assert_eq!(summary.clusters_deleted, 1);
        assert_eq!(summary.rollups_deleted, 1);
        assert_eq!(summary.budget_records_deleted, 1);
        assert!(!summary.event_vacuum_ran);
        assert!(!summary.budget_vacuum_ran);

        let remaining_events: i64 = conn
            .query_row("SELECT COUNT(*) FROM wrap_events", [], |row| row.get(0))
            .unwrap();
        let remaining_payloads: i64 = conn
            .query_row("SELECT COUNT(*) FROM wrap_event_payloads", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(remaining_events, 1);
        assert_eq!(remaining_payloads, 1);

        let budget_remaining = budget_storage
            .get_records_since(now - ChronoDuration::days(365))
            .unwrap();
        assert_eq!(budget_remaining.len(), 1);
        assert_eq!(budget_remaining[0].id, "r-new");
    }

    #[test]
    fn test_retention_vacuum_runs_when_enabled_and_threshold_met() {
        let dir = tempdir().unwrap();
        let events_db = dir.path().join("events.db");
        let conn = Connection::open(&events_db).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE wrap_events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                id TEXT NOT NULL UNIQUE,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                event_json TEXT NOT NULL
            );
            CREATE TABLE wrap_event_payloads (
                event_id TEXT NOT NULL,
                payload_kind TEXT NOT NULL,
                payload BLOB NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (event_id, payload_kind)
            );
            "#,
        )
        .unwrap();

        let old = (Utc::now() - ChronoDuration::days(10)).to_rfc3339();
        for idx in 0..300 {
            let id = format!("e-{idx}");
            insert_event(&conn, &id, &old, "ai_proxy");
        }

        let retention = RetentionConfig {
            ai_proxy_days: 1,
            mcp_days: 1,
            agent_app_days: 1,
            clusters_days: 14,
            rollups_days: 90,
            vacuum_after_cleanup: true,
        };

        let summary = run_retention_pass(&retention, Some(&events_db), None);
        assert!(summary.total_deleted() >= VACUUM_MIN_DELETED_ROWS);
        assert!(summary.event_vacuum_ran);

        let last_vacuum: Option<String> = conn
            .query_row(
                "SELECT value FROM retention_meta WHERE key=?1",
                params![EVENTS_VACUUM_META_KEY],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        assert!(last_vacuum.is_some());
    }

    #[test]
    fn test_retention_vacuum_is_rate_limited() {
        let dir = tempdir().unwrap();
        let events_db = dir.path().join("events.db");
        let conn = Connection::open(&events_db).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE wrap_events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                id TEXT NOT NULL UNIQUE,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                event_json TEXT NOT NULL
            );
            CREATE TABLE wrap_event_payloads (
                event_id TEXT NOT NULL,
                payload_kind TEXT NOT NULL,
                payload BLOB NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (event_id, payload_kind)
            );
            "#,
        )
        .unwrap();

        let old = (Utc::now() - ChronoDuration::days(10)).to_rfc3339();
        for idx in 0..300 {
            let id = format!("run1-{idx}");
            insert_event(&conn, &id, &old, "ai_proxy");
        }

        let retention = RetentionConfig {
            ai_proxy_days: 1,
            mcp_days: 1,
            agent_app_days: 1,
            clusters_days: 14,
            rollups_days: 90,
            vacuum_after_cleanup: true,
        };

        let first = run_retention_pass(&retention, Some(&events_db), None);
        assert!(first.event_vacuum_ran);

        for idx in 0..300 {
            let id = format!("run2-{idx}");
            insert_event(&conn, &id, &old, "ai_proxy");
        }

        let second = run_retention_pass(&retention, Some(&events_db), None);
        assert!(second.total_deleted() >= VACUUM_MIN_DELETED_ROWS);
        assert!(
            !second.event_vacuum_ran,
            "vacuum should be skipped due to min interval"
        );
    }

    #[test]
    fn test_budget_vacuum_runs_when_enabled_and_threshold_met() {
        let dir = tempdir().unwrap();
        let budget_db = dir.path().join("budget.db");
        let storage = BudgetStorage::new(&budget_db).unwrap();
        let now = Utc::now();
        for idx in 0..150 {
            storage
                .save_spend_record(&SpendRecord {
                    id: format!("old-{idx}"),
                    session_id: "s1".to_string(),
                    agent_id: None,
                    timestamp: now - ChronoDuration::days(30),
                    model: "gpt-4o".to_string(),
                    token_usage: TokenUsage::new(5, 2),
                    cost: 0.01,
                    method: Some("POST /v1/messages".to_string()),
                })
                .unwrap();
        }
        for idx in 0..3 {
            storage
                .save_spend_record(&SpendRecord {
                    id: format!("new-{idx}"),
                    session_id: "s2".to_string(),
                    agent_id: None,
                    timestamp: now - ChronoDuration::hours(6),
                    model: "gpt-4o".to_string(),
                    token_usage: TokenUsage::new(5, 2),
                    cost: 0.01,
                    method: Some("POST /v1/messages".to_string()),
                })
                .unwrap();
        }
        drop(storage);

        let retention = RetentionConfig {
            ai_proxy_days: 7,
            mcp_days: 7,
            agent_app_days: 7,
            clusters_days: 14,
            rollups_days: 90,
            vacuum_after_cleanup: true,
        };

        let summary = run_retention_pass(&retention, None, Some(&budget_db));
        assert!(summary.budget_records_deleted >= BUDGET_VACUUM_MIN_DELETED_ROWS);
        assert!(summary.budget_vacuum_ran);

        let conn = Connection::open(&budget_db).unwrap();
        let last_vacuum: Option<String> = conn
            .query_row(
                "SELECT value FROM retention_meta WHERE key=?1",
                params![BUDGET_VACUUM_META_KEY],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        assert!(last_vacuum.is_some());
    }

    fn insert_event(conn: &Connection, id: &str, timestamp: &str, source: &str) {
        let event_json = format!(r#"{{"id":"{id}","source":"{source}"}}"#);
        conn.execute(
            "INSERT INTO wrap_events (id, session_id, timestamp, event_json) VALUES (?1, 's', ?2, ?3)",
            params![id, timestamp, event_json],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO wrap_event_payloads (event_id, payload_kind, payload, created_at)
             VALUES (?1, 'request', x'01', ?2)",
            params![id, timestamp],
        )
        .unwrap();
    }
}
