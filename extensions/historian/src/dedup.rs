use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use crate::error::HistorianError;
use crate::types::AiTool;

/// Deduplication checker backed by historian.db `already_processed` table.
///
/// Uses `Mutex<Connection>` so it can be shared across async tasks via `Arc`.
pub struct DedupChecker {
    conn: Mutex<Connection>,
}

// Safety: Connection is guarded by Mutex, so only one thread accesses it at a time.
unsafe impl Send for DedupChecker {}
unsafe impl Sync for DedupChecker {}

impl DedupChecker {
    pub fn new(conn: Connection) -> Self {
        Self {
            conn: Mutex::new(conn),
        }
    }

    /// Check if this specific message has already been processed.
    ///
    /// Dedup layers (checked in order):
    /// 1. Primary: exact (tool, session, index) match
    /// 2. Secondary: semantic_hash within a timestamp window (catches near-dups across sessions)
    /// 3. Tertiary: exact content_hash match (catches verbatim cross-session dups)
    pub fn is_duplicate(
        &self,
        tool: &AiTool,
        session_id: &str,
        message_index: u32,
        semantic_hash: Option<&str>,
        content_hash: &str,
        timestamp: i64,
    ) -> bool {
        let conn = match self.conn.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!("dedup mutex poisoned, recovering");
                poisoned.into_inner()
            }
        };

        // Primary: exact (tool, session, index, content_hash) match.
        // Content-aware: a long-lived session (Cursor composer, Claude Code
        // thread) keeps growing, each new turn produces a new content_hash.
        // If we matched only on (tool, session, index), the first emission
        // would freeze the session forever. The tertiary content_hash check
        // below still suppresses true verbatim re-emissions.
        let primary: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM already_processed
                 WHERE tool_type = ?1
                   AND session_id = ?2
                   AND message_index = ?3
                   AND content_hash = ?4",
                params![tool.key(), session_id, message_index, content_hash],
                |row| row.get(0),
            )
            .optional()
            .unwrap_or(None);

        if primary.is_some() {
            return true;
        }

        // Secondary: semantic hash within ±5 min window
        if let Some(shash) = semantic_hash {
            let window_ms: i64 = 5 * 60 * 1000;
            let lo = timestamp.saturating_sub(window_ms);
            let hi = timestamp.saturating_add(window_ms);
            let semantic_dup: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM already_processed
                     WHERE semantic_hash = ?1
                       AND processed_at BETWEEN ?2 AND ?3
                     LIMIT 1",
                    params![shash, lo / 1000, hi / 1000],
                    |row| row.get(0),
                )
                .optional()
                .unwrap_or(None);
            if semantic_dup.is_some() {
                return true;
            }
        }

        // Tertiary: exact content hash match (catches cross-session dups)
        let content_dup: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM already_processed
                 WHERE content_hash = ?1 LIMIT 1",
                params![content_hash],
                |row| row.get(0),
            )
            .optional()
            .unwrap_or(None);

        content_dup.is_some()
    }

    /// Record that a message was processed and emitted as the given event.
    pub fn mark_processed(
        &self,
        tool: &AiTool,
        session_id: &str,
        message_index: u32,
        event_id: Uuid,
        content_hash: &str,
    ) -> Result<(), HistorianError> {
        self.mark_processed_with_semantic(
            tool,
            session_id,
            message_index,
            event_id,
            content_hash,
            None,
        )
    }

    /// Record with optional semantic hash for near-duplicate detection.
    pub fn mark_processed_with_semantic(
        &self,
        tool: &AiTool,
        session_id: &str,
        message_index: u32,
        event_id: Uuid,
        content_hash: &str,
        semantic_hash: Option<&str>,
    ) -> Result<(), HistorianError> {
        let conn = match self.conn.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!("dedup mutex poisoned, recovering");
                poisoned.into_inner()
            }
        };
        let now = chrono::Utc::now().timestamp();
        // UPSERT: when a session grows, the existing row at
        // (tool, session, index) holds the OLD content_hash. We overwrite
        // it with the new content_hash + new event_id so the next dedup
        // primary check correctly says "yes, that exact content was seen".
        conn.execute(
            "INSERT INTO already_processed
             (tool_type, session_id, message_index, event_id, content_hash, semantic_hash, processed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(tool_type, session_id, message_index)
             DO UPDATE SET
                event_id      = excluded.event_id,
                content_hash  = excluded.content_hash,
                semantic_hash = excluded.semantic_hash,
                processed_at  = excluded.processed_at",
            params![
                tool.key(),
                session_id,
                message_index,
                event_id.to_string(),
                content_hash,
                semantic_hash.unwrap_or(""),
                now,
            ],
        )?;
        Ok(())
    }

    /// Count of processed entries for a given tool.
    pub fn processed_count(&self, tool: &AiTool) -> u64 {
        let conn = match self.conn.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!("dedup mutex poisoned, recovering");
                poisoned.into_inner()
            }
        };
        conn.query_row(
            "SELECT COUNT(*) FROM already_processed WHERE tool_type = ?1",
            params![tool.key()],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0) as u64
    }

    /// Total count of all processed entries across all tools.
    pub fn total_processed(&self) -> u64 {
        let conn = match self.conn.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!("dedup mutex poisoned, recovering");
                poisoned.into_inner()
            }
        };
        conn.query_row("SELECT COUNT(*) FROM already_processed", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap_or(0) as u64
    }

    /// Per-tool breakdown of processed counts.
    pub fn stats_by_tool(&self) -> Vec<(String, u64)> {
        let conn = match self.conn.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!("dedup mutex poisoned, recovering");
                poisoned.into_inner()
            }
        };
        let mut stmt = match conn.prepare(
            "SELECT tool_type, COUNT(*) FROM already_processed GROUP BY tool_type ORDER BY tool_type",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(err = %e, "dedup stats_by_tool: prepare failed");
                return Vec::new();
            }
        };
        let result: Vec<(String, u64)> = match stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
        }) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(e) => {
                tracing::warn!(err = %e, "dedup stats_by_tool: query_map failed");
                Vec::new()
            }
        };
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use tempfile::TempDir;

    fn make_checker() -> (DedupChecker, TempDir) {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("historian.db");
        let conn = Connection::open(&db_path).unwrap();
        db::init_schema(&conn).unwrap();
        (DedupChecker::new(conn), tmp)
    }

    #[test]
    fn new_message_is_not_duplicate() {
        let (checker, _tmp) = make_checker();
        assert!(!checker.is_duplicate(
            &AiTool::ClaudeCode,
            "sess1",
            0,
            None,
            "hash_a",
            1700000000000,
        ));
    }

    #[test]
    fn marked_message_is_duplicate() {
        let (checker, _tmp) = make_checker();
        checker
            .mark_processed(&AiTool::ClaudeCode, "sess1", 0, Uuid::new_v4(), "hash_a")
            .unwrap();
        assert!(checker.is_duplicate(
            &AiTool::ClaudeCode,
            "sess1",
            0,
            None,
            "hash_a",
            1700000000000,
        ));
    }

    #[test]
    fn content_hash_dedup_across_sessions() {
        let (checker, _tmp) = make_checker();
        checker
            .mark_processed(&AiTool::ClaudeCode, "sess1", 0, Uuid::new_v4(), "hash_x")
            .unwrap();
        // Different session but same content hash → duplicate
        assert!(checker.is_duplicate(
            &AiTool::GeminiCli,
            "sess_other",
            0,
            None,
            "hash_x",
            1700000000000,
        ));
    }

    #[test]
    fn processed_count_tracks_inserts() {
        let (checker, _tmp) = make_checker();
        assert_eq!(checker.processed_count(&AiTool::ClaudeCode), 0);
        checker
            .mark_processed(&AiTool::ClaudeCode, "s1", 0, Uuid::new_v4(), "h1")
            .unwrap();
        checker
            .mark_processed(&AiTool::ClaudeCode, "s1", 1, Uuid::new_v4(), "h2")
            .unwrap();
        assert_eq!(checker.processed_count(&AiTool::ClaudeCode), 2);
        assert_eq!(checker.processed_count(&AiTool::GeminiCli), 0);
    }

    #[test]
    fn semantic_hash_dedup_within_time_window() {
        let (checker, _tmp) = make_checker();
        let now = chrono::Utc::now().timestamp_millis();

        // Mark with semantic hash
        checker
            .mark_processed_with_semantic(
                &AiTool::ClaudeCode,
                "s1",
                0,
                Uuid::new_v4(),
                "content_a",
                Some("semantic_x"),
            )
            .unwrap();

        // Different session, different content, but same semantic hash within window
        assert!(checker.is_duplicate(
            &AiTool::GeminiCli,
            "s_different",
            0,
            Some("semantic_x"),
            "content_b_totally_different",
            now,
        ));
    }

    #[test]
    fn semantic_hash_no_false_positives_without_hash() {
        let (checker, _tmp) = make_checker();
        let now = chrono::Utc::now().timestamp_millis();

        checker
            .mark_processed_with_semantic(
                &AiTool::ClaudeCode,
                "s1",
                0,
                Uuid::new_v4(),
                "content_a",
                Some("semantic_x"),
            )
            .unwrap();

        // Without semantic hash, should not match via semantic dedup
        // (but content_b is different from content_a, so no tertiary match either)
        assert!(!checker.is_duplicate(&AiTool::GeminiCli, "s_new", 0, None, "content_b", now,));
    }

    #[test]
    fn total_processed_counts_all_tools() {
        let (checker, _tmp) = make_checker();
        checker
            .mark_processed(&AiTool::ClaudeCode, "s1", 0, Uuid::new_v4(), "h1")
            .unwrap();
        checker
            .mark_processed(&AiTool::GeminiCli, "s2", 0, Uuid::new_v4(), "h2")
            .unwrap();
        assert_eq!(checker.total_processed(), 2);
    }

    #[test]
    fn stats_by_tool_returns_breakdown() {
        let (checker, _tmp) = make_checker();
        checker
            .mark_processed(&AiTool::ClaudeCode, "s1", 0, Uuid::new_v4(), "h1")
            .unwrap();
        checker
            .mark_processed(&AiTool::ClaudeCode, "s1", 1, Uuid::new_v4(), "h2")
            .unwrap();
        checker
            .mark_processed(&AiTool::GeminiCli, "s2", 0, Uuid::new_v4(), "h3")
            .unwrap();
        let stats = checker.stats_by_tool();
        assert_eq!(stats.len(), 2);
        assert!(stats.iter().any(|(t, c)| t == "claude_code" && *c == 2));
        assert!(stats.iter().any(|(t, c)| t == "gemini_cli" && *c == 1));
    }

    #[test]
    fn reconstruct_then_dedup_integration() {
        use crate::session::reconstruct_event;
        use crate::types::{HistoricalMessage, HistoricalSession};

        let (checker, _tmp) = make_checker();

        let session = HistoricalSession {
            tool: AiTool::ClaudeCode,
            session_id: "int-test-1".to_string(),
            messages: vec![
                HistoricalMessage {
                    role: "user".to_string(),
                    content: "refactor auth".to_string(),
                    timestamp: Some(1700000000000),
                    token_estimate: 3,
                },
                HistoricalMessage {
                    role: "assistant".to_string(),
                    content: "Done.".to_string(),
                    timestamp: Some(1700000001000),
                    token_estimate: 1,
                },
            ],
            started_at: Some(1700000000000),
            ended_at: Some(1700000001000),
        };

        let event = reconstruct_event(&session);
        let content_hash = event.context.metadata.get("conversation_hash").unwrap();
        let semantic_hash = event
            .context
            .metadata
            .get("semantic_hash")
            .map(|s| s.as_str());

        // First time: not a duplicate
        assert!(!checker.is_duplicate(
            &session.tool,
            &session.session_id,
            0,
            semantic_hash,
            content_hash,
            session.started_at.unwrap(),
        ));

        // Mark processed
        checker
            .mark_processed_with_semantic(
                &session.tool,
                &session.session_id,
                0,
                event.event_id,
                content_hash,
                semantic_hash,
            )
            .unwrap();

        // Second time: duplicate by primary key
        assert!(checker.is_duplicate(
            &session.tool,
            &session.session_id,
            0,
            semantic_hash,
            content_hash,
            session.started_at.unwrap(),
        ));

        // Different session, same content: duplicate by content hash
        assert!(checker.is_duplicate(
            &AiTool::GeminiCli,
            "different-session",
            0,
            None,
            content_hash,
            session.started_at.unwrap(),
        ));
    }
}
