//! Budget storage module - SQLite persistence for spend tracking

use crate::{Result, SothError};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use soth_core::types::budget::{
    BudgetScope, BudgetState, DailyTrendPoint, SpendRecord,
    SpendRequestType, TaggedSpendRecord, TokenUsage, ToolCostEntry,
};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

/// Helper to convert rusqlite errors
fn db_err(e: rusqlite::Error) -> SothError {
    SothError::Database(e.to_string())
}

/// Budget storage with SQLite backend
pub struct BudgetStorage {
    /// Database connection
    conn: Mutex<Connection>,
}

impl BudgetStorage {
    /// Create a new budget storage at the given path
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path).map_err(db_err)?;
        let storage = Self {
            conn: Mutex::new(conn),
        };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Create an in-memory budget storage (for testing)
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(db_err)?;
        let storage = Self {
            conn: Mutex::new(conn),
        };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Initialize database schema
    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| SothError::Internal("Lock poisoned".into()))?;

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS spend_records (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                agent_id TEXT,
                timestamp TEXT NOT NULL,
                model TEXT NOT NULL,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                cost REAL NOT NULL,
                method TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_spend_session ON spend_records(session_id);
            CREATE INDEX IF NOT EXISTS idx_spend_agent ON spend_records(agent_id);
            CREATE INDEX IF NOT EXISTS idx_spend_timestamp ON spend_records(timestamp);

            CREATE TABLE IF NOT EXISTS budget_states (
                id TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                daily_limit REAL,
                weekly_limit REAL,
                monthly_limit REAL,
                current_spend REAL NOT NULL DEFAULT 0,
                total_tokens INTEGER NOT NULL DEFAULT 0,
                total_requests INTEGER NOT NULL DEFAULT 0,
                period_start TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alert_history (
                id TEXT PRIMARY KEY,
                budget_id TEXT NOT NULL,
                threshold_percent INTEGER NOT NULL,
                current_spend REAL NOT NULL,
                budget_limit REAL NOT NULL,
                action TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (budget_id) REFERENCES budget_states(id)
            );

            CREATE INDEX IF NOT EXISTS idx_alert_budget ON alert_history(budget_id);
            CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON alert_history(timestamp);

            -- Cost tags table (many-to-many with spend_records)
            CREATE TABLE IF NOT EXISTS cost_tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id TEXT NOT NULL,
                tag_key TEXT NOT NULL,
                tag_value TEXT NOT NULL,
                UNIQUE(record_id, tag_key)
            );

            CREATE INDEX IF NOT EXISTS idx_tags_key_value ON cost_tags(tag_key, tag_value);
            CREATE INDEX IF NOT EXISTS idx_tags_record ON cost_tags(record_id);

            -- MCP attribution table
            CREATE TABLE IF NOT EXISTS mcp_attribution (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id TEXT NOT NULL UNIQUE,
                mcp_tool TEXT NOT NULL,
                mcp_server TEXT NOT NULL,
                mcp_session_id TEXT,
                request_type TEXT NOT NULL DEFAULT 'ai_inference'
            );

            CREATE INDEX IF NOT EXISTS idx_mcp_tool ON mcp_attribution(mcp_tool);
            CREATE INDEX IF NOT EXISTS idx_mcp_server ON mcp_attribution(mcp_server);

            -- Daily cost aggregates (materialized for performance)
            CREATE TABLE IF NOT EXISTS daily_cost_aggregates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                provider TEXT NOT NULL DEFAULT 'unknown',
                model TEXT NOT NULL,
                agent_id TEXT NOT NULL DEFAULT '',
                total_cost REAL NOT NULL DEFAULT 0,
                total_input_tokens INTEGER NOT NULL DEFAULT 0,
                total_output_tokens INTEGER NOT NULL DEFAULT 0,
                request_count INTEGER NOT NULL DEFAULT 0,
                UNIQUE (date, provider, model, agent_id)
            );

            CREATE INDEX IF NOT EXISTS idx_daily_date ON daily_cost_aggregates(date);
            CREATE INDEX IF NOT EXISTS idx_daily_provider ON daily_cost_aggregates(provider);
            "#,
        ).map_err(db_err)?;

        Ok(())
    }

    /// Save a spend record
    pub fn save_spend_record(&self, record: &SpendRecord) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| SothError::Internal("Lock poisoned".into()))?;

        conn.execute(
            r#"
            INSERT INTO spend_records (id, session_id, agent_id, timestamp, model, input_tokens, output_tokens, cost, method)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                record.id,
                record.session_id,
                record.agent_id,
                record.timestamp.to_rfc3339(),
                record.model,
                record.token_usage.input_tokens as i64,
                record.token_usage.output_tokens as i64,
                record.cost,
                record.method,
            ],
        ).map_err(db_err)?;

        Ok(())
    }

    /// Get spend records for a session
    pub fn get_session_records(&self, session_id: &str) -> Result<Vec<SpendRecord>> {
        let conn = self.conn.lock().map_err(|_| SothError::Internal("Lock poisoned".into()))?;

        let mut stmt = conn.prepare(
            r#"
            SELECT id, session_id, agent_id, timestamp, model, input_tokens, output_tokens, cost, method
            FROM spend_records
            WHERE session_id = ?1
            ORDER BY timestamp ASC
            "#,
        ).map_err(db_err)?;

        let records = stmt
            .query_map(params![session_id], |row| {
                Ok(SpendRecord {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    agent_id: row.get(2)?,
                    timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(3)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    model: row.get(4)?,
                    token_usage: TokenUsage::new(
                        row.get::<_, i64>(5)? as u64,
                        row.get::<_, i64>(6)? as u64,
                    ),
                    cost: row.get(7)?,
                    method: row.get(8)?,
                })
            }).map_err(db_err)?
            .collect::<std::result::Result<Vec<_>, _>>().map_err(db_err)?;

        Ok(records)
    }

    /// Get spend records since a timestamp
    pub fn get_records_since(&self, since: DateTime<Utc>) -> Result<Vec<SpendRecord>> {
        let conn = self.conn.lock().map_err(|_| SothError::Internal("Lock poisoned".into()))?;

        let mut stmt = conn.prepare(
            r#"
            SELECT id, session_id, agent_id, timestamp, model, input_tokens, output_tokens, cost, method
            FROM spend_records
            WHERE timestamp >= ?1
            ORDER BY timestamp ASC
            "#,
        ).map_err(db_err)?;

        let records = stmt
            .query_map(params![since.to_rfc3339()], |row| {
                Ok(SpendRecord {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    agent_id: row.get(2)?,
                    timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(3)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    model: row.get(4)?,
                    token_usage: TokenUsage::new(
                        row.get::<_, i64>(5)? as u64,
                        row.get::<_, i64>(6)? as u64,
                    ),
                    cost: row.get(7)?,
                    method: row.get(8)?,
                })
            }).map_err(db_err)?
            .collect::<std::result::Result<Vec<_>, _>>().map_err(db_err)?;

        Ok(records)
    }

    /// Get total spend since a timestamp
    pub fn get_total_spend_since(&self, since: DateTime<Utc>) -> Result<f64> {
        let conn = self.conn.lock().map_err(|_| SothError::Internal("Lock poisoned".into()))?;

        let total: f64 = conn.query_row(
            "SELECT COALESCE(SUM(cost), 0) FROM spend_records WHERE timestamp >= ?1",
            params![since.to_rfc3339()],
            |row| row.get(0),
        ).map_err(db_err)?;

        Ok(total)
    }

    /// Get spend for an agent since a timestamp
    pub fn get_agent_spend_since(&self, agent_id: &str, since: DateTime<Utc>) -> Result<f64> {
        let conn = self.conn.lock().map_err(|_| SothError::Internal("Lock poisoned".into()))?;

        let total: f64 = conn.query_row(
            "SELECT COALESCE(SUM(cost), 0) FROM spend_records WHERE agent_id = ?1 AND timestamp >= ?2",
            params![agent_id, since.to_rfc3339()],
            |row| row.get(0),
        ).map_err(db_err)?;

        Ok(total)
    }

    /// Save a budget state
    pub fn save_budget_state(&self, budget: &BudgetState) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| SothError::Internal("Lock poisoned".into()))?;

        conn.execute(
            r#"
            INSERT OR REPLACE INTO budget_states
            (id, scope, daily_limit, weekly_limit, monthly_limit, current_spend, total_tokens, total_requests, period_start, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            params![
                budget.id,
                format!("{:?}", budget.scope),
                budget.daily_limit,
                budget.weekly_limit,
                budget.monthly_limit,
                budget.current_spend,
                budget.total_tokens as i64,
                budget.total_requests as i64,
                budget.period_start.to_rfc3339(),
                budget.updated_at.to_rfc3339(),
            ],
        ).map_err(db_err)?;

        Ok(())
    }

    /// Get a budget state by ID
    pub fn get_budget_state(&self, id: &str) -> Result<Option<BudgetState>> {
        let conn = self.conn.lock().map_err(|_| SothError::Internal("Lock poisoned".into()))?;

        let result = conn
            .query_row(
                r#"
                SELECT id, scope, daily_limit, weekly_limit, monthly_limit, current_spend, total_tokens, total_requests, period_start, updated_at
                FROM budget_states
                WHERE id = ?1
                "#,
                params![id],
                |row| {
                    let scope_str: String = row.get(1)?;
                    let scope = match scope_str.as_str() {
                        "Global" => BudgetScope::Global,
                        "PerAgent" => BudgetScope::PerAgent,
                        "PerSession" => BudgetScope::PerSession,
                        "PerModel" => BudgetScope::PerModel,
                        _ => BudgetScope::Global,
                    };

                    Ok(BudgetState {
                        id: row.get(0)?,
                        scope,
                        daily_limit: row.get(2)?,
                        weekly_limit: row.get(3)?,
                        monthly_limit: row.get(4)?,
                        current_spend: row.get(5)?,
                        total_tokens: row.get::<_, i64>(6)? as u64,
                        total_requests: row.get::<_, i64>(7)? as u64,
                        period_start: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                            .map(|dt| dt.with_timezone(&Utc))
                            .unwrap_or_else(|_| Utc::now()),
                        updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                            .map(|dt| dt.with_timezone(&Utc))
                            .unwrap_or_else(|_| Utc::now()),
                    })
                },
            )
            .optional().map_err(db_err)?;

        Ok(result)
    }

    /// Get all budget states
    pub fn get_all_budget_states(&self) -> Result<Vec<BudgetState>> {
        let conn = self.conn.lock().map_err(|_| SothError::Internal("Lock poisoned".into()))?;

        let mut stmt = conn.prepare(
            r#"
            SELECT id, scope, daily_limit, weekly_limit, monthly_limit, current_spend, total_tokens, total_requests, period_start, updated_at
            FROM budget_states
            "#,
        ).map_err(db_err)?;

        let budgets = stmt
            .query_map([], |row| {
                let scope_str: String = row.get(1)?;
                let scope = match scope_str.as_str() {
                    "Global" => BudgetScope::Global,
                    "PerAgent" => BudgetScope::PerAgent,
                    "PerSession" => BudgetScope::PerSession,
                    "PerModel" => BudgetScope::PerModel,
                    _ => BudgetScope::Global,
                };

                Ok(BudgetState {
                    id: row.get(0)?,
                    scope,
                    daily_limit: row.get(2)?,
                    weekly_limit: row.get(3)?,
                    monthly_limit: row.get(4)?,
                    current_spend: row.get(5)?,
                    total_tokens: row.get::<_, i64>(6)? as u64,
                    total_requests: row.get::<_, i64>(7)? as u64,
                    period_start: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                })
            }).map_err(db_err)?
            .collect::<std::result::Result<Vec<_>, _>>().map_err(db_err)?;

        Ok(budgets)
    }

    /// Delete spend records older than a timestamp
    pub fn cleanup_old_records(&self, before: DateTime<Utc>) -> Result<usize> {
        let conn = self.conn.lock().map_err(|_| SothError::Internal("Lock poisoned".into()))?;

        let deleted = conn.execute(
            "DELETE FROM spend_records WHERE timestamp < ?1",
            params![before.to_rfc3339()],
        ).map_err(db_err)?;

        Ok(deleted)
    }

    /// Get spending summary by model
    pub fn get_spend_by_model(&self, since: DateTime<Utc>) -> Result<Vec<(String, f64, u64)>> {
        let conn = self.conn.lock().map_err(|_| SothError::Internal("Lock poisoned".into()))?;

        let mut stmt = conn.prepare(
            r#"
            SELECT model, SUM(cost) as total_cost, SUM(input_tokens + output_tokens) as total_tokens
            FROM spend_records
            WHERE timestamp >= ?1
            GROUP BY model
            ORDER BY total_cost DESC
            "#,
        ).map_err(db_err)?;

        let results = stmt
            .query_map(params![since.to_rfc3339()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, f64>(1)?,
                    row.get::<_, i64>(2)? as u64,
                ))
            }).map_err(db_err)?
            .collect::<std::result::Result<Vec<_>, _>>().map_err(db_err)?;

        Ok(results)
    }

    /// Get spending summary by agent
    pub fn get_spend_by_agent(&self, since: DateTime<Utc>) -> Result<Vec<(String, f64, u64)>> {
        let conn = self.conn.lock().map_err(|_| SothError::Internal("Lock poisoned".into()))?;

        let mut stmt = conn.prepare(
            r#"
            SELECT COALESCE(agent_id, 'unknown') as agent, SUM(cost) as total_cost, COUNT(*) as request_count
            FROM spend_records
            WHERE timestamp >= ?1
            GROUP BY agent_id
            ORDER BY total_cost DESC
            "#,
        ).map_err(db_err)?;

        let results = stmt
            .query_map(params![since.to_rfc3339()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, f64>(1)?,
                    row.get::<_, i64>(2)? as u64,
                ))
            }).map_err(db_err)?
            .collect::<std::result::Result<Vec<_>, _>>().map_err(db_err)?;

        Ok(results)
    }

    // ========================================================================
    // Tagged Spend Records (Advanced Budgeting)
    // ========================================================================

    /// Save a tagged spend record with MCP attribution
    pub fn save_tagged_spend_record(&self, record: &TaggedSpendRecord) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| SothError::Internal("Lock poisoned".into()))?;

        // Save base spend record
        conn.execute(
            r#"
            INSERT INTO spend_records (id, session_id, agent_id, timestamp, model, input_tokens, output_tokens, cost, method)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                record.record.id,
                record.record.session_id,
                record.record.agent_id,
                record.record.timestamp.to_rfc3339(),
                record.record.model,
                record.record.token_usage.input_tokens as i64,
                record.record.token_usage.output_tokens as i64,
                record.record.cost,
                record.record.method,
            ],
        ).map_err(db_err)?;

        // Save tags
        for tag in &record.tags {
            conn.execute(
                "INSERT OR REPLACE INTO cost_tags (record_id, tag_key, tag_value) VALUES (?1, ?2, ?3)",
                params![record.record.id, tag.key, tag.value],
            ).map_err(db_err)?;
        }

        // Save MCP attribution if present
        if record.mcp_tool.is_some() || record.mcp_server.is_some() {
            let request_type = match record.request_type {
                SpendRequestType::AiInference => "ai_inference",
                SpendRequestType::McpInference => "mcp_inference",
            };
            conn.execute(
                r#"
                INSERT OR REPLACE INTO mcp_attribution (record_id, mcp_tool, mcp_server, mcp_session_id, request_type)
                VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                params![
                    record.record.id,
                    record.mcp_tool.as_deref().unwrap_or(""),
                    record.mcp_server.as_deref().unwrap_or(""),
                    record.mcp_session_id,
                    request_type,
                ],
            ).map_err(db_err)?;
        }

        // Update daily aggregate
        let date = record.record.timestamp.format("%Y-%m-%d").to_string();
        let provider = record.provider.as_deref().unwrap_or("unknown");
        let agent_id = record.record.agent_id.as_deref().unwrap_or("");
        conn.execute(
            r#"
            INSERT INTO daily_cost_aggregates (date, provider, model, agent_id, total_cost, total_input_tokens, total_output_tokens, request_count)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)
            ON CONFLICT(date, provider, model, agent_id)
            DO UPDATE SET
                total_cost = total_cost + excluded.total_cost,
                total_input_tokens = total_input_tokens + excluded.total_input_tokens,
                total_output_tokens = total_output_tokens + excluded.total_output_tokens,
                request_count = request_count + 1
            "#,
            params![
                date,
                provider,
                record.record.model,
                agent_id,
                record.record.cost,
                record.record.token_usage.input_tokens as i64,
                record.record.token_usage.output_tokens as i64,
            ],
        ).map_err(db_err)?;

        Ok(())
    }

    /// Get cost breakdown by tag for a time period
    pub fn get_cost_by_tag(&self, tag_key: &str, since: DateTime<Utc>) -> Result<Vec<(String, f64, u64)>> {
        let conn = self.conn.lock().map_err(|_| SothError::Internal("Lock poisoned".into()))?;

        let mut stmt = conn.prepare(
            r#"
            SELECT ct.tag_value, SUM(sr.cost) as total_cost, COUNT(*) as request_count
            FROM spend_records sr
            INNER JOIN cost_tags ct ON sr.id = ct.record_id
            WHERE ct.tag_key = ?1 AND sr.timestamp >= ?2
            GROUP BY ct.tag_value
            ORDER BY total_cost DESC
            "#,
        ).map_err(db_err)?;

        let results = stmt
            .query_map(params![tag_key, since.to_rfc3339()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, f64>(1)?,
                    row.get::<_, i64>(2)? as u64,
                ))
            }).map_err(db_err)?
            .collect::<std::result::Result<Vec<_>, _>>().map_err(db_err)?;

        Ok(results)
    }

    /// Get cost breakdown by MCP tool
    pub fn get_cost_by_mcp_tool(&self, since: DateTime<Utc>) -> Result<Vec<ToolCostEntry>> {
        let conn = self.conn.lock().map_err(|_| SothError::Internal("Lock poisoned".into()))?;

        let mut stmt = conn.prepare(
            r#"
            SELECT ma.mcp_tool, ma.mcp_server, SUM(sr.cost) as total_cost, COUNT(*) as call_count
            FROM spend_records sr
            INNER JOIN mcp_attribution ma ON sr.id = ma.record_id
            WHERE sr.timestamp >= ?1 AND ma.mcp_tool != ''
            GROUP BY ma.mcp_tool, ma.mcp_server
            ORDER BY total_cost DESC
            "#,
        ).map_err(db_err)?;

        let results = stmt
            .query_map(params![since.to_rfc3339()], |row| {
                let total_cost: f64 = row.get(2)?;
                let call_count: i64 = row.get(3)?;
                Ok(ToolCostEntry {
                    tool_name: row.get(0)?,
                    server_name: row.get(1)?,
                    total_cost,
                    call_count: call_count as u64,
                    avg_cost_per_call: if call_count > 0 {
                        total_cost / call_count as f64
                    } else {
                        0.0
                    },
                })
            }).map_err(db_err)?
            .collect::<std::result::Result<Vec<_>, _>>().map_err(db_err)?;

        Ok(results)
    }

    /// Get cost breakdown by request type (ai_inference vs mcp_inference)
    pub fn get_cost_by_request_type(&self, since: DateTime<Utc>) -> Result<HashMap<String, f64>> {
        let conn = self.conn.lock().map_err(|_| SothError::Internal("Lock poisoned".into()))?;

        let mut stmt = conn.prepare(
            r#"
            SELECT COALESCE(ma.request_type, 'ai_inference') as req_type, SUM(sr.cost) as total_cost
            FROM spend_records sr
            LEFT JOIN mcp_attribution ma ON sr.id = ma.record_id
            WHERE sr.timestamp >= ?1
            GROUP BY req_type
            "#,
        ).map_err(db_err)?;

        let mut results = HashMap::new();
        let rows = stmt.query_map(params![since.to_rfc3339()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?))
        }).map_err(db_err)?;

        for row in rows {
            let (req_type, cost) = row.map_err(db_err)?;
            results.insert(req_type, cost);
        }

        Ok(results)
    }

    /// Get daily cost trend
    pub fn get_daily_trend(&self, days: u32, provider: Option<&str>) -> Result<Vec<DailyTrendPoint>> {
        let conn = self.conn.lock().map_err(|_| SothError::Internal("Lock poisoned".into()))?;

        let since = Utc::now() - chrono::Duration::days(days as i64);
        let since_date = since.format("%Y-%m-%d").to_string();

        let (sql, params_vec): (&str, Vec<String>) = if let Some(p) = provider {
            (
                r#"
                SELECT date, SUM(total_cost) as cost, SUM(total_input_tokens + total_output_tokens) as tokens, SUM(request_count) as requests
                FROM daily_cost_aggregates
                WHERE date >= ?1 AND provider = ?2
                GROUP BY date
                ORDER BY date ASC
                "#,
                vec![since_date, p.to_string()],
            )
        } else {
            (
                r#"
                SELECT date, SUM(total_cost) as cost, SUM(total_input_tokens + total_output_tokens) as tokens, SUM(request_count) as requests
                FROM daily_cost_aggregates
                WHERE date >= ?1
                GROUP BY date
                ORDER BY date ASC
                "#,
                vec![since_date],
            )
        };

        let mut stmt = conn.prepare(sql).map_err(db_err)?;

        let results: Vec<DailyTrendPoint> = if provider.is_some() {
            stmt.query_map(params![params_vec[0], params_vec[1]], |row| {
                Ok(DailyTrendPoint {
                    date: row.get(0)?,
                    cost: row.get(1)?,
                    tokens: row.get::<_, i64>(2)? as u64,
                    requests: row.get::<_, i64>(3)? as u64,
                    by_provider: HashMap::new(),
                })
            }).map_err(db_err)?
            .collect::<std::result::Result<Vec<_>, _>>().map_err(db_err)?
        } else {
            stmt.query_map(params![params_vec[0]], |row| {
                Ok(DailyTrendPoint {
                    date: row.get(0)?,
                    cost: row.get(1)?,
                    tokens: row.get::<_, i64>(2)? as u64,
                    requests: row.get::<_, i64>(3)? as u64,
                    by_provider: HashMap::new(),
                })
            }).map_err(db_err)?
            .collect::<std::result::Result<Vec<_>, _>>().map_err(db_err)?
        };

        Ok(results)
    }

    /// Get cost breakdown by provider
    pub fn get_cost_by_provider(&self, since: DateTime<Utc>) -> Result<Vec<(String, f64, u64, u64, u64)>> {
        let conn = self.conn.lock().map_err(|_| SothError::Internal("Lock poisoned".into()))?;

        let since_date = since.format("%Y-%m-%d").to_string();

        let mut stmt = conn.prepare(
            r#"
            SELECT provider, SUM(total_cost), SUM(total_input_tokens), SUM(total_output_tokens), SUM(request_count)
            FROM daily_cost_aggregates
            WHERE date >= ?1
            GROUP BY provider
            ORDER BY SUM(total_cost) DESC
            "#,
        ).map_err(db_err)?;

        let results = stmt
            .query_map(params![since_date], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, f64>(1)?,
                    row.get::<_, i64>(2)? as u64,
                    row.get::<_, i64>(3)? as u64,
                    row.get::<_, i64>(4)? as u64,
                ))
            }).map_err(db_err)?
            .collect::<std::result::Result<Vec<_>, _>>().map_err(db_err)?;

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_creation() {
        let storage = BudgetStorage::in_memory().unwrap();
        assert!(storage.get_all_budget_states().unwrap().is_empty());
    }

    #[test]
    fn test_save_and_get_spend_record() {
        let storage = BudgetStorage::in_memory().unwrap();

        let record = SpendRecord {
            id: "test-1".to_string(),
            session_id: "session-1".to_string(),
            agent_id: Some("agent-1".to_string()),
            timestamp: Utc::now(),
            model: "gpt-4o".to_string(),
            token_usage: TokenUsage::new(1000, 500),
            cost: 0.05,
            method: Some("tools/call".to_string()),
        };

        storage.save_spend_record(&record).unwrap();

        let records = storage.get_session_records("session-1").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, "test-1");
        assert_eq!(records[0].cost, 0.05);
    }

    #[test]
    fn test_save_and_get_budget_state() {
        let storage = BudgetStorage::in_memory().unwrap();

        let budget = BudgetState {
            id: "test-budget".to_string(),
            scope: BudgetScope::Global,
            daily_limit: Some(100.0),
            weekly_limit: None,
            monthly_limit: Some(1000.0),
            current_spend: 50.0,
            total_tokens: 10000,
            total_requests: 100,
            period_start: Utc::now(),
            updated_at: Utc::now(),
        };

        storage.save_budget_state(&budget).unwrap();

        let loaded = storage.get_budget_state("test-budget").unwrap().unwrap();
        assert_eq!(loaded.daily_limit, Some(100.0));
        assert_eq!(loaded.current_spend, 50.0);
    }

    #[test]
    fn test_get_total_spend() {
        let storage = BudgetStorage::in_memory().unwrap();
        let since = Utc::now() - chrono::Duration::hours(1);

        for i in 0..5 {
            let record = SpendRecord {
                id: format!("test-{}", i),
                session_id: "session-1".to_string(),
                agent_id: None,
                timestamp: Utc::now(),
                model: "gpt-4o".to_string(),
                token_usage: TokenUsage::new(1000, 500),
                cost: 0.10,
                method: None,
            };
            storage.save_spend_record(&record).unwrap();
        }

        let total = storage.get_total_spend_since(since).unwrap();
        assert!((total - 0.50).abs() < 0.001);
    }

    #[test]
    fn test_spend_by_model() {
        let storage = BudgetStorage::in_memory().unwrap();
        let since = Utc::now() - chrono::Duration::hours(1);

        storage
            .save_spend_record(&SpendRecord {
                id: "1".to_string(),
                session_id: "s1".to_string(),
                agent_id: None,
                timestamp: Utc::now(),
                model: "gpt-4o".to_string(),
                token_usage: TokenUsage::new(1000, 500),
                cost: 0.10,
                method: None,
            })
            .unwrap();

        storage
            .save_spend_record(&SpendRecord {
                id: "2".to_string(),
                session_id: "s1".to_string(),
                agent_id: None,
                timestamp: Utc::now(),
                model: "claude-opus-4".to_string(),
                token_usage: TokenUsage::new(1000, 500),
                cost: 0.50,
                method: None,
            })
            .unwrap();

        let by_model = storage.get_spend_by_model(since).unwrap();
        assert_eq!(by_model.len(), 2);
        // Should be sorted by cost descending
        assert_eq!(by_model[0].0, "claude-opus-4");
    }
}
