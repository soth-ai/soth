//! `soth events` command family.

use crate::cli_config;
use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use clap::{Args, Subcommand, ValueEnum};
use comfy_table::{presets::UTF8_BORDERS_ONLY, ContentArrangement, Table};
use rusqlite::types::Value as SqlValue;
use rusqlite::{params, Connection, OpenFlags};
use serde::Serialize;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Subcommand)]
pub enum EventsCommands {
    /// Query intercept_records from local SQLite storage
    List(EventsListArgs),
    /// Tail new events as they are written
    Stream(EventsStreamArgs),
}

#[derive(Debug, Clone, Args)]
pub struct EventsListArgs {
    /// Filter by provider name
    #[arg(long)]
    provider: Option<String>,

    /// Filter by model
    #[arg(long)]
    model: Option<String>,

    /// Filter by use-case label
    #[arg(long = "use-case")]
    use_case: Option<String>,

    /// Filter by policy decision
    #[arg(long = "policy-decision", value_enum)]
    policy_decision: Option<PolicyDecisionFilter>,

    /// Only include events where credential/private key signal is present
    #[arg(long)]
    credential_detected: bool,

    /// Only include events with anomaly score greater than this value
    #[arg(long)]
    anomaly_score_gt: Option<f64>,

    /// RFC3339 lower-bound timestamp
    #[arg(long)]
    since: Option<String>,

    /// Max events to return
    #[arg(long, default_value_t = 20)]
    limit: usize,

    /// Output format
    #[arg(long, value_enum, default_value_t = EventsListFormat::Table)]
    format: EventsListFormat,

    /// Config path override
    #[arg(short, long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct EventsStreamArgs {
    /// Output format
    #[arg(long, value_enum, default_value_t = EventsStreamFormat::Compact)]
    format: EventsStreamFormat,

    /// Config path override
    #[arg(short, long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum EventsListFormat {
    Table,
    Json,
    Csv,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum EventsStreamFormat {
    Compact,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PolicyDecisionFilter {
    Allow,
    Block,
    Redact,
    Flag,
}

impl PolicyDecisionFilter {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
            Self::Redact => "redact",
            Self::Flag => "flag",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct EventView {
    rowid: i64,
    timestamp_utc: i64,
    provider: String,
    model: Option<String>,
    use_case_label: Option<String>,
    policy_decision: Option<String>,
    estimated_cost_usd: Option<f64>,
    anomaly_score: Option<f64>,
    credential_detected: bool,
    code_present: bool,
}

#[derive(Debug, Clone)]
struct EventRow {
    rowid: i64,
    timestamp_utc: i64,
    provider: String,
    model: Option<String>,
    use_case_label: Option<String>,
    policy_decision: Option<String>,
    estimated_cost_usd: Option<f64>,
    anomaly_score: Option<f64>,
    credential_detected: bool,
    code_present: bool,
}

pub async fn run(command: EventsCommands, global_config: Option<PathBuf>) -> Result<()> {
    match command {
        EventsCommands::List(args) => run_list(args, global_config).await,
        EventsCommands::Stream(args) => run_stream(args, global_config).await,
    }
}

async fn run_list(args: EventsListArgs, global_config: Option<PathBuf>) -> Result<()> {
    let conn = open_db(args.config.as_ref(), global_config.as_ref())?;
    if !table_exists(&conn, "intercept_records")? {
        println!("No events found: intercept_records table is missing.");
        return Ok(());
    }

    let mut rows = fetch_rows_for_list(&conn, &args)?;
    rows.retain(|row| matches_client_filters(row, &args));
    if rows.len() > args.limit {
        rows.truncate(args.limit);
    }

    match args.format {
        EventsListFormat::Table => render_table(&rows),
        EventsListFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&rows).context("serialize JSON list output")?
            );
        }
        EventsListFormat::Csv => render_csv(&rows),
    }

    Ok(())
}

async fn run_stream(args: EventsStreamArgs, global_config: Option<PathBuf>) -> Result<()> {
    let conn = open_db(args.config.as_ref(), global_config.as_ref())?;
    if !table_exists(&conn, "intercept_records")? {
        println!("No events found: intercept_records table is missing.");
        return Ok(());
    }

    let mut last_rowid = current_max_rowid(&conn)?;
    let mut ticker = tokio::time::interval(Duration::from_millis(500));
    println!("Streaming events. Press Ctrl+C to stop.");

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let rows = fetch_rows_after(&conn, last_rowid)?;
                for row in rows {
                    if row.rowid > last_rowid {
                        last_rowid = row.rowid;
                    }
                    match args.format {
                        EventsStreamFormat::Compact => render_compact_line(&row),
                        EventsStreamFormat::Json => println!("{}", serde_json::to_string(&row).context("serialize JSON stream line")?),
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                println!();
                break;
            }
        }
    }

    Ok(())
}

fn fetch_rows_for_list(conn: &Connection, args: &EventsListArgs) -> Result<Vec<EventView>> {
    let capped_limit = args.limit.clamp(1, 1_000);
    let fetch_limit = (capped_limit.saturating_mul(20)).clamp(100, 10_000);

    let mut where_clauses: Vec<String> = Vec::new();
    let mut params: Vec<SqlValue> = Vec::new();

    if let Some(provider) = args.provider.as_ref() {
        where_clauses.push("provider = ?".to_string());
        params.push(SqlValue::Text(provider.clone()));
    }
    if let Some(model) = args.model.as_ref() {
        where_clauses.push("model = ?".to_string());
        params.push(SqlValue::Text(model.clone()));
    }
    if let Some(since_raw) = args.since.as_ref() {
        let since_ms = parse_rfc3339_to_epoch_ms(since_raw)?;
        where_clauses.push("timestamp_epoch_ms >= ?".to_string());
        params.push(SqlValue::Integer(since_ms));
    }
    if let Some(score) = args.anomaly_score_gt {
        where_clauses.push(
            "CAST(COALESCE(anomaly_score, json_extract(telemetry_json, '$.anomaly_score')) AS REAL) > ?"
                .to_string(),
        );
        params.push(SqlValue::Real(score));
    }

    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    let sql = format!(
        "SELECT
            rowid,
            CAST(timestamp_epoch_ms / 1000 AS INTEGER) AS timestamp_utc,
            COALESCE(provider, 'unknown') AS provider,
            model,
            LOWER(COALESCE(
                CAST(json_extract(telemetry_json, '$.use_case_label') AS TEXT),
                CAST(json_extract(telemetry_json, '$.use_case') AS TEXT)
            )) AS use_case_label,
            LOWER(NULLIF(COALESCE(policy_kind, ''), '')) AS policy_decision,
            CAST(COALESCE(
                json_extract(telemetry_json, '$.estimated_cost_usd'),
                json_extract(telemetry_json, '$.cost_usd')
            ) AS REAL) AS estimated_cost_usd,
            CAST(COALESCE(
                anomaly_score,
                json_extract(telemetry_json, '$.anomaly_score')
            ) AS REAL) AS anomaly_score,
            CASE
                WHEN COALESCE(json_extract(telemetry_json, '$.sensitive_code_flags.credential_pattern_detected'), 0) = 1
                  OR COALESCE(json_extract(telemetry_json, '$.sensitive_code_flags.private_key_detected'), 0) = 1
                THEN 1 ELSE 0
            END AS credential_detected,
            CASE
                WHEN COALESCE(json_extract(telemetry_json, '$.code_present'), 0) = 1
                THEN 1 ELSE 0
            END AS code_present
         FROM intercept_records
         {where_sql}
         ORDER BY timestamp_epoch_ms DESC
         LIMIT ?"
    );
    params.push(SqlValue::Integer(fetch_limit as i64));

    let mut stmt = conn.prepare(sql.as_str())?;
    let mut rows = stmt.query(rusqlite::params_from_iter(params.iter()))?;
    let mut output = Vec::new();
    while let Some(row) = rows.next()? {
        output.push(to_view(read_row(row)?));
    }
    Ok(output)
}

fn fetch_rows_after(conn: &Connection, last_rowid: i64) -> Result<Vec<EventView>> {
    let mut stmt = conn.prepare(
        "SELECT
            rowid,
            CAST(timestamp_epoch_ms / 1000 AS INTEGER) AS timestamp_utc,
            COALESCE(provider, 'unknown') AS provider,
            model,
            LOWER(COALESCE(
                CAST(json_extract(telemetry_json, '$.use_case_label') AS TEXT),
                CAST(json_extract(telemetry_json, '$.use_case') AS TEXT)
            )) AS use_case_label,
            LOWER(NULLIF(COALESCE(policy_kind, ''), '')) AS policy_decision,
            CAST(COALESCE(
                json_extract(telemetry_json, '$.estimated_cost_usd'),
                json_extract(telemetry_json, '$.cost_usd')
            ) AS REAL) AS estimated_cost_usd,
            CAST(COALESCE(
                anomaly_score,
                json_extract(telemetry_json, '$.anomaly_score')
            ) AS REAL) AS anomaly_score,
            CASE
                WHEN COALESCE(json_extract(telemetry_json, '$.sensitive_code_flags.credential_pattern_detected'), 0) = 1
                  OR COALESCE(json_extract(telemetry_json, '$.sensitive_code_flags.private_key_detected'), 0) = 1
                THEN 1 ELSE 0
            END AS credential_detected,
            CASE
                WHEN COALESCE(json_extract(telemetry_json, '$.code_present'), 0) = 1
                THEN 1 ELSE 0
            END AS code_present
         FROM intercept_records
         WHERE rowid > ?1
         ORDER BY rowid ASC
         LIMIT 500",
    )?;
    let mut rows = stmt.query(params![last_rowid])?;
    let mut output = Vec::new();
    while let Some(row) = rows.next()? {
        output.push(to_view(read_row(row)?));
    }
    Ok(output)
}

fn read_row(row: &rusqlite::Row<'_>) -> Result<EventRow> {
    Ok(EventRow {
        rowid: row.get(0)?,
        timestamp_utc: row.get(1)?,
        provider: row.get(2)?,
        model: row.get(3)?,
        use_case_label: row.get(4)?,
        policy_decision: row.get(5)?,
        estimated_cost_usd: row.get(6)?,
        anomaly_score: row.get(7)?,
        credential_detected: row.get::<_, i64>(8).map(|v| v != 0)?,
        code_present: row.get::<_, i64>(9).map(|v| v != 0)?,
    })
}

fn to_view(row: EventRow) -> EventView {
    EventView {
        rowid: row.rowid,
        timestamp_utc: row.timestamp_utc,
        provider: row.provider,
        model: row.model,
        use_case_label: normalize_optional_lower(row.use_case_label),
        policy_decision: normalize_optional_lower(row.policy_decision),
        estimated_cost_usd: row.estimated_cost_usd,
        anomaly_score: row.anomaly_score,
        credential_detected: row.credential_detected,
        code_present: row.code_present,
    }
}

fn matches_client_filters(row: &EventView, args: &EventsListArgs) -> bool {
    if let Some(use_case) = args.use_case.as_ref() {
        let Some(actual) = row.use_case_label.as_ref() else {
            return false;
        };
        if !actual.eq_ignore_ascii_case(use_case) {
            return false;
        }
    }

    if let Some(policy) = args.policy_decision {
        let Some(actual) = row.policy_decision.as_ref() else {
            return false;
        };
        if actual != policy.as_str() {
            return false;
        }
    }

    if args.credential_detected && !row.credential_detected {
        return false;
    }

    true
}

fn normalize_optional_lower(value: Option<String>) -> Option<String> {
    let raw = value?.trim().to_string();
    if raw.is_empty() {
        return None;
    }
    Some(raw.to_ascii_lowercase())
}

fn render_table(rows: &[EventView]) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_BORDERS_ONLY)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            "TIMESTAMP",
            "PROVIDER",
            "MODEL",
            "USE CASE",
            "POLICY",
            "COST",
        ]);

    for row in rows {
        table.add_row(vec![
            fmt_timestamp(row.timestamp_utc),
            row.provider.clone(),
            row.model.clone().unwrap_or_else(|| "-".to_string()),
            row.use_case_label
                .clone()
                .unwrap_or_else(|| "-".to_string()),
            row.policy_decision
                .clone()
                .unwrap_or_else(|| "allow".to_string()),
            fmt_cost(row.estimated_cost_usd),
        ]);
    }

    println!("{table}");
}

fn render_csv(rows: &[EventView]) {
    println!("timestamp_utc,provider,model,use_case_label,policy_decision,estimated_cost_usd,anomaly_score,credential_detected,code_present");
    for row in rows {
        let model = row.model.as_deref().unwrap_or("");
        let use_case = row.use_case_label.as_deref().unwrap_or("");
        let policy = row.policy_decision.as_deref().unwrap_or("allow");
        let cost = row
            .estimated_cost_usd
            .map(|value| format!("{value:.6}"))
            .unwrap_or_default();
        let anomaly = row
            .anomaly_score
            .map(|value| format!("{value:.6}"))
            .unwrap_or_default();
        println!(
            "{},{},{},{},{},{},{},{},{}",
            row.timestamp_utc,
            csv_escape(row.provider.as_str()),
            csv_escape(model),
            csv_escape(use_case),
            csv_escape(policy),
            cost,
            anomaly,
            row.credential_detected,
            row.code_present
        );
    }
}

fn render_compact_line(row: &EventView) {
    let ts = DateTime::<Utc>::from_timestamp(row.timestamp_utc, 0)
        .map(|value| value.format("%H:%M:%S").to_string())
        .unwrap_or_else(|| "??:??:??".to_string());
    let model = row.model.as_deref().unwrap_or("unknown-model");
    let use_case = row.use_case_label.as_deref().unwrap_or("Unknown");
    let policy = row.policy_decision.as_deref().unwrap_or("allow");
    let cost = fmt_cost(row.estimated_cost_usd);

    if row.credential_detected {
        println!(
            "[{ts}] {}/{}  {}  {}   credential detected",
            row.provider, model, use_case, policy
        );
    } else {
        println!(
            "[{ts}] {}/{}  {}  {}   {}",
            row.provider, model, use_case, policy, cost
        );
    }
}

fn fmt_timestamp(timestamp_utc: i64) -> String {
    Utc.timestamp_opt(timestamp_utc, 0)
        .single()
        .map(|value| value.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn fmt_cost(cost: Option<f64>) -> String {
    match cost {
        Some(value) if value > 0.0 => format!("${value:.2}"),
        _ => "-".to_string(),
    }
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn parse_rfc3339_to_epoch_ms(raw: &str) -> Result<i64> {
    let parsed = DateTime::parse_from_rfc3339(raw)
        .with_context(|| format!("invalid RFC3339 timestamp: {raw}"))?;
    Ok(parsed.timestamp_millis())
}

fn open_db(config_path: Option<&PathBuf>, global_config: Option<&PathBuf>) -> Result<Connection> {
    let config = cli_config::load_effective_config(config_path, global_config)?;
    let db_path = cli_config::resolved_db_path(&config);
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI;
    Connection::open_with_flags(db_path.as_path(), flags)
        .with_context(|| format!("failed opening {}", db_path.display()))
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    let mut stmt = conn.prepare(
        "SELECT 1
         FROM sqlite_master
         WHERE type = 'table' AND name = ?1
         LIMIT 1",
    )?;
    let mut rows = stmt.query(params![table])?;
    Ok(rows.next()?.is_some())
}

fn current_max_rowid(conn: &Connection) -> Result<i64> {
    let value = conn.query_row(
        "SELECT COALESCE(MAX(rowid), 0) FROM intercept_records",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(value)
}
