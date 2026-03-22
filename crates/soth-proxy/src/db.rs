use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use rusqlite::{named_params, params};
use soth_classify::ClassifiedResult;
use soth_core::{CaptureMode, DetectResult, ProxyContext};
use uuid::Uuid;

const SQLITE_BUSY_TIMEOUT_MS: u64 = 2_000;
const SQLITE_MMAP_SIZE_BYTES: i64 = 268_435_456; // 256 MB
const SQLITE_CACHE_SIZE_KIB: i64 = -64_000; // 64 MB

const REQUIRED_INTERCEPT_COLUMNS: &[(&str, &str)] = &[
    ("connection_id", "connection_id TEXT NOT NULL DEFAULT ''"),
    ("timestamp_utc", "timestamp_utc INTEGER NOT NULL DEFAULT 0"),
    ("provider", "provider TEXT NOT NULL DEFAULT 'unknown'"),
    ("model", "model TEXT NOT NULL DEFAULT 'unknown'"),
    ("endpoint_hash", "endpoint_hash TEXT NOT NULL DEFAULT ''"),
    ("api_version", "api_version TEXT"),
    ("is_multi_turn", "is_multi_turn INTEGER DEFAULT 0"),
    ("conversation_turn", "conversation_turn INTEGER"),
    ("input_tokens", "input_tokens INTEGER"),
    ("output_tokens", "output_tokens INTEGER"),
    ("estimated_cost_usd", "estimated_cost_usd REAL"),
    ("latency_ms", "latency_ms INTEGER"),
    ("ttfb_ms", "ttfb_ms INTEGER"),
    (
        "policy_decision",
        "policy_decision TEXT NOT NULL DEFAULT 'ALLOW'",
    ),
    ("policy_rule_id", "policy_rule_id TEXT"),
    ("classification_flags", "classification_flags TEXT"),
    ("redaction_event", "redaction_event INTEGER DEFAULT 0"),
    ("redaction_count", "redaction_count INTEGER DEFAULT 0"),
    (
        "commitment_hash",
        "commitment_hash TEXT NOT NULL DEFAULT ''",
    ),
    (
        "commitment_nonce",
        "commitment_nonce BLOB NOT NULL DEFAULT X''",
    ),
    ("embedding", "embedding BLOB"),
    ("topic_cluster_id", "topic_cluster_id INTEGER"),
    ("semantic_hash", "semantic_hash TEXT"),
    ("use_case_label", "use_case_label TEXT"),
    ("use_case_confidence", "use_case_confidence REAL"),
    ("secondary_label", "secondary_label TEXT"),
    ("complexity_score", "complexity_score INTEGER"),
    ("volatility_class", "volatility_class TEXT"),
    (
        "is_semantic_collision",
        "is_semantic_collision INTEGER DEFAULT 0",
    ),
    (
        "collision_response_stability",
        "collision_response_stability REAL",
    ),
    ("system_prompt_hash", "system_prompt_hash TEXT"),
    ("dynamic_fraction", "dynamic_fraction REAL"),
    ("code_present", "code_present INTEGER DEFAULT 0"),
    ("detected_languages", "detected_languages TEXT"),
    (
        "credential_detected",
        "credential_detected INTEGER DEFAULT 0",
    ),
    (
        "private_key_detected",
        "private_key_detected INTEGER DEFAULT 0",
    ),
    ("org_pattern_matches", "org_pattern_matches TEXT"),
    ("anomaly_score", "anomaly_score REAL DEFAULT 0.0"),
    ("anomaly_signals", "anomaly_signals TEXT"),
    ("model_was_rerouted", "model_was_rerouted INTEGER DEFAULT 0"),
    ("original_model", "original_model TEXT"),
    (
        "parse_confidence",
        "parse_confidence TEXT NOT NULL DEFAULT 'HEURISTIC'",
    ),
    ("parser_id", "parser_id TEXT"),
    ("is_ai_call", "is_ai_call INTEGER DEFAULT 1"),
    (
        "capture_mode",
        "capture_mode TEXT NOT NULL DEFAULT 'metadata_only'",
    ),
    ("policy_kind", "policy_kind TEXT"),
    (
        "policy_enforced",
        "policy_enforced INTEGER NOT NULL DEFAULT 0",
    ),
    ("matched_provider", "matched_provider TEXT"),
    ("matched_application", "matched_application TEXT"),
    (
        "telemetry_json",
        "telemetry_json TEXT NOT NULL DEFAULT '{}'",
    ),
    (
        "created_at_epoch_ms",
        "created_at_epoch_ms INTEGER NOT NULL DEFAULT 0",
    ),
];

pub fn open(db_path: &Path) -> Result<rusqlite::Connection> {
    soth_sqlite_vec::register_auto_extension();

    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create DB directory: {}", parent.display()))?;
    }

    let conn = rusqlite::Connection::open(db_path)
        .with_context(|| format!("failed to open sqlite database: {}", db_path.display()))?;

    conn.busy_timeout(Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS))
        .context("failed to configure sqlite busy timeout")?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .context("failed to enable WAL mode")?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .context("failed to set sqlite synchronous mode")?;
    conn.pragma_update(None, "mmap_size", SQLITE_MMAP_SIZE_BYTES)
        .context("failed to set sqlite mmap_size")?;
    conn.pragma_update(None, "page_size", 4096_i64)
        .context("failed to set sqlite page_size")?;
    conn.pragma_update(None, "cache_size", SQLITE_CACHE_SIZE_KIB)
        .context("failed to set sqlite cache_size")?;

    run_migrations(&conn)?;
    Ok(conn)
}

pub fn run_migrations(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS intercept_records (
            event_id                     TEXT PRIMARY KEY,
            connection_id                TEXT NOT NULL,
            timestamp_utc                INTEGER NOT NULL,
            provider                     TEXT NOT NULL DEFAULT 'unknown',
            model                        TEXT NOT NULL DEFAULT 'unknown',
            endpoint_hash                TEXT NOT NULL DEFAULT '',
            api_version                  TEXT,
            is_multi_turn                INTEGER DEFAULT 0,
            conversation_turn            INTEGER,
            input_tokens                 INTEGER,
            output_tokens                INTEGER,
            estimated_cost_usd           REAL,
            latency_ms                   INTEGER,
            ttfb_ms                      INTEGER,
            policy_decision              TEXT NOT NULL DEFAULT 'ALLOW',
            policy_rule_id               TEXT,
            classification_flags         TEXT,
            redaction_event              INTEGER DEFAULT 0,
            redaction_count              INTEGER DEFAULT 0,
            commitment_hash              TEXT NOT NULL DEFAULT '',
            commitment_nonce             BLOB NOT NULL DEFAULT X'',
            embedding                    BLOB,
            topic_cluster_id             INTEGER,
            semantic_hash                TEXT,
            use_case_label               TEXT,
            use_case_confidence          REAL,
            secondary_label              TEXT,
            complexity_score             INTEGER,
            volatility_class             TEXT,
            is_semantic_collision        INTEGER DEFAULT 0,
            collision_response_stability REAL,
            system_prompt_hash           TEXT,
            dynamic_fraction             REAL,
            code_present                 INTEGER DEFAULT 0,
            detected_languages           TEXT,
            credential_detected          INTEGER DEFAULT 0,
            private_key_detected         INTEGER DEFAULT 0,
            org_pattern_matches          TEXT,
            anomaly_score                REAL DEFAULT 0.0,
            anomaly_signals              TEXT,
            model_was_rerouted           INTEGER DEFAULT 0,
            original_model               TEXT,
            parse_confidence             TEXT NOT NULL DEFAULT 'HEURISTIC',
            parser_id                    TEXT,
            is_ai_call                   INTEGER DEFAULT 1,
            capture_mode                 TEXT NOT NULL DEFAULT 'metadata_only',
            policy_kind                  TEXT,
            policy_enforced              INTEGER NOT NULL DEFAULT 0,
            matched_provider             TEXT,
            matched_application          TEXT,
            telemetry_json               TEXT NOT NULL DEFAULT '{}',
            created_at_epoch_ms          INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_intercept_records_conn
            ON intercept_records (connection_id, timestamp_utc);

        CREATE INDEX IF NOT EXISTS idx_intercept_records_ts
            ON intercept_records (timestamp_utc DESC);
        ",
    )
    .context("failed to run proxy DB migrations")?;

    ensure_intercept_columns(conn)?;

    conn.execute_batch(
        "CREATE VIRTUAL TABLE IF NOT EXISTS embedding_index USING vec0(event_id TEXT, embedding FLOAT[384]);",
    )
    .context("failed to create sqlite-vec embedding_index table")?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn write_intercept_record(
    db: &Arc<Mutex<rusqlite::Connection>>,
    connection_id: Uuid,
    result: &ClassifiedResult,
    embedding: Option<&[f32]>,
    detect_result: &DetectResult,
    proxy_ctx: &ProxyContext,
    raw_body_for_commitment: Option<&[u8]>,
    capture_mode: CaptureMode,
    matched_provider: Option<&str>,
    matched_application: Option<&str>,
) -> Result<()> {
    let telemetry_json = serde_json::to_string(&result.telemetry_event)
        .context("failed to serialize telemetry event")?;
    let classification_flags =
        serde_json::to_string(&classification_flag_labels(&result.telemetry_event))?;
    let detected_languages = serde_json::to_string(&language_labels(&result.telemetry_event))?;
    let org_pattern_matches = serde_json::to_string(
        &result
            .telemetry_event
            .sensitive_code_flags
            .org_pattern_matches,
    )?;
    let anomaly_signals = serde_json::to_string(&anomaly_flag_labels(result))?;

    let is_redaction = matches!(
        result.policy_decision.kind,
        soth_core::PolicyDecisionKind::Redact { .. }
    );
    let redaction_count = match &result.policy_decision.kind {
        soth_core::PolicyDecisionKind::Redact { targets } => targets.len() as i64,
        _ => 0,
    };
    let model_was_rerouted = matches!(
        result.policy_decision.kind,
        soth_core::PolicyDecisionKind::Reroute { .. }
    );
    let policy_decision = policy_decision_label(&result.policy_decision.kind);
    let policy_rule_id = result
        .policy_decision
        .matched_rule
        .as_ref()
        .map(|rule| rule.rule_id.clone());
    let policy_kind = result
        .telemetry_event
        .policy_kind
        .map(|kind| format!("{kind:?}").to_ascii_uppercase());

    let input_tokens = result
        .telemetry_event
        .estimated_input_tokens
        .map(i64::from)
        .or_else(|| Some(i64::from(detect_result.normalized.estimated_input_tokens)));
    let output_tokens = result
        .telemetry_event
        .estimated_output_tokens
        .map(i64::from);
    let estimated_cost_usd = result
        .telemetry_event
        .estimated_cost_usd
        .map(f64::from)
        .or(Some(detect_result.normalized.estimated_cost_usd));
    let conversation_turn = detect_result.normalized.conversation_turn.map(i64::from);
    let commitment_hash = soth_core::commitment_hash(
        raw_body_for_commitment.unwrap_or_default(),
        &result.commitment_nonce,
    );
    let code_present = result
        .telemetry_event
        .classification_flags
        .iter()
        .any(|flag| matches!(flag, soth_core::ClassificationFlag::CodeDetected))
        || !result.telemetry_event.languages.is_empty();

    let model_value = result
        .telemetry_event
        .model
        .clone()
        .or_else(|| detect_result.normalized.model.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let original_model = if model_was_rerouted {
        detect_result.normalized.model.clone()
    } else {
        None
    };
    let embedding_json = embedding
        .map(serde_json::to_string)
        .transpose()
        .context("failed to serialize embedding for sqlite storage")?;

    let conn = db.lock().map_err(|_| anyhow!("sqlite lock poisoned"))?;
    let inserted_rows = conn.execute(
        "
        INSERT OR IGNORE INTO intercept_records (
            event_id,
            connection_id,
            timestamp_utc,
            provider,
            model,
            endpoint_hash,
            api_version,
            is_multi_turn,
            conversation_turn,
            input_tokens,
            output_tokens,
            estimated_cost_usd,
            latency_ms,
            ttfb_ms,
            policy_decision,
            policy_rule_id,
            classification_flags,
            redaction_event,
            redaction_count,
            commitment_hash,
            commitment_nonce,
            embedding,
            topic_cluster_id,
            semantic_hash,
            use_case_label,
            use_case_confidence,
            secondary_label,
            complexity_score,
            volatility_class,
            is_semantic_collision,
            collision_response_stability,
            system_prompt_hash,
            dynamic_fraction,
            code_present,
            detected_languages,
            credential_detected,
            private_key_detected,
            org_pattern_matches,
            anomaly_score,
            anomaly_signals,
            model_was_rerouted,
            original_model,
            parse_confidence,
            parser_id,
            is_ai_call,
            capture_mode,
            policy_kind,
            policy_enforced,
            matched_provider,
            matched_application,
            telemetry_json,
            created_at_epoch_ms
        ) VALUES (
            :event_id,
            :connection_id,
            :timestamp_utc,
            :provider,
            :model,
            :endpoint_hash,
            :api_version,
            :is_multi_turn,
            :conversation_turn,
            :input_tokens,
            :output_tokens,
            :estimated_cost_usd,
            :latency_ms,
            :ttfb_ms,
            :policy_decision,
            :policy_rule_id,
            :classification_flags,
            :redaction_event,
            :redaction_count,
            :commitment_hash,
            :commitment_nonce,
            :embedding,
            :topic_cluster_id,
            :semantic_hash,
            :use_case_label,
            :use_case_confidence,
            :secondary_label,
            :complexity_score,
            :volatility_class,
            :is_semantic_collision,
            :collision_response_stability,
            :system_prompt_hash,
            :dynamic_fraction,
            :code_present,
            :detected_languages,
            :credential_detected,
            :private_key_detected,
            :org_pattern_matches,
            :anomaly_score,
            :anomaly_signals,
            :model_was_rerouted,
            :original_model,
            :parse_confidence,
            :parser_id,
            :is_ai_call,
            :capture_mode,
            :policy_kind,
            :policy_enforced,
            :matched_provider,
            :matched_application,
            :telemetry_json,
            strftime('%s','now') * 1000
        )
        ",
        named_params! {
            ":event_id": result.telemetry_event.event_id.to_string(),
            ":connection_id": connection_id.to_string(),
            ":timestamp_utc": result.telemetry_event.timestamp_epoch_ms,
            ":provider": result.telemetry_event.provider.as_str(),
            ":model": model_value,
            ":endpoint_hash": proxy_ctx.endpoint_hash.clone(),
            ":api_version": detect_result.normalized.api_version.clone(),
            ":is_multi_turn": as_sql_bool(detect_result.normalized.conversation_turn.unwrap_or(0) > 1),
            ":conversation_turn": conversation_turn,
            ":input_tokens": input_tokens,
            ":output_tokens": output_tokens,
            ":estimated_cost_usd": estimated_cost_usd,
            ":latency_ms": (result.stage_latencies.total_us / 1_000) as i64,
            ":ttfb_ms": Option::<i64>::None,
            ":policy_decision": policy_decision,
            ":policy_rule_id": policy_rule_id,
            ":classification_flags": classification_flags,
            ":redaction_event": as_sql_bool(is_redaction),
            ":redaction_count": redaction_count,
            ":commitment_hash": commitment_hash,
            ":commitment_nonce": result.commitment_nonce.to_vec(),
            ":embedding": embedding_json.clone(),
            ":topic_cluster_id": i64::from(result.topic_cluster_id),
            ":semantic_hash": result.semantic_hash.clone(),
            ":use_case_label": format!("{:?}", result.use_case_label),
            ":use_case_confidence": f64::from(result.use_case_confidence),
            ":secondary_label": result.secondary_label.map(|label| format!("{label:?}")),
            ":complexity_score": i64::from(result.complexity_score),
            ":volatility_class": format!("{:?}", result.volatility_class),
            ":is_semantic_collision": as_sql_bool(result.is_semantic_collision),
            ":collision_response_stability": result.collision_response_stability.map(f64::from),
            ":system_prompt_hash": detect_result.normalized.system_prompt_hash.clone(),
            ":dynamic_fraction": f64::from(result.dynamic_fraction),
            ":code_present": as_sql_bool(code_present),
            ":detected_languages": detected_languages,
            ":credential_detected": as_sql_bool(result.telemetry_event.sensitive_code_flags.credential_pattern_detected),
            ":private_key_detected": as_sql_bool(result.telemetry_event.sensitive_code_flags.private_key_detected),
            ":org_pattern_matches": org_pattern_matches,
            ":anomaly_score": f64::from(result.anomaly_score),
            ":anomaly_signals": anomaly_signals,
            ":model_was_rerouted": as_sql_bool(model_was_rerouted),
            ":original_model": original_model,
            ":parse_confidence": parse_confidence_label(detect_result.confidence),
            ":parser_id": detect_result.normalized.parser_id.clone(),
            ":is_ai_call": as_sql_bool(detect_result.normalized.is_ai_call),
            ":capture_mode": format!("{capture_mode:?}"),
            ":policy_kind": policy_kind,
            ":policy_enforced": as_sql_bool(result.policy_enforced),
            ":matched_provider": matched_provider,
            ":matched_application": matched_application,
            ":telemetry_json": telemetry_json,
        },
    )
    .context("failed to insert intercept record")?;

    if inserted_rows == 0 {
        return Ok(());
    }

    if let Some(embedding_json) = embedding_json {
        if let Err(error) = conn.execute(
            "
            INSERT OR IGNORE INTO embedding_index (event_id, embedding)
            VALUES (?1, ?2)
            ",
            params![result.telemetry_event.event_id.to_string(), embedding_json],
        ) {
            if !is_missing_table_error(&error, "embedding_index") {
                return Err(error).context("failed to insert embedding into sqlite-vec index");
            }
        }
    }

    Ok(())
}

/// Update the most recent intercept record for a connection with stream usage data.
/// Called after stream completion when output_tokens/input_tokens become available.
pub fn update_stream_usage(
    db: &Arc<Mutex<rusqlite::Connection>>,
    connection_id: Uuid,
    usage: &crate::response::UsageSummary,
    extracted_model: Option<&str>,
) {
    let conn = match db.lock() {
        Ok(c) => c,
        Err(_) => return,
    };
    // Update the most recent record for this connection_id.
    // Also patch model if we extracted one from stream data (WebSocket frames).
    let result = conn.execute(
        "
        UPDATE intercept_records
        SET output_tokens = :output_tokens,
            input_tokens = CASE WHEN (input_tokens IS NULL OR input_tokens = 0) THEN :input_tokens ELSE input_tokens END,
            model = CASE WHEN (model IS NULL OR model = 'unknown') AND :model IS NOT NULL THEN :model ELSE model END
        WHERE event_id = (
            SELECT event_id FROM intercept_records
            WHERE connection_id = :connection_id
            ORDER BY created_at_epoch_ms DESC
            LIMIT 1
        )
        ",
        named_params! {
            ":output_tokens": usage.output_tokens as i64,
            ":input_tokens": usage.input_tokens as i64,
            ":model": extracted_model,
            ":connection_id": connection_id.to_string(),
        },
    );
    if let Err(error) = result {
        tracing::warn!(
            connection_id = %connection_id,
            error = %error,
            "failed to update stream usage in db"
        );
    }
}

/// Write a lightweight per-turn record for a completed turn within a WebSocket
/// stream.  Each `response.completed` event gets its own row so we capture
/// model and usage even if the WebSocket connection stays open for hours.
pub fn write_stream_turn(
    db: &Arc<Mutex<rusqlite::Connection>>,
    connection_id: Uuid,
    turn: &soth_detect::StreamTurn,
    pending: &crate::pending::PendingCapture,
) {
    let conn = match db.lock() {
        Ok(c) => c,
        Err(_) => return,
    };

    let event_id = Uuid::new_v4().to_string();
    let model = turn.model.as_deref().unwrap_or("unknown");
    let provider = pending.detect_result.normalized.provider.as_str();
    let capture_mode = format!("{:?}", pending.outcome.capture_mode);
    let now_ms = Utc::now().timestamp_millis();

    let result = conn.execute(
        "
        INSERT OR IGNORE INTO intercept_records (
            event_id,
            connection_id,
            timestamp_utc,
            provider,
            model,
            endpoint_hash,
            input_tokens,
            output_tokens,
            policy_decision,
            parse_confidence,
            parser_id,
            is_ai_call,
            capture_mode,
            matched_provider,
            matched_application,
            telemetry_json,
            created_at_epoch_ms
        ) VALUES (
            :event_id,
            :connection_id,
            :timestamp_utc,
            :provider,
            :model,
            :endpoint_hash,
            :input_tokens,
            :output_tokens,
            'ALLOW',
            'STREAM',
            'websocket-turn',
            1,
            :capture_mode,
            :matched_provider,
            :matched_application,
            '{}',
            :created_at_epoch_ms
        )
        ",
        named_params! {
            ":event_id": event_id,
            ":connection_id": connection_id.to_string(),
            ":timestamp_utc": now_ms,
            ":provider": provider,
            ":model": model,
            ":endpoint_hash": pending.proxy_ctx.endpoint_hash.clone(),
            ":input_tokens": turn.usage.input_tokens as i64,
            ":output_tokens": turn.usage.output_tokens as i64,
            ":capture_mode": capture_mode,
            ":matched_provider": pending.outcome.matched_provider.as_deref(),
            ":matched_application": pending.outcome.matched_application.as_deref(),
            ":created_at_epoch_ms": now_ms,
        },
    );

    match result {
        Ok(_) => {
            tracing::debug!(
                connection_id = %connection_id,
                turn = turn.turn_number,
                model = model,
                input_tokens = turn.usage.input_tokens,
                output_tokens = turn.usage.output_tokens,
                "wrote websocket turn record"
            );
        }
        Err(error) => {
            tracing::warn!(
                connection_id = %connection_id,
                turn = turn.turn_number,
                error = %error,
                "failed to write websocket turn record"
            );
        }
    }
}

pub fn expire_embeddings(db: &Arc<Mutex<rusqlite::Connection>>, days: u32) -> Result<usize> {
    let cutoff_epoch_ms = Utc::now()
        .timestamp_millis()
        .saturating_sub(i64::from(days).saturating_mul(86_400_000));

    let conn = db.lock().map_err(|_| anyhow!("sqlite lock poisoned"))?;
    if let Err(error) = conn.execute(
        "
        DELETE FROM embedding_index
        WHERE event_id IN (
            SELECT event_id
            FROM intercept_records
            WHERE timestamp_utc < ?1
        )
        ",
        params![cutoff_epoch_ms],
    ) {
        if !is_missing_table_error(&error, "embedding_index") {
            return Err(error).context("failed to delete expired sqlite-vec rows");
        }
    }

    let nulled_rows = conn
        .execute(
            "
            UPDATE intercept_records
            SET embedding = NULL
            WHERE timestamp_utc < ?1
              AND embedding IS NOT NULL
            ",
            params![cutoff_epoch_ms],
        )
        .context("failed to clear expired embedding blobs")?;

    Ok(nulled_rows)
}

fn ensure_intercept_columns(conn: &rusqlite::Connection) -> Result<()> {
    let existing = table_columns(conn, "intercept_records")?;
    for (name, definition) in REQUIRED_INTERCEPT_COLUMNS {
        if existing.contains(*name) {
            continue;
        }
        let sql = format!("ALTER TABLE intercept_records ADD COLUMN {definition}");
        conn.execute_batch(sql.as_str())
            .with_context(|| format!("failed adding intercept_records column: {name}"))?;
    }
    Ok(())
}

fn table_columns(conn: &rusqlite::Connection, table: &str) -> Result<HashSet<String>> {
    let mut stmt = conn
        .prepare(format!("PRAGMA table_info({table})").as_str())
        .with_context(|| format!("failed preparing PRAGMA table_info({table})"))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .with_context(|| format!("failed querying PRAGMA table_info({table})"))?;
    let mut out = HashSet::new();
    for row in rows {
        out.insert(row?);
    }
    Ok(out)
}

fn is_missing_table_error(error: &rusqlite::Error, table: &str) -> bool {
    match error {
        rusqlite::Error::SqliteFailure(_, Some(message)) => {
            message.contains("no such table")
                && (message.contains(table) || message.contains(&format!("\"{table}\"")))
        }
        _ => false,
    }
}

fn as_sql_bool(value: bool) -> i64 {
    if value {
        1
    } else {
        0
    }
}

fn policy_decision_label(kind: &soth_core::PolicyDecisionKind) -> &'static str {
    match kind {
        soth_core::PolicyDecisionKind::Allow => "ALLOW",
        soth_core::PolicyDecisionKind::Block { .. } => "BLOCK",
        soth_core::PolicyDecisionKind::Redact { .. } => "REDACT",
        soth_core::PolicyDecisionKind::Reroute { .. } => "REROUTE",
        soth_core::PolicyDecisionKind::Flag { .. } => "FLAG",
    }
}

fn parse_confidence_label(confidence: soth_core::ParseConfidence) -> &'static str {
    match confidence {
        soth_core::ParseConfidence::Full => "FULL",
        soth_core::ParseConfidence::Partial => "PARTIAL",
        soth_core::ParseConfidence::Heuristic => "HEURISTIC",
    }
}

fn classification_flag_labels(event: &soth_core::TelemetryEvent) -> Vec<&'static str> {
    event
        .classification_flags
        .iter()
        .map(|flag| match flag {
            soth_core::ClassificationFlag::CodeDetected => "code_detected",
            soth_core::ClassificationFlag::CredentialDetected => "credential_detected",
            soth_core::ClassificationFlag::HighAnomaly => "high_anomaly",
            soth_core::ClassificationFlag::PolicyTriggered => "policy_triggered",
        })
        .collect()
}

fn language_labels(event: &soth_core::TelemetryEvent) -> Vec<&'static str> {
    event
        .languages
        .iter()
        .map(|lang| match lang {
            soth_core::ProgrammingLanguage::Python => "python",
            soth_core::ProgrammingLanguage::JavaScript => "javascript",
            soth_core::ProgrammingLanguage::TypeScript => "typescript",
            soth_core::ProgrammingLanguage::Rust => "rust",
            soth_core::ProgrammingLanguage::Go => "go",
            soth_core::ProgrammingLanguage::Java => "java",
            soth_core::ProgrammingLanguage::Cpp => "cpp",
            soth_core::ProgrammingLanguage::C => "c",
            soth_core::ProgrammingLanguage::CSharp => "csharp",
            soth_core::ProgrammingLanguage::Ruby => "ruby",
            soth_core::ProgrammingLanguage::Php => "php",
            soth_core::ProgrammingLanguage::Swift => "swift",
            soth_core::ProgrammingLanguage::Kotlin => "kotlin",
            soth_core::ProgrammingLanguage::Sql => "sql",
            soth_core::ProgrammingLanguage::Shell => "shell",
            soth_core::ProgrammingLanguage::Terraform => "terraform",
            soth_core::ProgrammingLanguage::Solidity => "solidity",
            soth_core::ProgrammingLanguage::Yaml => "yaml",
            soth_core::ProgrammingLanguage::Json => "json",
            soth_core::ProgrammingLanguage::Unknown => "unknown",
        })
        .collect()
}

fn anomaly_flag_labels(result: &ClassifiedResult) -> Vec<&'static str> {
    result
        .anomaly_flags
        .iter()
        .map(|flag| match flag {
            soth_core::AnomalyFlag::TopicDrift => "topic_drift",
            soth_core::AnomalyFlag::CredentialBurst => "credential_burst",
            soth_core::AnomalyFlag::TokenBurst => "token_burst",
            soth_core::AnomalyFlag::ModelSwitch => "model_switch",
            soth_core::AnomalyFlag::AgentLoopPattern => "agent_loop_pattern",
            soth_core::AnomalyFlag::RapidFireRequests => "rapid_fire_requests",
            soth_core::AnomalyFlag::UnusualSystemPromptChange => "unusual_system_prompt_change",
            soth_core::AnomalyFlag::ToolCallDepthSpike => "tool_call_depth_spike",
        })
        .collect()
}
