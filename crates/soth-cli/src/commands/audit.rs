//! Audit trail management commands

use crate::AuditCommands;
use anyhow::Result;
use rusqlite::{params, Connection};
use sha2::Digest;
use soth_identity::{decode_did_key, KeyPair};
use soth_observe::{MerkleTree, SqliteStorage};
use std::path::{Path, PathBuf};
use tokio::fs;

/// Run audit command
pub async fn run(action: AuditCommands) -> Result<()> {
    match action {
        AuditCommands::Verify { log, from, to } => {
            verify_log(log, from, to).await?;
        }
        AuditCommands::Proof { event_id, output } => {
            generate_proof(&event_id, output).await?;
        }
        AuditCommands::Stats { log } => {
            show_stats(log).await?;
        }
    }
    Ok(())
}

/// Verify Merkle audit trail integrity from events SQLite storage.
async fn verify_log(
    log_path: Option<PathBuf>,
    from: Option<String>,
    to: Option<String>,
) -> Result<()> {
    let log_path = if let Some(path) = log_path {
        path
    } else {
        soth_core::event_logger::default_event_log_write_path()?
    };

    if !log_path.exists() {
        anyhow::bail!("Log file not found: {log_path:?}");
    }
    if !is_sqlite_path(&log_path) {
        anyhow::bail!("Audit verify requires an SQLite events DB path");
    }

    let summary = tokio::task::spawn_blocking(move || verify_sqlite_merkle(&log_path, from, to))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to run audit verification: {e}"))??;

    println!("Audit verification complete");
    println!("════════════════════════════");
    println!("  Batches verified: {}", summary.batches_verified);
    println!("  Events verified:  {}", summary.events_verified);
    println!(
        "  Root hash:        {}",
        summary.last_root.unwrap_or_else(|| "-".to_string())
    );
    println!("  Signers seen:     {}", summary.unique_signers.len());
    if !summary.unique_signers.is_empty() {
        for signer in summary.unique_signers {
            println!("    - {signer}");
        }
    }

    Ok(())
}

#[derive(Debug)]
struct VerifySummary {
    batches_verified: usize,
    events_verified: usize,
    last_root: Option<String>,
    unique_signers: std::collections::BTreeSet<String>,
}

#[derive(Debug)]
struct MerkleBatchRow {
    batch_id: String,
    seq_start: i64,
    seq_end: i64,
    root_hash: String,
    signature: String,
    signer_did: String,
    prev_root: Option<String>,
}

fn verify_sqlite_merkle(
    db_path: &Path,
    from: Option<String>,
    to: Option<String>,
) -> Result<VerifySummary> {
    let conn = Connection::open(db_path)?;

    let mut sql = String::from(
        "SELECT batch_id, seq_start, seq_end, root_hash, signature, signer_did, prev_root \
         FROM merkle_batches",
    );
    let mut where_clauses: Vec<String> = Vec::new();
    let mut params: Vec<String> = Vec::new();
    if let Some(from) = from {
        where_clauses.push("sealed_at >= ?".to_string());
        params.push(from);
    }
    if let Some(to) = to {
        where_clauses.push("sealed_at <= ?".to_string());
        params.push(to);
    }
    if !where_clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&where_clauses.join(" AND "));
    }
    sql.push_str(" ORDER BY seq_start ASC");

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
        Ok(MerkleBatchRow {
            batch_id: row.get(0)?,
            seq_start: row.get(1)?,
            seq_end: row.get(2)?,
            root_hash: row.get(3)?,
            signature: row.get(4)?,
            signer_did: row.get(5)?,
            prev_root: row.get(6)?,
        })
    })?;

    let mut batches: Vec<MerkleBatchRow> = Vec::new();
    for row in rows {
        batches.push(row?);
    }

    if batches.is_empty() {
        return Ok(VerifySummary {
            batches_verified: 0,
            events_verified: 0,
            last_root: None,
            unique_signers: std::collections::BTreeSet::new(),
        });
    }

    let mut summary = VerifySummary {
        batches_verified: 0,
        events_verified: 0,
        last_root: None,
        unique_signers: std::collections::BTreeSet::new(),
    };

    let mut previous_root: Option<String> = None;
    for (index, batch) in batches.iter().enumerate() {
        if batch.seq_end < batch.seq_start {
            anyhow::bail!(
                "Invalid batch range for {}: {}..{}",
                batch.batch_id,
                batch.seq_start,
                batch.seq_end
            );
        }

        if index > 0 && batch.prev_root != previous_root {
            anyhow::bail!(
                "Batch chain discontinuity at {} (expected prev_root {:?}, got {:?})",
                batch.batch_id,
                previous_root,
                batch.prev_root
            );
        }

        let mut event_stmt = conn.prepare(
            "SELECT event_json FROM wrap_events WHERE seq >= ?1 AND seq <= ?2 ORDER BY seq ASC",
        )?;
        let event_rows = event_stmt.query_map(params![batch.seq_start, batch.seq_end], |row| {
            row.get::<_, String>(0)
        })?;

        let mut event_hashes = Vec::new();
        for event_row in event_rows {
            let event_json = event_row?;
            let event: soth_core::types::WrapEvent = serde_json::from_str(&event_json)?;
            let Some(event_hash) = event.event_hash else {
                anyhow::bail!(
                    "Missing event_hash in sealed range for batch {}",
                    batch.batch_id
                );
            };
            if event.merkle_batch_id.as_deref() != Some(batch.batch_id.as_str()) {
                anyhow::bail!(
                    "Event batch_id mismatch in {} (expected {}, got {:?})",
                    event.id,
                    batch.batch_id,
                    event.merkle_batch_id
                );
            }
            event_hashes.push(decode_hash_32(&event_hash)?);
        }

        if event_hashes.is_empty() {
            anyhow::bail!("Batch {} has no events in range", batch.batch_id);
        }

        let base_root = compute_merkle_root(&event_hashes);
        let chained_root = if let Some(prev_root) = batch.prev_root.as_deref() {
            let prev = decode_hash_32(prev_root)?;
            hash_root_link(&prev, &base_root)
        } else {
            base_root
        };
        let chained_root_hex = hex::encode(chained_root);
        if chained_root_hex != batch.root_hash {
            anyhow::bail!(
                "Root mismatch for batch {}: expected {}, computed {}",
                batch.batch_id,
                batch.root_hash,
                chained_root_hex
            );
        }

        let public_key = decode_did_key(&batch.signer_did)?;
        let verifier = KeyPair::from_public_key_bytes(&public_key)?;
        let signature = hex::decode(&batch.signature)?;
        if !verifier.verify(&chained_root, &signature) {
            anyhow::bail!("Invalid Merkle signature for batch {}", batch.batch_id);
        }

        previous_root = Some(batch.root_hash.clone());
        summary.last_root = Some(batch.root_hash.clone());
        summary.unique_signers.insert(batch.signer_did.clone());
        summary.events_verified += event_hashes.len();
        summary.batches_verified += 1;
    }

    Ok(summary)
}

fn decode_hash_32(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value)?;
    if bytes.len() != 32 {
        anyhow::bail!("Expected 32-byte hash, got {}", bytes.len());
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return sha2::Sha256::digest([]).into();
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            let mut hasher = sha2::Sha256::new();
            hasher.update([0x01]);
            hasher.update(left);
            hasher.update(right);
            next.push(hasher.finalize().into());
        }
        level = next;
    }
    level[0]
}

fn hash_root_link(prev_root: &[u8; 32], current_root: &[u8; 32]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(prev_root);
    hasher.update(current_root);
    hasher.finalize().into()
}

/// Generate proof for an event
async fn generate_proof(event_id: &str, output: Option<PathBuf>) -> Result<()> {
    let log_path = default_observation_log_path();

    if !log_path.exists() {
        anyhow::bail!("Log file not found: {log_path:?}");
    }

    let events = load_audit_events(&log_path).await?;

    // Build Merkle tree and find event
    let mut tree = MerkleTree::new();
    let mut event_index = None;
    let mut event_data = None;

    for (i, event) in events.iter().enumerate() {
        let data = serde_json::to_vec(event)?;
        tree.append(&data);

        if event.get("id").and_then(|id| id.as_str()) == Some(event_id) {
            event_index = Some(i);
            event_data = Some(event.clone());
        }
    }

    let index = event_index.ok_or_else(|| anyhow::anyhow!("Event not found: {event_id}"))?;
    let event = event_data.unwrap();

    // Generate proof
    let proof = tree
        .get_proof(index)
        .ok_or_else(|| anyhow::anyhow!("Could not generate proof"))?;

    let proof_data = serde_json::json!({
        "event_id": event_id,
        "event": event,
        "proof": proof.to_json(),
        "root": tree.root_hex(),
        "tree_size": tree.len(),
        "generated_at": chrono::Utc::now().to_rfc3339(),
    });

    if let Some(output_path) = output {
        fs::write(&output_path, serde_json::to_string_pretty(&proof_data)?).await?;
        println!("Proof written to {output_path:?}");
    } else {
        println!("{}", serde_json::to_string_pretty(&proof_data)?);
    }

    Ok(())
}

/// Show audit statistics
async fn show_stats(log_path: PathBuf) -> Result<()> {
    if !log_path.exists() {
        anyhow::bail!("Log file not found: {log_path:?}");
    }

    let events = load_audit_events(&log_path).await?;

    let mut stats = AuditStats::default();

    for event in &events {
        stats.total_events += 1;

        // Count by direction
        match event.get("direction").and_then(|d| d.as_str()) {
            Some("in") => stats.inbound += 1,
            Some("out") => stats.outbound += 1,
            _ => {}
        }

        // Count by event type
        if let Some(event_type) = event.get("event_type").and_then(|t| t.as_str()) {
            *stats.by_type.entry(event_type.to_string()).or_insert(0) += 1;
        }

        // Sum tokens
        if let Some(tokens) = event.get("token_count").and_then(|t| t.as_u64()) {
            stats.total_tokens += tokens;
        }

        // Count PII detections
        if let Some(pii_detected) = event.get("pii_detected").and_then(|p| p.as_bool()) {
            if pii_detected {
                stats.pii_events += 1;
            }
        }

        // Track sessions
        if let Some(session) = event.get("session_id").and_then(|s| s.as_str()) {
            stats.unique_sessions.insert(session.to_string());
        }

        // Track time range
        if let Some(timestamp) = event.get("timestamp").and_then(|t| t.as_str()) {
            if stats.first_event.is_none() {
                stats.first_event = Some(timestamp.to_string());
            }
            stats.last_event = Some(timestamp.to_string());
        }
    }

    // Display stats
    println!("Audit Log Statistics");
    println!("═══════════════════\n");

    println!("Overview:");
    println!("  Total events:    {}", stats.total_events);
    println!("  Inbound:         {}", stats.inbound);
    println!("  Outbound:        {}", stats.outbound);
    println!("  Total tokens:    {}", stats.total_tokens);
    println!("  Unique sessions: {}", stats.unique_sessions.len());

    if let (Some(first), Some(last)) = (&stats.first_event, &stats.last_event) {
        println!("\nTime Range:");
        println!("  First: {first}");
        println!("  Last:  {last}");
    }

    if !stats.by_type.is_empty() {
        println!("\nBy Event Type:");
        let mut types: Vec<_> = stats.by_type.iter().collect();
        types.sort_by(|a, b| b.1.cmp(a.1));
        for (event_type, count) in types {
            println!("  {event_type:<20} {count}");
        }
    }

    if stats.pii_events > 0 {
        println!("\nPII Detections: {}", stats.pii_events);
    }

    Ok(())
}

#[derive(Default)]
struct AuditStats {
    total_events: usize,
    inbound: usize,
    outbound: usize,
    total_tokens: u64,
    by_type: std::collections::HashMap<String, usize>,
    pii_events: usize,
    unique_sessions: std::collections::HashSet<String>,
    first_event: Option<String>,
    last_event: Option<String>,
}

fn default_observation_log_path() -> PathBuf {
    let sqlite = PathBuf::from("logs/observations.db");
    if sqlite.exists() {
        sqlite
    } else {
        PathBuf::from("logs/observations.jsonl")
    }
}

fn is_sqlite_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()).map(|s| s.to_lowercase()),
        Some(ext) if ext == "db" || ext == "sqlite" || ext == "sqlite3"
    )
}

async fn load_audit_events(path: &Path) -> Result<Vec<serde_json::Value>> {
    if is_sqlite_path(path) {
        let db_path = path.to_path_buf();
        let events = tokio::task::spawn_blocking(move || -> Result<Vec<serde_json::Value>> {
            let storage = SqliteStorage::new(&db_path)?;
            let events = storage.read_all()?;
            let mut values = Vec::with_capacity(events.len());
            for event in events {
                values.push(serde_json::to_value(event)?);
            }
            Ok(values)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load sqlite audit events: {e}"))??;

        Ok(events)
    } else {
        let content = fs::read_to_string(path).await?;
        let mut values = Vec::new();
        for line in content.lines().filter(|line| !line.trim().is_empty()) {
            values.push(serde_json::from_str::<serde_json::Value>(line)?);
        }
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soth_core::event_logger::{EventLogger, EventLoggerOptions, MerkleLoggingConfig};
    use soth_core::types::{AgentInfo, DetectionSource, WrapDirection, WrapEvent};
    use tempfile::tempdir;

    #[test]
    fn test_verify_sqlite_merkle_roundtrip() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("events.db");
        let options = EventLoggerOptions {
            inline_payload_max_bytes: 16 * 1024,
            merkle: MerkleLoggingConfig {
                enabled: true,
                seal_interval: std::time::Duration::from_secs(60),
                max_events_per_batch: 2,
            },
        };
        let logger = EventLogger::new_with_options(db_path.clone(), options).unwrap();

        let agent = AgentInfo::new("AuditTest", DetectionSource::CommandLine);
        let e1 = WrapEvent::new(
            "sess-audit",
            "api.openai.com",
            WrapDirection::Out,
            agent.clone(),
        )
        .with_method("POST /v1/chat/completions");
        let e2 = WrapEvent::new(
            "sess-audit",
            "api.openai.com",
            WrapDirection::In,
            agent.clone(),
        )
        .with_method("POST /v1/chat/completions");
        let e3 = WrapEvent::new("sess-audit", "api.openai.com", WrapDirection::Out, agent)
            .with_method("POST /v1/chat/completions");
        logger.log(&e1);
        logger.log(&e2);
        logger.log(&e3);
        logger.close();

        let summary = verify_sqlite_merkle(&db_path, None, None).unwrap();
        assert_eq!(summary.batches_verified, 2);
        assert_eq!(summary.events_verified, 3);
        assert!(summary.last_root.is_some());
        assert!(!summary.unique_signers.is_empty());
    }
}
