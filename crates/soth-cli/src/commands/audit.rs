//! Audit trail management commands

use crate::AuditCommands;
use anyhow::{anyhow, Result};
use rusqlite::{params, Connection};
use sha2::Digest;
use soth_core::types::{WrapDirection, WrapEvent};
use soth_crypto::identity::{decode_did_key, KeyPair};
use soth_observe::MerkleTree;
use std::path::{Path, PathBuf};
use tokio::fs;

/// Run audit command
pub async fn run(action: AuditCommands) -> Result<()> {
    match action {
        AuditCommands::Verify { log, from, to } => {
            verify_log(log, from, to).await?;
        }
        AuditCommands::Proof {
            event_id,
            output,
            log,
        } => {
            generate_proof(log, &event_id, output).await?;
        }
        AuditCommands::Stats { log } => {
            show_stats(log).await?;
        }
    }
    Ok(())
}

fn resolve_audit_log_path(log_path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = log_path {
        return Ok(path);
    }
    Ok(soth_core::event_logger::default_event_log_write_path()?)
}

fn validate_sqlite_log_path(log_path: &Path, action: &str) -> Result<()> {
    if !log_path.exists() {
        anyhow::bail!("Log file not found: {log_path:?}");
    }
    if !is_sqlite_path(log_path) {
        anyhow::bail!("{action} requires an SQLite events DB path");
    }
    Ok(())
}

/// Verify Merkle audit trail integrity from events SQLite storage.
async fn verify_log(
    log_path: Option<PathBuf>,
    from: Option<String>,
    to: Option<String>,
) -> Result<()> {
    let log_path = resolve_audit_log_path(log_path)?;
    validate_sqlite_log_path(&log_path, "Audit verify")?;

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
async fn generate_proof(
    log_path: Option<PathBuf>,
    event_id: &str,
    output: Option<PathBuf>,
) -> Result<()> {
    let log_path = resolve_audit_log_path(log_path)?;
    validate_sqlite_log_path(&log_path, "Audit proof")?;
    let target_event_id = event_id.to_string();

    let proof_data =
        tokio::task::spawn_blocking(move || generate_sqlite_proof(&log_path, &target_event_id))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to generate audit proof: {e}"))??;

    if let Some(output_path) = output {
        fs::write(&output_path, serde_json::to_string_pretty(&proof_data)?).await?;
        println!("Proof written to {output_path:?}");
    } else {
        println!("{}", serde_json::to_string_pretty(&proof_data)?);
    }

    Ok(())
}

/// Show audit statistics
async fn show_stats(log_path: Option<PathBuf>) -> Result<()> {
    let log_path = resolve_audit_log_path(log_path)?;
    validate_sqlite_log_path(&log_path, "Audit stats")?;
    let events = tokio::task::spawn_blocking(move || load_wrap_events(&log_path))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load audit stats: {e}"))??;

    let mut stats = AuditStats::default();

    for event in &events {
        stats.total_events += 1;

        // Count by direction
        match event.direction {
            WrapDirection::In => stats.inbound += 1,
            WrapDirection::Out => stats.outbound += 1,
        }

        // Count by request method label
        let method = event.method.as_deref().unwrap_or("unknown");
        *stats.by_method.entry(method.to_string()).or_insert(0) += 1;

        // Sum tokens
        let total_tokens = event
            .token_count
            .or_else(|| match (event.input_tokens, event.output_tokens) {
                (Some(input), Some(output)) => Some(input.saturating_add(output)),
                _ => None,
            })
            .unwrap_or(0);
        stats.total_tokens = stats.total_tokens.saturating_add(total_tokens);

        // Count PII detections
        if event.pii_detected {
            stats.pii_events += 1;
        }

        // Track sessions
        stats.unique_sessions.insert(event.session_id.clone());

        // Track time range
        let timestamp = event.timestamp.to_rfc3339();
        if stats.first_event.is_none() {
            stats.first_event = Some(timestamp.clone());
        }
        stats.last_event = Some(timestamp);
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

    if !stats.by_method.is_empty() {
        println!("\nBy Method:");
        let mut methods: Vec<_> = stats.by_method.iter().collect();
        methods.sort_by(|a, b| b.1.cmp(a.1));
        for (method, count) in methods {
            println!("  {method:<20} {count}");
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
    by_method: std::collections::HashMap<String, usize>,
    pii_events: usize,
    unique_sessions: std::collections::HashSet<String>,
    first_event: Option<String>,
    last_event: Option<String>,
}

fn is_sqlite_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()).map(|s| s.to_lowercase()),
        Some(ext) if ext == "db" || ext == "sqlite" || ext == "sqlite3"
    )
}

fn load_wrap_events(db_path: &Path) -> Result<Vec<WrapEvent>> {
    let conn = Connection::open(db_path)?;
    let mut stmt = conn.prepare("SELECT seq, event_json FROM wrap_events ORDER BY seq ASC")?;
    let rows = stmt.query_map([], |row| {
        let seq: i64 = row.get(0)?;
        let event_json: String = row.get(1)?;
        Ok((seq, event_json))
    })?;

    let mut events = Vec::new();
    for row in rows {
        let (seq, event_json) = row?;
        let mut event: WrapEvent = serde_json::from_str(&event_json)?;
        event.seq = Some(seq);
        events.push(event);
    }
    Ok(events)
}

fn generate_sqlite_proof(db_path: &Path, event_id: &str) -> Result<serde_json::Value> {
    let conn = Connection::open(db_path)?;
    let (target_seq, target_event) = load_event_by_id(&conn, event_id)?;
    let batch_id = target_event
        .merkle_batch_id
        .clone()
        .ok_or_else(|| anyhow!("Event {event_id} is not sealed into a Merkle batch"))?;
    let batch = load_batch_by_id(&conn, &batch_id)?;
    if target_seq < batch.seq_start || target_seq > batch.seq_end {
        anyhow::bail!(
            "Event {} (seq {}) is outside batch {} range {}..{}",
            event_id,
            target_seq,
            batch.batch_id,
            batch.seq_start,
            batch.seq_end
        );
    }

    let events = load_batch_events(&conn, &batch)?;
    if events.is_empty() {
        anyhow::bail!("Batch {} has no events in range", batch.batch_id);
    }

    let mut event_hashes = Vec::with_capacity(events.len());
    let mut event_index = None;
    for (index, event) in events.iter().enumerate() {
        let event_hash = event.event_hash.as_deref().ok_or_else(|| {
            anyhow!(
                "Missing event_hash in sealed range for batch {}",
                batch.batch_id
            )
        })?;
        if event.merkle_batch_id.as_deref() != Some(batch.batch_id.as_str()) {
            anyhow::bail!(
                "Event batch_id mismatch in {} (expected {}, got {:?})",
                event.id,
                batch.batch_id,
                event.merkle_batch_id
            );
        }
        event_hashes.push(decode_hash_32(event_hash)?);
        if event.id == event_id {
            event_index = Some(index);
        }
    }

    let event_index = event_index.ok_or_else(|| anyhow!("Event not found in batch: {event_id}"))?;
    let tree = MerkleTree::from_leaves(event_hashes.clone());
    let proof = tree
        .get_proof(event_index)
        .ok_or_else(|| anyhow!("Could not generate proof"))?;
    let base_root = tree
        .root()
        .copied()
        .ok_or_else(|| anyhow!("Could not compute Merkle root"))?;
    let base_root_hex = hex::encode(base_root);
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

    Ok(serde_json::json!({
        "event_id": event_id,
        "event_seq": target_seq,
        "event": target_event,
        "proof": proof.to_json(),
        "root": base_root_hex,
        "tree_size": event_hashes.len(),
        "batch_id": batch.batch_id,
        "batch_seq_start": batch.seq_start,
        "batch_seq_end": batch.seq_end,
        "batch_root": batch.root_hash,
        "chained_root": chained_root_hex,
        "signer_did": batch.signer_did,
        "signature": batch.signature,
        "generated_at": chrono::Utc::now().to_rfc3339(),
    }))
}

fn load_event_by_id(conn: &Connection, event_id: &str) -> Result<(i64, WrapEvent)> {
    let mut stmt = conn.prepare(
        "SELECT seq, event_json FROM wrap_events WHERE id = ?1 ORDER BY seq DESC LIMIT 1",
    )?;
    let mut rows = stmt.query(params![event_id])?;
    let row = rows
        .next()?
        .ok_or_else(|| anyhow!("Event not found: {event_id}"))?;
    let seq: i64 = row.get(0)?;
    let event_json: String = row.get(1)?;
    let mut event: WrapEvent = serde_json::from_str(&event_json)?;
    event.seq = Some(seq);
    Ok((seq, event))
}

fn load_batch_by_id(conn: &Connection, batch_id: &str) -> Result<MerkleBatchRow> {
    let mut stmt = conn.prepare(
        "SELECT batch_id, seq_start, seq_end, root_hash, signature, signer_did, prev_root \
         FROM merkle_batches WHERE batch_id = ?1",
    )?;
    let mut rows = stmt.query(params![batch_id])?;
    let row = rows
        .next()?
        .ok_or_else(|| anyhow!("Batch not found: {batch_id}"))?;
    Ok(MerkleBatchRow {
        batch_id: row.get(0)?,
        seq_start: row.get(1)?,
        seq_end: row.get(2)?,
        root_hash: row.get(3)?,
        signature: row.get(4)?,
        signer_did: row.get(5)?,
        prev_root: row.get(6)?,
    })
}

fn load_batch_events(conn: &Connection, batch: &MerkleBatchRow) -> Result<Vec<WrapEvent>> {
    let mut stmt = conn.prepare(
        "SELECT seq, event_json FROM wrap_events WHERE seq >= ?1 AND seq <= ?2 ORDER BY seq ASC",
    )?;
    let rows = stmt.query_map(params![batch.seq_start, batch.seq_end], |row| {
        let seq: i64 = row.get(0)?;
        let event_json: String = row.get(1)?;
        Ok((seq, event_json))
    })?;

    let mut events = Vec::new();
    for row in rows {
        let (seq, event_json) = row?;
        let mut event: WrapEvent = serde_json::from_str(&event_json)?;
        event.seq = Some(seq);
        events.push(event);
    }
    Ok(events)
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

    #[test]
    fn test_generate_sqlite_proof_roundtrip() {
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

        let agent = AgentInfo::new("AuditProofTest", DetectionSource::CommandLine);
        let e1 = WrapEvent::new(
            "sess-proof",
            "api.openai.com",
            WrapDirection::Out,
            agent.clone(),
        )
        .with_method("POST /v1/chat/completions");
        let e2 = WrapEvent::new("sess-proof", "api.openai.com", WrapDirection::In, agent)
            .with_method("POST /v1/chat/completions");
        let event_id = e1.id.clone();
        logger.log(&e1);
        logger.log(&e2);
        logger.close();

        let proof = generate_sqlite_proof(&db_path, &event_id).unwrap();
        assert_eq!(proof["event_id"].as_str(), Some(event_id.as_str()));
        assert!(proof["proof"]["siblings"].is_array());
        assert!(proof["batch_id"].as_str().is_some());
        assert_eq!(proof["tree_size"].as_u64(), Some(2));
    }
}
