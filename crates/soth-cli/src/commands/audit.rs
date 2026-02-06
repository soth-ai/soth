//! Audit trail management commands

use crate::AuditCommands;
use anyhow::Result;
use soth_observe::MerkleTree;
use std::path::PathBuf;
use tokio::fs;

/// Run audit command
pub async fn run(action: AuditCommands) -> Result<()> {
    match action {
        AuditCommands::Verify { log } => {
            verify_log(log).await?;
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

/// Convert bytes to hex string
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Verify Merkle audit trail integrity
async fn verify_log(log_path: PathBuf) -> Result<()> {
    if !log_path.exists() {
        anyhow::bail!("Log file not found: {log_path:?}");
    }

    let content = fs::read_to_string(&log_path).await?;
    let lines: Vec<&str> = content.lines().collect();

    if lines.is_empty() {
        println!("Log file is empty");
        return Ok(());
    }

    println!("Verifying {} entries...\n", lines.len());

    let mut tree = MerkleTree::new();
    let mut errors = 0;
    let mut valid = 0;

    for (i, line) in lines.iter().enumerate() {
        if let Ok(event) = serde_json::from_str::<serde_json::Value>(line) {
            // Add to Merkle tree
            let data = serde_json::to_vec(&event)?;
            tree.append(&data);
            valid += 1;

            // Show progress every 1000 entries
            if (i + 1) % 1000 == 0 {
                print!("\rProcessed {} entries...", i + 1);
            }
        } else {
            errors += 1;
            println!("  Line {}: Invalid JSON", i + 1);
        }
    }

    println!("\r");

    if errors == 0 {
        println!("All {valid} entries are valid");
        println!("\nMerkle Tree:");
        if let Some(root) = tree.root() {
            println!("  Root hash: {}", hex_encode(root));
        }
        println!("  Entries: {}", tree.len());
    } else {
        println!("Found {} invalid entries out of {}", errors, lines.len());
    }

    Ok(())
}

/// Generate proof for an event
async fn generate_proof(event_id: &str, output: Option<PathBuf>) -> Result<()> {
    let log_path = PathBuf::from("logs/observations.jsonl");

    if !log_path.exists() {
        anyhow::bail!("Log file not found: {log_path:?}");
    }

    let content = fs::read_to_string(&log_path).await?;
    let lines: Vec<&str> = content.lines().collect();

    // Build Merkle tree and find event
    let mut tree = MerkleTree::new();
    let mut event_index = None;
    let mut event_data = None;

    for (i, line) in lines.iter().enumerate() {
        if let Ok(event) = serde_json::from_str::<serde_json::Value>(line) {
            let data = serde_json::to_vec(&event)?;
            tree.append(&data);

            if event.get("id").and_then(|id| id.as_str()) == Some(event_id) {
                event_index = Some(i);
                event_data = Some(event);
            }
        }
    }

    let index = event_index.ok_or_else(|| anyhow::anyhow!("Event not found: {event_id}"))?;
    let event = event_data.unwrap();

    // Generate proof
    let proof = tree.get_proof(index)
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

    let content = fs::read_to_string(&log_path).await?;
    let lines: Vec<&str> = content.lines().collect();

    let mut stats = AuditStats::default();

    for line in &lines {
        if let Ok(event) = serde_json::from_str::<serde_json::Value>(line) {
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
