use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use soth_core::{GovernableEvent, PolicyDecision};

use crate::context::ExtensionRuntimeContext;
use crate::error::ExtensionError;

// ---------------------------------------------------------------------------
// TelemetryQueueWriter — governance path queue file writer
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct TelemetryQueueWriter {
    path: PathBuf,
}

impl TelemetryQueueWriter {
    pub fn for_extension(ctx: &ExtensionRuntimeContext, name: &str) -> Self {
        Self {
            path: ctx.governance_queue_file(name),
        }
    }

    pub fn from_path(path: PathBuf) -> Self {
        Self { path }
    }

    /// O_APPEND atomic write. On error: log warning, continue.
    /// Never hard-fails a hook invocation.
    pub fn enqueue(
        &self,
        event: &GovernableEvent,
        decision: &PolicyDecision,
    ) -> Result<(), ExtensionError> {
        let record = GovernableQueueRecord {
            schema_version: 1,
            extension: &event.context.extension_name,
            event,
            decision,
        };
        let mut line = serde_json::to_string(&record)
            .map_err(|e| ExtensionError::QueueWrite(e.to_string()))?;
        line.push('\n');

        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ExtensionError::QueueWrite(e.to_string()))?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| ExtensionError::QueueWrite(e.to_string()))?;
        file.write_all(line.as_bytes())
            .map_err(|e| ExtensionError::QueueWrite(e.to_string()))?;
        Ok(())
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

/// Borrowed record for writing. soth-telemetry's drain loop declares its own
/// owned deserialization struct — no cross-crate dep needed.
#[derive(Serialize)]
pub struct GovernableQueueRecord<'a> {
    pub schema_version: u8,
    pub extension: &'a str,
    pub event: &'a GovernableEvent,
    pub decision: &'a PolicyDecision,
}

/// Owned record for reading back from queue files (used in tests, drain loops).
#[derive(Deserialize)]
pub struct OwnedGovernableQueueRecord {
    pub schema_version: u8,
    pub extension: String,
    pub event: GovernableEvent,
    pub decision: PolicyDecision,
}
