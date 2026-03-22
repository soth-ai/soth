use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use soth_core::ObservationEvent;

use crate::context::ExtensionRuntimeContext;
use crate::error::ExtensionError;

// ---------------------------------------------------------------------------
// ObservationQueueWriter — passive observer path queue file writer
// ---------------------------------------------------------------------------

pub struct ObservationQueueWriter {
    path: PathBuf,
}

impl ObservationQueueWriter {
    pub fn for_extension(ctx: &ExtensionRuntimeContext, name: &str) -> Self {
        Self {
            path: ctx.observation_queue_file(name),
        }
    }

    pub fn from_path(path: PathBuf) -> Self {
        Self { path }
    }

    /// O_APPEND atomic write. On error: log warning, continue.
    /// Observations are best-effort — a missed write is not a governance failure.
    pub fn enqueue(&self, event: &ObservationEvent) -> Result<(), ExtensionError> {
        let record = ObservationQueueRecord {
            schema_version: 1,
            extension: event.extension_source.name(),
            event,
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

/// Borrowed record for writing.
#[derive(Serialize)]
pub struct ObservationQueueRecord<'a> {
    pub schema_version: u8,
    pub extension: &'a str,
    pub event: &'a ObservationEvent,
}

/// Owned record for reading back from queue files.
#[derive(Deserialize)]
pub struct OwnedObservationQueueRecord {
    pub schema_version: u8,
    pub extension: String,
    pub event: ObservationEvent,
}
