//! Persists the last heartbeat rejection so out-of-process readers
//! (`soth status`, `soth doctor`) can surface *why* the daemon stopped
//! heartbeating instead of just showing "Last heartbeat: never".
//!
//! Lives at `~/.soth/run/heartbeat_rejection.json`. Written whenever the
//! cloud responds to a heartbeat with a non-2xx status (most commonly a
//! 403 org/identity mismatch after an org migration), and cleared on the
//! next accepted heartbeat. Best-effort throughout — a disk failure here
//! must never abort the heartbeat loop.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// On-disk shape for `~/.soth/run/heartbeat_rejection.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRejection {
    /// Unix epoch seconds when the rejection was observed.
    pub rejected_at: u64,
    /// HTTP status the cloud returned (e.g. 403).
    pub status: u16,
    /// Truncated response body / server message, for operator context.
    pub message: String,
    /// The endpoint URL the heartbeat targeted.
    pub endpoint: String,
}

/// Resolve `~/.soth/run/heartbeat_rejection.json`.
pub fn default_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("could not resolve home directory"))?;
    Ok(home
        .join(".soth")
        .join("run")
        .join("heartbeat_rejection.json"))
}

pub fn write(entry: &HeartbeatRejection) -> Result<PathBuf> {
    let path = default_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let body = serde_json::to_vec_pretty(entry).context("serializing heartbeat_rejection.json")?;
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

pub fn read() -> Result<Option<HeartbeatRejection>> {
    let path = default_path()?;
    match std::fs::read(&path) {
        Ok(body) => {
            let parsed: HeartbeatRejection = serde_json::from_slice(&body)
                .with_context(|| format!("parsing {}", path.display()))?;
            Ok(Some(parsed))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::Error::from(e).context(format!("reading {}", path.display()))),
    }
}

/// Best-effort delete. Called on the next accepted heartbeat so a stale
/// rejection doesn't keep alarming `soth status` after recovery.
pub fn clear() -> Result<()> {
    let path = default_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::Error::from(e).context(format!("removing {}", path.display()))),
    }
}

pub fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_serde_preserves_fields() {
        let entry = HeartbeatRejection {
            rejected_at: 1_700_000_000,
            status: 403,
            message: "org mismatch".into(),
            endpoint: "https://ingest.example.com/v1/edge/heartbeat".into(),
        };
        let body = serde_json::to_vec(&entry).unwrap();
        let back: HeartbeatRejection = serde_json::from_slice(&body).unwrap();
        assert_eq!(back.status, 403);
        assert_eq!(back.rejected_at, 1_700_000_000);
        assert_eq!(back.message, "org mismatch");
        assert_eq!(back.endpoint, "https://ingest.example.com/v1/edge/heartbeat");
    }
}
