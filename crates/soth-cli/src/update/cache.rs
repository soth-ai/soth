//! Disk cache for the most-recent `soth update --check` result.
//!
//! Lives at `~/.soth/run/update_cache.json`. Read by `soth status` so
//! it can surface "🔔 Update available" without making its own network
//! call. Written by `soth update --check|--apply`.
//!
//! Phase 2 will extend this with the heartbeat-delivered offer (a
//! parallel `update_pending.json`).

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Payload of `~/.soth/run/update_cache.json`. Shape is allowed to grow
/// (additive serde fields with `#[serde(default)]`); never break old
/// readers in 0.1.x.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedUpdate {
    /// Unix epoch seconds when this entry was written.
    pub checked_at: u64,
    /// Channel that was queried.
    pub channel: String,
    /// Manifest-supplied latest version. None if the check ran but the
    /// channel reported no manifest yet.
    pub latest_version: Option<String>,
    /// Local CARGO_PKG_VERSION at the time of the check — handy for
    /// `soth status` to display "you're on X" without re-reading.
    pub current_version: String,
    /// Manifest-supplied release_seq for anti-rollback on the next apply.
    #[serde(default)]
    pub latest_release_seq: Option<u64>,
    /// Direct download URL for this host's platform, when applicable.
    #[serde(default)]
    pub download_url: Option<String>,
    /// Sha256 the binary at `download_url` must match.
    #[serde(default)]
    pub download_sha256: Option<String>,
    /// Optional release-notes URL pulled straight from the manifest.
    #[serde(default)]
    pub release_notes_url: Option<String>,
}

/// Resolve `~/.soth/run/update_cache.json`. Visible so callers (status,
/// integration tests) can stat / overwrite it without going through this
/// module's API.
pub struct UpdateCache;

impl UpdateCache {
    pub fn default_path() -> Result<PathBuf> {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("could not resolve home directory"))?;
        Ok(home.join(".soth").join("run").join("update_cache.json"))
    }

    pub fn write(entry: &CachedUpdate) -> Result<PathBuf> {
        let path = Self::default_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let body = serde_json::to_vec_pretty(entry).context("serializing update cache")?;
        std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
        Ok(path)
    }

    pub fn read() -> Result<Option<CachedUpdate>> {
        let path = Self::default_path()?;
        match std::fs::read(&path) {
            Ok(body) => {
                let parsed: CachedUpdate = serde_json::from_slice(&body)
                    .with_context(|| format!("parsing {}", path.display()))?;
                Ok(Some(parsed))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow::Error::from(e).context(format!("reading {}", path.display()))),
        }
    }

    pub fn now_epoch_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}
