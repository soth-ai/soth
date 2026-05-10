//! Persists the heartbeat-delivered hot-update offer to disk so that
//! out-of-process readers (`soth status`, `soth update --apply`,
//! the Phase 4 auto-applier) can act on it without making their own
//! network call.
//!
//! Lives at `~/.soth/run/update_pending.json`. Distinct from
//! `update_cache.json` (Phase 1) which records the *last manifest fetch*
//! result. Phase 1 is pull-based; Phase 2 is push-based — both files
//! coexist, and `soth update --apply` prefers the freshest one.

use crate::api_types::UpdateAvailable;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// On-disk shape for `~/.soth/run/update_pending.json`. The offer is
/// embedded as-is, plus a `received_at` Unix-epoch timestamp so readers
/// can decide whether the file is fresh enough to act on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingUpdate {
    /// Unix epoch seconds when the offer was received.
    pub received_at: u64,
    /// Heartbeat agent_instance_id this offer was targeted at. Lets
    /// readers detect (e.g. on a re-enrolled instance) when a stale
    /// pending file is pointing at a different identity.
    pub agent_instance_id: String,
    /// Local CARGO_PKG_VERSION at the time of receipt, so out-of-process
    /// readers don't need to re-derive it.
    pub current_version: String,
    /// The unmodified offer the cloud sent.
    pub offer: UpdateAvailable,
    /// `true` once `soth update --apply` records that this offer's apply
    /// failed. Phase 4 auto-applier reads this to back off — never
    /// auto-retries the same `release_seq` if `apply_failed=true`.
    #[serde(default)]
    pub apply_failed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply_failed_reason: Option<String>,
}

/// Resolve `~/.soth/run/update_pending.json`.
pub fn default_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("could not resolve home directory"))?;
    Ok(home.join(".soth").join("run").join("update_pending.json"))
}

pub fn write(entry: &PendingUpdate) -> Result<PathBuf> {
    let path = default_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let body = serde_json::to_vec_pretty(entry).context("serializing update_pending.json")?;
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

pub fn read() -> Result<Option<PendingUpdate>> {
    let path = default_path()?;
    match std::fs::read(&path) {
        Ok(body) => {
            let parsed: PendingUpdate = serde_json::from_slice(&body)
                .with_context(|| format!("parsing {}", path.display()))?;
            Ok(Some(parsed))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::Error::from(e)
            .context(format!("reading {}", path.display()))),
    }
}

/// Best-effort delete. Used by `soth update --apply` after a successful
/// apply to clear the pending offer so subsequent `soth status` calls
/// don't keep nagging the user.
pub fn clear() -> Result<()> {
    let path = default_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::Error::from(e)
            .context(format!("removing {}", path.display()))),
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
    use crate::api_types::UpdateUrgency;

    fn fixture_offer(version: &str, seq: u64) -> UpdateAvailable {
        UpdateAvailable {
            version: version.to_string(),
            release_seq: seq,
            url: "https://example.invalid/binary".to_string(),
            sha256: "0".repeat(64),
            urgency: UpdateUrgency::Recommended,
            release_notes_url: None,
            apply_after: None,
        }
    }

    #[test]
    fn roundtrip_serde_preserves_fields() {
        let entry = PendingUpdate {
            received_at: 1_700_000_000,
            agent_instance_id: "agent-x".into(),
            current_version: "0.1.1".into(),
            offer: fixture_offer("0.1.2", 7),
            apply_failed: false,
            apply_failed_reason: None,
        };
        let body = serde_json::to_vec(&entry).unwrap();
        let back: PendingUpdate = serde_json::from_slice(&body).unwrap();
        assert_eq!(back.offer.version, "0.1.2");
        assert_eq!(back.offer.release_seq, 7);
        assert_eq!(back.received_at, 1_700_000_000);
        assert!(!back.apply_failed);
    }

    #[test]
    fn missing_apply_failed_defaults_false() {
        let body = br#"{
            "received_at": 1,
            "agent_instance_id": "x",
            "current_version": "0.1.1",
            "offer": {
                "version": "0.1.2",
                "release_seq": 1,
                "url": "u",
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                "urgency": "recommended"
            }
        }"#;
        let parsed: PendingUpdate = serde_json::from_slice(body).unwrap();
        assert!(!parsed.apply_failed);
        assert!(parsed.apply_failed_reason.is_none());
    }
}
