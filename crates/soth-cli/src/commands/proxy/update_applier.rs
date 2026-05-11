//! Phase 4 hot-update auto-applier.
//!
//! Tokio task spawned by the proxy supervisor. Polls the heartbeat-
//! delivered offer at `~/.soth/run/update_pending.json` every 60s and,
//! when the offer carries `urgency=Forced` and is otherwise eligible,
//! executes the same `--apply` path a user would run from the CLI.
//!
//! Trust model: the offer file alone is not sufficient — the apply
//! path always re-fetches and verifies the signed static manifest
//! before swapping bytes. The pending offer just tells the supervisor
//! "the cloud thinks you should apply now."
//!
//! Eligibility (all must hold):
//!   - urgency == Forced
//!   - apply_failed == false (cleared on success, set on failure)
//!   - consecutive_update_failures < 3 (the 3-strike cutoff)
//!   - offer.version > current local version (semver)
//!   - now >= apply_after_utc (RFC3339 floor; None = anytime)
//!
//! On apply failure: increment the local failure counter and write
//! `apply_failed=true` into the offer. The next heartbeat carries the
//! updated count; after 3 strikes the resolver stops offering updates
//! to this device.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

use crate::update::Channel;

const POLL_INTERVAL: Duration = Duration::from_secs(60);
const COUNTDOWN_SECS: u64 = 60;
const MAX_FAILURES: u32 = 3;

/// Sidecar file at `~/.soth/run/update_failures.json` carrying just the
/// running count. Kept separate from `update_pending.json` so a fresh
/// offer (which clears `apply_failed`) doesn't lose the counter we
/// report to the cloud.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ApplyFailures {
    #[serde(default)]
    pub count: u32,
    /// Last release_seq that failed. Lets us detect "operator pushed a
    /// new release" and reset the counter.
    #[serde(default)]
    pub last_release_seq: Option<u64>,
}

fn failures_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("no home directory"))?;
    Ok(home.join(".soth").join("run").join("update_failures.json"))
}

fn read_failures() -> ApplyFailures {
    let Ok(path) = failures_path() else {
        return ApplyFailures::default();
    };
    match std::fs::read(&path) {
        Ok(body) => serde_json::from_slice(&body).unwrap_or_default(),
        Err(_) => ApplyFailures::default(),
    }
}

fn write_failures(state: &ApplyFailures) {
    let path = match failures_path() {
        Ok(p) => p,
        Err(_) => return,
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(body) = serde_json::to_vec_pretty(state) {
        let _ = std::fs::write(path, body);
    }
}

/// Top-level supervisor task. Runs forever; logs but never propagates
/// errors so a transient disk/network failure doesn't take down the
/// whole proxy daemon.
pub async fn run() {
    tracing::info!(
        poll_secs = POLL_INTERVAL.as_secs(),
        "update auto-applier started"
    );
    loop {
        if let Err(error) = tick().await {
            tracing::warn!(error = %error, "update auto-applier tick failed");
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn tick() -> Result<()> {
    let pending = match soth_sync::update_pending::read()? {
        Some(p) => p,
        None => return Ok(()),
    };

    // Only Forced urgency is auto-applied. Notify / Recommended remain
    // user-driven — they show up in `soth status` and require an
    // explicit `soth update --apply`.
    if !matches!(
        pending.offer.urgency,
        soth_sync::api_types::UpdateUrgency::Forced
    ) {
        return Ok(());
    }

    if pending.apply_failed {
        // The user (or a previous tick of this loop) recorded a failure.
        // Wait for either a fresh offer (different release_seq) or
        // operator intervention before retrying.
        return Ok(());
    }

    // Reset the counter when the cloud advances release_seq — that's a
    // brand-new release, not a retry of the failing one.
    let mut failures = read_failures();
    if failures.last_release_seq != Some(pending.offer.release_seq) {
        failures = ApplyFailures::default();
        write_failures(&failures);
    }

    if failures.count >= MAX_FAILURES {
        tracing::warn!(
            failures = failures.count,
            release_seq = pending.offer.release_seq,
            "auto-applier giving up — failure cutoff reached; operator must clear"
        );
        return Ok(());
    }

    if !version_strictly_newer(&pending.offer.version, env!("CARGO_PKG_VERSION")) {
        // Offer is for an older or same version — nothing to do.
        return Ok(());
    }

    if let Some(apply_after) = pending.offer.apply_after.as_deref() {
        if let Ok(target) = chrono::DateTime::parse_from_rfc3339(apply_after) {
            if chrono::Utc::now() < target.with_timezone(&chrono::Utc) {
                tracing::debug!(
                    apply_after = %apply_after,
                    "auto-applier waiting for apply_after_utc"
                );
                return Ok(());
            }
        }
    }

    // The offer doesn't carry the channel name directly. Use the local
    // update_cache.json's last seen channel as a hint (the resolver
    // populates this whenever `soth update --check` runs); fall back
    // to stable, which is the most likely auto-applier user.
    let channel: Channel = match crate::update::UpdateCache::read() {
        Ok(Some(c)) if !c.channel.is_empty() => c.channel.parse().unwrap_or(Channel::Stable),
        _ => Channel::Stable,
    };

    eprintln!();
    eprintln!(
        "── soth auto-update: applying {} (urgency=Forced, release_seq={}) ──",
        pending.offer.version, pending.offer.release_seq,
    );
    countdown(COUNTDOWN_SECS).await;

    match crate::commands::update::run_apply(channel, None, false, None).await {
        Ok(()) => {
            tracing::info!(
                version = %pending.offer.version,
                release_seq = pending.offer.release_seq,
                "auto-applier succeeded"
            );
            // run_apply already cleared update_pending.json on success.
            // Reset the failure counter for good measure.
            write_failures(&ApplyFailures::default());
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                version = %pending.offer.version,
                release_seq = pending.offer.release_seq,
                "auto-applier apply failed; recording failure"
            );
            failures.count = failures.count.saturating_add(1);
            failures.last_release_seq = Some(pending.offer.release_seq);
            write_failures(&failures);
            // run_apply already wrote apply_failed=true into update_pending.
        }
    }

    Ok(())
}

async fn countdown(secs: u64) {
    eprintln!(
        "Restarting soth in {} seconds. Press Ctrl-C in the daemon to abort.",
        secs
    );
    let interval = if secs >= 5 { secs / 5 } else { 1 };
    let mut remaining = secs;
    while remaining > 0 {
        let step = remaining.min(interval);
        tokio::time::sleep(Duration::from_secs(step)).await;
        remaining = remaining.saturating_sub(step);
        if remaining > 0 {
            eprintln!("  …{} seconds…", remaining);
        }
    }
}

fn version_strictly_newer(candidate: &str, current: &str) -> bool {
    use semver::Version;
    match (Version::parse(candidate), Version::parse(current)) {
        (Ok(a), Ok(b)) => a > b,
        _ => candidate != current,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_strictly_newer_basic() {
        assert!(version_strictly_newer("0.1.5", "0.1.4"));
        assert!(version_strictly_newer("0.2.0", "0.1.99"));
        assert!(!version_strictly_newer("0.1.4", "0.1.4"));
        assert!(!version_strictly_newer("0.1.3", "0.1.4"));
    }

    #[test]
    fn version_strictly_newer_falls_back_on_garbage() {
        // Falls back to strict string compare; never panics.
        assert!(version_strictly_newer("nonsense", "0.1.4"));
        assert!(!version_strictly_newer("0.1.4", "0.1.4"));
    }

    #[test]
    fn failures_state_serde_roundtrip() {
        let s = ApplyFailures {
            count: 2,
            last_release_seq: Some(7),
        };
        let body = serde_json::to_vec(&s).unwrap();
        let back: ApplyFailures = serde_json::from_slice(&body).unwrap();
        assert_eq!(back.count, 2);
        assert_eq!(back.last_release_seq, Some(7));
    }

    #[test]
    fn failures_state_defaults_when_empty() {
        let body = b"{}";
        let parsed: ApplyFailures = serde_json::from_slice(body).unwrap();
        assert_eq!(parsed.count, 0);
        assert_eq!(parsed.last_release_seq, None);
    }
}
