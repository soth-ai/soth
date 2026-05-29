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

    // Derive the manifest base URL from the offer's download URL so we
    // apply against the *same* environment the cloud just pointed us at
    // (staging cloud → staging storage, prod cloud → prod storage).
    // Without this the auto-applier would always fall back to the
    // baked-in prod default, which is wrong for staging-resolved offers.
    //
    // Pin the version too: that fetches the frozen per-version manifest
    // snapshot (immutable) and implicitly opts out of anti-rollback —
    // the operator pushing a Forced offer for a specific version IS the
    // explicit authorization to install it.
    let base_url = crate::commands::update::derive_base_url_from_offer(
        &pending.offer.url,
        &pending.offer.version,
    );
    let pinned_version = Some(pending.offer.version.clone());

    let outcome =
        run_apply_for_platform(channel, base_url, pinned_version, &pending.offer.version).await;

    match outcome {
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

/// Platform-specific apply dispatch.
///
/// macOS and Linux both have a self-kill problem: the swap's pre-step
/// stops the running daemon via the platform supervisor (`launchctl
/// bootout` on macOS, `systemctl stop` / SIGTERM on Linux), which
/// kills the very process trying to perform the swap. The fix is to
/// download in the daemon, then hand off the staged file to a
/// detached `soth update --finish-staged` helper (forked with
/// `setsid(2)` so it survives the daemon's death) that drives the
/// rest of the swap from outside the daemon's process group.
///
/// Windows takes the direct `run_apply` path — its `Swapper::swap`
/// already spawns the `soth-update.exe` sidecar and exits the parent
/// process cleanly, so the equivalent handoff happens inside the
/// existing swap implementation.
#[cfg(unix)]
async fn run_apply_for_platform(
    channel: crate::update::Channel,
    base_url: Option<String>,
    pinned_version: Option<String>,
    offer_version: &str,
) -> anyhow::Result<()> {
    use crate::update::{
        download_binary, fetch_and_verify_manifest, platform_key, BinarySink, VerifyOptions,
    };
    use anyhow::Context;

    let opts = VerifyOptions {
        base_url: base_url.clone(),
        last_release_seq: None,
        force_downgrade: false,
        current_version_override: None,
        pinned_version: pinned_version.clone(),
    };
    let manifest = fetch_and_verify_manifest(channel, &opts)
        .await
        .with_context(|| format!("manifest fetch/verify for channel {}", channel.as_str()))?;

    if manifest.version != offer_version {
        anyhow::bail!(
            "fetched manifest version '{}' does not match offered '{}' — \
             aborting auto-apply",
            manifest.version,
            offer_version
        );
    }

    let plat = platform_key();
    let entry = manifest
        .platforms
        .get(plat)
        .with_context(|| format!("manifest has no platform entry for '{plat}'"))?
        .clone();

    tracing::info!(
        version = %manifest.version,
        url = %entry.url,
        "auto-applier downloading staged binary"
    );
    let sink = BinarySink::default_for_user()?;
    let staged = download_binary(&entry.url, &entry.sha256, &sink)
        .await
        .context("download / sha256-verify failed")?;

    spawn_finish_staged_helper(channel, &staged, base_url, pinned_version)
        .context("spawning --finish-staged helper")?;

    // Handoff complete; the helper will stop us (launchctl bootout /
    // systemctl stop) in a moment. Return Ok so the failure counter
    // doesn't increment — if the helper itself fails, it writes
    // apply_failed back into update_pending.json which we'll see next
    // tick (assuming the supervisor respawns us with the OLD binary).
    Ok(())
}

#[cfg(windows)]
async fn run_apply_for_platform(
    channel: crate::update::Channel,
    base_url: Option<String>,
    pinned_version: Option<String>,
    _offer_version: &str,
) -> anyhow::Result<()> {
    crate::commands::update::run_apply(channel, base_url, false, pinned_version).await
}

/// Fork a detached child running `soth update --finish-staged`. New
/// session via `setsid(2)` so the supervisor signal (launchctl bootout
/// on macOS, systemctl stop / SIGTERM on Linux) sent at the daemon
/// during the helper's pre_swap doesn't propagate to the helper.
#[cfg(unix)]
fn spawn_finish_staged_helper(
    channel: crate::update::Channel,
    staged_path: &std::path::Path,
    base_url: Option<String>,
    pinned_version: Option<String>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let exe = std::env::current_exe().context("resolving current exe for helper")?;

    let log_path = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("no home dir"))?
        .join(".soth")
        .join("logs")
        .join("auto-update-helper.log");
    if let Some(parent) = log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let log_out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("opening helper log {}", log_path.display()))?;
    let log_err = log_out
        .try_clone()
        .context("cloning helper log handle for stderr")?;

    let mut cmd = Command::new(&exe);
    cmd.args(["update", "--finish-staged"])
        .arg("--channel")
        .arg(channel.as_str())
        .arg("--staged-path")
        .arg(staged_path);
    if let Some(url) = base_url.as_deref() {
        cmd.arg("--manifest-url").arg(url);
    }
    if let Some(v) = pinned_version.as_deref() {
        cmd.arg("--version").arg(v);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(log_out))
        .stderr(Stdio::from(log_err));

    // Detach: new session via setsid so launchctl bootout (sent at the
    // daemon, the helper's parent) doesn't take the helper out with it.
    // Safety: pre_exec runs in the child after fork, before exec —
    // setsid is async-signal-safe so this is fine.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = cmd.spawn().context("spawning detached helper")?;
    tracing::info!(
        helper_pid = child.id(),
        log = %log_path.display(),
        "auto-update helper spawned (detached); daemon will be killed by bootout shortly"
    );
    // Intentionally don't .wait() — the helper is detached and will
    // outlive us. If we waited, we'd block forever (we're about to die).
    std::mem::forget(child);
    Ok(())
}

async fn countdown(secs: u64) {
    eprintln!("Restarting soth in {secs} seconds. Press Ctrl-C in the daemon to abort.");
    let interval = if secs >= 5 { secs / 5 } else { 1 };
    let mut remaining = secs;
    while remaining > 0 {
        let step = remaining.min(interval);
        tokio::time::sleep(Duration::from_secs(step)).await;
        remaining = remaining.saturating_sub(step);
        if remaining > 0 {
            eprintln!("  …{remaining} seconds…");
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
