//! `soth update` — Phase 1 hot-update entry points.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;

use crate::update::{
    download_binary, fetch_and_verify_manifest, make_swapper, platform_key, BinarySink,
    CachedUpdate, Channel, UpdateCache, VerifyOptions,
};

/// Status reported by `soth update --check`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateStatus {
    /// Server reports no manifest yet, or our version >= manifest version.
    UpToDate,
    /// Manifest's version is newer than our local version.
    UpdateAvailable,
}

impl UpdateStatus {
    pub fn exit_code(self) -> i32 {
        match self {
            UpdateStatus::UpToDate => 0,
            UpdateStatus::UpdateAvailable => 2, // 0=no-op, 1=err, 2=actionable
        }
    }
}

/// `soth update [--check]` — fetch + verify manifest, write cache, print status.
pub async fn run_check(
    channel: Channel,
    base_url_override: Option<String>,
) -> Result<UpdateStatus> {
    let opts = VerifyOptions {
        base_url: base_url_override,
        last_release_seq: read_last_seen_seq(channel),
        force_downgrade: false,
        current_version_override: None,
    };

    let manifest = match fetch_and_verify_manifest(channel, &opts).await {
        Ok(m) => m,
        Err(e) => {
            // Soft-fail on the seq gate — we don't want a downgraded
            // manifest to look like an error to a user just running
            // `soth update --check`. Surface as "up-to-date" but warn.
            let msg = format!("{:#}", e);
            if msg.contains("anti-rollback gate") {
                println!("up-to-date (server's manifest is older than last applied)");
                write_cache_no_update(channel)?;
                return Ok(UpdateStatus::UpToDate);
            }
            return Err(e).with_context(|| {
                format!(
                    "could not fetch / verify manifest for channel {}",
                    channel.as_str()
                )
            });
        }
    };

    let plat = platform_key();
    let entry = manifest.platforms.get(plat).cloned();

    let current = env!("CARGO_PKG_VERSION").to_string();
    let is_newer = is_strictly_newer(&manifest.version, &current);

    let cached = CachedUpdate {
        checked_at: UpdateCache::now_epoch_secs(),
        channel: manifest.channel.clone(),
        latest_version: Some(manifest.version.clone()),
        current_version: current.clone(),
        latest_release_seq: Some(manifest.release_seq),
        download_url: entry.as_ref().map(|e| e.url.clone()),
        download_sha256: entry.as_ref().map(|e| e.sha256.clone()),
        release_notes_url: manifest.release_notes_url.clone(),
    };
    UpdateCache::write(&cached)?;

    if !is_newer {
        println!(
            "up-to-date (you're on {}, channel {} latest is {})",
            current, manifest.channel, manifest.version
        );
        return Ok(UpdateStatus::UpToDate);
    }

    if entry.is_none() {
        println!(
            "update available: {} → {} (channel {})",
            current, manifest.version, manifest.channel
        );
        println!(
            "  but no platform entry for '{}' — manual download required",
            plat
        );
        return Ok(UpdateStatus::UpdateAvailable);
    }
    let entry = entry.unwrap();

    println!(
        "update available: {} → {} (channel {}, release_seq={})",
        current, manifest.version, manifest.channel, manifest.release_seq
    );
    println!("  url:    {}", entry.url);
    println!("  sha256: {}", entry.sha256);
    if let Some(notes) = &manifest.release_notes_url {
        println!("  notes:  {}", notes);
    }
    println!(
        "  apply:  soth update --apply --channel {}",
        manifest.channel
    );

    Ok(UpdateStatus::UpdateAvailable)
}

/// `soth update --apply` — download, verify, swap, restart.
///
/// Note on the heartbeat-delivered offer (Phase 2):
///   The agent persists `~/.soth/run/update_pending.json` when the
///   cloud signals an offer over heartbeat. We deliberately do NOT use
///   that as the source of truth for `--apply`. The signed static
///   manifest at the storage URL is the trust root — operator-
///   controlled, independent of cloud auth. A compromised cloud could
///   push a malicious heartbeat offer; the manifest signature gate
///   prevents that from translating into a malicious binary install.
///   We do clear / mark the pending file based on apply outcome, but
///   the *trust* path is always manifest → signature → sha256.
pub async fn run_apply(
    channel: Channel,
    base_url_override: Option<String>,
    force_downgrade: bool,
) -> Result<()> {
    let opts = VerifyOptions {
        base_url: base_url_override,
        last_release_seq: read_last_seen_seq(channel),
        force_downgrade,
        current_version_override: None,
    };
    let manifest = fetch_and_verify_manifest(channel, &opts)
        .await
        .with_context(|| format!("manifest fetch/verify for channel {}", channel.as_str()))?;

    let current = env!("CARGO_PKG_VERSION");
    if !force_downgrade && !is_strictly_newer(&manifest.version, current) {
        println!(
            "already on {} (channel {} latest is {}); nothing to do",
            current, manifest.channel, manifest.version
        );
        return Ok(());
    }

    let plat = platform_key();
    let entry = manifest
        .platforms
        .get(plat)
        .with_context(|| format!("manifest has no platform entry for '{}'", plat))?
        .clone();

    println!("downloading soth {} from {}…", manifest.version, entry.url);
    let sink = BinarySink::default_for_user()?;
    let staged = download_binary(&entry.url, &entry.sha256, &sink)
        .await
        .context("download / sha256-verify failed")?;

    println!("staged at {}; swapping…", staged.display());
    let swapper = make_swapper(staged)?;

    if let Err(e) = swapper.pre_swap().await {
        mark_pending_apply_failed(&format!("pre-swap: {:#}", e));
        bail!("pre-swap failed: {:#}", e);
    }
    if let Err(e) = swapper.swap().await {
        // We may have stopped the daemon but failed mid-rename. Best-effort
        // restart of whatever is still on disk so the user isn't left
        // without a running proxy.
        let _ = swapper.post_swap().await;
        mark_pending_apply_failed(&format!("swap: {:#}", e));
        bail!("swap failed: {:#} (daemon restart attempted)", e);
    }
    if let Err(e) = swapper.post_swap().await {
        tracing::warn!(error = %e, "post-swap healthcheck failed; rolling back");
        if let Err(rb) = swapper.rollback().await {
            mark_pending_apply_failed(&format!("apply+rollback: {:#}", e));
            bail!(
                "apply failed AND rollback failed: apply={:#}; rollback={:#}",
                e,
                rb
            );
        }
        mark_pending_apply_failed(&format!("post-swap rolled back: {:#}", e));
        bail!("apply failed: {:#}; rolled back to previous binary", e);
    }

    // On success, persist updated cache so subsequent --check is honest.
    let cached = CachedUpdate {
        checked_at: UpdateCache::now_epoch_secs(),
        channel: manifest.channel.clone(),
        latest_version: Some(manifest.version.clone()),
        current_version: manifest.version.clone(),
        latest_release_seq: Some(manifest.release_seq),
        download_url: Some(entry.url),
        download_sha256: Some(entry.sha256),
        release_notes_url: manifest.release_notes_url.clone(),
    };
    UpdateCache::write(&cached)?;

    // Phase 2: clear the heartbeat-delivered offer so subsequent
    // `soth status` calls don't keep nagging.
    if let Err(e) = soth_sync::update_pending::clear() {
        tracing::warn!(error = %e, "failed to clear update_pending.json after successful apply");
    }

    println!(
        "✓ updated to {} (channel {})",
        manifest.version, manifest.channel
    );
    Ok(())
}

/// Mark the in-flight heartbeat offer as failed so the auto-applier
/// (Phase 4) doesn't immediately re-attempt the same `release_seq`.
/// Best-effort; never propagates errors out of the apply path.
fn mark_pending_apply_failed(reason: &str) {
    if let Ok(Some(mut pending)) = soth_sync::update_pending::read() {
        pending.apply_failed = true;
        pending.apply_failed_reason = Some(reason.to_string());
        if let Err(e) = soth_sync::update_pending::write(&pending) {
            tracing::warn!(error = %e, "failed to persist apply_failed=true");
        }
    }
}

/// `soth update --rollback` — restore `<install>.previous`.
pub async fn run_rollback() -> Result<()> {
    let stage = PathBuf::from("/dev/null"); // unused for rollback
    let swapper = make_swapper(stage)?;
    swapper.rollback().await.context("rollback")?;
    println!("✓ rolled back to previous binary");
    Ok(())
}

fn is_strictly_newer(candidate: &str, current: &str) -> bool {
    use semver::Version;
    match (Version::parse(candidate), Version::parse(current)) {
        (Ok(c), Ok(u)) => c > u,
        // If either is unparseable, fall back to strict string compare —
        // safer than auto-applying.
        _ => candidate != current,
    }
}

fn read_last_seen_seq(_channel: Channel) -> Option<u64> {
    UpdateCache::read()
        .ok()
        .flatten()
        .and_then(|c| c.latest_release_seq)
}

fn write_cache_no_update(channel: Channel) -> Result<()> {
    let entry = CachedUpdate {
        checked_at: UpdateCache::now_epoch_secs(),
        channel: channel.as_str().to_string(),
        latest_version: None,
        current_version: env!("CARGO_PKG_VERSION").to_string(),
        latest_release_seq: None,
        download_url: None,
        download_sha256: None,
        release_notes_url: None,
    };
    UpdateCache::write(&entry).map(|_| ())
}
