use std::path::PathBuf;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub(crate) const RUNTIME_STATUS_FILE_NAME: &str = "proxy.bundle_runtime.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StartupBundleSource {
    #[default]
    Primary,
    FallbackLastKnownGood,
    StartupFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RuntimeBundleState {
    pub startup_bundle_source: StartupBundleSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub startup_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_reload_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_bundle_version: Option<String>,
    pub updated_at_epoch_ms: u64,
}

impl RuntimeBundleState {
    pub(crate) fn new(
        startup_bundle_source: StartupBundleSource,
        startup_error: Option<String>,
        active_bundle_version: Option<String>,
    ) -> Self {
        Self {
            startup_bundle_source,
            startup_error,
            last_reload_error: None,
            active_bundle_version,
            updated_at_epoch_ms: now_epoch_ms(),
        }
    }
}

pub(crate) fn record_bundle_reload_success(
    startup_bundle_source: StartupBundleSource,
    active_bundle_version: &str,
) -> Result<()> {
    let mut state = read_runtime_status().unwrap_or_else(|| {
        RuntimeBundleState::new(
            startup_bundle_source,
            None,
            Some(active_bundle_version.to_string()),
        )
    });
    state.startup_bundle_source = startup_bundle_source;
    state.active_bundle_version = Some(active_bundle_version.to_string());
    state.last_reload_error = None;
    state.updated_at_epoch_ms = now_epoch_ms();
    write_runtime_status(&state)
}

pub(crate) fn record_bundle_reload_failure(
    startup_bundle_source: StartupBundleSource,
    message: &str,
    active_bundle_version: Option<&str>,
) -> Result<()> {
    let mut state = read_runtime_status().unwrap_or_else(|| {
        RuntimeBundleState::new(
            startup_bundle_source,
            None,
            active_bundle_version.map(|value| value.to_string()),
        )
    });
    state.startup_bundle_source = startup_bundle_source;
    if let Some(version) = active_bundle_version {
        state.active_bundle_version = Some(version.to_string());
    }
    state.last_reload_error = Some(message.to_string());
    state.updated_at_epoch_ms = now_epoch_ms();
    write_runtime_status(&state)
}

pub(crate) fn write_runtime_status(state: &RuntimeBundleState) -> Result<()> {
    let path = runtime_status_path();
    let Some(parent) = path.parent() else {
        anyhow::bail!("runtime status path has no parent: {}", path.display());
    };
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create runtime status parent {}", parent.display()))?;
    let tmp_path = parent.join(format!(
        "{RUNTIME_STATUS_FILE_NAME}.tmp.{}.{}",
        process::id(),
        now_epoch_ms()
    ));
    let body = serde_json::to_vec_pretty(state).context("serialize runtime bundle status JSON")?;
    std::fs::write(tmp_path.as_path(), body)
        .with_context(|| format!("write temp runtime status {}", tmp_path.display()))?;
    if let Err(error) = std::fs::rename(tmp_path.as_path(), path.as_path()) {
        let _ = std::fs::remove_file(tmp_path.as_path());
        return Err(error).with_context(|| {
            format!(
                "promote runtime status from {} to {}",
                tmp_path.display(),
                path.display()
            )
        });
    }
    Ok(())
}

fn read_runtime_status() -> Option<RuntimeBundleState> {
    let path = runtime_status_path();
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<RuntimeBundleState>(&raw).ok()
}

fn runtime_status_path() -> PathBuf {
    run_dir().join(RUNTIME_STATUS_FILE_NAME)
}

fn now_epoch_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis() as u64,
        Err(e) => {
            tracing::warn!(error = %e, "system clock before UNIX epoch; using timestamp 0");
            0
        }
    }
}

fn run_dir() -> PathBuf {
    soth_home_dir().join("run")
}

fn soth_home_dir() -> PathBuf {
    if let Ok(value) = std::env::var("SOTH_HOME_DIR") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    dirs::home_dir()
        .map(|home| home.join(".soth"))
        .unwrap_or_else(|| PathBuf::from(".soth"))
}
