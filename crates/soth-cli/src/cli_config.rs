//! Shared CLI config resolution helpers.

use anyhow::Result;
use soth_core::config::{self as shared_config, load_config, SothConfig};
use std::path::PathBuf;

pub use soth_core::config::{discover_default_config_path, expand_tilde, read_client_device_id};

pub fn resolve_config_path(
    explicit: Option<&PathBuf>,
    global: Option<&PathBuf>,
) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return Some(expand_tilde(path));
    }
    if let Some(path) = global {
        return Some(expand_tilde(path));
    }
    discover_default_config_path()
}

pub fn load_effective_config(
    explicit: Option<&PathBuf>,
    global: Option<&PathBuf>,
) -> Result<SothConfig> {
    if let Some(path) = resolve_config_path(explicit, global) {
        return Ok(load_config(path)?);
    }
    Ok(SothConfig::default())
}

pub fn sync_client_device_id(
    config: &mut SothConfig,
    preferred_device_id: Option<&str>,
) -> Result<String> {
    Ok(shared_config::sync_client_device_id(
        config,
        preferred_device_id,
    )?)
}
