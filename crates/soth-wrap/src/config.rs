//! Config resolution helpers for wrap runtime.

use anyhow::Result;
use soth_core::config::{self as shared_config, load_config, SothConfig};
use soth_core::config::{discover_default_config_path, expand_tilde};
use std::path::PathBuf;

pub fn load_effective_config(explicit: Option<&PathBuf>) -> Result<SothConfig> {
    if let Some(path) = explicit {
        return Ok(load_config(expand_tilde(path))?);
    }
    if let Some(path) = discover_default_config_path() {
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
