//! Shared CLI config resolution helpers.

use anyhow::Result;
use soth_core::config::{load_config, SothConfig};
use std::path::{Path, PathBuf};

const DEFAULT_CONFIG_CANDIDATES: [&str; 4] =
    ["soth.yaml", "soth.yml", ".soth.yaml", "~/.soth/soth.yaml"];

pub fn expand_tilde(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    let as_str = path.to_string_lossy();
    if let Some(stripped) = as_str.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped);
        }
    }
    path.to_path_buf()
}

pub fn default_config_candidates() -> Vec<PathBuf> {
    DEFAULT_CONFIG_CANDIDATES
        .iter()
        .map(|candidate| expand_tilde(Path::new(candidate)))
        .collect()
}

pub fn discover_default_config_path() -> Option<PathBuf> {
    default_config_candidates()
        .into_iter()
        .find(|candidate| candidate.exists())
}

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

pub fn load_effective_config(explicit: Option<&PathBuf>, global: Option<&PathBuf>) -> Result<SothConfig> {
    if let Some(path) = resolve_config_path(explicit, global) {
        return Ok(load_config(path)?);
    }
    Ok(SothConfig::default())
}

