//! Shared CLI config resolution helpers.

use anyhow::{Context, Result};
use soth_core::config::{load_config, SothConfig};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const DEFAULT_CONFIG_CANDIDATES: [&str; 4] =
    ["soth.yaml", "soth.yml", ".soth.yaml", "~/.soth/soth.yaml"];
const CLIENT_DEVICE_ID_FILE_NAME: &str = "client_device_id";

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

pub fn load_effective_config(
    explicit: Option<&PathBuf>,
    global: Option<&PathBuf>,
) -> Result<SothConfig> {
    if let Some(path) = resolve_config_path(explicit, global) {
        return Ok(load_config(path)?);
    }
    Ok(SothConfig::default())
}

pub fn default_soth_home_dir() -> PathBuf {
    dirs::home_dir()
        .map(|home| home.join(".soth"))
        .unwrap_or_else(|| PathBuf::from(".soth"))
}

pub fn client_device_id_path() -> PathBuf {
    default_soth_home_dir().join(CLIENT_DEVICE_ID_FILE_NAME)
}

pub fn read_client_device_id() -> Option<String> {
    let path = client_device_id_path();
    let raw = fs::read_to_string(path).ok()?;
    normalize_client_device_id(raw.as_str())
}

pub fn sync_client_device_id(
    config: &mut SothConfig,
    preferred_device_id: Option<&str>,
) -> Result<String> {
    let resolved = normalize_client_device_id_opt(preferred_device_id)
        .or_else(|| {
            config
                .cloud
                .tags
                .get("device_id")
                .and_then(|value| normalize_client_device_id(value))
        })
        .or_else(read_client_device_id)
        .unwrap_or_else(generate_client_device_id);

    config
        .cloud
        .tags
        .insert("device_id".to_string(), resolved.clone());
    write_client_device_id(resolved.as_str())?;
    Ok(resolved)
}

fn write_client_device_id(device_id: &str) -> Result<()> {
    let path = client_device_id_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    fs::write(&path, format!("{device_id}\n"))
        .with_context(|| format!("failed writing {}", path.display()))?;
    set_client_device_id_readable_permissions(path.as_path());
    Ok(())
}

fn set_client_device_id_readable_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(path) {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o644);
            let _ = fs::set_permissions(path, permissions);
        }
    }
}

fn generate_client_device_id() -> String {
    format!("dev_{}", Uuid::new_v4().simple())
}

fn normalize_client_device_id_opt(value: Option<&str>) -> Option<String> {
    value.and_then(normalize_client_device_id)
}

fn normalize_client_device_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
