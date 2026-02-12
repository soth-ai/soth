use anyhow::Context;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use soth_core::api::{ConfigResponse, RegistryVersionResponse};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedConfigEnvelope {
    pub fetched_at: String,
    pub config: ConfigResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedRegistryBundleEnvelope {
    pub fetched_at: String,
    pub etag: String,
    pub metadata: RegistryVersionResponse,
    pub bundle: Value,
}

pub fn default_cache_path() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".soth").join("cloud_config_cache.json")
    } else {
        PathBuf::from(".soth/cloud_config_cache.json")
    }
}

pub fn default_registry_cache_path() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".soth").join("registry_bundle_cache.json")
    } else {
        PathBuf::from(".soth/registry_bundle_cache.json")
    }
}

pub fn load_config_cache(path: &Path) -> anyhow::Result<Option<ConfigResponse>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading cloud cache {}", path.display()))?;
    let envelope: CachedConfigEnvelope = serde_json::from_str(&content)
        .with_context(|| format!("failed parsing cloud cache {}", path.display()))?;
    Ok(Some(envelope.config))
}

pub fn save_config_cache(path: &Path, config: &ConfigResponse) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating cloud cache parent directory {}",
                parent.display()
            )
        })?;
    }
    let envelope = CachedConfigEnvelope {
        fetched_at: Utc::now().to_rfc3339(),
        config: config.clone(),
    };
    let payload = serde_json::to_string_pretty(&envelope)
        .context("failed serializing cached cloud config")?;
    std::fs::write(path, payload)
        .with_context(|| format!("failed writing cloud cache {}", path.display()))?;
    Ok(())
}

pub fn load_registry_bundle_cache(
    path: &Path,
) -> anyhow::Result<Option<CachedRegistryBundleEnvelope>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading registry cache {}", path.display()))?;
    let envelope: CachedRegistryBundleEnvelope = serde_json::from_str(&content)
        .with_context(|| format!("failed parsing registry cache {}", path.display()))?;
    Ok(Some(envelope))
}

pub fn save_registry_bundle_cache(
    path: &Path,
    metadata: &RegistryVersionResponse,
    etag: &str,
    bundle_bytes: &[u8],
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating registry cache parent directory {}",
                parent.display()
            )
        })?;
    }

    let bundle: Value = serde_json::from_slice(bundle_bytes)
        .context("failed parsing registry bundle payload as JSON")?;
    let envelope = CachedRegistryBundleEnvelope {
        fetched_at: Utc::now().to_rfc3339(),
        etag: etag.to_string(),
        metadata: metadata.clone(),
        bundle,
    };

    let payload = serde_json::to_string_pretty(&envelope)
        .context("failed serializing cached registry bundle")?;
    std::fs::write(path, payload)
        .with_context(|| format!("failed writing registry cache {}", path.display()))?;
    Ok(())
}
