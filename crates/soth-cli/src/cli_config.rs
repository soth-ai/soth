//! Shared CLI config resolution/helpers for `soth`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const DEFAULT_CONFIG_FILE: &str = "soth.yaml";
pub const DEFAULT_DEVICE_ID_FILE: &str = "device_id";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SothConfig {
    pub forward_proxy: ForwardProxyConfig,
    pub cloud: CloudConfig,
    pub exchange: ExchangeConfig,
    pub bundle: BundleConfig,
    pub proxy: ProxyConfig,
}

impl Default for SothConfig {
    fn default() -> Self {
        Self {
            forward_proxy: ForwardProxyConfig::default(),
            cloud: CloudConfig::default(),
            exchange: ExchangeConfig::default(),
            bundle: BundleConfig::default(),
            proxy: ProxyConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ForwardProxyConfig {
    pub enabled: bool,
    pub address: String,
    pub port: u16,
    pub autostart_on_boot: bool,
    pub ca: CaConfig,
}

impl Default for ForwardProxyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            address: "127.0.0.1".to_string(),
            port: 8080,
            autostart_on_boot: true,
            ca: CaConfig::default(),
        }
    }
}

impl ForwardProxyConfig {
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CaConfig {
    pub cert_path: String,
    pub key_path: String,
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            cert_path: "~/.soth/certs/soth-mitm-ca.pem".to_string(),
            key_path: "~/.soth/certs/soth-mitm-ca-key.pem".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CloudConfig {
    pub enabled: bool,
    pub api_key: Option<String>,
    pub endpoint: String,
    pub sync_interval_secs: u64,
    pub tags: BTreeMap<String, String>,
}

impl Default for CloudConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_key: None,
            endpoint: "https://api.soth.ai".to_string(),
            sync_interval_secs: 30,
            tags: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ExchangeConfig {
    pub enabled: bool,
}

impl Default for ExchangeConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BundleConfig {
    pub bundle_dir: String,
    pub vendor_pubkey_hex: String,
    pub verify_vendor_signature: bool,
}

impl Default for BundleConfig {
    fn default() -> Self {
        Self {
            bundle_dir: "~/.soth/bundle".to_string(),
            vendor_pubkey_hex: "00".repeat(32),
            verify_vendor_signature: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    pub db_path: String,
    pub classify_max_in_flight: usize,
    pub classify_slot_acquire_timeout_ms: u64,
    pub db_write_queue_capacity: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            db_path: "~/.soth/logs/events.db".to_string(),
            classify_max_in_flight: 8,
            classify_slot_acquire_timeout_ms: 250,
            db_write_queue_capacity: 4_096,
        }
    }
}

pub fn default_config_path() -> PathBuf {
    dirs::home_dir()
        .map(|home| home.join(".soth").join(DEFAULT_CONFIG_FILE))
        .unwrap_or_else(|| PathBuf::from(".soth").join(DEFAULT_CONFIG_FILE))
}

pub fn default_device_id_path() -> PathBuf {
    dirs::home_dir()
        .map(|home| home.join(".soth").join(DEFAULT_DEVICE_ID_FILE))
        .unwrap_or_else(|| PathBuf::from(".soth").join(DEFAULT_DEVICE_ID_FILE))
}

pub fn discover_default_config_path() -> Option<PathBuf> {
    let path = default_config_path();
    if path.exists() {
        Some(path)
    } else {
        None
    }
}

pub fn expand_tilde(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if let Some(rest) = raw.strip_prefix("~/") {
        return dirs::home_dir()
            .map(|home| home.join(rest))
            .unwrap_or_else(|| PathBuf::from(raw.as_ref()));
    }
    path.to_path_buf()
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

pub fn load_config(path: PathBuf) -> Result<SothConfig> {
    let content =
        fs::read_to_string(&path).with_context(|| format!("failed reading {}", path.display()))?;
    let cfg = serde_yaml::from_str::<SothConfig>(&content)
        .with_context(|| format!("failed parsing {}", path.display()))?;
    Ok(cfg)
}

pub fn load_effective_config(
    explicit: Option<&PathBuf>,
    global: Option<&PathBuf>,
) -> Result<SothConfig> {
    if let Some(path) = resolve_config_path(explicit, global) {
        return load_config(path);
    }
    Ok(SothConfig::default())
}

pub fn write_config(path: &Path, config: &SothConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    let body = serde_yaml::to_string(config).context("failed serializing config YAML")?;
    fs::write(path, body).with_context(|| format!("failed writing {}", path.display()))?;
    Ok(())
}

pub fn read_client_device_id() -> Option<String> {
    let path = default_device_id_path();
    let value = fs::read_to_string(path).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn write_client_device_id(device_id: &str) -> Result<()> {
    let path = default_device_id_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    fs::write(&path, format!("{device_id}\n"))
        .with_context(|| format!("failed writing {}", path.display()))?;
    Ok(())
}

pub fn sync_client_device_id(
    config: &mut SothConfig,
    preferred_device_id: Option<&str>,
) -> Result<String> {
    let device_id = preferred_device_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            config
                .cloud
                .tags
                .get("device_id")
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .or_else(read_client_device_id)
        .unwrap_or_else(|| format!("device-{}", Uuid::new_v4()));

    config
        .cloud
        .tags
        .insert("device_id".to_string(), device_id.clone());
    let _ = write_client_device_id(&device_id);
    Ok(device_id)
}

pub fn resolved_db_path(config: &SothConfig) -> PathBuf {
    expand_tilde(Path::new(config.proxy.db_path.as_str()))
}
