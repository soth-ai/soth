use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    pub mitm: MitmRuntimeConfig,
    pub bundle: BundleConfig,
    pub telemetry: TelemetryPipelineConfig,
    pub sync: SyncRuntimeConfig,
    pub classify: ClassifyRuntimeConfig,
    pub pipeline: PipelineConfig,
    pub db_path: PathBuf,
    pub org_id: String,
    pub team_id: String,
    pub device_id_hash: String,
    pub user_hmac_secret: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let logs_dir = home.join(".soth").join("logs");

        Self {
            mitm: MitmRuntimeConfig::default(),
            bundle: BundleConfig::default(),
            telemetry: TelemetryPipelineConfig::default(),
            sync: SyncRuntimeConfig::default(),
            classify: ClassifyRuntimeConfig::default(),
            pipeline: PipelineConfig::default(),
            db_path: logs_dir.join("events.db"),
            org_id: "local-org".to_string(),
            team_id: "local-team".to_string(),
            device_id_hash: "local-device".to_string(),
            user_hmac_secret: "local-dev-secret".to_string(),
        }
    }
}

impl ProxyConfig {
    pub fn from_env_or_default() -> Result<Self> {
        match std::env::var("SOTH_PROXY_CONFIG") {
            Ok(path) => Self::from_toml_file(Path::new(path.as_str())),
            Err(_) => Ok(Self::default()),
        }
    }

    pub fn from_toml_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed reading proxy config: {}", path.display()))?;
        let mut cfg: Self = toml::from_str(content.as_str())
            .with_context(|| format!("failed parsing TOML config: {}", path.display()))?;

        if cfg.db_path.as_os_str().is_empty() {
            cfg.db_path = Self::default().db_path;
        }

        Ok(cfg)
    }

    pub fn mitm_config(&self) -> Result<soth_mitm::MitmConfig> {
        self.mitm.build()
    }

    pub fn bundle_vendor_pubkey(&self) -> Result<[u8; 32]> {
        parse_fixed_hex::<32>(
            self.bundle.vendor_pubkey_hex.as_str(),
            "bundle.vendor_pubkey_hex",
        )
    }

    pub fn org_signed_config(&self) -> soth_bundle::OrgSignedConfig {
        soth_bundle::OrgSignedConfig {
            allows_https_intercept: self.bundle.allows_https_intercept,
            allows_http_intercept: self.bundle.allows_http_intercept,
            process_filter: self.bundle.process_filter.clone(),
            allowed_capture_modes: self.bundle.allowed_capture_modes.clone(),
        }
    }

    pub fn bundle_verification_options(&self) -> soth_bundle::VerificationOptions {
        soth_bundle::VerificationOptions {
            verify_vendor_signature: self.bundle.verify_vendor_signature,
        }
    }

    pub fn classify_config(&self) -> soth_classify::ClassifyConfig {
        self.classify.to_classify_config()
    }

    pub fn classify_runtime_config(&self) -> crate::classify_task::RuntimeConfig {
        self.classify.to_runtime_config()
    }

    pub fn telemetry_config(
        &self,
        bundle_version: String,
    ) -> Result<Option<soth_telemetry::TelemetryConfig>> {
        if !self.telemetry.enabled {
            return Ok(None);
        }

        let config = self
            .telemetry
            .to_telemetry_config(self.org_id.clone(), bundle_version)?;
        Ok(Some(config))
    }

    pub fn sync_config(&self) -> soth_sync::SyncAgentConfig {
        self.sync
            .to_sync_agent_config(self.db_path.clone(), self.bundle.bundle_dir.clone())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MitmRuntimeConfig {
    pub bind: String,
    pub unix_socket_path: Option<PathBuf>,
    pub destinations: Vec<String>,
    pub passthrough_unlisted: bool,
    pub process_attribution_enabled: bool,
    pub process_lookup_timeout_ms: u64,
    pub ca_cert_path: PathBuf,
    pub ca_key_path: PathBuf,
    pub capture_fingerprint: bool,
    pub upstream_timeout_ms: u64,
    pub upstream_connect_timeout_ms: u64,
    pub verify_upstream_tls: bool,
    pub max_connections_per_host: u32,
    pub idle_timeout_ms: u64,
    pub max_idle_per_host: u32,
    pub max_body_bytes: usize,
    pub buffer_request_bodies: bool,
    pub request_timeout_ms: u64,
    pub response_timeout_ms: u64,
}

impl Default for MitmRuntimeConfig {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let certs = home.join(".soth").join("certs");
        Self {
            bind: "127.0.0.1:8080".to_string(),
            unix_socket_path: None,
            destinations: vec!["*".to_string()],
            passthrough_unlisted: true,
            process_attribution_enabled: true,
            process_lookup_timeout_ms: 5_000,
            ca_cert_path: certs.join("soth-mitm-ca.pem"),
            ca_key_path: certs.join("soth-mitm-ca-key.pem"),
            capture_fingerprint: true,
            upstream_timeout_ms: 30_000,
            upstream_connect_timeout_ms: 10_000,
            verify_upstream_tls: true,
            max_connections_per_host: 64,
            idle_timeout_ms: 60_000,
            max_idle_per_host: 16,
            max_body_bytes: 10 * 1024 * 1024,
            buffer_request_bodies: true,
            request_timeout_ms: 5_000,
            response_timeout_ms: 5_000,
        }
    }
}

impl MitmRuntimeConfig {
    fn build(&self) -> Result<soth_mitm::MitmConfig> {
        let bind: SocketAddr = self
            .bind
            .parse()
            .with_context(|| format!("invalid mitm.bind address: {}", self.bind))?;

        Ok(soth_mitm::MitmConfig {
            bind,
            unix_socket_path: self.unix_socket_path.clone(),
            interception: soth_mitm::InterceptionScope {
                destinations: self.destinations.clone(),
                passthrough_unlisted: self.passthrough_unlisted,
            },
            process_attribution: soth_mitm::ProcessAttributionConfig {
                enabled: self.process_attribution_enabled,
                lookup_timeout_ms: self.process_lookup_timeout_ms,
            },
            tls: soth_mitm::TlsConfig {
                ca_cert_path: self.ca_cert_path.clone(),
                ca_key_path: self.ca_key_path.clone(),
                min_version: soth_mitm::TlsVersion::Tls12,
                capture_fingerprint: self.capture_fingerprint,
            },
            upstream: soth_mitm::UpstreamConfig {
                timeout_ms: self.upstream_timeout_ms,
                connect_timeout_ms: self.upstream_connect_timeout_ms,
                retry_on_failure: false,
                retry_delay_ms: 200,
                verify_upstream_tls: self.verify_upstream_tls,
            },
            connection_pool: soth_mitm::ConnectionPoolConfig {
                max_connections_per_host: self.max_connections_per_host,
                idle_timeout_ms: self.idle_timeout_ms,
                max_idle_per_host: self.max_idle_per_host,
            },
            body: soth_mitm::BodyConfig {
                max_size_bytes: self.max_body_bytes,
                buffer_request_bodies: self.buffer_request_bodies,
            },
            handler: soth_mitm::HandlerConfig {
                request_timeout_ms: self.request_timeout_ms,
                response_timeout_ms: self.response_timeout_ms,
                recover_from_panics: true,
            },
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BundleConfig {
    pub bundle_dir: PathBuf,
    pub vendor_pubkey_hex: String,
    pub verify_vendor_signature: bool,
    pub allows_https_intercept: bool,
    pub allows_http_intercept: bool,
    pub process_filter: Option<Vec<String>>,
    pub allowed_capture_modes: Vec<String>,
}

impl Default for BundleConfig {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        Self {
            bundle_dir: home.join(".soth").join("bundle"),
            vendor_pubkey_hex: "00".repeat(32),
            verify_vendor_signature: false,
            allows_https_intercept: true,
            allows_http_intercept: true,
            process_filter: None,
            allowed_capture_modes: vec![
                "metadata_only".to_string(),
                "sensitive_artifacts".to_string(),
                "full".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ClassifyRuntimeConfig {
    pub embedding_enabled: bool,
    pub anomaly_enabled: bool,
    pub lsh_near_dupe_threshold: u32,
    pub max_in_flight: usize,
    pub slot_acquire_timeout_ms: u64,
    pub db_write_queue_capacity: usize,
}

impl Default for ClassifyRuntimeConfig {
    fn default() -> Self {
        let runtime_defaults = crate::classify_task::RuntimeConfig::default();
        Self {
            embedding_enabled: true,
            anomaly_enabled: true,
            lsh_near_dupe_threshold: 8,
            max_in_flight: runtime_defaults.max_in_flight,
            slot_acquire_timeout_ms: runtime_defaults.slot_acquire_timeout_ms,
            db_write_queue_capacity: runtime_defaults.db_write_queue_capacity,
        }
    }
}

impl ClassifyRuntimeConfig {
    fn to_classify_config(&self) -> soth_classify::ClassifyConfig {
        let mut cfg = soth_classify::ClassifyConfig::default();
        cfg.embedding_enabled = self.embedding_enabled;
        cfg.anomaly_enabled = self.anomaly_enabled;
        cfg.lsh_near_dupe_threshold = self.lsh_near_dupe_threshold;
        cfg
    }

    fn to_runtime_config(&self) -> crate::classify_task::RuntimeConfig {
        crate::classify_task::RuntimeConfig {
            max_in_flight: self.max_in_flight,
            slot_acquire_timeout_ms: self.slot_acquire_timeout_ms,
            db_write_queue_capacity: self.db_write_queue_capacity,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TelemetryPipelineConfig {
    pub enabled: bool,
    pub batch_window_secs: u64,
    pub max_batch_size: usize,
    pub anomaly_threshold: f32,
    pub signing_key_hex: Option<String>,
    pub encryption: TelemetryEncryptionConfig,
    pub proxy_version: String,
}

impl Default for TelemetryPipelineConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            batch_window_secs: 30,
            max_batch_size: 500,
            anomaly_threshold: 0.8,
            signing_key_hex: None,
            encryption: TelemetryEncryptionConfig::None,
            proxy_version: "soth-proxy-dev".to_string(),
        }
    }
}

impl TelemetryPipelineConfig {
    fn to_telemetry_config(
        &self,
        org_id: String,
        bundle_version: String,
    ) -> Result<soth_telemetry::TelemetryConfig> {
        let signing_key_bytes = match &self.signing_key_hex {
            Some(hex) if !hex.trim().is_empty() => {
                parse_fixed_hex::<32>(hex.as_str(), "telemetry.signing_key_hex")?
            }
            _ => [7u8; 32],
        };
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);

        let encryption = match &self.encryption {
            TelemetryEncryptionConfig::None => soth_telemetry::EncryptionMode::None,
            TelemetryEncryptionConfig::Ecies { vendor_pubkey_hex } => {
                let vendor_pubkey = parse_fixed_hex::<32>(
                    vendor_pubkey_hex.as_str(),
                    "telemetry.encryption.vendor_pubkey_hex",
                )?;
                soth_telemetry::EncryptionMode::Ecies { vendor_pubkey }
            }
        };

        Ok(soth_telemetry::TelemetryConfig {
            batch_window: Duration::from_secs(self.batch_window_secs.max(1)),
            max_batch_size: self.max_batch_size.max(1),
            anomaly_threshold: self.anomaly_threshold,
            signing_key,
            encryption,
            proxy_version: self.proxy_version.clone(),
            bundle_version,
            org_id,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum TelemetryEncryptionConfig {
    None,
    Ecies { vendor_pubkey_hex: String },
}

impl Default for TelemetryEncryptionConfig {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SyncRuntimeConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub api_key: String,
    pub cache_path: PathBuf,
    pub registry_cache_path: Option<PathBuf>,
    pub agent_instance_id: String,
    pub retry_queue_dir: PathBuf,
    pub retry_queue_max_bytes: u64,
    pub sync_interval_secs: u64,
    pub batch_size: usize,
    pub body_batch_size: usize,
    pub body_upload_enabled: bool,
    pub metadata_max_events_per_batch: usize,
    pub metadata_max_compressed_batch_bytes: usize,
    pub frontload_enabled: bool,
    pub frontload_max_events_per_batch: usize,
    pub frontload_max_compressed_batch_bytes: usize,
    pub frontload_hard_events_cap: usize,
    pub frontload_hard_compressed_cap_bytes: usize,
    pub body_upload_max_bytes: usize,
    pub telemetry_enabled: bool,
}

impl Default for SyncRuntimeConfig {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let root = home.join(".soth");
        Self {
            enabled: false,
            endpoint: "https://api.soth.local".to_string(),
            api_key: "".to_string(),
            cache_path: root.join("cache"),
            registry_cache_path: None,
            agent_instance_id: "local-agent".to_string(),
            retry_queue_dir: root.join("retry"),
            retry_queue_max_bytes: 512 * 1024 * 1024,
            sync_interval_secs: 30,
            batch_size: 100,
            body_batch_size: 50,
            body_upload_enabled: false,
            metadata_max_events_per_batch: 200,
            metadata_max_compressed_batch_bytes: 5 * 1024 * 1024,
            frontload_enabled: false,
            frontload_max_events_per_batch: 1500,
            frontload_max_compressed_batch_bytes: 32 * 1024 * 1024,
            frontload_hard_events_cap: 5000,
            frontload_hard_compressed_cap_bytes: 64 * 1024 * 1024,
            body_upload_max_bytes: 2 * 1024 * 1024,
            telemetry_enabled: true,
        }
    }
}

impl SyncRuntimeConfig {
    fn to_sync_agent_config(
        &self,
        db_path: PathBuf,
        bundle_dir: PathBuf,
    ) -> soth_sync::SyncAgentConfig {
        let registry_cache_path = self
            .registry_cache_path
            .clone()
            .or_else(|| Some(bundle_dir.join("registry_bundle_cache.json")));
        let heartbeat_registry_cache_path = registry_cache_path.clone();

        soth_sync::SyncAgentConfig {
            endpoint: self.endpoint.clone(),
            api_key: self.api_key.clone(),
            event_db_path: db_path,
            cache_path: self.cache_path.clone(),
            registry_cache_path,
            agent_instance_id: self.agent_instance_id.clone(),
            proxy_version: "soth-proxy-dev".to_string(),
            retry_queue_dir: self.retry_queue_dir.clone(),
            retry_queue_max_bytes: self.retry_queue_max_bytes,
            sync_interval: Duration::from_secs(self.sync_interval_secs.max(1)),
            batch_size: self.batch_size.max(1),
            body_batch_size: self.body_batch_size.max(1),
            body_upload_enabled: self.body_upload_enabled,
            metadata_max_events_per_batch: self.metadata_max_events_per_batch.max(1),
            metadata_max_compressed_batch_bytes: self.metadata_max_compressed_batch_bytes.max(1),
            frontload_enabled: self.frontload_enabled,
            frontload_max_events_per_batch: self.frontload_max_events_per_batch.max(1),
            frontload_max_compressed_batch_bytes: self.frontload_max_compressed_batch_bytes.max(1),
            frontload_hard_events_cap: self.frontload_hard_events_cap.max(1),
            frontload_hard_compressed_cap_bytes: self.frontload_hard_compressed_cap_bytes.max(1),
            frontload_exchange_upload_path: None,
            body_upload_max_bytes: self.body_upload_max_bytes.max(1),
            global_tags: BTreeMap::new(),
            heartbeat_telemetry: Some(Arc::new(move || {
                if let Some(path) = heartbeat_registry_cache_path.as_ref() {
                    crate::heartbeat_telemetry::refresh_registry_runtime_metrics(path);
                }
                Some(crate::heartbeat_telemetry::heartbeat_telemetry_snapshot())
            })),
            telemetry: soth_sync::TelemetrySyncConfig {
                enabled: self.telemetry_enabled,
                ..soth_sync::TelemetrySyncConfig::default()
            },
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PipelineConfig {
    pub body_size_limit_bytes: usize,
    pub block_signal_timeout_ms: u64,
    pub session_ttl_secs: u64,
    pub unknown_app_action: Option<GateAction>,
    pub non_cataloged_host_action: Option<GateAction>,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            body_size_limit_bytes: 10 * 1024 * 1024,
            block_signal_timeout_ms: 0,
            session_ttl_secs: 3_600,
            unknown_app_action: None,
            non_cataloged_host_action: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GateAction {
    Skip,
    Intercept,
    Block,
}

impl Default for GateAction {
    fn default() -> Self {
        Self::Skip
    }
}

fn parse_fixed_hex<const N: usize>(value: &str, field: &str) -> Result<[u8; N]> {
    let trimmed = value.trim();
    let bytes = hex::decode(trimmed).with_context(|| format!("{field} must be hex-encoded"))?;
    if bytes.len() != N {
        anyhow::bail!(
            "{field} must decode to exactly {N} bytes, got {} bytes",
            bytes.len()
        );
    }

    let mut out = [0u8; N];
    out.copy_from_slice(bytes.as_slice());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::ProxyConfig;

    #[test]
    fn sync_config_wires_edge_heartbeat_telemetry_provider() {
        let cfg = ProxyConfig::default();
        let sync_cfg = cfg.sync_config();
        let provider = sync_cfg
            .heartbeat_telemetry
            .as_ref()
            .expect("heartbeat telemetry provider should be wired");
        let telemetry = provider().expect("heartbeat telemetry should be present");
        assert!(telemetry
            .counters
            .contains_key("edge.blacklist.keyword_dropped_total"));
        assert!(telemetry
            .counters
            .contains_key("edge.registry.source_state"));
        assert!(telemetry
            .counters
            .contains_key("edge.runtime.policy_enforced_false_total"));
    }

    #[test]
    fn classify_runtime_knobs_map_from_config() {
        let mut cfg = ProxyConfig::default();
        cfg.classify.max_in_flight = 12;
        cfg.classify.slot_acquire_timeout_ms = 750;
        cfg.classify.db_write_queue_capacity = 8_192;

        let runtime = cfg.classify_runtime_config();
        assert_eq!(runtime.max_in_flight, 12);
        assert_eq!(runtime.slot_acquire_timeout_ms, 750);
        assert_eq!(runtime.db_write_queue_capacity, 8_192);
    }
}
