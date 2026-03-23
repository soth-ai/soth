use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use rand::Rng;
use serde::Deserialize;
use soth_core::derive_proxy_signing_seed;
use std::sync::Arc;

#[derive(Clone, Deserialize)]
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

impl std::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("mitm", &self.mitm)
            .field("bundle", &self.bundle)
            .field("telemetry", &self.telemetry)
            .field("sync", &self.sync)
            .field("classify", &self.classify)
            .field("pipeline", &self.pipeline)
            .field("db_path", &self.db_path)
            .field("org_id", &self.org_id)
            .field("team_id", &self.team_id)
            .field("device_id_hash", &self.device_id_hash)
            .field("user_hmac_secret", &"[REDACTED]")
            .finish()
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let logs_dir = home.join(".soth").join("logs");

        let mut secret_bytes = [0u8; 32];
        rand::thread_rng().fill(&mut secret_bytes);
        let user_hmac_secret = hex::encode(secret_bytes);

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
            user_hmac_secret,
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

    pub fn bundle_verification_options(&self) -> Result<soth_bundle::VerificationOptions> {
        let org_approval_pubkey = self
            .bundle
            .org_approval_pubkey_hex
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(|value| parse_fixed_hex::<32>(value, "bundle.org_approval_pubkey_hex"))
            .transpose()?;

        Ok(soth_bundle::VerificationOptions {
            verify_vendor_signature: self.bundle.verify_vendor_signature,
            require_verified_bundle: self.bundle.require_verified_bundle,
            org_approval_pubkey,
        })
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

        let config = self.telemetry.to_telemetry_config(
            self.org_id.clone(),
            bundle_version,
            self.device_id_hash.clone(),
        )?;
        Ok(Some(config))
    }

    pub fn sync_config(&self) -> soth_sync::SyncAgentConfig {
        self.sync.to_sync_agent_config(
            self.db_path.clone(),
            self.bundle.bundle_dir.clone(),
            self.device_id_hash.clone(),
            self.telemetry.signing_key_hex.clone(),
        )
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
    pub process_cache_capacity: usize,
    pub process_cache_ttl_ms: Option<u64>,
    pub ca_cert_path: PathBuf,
    pub ca_key_path: PathBuf,
    pub capture_fingerprint: bool,
    pub http2_enabled: bool,
    pub http2_max_header_list_size: u32,
    pub http3_passthrough: bool,
    pub max_http_head_bytes: usize,
    pub accept_retry_backoff_ms: u64,
    pub max_flow_event_backlog: usize,
    pub max_in_flight_bytes: usize,
    pub max_concurrent_flows: usize,
    pub upstream_timeout_ms: u64,
    pub h2_header_stage_timeout_ms: u64,
    pub h2_body_idle_timeout_ms: u64,
    pub h2_response_overflow_mode: H2ResponseOverflowModeConfig,
    pub upstream_connect_timeout_ms: u64,
    pub upstream_retry_on_failure: bool,
    pub upstream_retry_delay_ms: u64,
    pub verify_upstream_tls: bool,
    pub max_connections_per_host: u32,
    pub idle_timeout_ms: u64,
    pub max_idle_per_host: u32,
    pub max_body_bytes: usize,
    pub buffer_request_bodies: bool,
    pub intercept_mode: Option<InterceptModeConfig>,
    pub request_timeout_ms: u64,
    pub response_timeout_ms: u64,
    pub handler_recover_from_panics: bool,
    pub flow_dispatch_queue_capacity: Option<usize>,
    pub closed_flow_lru_capacity: Option<usize>,
    pub stale_flow_ttl_ms: Option<u64>,
    pub stale_reap_max_batch: Option<usize>,
    pub dispatch_queue_send_timeout_ms: Option<u64>,
    pub dispatch_close_join_timeout_ms: Option<u64>,
}

/// Controls whether the proxy runs in observe-only or store-and-forward mode.
/// When set, this takes precedence over `buffer_request_bodies`.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InterceptModeConfig {
    /// Streaming tee: forward request to upstream immediately while observing.
    Monitor,
    /// Store-and-forward: buffer request body, call handler, then forward or block.
    Enforce,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum H2ResponseOverflowModeConfig {
    TruncateContinue,
    StrictFail,
}

impl Default for H2ResponseOverflowModeConfig {
    fn default() -> Self {
        Self::TruncateContinue
    }
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
            process_cache_capacity: 4_096,
            process_cache_ttl_ms: None,
            ca_cert_path: certs.join("soth-mitm-ca.pem"),
            ca_key_path: certs.join("soth-mitm-ca-key.pem"),
            capture_fingerprint: true,
            http2_enabled: true,
            http2_max_header_list_size: 64 * 1024,
            http3_passthrough: true,
            max_http_head_bytes: 64 * 1024,
            accept_retry_backoff_ms: 100,
            max_flow_event_backlog: 8 * 1024,
            max_in_flight_bytes: 64 * 1024 * 1024,
            max_concurrent_flows: 16_384,
            upstream_timeout_ms: 30_000,
            h2_header_stage_timeout_ms: 120_000,
            h2_body_idle_timeout_ms: 60_000,
            h2_response_overflow_mode: H2ResponseOverflowModeConfig::TruncateContinue,
            upstream_connect_timeout_ms: 10_000,
            upstream_retry_on_failure: false,
            upstream_retry_delay_ms: 200,
            verify_upstream_tls: true,
            max_connections_per_host: 64,
            idle_timeout_ms: 90_000,
            max_idle_per_host: 16,
            max_body_bytes: 32 * 1024 * 1024,
            buffer_request_bodies: false,
            intercept_mode: Some(InterceptModeConfig::Monitor),
            request_timeout_ms: 15_000,
            response_timeout_ms: 15_000,
            handler_recover_from_panics: true,
            flow_dispatch_queue_capacity: None,
            closed_flow_lru_capacity: Some(32_768),
            stale_flow_ttl_ms: Some(300_000), // 5 min — LLM APIs can take 30-120s for first token
            stale_reap_max_batch: Some(256),  // large batches to keep up with tunnel churn
            dispatch_queue_send_timeout_ms: None,
            dispatch_close_join_timeout_ms: None,
        }
    }
}

impl MitmRuntimeConfig {
    fn build(&self) -> Result<soth_mitm::MitmConfig> {
        let bind: SocketAddr = self
            .bind
            .parse()
            .with_context(|| format!("invalid mitm.bind address: {}", self.bind))?;

        let mut interception = soth_mitm::InterceptionScope::default();
        interception.destinations = self.destinations.clone();
        interception.passthrough_unlisted = self.passthrough_unlisted;

        let mut process_attribution = soth_mitm::ProcessAttributionConfig::default();
        process_attribution.enabled = self.process_attribution_enabled;
        process_attribution.lookup_timeout_ms = self.process_lookup_timeout_ms;
        process_attribution.cache_capacity = self.process_cache_capacity.max(1);
        process_attribution.cache_ttl_ms = self.process_cache_ttl_ms.filter(|ttl| *ttl > 0);

        let mut tls = soth_mitm::TlsConfig::default();
        tls.ca_cert_path = self.ca_cert_path.clone();
        tls.ca_key_path = self.ca_key_path.clone();
        tls.min_version = soth_mitm::TlsVersion::Tls12;
        tls.capture_fingerprint = self.capture_fingerprint;

        let mut upstream = soth_mitm::UpstreamConfig::default();
        upstream.timeout_ms = self.upstream_timeout_ms;
        upstream.h2_header_stage_timeout_ms = self.h2_header_stage_timeout_ms;
        upstream.h2_body_idle_timeout_ms = self.h2_body_idle_timeout_ms;
        upstream.h2_response_overflow_mode = match self.h2_response_overflow_mode {
            H2ResponseOverflowModeConfig::TruncateContinue => {
                soth_mitm::H2ResponseOverflowMode::TruncateContinue
            }
            H2ResponseOverflowModeConfig::StrictFail => {
                soth_mitm::H2ResponseOverflowMode::StrictFail
            }
        };
        upstream.connect_timeout_ms = self.upstream_connect_timeout_ms;
        upstream.retry_on_failure = self.upstream_retry_on_failure;
        upstream.retry_delay_ms = self.upstream_retry_delay_ms.max(1);
        upstream.verify_upstream_tls = self.verify_upstream_tls;

        let mut connection_pool = soth_mitm::ConnectionPoolConfig::default();
        connection_pool.max_connections_per_host = self.max_connections_per_host;
        connection_pool.idle_timeout_ms = self.idle_timeout_ms;
        connection_pool.max_idle_per_host = self.max_idle_per_host;

        let mut body = soth_mitm::BodyConfig::default();
        body.max_size_bytes = self.max_body_bytes;
        body.buffer_request_bodies = self.buffer_request_bodies;

        let intercept_mode = match self.intercept_mode {
            Some(InterceptModeConfig::Monitor) => soth_mitm::InterceptMode::Monitor,
            Some(InterceptModeConfig::Enforce) => soth_mitm::InterceptMode::Enforce,
            // Backwards-compat: derive from buffer_request_bodies when not explicitly set.
            None => {
                if self.buffer_request_bodies {
                    soth_mitm::InterceptMode::Enforce
                } else {
                    soth_mitm::InterceptMode::Monitor
                }
            }
        };

        let mut handler = soth_mitm::HandlerConfig::default();
        handler.request_timeout_ms = self.request_timeout_ms;
        handler.response_timeout_ms = self.response_timeout_ms;
        handler.recover_from_panics = self.handler_recover_from_panics;

        let mut flow_runtime = soth_mitm::FlowRuntimeConfig::default();
        flow_runtime.dispatch_queue_capacity = self.flow_dispatch_queue_capacity.map(|v| v.max(1));
        flow_runtime.closed_flow_lru_capacity = self.closed_flow_lru_capacity.map(|v| v.max(1));
        flow_runtime.stale_flow_ttl_ms = self.stale_flow_ttl_ms.filter(|ttl| *ttl > 0);
        flow_runtime.stale_reap_max_batch = self.stale_reap_max_batch.map(|v| v.max(1));
        flow_runtime.dispatch_queue_send_timeout_ms = self
            .dispatch_queue_send_timeout_ms
            .filter(|timeout| *timeout > 0);
        flow_runtime.dispatch_close_join_timeout_ms = self
            .dispatch_close_join_timeout_ms
            .filter(|timeout| *timeout > 0);

        let mut config = soth_mitm::MitmConfig::default();
        config.bind = bind;
        config.unix_socket_path = self.unix_socket_path.clone();
        config.interception = interception;
        config.process_attribution = process_attribution;
        config.tls = tls;
        config.http2_enabled = self.http2_enabled;
        config.http2_max_header_list_size = self.http2_max_header_list_size.max(1);
        config.http3_passthrough = self.http3_passthrough;
        config.max_http_head_bytes = self.max_http_head_bytes.max(1);
        config.accept_retry_backoff_ms = self.accept_retry_backoff_ms.max(1);
        config.max_flow_event_backlog = self.max_flow_event_backlog.max(1);
        config.max_in_flight_bytes = self.max_in_flight_bytes.max(1);
        config.max_concurrent_flows = self.max_concurrent_flows.max(1);
        config.upstream = upstream;
        config.connection_pool = connection_pool;
        config.body = body;
        config.intercept_mode = intercept_mode;
        config.handler = handler;
        config.flow_runtime = flow_runtime;
        Ok(config)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BundleConfig {
    pub bundle_dir: PathBuf,
    pub vendor_pubkey_hex: String,
    pub verify_vendor_signature: bool,
    pub require_verified_bundle: bool,
    pub org_approval_pubkey_hex: Option<String>,
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
            verify_vendor_signature: true,
            require_verified_bundle: false,
            org_approval_pubkey_hex: None,
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
        soth_classify::ClassifyConfig {
            embedding_enabled: self.embedding_enabled,
            anomaly_enabled: self.anomaly_enabled,
            lsh_near_dupe_threshold: self.lsh_near_dupe_threshold,
            ..Default::default()
        }
    }

    fn to_runtime_config(&self) -> crate::classify_task::RuntimeConfig {
        crate::classify_task::RuntimeConfig {
            max_in_flight: self.max_in_flight,
            slot_acquire_timeout_ms: self.slot_acquire_timeout_ms,
            db_write_queue_capacity: self.db_write_queue_capacity,
        }
    }
}

#[derive(Clone, Deserialize)]
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

impl std::fmt::Debug for TelemetryPipelineConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelemetryPipelineConfig")
            .field("enabled", &self.enabled)
            .field("batch_window_secs", &self.batch_window_secs)
            .field("max_batch_size", &self.max_batch_size)
            .field("anomaly_threshold", &self.anomaly_threshold)
            .field(
                "signing_key_hex",
                &self.signing_key_hex.as_deref().map(|_| "[REDACTED]"),
            )
            .field("encryption", &self.encryption)
            .field("proxy_version", &self.proxy_version)
            .finish()
    }
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
        device_id_hash: String,
    ) -> Result<soth_telemetry::TelemetryConfig> {
        let signing_key_bytes = match &self.signing_key_hex {
            Some(hex) if !hex.trim().is_empty() => {
                parse_fixed_hex::<32>(hex.as_str(), "telemetry.signing_key_hex")?
            }
            _ => derive_proxy_signing_seed(device_id_hash.as_str()),
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
            observation_queue_dir: None, // wired by extension registry when enabled
            governance_queue_dir: None,  // wired by extension registry when enabled
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

#[derive(Clone, Deserialize)]
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
    pub legacy_exchange_upload_enabled: bool,
    pub body_upload_max_bytes: usize,
    pub telemetry_enabled: bool,
    pub telemetry_signing_key_hex: Option<String>,
}

impl std::fmt::Debug for SyncRuntimeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncRuntimeConfig")
            .field("enabled", &self.enabled)
            .field("endpoint", &self.endpoint)
            .field("api_key", &"[REDACTED]")
            .field("cache_path", &self.cache_path)
            .field("registry_cache_path", &self.registry_cache_path)
            .field("agent_instance_id", &self.agent_instance_id)
            .field("retry_queue_dir", &self.retry_queue_dir)
            .field("retry_queue_max_bytes", &self.retry_queue_max_bytes)
            .field("sync_interval_secs", &self.sync_interval_secs)
            .field("batch_size", &self.batch_size)
            .field("body_batch_size", &self.body_batch_size)
            .field("body_upload_enabled", &self.body_upload_enabled)
            .field(
                "metadata_max_events_per_batch",
                &self.metadata_max_events_per_batch,
            )
            .field(
                "metadata_max_compressed_batch_bytes",
                &self.metadata_max_compressed_batch_bytes,
            )
            .field("frontload_enabled", &self.frontload_enabled)
            .field(
                "frontload_max_events_per_batch",
                &self.frontload_max_events_per_batch,
            )
            .field(
                "frontload_max_compressed_batch_bytes",
                &self.frontload_max_compressed_batch_bytes,
            )
            .field("frontload_hard_events_cap", &self.frontload_hard_events_cap)
            .field(
                "frontload_hard_compressed_cap_bytes",
                &self.frontload_hard_compressed_cap_bytes,
            )
            .field(
                "legacy_exchange_upload_enabled",
                &self.legacy_exchange_upload_enabled,
            )
            .field("body_upload_max_bytes", &self.body_upload_max_bytes)
            .field("telemetry_enabled", &self.telemetry_enabled)
            .field(
                "telemetry_signing_key_hex",
                &self
                    .telemetry_signing_key_hex
                    .as_deref()
                    .map(|_| "[REDACTED]"),
            )
            .finish()
    }
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
            legacy_exchange_upload_enabled: false,
            body_upload_max_bytes: 2 * 1024 * 1024,
            telemetry_enabled: true,
            telemetry_signing_key_hex: None,
        }
    }
}

impl SyncRuntimeConfig {
    fn to_sync_agent_config(
        &self,
        db_path: PathBuf,
        bundle_dir: PathBuf,
        device_id_hash: String,
        telemetry_signing_key_hex: Option<String>,
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
            legacy_exchange_upload_enabled: self.legacy_exchange_upload_enabled,
            body_upload_max_bytes: self.body_upload_max_bytes.max(1),
            global_tags: BTreeMap::new(),
            device_id_hash,
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
            telemetry_signing_key_hex,
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
    pub session: SessionConfig,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            body_size_limit_bytes: 10 * 1024 * 1024,
            block_signal_timeout_ms: 0,
            session_ttl_secs: 3_600,
            unknown_app_action: None,
            non_cataloged_host_action: None,
            session: SessionConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SessionConfig {
    pub window_secs: u64,
    pub max_sessions: usize,
    pub reaper_interval_secs: u64,
    pub code_hash_ring_capacity: usize,
    pub prefix_hash_ring_capacity: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            window_secs: 3_600,
            max_sessions: 1_024,
            reaper_interval_secs: 3_600,
            code_hash_ring_capacity: 256,
            prefix_hash_ring_capacity: 128,
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
    use super::{H2ResponseOverflowModeConfig, ProxyConfig};

    #[test]
    fn sync_config_wires_edge_heartbeat_telemetry_provider() {
        let cfg = ProxyConfig::default();
        let sync_cfg = cfg.sync_config();
        assert!(!sync_cfg.legacy_exchange_upload_enabled);
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
    fn sync_config_maps_legacy_exchange_upload_flag() {
        let mut cfg = ProxyConfig::default();
        cfg.sync.legacy_exchange_upload_enabled = true;
        let sync_cfg = cfg.sync_config();
        assert!(sync_cfg.legacy_exchange_upload_enabled);
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

    #[test]
    fn mitm_h2_reliability_knobs_map_from_config() {
        let mut cfg = ProxyConfig::default();
        cfg.mitm.h2_header_stage_timeout_ms = 9_000;
        cfg.mitm.h2_body_idle_timeout_ms = 120_000;
        cfg.mitm.h2_response_overflow_mode = H2ResponseOverflowModeConfig::StrictFail;

        let mitm = cfg.mitm_config().expect("mitm config");
        assert_eq!(mitm.upstream.h2_header_stage_timeout_ms, 9_000);
        assert_eq!(mitm.upstream.h2_body_idle_timeout_ms, 120_000);
        assert_eq!(
            mitm.upstream.h2_response_overflow_mode,
            soth_mitm::H2ResponseOverflowMode::StrictFail
        );
    }
}
