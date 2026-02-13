//! Configuration types for SOTH
//!
//! Defines the complete configuration structure for the SOTH edge proxy.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

/// Root configuration structure for SOTH
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SothConfig {
    /// Configuration version
    #[serde(default = "default_version")]
    pub version: String,

    /// Server settings
    #[serde(default)]
    pub server: ServerConfig,

    /// Upstream MCP server connection
    #[serde(default)]
    pub upstream: UpstreamConfig,

    /// Default agent identity
    #[serde(default)]
    pub agent: AgentConfig,

    /// Identity verification settings
    #[serde(default)]
    pub identity: IdentityConfig,

    /// Unified cryptographic identity/audit/tls settings
    #[serde(default)]
    pub crypto_identity: CryptoIdentityConfig,

    /// Policy engine settings
    #[serde(default)]
    pub policy: PolicyConfig,

    /// Observability/audit settings
    #[serde(default)]
    pub observe: ObserveConfig,

    /// Budget tracking settings
    #[serde(default)]
    pub budget: BudgetConfig,

    /// Cloud sync configuration (optional)
    #[serde(default)]
    pub cloud: CloudConfig,

    /// Dashboard settings
    #[serde(default)]
    pub dashboard: DashboardConfig,

    /// Forward proxy settings (HTTP/HTTPS interception)
    #[serde(default)]
    pub forward_proxy: ForwardProxyConfig,

    /// Production hardening settings
    #[serde(default)]
    pub production: ProductionConfig,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,
}

fn default_version() -> String {
    "1.0".to_string()
}

impl Default for SothConfig {
    fn default() -> Self {
        Self {
            version: default_version(),
            server: ServerConfig::default(),
            upstream: UpstreamConfig::default(),
            agent: AgentConfig::default(),
            identity: IdentityConfig::default(),
            crypto_identity: CryptoIdentityConfig::default(),
            policy: PolicyConfig::default(),
            observe: ObserveConfig::default(),
            budget: BudgetConfig::default(),
            cloud: CloudConfig::default(),
            dashboard: DashboardConfig::default(),
            forward_proxy: ForwardProxyConfig::default(),
            production: ProductionConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Listen address and port
    #[serde(default)]
    pub listen: ListenConfig,

    /// Transport type: stdio, sse, http
    #[serde(default = "default_transport")]
    pub transport: String,

    /// Read timeout in seconds
    #[serde(default = "default_timeout", with = "humantime_serde")]
    pub read_timeout: Duration,

    /// Write timeout in seconds
    #[serde(default = "default_timeout", with = "humantime_serde")]
    pub write_timeout: Duration,

    /// Graceful shutdown timeout
    #[serde(default = "default_shutdown_timeout", with = "humantime_serde")]
    pub graceful_shutdown: Duration,

    /// Maximum concurrent connections
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

fn default_transport() -> String {
    "stdio".to_string()
}

fn default_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_shutdown_timeout() -> Duration {
    Duration::from_secs(10)
}

fn default_max_connections() -> usize {
    1000
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: ListenConfig::default(),
            transport: default_transport(),
            read_timeout: default_timeout(),
            write_timeout: default_timeout(),
            graceful_shutdown: default_shutdown_timeout(),
            max_connections: default_max_connections(),
        }
    }
}

/// Listen address configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenConfig {
    #[serde(default = "default_address")]
    pub address: String,

    #[serde(default = "default_port")]
    pub port: u16,
}

fn default_address() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    3000
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            address: default_address(),
            port: default_port(),
        }
    }
}

impl ListenConfig {
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }
}

/// Upstream MCP server configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpstreamConfig {
    /// URL for HTTP/SSE transport
    pub url: Option<String>,

    /// Command to spawn for stdio transport
    pub command: Option<String>,

    /// Arguments for the command
    #[serde(default)]
    pub args: Vec<String>,

    /// Environment variables for the command
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,

    /// Connection timeout
    #[serde(default = "default_timeout", with = "humantime_serde")]
    pub timeout: Duration,

    /// Retry configuration
    #[serde(default)]
    pub retry: RetryConfig,
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,

    #[serde(default = "default_initial_delay", with = "humantime_serde")]
    pub initial_delay: Duration,

    #[serde(default = "default_max_delay", with = "humantime_serde")]
    pub max_delay: Duration,

    #[serde(default = "default_backoff")]
    pub backoff: String,
}

fn default_true() -> bool {
    true
}

fn default_max_attempts() -> u32 {
    3
}

fn default_initial_delay() -> Duration {
    Duration::from_millis(100)
}

fn default_max_delay() -> Duration {
    Duration::from_secs(5)
}

fn default_backoff() -> String {
    "exponential".to_string()
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            max_attempts: default_max_attempts(),
            initial_delay: default_initial_delay(),
            max_delay: default_max_delay(),
            backoff: default_backoff(),
        }
    }
}

/// Default agent identity configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentConfig {
    /// Agent identifier
    pub id: Option<String>,

    /// Agent name
    pub name: Option<String>,

    /// Agent capabilities
    #[serde(default)]
    pub capabilities: Vec<String>,

    /// Model being used
    pub model: Option<String>,

    /// Publisher/organization
    pub publisher: Option<String>,

    /// Tags for categorization
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Identity verification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Mode: disabled, optional, required
    #[serde(default = "default_identity_mode")]
    pub mode: String,

    /// Path to key file
    pub key_path: Option<PathBuf>,

    /// Path to trust store directory
    pub trust_store_path: Option<PathBuf>,

    /// Maximum age for credentials
    #[serde(default = "default_max_age", with = "humantime_serde")]
    pub max_age: Duration,

    /// Allowed clock skew
    #[serde(default = "default_clock_skew", with = "humantime_serde")]
    pub clock_skew: Duration,

    /// Allowed DIDs (empty = allow all)
    #[serde(default)]
    pub allowed_dids: Vec<String>,
}

fn default_identity_mode() -> String {
    "optional".to_string()
}

fn default_max_age() -> Duration {
    Duration::from_secs(3600)
}

fn default_clock_skew() -> Duration {
    Duration::from_secs(60)
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            mode: default_identity_mode(),
            key_path: None,
            trust_store_path: None,
            max_age: default_max_age(),
            clock_skew: default_clock_skew(),
            allowed_dids: Vec::new(),
        }
    }
}

/// Unified cryptographic identity configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoIdentityConfig {
    /// Enable unified crypto identity pipeline
    #[serde(default)]
    pub enabled: bool,

    /// Mode: audit, enforce
    #[serde(default = "default_crypto_identity_mode")]
    pub mode: String,

    /// Optional principal allowlist for staged enforcement when mode=enforce.
    ///
    /// If this list is empty and mode=enforce, signature verification is required globally.
    /// If this list is non-empty and mode=enforce, only matching principals are required.
    /// Principal entries can be DID values (did:key:...) or agent IDs/names.
    #[serde(default)]
    pub enforce_principals: Vec<String>,

    /// Envelope signing controls
    #[serde(default)]
    pub signing: CryptoSigningConfig,

    /// Key hierarchy and rotation controls
    #[serde(default)]
    pub hierarchy: CryptoHierarchyConfig,

    /// Merkle accumulator controls
    #[serde(default)]
    pub merkle: CryptoMerkleConfig,

    /// TLS key binding controls
    #[serde(default)]
    pub tls: CryptoTlsBindingConfig,
}

fn default_crypto_identity_mode() -> String {
    "audit".to_string()
}

impl Default for CryptoIdentityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: default_crypto_identity_mode(),
            enforce_principals: Vec::new(),
            signing: CryptoSigningConfig::default(),
            hierarchy: CryptoHierarchyConfig::default(),
            merkle: CryptoMerkleConfig::default(),
            tls: CryptoTlsBindingConfig::default(),
        }
    }
}

/// Signature behavior for request envelopes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoSigningConfig {
    /// Sign envelope metadata only (not full request body)
    #[serde(default = "default_true")]
    pub envelope_metadata_only: bool,

    /// Signature algorithm for envelope signing
    #[serde(default = "default_crypto_signing_algorithm")]
    pub algorithm: String,
}

fn default_crypto_signing_algorithm() -> String {
    "ed25519".to_string()
}

impl Default for CryptoSigningConfig {
    fn default() -> Self {
        Self {
            envelope_metadata_only: true,
            algorithm: default_crypto_signing_algorithm(),
        }
    }
}

/// Key hierarchy and rotation settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoHierarchyConfig {
    /// Derivation scheme for org/user/agent key hierarchy
    #[serde(default = "default_crypto_derivation")]
    pub derivation: String,

    /// Rotation cadence in days for active keys
    #[serde(default = "default_crypto_rotation_days")]
    pub rotation_days: u32,
}

fn default_crypto_derivation() -> String {
    "slip10_hardened".to_string()
}

fn default_crypto_rotation_days() -> u32 {
    90
}

impl Default for CryptoHierarchyConfig {
    fn default() -> Self {
        Self {
            derivation: default_crypto_derivation(),
            rotation_days: default_crypto_rotation_days(),
        }
    }
}

/// Merkle tree sealing behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoMerkleConfig {
    /// Enable Merkle audit chain
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Batch seal interval
    #[serde(
        default = "default_crypto_merkle_seal_interval",
        with = "humantime_serde"
    )]
    pub seal_interval: Duration,

    /// Max events per Merkle batch before seal
    #[serde(default = "default_crypto_merkle_batch_size")]
    pub max_events_per_batch: usize,
}

fn default_crypto_merkle_seal_interval() -> Duration {
    Duration::from_secs(3)
}

fn default_crypto_merkle_batch_size() -> usize {
    500
}

impl Default for CryptoMerkleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            seal_interval: default_crypto_merkle_seal_interval(),
            max_events_per_batch: default_crypto_merkle_batch_size(),
        }
    }
}

/// TLS behavior controlled by crypto identity lifecycle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoTlsBindingConfig {
    /// Bind TLS issuer lifecycle to organization identity keys
    #[serde(default = "default_true")]
    pub bind_to_org_identity: bool,

    /// Leaf certificate TTL
    #[serde(default = "default_crypto_tls_leaf_ttl", with = "humantime_serde")]
    pub leaf_ttl: Duration,
}

fn default_crypto_tls_leaf_ttl() -> Duration {
    Duration::from_secs(24 * 60 * 60)
}

impl Default for CryptoTlsBindingConfig {
    fn default() -> Self {
        Self {
            bind_to_org_identity: true,
            leaf_ttl: default_crypto_tls_leaf_ttl(),
        }
    }
}

/// Policy engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub enabled: bool,

    /// Mode: audit, enforce
    #[serde(default = "default_policy_mode")]
    pub mode: String,

    /// Directory containing policy files
    pub policy_dir: Option<PathBuf>,

    /// Path to policy data JSON file
    pub data_file: Option<PathBuf>,

    /// Watch for policy file changes
    #[serde(default)]
    pub watch_for_changes: bool,

    /// Environment: development, staging, production
    #[serde(default = "default_environment")]
    pub environment: String,

    /// Cache configuration
    #[serde(default)]
    pub cache: CacheConfig,

    /// Evaluation timeout
    #[serde(default = "default_eval_timeout", with = "humantime_serde")]
    pub evaluation_timeout: Duration,
}

fn default_policy_mode() -> String {
    "enforce".to_string()
}

fn default_environment() -> String {
    "development".to_string()
}

fn default_eval_timeout() -> Duration {
    Duration::from_millis(100)
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: default_policy_mode(),
            policy_dir: None,
            data_file: None,
            watch_for_changes: false,
            environment: default_environment(),
            cache: CacheConfig::default(),
            evaluation_timeout: default_eval_timeout(),
        }
    }
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// L1 cache TTL (exact match, short-lived)
    #[serde(default = "default_l1_ttl", with = "humantime_serde")]
    pub l1_ttl: Duration,

    /// L2 cache TTL (pattern match, longer-lived). Defaults to 30x l1_ttl if not specified.
    #[serde(default, with = "humantime_serde_option")]
    pub l2_ttl: Option<Duration>,

    /// Maximum L1 cache entries
    #[serde(default = "default_l1_max_entries")]
    pub l1_max_entries: usize,

    /// Maximum L2 cache entries
    #[serde(default = "default_l2_max_entries")]
    pub l2_max_entries: usize,
}

fn default_l1_ttl() -> Duration {
    Duration::from_secs(10)
}

fn default_l1_max_entries() -> usize {
    10000
}

fn default_l2_max_entries() -> usize {
    1000
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            l1_ttl: default_l1_ttl(),
            l2_ttl: None,
            l1_max_entries: default_l1_max_entries(),
            l2_max_entries: default_l2_max_entries(),
        }
    }
}

impl CacheConfig {
    /// Get the effective L2 TTL, defaulting to 30x L1 TTL if not specified
    pub fn effective_l2_ttl(&self) -> Duration {
        self.l2_ttl.unwrap_or(self.l1_ttl * 30)
    }
}

/// Observability configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserveConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Enable PII detection
    #[serde(default = "default_true")]
    pub pii_detection: bool,

    /// Source scopes where PII detection runs.
    #[serde(default)]
    pub pii_scopes: ObservePiiScopes,

    /// User-defined tags attached to all emitted observability events.
    #[serde(default)]
    pub event_tags: BTreeMap<String, String>,

    /// Log requests
    #[serde(default = "default_true")]
    pub log_requests: bool,

    /// Log responses
    #[serde(default = "default_true")]
    pub log_responses: bool,

    /// Enable tamper-proof Merkle logging
    #[serde(default)]
    pub tamper_proof: bool,

    /// Storage configuration
    #[serde(default)]
    pub storage: StorageConfig,

    /// Buffer size for async logging
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    /// Flush interval
    #[serde(default = "default_flush_interval", with = "humantime_serde")]
    pub flush_interval: Duration,
}

fn default_buffer_size() -> usize {
    1000
}

fn default_flush_interval() -> Duration {
    Duration::from_secs(1)
}

impl Default for ObserveConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            pii_detection: true,
            pii_scopes: ObservePiiScopes::default(),
            event_tags: BTreeMap::new(),
            log_requests: true,
            log_responses: true,
            tamper_proof: false,
            storage: StorageConfig::default(),
            buffer_size: default_buffer_size(),
            flush_interval: default_flush_interval(),
        }
    }
}

/// Source scopes for PII detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservePiiScopes {
    /// Run PII detection for direct AI inference/provider traffic.
    #[serde(default = "default_true")]
    pub ai_inference: bool,
    /// Run PII detection for MCP request/response traffic.
    #[serde(default = "default_true")]
    pub mcp: bool,
    /// Run PII detection for agent-app traffic.
    #[serde(default = "default_true")]
    pub agent_apps: bool,
}

impl Default for ObservePiiScopes {
    fn default() -> Self {
        Self {
            ai_inference: true,
            mcp: true,
            agent_apps: true,
        }
    }
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Backend: sqlite
    #[serde(default = "default_storage_backend")]
    pub backend: String,

    /// Path for storage
    #[serde(default = "default_storage_path")]
    pub path: PathBuf,

    /// Source-aware retention configuration.
    #[serde(default)]
    pub retention: RetentionConfig,

    /// Inline payload threshold (bytes) before payload side-table offload.
    #[serde(default = "default_inline_threshold_bytes")]
    pub inline_threshold_bytes: usize,

    /// Deprecated single retention days setting (0 = forever).
    /// Read for backward compatibility from existing configs.
    #[serde(default)]
    #[serde(rename = "retention_days")]
    #[serde(skip_serializing)]
    pub legacy_retention_days: Option<u32>,
}

fn default_storage_backend() -> String {
    "sqlite".to_string()
}

fn default_storage_path() -> PathBuf {
    PathBuf::from("./logs")
}

fn default_inline_threshold_bytes() -> usize {
    4096
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: default_storage_backend(),
            path: default_storage_path(),
            retention: RetentionConfig::default(),
            inline_threshold_bytes: default_inline_threshold_bytes(),
            legacy_retention_days: None,
        }
    }
}

impl StorageConfig {
    /// Applies deprecated `retention_days` when present and no explicit
    /// source-aware retention values were configured.
    pub fn apply_legacy_retention_days(&mut self) {
        let Some(days) = self.legacy_retention_days.take() else {
            return;
        };

        if self.retention.is_default() {
            self.retention = RetentionConfig::uniform(days);
        }
    }
}

/// Source-aware retention policy for observability artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// AI provider/direct inference events.
    #[serde(default = "default_retention_ai_proxy_days")]
    pub ai_proxy_days: u32,
    /// MCP events.
    #[serde(default = "default_retention_mcp_days")]
    pub mcp_days: u32,
    /// Agent app events (typically highest volume/noisiest).
    #[serde(default = "default_retention_agent_app_days")]
    pub agent_app_days: u32,
    /// Materialized request/response clusters.
    #[serde(default = "default_retention_clusters_days")]
    pub clusters_days: u32,
    /// Minute rollups for dashboard warm starts and trends.
    #[serde(default = "default_retention_rollups_days")]
    pub rollups_days: u32,
    /// Whether maintenance may run VACUUM after cleanup.
    #[serde(default = "default_true")]
    pub vacuum_after_cleanup: bool,
}

fn default_retention_ai_proxy_days() -> u32 {
    7
}

fn default_retention_mcp_days() -> u32 {
    7
}

fn default_retention_agent_app_days() -> u32 {
    1
}

fn default_retention_clusters_days() -> u32 {
    14
}

fn default_retention_rollups_days() -> u32 {
    90
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            ai_proxy_days: default_retention_ai_proxy_days(),
            mcp_days: default_retention_mcp_days(),
            agent_app_days: default_retention_agent_app_days(),
            clusters_days: default_retention_clusters_days(),
            rollups_days: default_retention_rollups_days(),
            vacuum_after_cleanup: true,
        }
    }
}

impl RetentionConfig {
    pub fn uniform(days: u32) -> Self {
        Self {
            ai_proxy_days: days,
            mcp_days: days,
            agent_app_days: days,
            clusters_days: days,
            rollups_days: days,
            vacuum_after_cleanup: true,
        }
    }

    pub fn is_default(&self) -> bool {
        self.ai_proxy_days == default_retention_ai_proxy_days()
            && self.mcp_days == default_retention_mcp_days()
            && self.agent_app_days == default_retention_agent_app_days()
            && self.clusters_days == default_retention_clusters_days()
            && self.rollups_days == default_retention_rollups_days()
            && self.vacuum_after_cleanup
    }
}

/// Budget configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetConfig {
    #[serde(default)]
    pub enabled: bool,

    /// Budget limits
    #[serde(default)]
    pub limits: Vec<BudgetLimit>,

    /// Alert thresholds
    #[serde(default)]
    pub alerts: Vec<AlertConfig>,

    /// Database path for persistence
    #[serde(default = "default_budget_db_path")]
    #[serde(alias = "storage_path")]
    pub db_path: Option<PathBuf>,
}

fn default_budget_db_path() -> Option<PathBuf> {
    Some(PathBuf::from("~/.soth/budget.db"))
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            limits: Vec::new(),
            alerts: Vec::new(),
            db_path: default_budget_db_path(),
        }
    }
}

/// Cloud sync configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudConfig {
    /// Whether cloud sync hooks are enabled
    #[serde(default)]
    pub enabled: bool,

    /// API key for cloud authentication
    pub api_key: Option<String>,

    /// Cloud API endpoint
    #[serde(default = "default_cloud_endpoint")]
    pub endpoint: String,

    /// User-defined cloud tags for attribution
    #[serde(default)]
    pub tags: BTreeMap<String, String>,

    /// Metadata sync interval
    #[serde(default = "default_cloud_sync_interval_secs")]
    pub sync_interval_secs: u64,

    /// Config pull interval
    #[serde(default = "default_cloud_config_pull_interval_secs")]
    pub config_pull_interval_secs: u64,

    /// Debounce window before applying a newly pulled config version
    #[serde(default = "default_cloud_config_debounce_secs")]
    pub config_debounce_secs: u64,

    /// Whether response/request body uploads are enabled
    #[serde(default)]
    pub body_upload_enabled: bool,

    /// Maximum metadata events per upload batch.
    #[serde(default = "default_cloud_metadata_max_events_per_batch")]
    pub metadata_max_events_per_batch: usize,

    /// Maximum compressed metadata batch size in bytes.
    #[serde(default = "default_cloud_metadata_max_compressed_batch_bytes")]
    pub metadata_max_compressed_batch_bytes: u64,

    /// Maximum request/response body size eligible for cloud body upload.
    #[serde(default = "default_cloud_body_upload_max_bytes")]
    pub body_upload_max_bytes: u64,

    /// Local path for cached cloud config snapshot
    #[serde(default = "default_cloud_cache_path")]
    pub cache_path: Option<PathBuf>,
}

fn default_cloud_endpoint() -> String {
    "https://api.soth.ai".to_string()
}

fn default_cloud_sync_interval_secs() -> u64 {
    60
}

fn default_cloud_config_pull_interval_secs() -> u64 {
    300
}

fn default_cloud_config_debounce_secs() -> u64 {
    6
}

fn default_cloud_cache_path() -> Option<PathBuf> {
    Some(PathBuf::from("~/.soth/cloud_config_cache.json"))
}

fn default_cloud_metadata_max_events_per_batch() -> usize {
    200
}

fn default_cloud_metadata_max_compressed_batch_bytes() -> u64 {
    5 * 1024 * 1024
}

fn default_cloud_body_upload_max_bytes() -> u64 {
    15 * 1024 * 1024
}

impl Default for CloudConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_key: None,
            endpoint: default_cloud_endpoint(),
            tags: BTreeMap::new(),
            sync_interval_secs: default_cloud_sync_interval_secs(),
            config_pull_interval_secs: default_cloud_config_pull_interval_secs(),
            config_debounce_secs: default_cloud_config_debounce_secs(),
            body_upload_enabled: true,
            metadata_max_events_per_batch: default_cloud_metadata_max_events_per_batch(),
            metadata_max_compressed_batch_bytes:
                default_cloud_metadata_max_compressed_batch_bytes(),
            body_upload_max_bytes: default_cloud_body_upload_max_bytes(),
            cache_path: default_cloud_cache_path(),
        }
    }
}

/// Budget limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetLimit {
    /// Scope: global, per_agent, per_session, per_model
    pub scope: String,

    /// Daily limit in USD
    pub daily: Option<f64>,

    /// Weekly limit in USD
    pub weekly: Option<f64>,

    /// Monthly limit in USD
    pub monthly: Option<f64>,

    /// Agent ID (for per_agent scope)
    pub agent_id: Option<String>,

    /// Model ID (for per_model scope)
    pub model: Option<String>,
}

/// Alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Threshold percentage (0-100)
    pub threshold_percent: u8,

    /// Action: notify, warn, block
    pub action: String,

    /// Webhook URL for notifications
    pub webhook_url: Option<String>,
}

/// Dashboard configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    /// Whether the dashboard is enabled
    #[serde(default)]
    pub enabled: bool,

    /// Port for the dashboard server
    #[serde(default = "default_dashboard_port")]
    pub port: u16,
}

fn default_dashboard_port() -> u16 {
    3001
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: default_dashboard_port(),
        }
    }
}

/// Soth proxy configuration (HTTP/HTTPS interception)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardProxyConfig {
    /// Whether the soth proxy is enabled
    #[serde(default)]
    pub enabled: bool,

    /// Port to listen on
    #[serde(default = "default_forward_proxy_port")]
    pub port: u16,

    /// Address to bind to
    #[serde(default = "default_address")]
    pub address: String,

    /// CA certificate configuration
    #[serde(default)]
    pub ca: CaConfig,

    /// Connection pool configuration
    #[serde(default)]
    pub pool: PoolConfig,

    /// Host filtering configuration
    #[serde(default)]
    pub hosts: HostFilterConfig,

    /// TLS interception behavior overrides.
    #[serde(default)]
    pub tls: ForwardProxyTlsConfig,

    /// Request timeout for AI providers (streaming can be long)
    #[serde(default = "default_ai_timeout", with = "humantime_serde")]
    pub request_timeout: Duration,

    /// Detection/classification mode during registry migration.
    #[serde(default)]
    pub registry_mode: RegistryMode,

    /// Maximum HTTP request/response body size to capture for observability.
    #[serde(default = "default_forward_proxy_capture_max_body_bytes")]
    pub capture_max_body_bytes: u64,
}

fn default_forward_proxy_port() -> u16 {
    8080
}

fn default_ai_timeout() -> Duration {
    Duration::from_secs(300) // 5 minutes for long AI responses
}

fn default_forward_proxy_capture_max_body_bytes() -> u64 {
    15 * 1024 * 1024
}

impl Default for ForwardProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: default_forward_proxy_port(),
            address: default_address(),
            ca: CaConfig::default(),
            pool: PoolConfig::default(),
            hosts: HostFilterConfig::default(),
            tls: ForwardProxyTlsConfig::default(),
            request_timeout: default_ai_timeout(),
            registry_mode: RegistryMode::default(),
            capture_max_body_bytes: default_forward_proxy_capture_max_body_bytes(),
        }
    }
}

impl ForwardProxyConfig {
    /// Get the socket address for the proxy
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }
}

/// TLS-specific options for the forward proxy transport.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ForwardProxyTlsConfig {
    /// Adaptive passthrough of learned cert-pinned hosts.
    #[serde(default)]
    pub learned_passthrough: LearnedPassthroughConfig,
}

/// Learned TLS passthrough configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedPassthroughConfig {
    /// Whether learned passthrough is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// JSON state path for learned host map.
    #[serde(default = "default_learned_passthrough_state_path")]
    pub state_path: PathBuf,

    /// Max age before learned hosts expire.
    #[serde(
        default = "default_learned_passthrough_max_age",
        with = "humantime_serde"
    )]
    pub max_age: Duration,

    /// Number of repeated failed intercept attempts before learning passthrough.
    #[serde(default = "default_learned_passthrough_failure_threshold")]
    pub failure_threshold: u32,

    /// Rolling window used for failure threshold accumulation.
    #[serde(
        default = "default_learned_passthrough_failure_window",
        with = "humantime_serde"
    )]
    pub failure_window: Duration,
}

fn default_learned_passthrough_state_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".soth")
        .join("learned-passthrough.json")
}

fn default_learned_passthrough_max_age() -> Duration {
    Duration::from_secs(7 * 24 * 60 * 60)
}

fn default_learned_passthrough_failure_threshold() -> u32 {
    3
}

fn default_learned_passthrough_failure_window() -> Duration {
    Duration::from_secs(90)
}

impl Default for LearnedPassthroughConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            state_path: default_learned_passthrough_state_path(),
            max_age: default_learned_passthrough_max_age(),
            failure_threshold: default_learned_passthrough_failure_threshold(),
            failure_window: default_learned_passthrough_failure_window(),
        }
    }
}

/// CA certificate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaConfig {
    /// Path to CA certificate file
    #[serde(default = "default_ca_cert_path")]
    pub cert_path: PathBuf,

    /// Path to CA private key file
    #[serde(default = "default_ca_key_path")]
    pub key_path: PathBuf,

    /// Generated certificate validity duration
    #[serde(default = "default_cert_validity", with = "humantime_serde")]
    pub cert_validity: Duration,

    /// Certificate cache TTL
    #[serde(default = "default_cache_ttl", with = "humantime_serde")]
    pub cache_ttl: Duration,

    /// Maximum cached certificates
    #[serde(default = "default_cache_max")]
    pub cache_max: usize,
}

fn default_ca_cert_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".soth")
        .join("ca")
        .join("ca.crt")
}

fn default_ca_key_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".soth")
        .join("ca")
        .join("ca.key")
}

fn default_cert_validity() -> Duration {
    Duration::from_secs(24 * 60 * 60) // 24 hours
}

fn default_cache_ttl() -> Duration {
    Duration::from_secs(60 * 60) // 1 hour
}

fn default_cache_max() -> usize {
    10_000
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            cert_path: default_ca_cert_path(),
            key_path: default_ca_key_path(),
            cert_validity: default_cert_validity(),
            cache_ttl: default_cache_ttl(),
            cache_max: default_cache_max(),
        }
    }
}

/// Connection pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    /// Maximum connections per host
    #[serde(default = "default_max_connections_per_host")]
    pub max_connections_per_host: usize,

    /// Idle connection timeout
    #[serde(default = "default_idle_timeout", with = "humantime_serde")]
    pub idle_timeout: Duration,

    /// Connection timeout
    #[serde(default = "default_connect_timeout", with = "humantime_serde")]
    pub connect_timeout: Duration,
}

fn default_max_connections_per_host() -> usize {
    10
}

fn default_idle_timeout() -> Duration {
    Duration::from_secs(90)
}

fn default_connect_timeout() -> Duration {
    Duration::from_secs(10)
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_host: default_max_connections_per_host(),
            idle_timeout: default_idle_timeout(),
            connect_timeout: default_connect_timeout(),
        }
    }
}

/// Host filtering configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostFilterConfig {
    /// Host filtering mode:
    /// - selective: intercept configured AI/MCP hosts and tunnel the rest (default)
    /// - discovery: intercept all non-local hosts to discover new MCP/AI domains
    #[serde(default)]
    pub mode: HostFilterMode,

    /// Hosts classified as AI inference/app traffic.
    #[serde(default = "default_ai_inference_hosts")]
    pub ai_inference: Vec<String>,

    /// Hosts classified as MCP transport/service traffic.
    #[serde(default = "default_mcp_service_hosts")]
    pub mcp: Vec<String>,

    /// Hosts classified as agent app traffic (ChatGPT, Claude, Gemini web apps, IDE agents).
    #[serde(default = "default_agent_app_hosts")]
    pub agent_apps: Vec<String>,

    /// Optional external domain-list files.
    /// When set, each file replaces the corresponding inline list at load time.
    #[serde(default)]
    pub domain_files: HostDomainFilesConfig,

    /// Blocked hosts - these are rejected with 403
    #[serde(default)]
    pub block: Vec<String>,
}

/// Optional file paths for host domain classes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostDomainFilesConfig {
    /// YAML file for AI inference domains.
    pub ai_inference: Option<PathBuf>,
    /// YAML file for MCP domains.
    pub mcp: Option<PathBuf>,
    /// YAML file for agent app domains.
    pub agent_apps: Option<PathBuf>,
}

/// Host filtering mode for soth proxy interception
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HostFilterMode {
    /// Intercept configured hosts only; blind tunnel everything else.
    #[default]
    Selective,
    /// Intercept all non-local hosts (useful for discovery).
    Discovery,
}

/// Registry migration mode for forward proxy classification/routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RegistryMode {
    /// Registry bundle-driven detection/intercept decisions.
    ///
    /// `legacy` and `shadow` are accepted as compatibility aliases and map to this mode.
    #[default]
    #[serde(alias = "legacy", alias = "shadow")]
    Registry,
}

impl std::fmt::Display for RegistryMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "registry")
    }
}

impl std::fmt::Display for HostFilterMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Selective => write!(f, "selective"),
            Self::Discovery => write!(f, "discovery"),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct DomainSeedFile {
    #[serde(default)]
    domains: Vec<String>,
}

fn default_ai_inference_hosts() -> Vec<String> {
    load_seed_domains(include_str!("../../../../domains/ai_inference.yaml"))
}

fn default_mcp_service_hosts() -> Vec<String> {
    load_seed_domains(include_str!("../../../../domains/mcp.yaml"))
}

fn default_agent_app_hosts() -> Vec<String> {
    load_seed_domains(include_str!("../../../../domains/agent_apps.yaml"))
}

fn load_seed_domains(contents: &str) -> Vec<String> {
    match serde_yaml::from_str::<DomainSeedFile>(contents) {
        Ok(seed) => dedupe_hosts(seed.domains),
        Err(error) => {
            tracing::warn!("Failed to parse embedded domain seed list: {error}");
            Vec::new()
        }
    }
}

fn dedupe_hosts(hosts: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::with_capacity(hosts.len());
    let mut deduped = Vec::with_capacity(hosts.len());
    for host in hosts {
        if seen.insert(host.clone()) {
            deduped.push(host);
        }
    }
    deduped
}

impl Default for HostFilterConfig {
    fn default() -> Self {
        Self {
            mode: HostFilterMode::default(),
            ai_inference: default_ai_inference_hosts(),
            mcp: default_mcp_service_hosts(),
            agent_apps: default_agent_app_hosts(),
            domain_files: HostDomainFilesConfig::default(),
            block: Vec::new(),
        }
    }
}

impl HostFilterConfig {
    fn matches_any(host: &str, patterns: &[String]) -> bool {
        patterns
            .iter()
            .any(|pattern| Self::matches_pattern(host, pattern))
    }

    /// API endpoints that should stay in AI inference class even if they match
    /// a broad agent-app wildcard.
    fn is_ai_api_host(host: &str) -> bool {
        host == "api.openai.com"
            || host.ends_with(".api.openai.com")
            || host == "api.anthropic.com"
            || host.ends_with(".api.anthropic.com")
            || host == "api.claude.ai"
            || host.ends_with(".api.claude.ai")
    }

    /// Check if host is in AI inference/app whitelist.
    pub fn should_check_ai_inference(&self, host: &str) -> bool {
        Self::matches_any(host, &self.ai_inference)
    }

    /// Check if host is in MCP whitelist.
    pub fn should_check_mcp(&self, host: &str) -> bool {
        if !self.mcp.is_empty() {
            Self::matches_any(host, &self.mcp)
        } else {
            false
        }
    }

    /// Check if host is in agent app whitelist.
    pub fn should_check_agent_app(&self, host: &str) -> bool {
        if Self::is_ai_api_host(host) {
            return false;
        }
        Self::matches_any(host, &self.agent_apps)
    }

    /// Number of unique host patterns that can trigger interception.
    pub fn intercept_domain_count(&self) -> usize {
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for host in &self.ai_inference {
            seen.insert(host.as_str());
        }
        for host in &self.mcp {
            seen.insert(host.as_str());
        }
        for host in &self.agent_apps {
            seen.insert(host.as_str());
        }
        seen.len()
    }

    /// Check if a host should be intercepted (full MITM)
    pub fn should_intercept(&self, host: &str) -> bool {
        self.should_check_ai_inference(host)
            || self.should_check_mcp(host)
            || self.should_check_agent_app(host)
    }

    /// Check if a host is blocked (rejected with 403)
    pub fn is_blocked(&self, host: &str) -> bool {
        self.block
            .iter()
            .any(|pattern| Self::matches_pattern(host, pattern))
    }

    /// Match a host against a pattern with wildcard support
    /// Supports:
    /// - Exact match: "api.openai.com"
    /// - Prefix wildcard: "*.openai.azure.com" matches "foo.openai.azure.com"
    /// - Prefix wildcard (no dot): "*-aiplatform.googleapis.com" matches "us-central1-aiplatform.googleapis.com"
    /// - Middle wildcard: "bedrock.*.amazonaws.com" matches "bedrock.us-east-1.amazonaws.com"
    fn matches_pattern(host: &str, pattern: &str) -> bool {
        if !pattern.contains('*') {
            // Exact match
            return host == pattern;
        }

        // Find the wildcard position
        if let Some(star_pos) = pattern.find('*') {
            let prefix = &pattern[..star_pos]; // Everything before *
            let suffix = &pattern[star_pos + 1..]; // Everything after *

            // Check if host matches prefix...suffix pattern
            if host.starts_with(prefix) && host.ends_with(suffix) {
                // Ensure there's something in the middle (wildcard matched something)
                let middle_len = host.len().saturating_sub(prefix.len() + suffix.len());
                return middle_len > 0;
            }
        }

        false
    }

    /// Check if a host is a local address that should always be tunneled
    fn is_local_host(host: &str) -> bool {
        let host_lower = host.to_lowercase();
        host_lower == "localhost"
            || host_lower == "127.0.0.1"
            || host_lower == "::1"
            || host_lower.ends_with(".local")
            || host_lower.ends_with(".localhost")
            || host_lower.starts_with("192.168.")
            || host_lower.starts_with("10.")
            || host_lower.starts_with("172.16.")
            || host_lower.starts_with("172.17.")
            || host_lower.starts_with("172.18.")
            || host_lower.starts_with("172.19.")
            || host_lower.starts_with("172.20.")
            || host_lower.starts_with("172.21.")
            || host_lower.starts_with("172.22.")
            || host_lower.starts_with("172.23.")
            || host_lower.starts_with("172.24.")
            || host_lower.starts_with("172.25.")
            || host_lower.starts_with("172.26.")
            || host_lower.starts_with("172.27.")
            || host_lower.starts_with("172.28.")
            || host_lower.starts_with("172.29.")
            || host_lower.starts_with("172.30.")
            || host_lower.starts_with("172.31.")
    }

    /// Determine the action for a host
    pub fn action_for_host(&self, host: &str) -> HostAction {
        // Always tunnel local addresses - never intercept or block
        if Self::is_local_host(host) {
            return HostAction::Tunnel;
        }

        // First check if blocked
        if self.is_blocked(host) {
            return HostAction::Block;
        }

        match self.mode {
            HostFilterMode::Discovery => HostAction::Intercept,
            HostFilterMode::Selective => {
                // Intercept configured host patterns; tunnel everything else.
                if self.should_intercept(host) {
                    HostAction::Intercept
                } else {
                    HostAction::Tunnel
                }
            }
        }
    }
}

/// Action to take for a host
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostAction {
    /// Intercept with full MITM (TLS termination + inspection)
    Intercept,
    /// Blind tunnel (just pass TCP bytes through)
    Tunnel,
    /// Block with 403 Forbidden
    Block,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level: debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Format: json, text
    #[serde(default = "default_log_format")]
    pub format: String,

    /// Output: stdout, stderr, file
    #[serde(default = "default_log_output")]
    pub output: String,

    /// Log file path (when output = file)
    pub file_path: Option<PathBuf>,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

fn default_log_output() -> String {
    "stderr".to_string()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
            output: default_log_output(),
            file_path: None,
        }
    }
}

/// Custom serde module for humantime Duration parsing
mod humantime_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = humantime::format_duration(*duration).to_string();
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        humantime::parse_duration(&s).map_err(serde::de::Error::custom)
    }
}

// === Production Hardening Configs ===

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Whether rate limiting is enabled
    #[serde(default)]
    pub enabled: bool,

    /// Requests per second per key
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second: f64,

    /// Maximum burst capacity per key
    #[serde(default = "default_burst_size")]
    pub burst_size: u32,

    /// Global requests per second limit
    #[serde(default = "default_global_rps")]
    pub global_requests_per_second: f64,

    /// Global burst capacity
    #[serde(default = "default_global_burst")]
    pub global_burst_size: u32,
}

fn default_requests_per_second() -> f64 {
    100.0
}

fn default_burst_size() -> u32 {
    200
}

fn default_global_rps() -> f64 {
    1000.0
}

fn default_global_burst() -> u32 {
    2000
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            requests_per_second: default_requests_per_second(),
            burst_size: default_burst_size(),
            global_requests_per_second: default_global_rps(),
            global_burst_size: default_global_burst(),
        }
    }
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Whether circuit breaker is enabled
    #[serde(default = "default_circuit_breaker_enabled")]
    pub enabled: bool,

    /// Number of failures before opening circuit
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,

    /// Duration to keep circuit open before half-open
    #[serde(default = "default_open_duration", with = "humantime_serde")]
    pub open_duration: Duration,

    /// Number of successful requests in half-open to close circuit
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,

    /// Time window for counting failures
    #[serde(default = "default_failure_window", with = "humantime_serde")]
    pub failure_window: Duration,
}

fn default_circuit_breaker_enabled() -> bool {
    true
}

fn default_failure_threshold() -> u32 {
    5
}

fn default_open_duration() -> Duration {
    Duration::from_secs(30)
}

fn default_success_threshold() -> u32 {
    3
}

fn default_failure_window() -> Duration {
    Duration::from_secs(60)
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: default_circuit_breaker_enabled(),
            failure_threshold: default_failure_threshold(),
            open_duration: default_open_duration(),
            success_threshold: default_success_threshold(),
            failure_window: default_failure_window(),
        }
    }
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Whether health endpoints are enabled
    #[serde(default = "default_health_enabled")]
    pub enabled: bool,

    /// Path for liveness probe
    #[serde(default = "default_liveness_path")]
    pub liveness_path: String,

    /// Path for readiness probe
    #[serde(default = "default_readiness_path")]
    pub readiness_path: String,

    /// Path for Prometheus metrics
    #[serde(default = "default_metrics_path")]
    pub metrics_path: String,
}

fn default_health_enabled() -> bool {
    true
}

fn default_liveness_path() -> String {
    "/healthz".to_string()
}

fn default_readiness_path() -> String {
    "/readyz".to_string()
}

fn default_metrics_path() -> String {
    "/metrics".to_string()
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: default_health_enabled(),
            liveness_path: default_liveness_path(),
            readiness_path: default_readiness_path(),
            metrics_path: default_metrics_path(),
        }
    }
}

/// Connection limits and timeout configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionLimitsConfig {
    /// Maximum total connections globally
    #[serde(default = "default_conn_max_total")]
    pub max_total_connections: usize,

    /// Maximum connections per upstream host
    #[serde(default = "default_conn_max_per_host")]
    pub max_connections_per_host: usize,

    /// Connection idle timeout
    #[serde(default = "default_conn_idle_timeout", with = "humantime_serde")]
    pub idle_timeout: Duration,

    /// TCP connect timeout
    #[serde(default = "default_conn_connect_timeout", with = "humantime_serde")]
    pub connect_timeout: Duration,

    /// Request timeout (for AI requests, can be longer)
    #[serde(default = "default_conn_request_timeout", with = "humantime_serde")]
    pub request_timeout: Duration,

    /// TLS handshake timeout
    #[serde(default = "default_conn_tls_timeout", with = "humantime_serde")]
    pub tls_timeout: Duration,
}

fn default_conn_max_total() -> usize {
    1000
}

fn default_conn_max_per_host() -> usize {
    100
}

fn default_conn_idle_timeout() -> Duration {
    Duration::from_secs(90)
}

fn default_conn_connect_timeout() -> Duration {
    Duration::from_secs(10)
}

fn default_conn_request_timeout() -> Duration {
    Duration::from_secs(300) // 5 minutes for AI requests
}

fn default_conn_tls_timeout() -> Duration {
    Duration::from_secs(10)
}

impl Default for ConnectionLimitsConfig {
    fn default() -> Self {
        Self {
            max_total_connections: default_conn_max_total(),
            max_connections_per_host: default_conn_max_per_host(),
            idle_timeout: default_conn_idle_timeout(),
            connect_timeout: default_conn_connect_timeout(),
            request_timeout: default_conn_request_timeout(),
            tls_timeout: default_conn_tls_timeout(),
        }
    }
}

/// Fail-open behavior when enforcement internals timeout or error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailOpenConfig {
    /// Whether enforcement should fail open on internal timeout/error.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Maximum wall-clock time for enforcement pipeline evaluation.
    #[serde(default = "default_enforcement_timeout", with = "humantime_serde")]
    pub enforcement_timeout: Duration,

    /// Fail-open on policy evaluation internal errors.
    #[serde(default = "default_true")]
    pub policy_fail_open: bool,

    /// Fail-open on budget evaluation internal errors.
    #[serde(default = "default_true")]
    pub budget_fail_open: bool,
}

fn default_enforcement_timeout() -> Duration {
    Duration::from_millis(500)
}

impl Default for FailOpenConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            enforcement_timeout: default_enforcement_timeout(),
            policy_fail_open: default_true(),
            budget_fail_open: default_true(),
        }
    }
}

/// Production configuration combining all hardening options
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProductionConfig {
    /// Rate limiting settings
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// Circuit breaker settings
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,

    /// Health check settings
    #[serde(default)]
    pub health: HealthCheckConfig,

    /// Connection limits and timeouts
    #[serde(default)]
    pub connection_limits: ConnectionLimitsConfig,

    /// Fail-open behavior for enforcement timeout/error paths.
    #[serde(default)]
    pub fail_open: FailOpenConfig,
}

/// Custom serde module for optional humantime Duration parsing
mod humantime_serde_option {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match duration {
            Some(d) => {
                let s = humantime::format_duration(*d).to_string();
                serializer.serialize_some(&s)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => humantime::parse_duration(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SothConfig::default();
        assert_eq!(config.version, "1.0");
        assert_eq!(config.server.transport, "stdio");
        assert_eq!(config.server.listen.port, 3000);
        assert!(!config.crypto_identity.enabled);
        assert_eq!(config.crypto_identity.mode, "audit");
        assert_eq!(config.crypto_identity.signing.algorithm, "ed25519");
        assert!(!config.cloud.enabled);
        assert_eq!(config.cloud.endpoint, "https://api.soth.ai");
        assert_eq!(config.cloud.config_debounce_secs, 6);
        assert!(config.forward_proxy.tls.learned_passthrough.enabled);
    }

    #[test]
    fn test_listen_socket_addr() {
        let listen = ListenConfig::default();
        assert_eq!(listen.socket_addr(), "127.0.0.1:3000");
    }

    #[test]
    fn test_parse_yaml() {
        let yaml = r#"
version: "1.0"
server:
  listen:
    address: "0.0.0.0"
    port: 8080
  transport: sse
upstream:
  command: npx
  args:
    - "-y"
    - "@modelcontextprotocol/server-filesystem"
"#;
        let config: SothConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.server.listen.address, "0.0.0.0");
        assert_eq!(config.server.listen.port, 8080);
        assert_eq!(config.server.transport, "sse");
        assert_eq!(config.upstream.command, Some("npx".to_string()));
    }

    #[test]
    fn test_parse_cloud_config_yaml() {
        let yaml = r#"
cloud:
  enabled: true
  api_key: "soth_live_abc123"
  endpoint: "https://staging.soth.ai"
  sync_interval_secs: 30
  config_pull_interval_secs: 120
  config_debounce_secs: 8
  body_upload_enabled: true
  metadata_max_events_per_batch: 120
  metadata_max_compressed_batch_bytes: 3145728
  body_upload_max_bytes: 10485760
  tags:
    project: "edge"
    env: "staging"
"#;
        let config: SothConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.cloud.enabled);
        assert_eq!(config.cloud.api_key.as_deref(), Some("soth_live_abc123"));
        assert_eq!(config.cloud.endpoint, "https://staging.soth.ai");
        assert_eq!(config.cloud.sync_interval_secs, 30);
        assert_eq!(config.cloud.config_pull_interval_secs, 120);
        assert_eq!(config.cloud.config_debounce_secs, 8);
        assert!(config.cloud.body_upload_enabled);
        assert_eq!(config.cloud.metadata_max_events_per_batch, 120);
        assert_eq!(config.cloud.metadata_max_compressed_batch_bytes, 3_145_728);
        assert_eq!(config.cloud.body_upload_max_bytes, 10_485_760);
        assert_eq!(config.cloud.tags.get("project"), Some(&"edge".to_string()));
    }

    #[test]
    fn test_parse_crypto_identity_yaml() {
        let yaml = r#"
crypto_identity:
  enabled: true
  mode: enforce
  enforce_principals:
    - "did:key:z6MkhVexamplePrincipal"
    - "cursor"
  signing:
    envelope_metadata_only: true
    algorithm: "ed25519"
  hierarchy:
    derivation: "slip10_hardened"
    rotation_days: 60
  merkle:
    enabled: true
    seal_interval: "5s"
    max_events_per_batch: 400
  tls:
    bind_to_org_identity: true
    leaf_ttl: "12h"
"#;
        let config: SothConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.crypto_identity.enabled);
        assert_eq!(config.crypto_identity.mode, "enforce");
        assert_eq!(
            config.crypto_identity.enforce_principals,
            vec![
                "did:key:z6MkhVexamplePrincipal".to_string(),
                "cursor".to_string()
            ]
        );
        assert!(config.crypto_identity.signing.envelope_metadata_only);
        assert_eq!(config.crypto_identity.signing.algorithm, "ed25519");
        assert_eq!(
            config.crypto_identity.hierarchy.derivation,
            "slip10_hardened"
        );
        assert_eq!(config.crypto_identity.hierarchy.rotation_days, 60);
        assert!(config.crypto_identity.merkle.enabled);
        assert_eq!(
            config.crypto_identity.merkle.seal_interval,
            Duration::from_secs(5)
        );
        assert_eq!(config.crypto_identity.merkle.max_events_per_batch, 400);
        assert!(config.crypto_identity.tls.bind_to_org_identity);
        assert_eq!(
            config.crypto_identity.tls.leaf_ttl,
            Duration::from_secs(12 * 60 * 60)
        );
    }

    #[test]
    fn test_forward_proxy_default() {
        let config = ForwardProxyConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.port, 8080);
        assert_eq!(config.address, "127.0.0.1");
        assert_eq!(config.socket_addr(), "127.0.0.1:8080");
        assert_eq!(config.registry_mode, RegistryMode::Registry);
    }

    #[test]
    fn test_host_filter_intercept_and_tunnel() {
        use super::HostAction;
        let filter = HostFilterConfig {
            mode: HostFilterMode::Selective,
            ai_inference: vec!["api.openai.com".to_string()],
            mcp: vec![],
            agent_apps: vec![],
            domain_files: HostDomainFilesConfig::default(),
            block: vec![],
        };
        assert_eq!(
            filter.action_for_host("api.openai.com"),
            HostAction::Intercept
        );
        assert_eq!(
            filter.action_for_host("api.example.com"),
            HostAction::Tunnel
        );
    }

    #[test]
    fn test_host_filter_blacklist() {
        use super::HostAction;
        let filter = HostFilterConfig {
            mode: HostFilterMode::Selective,
            ai_inference: vec![],
            mcp: vec![],
            agent_apps: vec![],
            domain_files: HostDomainFilesConfig::default(),
            block: vec!["blocked.com".to_string()],
        };
        assert_eq!(filter.action_for_host("api.openai.com"), HostAction::Tunnel);
        assert_eq!(filter.action_for_host("blocked.com"), HostAction::Block);
    }

    #[test]
    fn test_host_filter_default_selective() {
        use super::HostAction;
        let filter = HostFilterConfig::default();
        assert_eq!(filter.mode, HostFilterMode::Selective);

        // AI domains should be intercepted
        assert_eq!(
            filter.action_for_host("api.openai.com"),
            HostAction::Intercept
        );
        assert_eq!(
            filter.action_for_host("api.anthropic.com"),
            HostAction::Intercept
        );
        assert_eq!(
            filter.action_for_host("generativelanguage.googleapis.com"),
            HostAction::Intercept
        );

        // Non-AI domains should be tunneled (not blocked!)
        assert_eq!(
            filter.action_for_host("random.example.com"),
            HostAction::Tunnel
        );
        assert_eq!(filter.action_for_host("google.com"), HostAction::Tunnel);
    }

    #[test]
    fn test_host_filter_intercept() {
        let filter = HostFilterConfig {
            mode: HostFilterMode::Selective,
            ai_inference: vec![
                "api.openai.com".to_string(),
                "*.openai.azure.com".to_string(),
            ],
            mcp: vec![],
            agent_apps: vec![],
            domain_files: HostDomainFilesConfig::default(),
            block: vec![],
        };

        assert!(filter.should_intercept("api.openai.com"));
        assert!(filter.should_intercept("myinstance.openai.azure.com"));
        assert!(!filter.should_intercept("google.com"));
    }

    #[test]
    fn test_host_filter_wildcard_patterns() {
        let filter = HostFilterConfig {
            mode: HostFilterMode::Selective,
            ai_inference: vec![
                "api.openai.com".to_string(),          // Exact
                "*.openai.azure.com".to_string(),      // Prefix wildcard
                "bedrock.*.amazonaws.com".to_string(), // Middle wildcard
                "*.huggingface.co".to_string(),        // Prefix wildcard
            ],
            mcp: vec![],
            agent_apps: vec![],
            domain_files: HostDomainFilesConfig::default(),
            block: vec![],
        };

        // Exact match
        assert!(filter.should_intercept("api.openai.com"));
        assert!(!filter.should_intercept("api.openai.com.fake.com"));

        // Prefix wildcard
        assert!(filter.should_intercept("myinstance.openai.azure.com"));
        assert!(filter.should_intercept("corp.openai.azure.com"));
        assert!(!filter.should_intercept("openai.azure.com")); // Must have prefix

        // Middle wildcard (AWS Bedrock regions)
        assert!(filter.should_intercept("bedrock.us-east-1.amazonaws.com"));
        assert!(filter.should_intercept("bedrock.eu-west-1.amazonaws.com"));
        assert!(filter.should_intercept("bedrock.ap-northeast-1.amazonaws.com"));
        assert!(!filter.should_intercept("bedrock.amazonaws.com")); // Must have middle part
        assert!(!filter.should_intercept("s3.us-east-1.amazonaws.com")); // Different prefix

        // Hugging Face
        assert!(filter.should_intercept("api-inference.huggingface.co"));
        assert!(filter.should_intercept("datasets.huggingface.co"));
    }

    #[test]
    fn test_default_ai_domains_coverage() {
        let filter = HostFilterConfig::default();

        // Major AI providers should be intercepted by default
        let ai_domains = vec![
            // OpenAI
            "api.openai.com",
            "chat.openai.com",
            "ws.chat.openai.com",
            "myinstance.openai.azure.com",
            // Anthropic
            "api.anthropic.com",
            // Google
            "gemini.google.com",
            "generativelanguage.googleapis.com",
            "aiplatform.googleapis.com",
            "us-central1-aiplatform.googleapis.com",
            // AWS Bedrock
            "bedrock.us-east-1.amazonaws.com",
            "bedrock-runtime.us-west-2.amazonaws.com",
            // Amazon Q / CodeWhisperer
            "codewhisperer.us-east-1.amazonaws.com",
            // GitHub Copilot
            "api.githubcopilot.com",
            "enterprise.githubcopilot.com",
            // Cursor / Windsurf / Zed / Junie
            "api2.cursor.sh",
            "server.codeium.com",
            "cloud.zed.dev",
            "api.jetbrains.ai",
            // Mistral
            "api.mistral.ai",
            // Cohere
            "api.cohere.ai",
            // xAI
            "api.x.ai",
            // Groq
            "api.groq.com",
            // Together
            "api.together.xyz",
            // Perplexity
            "api.perplexity.ai",
            // Replicate
            "api.replicate.com",
            // Hugging Face
            "api-inference.huggingface.co",
            // Fireworks
            "api.fireworks.ai",
            // OpenRouter
            "openrouter.ai",
        ];

        for domain in ai_domains {
            assert!(
                filter.should_intercept(domain),
                "Expected {domain} to be intercepted"
            );
        }

        // Non-AI domains should NOT be intercepted (tunneled instead)
        let non_ai_domains = vec![
            "google.com",
            "example.org",
            "stackoverflow.com",
            "example.com",
        ];

        for domain in non_ai_domains {
            assert!(
                !filter.should_intercept(domain),
                "Expected {domain} to NOT be intercepted"
            );
        }
    }

    #[test]
    fn test_default_mcp_domain_seed_coverage() {
        let mcp_hosts = default_mcp_service_hosts();
        assert!(
            mcp_hosts.len() >= 100,
            "Expected >=100 MCP service hosts, got {}",
            mcp_hosts.len()
        );
        assert!(
            mcp_hosts.contains(&"api.github.com".to_string()),
            "api.github.com should be in MCP seed list"
        );
        assert!(
            mcp_hosts.contains(&"api.slack.com".to_string()),
            "api.slack.com should be in MCP seed list"
        );
        assert!(
            mcp_hosts.contains(&"api.notion.com".to_string()),
            "api.notion.com should be in MCP seed list"
        );
    }

    #[test]
    fn test_default_agent_app_domain_seed_coverage() {
        let agent_hosts = default_agent_app_hosts();
        assert!(
            agent_hosts.contains(&"chatgpt.com".to_string()),
            "chatgpt.com should be in agent app seed list"
        );
        assert!(
            agent_hosts.contains(&"claude.ai".to_string()),
            "claude.ai should be in agent app seed list"
        );
        assert!(
            agent_hosts.contains(&"gemini.google.com".to_string()),
            "gemini.google.com should be in agent app seed list"
        );
    }

    #[test]
    fn test_separate_ai_and_mcp_whitelists() {
        let filter = HostFilterConfig {
            mode: HostFilterMode::Selective,
            ai_inference: vec!["api.openai.com".to_string()],
            mcp: vec!["api.github.com".to_string()],
            agent_apps: vec!["chatgpt.com".to_string()],
            domain_files: HostDomainFilesConfig::default(),
            block: vec![],
        };

        assert!(filter.should_check_ai_inference("api.openai.com"));
        assert!(!filter.should_check_mcp("api.openai.com"));
        assert!(!filter.should_check_agent_app("api.openai.com"));

        assert!(filter.should_check_mcp("api.github.com"));
        assert!(!filter.should_check_ai_inference("api.github.com"));

        assert!(filter.should_check_agent_app("chatgpt.com"));
        assert!(!filter.should_check_mcp("chatgpt.com"));
    }

    #[test]
    fn test_host_filter_intercepts_agent_app_hosts() {
        let filter = HostFilterConfig {
            mode: HostFilterMode::Selective,
            ai_inference: vec![],
            mcp: vec![],
            agent_apps: vec!["chatgpt.com".to_string()],
            domain_files: HostDomainFilesConfig::default(),
            block: vec![],
        };

        assert!(filter.should_intercept("chatgpt.com"));
        assert!(!filter.should_intercept("api.openai.com"));
    }

    #[test]
    fn test_agent_app_class_excludes_claude_api_host() {
        let filter = HostFilterConfig::default();
        assert!(!filter.should_check_agent_app("api.claude.ai"));
        assert!(filter.should_check_agent_app("claude.ai"));
    }

    #[test]
    fn test_default_host_filter_tunnels_unknown_mcp_hosts() {
        let filter = HostFilterConfig::default();

        // Unknown hosts are tunneled by default. For HTTPS CONNECT, this means we
        // cannot inspect payloads on those hosts unless they are explicitly listed.
        assert_eq!(
            filter.action_for_host("custom-mcp.example.com"),
            HostAction::Tunnel
        );
        assert_eq!(
            filter.action_for_host("mcp.partner.internal"),
            HostAction::Tunnel
        );
    }

    #[test]
    fn test_default_host_filter_intercepts_known_claude_mcp_hosts() {
        let filter = HostFilterConfig::default();

        // Claude/Anthropic app transport domains are included in default host lists.
        assert_eq!(
            filter.action_for_host("a-api.anthropic.com"),
            HostAction::Intercept
        );
        assert_eq!(
            filter.action_for_host("statsig.anthropic.com"),
            HostAction::Intercept
        );
    }

    #[test]
    fn test_host_filter_catch_all_pattern_intercepts_non_local_hosts() {
        let filter = HostFilterConfig {
            mode: HostFilterMode::Selective,
            ai_inference: vec!["*".to_string()],
            mcp: vec![],
            agent_apps: vec![],
            domain_files: HostDomainFilesConfig::default(),
            block: vec![],
        };

        assert_eq!(
            filter.action_for_host("custom-mcp.example.com"),
            HostAction::Intercept
        );
        assert_eq!(
            filter.action_for_host("unlisted.vendor.tld"),
            HostAction::Intercept
        );

        // Local addresses still bypass interception.
        assert_eq!(filter.action_for_host("localhost"), HostAction::Tunnel);
        assert_eq!(filter.action_for_host("127.0.0.1"), HostAction::Tunnel);
    }

    #[test]
    fn test_host_filter_discovery_mode_intercepts_unknown_non_local_hosts() {
        let filter = HostFilterConfig {
            mode: HostFilterMode::Discovery,
            ai_inference: vec![],
            mcp: vec![],
            agent_apps: vec![],
            domain_files: HostDomainFilesConfig::default(),
            block: vec!["malware.com".to_string()],
        };

        assert_eq!(
            filter.action_for_host("custom-mcp.example.com"),
            HostAction::Intercept
        );
        assert_eq!(
            filter.action_for_host("unlisted.vendor.tld"),
            HostAction::Intercept
        );
        assert_eq!(filter.action_for_host("malware.com"), HostAction::Block);
        assert_eq!(filter.action_for_host("localhost"), HostAction::Tunnel);
    }

    #[test]
    fn test_host_filter_block() {
        use super::HostAction;
        let filter = HostFilterConfig {
            mode: HostFilterMode::Selective,
            ai_inference: vec!["api.openai.com".to_string()],
            mcp: vec![],
            agent_apps: vec![],
            domain_files: HostDomainFilesConfig::default(),
            block: vec!["malware.com".to_string(), "*.bad.com".to_string()],
        };

        assert_eq!(filter.action_for_host("malware.com"), HostAction::Block);
        assert_eq!(
            filter.action_for_host("anything.bad.com"),
            HostAction::Block
        );
        assert_eq!(
            filter.action_for_host("api.openai.com"),
            HostAction::Intercept
        );
        assert_eq!(filter.action_for_host("google.com"), HostAction::Tunnel);
    }

    #[test]
    fn test_parse_forward_proxy_yaml_selective() {
        use super::HostAction;
        let yaml = r#"
forward_proxy:
  enabled: true
  port: 9090
  address: "0.0.0.0"
  hosts:
    ai_inference:
      - "api.openai.com"
      - "api.anthropic.com"
      - "*.openai.azure.com"
    block:
      - "malware.com"
"#;
        let config: SothConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.forward_proxy.enabled);
        assert_eq!(config.forward_proxy.port, 9090);
        assert_eq!(config.forward_proxy.address, "0.0.0.0");

        // AI domains intercepted
        assert_eq!(
            config.forward_proxy.hosts.action_for_host("api.openai.com"),
            HostAction::Intercept
        );
        assert_eq!(
            config
                .forward_proxy
                .hosts
                .action_for_host("api.anthropic.com"),
            HostAction::Intercept
        );
        assert_eq!(
            config
                .forward_proxy
                .hosts
                .action_for_host("foo.openai.azure.com"),
            HostAction::Intercept
        );

        // Blocked domains blocked
        assert_eq!(
            config.forward_proxy.hosts.action_for_host("malware.com"),
            HostAction::Block
        );

        // Other domains tunneled
        assert_eq!(
            config.forward_proxy.hosts.action_for_host("google.com"),
            HostAction::Tunnel
        );
    }

    #[test]
    fn test_parse_forward_proxy_registry_mode_yaml() {
        let yaml = r#"
forward_proxy:
  enabled: true
  registry_mode: registry
"#;
        let config: SothConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.forward_proxy.registry_mode, RegistryMode::Registry);
    }

    #[test]
    fn test_parse_forward_proxy_registry_mode_legacy_aliases_yaml() {
        for mode in ["legacy", "shadow"] {
            let yaml = format!(
                r#"
forward_proxy:
  enabled: true
  registry_mode: {mode}
"#
            );
            let config: SothConfig = serde_yaml::from_str(&yaml).unwrap();
            assert_eq!(config.forward_proxy.registry_mode, RegistryMode::Registry);
        }
    }

    #[test]
    fn test_parse_forward_proxy_yaml_ai_inference_only() {
        use super::HostAction;
        let yaml = r#"
forward_proxy:
  enabled: true
  port: 9090
  hosts:
    ai_inference:
      - "api.openai.com"
      - "custom.api.com"
"#;
        let config: SothConfig = serde_yaml::from_str(yaml).unwrap();

        // Allowed hosts intercepted
        assert_eq!(
            config.forward_proxy.hosts.action_for_host("api.openai.com"),
            HostAction::Intercept
        );
        assert_eq!(
            config.forward_proxy.hosts.action_for_host("custom.api.com"),
            HostAction::Intercept
        );

        // Other hosts tunneled by default
        assert_eq!(
            config.forward_proxy.hosts.action_for_host("other.com"),
            HostAction::Tunnel
        );
    }

    #[test]
    fn test_parse_forward_proxy_yaml_agent_apps_only() {
        use super::HostAction;
        let yaml = r#"
forward_proxy:
  enabled: true
  hosts:
    ai_inference: []
    mcp: []
    agent_apps:
      - "chatgpt.com"
"#;
        let config: SothConfig = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(
            config.forward_proxy.hosts.action_for_host("chatgpt.com"),
            HostAction::Intercept
        );
        assert_eq!(
            config.forward_proxy.hosts.action_for_host("api.openai.com"),
            HostAction::Tunnel
        );
    }

    #[test]
    fn test_parse_forward_proxy_yaml_discovery_mode() {
        use super::HostAction;
        let yaml = r#"
forward_proxy:
  enabled: true
  hosts:
    mode: "discovery"
    block:
      - "blocked.example"
"#;
        let config: SothConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.forward_proxy.hosts.mode, HostFilterMode::Discovery);
        assert_eq!(
            config
                .forward_proxy
                .hosts
                .action_for_host("unknown.example"),
            HostAction::Intercept
        );
        assert_eq!(
            config
                .forward_proxy
                .hosts
                .action_for_host("blocked.example"),
            HostAction::Block
        );
        assert_eq!(
            config.forward_proxy.hosts.action_for_host("localhost"),
            HostAction::Tunnel
        );
    }

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.requests_per_second, 100.0);
        assert_eq!(config.burst_size, 200);
        assert_eq!(config.global_requests_per_second, 1000.0);
        assert_eq!(config.global_burst_size, 2000);
    }

    #[test]
    fn test_circuit_breaker_config_default() {
        let config = CircuitBreakerConfig::default();
        assert!(config.enabled);
        assert_eq!(config.failure_threshold, 5);
        assert_eq!(config.open_duration, Duration::from_secs(30));
        assert_eq!(config.success_threshold, 3);
        assert_eq!(config.failure_window, Duration::from_secs(60));
    }

    #[test]
    fn test_health_check_config_default() {
        let config = HealthCheckConfig::default();
        assert!(config.enabled);
        assert_eq!(config.liveness_path, "/healthz");
        assert_eq!(config.readiness_path, "/readyz");
        assert_eq!(config.metrics_path, "/metrics");
    }

    #[test]
    fn test_connection_limits_config_default() {
        let config = ConnectionLimitsConfig::default();
        assert_eq!(config.max_total_connections, 1000);
        assert_eq!(config.max_connections_per_host, 100);
        assert_eq!(config.idle_timeout, Duration::from_secs(90));
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert_eq!(config.request_timeout, Duration::from_secs(300));
        assert_eq!(config.tls_timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_learned_passthrough_config_default() {
        let config = LearnedPassthroughConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_age, Duration::from_secs(7 * 24 * 60 * 60));
        assert_eq!(config.failure_threshold, 3);
        assert_eq!(config.failure_window, Duration::from_secs(90));
    }

    #[test]
    fn test_fail_open_config_default() {
        let config = FailOpenConfig::default();
        assert!(config.enabled);
        assert_eq!(config.enforcement_timeout, Duration::from_millis(500));
        assert!(config.policy_fail_open);
        assert!(config.budget_fail_open);
    }

    #[test]
    fn test_production_config_default() {
        let config = ProductionConfig::default();
        assert!(!config.rate_limit.enabled);
        assert!(config.circuit_breaker.enabled);
        assert!(config.health.enabled);
        assert_eq!(config.connection_limits.max_total_connections, 1000);
        assert!(config.fail_open.enabled);
        assert_eq!(
            config.fail_open.enforcement_timeout,
            Duration::from_millis(500)
        );
    }

    #[test]
    fn test_parse_production_yaml() {
        let yaml = r#"
production:
  rate_limit:
    enabled: true
    requests_per_second: 50.0
    burst_size: 100
  circuit_breaker:
    enabled: true
    failure_threshold: 3
    open_duration: "60s"
    success_threshold: 2
  health:
    enabled: true
    liveness_path: "/health"
    readiness_path: "/ready"
    metrics_path: "/prom"
  connection_limits:
    max_total_connections: 500
    max_connections_per_host: 50
    idle_timeout: "2m"
    connect_timeout: "5s"
    request_timeout: "10m"
    tls_timeout: "15s"
  fail_open:
    enabled: false
    enforcement_timeout: "750ms"
    policy_fail_open: false
    budget_fail_open: true
"#;
        let config: SothConfig = serde_yaml::from_str(yaml).unwrap();

        // Rate limit
        assert!(config.production.rate_limit.enabled);
        assert_eq!(config.production.rate_limit.requests_per_second, 50.0);
        assert_eq!(config.production.rate_limit.burst_size, 100);

        // Circuit breaker
        assert!(config.production.circuit_breaker.enabled);
        assert_eq!(config.production.circuit_breaker.failure_threshold, 3);
        assert_eq!(
            config.production.circuit_breaker.open_duration,
            Duration::from_secs(60)
        );
        assert_eq!(config.production.circuit_breaker.success_threshold, 2);

        // Health
        assert!(config.production.health.enabled);
        assert_eq!(config.production.health.liveness_path, "/health");
        assert_eq!(config.production.health.readiness_path, "/ready");
        assert_eq!(config.production.health.metrics_path, "/prom");

        // Connection limits
        assert_eq!(
            config.production.connection_limits.max_total_connections,
            500
        );
        assert_eq!(
            config.production.connection_limits.max_connections_per_host,
            50
        );
        assert_eq!(
            config.production.connection_limits.idle_timeout,
            Duration::from_secs(120)
        );
        assert_eq!(
            config.production.connection_limits.connect_timeout,
            Duration::from_secs(5)
        );
        assert_eq!(
            config.production.connection_limits.request_timeout,
            Duration::from_secs(600)
        );
        assert_eq!(
            config.production.connection_limits.tls_timeout,
            Duration::from_secs(15)
        );

        // Fail-open
        assert!(!config.production.fail_open.enabled);
        assert_eq!(
            config.production.fail_open.enforcement_timeout,
            Duration::from_millis(750)
        );
        assert!(!config.production.fail_open.policy_fail_open);
        assert!(config.production.fail_open.budget_fail_open);
    }

    #[test]
    fn test_parse_forward_proxy_tls_yaml() {
        let yaml = r#"
forward_proxy:
  tls:
    learned_passthrough:
      enabled: true
      state_path: "/tmp/learned-passthrough.json"
      max_age: "5d"
      failure_threshold: 4
      failure_window: "2m"
"#;

        let config: SothConfig = serde_yaml::from_str(yaml).unwrap();
        let learned = &config.forward_proxy.tls.learned_passthrough;
        assert!(learned.enabled);
        assert_eq!(
            learned.state_path,
            PathBuf::from("/tmp/learned-passthrough.json")
        );
        assert_eq!(learned.max_age, Duration::from_secs(5 * 24 * 60 * 60));
        assert_eq!(learned.failure_threshold, 4);
        assert_eq!(learned.failure_window, Duration::from_secs(120));
    }

    #[test]
    fn test_localhost_bypass() {
        use super::HostAction;
        let filter = HostFilterConfig::default();

        // Localhost and local addresses should ALWAYS tunnel (never intercept or block)
        let local_addresses = vec![
            "localhost",
            "127.0.0.1",
            "::1",
            "myapp.local",
            "printer.localhost",
            "192.168.1.1",
            "192.168.0.100",
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
        ];

        for addr in local_addresses {
            assert_eq!(
                filter.action_for_host(addr),
                HostAction::Tunnel,
                "Expected {addr} to always tunnel (bypass proxy)"
            );
        }

        // Even if localhost is in the block list, it should still tunnel
        let filter_with_block = HostFilterConfig {
            mode: HostFilterMode::Selective,
            ai_inference: vec![],
            mcp: vec![],
            agent_apps: vec![],
            domain_files: HostDomainFilesConfig::default(),
            block: vec!["localhost".to_string(), "127.0.0.1".to_string()],
        };

        assert_eq!(
            filter_with_block.action_for_host("localhost"),
            HostAction::Tunnel,
            "localhost should bypass even if in block list"
        );
        assert_eq!(
            filter_with_block.action_for_host("127.0.0.1"),
            HostAction::Tunnel,
            "127.0.0.1 should bypass even if in block list"
        );
    }
}
