//! Configuration types for SOTH
//!
//! Defines the complete configuration structure for the SOTH edge proxy.

use serde::{Deserialize, Serialize};
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

    /// Policy engine settings
    #[serde(default)]
    pub policy: PolicyConfig,

    /// Observability/audit settings
    #[serde(default)]
    pub observe: ObserveConfig,

    /// Budget tracking settings
    #[serde(default)]
    pub budget: BudgetConfig,

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
            policy: PolicyConfig::default(),
            observe: ObserveConfig::default(),
            budget: BudgetConfig::default(),
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
            log_requests: true,
            log_responses: true,
            tamper_proof: false,
            storage: StorageConfig::default(),
            buffer_size: default_buffer_size(),
            flush_interval: default_flush_interval(),
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

    /// Retention in days (0 = forever)
    #[serde(default)]
    pub retention_days: u32,
}

fn default_storage_backend() -> String {
    "sqlite".to_string()
}

fn default_storage_path() -> PathBuf {
    PathBuf::from("./logs")
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: default_storage_backend(),
            path: default_storage_path(),
            retention_days: 0,
        }
    }
}

/// Budget configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
    pub db_path: Option<PathBuf>,
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

/// Forward proxy configuration (HTTP/HTTPS interception)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardProxyConfig {
    /// Whether the forward proxy is enabled
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

    /// Request timeout for AI providers (streaming can be long)
    #[serde(default = "default_ai_timeout", with = "humantime_serde")]
    pub request_timeout: Duration,
}

fn default_forward_proxy_port() -> u16 {
    8080
}

fn default_ai_timeout() -> Duration {
    Duration::from_secs(300) // 5 minutes for long AI responses
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
            request_timeout: default_ai_timeout(),
        }
    }
}

impl ForwardProxyConfig {
    /// Get the socket address for the proxy
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.address, self.port)
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

    /// Blocked hosts - these are rejected with 403
    #[serde(default)]
    pub block: Vec<String>,
}

/// Host filtering mode for forward proxy interception
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HostFilterMode {
    /// Intercept configured hosts only; blind tunnel everything else.
    #[default]
    Selective,
    /// Intercept all non-local hosts (useful for discovery).
    Discovery,
}

impl std::fmt::Display for HostFilterMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Selective => write!(f, "selective"),
            Self::Discovery => write!(f, "discovery"),
        }
    }
}

fn default_ai_inference_hosts() -> Vec<String> {
    dedupe_hosts(vec![
        // ===== OpenAI / ChatGPT =====
        "api.openai.com".to_string(),
        "*.openai.azure.com".to_string(), // Azure OpenAI
        "chatgpt.com".to_string(),        // ChatGPT web app
        "*.chatgpt.com".to_string(),      // ChatGPT WebSocket (ws.chatgpt.com)
        // ===== Anthropic =====
        "api.anthropic.com".to_string(),
        "*.anthropic.com".to_string(), // Claude Desktop uses a-api, statsig, s-cdn subdomains
        "claude.ai".to_string(),       // Claude Desktop app
        "*.claude.ai".to_string(),     // Claude Desktop WebSocket connections
        // ===== Google =====
        "generativelanguage.googleapis.com".to_string(), // Gemini API
        "aiplatform.googleapis.com".to_string(),         // Vertex AI
        "*-aiplatform.googleapis.com".to_string(),       // Regional
        "*.aiplatform.googleapis.com".to_string(),
        // ===== AWS Bedrock =====
        "bedrock.*.amazonaws.com".to_string(),
        "bedrock-runtime.*.amazonaws.com".to_string(),
        // ===== Microsoft/GitHub =====
        "api.githubcopilot.com".to_string(),
        "*.githubcopilot.com".to_string(),
        "copilot-proxy.githubusercontent.com".to_string(),
        "*.ingest.monitor.azure.com".to_string(), // Azure AI telemetry
        // ===== Mistral =====
        "api.mistral.ai".to_string(),
        "*.mistral.ai".to_string(),
        // ===== Cohere =====
        "api.cohere.ai".to_string(),
        "api.cohere.com".to_string(),
        "*.cohere.ai".to_string(),
        // ===== xAI (Grok) =====
        "api.x.ai".to_string(),
        "*.x.ai".to_string(),
        // ===== Groq =====
        "api.groq.com".to_string(),
        "*.groq.com".to_string(),
        // ===== Together AI =====
        "api.together.xyz".to_string(),
        "*.together.xyz".to_string(),
        // ===== Perplexity =====
        "api.perplexity.ai".to_string(),
        "*.perplexity.ai".to_string(),
        // ===== Replicate =====
        "api.replicate.com".to_string(),
        "*.replicate.delivery".to_string(), // Model delivery
        // ===== Hugging Face =====
        "*.huggingface.co".to_string(),
        "*.hf.co".to_string(), // Short domain
        // ===== Fireworks AI =====
        "api.fireworks.ai".to_string(),
        "*.fireworks.ai".to_string(),
        // ===== DeepInfra =====
        "api.deepinfra.com".to_string(),
        "*.deepinfra.com".to_string(),
        // ===== AI21 Labs =====
        "api.ai21.com".to_string(),
        "*.ai21.com".to_string(),
        // ===== Stability AI =====
        "api.stability.ai".to_string(),
        "*.stability.ai".to_string(),
        // ===== OpenRouter =====
        "openrouter.ai".to_string(),
        "*.openrouter.ai".to_string(),
        // ===== Anyscale =====
        "*.anyscale.com".to_string(),
        // ===== Voyage AI (embeddings) =====
        "api.voyageai.com".to_string(),
        // ===== Nvidia =====
        "api.nvcf.nvidia.com".to_string(),
        "integrate.api.nvidia.com".to_string(),
        "*.ngc.nvidia.com".to_string(), // NGC containers
        // ===== IBM watsonx =====
        "*.watsonx.ai".to_string(),
        "*.ml.cloud.ibm.com".to_string(),
        // ===== Databricks =====
        "*.databricks.com".to_string(),
        "*.azuredatabricks.net".to_string(),
        "*.cloud.databricks.com".to_string(),
        // ===== Snowflake Cortex =====
        "*.snowflakecomputing.com".to_string(),
        // ===== LangChain / LangSmith =====
        "*.langchain.com".to_string(),
        "*.langsmith.com".to_string(),
        // ===== Writer =====
        "api.writer.com".to_string(),
        "*.writer.com".to_string(),
        // ===== Reka =====
        "api.reka.ai".to_string(),
        // ===== Code Completion Tools =====
        "api2.cursor.sh".to_string(),
        "api3.cursor.sh".to_string(),
        "*.cursor.sh".to_string(),
        "api.vercel.ai".to_string(),
        "*.tabnine.com".to_string(),
        "cloud.zed.dev".to_string(),
        "*.zed.dev".to_string(),
        "*.codeium.com".to_string(),
        "api.jetbrains.ai".to_string(),
        "*.jetbrains.ai".to_string(),
        "codewhisperer.*.amazonaws.com".to_string(),
        "*.sourcegraph.com".to_string(), // Cody
        // ===== Inference Platforms =====
        "*.modal.com".to_string(),
        "*.lepton.ai".to_string(),
        "*.baseten.co".to_string(),
        "*.banana.dev".to_string(),
        "*.runpod.io".to_string(),
        "*.lambdalabs.com".to_string(),
        "*.cerebras.ai".to_string(),
        "*.sambanova.ai".to_string(),
        "*.octo.ai".to_string(),
        "*.octoml.ai".to_string(),
        // ===== Embedding Providers =====
        "api.jina.ai".to_string(),
        "*.jina.ai".to_string(),
        "api.mixedbread.ai".to_string(),
        // ===== Speech/Audio AI =====
        "api.elevenlabs.io".to_string(),
        "*.elevenlabs.io".to_string(),
        "api.assemblyai.com".to_string(),
        "*.assemblyai.com".to_string(),
        "api.deepgram.com".to_string(),
        "*.deepgram.com".to_string(),
        "api.openai.com".to_string(), // Whisper via OpenAI
        // ===== Image Generation =====
        "api.leonardo.ai".to_string(),
        "*.leonardo.ai".to_string(),
        "api.getimg.ai".to_string(),
        "*.clipdrop.co".to_string(),
        "api.ideogram.ai".to_string(),
        "api.black-forest-labs.ai".to_string(), // FLUX
        // ===== Vector DBs =====
        "*.pinecone.io".to_string(),
        "*.weaviate.cloud".to_string(),
        "*.qdrant.io".to_string(),
        "*.qdrant.cloud".to_string(),
        "*.milvus.io".to_string(),
        "*.zilliz.com".to_string(), // Managed Milvus
        "*.chroma.com".to_string(),
        "*.turbopuffer.com".to_string(),
        // ===== AI Agents / Orchestration =====
        "api.e2b.dev".to_string(), // Code execution
        "*.e2b.dev".to_string(),
        "*.relevanceai.com".to_string(),
        "*.dust.tt".to_string(),
        // ===== Enterprise AI =====
        "*.scale.com".to_string(), // Scale AI
        "*.enterprisedb.ai".to_string(),
        "*.vectara.io".to_string(),
        "*.forethought.ai".to_string(),
        // ===== China AI Providers =====
        "api.moonshot.cn".to_string(), // Moonshot (Kimi)
        "*.moonshot.cn".to_string(),
        "aip.baidubce.com".to_string(), // Baidu ERNIE
        "*.baidubce.com".to_string(),
        "dashscope.aliyuncs.com".to_string(), // Alibaba Qwen
        "*.dashscope.aliyuncs.com".to_string(),
        "open.bigmodel.cn".to_string(), // Zhipu (GLM)
        "*.bigmodel.cn".to_string(),
        "api.minimax.chat".to_string(),  // MiniMax
        "*.sensecore.cn".to_string(),    // SenseTime
        "*.baichuan-ai.com".to_string(), // Baichuan
        "*.01.ai".to_string(),           // Yi (01.AI)
        "*.deepseek.com".to_string(),    // DeepSeek
    ])
}

fn default_mcp_service_hosts() -> Vec<String> {
    vec![
        // ===== Source Control / Code Hosting =====
        "api.github.com".to_string(),
        "github.com".to_string(),
        "uploads.github.com".to_string(),
        "raw.githubusercontent.com".to_string(),
        "objects.githubusercontent.com".to_string(),
        "codeload.github.com".to_string(),
        "*.githubusercontent.com".to_string(),
        "api.gitlab.com".to_string(),
        "gitlab.com".to_string(),
        "*.gitlab.com".to_string(),
        "api.bitbucket.org".to_string(),
        "bitbucket.org".to_string(),
        "api.atlassian.com".to_string(),
        "*.atlassian.net".to_string(),
        "api.azure.dev".to_string(),
        "dev.azure.com".to_string(),
        "*.visualstudio.com".to_string(),
        // ===== Project / Knowledge Tools =====
        "api.linear.app".to_string(),
        "linear.app".to_string(),
        "*.linear.app".to_string(),
        "api.notion.com".to_string(),
        "www.notion.so".to_string(),
        "*.notion.so".to_string(),
        "api.asana.com".to_string(),
        "app.asana.com".to_string(),
        "*.asana.com".to_string(),
        "api.clickup.com".to_string(),
        "app.clickup.com".to_string(),
        "*.clickup.com".to_string(),
        "api.monday.com".to_string(),
        "*.monday.com".to_string(),
        "api.airtable.com".to_string(),
        "airtable.com".to_string(),
        "*.airtable.com".to_string(),
        "api.trello.com".to_string(),
        "trello.com".to_string(),
        "*.trello.com".to_string(),
        "api.todoist.com".to_string(),
        "todoist.com".to_string(),
        "*.todoist.com".to_string(),
        "api.coda.io".to_string(),
        "coda.io".to_string(),
        "*.coda.io".to_string(),
        // ===== Chat / Collaboration =====
        "slack.com".to_string(),
        "api.slack.com".to_string(),
        "*.slack.com".to_string(),
        "hooks.slack.com".to_string(),
        "discord.com".to_string(),
        "*.discord.com".to_string(),
        "api.twilio.com".to_string(),
        "*.twilio.com".to_string(),
        // ===== Google Workspace =====
        "www.googleapis.com".to_string(),
        "drive.googleapis.com".to_string(),
        "docs.googleapis.com".to_string(),
        "sheets.googleapis.com".to_string(),
        "calendar.googleapis.com".to_string(),
        "gmail.googleapis.com".to_string(),
        "people.googleapis.com".to_string(),
        "admin.googleapis.com".to_string(),
        "script.googleapis.com".to_string(),
        "storage.googleapis.com".to_string(),
        // ===== Microsoft 365 =====
        "graph.microsoft.com".to_string(),
        "login.microsoftonline.com".to_string(),
        "outlook.office.com".to_string(),
        "*.sharepoint.com".to_string(),
        "*.office.com".to_string(),
        "*.office365.com".to_string(),
        // ===== File Storage / Docs =====
        "api.dropboxapi.com".to_string(),
        "content.dropboxapi.com".to_string(),
        "www.dropbox.com".to_string(),
        "api.box.com".to_string(),
        "upload.box.com".to_string(),
        "*.box.com".to_string(),
        "api.figma.com".to_string(),
        "*.figma.com".to_string(),
        "api.canva.com".to_string(),
        "*.canva.com".to_string(),
        // ===== Payments / CRM / Support =====
        "api.stripe.com".to_string(),
        "dashboard.stripe.com".to_string(),
        "*.stripe.com".to_string(),
        "api.hubapi.com".to_string(),
        "app.hubspot.com".to_string(),
        "*.hubspot.com".to_string(),
        "login.salesforce.com".to_string(),
        "*.salesforce.com".to_string(),
        "api.zendesk.com".to_string(),
        "*.zendesk.com".to_string(),
        "api.shopify.com".to_string(),
        "partners.shopify.com".to_string(),
        "*.myshopify.com".to_string(),
        "*.shopify.com".to_string(),
        // ===== Cloud / Deploy / Infra =====
        "api.cloudflare.com".to_string(),
        "dash.cloudflare.com".to_string(),
        "*.workers.dev".to_string(),
        "api.vercel.com".to_string(),
        "vercel.com".to_string(),
        "*.vercel.app".to_string(),
        "api.netlify.com".to_string(),
        "app.netlify.com".to_string(),
        "*.netlify.app".to_string(),
        "api.render.com".to_string(),
        "dashboard.render.com".to_string(),
        "api.fly.io".to_string(),
        "fly.io".to_string(),
        "api.railway.app".to_string(),
        "railway.app".to_string(),
        "api.heroku.com".to_string(),
        "*.herokuapp.com".to_string(),
        // ===== Data / Observability =====
        "api.supabase.com".to_string(),
        "*.supabase.co".to_string(),
        "*.supabase.com".to_string(),
        "api.planetscale.com".to_string(),
        "*.planetscale.com".to_string(),
        "api.neon.tech".to_string(),
        "console.neon.tech".to_string(),
        "*.neon.tech".to_string(),
        "cloud.mongodb.com".to_string(),
        "*.mongodb.net".to_string(),
        "api.segment.io".to_string(),
        "app.segment.com".to_string(),
        "*.segment.io".to_string(),
        "api.datadoghq.com".to_string(),
        "app.datadoghq.com".to_string(),
        "*.datadoghq.com".to_string(),
        "api.newrelic.com".to_string(),
        "one.newrelic.com".to_string(),
        "*.newrelic.com".to_string(),
        "api.sentry.io".to_string(),
        "sentry.io".to_string(),
        "*.sentry.io".to_string(),
        // ===== MCP Middleware / Automation =====
        "api.pipedream.com".to_string(),
        "*.pipedream.net".to_string(),
        "api.composio.dev".to_string(),
        "*.composio.dev".to_string(),
        "api.browserbase.com".to_string(),
        "*.browserbase.com".to_string(),
        "api.firecrawl.dev".to_string(),
        "*.firecrawl.dev".to_string(),
        "api.scrapfly.io".to_string(),
        "*.scrapfly.io".to_string(),
        "api.zyte.com".to_string(),
        "*.zyte.com".to_string(),
        "api.resend.com".to_string(),
        "resend.com".to_string(),
        "api.postmarkapp.com".to_string(),
        "*.postmarkapp.com".to_string(),
        "api.mailgun.net".to_string(),
        "*.mailgun.net".to_string(),
        "api.sendgrid.com".to_string(),
        "*.sendgrid.com".to_string(),
        "api.n8n.io".to_string(),
        "n8n.io".to_string(),
        "*.n8n.cloud".to_string(),
        "api.zapier.com".to_string(),
        "zapier.com".to_string(),
        "*.zapier.com".to_string(),
        "api.make.com".to_string(),
        "www.make.com".to_string(),
        "*.integromat.com".to_string(),
        "api.retool.com".to_string(),
        "retool.com".to_string(),
        "*.retool.com".to_string(),
        // ===== Identity / Auth Backends Common in MCP Connectors =====
        "api.okta.com".to_string(),
        "*.okta.com".to_string(),
        "api.auth0.com".to_string(),
        "*.auth0.com".to_string(),
    ]
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

    /// Number of unique host patterns that can trigger interception.
    pub fn intercept_domain_count(&self) -> usize {
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for host in &self.ai_inference {
            seen.insert(host.as_str());
        }
        for host in &self.mcp {
            seen.insert(host.as_str());
        }
        seen.len()
    }

    /// Check if a host should be intercepted (full MITM)
    pub fn should_intercept(&self, host: &str) -> bool {
        self.should_check_ai_inference(host) || self.should_check_mcp(host)
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
    fn test_forward_proxy_default() {
        let config = ForwardProxyConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.port, 8080);
        assert_eq!(config.address, "127.0.0.1");
        assert_eq!(config.socket_addr(), "127.0.0.1:8080");
    }

    #[test]
    fn test_host_filter_intercept_and_tunnel() {
        use super::HostAction;
        let filter = HostFilterConfig {
            mode: HostFilterMode::Selective,
            ai_inference: vec!["api.openai.com".to_string()],
            mcp: vec![],
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
            "myinstance.openai.azure.com",
            // Anthropic
            "api.anthropic.com",
            // Google
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
                "Expected {} to be intercepted",
                domain
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
                "Expected {} to NOT be intercepted",
                domain
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
    fn test_separate_ai_and_mcp_whitelists() {
        let filter = HostFilterConfig {
            mode: HostFilterMode::Selective,
            ai_inference: vec!["api.openai.com".to_string()],
            mcp: vec!["api.github.com".to_string()],
            block: vec![],
        };

        assert!(filter.should_check_ai_inference("api.openai.com"));
        assert!(!filter.should_check_mcp("api.openai.com"));

        assert!(filter.should_check_mcp("api.github.com"));
        assert!(!filter.should_check_ai_inference("api.github.com"));
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
    fn test_production_config_default() {
        let config = ProductionConfig::default();
        assert!(!config.rate_limit.enabled);
        assert!(config.circuit_breaker.enabled);
        assert!(config.health.enabled);
        assert_eq!(config.connection_limits.max_total_connections, 1000);
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
                "Expected {} to always tunnel (bypass proxy)",
                addr
            );
        }

        // Even if localhost is in the block list, it should still tunnel
        let filter_with_block = HostFilterConfig {
            mode: HostFilterMode::Selective,
            ai_inference: vec![],
            mcp: vec![],
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
