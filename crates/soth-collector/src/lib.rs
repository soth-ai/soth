use anyhow::Context;
use base64::Engine as _;
use chrono::{DateTime, TimeZone, Utc};
use rusqlite::{
    params, params_from_iter,
    types::{Value as SqlValue, ValueRef},
    Connection,
};
use serde::{Deserialize, Serialize};
use soth_core::api::{
    version::{API_VERSION, API_VERSION_HEADER},
    LocalSessionArtifact, LocalSessionsBatchRequest, LocalSessionsBatchResponse,
};
use soth_core::config::types::ExchangeConfig;
use soth_core::types::exchange::ExchangeSourceClass;
use soth_core::types::{AgentInfo, DetectionSource, EventSource, WrapDirection, WrapEvent};
use soth_core::EventLogger;
use soth_observe::PiiRedactor;
use soth_storage::open_sqlite_read_only;
use std::collections::{hash_map::DefaultHasher, BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, UNIX_EPOCH};
use tracing::{info, warn};

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_MAX_READ_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_LINE_BYTES: usize = 64 * 1024;
const DEFAULT_FRONTLOAD_MAX_CYCLES: usize = 24;
const DEFAULT_FRONTLOAD_MAX_READ_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_AUTO_DISCOVER_MAX_SOURCES: usize = 48;
const DEFAULT_LOCAL_SESSIONS_UPLOAD_PATH: &str = "/api/v1/ingest/local-sessions";
const DEFAULT_LOCAL_SESSIONS_UPLOAD_BATCH_SIZE: usize = 200;
const DEFAULT_LOCAL_SESSIONS_UPLOAD_TIMEOUT_SECS: u64 = 20;
const DEFAULT_LOCAL_SESSIONS_RATE_LIMIT_BACKOFF_SECS: u64 = 15;

#[derive(Debug)]
pub struct CollectorRuntime {
    pub shutdown_tx: tokio::sync::oneshot::Sender<()>,
    pub task: tokio::task::JoinHandle<()>,
}

#[derive(Debug, Clone)]
pub struct CollectorConfig {
    pub poll_interval: Duration,
    pub state_path: PathBuf,
    pub max_read_bytes_per_source: usize,
    pub max_line_bytes: usize,
    pub auto_discover_sources: bool,
    pub frontload_on_start: bool,
    pub frontload_force_first_run: bool,
    pub frontload_reset_offsets_on_start: bool,
    pub frontload_max_cycles: usize,
    pub frontload_max_read_bytes_per_source: usize,
    pub agent_name: String,
    pub event_source: EventSource,
    pub exchange: ExchangeConfig,
    pub direct_upload: Option<CollectorDirectUploadConfig>,
    pub sources: Vec<CollectorSource>,
    pub sqlite_sources: Vec<CollectorSqliteSource>,
}

#[derive(Debug, Clone)]
pub struct CollectorDirectUploadConfig {
    pub endpoint: String,
    pub api_key: String,
    pub upload_path: String,
    pub batch_size: usize,
    pub request_timeout: Duration,
    pub agent_instance_id: String,
    pub config_version: Option<String>,
    pub client_device_id: Option<String>,
}

#[derive(Clone)]
struct CollectorDirectUploader {
    cfg: CollectorDirectUploadConfig,
    client: reqwest::Client,
}

#[derive(Debug)]
struct CollectorUploadError {
    message: String,
    rate_limited: bool,
    retry_after_secs: Option<u64>,
}

impl std::fmt::Display for CollectorUploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CollectorUploadError {}

#[derive(Debug, Clone)]
pub struct CollectorSource {
    pub name: String,
    pub path: PathBuf,
    pub parser: CollectorParser,
    pub skip_patterns: Vec<String>,
    pub agent: Option<String>,
    pub server_name: Option<String>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct CollectorSqliteSource {
    pub name: String,
    pub db_path: PathBuf,
    pub server_name: Option<String>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub tags: BTreeMap<String, String>,
    pub queries: Vec<CollectorSqliteQuery>,
}

#[derive(Debug, Clone)]
pub struct CollectorSqliteQuery {
    pub file_type: String,
    pub sql: String,
    pub incremental_field: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorParser {
    JsonLines,
    TextLines,
}

impl CollectorParser {
    fn as_tag(self) -> &'static str {
        match self {
            Self::JsonLines => "jsonl",
            Self::TextLines => "text",
        }
    }
}

#[derive(Debug, Deserialize)]
struct EnvSqliteSource {
    name: String,
    db_path: String,
    #[serde(default)]
    server_name: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    tags: BTreeMap<String, String>,
    #[serde(default)]
    queries: Vec<EnvSqliteQuery>,
}

#[derive(Debug, Deserialize)]
struct EnvFileSource {
    #[serde(default)]
    name: Option<String>,
    path: String,
    #[serde(default)]
    parser: Option<String>,
    #[serde(default)]
    skip_patterns: Vec<String>,
    #[serde(default)]
    agent: Option<String>,
    #[serde(default)]
    server_name: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    tags: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct EnvSqliteQuery {
    file_type: String,
    sql: String,
    #[serde(default)]
    incremental_field: Option<String>,
}

impl CollectorConfig {
    pub fn from_env() -> Option<Self> {
        let enabled = std::env::var("SOTH_COLLECTOR_ENABLED")
            .ok()
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);
        if !enabled {
            return None;
        }

        let auto_discover_sources = parse_bool_env("SOTH_COLLECTOR_AUTO_DISCOVER").unwrap_or(true);
        let frontload_on_start =
            parse_bool_env("SOTH_COLLECTOR_FRONTLOAD_ON_START").unwrap_or(true);
        let frontload_force_first_run =
            parse_bool_env("SOTH_COLLECTOR_FRONTLOAD_FORCE_FIRST_RUN").unwrap_or(true);
        let frontload_reset_offsets_on_start =
            parse_bool_env("SOTH_COLLECTOR_FRONTLOAD_RESET_OFFSETS_ON_START").unwrap_or(false);

        let mut sources = parse_file_sources_from_env();

        let sqlite_sources = parse_sqlite_sources_from_env();
        if auto_discover_sources && sources.is_empty() && sqlite_sources.is_empty() {
            let discovered_sources = discover_default_sources(DEFAULT_AUTO_DISCOVER_MAX_SOURCES);
            if !discovered_sources.is_empty() {
                info!(
                    discovered = discovered_sources.len(),
                    "Collector auto-discovered local history sources"
                );
                sources = discovered_sources;
            }
        }

        if sources.is_empty() && sqlite_sources.is_empty() {
            warn!(
                "SOTH_COLLECTOR_ENABLED=true but both SOTH_COLLECTOR_SOURCES and SOTH_COLLECTOR_SQLITE_SOURCES are empty; collector disabled"
            );
            return None;
        }

        let poll_interval = std::env::var("SOTH_COLLECTOR_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_POLL_INTERVAL);
        let max_read_bytes_per_source = std::env::var("SOTH_COLLECTOR_MAX_READ_BYTES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_READ_BYTES)
            .max(8 * 1024);
        let max_line_bytes = std::env::var("SOTH_COLLECTOR_MAX_LINE_BYTES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_LINE_BYTES)
            .max(1024);
        let frontload_max_cycles = std::env::var("SOTH_COLLECTOR_FRONTLOAD_MAX_CYCLES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_FRONTLOAD_MAX_CYCLES)
            .max(1);
        let frontload_max_read_bytes_per_source =
            std::env::var("SOTH_COLLECTOR_FRONTLOAD_MAX_READ_BYTES")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(DEFAULT_FRONTLOAD_MAX_READ_BYTES)
                .max(max_read_bytes_per_source);
        let state_path = std::env::var("SOTH_COLLECTOR_STATE_PATH")
            .ok()
            .map(PathBuf::from)
            .map(|p| expand_home_path(&p))
            .unwrap_or_else(default_state_path);
        let agent_name = std::env::var("SOTH_COLLECTOR_AGENT")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "collector".to_string());
        let event_source = std::env::var("SOTH_COLLECTOR_EVENT_SOURCE")
            .ok()
            .and_then(|v| parse_event_source(&v))
            .unwrap_or(EventSource::AgentApp);
        let direct_upload = CollectorDirectUploadConfig::from_env();

        Some(Self {
            poll_interval,
            state_path,
            max_read_bytes_per_source,
            max_line_bytes,
            auto_discover_sources,
            frontload_on_start,
            frontload_force_first_run,
            frontload_reset_offsets_on_start,
            frontload_max_cycles,
            frontload_max_read_bytes_per_source,
            agent_name,
            event_source,
            exchange: ExchangeConfig::default(),
            direct_upload,
            sources,
            sqlite_sources,
        })
    }
}

impl CollectorDirectUploadConfig {
    fn from_env() -> Option<Self> {
        let enabled = parse_bool_env("SOTH_COLLECTOR_DIRECT_UPLOAD_ENABLED").unwrap_or(true);
        if !enabled {
            return None;
        }

        let endpoint = std::env::var("SOTH_COLLECTOR_CLOUD_ENDPOINT")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())?;
        let api_key = std::env::var("SOTH_COLLECTOR_CLOUD_API_KEY")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())?;
        let upload_path = std::env::var("SOTH_COLLECTOR_UPLOAD_PATH")
            .ok()
            .and_then(|value| normalize_upload_path_or_url(value.as_str()))
            .unwrap_or_else(|| DEFAULT_LOCAL_SESSIONS_UPLOAD_PATH.to_string());
        let batch_size = std::env::var("SOTH_COLLECTOR_UPLOAD_BATCH_SIZE")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(DEFAULT_LOCAL_SESSIONS_UPLOAD_BATCH_SIZE)
            .max(1);
        let timeout_secs = std::env::var("SOTH_COLLECTOR_UPLOAD_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_LOCAL_SESSIONS_UPLOAD_TIMEOUT_SECS)
            .max(1);
        let agent_instance_id = std::env::var("SOTH_COLLECTOR_AGENT_INSTANCE_ID")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(build_default_agent_instance_id);
        let config_version = std::env::var("SOTH_COLLECTOR_CONFIG_VERSION")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let client_device_id = std::env::var("SOTH_COLLECTOR_CLIENT_DEVICE_ID")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        Some(Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            api_key,
            upload_path,
            batch_size,
            request_timeout: Duration::from_secs(timeout_secs),
            agent_instance_id,
            config_version,
            client_device_id,
        })
    }
}

impl CollectorDirectUploader {
    fn new(cfg: CollectorDirectUploadConfig) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(cfg.request_timeout)
            .build()
            .context("failed building collector local-sessions HTTP client")?;
        Ok(Self { cfg, client })
    }

    async fn push_artifacts(
        &self,
        artifacts: Vec<LocalSessionArtifact>,
        mode: CollectorIngestMode,
    ) -> Result<(), CollectorUploadError> {
        if artifacts.is_empty() {
            return Ok(());
        }

        let url = compose_upload_url(self.cfg.endpoint.as_str(), self.cfg.upload_path.as_str());
        for chunk in artifacts.chunks(self.cfg.batch_size) {
            let request = LocalSessionsBatchRequest {
                agent_instance_id: self.cfg.agent_instance_id.clone(),
                config_version: self.cfg.config_version.clone(),
                client_device_id: self.cfg.client_device_id.clone(),
                ingest_mode: Some(mode.as_tag().to_string()),
                batch: chunk.to_vec(),
            };
            let response = self
                .client
                .post(url.as_str())
                .header(API_VERSION_HEADER, API_VERSION)
                .header("content-type", "application/json")
                .bearer_auth(self.cfg.api_key.as_str())
                .json(&request)
                .send()
                .await
                .map_err(|error| CollectorUploadError {
                    message: format!("collector local sessions upload failed for {url}: {error}"),
                    rate_limited: false,
                    retry_after_secs: None,
                })?;
            let status = response.status();
            if !status.is_success() {
                let retry_after_secs = parse_retry_after_secs(response.headers())
                    .or_else(|| status.as_u16().eq(&429).then_some(1));
                let body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unavailable>".to_string());
                let retry_after_secs =
                    retry_after_secs.or_else(|| parse_retry_after_secs_body(&body));
                let body = truncate_utf8(body.as_str(), 256);
                return Err(CollectorUploadError {
                    message: format!(
                        "collector local sessions upload returned status {} body={}",
                        status.as_u16(),
                        body
                    ),
                    rate_limited: status == reqwest::StatusCode::TOO_MANY_REQUESTS,
                    retry_after_secs,
                });
            }
            let decoded = response
                .json::<LocalSessionsBatchResponse>()
                .await
                .map_err(|error| CollectorUploadError {
                    message: format!("failed decoding local sessions upload response: {error}"),
                    rate_limited: false,
                    retry_after_secs: None,
                })?;
            if decoded.rejected > 0 {
                let mut duplicate_rejections = 0u64;
                let mut top_reason: Option<String> = None;
                let mut top_reason_count = 0u64;
                let mut reason_counts: HashMap<String, u64> = HashMap::new();
                for error in &decoded.errors {
                    let reason = error
                        .code
                        .as_deref()
                        .or(Some(error.reason.as_str()))
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .unwrap_or("unknown")
                        .to_ascii_lowercase();
                    let next = reason_counts
                        .get(reason.as_str())
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(1);
                    reason_counts.insert(reason.clone(), next);
                    if next > top_reason_count {
                        top_reason_count = next;
                        top_reason = Some(reason.clone());
                    }
                    if reason == "duplicate" {
                        duplicate_rejections = duplicate_rejections.saturating_add(1);
                    }
                }

                if duplicate_rejections == decoded.rejected {
                    info!(
                        accepted = decoded.accepted,
                        rejected = decoded.rejected,
                        "Collector local-sessions upload returned duplicate rows only"
                    );
                } else {
                    warn!(
                        accepted = decoded.accepted,
                        rejected = decoded.rejected,
                        duplicate_rejected = duplicate_rejections,
                        top_reason = top_reason.unwrap_or_else(|| "unknown".to_string()),
                        "Collector local-sessions upload returned rejected rows"
                    );
                }
            }
        }

        Ok(())
    }
}

fn normalize_upload_path_or_url(path: &str) -> Option<String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Some(trimmed.trim_end_matches('/').to_string());
    }
    let normalized = if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };
    let normalized = normalized.trim_end_matches('/').to_string();
    if normalized.is_empty() {
        Some("/".to_string())
    } else {
        Some(normalized)
    }
}

fn compose_upload_url(endpoint: &str, path_or_url: &str) -> String {
    if path_or_url.starts_with("http://") || path_or_url.starts_with("https://") {
        return path_or_url.to_string();
    }
    format!("{endpoint}{path_or_url}")
}

fn parse_retry_after_secs(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    let raw = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    raw.trim().parse::<u64>().ok()
}

fn parse_retry_after_secs_body(body: &str) -> Option<u64> {
    let value = serde_json::from_str::<serde_json::Value>(body).ok()?;
    value
        .get("retry_after_secs")
        .and_then(|value| value.as_u64())
}

fn build_default_agent_instance_id() -> String {
    let host = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "edge".to_string());
    format!(
        "collector-{}-{}-{}",
        host,
        std::process::id(),
        uuid::Uuid::new_v4()
    )
}

fn parse_sqlite_sources_from_env() -> Vec<CollectorSqliteSource> {
    let raw = match std::env::var("SOTH_COLLECTOR_SQLITE_SOURCES") {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    let parsed = match serde_json::from_str::<Vec<EnvSqliteSource>>(&raw) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                error = %error,
                "Invalid SOTH_COLLECTOR_SQLITE_SOURCES JSON; sqlite collection disabled"
            );
            return Vec::new();
        }
    };

    parsed
        .into_iter()
        .filter_map(|source| {
            let db_path = expand_home_path(Path::new(source.db_path.trim()));
            if source.name.trim().is_empty() || source.queries.is_empty() {
                return None;
            }
            let queries = source
                .queries
                .into_iter()
                .filter_map(|query| {
                    if query.file_type.trim().is_empty() || query.sql.trim().is_empty() {
                        return None;
                    }
                    Some(CollectorSqliteQuery {
                        file_type: query.file_type.trim().to_string(),
                        sql: query.sql,
                        incremental_field: query.incremental_field.and_then(|value| {
                            let trimmed = value.trim();
                            if trimmed.is_empty() {
                                None
                            } else {
                                Some(trimmed.to_string())
                            }
                        }),
                    })
                })
                .collect::<Vec<_>>();
            if queries.is_empty() {
                return None;
            }
            Some(CollectorSqliteSource {
                name: source.name.trim().to_string(),
                db_path,
                server_name: source.server_name.and_then(|value| {
                    let trimmed = value.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    }
                }),
                provider: source.provider.and_then(|value| {
                    let trimmed = value.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    }
                }),
                model: source.model.and_then(|value| {
                    let trimmed = value.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    }
                }),
                tags: source.tags,
                queries,
            })
        })
        .collect::<Vec<_>>()
}

fn parse_file_sources_from_env() -> Vec<CollectorSource> {
    let mut sources = parse_file_sources_json_from_env();
    if !sources.is_empty() {
        return sources;
    }

    let sources_raw = match std::env::var("SOTH_COLLECTOR_SOURCES") {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    for raw in sources_raw.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let path = expand_home_path(Path::new(raw));
        let name = default_source_name(&path);
        let parser = parser_for_path_and_hint(&path, None);
        sources.push(CollectorSource {
            name,
            path,
            parser,
            skip_patterns: Vec::new(),
            agent: None,
            server_name: None,
            provider: None,
            model: None,
            tags: BTreeMap::new(),
        });
    }
    sources
}

fn parse_file_sources_json_from_env() -> Vec<CollectorSource> {
    let raw = match std::env::var("SOTH_COLLECTOR_SOURCES_JSON") {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    let parsed = match serde_json::from_str::<Vec<EnvFileSource>>(&raw) {
        Ok(value) => value,
        Err(error) => {
            warn!(
                error = %error,
                "Invalid SOTH_COLLECTOR_SOURCES_JSON; falling back to path-based source parsing"
            );
            return Vec::new();
        }
    };

    parsed
        .into_iter()
        .filter_map(|source| {
            let raw_path = source.path.trim();
            if raw_path.is_empty() {
                return None;
            }
            let path = expand_home_path(Path::new(raw_path));
            let name = source
                .name
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| default_source_name(&path));
            let parser = parser_for_path_and_hint(&path, source.parser.as_deref());
            let skip_patterns = normalize_skip_patterns(source.skip_patterns);
            let agent = normalize_optional_text(source.agent.as_deref());
            let server_name = normalize_optional_text(source.server_name.as_deref());
            let provider = normalize_optional_text(source.provider.as_deref());
            let model = normalize_optional_text(source.model.as_deref());
            Some(CollectorSource {
                name,
                path,
                parser,
                skip_patterns,
                agent,
                server_name,
                provider,
                model,
                tags: source.tags,
            })
        })
        .collect()
}

fn parser_for_path_and_hint(path: &Path, parser_hint: Option<&str>) -> CollectorParser {
    if let Some(hint) = parser_hint {
        match hint.trim().to_ascii_lowercase().as_str() {
            "jsonl" | "ndjson" | "json_lines" | "jsonlines" => return CollectorParser::JsonLines,
            "text" | "txt" | "text_lines" | "lines" => return CollectorParser::TextLines,
            _ => {}
        }
    }

    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "jsonl" | "ndjson" => CollectorParser::JsonLines,
        _ => CollectorParser::TextLines,
    }
}

fn default_source_name(path: &Path) -> String {
    path.file_name()
        .and_then(|v| v.to_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("collector-source")
        .to_string()
}

fn normalize_skip_patterns(patterns: Vec<String>) -> Vec<String> {
    patterns
        .into_iter()
        .map(|pattern| pattern.trim().to_string())
        .filter(|pattern| !pattern.is_empty())
        .collect()
}

fn normalize_optional_text(value: Option<&str>) -> Option<String> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn parse_bool_env(key: &str) -> Option<bool> {
    std::env::var(key).ok().map(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

pub fn spawn_from_env(
    event_logger: EventLogger,
    global_tags: BTreeMap<String, String>,
    exchange: ExchangeConfig,
) -> Option<CollectorRuntime> {
    let mut config = CollectorConfig::from_env()?;
    config.exchange = exchange;
    Some(spawn_runtime(event_logger, global_tags, config))
}

pub fn spawn_runtime(
    event_logger: EventLogger,
    global_tags: BTreeMap<String, String>,
    config: CollectorConfig,
) -> CollectorRuntime {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let mut collector = CollectorAgent::new(config, global_tags);
    info!(
        file_sources = collector.config.sources.len(),
        sqlite_sources = collector.config.sqlite_sources.len(),
        auto_discover = collector.config.auto_discover_sources,
        frontload_on_start = collector.config.frontload_on_start,
        frontload_force_first_run = collector.config.frontload_force_first_run,
        frontload_reset_offsets_on_start = collector.config.frontload_reset_offsets_on_start,
        frontload_cycles = collector.config.frontload_max_cycles,
        direct_upload_enabled = collector.uploader.is_some(),
        poll_secs = collector.config.poll_interval.as_secs(),
        state_path = %collector.config.state_path.display(),
        "Local collector enabled"
    );

    let task = tokio::spawn(async move {
        if let Err(error) = collector.load_state() {
            warn!("Collector state load failed: {}", error);
        }

        let should_force_first_run_frontload = collector.config.frontload_on_start
            && collector.config.frontload_force_first_run
            && !collector.frontload_bootstrap_completed();
        if should_force_first_run_frontload {
            info!(
                bootstrap_path = %collector.frontload_bootstrap_path().display(),
                "Collector first-run frontload bootstrap active; resetting offsets"
            );
            collector.offsets = OffsetState::default();
            if let Err(error) = collector.save_state() {
                warn!("Collector state reset failed: {}", error);
            }
        } else if collector.config.frontload_on_start
            && collector.config.frontload_reset_offsets_on_start
        {
            collector.offsets = OffsetState::default();
            if let Err(error) = collector.save_state() {
                warn!("Collector state reset failed: {}", error);
            }
        }
        let should_run_frontload = collector.config.frontload_on_start
            && (!collector.config.frontload_force_first_run || should_force_first_run_frontload);
        if should_run_frontload {
            let frontload_result = collector.run_frontload(&event_logger).await;
            if should_force_first_run_frontload {
                // Mark bootstrap complete after first-run attempt so we never loop in perpetual frontload.
                if let Err(error) = collector.mark_frontload_bootstrap_complete() {
                    warn!("Collector frontload bootstrap mark failed: {}", error);
                }
            }
            if let Err(error) = frontload_result {
                warn!("Collector frontload failed: {}", error);
            }
        }
        let mut interval = tokio::time::interval(collector.config.poll_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    if let Err(error) = collector.save_state() {
                        warn!("Collector state save failed during shutdown: {}", error);
                    }
                    break;
                }
                _ = interval.tick() => {
                    if let Err(error) = collector.poll_once(&event_logger).await {
                        warn!("Collector poll failed: {}", error);
                    }
                }
            }
        }
    });

    CollectorRuntime { shutdown_tx, task }
}

struct CollectorAgent {
    config: CollectorConfig,
    global_tags: BTreeMap<String, String>,
    offsets: OffsetState,
    session_id: String,
    redactor: PiiRedactor,
    uploader: Option<CollectorDirectUploader>,
    upload_backoff_until: Option<Instant>,
}

#[derive(Debug, Clone, Copy)]
enum CollectorIngestMode {
    Incremental,
    Frontload,
}

impl CollectorIngestMode {
    fn as_tag(self) -> &'static str {
        match self {
            Self::Incremental => "incremental",
            Self::Frontload => "frontload",
        }
    }
}

#[derive(Debug, Default)]
struct PollStats {
    events_emitted: usize,
    state_changed: bool,
}

impl CollectorAgent {
    fn new(config: CollectorConfig, global_tags: BTreeMap<String, String>) -> Self {
        let uploader =
            config
                .direct_upload
                .clone()
                .and_then(|cfg| match CollectorDirectUploader::new(cfg) {
                    Ok(uploader) => Some(uploader),
                    Err(error) => {
                        warn!(
                            error = %error,
                            "Collector direct upload disabled: failed initializing uploader"
                        );
                        None
                    }
                });
        Self {
            config,
            global_tags,
            offsets: OffsetState::default(),
            session_id: uuid::Uuid::new_v4().to_string(),
            redactor: PiiRedactor::new().with_preserve_length(false),
            uploader,
            upload_backoff_until: None,
        }
    }

    fn load_state(&mut self) -> anyhow::Result<()> {
        self.offsets = OffsetState::load(&self.config.state_path)?;
        Ok(())
    }

    fn save_state(&self) -> anyhow::Result<()> {
        self.offsets.save(&self.config.state_path)
    }

    fn frontload_bootstrap_path(&self) -> PathBuf {
        if let Some(parent) = self.config.state_path.parent() {
            return parent.join("collector_frontload_bootstrap.json");
        }
        PathBuf::from(".soth/runtime/collector_frontload_bootstrap.json")
    }

    fn frontload_bootstrap_completed(&self) -> bool {
        let path = self.frontload_bootstrap_path();
        FrontloadBootstrapState::load(&path)
            .map(|state| state.completed)
            .unwrap_or(false)
    }

    fn mark_frontload_bootstrap_complete(&self) -> anyhow::Result<()> {
        let path = self.frontload_bootstrap_path();
        let state = FrontloadBootstrapState {
            completed: true,
            completed_at_unix_secs: Some(
                std::time::SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            ),
        };
        state.save(&path)
    }

    async fn run_frontload(&mut self, logger: &EventLogger) -> anyhow::Result<()> {
        let mut total_events = 0usize;
        let mut cycles = 0usize;
        for _ in 0..self.config.frontload_max_cycles {
            let stats = self
                .poll_once_with_limits(
                    logger,
                    self.config.frontload_max_read_bytes_per_source,
                    CollectorIngestMode::Frontload,
                )
                .await?;
            cycles += 1;
            total_events += stats.events_emitted;
            if !stats.state_changed {
                break;
            }
        }
        if cycles > 0 {
            info!(
                cycles,
                events = total_events,
                max_cycles = self.config.frontload_max_cycles,
                read_bytes_per_source = self.config.frontload_max_read_bytes_per_source,
                "Collector frontload completed"
            );
        }
        Ok(())
    }

    async fn poll_once(&mut self, logger: &EventLogger) -> anyhow::Result<()> {
        self.poll_once_with_limits(
            logger,
            self.config.max_read_bytes_per_source,
            CollectorIngestMode::Incremental,
        )
        .await?;
        Ok(())
    }

    async fn poll_once_with_limits(
        &mut self,
        logger: &EventLogger,
        max_read_bytes_per_source: usize,
        mode: CollectorIngestMode,
    ) -> anyhow::Result<PollStats> {
        if let Some(until) = self.upload_backoff_until {
            let now = Instant::now();
            if now < until {
                let remaining = until.saturating_duration_since(now).as_secs().max(1);
                if matches!(mode, CollectorIngestMode::Frontload) {
                    return Err(anyhow::anyhow!(
                        "collector local sessions upload paused by rate limit ({}s remaining)",
                        remaining
                    ));
                }
                return Ok(PollStats {
                    events_emitted: 0,
                    state_changed: false,
                });
            }
            self.upload_backoff_until = None;
        }

        let mut state_changed = false;
        let mut events_emitted = 0usize;
        let mut rate_limited_backoff: Option<u64> = None;

        'file_sources: for source in resolve_collector_sources_for_scan(&self.config.sources) {
            let key = source.path.to_string_lossy().to_string();
            let prior_state = self.offsets.files.get(&key).cloned().unwrap_or_default();
            let outcome = collect_source_events(
                &source,
                &prior_state,
                max_read_bytes_per_source,
                self.config.max_line_bytes,
            )?;
            let mut source_upload_failed = false;
            if let Some(uploader) = self.uploader.as_ref() {
                let mut artifacts = Vec::new();
                for source_line in outcome.lines {
                    if let Some(artifact) =
                        self.build_local_session_artifact(&source, source_line, mode)
                    {
                        events_emitted += 1;
                        artifacts.push(artifact);
                    }
                }
                if !artifacts.is_empty() {
                    if let Err(error) = uploader.push_artifacts(artifacts, mode).await {
                        if error.rate_limited {
                            let backoff_secs = error
                                .retry_after_secs
                                .unwrap_or(DEFAULT_LOCAL_SESSIONS_RATE_LIMIT_BACKOFF_SECS)
                                .max(1)
                                .min(300);
                            self.upload_backoff_until =
                                Some(Instant::now() + Duration::from_secs(backoff_secs));
                            rate_limited_backoff = Some(backoff_secs);
                            warn!(
                                mode = mode.as_tag(),
                                backoff_secs,
                                "Collector local sessions upload rate-limited; pausing uploads"
                            );
                            break 'file_sources;
                        }
                        source_upload_failed = true;
                        warn!(
                            source = %source.name,
                            path = %source.path.display(),
                            mode = mode.as_tag(),
                            error = %error.message,
                            "Collector local artifact upload failed; offsets unchanged for retry"
                        );
                    }
                }
            } else {
                for source_line in outcome.lines {
                    if let Some(event) = self.build_event(&source, source_line, mode) {
                        events_emitted += 1;
                        logger.log(&event);
                        if self.config.exchange.enabled {
                            let source_class = if source.agent.is_some() {
                                ExchangeSourceClass::AgentApp
                            } else {
                                ExchangeSourceClass::Collector
                            };
                            if let Err(error) = logger.enqueue_exchange_from_wrap_event(
                                &event,
                                &self.config.exchange,
                                Some(source_class),
                            ) {
                                warn!(
                                    event_id = %event.id,
                                    error = %error,
                                    "Collector failed to enqueue exchange payload"
                                );
                            }
                        }
                    }
                }
            }
            if !source_upload_failed && outcome.next_state != prior_state {
                self.offsets.files.insert(key, outcome.next_state);
                state_changed = true;
            }
        }

        if rate_limited_backoff.is_none() {
            'sqlite_sources: for source in &self.config.sqlite_sources {
                let key = source.db_path.to_string_lossy().to_string();
                let prior_state = self.offsets.sqlite.get(&key).cloned().unwrap_or_default();
                let outcome =
                    collect_sqlite_events(source, &prior_state, self.config.max_line_bytes)?;
                let mut source_upload_failed = false;
                if let Some(uploader) = self.uploader.as_ref() {
                    let mut artifacts = Vec::new();
                    for source_line in outcome.lines {
                        if let Some(artifact) =
                            self.build_local_sqlite_artifact(source, source_line, mode)
                        {
                            events_emitted += 1;
                            artifacts.push(artifact);
                        }
                    }
                    if !artifacts.is_empty() {
                        if let Err(error) = uploader.push_artifacts(artifacts, mode).await {
                            if error.rate_limited {
                                let backoff_secs = error
                                    .retry_after_secs
                                    .unwrap_or(DEFAULT_LOCAL_SESSIONS_RATE_LIMIT_BACKOFF_SECS)
                                    .max(1)
                                    .min(300);
                                self.upload_backoff_until =
                                    Some(Instant::now() + Duration::from_secs(backoff_secs));
                                rate_limited_backoff = Some(backoff_secs);
                                warn!(
                                    mode = mode.as_tag(),
                                    backoff_secs,
                                    "Collector local sessions upload rate-limited; pausing uploads"
                                );
                                break 'sqlite_sources;
                            }
                            source_upload_failed = true;
                            warn!(
                                source = %source.name,
                                db_path = %source.db_path.display(),
                                mode = mode.as_tag(),
                                error = %error.message,
                                "Collector sqlite artifact upload failed; offsets unchanged for retry"
                            );
                        }
                    }
                } else {
                    for source_line in outcome.lines {
                        if let Some(event) = self.build_sqlite_event(source, source_line, mode) {
                            events_emitted += 1;
                            logger.log(&event);
                            if self.config.exchange.enabled {
                                if let Err(error) = logger.enqueue_exchange_from_wrap_event(
                                    &event,
                                    &self.config.exchange,
                                    Some(ExchangeSourceClass::Collector),
                                ) {
                                    warn!(
                                        event_id = %event.id,
                                        error = %error,
                                        "Collector failed to enqueue exchange payload"
                                    );
                                }
                            }
                        }
                    }
                }
                if !source_upload_failed && outcome.next_state != prior_state {
                    self.offsets.sqlite.insert(key, outcome.next_state);
                    state_changed = true;
                }
            }
        }

        if state_changed {
            self.save_state()?;
        }

        if let Some(backoff_secs) = rate_limited_backoff {
            if matches!(mode, CollectorIngestMode::Frontload) {
                return Err(anyhow::anyhow!(
                    "collector local sessions upload rate-limited; backoff={}s",
                    backoff_secs
                ));
            }
        }

        Ok(PollStats {
            events_emitted,
            state_changed,
        })
    }

    fn build_local_session_artifact(
        &self,
        source: &CollectorSource,
        line: SourceLine,
        mode: CollectorIngestMode,
    ) -> Option<LocalSessionArtifact> {
        let trimmed = line.content.trim();
        if trimmed.is_empty() {
            return None;
        }

        let parsed = parse_line(source.parser, trimmed);
        let observed_at = parsed.occurred_at.unwrap_or_else(Utc::now);
        let local_type = normalize_local_type(
            source
                .agent
                .as_deref()
                .or(parsed.agent.as_deref())
                .unwrap_or(source.name.as_str()),
        );
        let content_type = if matches!(source.parser, CollectorParser::JsonLines) {
            Some("application/json".to_string())
        } else {
            Some("text/plain".to_string())
        };
        let body_inline = parsed.content;
        let body_bytes = Some(body_inline.len() as u64);
        let mut tags = HashMap::new();
        for (key, value) in &self.global_tags {
            tags.insert(key.clone(), value.clone());
        }
        for (key, value) in &source.tags {
            tags.insert(key.clone(), value.clone());
        }
        if let Some(agent) = parsed.agent.as_ref().or(source.agent.as_ref()) {
            tags.entry("collector.agent".to_string())
                .or_insert_with(|| agent.clone());
        }
        tags.entry("collector.source".to_string())
            .or_insert_with(|| source.name.clone());
        tags.entry("collector.parser".to_string())
            .or_insert_with(|| source.parser.as_tag().to_string());
        tags.insert(
            "collector.ingest_mode".to_string(),
            mode.as_tag().to_string(),
        );
        tags.insert("collector.offset".to_string(), line.end_offset.to_string());
        if matches!(mode, CollectorIngestMode::Frontload) {
            tags.insert("collector.frontload".to_string(), "true".to_string());
        }
        if let Some(project) = parsed.project.as_ref() {
            tags.insert("collector.project".to_string(), project.clone());
        }
        if let Some(method) = parsed.method.as_ref() {
            tags.insert("collector.method".to_string(), method.clone());
        }
        if let Some(tool_name) = parsed.tool_name.as_ref() {
            tags.insert("collector.tool".to_string(), tool_name.clone());
        }

        let metadata = serde_json::json!({
            "collector": {
                "source": source.name,
                "offset": line.end_offset,
                "parser": source.parser.as_tag(),
                "ingest_mode": mode.as_tag(),
                "source_path": source.path.to_string_lossy().to_string(),
            },
            "parsed": {
                "direction": parsed.direction.map(direction_tag),
                "method": parsed.method,
                "tool_name": parsed.tool_name,
                "request": parsed.request,
                "response": parsed.response,
            },
        });

        Some(LocalSessionArtifact {
            artifact_id: build_local_artifact_id(
                source.path.to_string_lossy().as_ref(),
                local_type.as_str(),
                line.end_offset,
            ),
            observed_at: observed_at.to_rfc3339(),
            local_type,
            file_type: Some(source.parser.as_tag().to_string()),
            parser_hint: Some(source.parser.as_tag().to_string()),
            source_path: Some(source.path.to_string_lossy().to_string()),
            source_db_path: None,
            source_query: None,
            read_mode: Some(mode.as_tag().to_string()),
            content_type,
            body_inline: Some(body_inline),
            body_blob_key: None,
            body_sha256: None,
            body_bytes,
            session_id: parsed
                .session_id
                .or_else(|| Some(self.session_id.clone()))
                .filter(|value| !value.trim().is_empty()),
            provider: parsed.provider.or(source.provider.clone()),
            model: parsed.model.or(source.model.clone()),
            agent: parsed
                .agent
                .or(source.agent.clone())
                .or_else(|| Some(self.config.agent_name.clone())),
            tags: if tags.is_empty() { None } else { Some(tags) },
            metadata: Some(metadata),
        })
    }

    fn build_local_sqlite_artifact(
        &self,
        source: &CollectorSqliteSource,
        line: SqliteSourceLine,
        mode: CollectorIngestMode,
    ) -> Option<LocalSessionArtifact> {
        let trimmed = line.content.trim();
        if trimmed.is_empty() {
            return None;
        }

        let parsed = parse_line(CollectorParser::JsonLines, trimmed);
        let observed_at = parsed.occurred_at.unwrap_or_else(Utc::now);
        let local_type = normalize_local_type(
            parsed
                .agent
                .as_deref()
                .or(source.server_name.as_deref())
                .unwrap_or(source.name.as_str()),
        );
        let body_inline = parsed.content;
        let body_bytes = Some(body_inline.len() as u64);
        let mut tags = HashMap::new();
        for (key, value) in &self.global_tags {
            tags.insert(key.clone(), value.clone());
        }
        for (key, value) in &source.tags {
            tags.insert(key.clone(), value.clone());
        }
        tags.entry("collector.source".to_string())
            .or_insert_with(|| source.name.clone());
        tags.entry("collector.parser".to_string())
            .or_insert_with(|| CollectorParser::JsonLines.as_tag().to_string());
        tags.insert(
            "collector.ingest_mode".to_string(),
            mode.as_tag().to_string(),
        );
        tags.insert("collector.query_type".to_string(), line.file_type.clone());
        tags.insert("collector.offset".to_string(), line.end_offset.to_string());
        if matches!(mode, CollectorIngestMode::Frontload) {
            tags.insert("collector.frontload".to_string(), "true".to_string());
        }
        if let Some(project) = parsed.project.as_ref() {
            tags.insert("collector.project".to_string(), project.clone());
        }
        if let Some(method) = parsed.method.as_ref() {
            tags.insert("collector.method".to_string(), method.clone());
        }
        if let Some(tool_name) = parsed.tool_name.as_ref() {
            tags.insert("collector.tool".to_string(), tool_name.clone());
        }
        if let Some(agent) = parsed.agent.as_ref() {
            tags.entry("collector.agent".to_string())
                .or_insert_with(|| agent.clone());
        }

        let metadata = serde_json::json!({
            "collector": {
                "source": source.name,
                "offset": line.end_offset,
                "query_type": line.file_type,
                "ingest_mode": mode.as_tag(),
                "source_db_path": source.db_path.to_string_lossy().to_string(),
            },
            "parsed": {
                "direction": parsed.direction.map(direction_tag),
                "method": parsed.method,
                "tool_name": parsed.tool_name,
                "request": parsed.request,
                "response": parsed.response,
            },
        });

        Some(LocalSessionArtifact {
            artifact_id: build_local_artifact_id(
                source.db_path.to_string_lossy().as_ref(),
                local_type.as_str(),
                line.end_offset,
            ),
            observed_at: observed_at.to_rfc3339(),
            local_type,
            file_type: Some(line.file_type.clone()),
            parser_hint: Some("jsonl".to_string()),
            source_path: None,
            source_db_path: Some(source.db_path.to_string_lossy().to_string()),
            source_query: Some(line.file_type),
            read_mode: Some(mode.as_tag().to_string()),
            content_type: Some("application/json".to_string()),
            body_inline: Some(body_inline),
            body_blob_key: None,
            body_sha256: None,
            body_bytes,
            session_id: parsed
                .session_id
                .or_else(|| Some(self.session_id.clone()))
                .filter(|value| !value.trim().is_empty()),
            provider: parsed.provider.or(source.provider.clone()),
            model: parsed.model.or(source.model.clone()),
            agent: parsed
                .agent
                .or_else(|| source.server_name.clone())
                .or_else(|| Some(self.config.agent_name.clone())),
            tags: if tags.is_empty() { None } else { Some(tags) },
            metadata: Some(metadata),
        })
    }

    fn build_event(
        &self,
        source: &CollectorSource,
        line: SourceLine,
        mode: CollectorIngestMode,
    ) -> Option<WrapEvent> {
        let trimmed = line.content.trim();
        if trimmed.is_empty() {
            return None;
        }

        let parsed = parse_line(source.parser, trimmed);
        let observed_at = parsed.occurred_at.clone();
        let source_session_id = parsed.session_id.clone();
        let source_project = parsed.project.clone();
        let agent_name = source
            .agent
            .clone()
            .or(parsed.agent.clone())
            .unwrap_or_else(|| self.config.agent_name.clone());
        let server_name = source
            .server_name
            .clone()
            .unwrap_or_else(|| source.name.clone());
        let direction = parsed.direction.unwrap_or(WrapDirection::In);
        let source_kind = if source.agent.is_some() {
            EventSource::AgentApp
        } else {
            parsed.source.unwrap_or(self.config.event_source)
        };

        let mut event = WrapEvent::new(
            source_session_id.unwrap_or_else(|| self.session_id.clone()),
            server_name,
            direction,
            AgentInfo::new(agent_name, DetectionSource::Environment),
        )
        .with_source(source_kind)
        .with_collector_metadata(source.name.clone(), line.end_offset);
        if let Some(timestamp) = observed_at {
            event.timestamp = timestamp;
        }

        if let Some(provider) = parsed.provider.as_ref().or(source.provider.as_ref()) {
            event = event.with_provider(provider.clone());
        }
        if let Some(model) = parsed.model.as_ref().or(source.model.as_ref()) {
            event = event.with_model(model.clone());
        }
        if let Some(method) = parsed.method.as_ref() {
            event = event.with_method(method.clone());
        }
        if let Some(tool_name) = parsed.tool_name.as_ref() {
            event = event.with_tool_name(tool_name.clone());
        }

        let (content, pii_types) = redact_content(&self.redactor, parsed.content);
        let preview = build_preview(&content, 240);
        event = event.with_content(content).with_content_preview(preview);

        if let Some(request) = parsed.request {
            let (redacted_request, _) = redact_content(&self.redactor, request);
            let request_preview = build_preview(&redacted_request, 180);
            event = event.with_request(redacted_request, request_preview);
        }
        if let Some(response) = parsed.response {
            let (redacted_response, _) = redact_content(&self.redactor, response);
            let response_preview = build_preview(&redacted_response, 180);
            event = event.with_response(redacted_response, response_preview);
        }

        if !pii_types.is_empty() {
            event = event.with_pii(true, pii_types);
        }

        let mut tags = self.global_tags.clone();
        for (k, v) in &source.tags {
            tags.insert(k.clone(), v.clone());
        }
        if let Some(agent) = parsed.agent.as_ref().or(source.agent.as_ref()) {
            tags.entry("collector.agent".to_string())
                .or_insert_with(|| agent.clone());
        }
        tags.entry("collector.parser".to_string())
            .or_insert_with(|| source.parser.as_tag().to_string());
        tags.insert(
            "collector.ingest_mode".to_string(),
            mode.as_tag().to_string(),
        );
        if let Some(project) = source_project {
            tags.insert("collector.project".to_string(), project);
        }
        if matches!(mode, CollectorIngestMode::Frontload) {
            tags.insert("collector.frontload".to_string(), "true".to_string());
        }
        if !tags.is_empty() {
            event = event.with_tags(tags);
        }

        Some(event)
    }

    fn build_sqlite_event(
        &self,
        source: &CollectorSqliteSource,
        line: SqliteSourceLine,
        mode: CollectorIngestMode,
    ) -> Option<WrapEvent> {
        let trimmed = line.content.trim();
        if trimmed.is_empty() {
            return None;
        }

        let parsed = parse_line(CollectorParser::JsonLines, trimmed);
        let observed_at = parsed.occurred_at.clone();
        let source_session_id = parsed.session_id.clone();
        let source_project = parsed.project.clone();
        let agent_name = parsed
            .agent
            .clone()
            .unwrap_or_else(|| self.config.agent_name.clone());
        let server_name = source
            .server_name
            .clone()
            .unwrap_or_else(|| source.name.clone());
        let direction = parsed.direction.unwrap_or(WrapDirection::In);
        let source_kind = parsed.source.unwrap_or(self.config.event_source);
        let mut event = WrapEvent::new(
            source_session_id.unwrap_or_else(|| self.session_id.clone()),
            server_name,
            direction,
            AgentInfo::new(agent_name, DetectionSource::Environment),
        )
        .with_source(source_kind)
        .with_collector_metadata(
            format!("{}:{}", source.name, line.file_type),
            line.end_offset,
        );
        if let Some(timestamp) = observed_at {
            event.timestamp = timestamp;
        }

        if let Some(provider) = parsed.provider.as_ref().or(source.provider.as_ref()) {
            event = event.with_provider(provider.clone());
        }
        if let Some(model) = parsed.model.as_ref().or(source.model.as_ref()) {
            event = event.with_model(model.clone());
        }
        if let Some(method) = parsed.method.as_ref() {
            event = event.with_method(method.clone());
        } else {
            event = event.with_method(format!("sqlite:{}", line.file_type));
        }
        if let Some(tool_name) = parsed.tool_name.as_ref() {
            event = event.with_tool_name(tool_name.clone());
        }

        let (content, pii_types) = redact_content(&self.redactor, parsed.content);
        let preview = build_preview(&content, 240);
        event = event.with_content(content).with_content_preview(preview);

        if let Some(request) = parsed.request {
            let (redacted_request, _) = redact_content(&self.redactor, request);
            let request_preview = build_preview(&redacted_request, 180);
            event = event.with_request(redacted_request, request_preview);
        }
        if let Some(response) = parsed.response {
            let (redacted_response, _) = redact_content(&self.redactor, response);
            let response_preview = build_preview(&redacted_response, 180);
            event = event.with_response(redacted_response, response_preview);
        }

        if !pii_types.is_empty() {
            event = event.with_pii(true, pii_types);
        }

        let mut tags = self.global_tags.clone();
        for (k, v) in &source.tags {
            tags.insert(k.clone(), v.clone());
        }
        tags.entry("collector.agent".to_string())
            .or_insert_with(|| {
                source
                    .server_name
                    .clone()
                    .unwrap_or_else(|| source.name.clone())
            });
        tags.entry("collector.parser".to_string())
            .or_insert_with(|| CollectorParser::JsonLines.as_tag().to_string());
        tags.insert("collector.query_type".to_string(), line.file_type);
        tags.insert(
            "collector.ingest_mode".to_string(),
            mode.as_tag().to_string(),
        );
        if let Some(project) = source_project {
            tags.insert("collector.project".to_string(), project);
        }
        if matches!(mode, CollectorIngestMode::Frontload) {
            tags.insert("collector.frontload".to_string(), "true".to_string());
        }
        if !tags.is_empty() {
            event = event.with_tags(tags);
        }

        Some(event)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct FileScanState {
    #[serde(default)]
    offset: u64,
    #[serde(default)]
    mtime: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct SqliteScanState {
    #[serde(default)]
    mtime: u64,
    #[serde(default)]
    incremental: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct OffsetState {
    #[serde(default)]
    files: HashMap<String, FileScanState>,
    #[serde(default)]
    sqlite: HashMap<String, SqliteScanState>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct FrontloadBootstrapState {
    #[serde(default)]
    completed: bool,
    #[serde(default)]
    completed_at_unix_secs: Option<u64>,
}

impl OffsetState {
    fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read(path)?;
        serde_json::from_slice(&data)
            .with_context(|| format!("failed parsing collector offset state: {}", path.display()))
    }

    fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = File::create(path)?;
        let payload = serde_json::to_vec_pretty(self)?;
        file.write_all(&payload)?;
        file.flush()?;
        Ok(())
    }
}

impl FrontloadBootstrapState {
    fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read(path)?;
        serde_json::from_slice(&data).with_context(|| {
            format!(
                "failed parsing frontload bootstrap state: {}",
                path.display()
            )
        })
    }

    fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = File::create(path)?;
        let payload = serde_json::to_vec_pretty(self)?;
        file.write_all(&payload)?;
        file.flush()?;
        Ok(())
    }
}

#[derive(Debug)]
struct CollectOutcome {
    next_state: FileScanState,
    lines: Vec<SourceLine>,
}

#[derive(Debug)]
struct SqliteCollectOutcome {
    next_state: SqliteScanState,
    lines: Vec<SqliteSourceLine>,
}

#[derive(Debug)]
struct SourceLine {
    content: String,
    end_offset: u64,
}

#[derive(Debug)]
struct SqliteSourceLine {
    content: String,
    file_type: String,
    end_offset: u64,
}

fn collect_source_events(
    source: &CollectorSource,
    previous_state: &FileScanState,
    max_read_bytes: usize,
    max_line_bytes: usize,
) -> anyhow::Result<CollectOutcome> {
    let metadata = match std::fs::metadata(&source.path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CollectOutcome {
                next_state: FileScanState::default(),
                lines: Vec::new(),
            });
        }
        Err(error) => return Err(error).with_context(|| source.path.display().to_string()),
    };

    let file_len = metadata.len();
    let current_mtime = metadata_mtime_seconds(&metadata);
    let mut offset = previous_state.offset;
    if current_mtime == previous_state.mtime && offset >= file_len {
        return Ok(CollectOutcome {
            next_state: previous_state.clone(),
            lines: Vec::new(),
        });
    }
    if file_len < offset {
        // Rotation/truncation: restart from beginning.
        offset = 0;
    }

    if file_len <= offset {
        return Ok(CollectOutcome {
            next_state: FileScanState {
                offset,
                mtime: current_mtime,
            },
            lines: Vec::new(),
        });
    }

    let mut file = File::open(&source.path)
        .with_context(|| format!("collector open failed: {}", source.path.display()))?;
    file.seek(SeekFrom::Start(offset))
        .with_context(|| format!("collector seek failed: {}", source.path.display()))?;

    let remaining = (file_len - offset) as usize;
    let to_read = remaining.min(max_read_bytes);
    let mut buffer = vec![0u8; to_read];
    let bytes_read = file
        .read(&mut buffer)
        .with_context(|| format!("collector read failed: {}", source.path.display()))?;
    if bytes_read == 0 {
        return Ok(CollectOutcome {
            next_state: FileScanState {
                offset,
                mtime: current_mtime,
            },
            lines: Vec::new(),
        });
    }
    buffer.truncate(bytes_read);

    let at_eof = offset + bytes_read as u64 >= file_len;
    let (consumed_bytes, raw_lines) = extract_complete_lines(&buffer, at_eof);
    if consumed_bytes == 0 {
        return Ok(CollectOutcome {
            next_state: FileScanState {
                offset,
                mtime: current_mtime,
            },
            lines: Vec::new(),
        });
    }

    let mut lines = Vec::with_capacity(raw_lines.len());
    let mut consumed_cursor = 0u64;
    for raw in raw_lines {
        consumed_cursor += raw.len() as u64;
        let mut content = String::from_utf8_lossy(raw).to_string();
        if content.ends_with('\n') {
            content.pop();
        }
        if content.ends_with('\r') {
            content.pop();
        }
        if content.len() > max_line_bytes {
            content = truncate_utf8(content.as_str(), max_line_bytes);
        }
        if !content.trim().is_empty() {
            lines.push(SourceLine {
                content,
                end_offset: offset + consumed_cursor,
            });
        }
    }

    Ok(CollectOutcome {
        next_state: FileScanState {
            offset: offset + consumed_bytes as u64,
            mtime: current_mtime,
        },
        lines,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GlobToken {
    Literal(char),
    Star,
    DoubleStar,
    Qmark,
}

fn resolve_collector_sources_for_scan(sources: &[CollectorSource]) -> Vec<CollectorSource> {
    let mut resolved = Vec::new();
    let mut seen = BTreeSet::new();

    for source in sources {
        for path in expand_source_paths_for_scan(&source.path) {
            if source_path_matches_skip_patterns(&path, &source.skip_patterns) {
                continue;
            }
            let key = format!(
                "{}|{}|{}",
                source.name,
                source.agent.clone().unwrap_or_default(),
                path.to_string_lossy()
            );
            if !seen.insert(key) {
                continue;
            }
            let mut resolved_source = source.clone();
            resolved_source.path = path;
            resolved.push(resolved_source);
        }
    }

    resolved
}

fn expand_source_paths_for_scan(path: &Path) -> Vec<PathBuf> {
    if !source_path_contains_glob(path) {
        return vec![path.to_path_buf()];
    }

    let pattern = normalize_glob_path(path);
    let root = glob_search_root(&pattern);
    if !root.exists() {
        return Vec::new();
    }

    let mut matches = if root.is_file() {
        if glob_pattern_matches(&pattern, &normalize_glob_path(&root)) {
            vec![root]
        } else {
            Vec::new()
        }
    } else {
        discover_files_recursive(&root)
            .into_iter()
            .filter(|candidate| glob_pattern_matches(&pattern, &normalize_glob_path(candidate)))
            .collect::<Vec<_>>()
    };
    matches.sort_by(|left, right| left.to_string_lossy().cmp(&right.to_string_lossy()));
    matches.dedup();
    matches
}

fn source_path_contains_glob(path: &Path) -> bool {
    let raw = path.to_string_lossy();
    raw.contains('*') || raw.contains('?')
}

fn source_path_matches_skip_patterns(path: &Path, skip_patterns: &[String]) -> bool {
    if skip_patterns.is_empty() {
        return false;
    }
    let normalized_path = normalize_glob_path(path);
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();

    skip_patterns.iter().any(|pattern| {
        let normalized_pattern = normalize_skip_pattern(pattern);
        glob_pattern_matches(&normalized_pattern, &normalized_path)
            || glob_pattern_matches(&normalized_pattern, file_name)
    })
}

fn normalize_skip_pattern(pattern: &str) -> String {
    if pattern.starts_with("~/") {
        normalize_glob_path(&expand_home_path(Path::new(pattern)))
    } else {
        pattern.replace('\\', "/")
    }
}

fn normalize_glob_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn glob_search_root(pattern: &str) -> PathBuf {
    let first_meta = pattern.find(|ch| matches!(ch, '*' | '?'));
    let Some(meta_index) = first_meta else {
        return PathBuf::from(pattern);
    };
    let prefix = &pattern[..meta_index];
    let last_sep = prefix.rfind(|ch| matches!(ch, '/' | '\\'));
    match last_sep {
        Some(0) if pattern.starts_with('/') => PathBuf::from("/"),
        Some(index) if index > 0 => PathBuf::from(&pattern[..index]),
        _ if pattern.starts_with('/') => PathBuf::from("/"),
        _ => PathBuf::from("."),
    }
}

fn discover_files_recursive(root: &Path) -> Vec<PathBuf> {
    let mut discovered = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let read_dir = match std::fs::read_dir(&dir) {
            Ok(value) => value,
            Err(_) => continue,
        };
        for entry in read_dir.flatten() {
            let file_type = match entry.file_type() {
                Ok(value) => value,
                Err(_) => continue,
            };
            let path = entry.path();
            if file_type.is_dir() {
                if !file_type.is_symlink() {
                    stack.push(path);
                }
                continue;
            }
            if file_type.is_file() {
                discovered.push(path);
            }
        }
    }
    discovered
}

fn glob_pattern_matches(pattern: &str, candidate: &str) -> bool {
    let tokens = tokenize_glob_pattern(pattern);
    let chars = candidate.chars().collect::<Vec<_>>();
    let token_count = tokens.len();
    let char_count = chars.len();
    let mut dp = vec![vec![false; char_count + 1]; token_count + 1];
    dp[0][0] = true;

    for i in 1..=token_count {
        match tokens[i - 1] {
            GlobToken::Literal(ch) => {
                for j in 1..=char_count {
                    if dp[i - 1][j - 1] && chars[j - 1] == ch {
                        dp[i][j] = true;
                    }
                }
            }
            GlobToken::Qmark => {
                for j in 1..=char_count {
                    if dp[i - 1][j - 1] && chars[j - 1] != '/' {
                        dp[i][j] = true;
                    }
                }
            }
            GlobToken::Star => {
                for j in 0..=char_count {
                    if dp[i - 1][j] {
                        dp[i][j] = true;
                    }
                    if j > 0 && chars[j - 1] != '/' && dp[i][j - 1] {
                        dp[i][j] = true;
                    }
                }
            }
            GlobToken::DoubleStar => {
                for j in 0..=char_count {
                    if dp[i - 1][j] {
                        dp[i][j] = true;
                    }
                    if j > 0 && dp[i][j - 1] {
                        dp[i][j] = true;
                    }
                }
            }
        }
    }

    dp[token_count][char_count]
}

fn tokenize_glob_pattern(pattern: &str) -> Vec<GlobToken> {
    let chars = pattern.chars().collect::<Vec<_>>();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while index < chars.len() {
        match chars[index] {
            '*' => {
                if index + 1 < chars.len() && chars[index + 1] == '*' {
                    tokens.push(GlobToken::DoubleStar);
                    index += 2;
                } else {
                    tokens.push(GlobToken::Star);
                    index += 1;
                }
            }
            '?' => {
                tokens.push(GlobToken::Qmark);
                index += 1;
            }
            ch => {
                tokens.push(GlobToken::Literal(ch));
                index += 1;
            }
        }
    }
    tokens
}

fn metadata_mtime_seconds(metadata: &std::fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn collect_sqlite_events(
    source: &CollectorSqliteSource,
    previous_state: &SqliteScanState,
    max_line_bytes: usize,
) -> anyhow::Result<SqliteCollectOutcome> {
    let metadata = match std::fs::metadata(&source.db_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SqliteCollectOutcome {
                next_state: SqliteScanState::default(),
                lines: Vec::new(),
            });
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "collector sqlite metadata failed: {}",
                    source.db_path.display()
                )
            });
        }
    };
    let mut current_mtime = metadata_mtime_seconds(&metadata);
    let wal_path = PathBuf::from(format!("{}-wal", source.db_path.display()));
    if let Ok(wal_metadata) = std::fs::metadata(&wal_path) {
        current_mtime = current_mtime.max(metadata_mtime_seconds(&wal_metadata));
    }

    let has_incremental_queries = source
        .queries
        .iter()
        .any(|query| query.incremental_field.is_some());
    if current_mtime == previous_state.mtime && !has_incremental_queries {
        return Ok(SqliteCollectOutcome {
            next_state: previous_state.clone(),
            lines: Vec::new(),
        });
    }

    let mut next_state = previous_state.clone();
    let mut lines = Vec::new();
    let conn = open_sqlite_read_only(&source.db_path)
        .with_context(|| format!("collector sqlite open failed: {}", source.db_path.display()))?;
    for query in &source.queries {
        let previous_incremental = previous_state.incremental.get(&query.file_type);
        let result = execute_sqlite_query(query, &conn, previous_incremental, max_line_bytes)
            .with_context(|| {
                format!(
                    "collector sqlite query failed ({} on {})",
                    query.file_type,
                    source.db_path.display()
                )
            })?;
        if let Some(value) = result.max_incremental {
            next_state
                .incremental
                .insert(query.file_type.clone(), value);
        }
        lines.extend(result.lines);
    }
    next_state.mtime = current_mtime;
    Ok(SqliteCollectOutcome { next_state, lines })
}

struct SqliteQueryResult {
    lines: Vec<SqliteSourceLine>,
    max_incremental: Option<serde_json::Value>,
}

fn execute_sqlite_query(
    query: &CollectorSqliteQuery,
    conn: &Connection,
    previous_incremental: Option<&serde_json::Value>,
    max_line_bytes: usize,
) -> anyhow::Result<SqliteQueryResult> {
    let mut stmt = conn
        .prepare(query.sql.as_str())
        .with_context(|| format!("failed preparing sqlite query '{}'", query.file_type))?;
    let column_names = stmt
        .column_names()
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    let use_param = query.incremental_field.is_some() && query.sql.contains('?');
    let mut rows = if use_param {
        let parameter = sqlite_param_from_incremental(previous_incremental);
        let params = vec![parameter];
        stmt.query(params_from_iter(params.iter()))
            .with_context(|| format!("failed executing sqlite query '{}'", query.file_type))?
    } else {
        stmt.query(params![])
            .with_context(|| format!("failed executing sqlite query '{}'", query.file_type))?
    };

    let mut lines = Vec::new();
    let mut max_incremental = previous_incremental.cloned();
    let mut row_index = 0_u64;
    while let Some(row) = rows.next()? {
        let mut object = serde_json::Map::with_capacity(column_names.len());
        for (index, column_name) in column_names.iter().enumerate() {
            let value = json_value_from_sqlite_ref(
                row.get_ref(index)
                    .with_context(|| format!("failed reading sqlite column '{}'", column_name))?,
            );
            object.insert(column_name.clone(), value);
        }

        let json_value = serde_json::Value::Object(object);
        let incremental_value = query
            .incremental_field
            .as_deref()
            .and_then(|field| incremental_value_for_query(&json_value, field));
        if let Some(ref value) = incremental_value {
            if !use_param {
                if let Some(previous) = previous_incremental {
                    if !incremental_is_after(value, previous) {
                        continue;
                    }
                }
            }
            max_incremental = match max_incremental {
                Some(ref current) if !incremental_is_after(value, current) => max_incremental,
                _ => Some(value.clone()),
            };
        }

        row_index += 1;
        let mut raw_line = serde_json::to_string(&json_value)?;
        if raw_line.len() > max_line_bytes {
            raw_line = truncate_utf8(raw_line.as_str(), max_line_bytes);
        }
        lines.push(SqliteSourceLine {
            content: raw_line,
            file_type: query.file_type.clone(),
            end_offset: row_index,
        });
    }

    Ok(SqliteQueryResult {
        lines,
        max_incremental,
    })
}

fn sqlite_param_from_incremental(value: Option<&serde_json::Value>) -> SqlValue {
    let Some(value) = value else {
        return SqlValue::Integer(0);
    };
    match value {
        serde_json::Value::Null => SqlValue::Null,
        serde_json::Value::Bool(flag) => SqlValue::Integer(i64::from(*flag)),
        serde_json::Value::Number(number) => number
            .as_i64()
            .map(SqlValue::Integer)
            .or_else(|| number.as_f64().map(SqlValue::Real))
            .unwrap_or(SqlValue::Integer(0)),
        serde_json::Value::String(text) => SqlValue::Text(text.clone()),
        _ => SqlValue::Text(value.to_string()),
    }
}

fn json_value_from_sqlite_ref(value: ValueRef<'_>) -> serde_json::Value {
    match value {
        ValueRef::Null => serde_json::Value::Null,
        ValueRef::Integer(v) => serde_json::Value::from(v),
        ValueRef::Real(v) => serde_json::Value::from(v),
        ValueRef::Text(v) => serde_json::Value::String(String::from_utf8_lossy(v).to_string()),
        ValueRef::Blob(v) => {
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(v))
        }
    }
}

fn incremental_value_for_query(row: &serde_json::Value, field: &str) -> Option<serde_json::Value> {
    let object = row.as_object()?;
    if let Some(value) = object.get(field) {
        return Some(value.clone());
    }
    object.iter().find_map(|(key, value)| {
        if key.contains(field) || field.contains(key) {
            Some(value.clone())
        } else {
            None
        }
    })
}

fn incremental_is_after(candidate: &serde_json::Value, previous: &serde_json::Value) -> bool {
    match (candidate, previous) {
        (serde_json::Value::Number(left), serde_json::Value::Number(right)) => left
            .as_f64()
            .zip(right.as_f64())
            .map(|(l, r)| l > r)
            .unwrap_or(false),
        (serde_json::Value::String(left), serde_json::Value::String(right)) => left > right,
        (serde_json::Value::String(left), serde_json::Value::Number(right)) => right
            .as_f64()
            .and_then(|r| left.parse::<f64>().ok().map(|l| l > r))
            .unwrap_or(false),
        (serde_json::Value::Number(left), serde_json::Value::String(right)) => left
            .as_f64()
            .and_then(|l| right.parse::<f64>().ok().map(|r| l > r))
            .unwrap_or(false),
        _ => candidate != previous,
    }
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    if max_bytes == 0 {
        return String::new();
    }
    let marker = "... [truncated]";
    let marker_bytes = marker.len();
    let budget = max_bytes.saturating_sub(marker_bytes).max(1);
    let mut out = String::new();
    for ch in value.chars() {
        let ch_bytes = ch.len_utf8();
        if out.len() + ch_bytes > budget {
            break;
        }
        out.push(ch);
    }
    out.push_str(marker);
    out
}

fn extract_complete_lines(bytes: &[u8], at_eof: bool) -> (usize, Vec<&[u8]>) {
    let mut consumed = 0usize;
    let mut lines = Vec::new();
    let mut start = 0usize;

    for (idx, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            let end = idx + 1;
            lines.push(&bytes[start..end]);
            consumed = end;
            start = end;
        }
    }

    if at_eof && start < bytes.len() {
        lines.push(&bytes[start..bytes.len()]);
        consumed = bytes.len();
    }

    (consumed, lines)
}

#[derive(Debug)]
struct ParsedLine {
    content: String,
    occurred_at: Option<DateTime<Utc>>,
    source: Option<EventSource>,
    direction: Option<WrapDirection>,
    provider: Option<String>,
    model: Option<String>,
    method: Option<String>,
    tool_name: Option<String>,
    agent: Option<String>,
    session_id: Option<String>,
    project: Option<String>,
    request: Option<String>,
    response: Option<String>,
}

fn parse_line(parser: CollectorParser, line: &str) -> ParsedLine {
    match parser {
        CollectorParser::TextLines => ParsedLine {
            content: line.to_string(),
            occurred_at: None,
            source: None,
            direction: None,
            provider: None,
            model: None,
            method: None,
            tool_name: None,
            agent: None,
            session_id: None,
            project: None,
            request: None,
            response: None,
        },
        CollectorParser::JsonLines => parse_json_line(line).unwrap_or(ParsedLine {
            content: line.to_string(),
            occurred_at: None,
            source: None,
            direction: None,
            provider: None,
            model: None,
            method: None,
            tool_name: None,
            agent: None,
            session_id: None,
            project: None,
            request: None,
            response: None,
        }),
    }
}

fn parse_json_line(line: &str) -> Option<ParsedLine> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let content = serde_json::to_string(&value).ok()?;
    let occurred_at = extract_json_timestamp(&value);
    let source = value
        .get("source")
        .and_then(|v| v.as_str())
        .and_then(parse_event_source);
    let direction = value
        .get("direction")
        .and_then(|v| v.as_str())
        .and_then(parse_direction);
    let provider = extract_string_with_sections(
        &value,
        &["provider", "vendor", "model_provider", "modelProvider"],
        &["payload", "request", "response", "metadata", "meta"],
    );
    let model = extract_string_with_sections(
        &value,
        &["model", "model_name", "modelName"],
        &["payload", "request", "response", "metadata", "meta"],
    );
    let method = extract_string_with_sections(
        &value,
        &["method", "operation", "rpc_method"],
        &["payload", "request", "response", "metadata", "meta"],
    )
    .or_else(|| {
        value
            .get("request")
            .and_then(|v| v.get("method"))
            .and_then(|v| v.as_str())
            .map(|v| v.to_string())
    });
    let tool_name = extract_string(&value, &["tool_name", "tool"]);
    let agent = extract_string_with_sections(
        &value,
        &["agent", "agent_name", "client", "client_name"],
        &["payload", "request", "response", "metadata", "meta"],
    );
    let session_id = extract_string_with_sections(
        &value,
        &[
            "session_id",
            "sessionId",
            "conversation_id",
            "conversationId",
            "thread_id",
            "threadId",
            "chat_id",
            "chatId",
        ],
        &["payload", "request", "response", "metadata", "meta"],
    );
    let project = extract_string_with_sections(
        &value,
        &["project", "cwd"],
        &["payload", "metadata", "meta"],
    );
    let request = value
        .get("request")
        .and_then(|v| serde_json::to_string(v).ok());
    let response = value
        .get("response")
        .and_then(|v| serde_json::to_string(v).ok());

    Some(ParsedLine {
        content,
        occurred_at,
        source,
        direction,
        provider,
        model,
        method,
        tool_name,
        agent,
        session_id,
        project,
        request,
        response,
    })
}

fn extract_string(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(raw) = value.get(*key).and_then(|v| v.as_str()) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn extract_string_with_sections(
    value: &serde_json::Value,
    keys: &[&str],
    sections: &[&str],
) -> Option<String> {
    if let Some(found) = extract_string(value, keys) {
        return Some(found);
    }

    for section in sections {
        let Some(candidate) = value.get(*section) else {
            continue;
        };
        if let Some(found) = extract_string(candidate, keys) {
            return Some(found);
        }
    }

    None
}

fn extract_json_timestamp(value: &serde_json::Value) -> Option<DateTime<Utc>> {
    const KEYS: &[&str] = &[
        "ts",
        "timestamp",
        "time",
        "created_at",
        "createdAt",
        "updated_at",
        "updatedAt",
        "observed_at",
    ];
    for key in KEYS {
        if let Some(raw) = value.get(*key).and_then(parse_json_timestamp_value) {
            return Some(raw);
        }
    }
    value
        .get("payload")
        .and_then(serde_json::Value::as_object)
        .and_then(|payload| {
            KEYS.iter()
                .find_map(|key| payload.get(*key).and_then(parse_json_timestamp_value))
        })
}

fn parse_json_timestamp_value(value: &serde_json::Value) -> Option<DateTime<Utc>> {
    let epoch = match value {
        serde_json::Value::Number(num) => {
            if let Some(raw) = num.as_i64() {
                Some(raw)
            } else {
                num.as_f64().map(|raw| raw.trunc() as i64)
            }
        }
        serde_json::Value::String(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return None;
            }
            if let Ok(parsed) = trimmed.parse::<i64>() {
                Some(parsed)
            } else if let Ok(parsed) = DateTime::parse_from_rfc3339(trimmed) {
                return Some(parsed.with_timezone(&Utc));
            } else {
                None
            }
        }
        _ => None,
    }?;
    datetime_from_unix_epoch(epoch)
}

fn datetime_from_unix_epoch(raw: i64) -> Option<DateTime<Utc>> {
    if raw <= 0 {
        return None;
    }
    let (secs, nanos) = if raw >= 1_000_000_000_000_000_000 {
        (raw / 1_000_000_000, (raw % 1_000_000_000) as u32)
    } else if raw >= 1_000_000_000_000_000 {
        (raw / 1_000_000, ((raw % 1_000_000) * 1_000) as u32)
    } else if raw >= 1_000_000_000_000 {
        (raw / 1_000, ((raw % 1_000) * 1_000_000) as u32)
    } else {
        (raw, 0)
    };
    Utc.timestamp_opt(secs, nanos).single()
}

fn parse_event_source(raw: &str) -> Option<EventSource> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "mcp" => Some(EventSource::Mcp),
        "ai" | "ai_proxy" | "inference" | "ai_inference" => Some(EventSource::AiProxy),
        "agent" | "agent_app" | "agent_apps" => Some(EventSource::AgentApp),
        _ => None,
    }
}

fn parse_direction(raw: &str) -> Option<WrapDirection> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "in" | "incoming" | "request" | "req" => Some(WrapDirection::In),
        "out" | "outgoing" | "response" | "res" => Some(WrapDirection::Out),
        _ => None,
    }
}

fn direction_tag(direction: WrapDirection) -> &'static str {
    match direction {
        WrapDirection::In => "in",
        WrapDirection::Out => "out",
    }
}

fn normalize_local_type(raw: &str) -> String {
    let trimmed = raw
        .trim()
        .trim_start_matches("registry:")
        .trim_start_matches("local:")
        .trim();
    if trimmed.is_empty() {
        return "unknown".to_string();
    }
    let normalized = trimmed
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    let normalized = normalized.trim_matches('-').replace("--", "-");
    if normalized.is_empty() {
        "unknown".to_string()
    } else {
        normalized
    }
}

fn build_local_artifact_id(source_key: &str, local_type: &str, offset: u64) -> String {
    let mut hasher = DefaultHasher::new();
    source_key.hash(&mut hasher);
    local_type.hash(&mut hasher);
    let hash = hasher.finish();
    format!("{}-{:016x}-{}", local_type, hash, offset)
}

fn redact_content(redactor: &PiiRedactor, content: String) -> (String, Vec<String>) {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
        let (redacted, redactions) = redactor.redact_json(&json);
        let text = serde_json::to_string(&redacted).unwrap_or(content);
        let pii_types = redactions
            .iter()
            .map(|r| r.pii_type.to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        (text, pii_types)
    } else {
        let result = redactor.redact(&content);
        let pii_types = result
            .redactions
            .iter()
            .map(|r| r.pii_type.to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        (result.text, pii_types)
    }
}

fn build_preview(content: &str, max_chars: usize) -> String {
    if content.chars().count() <= max_chars {
        return content.to_string();
    }
    let mut out = String::with_capacity(max_chars + 3);
    for ch in content.chars().take(max_chars) {
        out.push(ch);
    }
    out.push_str("...");
    out
}

fn discover_default_sources(limit: usize) -> Vec<CollectorSource> {
    if limit == 0 {
        return Vec::new();
    }
    let mut discovered = Vec::new();
    let mut seen = BTreeSet::new();
    for (root_name, raw_root) in default_source_roots() {
        if discovered.len() >= limit {
            break;
        }
        let root = expand_home_path(Path::new(raw_root));
        if !root.exists() {
            continue;
        }
        let remaining = limit.saturating_sub(discovered.len());
        for path in discover_history_files_under(&root, remaining, 4) {
            if !seen.insert(path.clone()) {
                continue;
            }
            let parser = match path
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str()
            {
                "jsonl" | "ndjson" => CollectorParser::JsonLines,
                _ => CollectorParser::TextLines,
            };
            let rel = path
                .strip_prefix(&root)
                .ok()
                .map(|v| v.to_string_lossy().to_string())
                .unwrap_or_else(|| {
                    path.file_name()
                        .and_then(|v| v.to_str())
                        .unwrap_or("history")
                        .to_string()
                });
            let mut tags = BTreeMap::new();
            tags.insert("collector.discovery".to_string(), "auto".to_string());
            tags.insert("collector.root".to_string(), root_name.to_string());
            discovered.push(CollectorSource {
                name: format!("{}:{}", root_name, rel),
                path,
                parser,
                skip_patterns: Vec::new(),
                agent: None,
                server_name: None,
                provider: None,
                model: None,
                tags,
            });
            if discovered.len() >= limit {
                break;
            }
        }
    }
    discovered
}

fn default_source_roots() -> &'static [(&'static str, &'static str)] {
    &[
        ("codex", "~/.codex"),
        ("claude", "~/.claude"),
        ("cursor", "~/.cursor"),
        ("windsurf", "~/.codeium/windsurf"),
        ("warp", "~/.warp"),
    ]
}

fn discover_history_files_under(root: &Path, limit: usize, max_depth: usize) -> Vec<PathBuf> {
    let mut discovered = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if discovered.len() >= limit {
            break;
        }
        let read_dir = match std::fs::read_dir(&dir) {
            Ok(value) => value,
            Err(_) => continue,
        };
        for entry in read_dir.flatten() {
            if discovered.len() >= limit {
                break;
            }
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(value) => value,
                Err(_) => continue,
            };
            if file_type.is_dir() {
                if depth < max_depth && !is_ignored_history_dir(&path) {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            if is_candidate_history_file(&path) {
                discovered.push(path);
            }
        }
    }
    discovered
}

fn is_ignored_history_dir(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(
        name.as_str(),
        ".git"
            | "node_modules"
            | "cache"
            | ".cache"
            | "tmp"
            | "temp"
            | "logs"
            | "log"
            | "vendor"
            | "dist"
            | "build"
    )
}

fn is_candidate_history_file(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if ext != "jsonl" && ext != "ndjson" && ext != "log" && ext != "txt" {
        return false;
    }
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.contains("history")
        || name.contains("session")
        || name.contains("conversation")
        || name.contains("chat")
        || name.contains("prompt")
}

fn default_state_path() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        return home
            .join(".soth")
            .join("runtime")
            .join("collector_offsets.json");
    }
    PathBuf::from(".soth/runtime/collector_offsets.json")
}

fn expand_home_path(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn test_collector_config() -> CollectorConfig {
        CollectorConfig {
            poll_interval: Duration::from_secs(5),
            state_path: PathBuf::from("/tmp/collector-test-state.json"),
            max_read_bytes_per_source: 64 * 1024,
            max_line_bytes: 64 * 1024,
            auto_discover_sources: false,
            frontload_on_start: false,
            frontload_force_first_run: false,
            frontload_reset_offsets_on_start: false,
            frontload_max_cycles: 1,
            frontload_max_read_bytes_per_source: 64 * 1024,
            agent_name: "collector".to_string(),
            event_source: EventSource::AgentApp,
            exchange: ExchangeConfig::default(),
            direct_upload: None,
            sources: Vec::new(),
            sqlite_sources: Vec::new(),
        }
    }

    #[test]
    fn extract_complete_lines_skips_partial_non_eof() {
        let input = b"one\ntwo\nthree";
        let (consumed, lines) = extract_complete_lines(input, false);
        assert_eq!(consumed, 8);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], b"one\n");
        assert_eq!(lines[1], b"two\n");
    }

    #[test]
    fn extract_complete_lines_consumes_tail_at_eof() {
        let input = b"one\ntwo";
        let (consumed, lines) = extract_complete_lines(input, true);
        assert_eq!(consumed, input.len());
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], b"one\n");
        assert_eq!(lines[1], b"two");
    }

    #[test]
    fn parse_event_source_aliases() {
        assert_eq!(parse_event_source("mcp"), Some(EventSource::Mcp));
        assert_eq!(
            parse_event_source("ai_inference"),
            Some(EventSource::AiProxy)
        );
        assert_eq!(
            parse_event_source("agent_apps"),
            Some(EventSource::AgentApp)
        );
    }

    #[test]
    fn parse_json_timestamp_supports_seconds_millis_and_rfc3339() {
        let secs = parse_json_timestamp_value(&json!(1757962470)).unwrap();
        assert_eq!(secs, Utc.timestamp_opt(1757962470, 0).single().unwrap());

        let millis = parse_json_timestamp_value(&json!(1767383435897_i64)).unwrap();
        assert_eq!(
            millis,
            Utc.timestamp_millis_opt(1767383435897).single().unwrap()
        );

        let rfc3339 = parse_json_timestamp_value(&json!("2026-02-18T19:21:32.980Z")).unwrap();
        assert_eq!(
            rfc3339,
            Utc.timestamp_millis_opt(1771442492980).single().unwrap()
        );
    }

    #[test]
    fn collector_event_uses_source_timestamp_and_session_id() {
        let agent = CollectorAgent::new(test_collector_config(), BTreeMap::new());
        let source = CollectorSource {
            name: "registry:codex".to_string(),
            path: PathBuf::from("/tmp/codex-history.jsonl"),
            parser: CollectorParser::JsonLines,
            skip_patterns: Vec::new(),
            agent: Some("codex".to_string()),
            server_name: Some("codex".to_string()),
            provider: None,
            model: None,
            tags: BTreeMap::new(),
        };
        let line = SourceLine {
            content: "{\"session_id\":\"source-session-1\",\"ts\":1757962470,\"project\":\"/tmp/example\",\"text\":\"hello\"}".to_string(),
            end_offset: 10,
        };

        let event = agent
            .build_event(&source, line, CollectorIngestMode::Incremental)
            .expect("event");

        assert_eq!(event.session_id, "source-session-1");
        assert_eq!(
            event.timestamp,
            Utc.timestamp_opt(1757962470, 0).single().unwrap()
        );
        assert_eq!(event.source, EventSource::AgentApp);
        assert_eq!(
            event
                .tags
                .as_ref()
                .and_then(|tags| tags.get("collector.project")),
            Some(&"/tmp/example".to_string())
        );
    }

    #[test]
    fn parse_json_line_extracts_nested_session_aliases() {
        let line = json!({
            "payload": {
                "conversationId": "conversation-123",
                "model": "gpt-4o-mini",
                "provider": "openai"
            },
            "request": {
                "method": "POST"
            }
        })
        .to_string();

        let parsed = parse_json_line(&line).expect("parsed JSON line");
        assert_eq!(parsed.session_id.as_deref(), Some("conversation-123"));
        assert_eq!(parsed.model.as_deref(), Some("gpt-4o-mini"));
        assert_eq!(parsed.provider.as_deref(), Some("openai"));
        assert_eq!(parsed.method.as_deref(), Some("POST"));
    }

    #[test]
    fn collect_source_events_skips_when_file_unchanged() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        std::fs::write(&path, b"{\"ok\":1}\n").unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        let size = metadata.len();
        let mtime = metadata_mtime_seconds(&metadata);
        let source = CollectorSource {
            name: "events".to_string(),
            path,
            parser: CollectorParser::JsonLines,
            skip_patterns: Vec::new(),
            agent: None,
            server_name: None,
            provider: None,
            model: None,
            tags: BTreeMap::new(),
        };
        let prior = FileScanState {
            offset: size,
            mtime,
        };
        let outcome = collect_source_events(&source, &prior, 64 * 1024, 64 * 1024).unwrap();
        assert_eq!(outcome.next_state, prior);
        assert!(outcome.lines.is_empty());
    }

    #[test]
    fn collect_source_events_truncates_utf8_without_panicking() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        std::fs::write(&path, "éxample line\n").unwrap();

        let source = CollectorSource {
            name: "events".to_string(),
            path,
            parser: CollectorParser::JsonLines,
            skip_patterns: Vec::new(),
            agent: None,
            server_name: None,
            provider: None,
            model: None,
            tags: BTreeMap::new(),
        };

        let prior = FileScanState::default();
        let outcome = collect_source_events(&source, &prior, 64 * 1024, 1).unwrap();
        assert_eq!(outcome.lines.len(), 1);
        assert!(outcome.lines[0].content.contains("[truncated]"));
    }

    #[test]
    fn glob_pattern_matches_supports_recursive_paths() {
        let pattern = "/tmp/.codex/sessions/**/*.jsonl";
        assert!(glob_pattern_matches(
            pattern,
            "/tmp/.codex/sessions/2026/02/rollout.jsonl"
        ));
        assert!(!glob_pattern_matches(
            pattern,
            "/tmp/.codex/sessions/rollout.jsonl"
        ));
        assert!(!glob_pattern_matches(
            pattern,
            "/tmp/.codex/sessions/2026/02/rollout.log"
        ));
    }

    #[test]
    fn resolve_collector_sources_for_scan_expands_glob_paths() {
        let dir = tempdir().unwrap();
        let sessions = dir.path().join("sessions");
        let jan_dir = sessions.join("2026").join("01");
        let feb_dir = sessions.join("2026").join("02");
        std::fs::create_dir_all(&jan_dir).unwrap();
        std::fs::create_dir_all(&feb_dir).unwrap();
        std::fs::write(jan_dir.join("rollout-a.jsonl"), b"{}\n").unwrap();
        std::fs::write(feb_dir.join("rollout-b.jsonl"), b"{}\n").unwrap();
        std::fs::write(feb_dir.join("notes.txt"), b"hello\n").unwrap();

        let source = CollectorSource {
            name: "registry:codex".to_string(),
            path: sessions.join("**").join("rollout-*.jsonl"),
            parser: CollectorParser::JsonLines,
            skip_patterns: Vec::new(),
            agent: Some("codex".to_string()),
            server_name: Some("codex".to_string()),
            provider: None,
            model: None,
            tags: BTreeMap::new(),
        };

        let resolved = resolve_collector_sources_for_scan(&[source]);
        let mut relative = resolved
            .iter()
            .map(|source| {
                source
                    .path
                    .strip_prefix(dir.path())
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect::<Vec<_>>();
        relative.sort();

        assert_eq!(
            relative,
            vec![
                "sessions/2026/01/rollout-a.jsonl".to_string(),
                "sessions/2026/02/rollout-b.jsonl".to_string()
            ]
        );
    }

    #[test]
    fn source_path_matches_skip_patterns_supports_filename_globs() {
        let path = Path::new("/tmp/sessions/rollout-a.deleted.jsonl");
        let skip_patterns = vec![
            "*.deleted.*".to_string(),
            "*.resolved".to_string(),
            "*.resolved.*".to_string(),
        ];
        assert!(source_path_matches_skip_patterns(path, &skip_patterns));
        assert!(!source_path_matches_skip_patterns(
            Path::new("/tmp/sessions/rollout-a.jsonl"),
            &skip_patterns
        ));
    }

    #[test]
    fn resolve_collector_sources_for_scan_applies_skip_patterns() {
        let dir = tempdir().unwrap();
        let sessions = dir.path().join("sessions");
        let month_dir = sessions.join("2026").join("02");
        std::fs::create_dir_all(&month_dir).unwrap();
        std::fs::write(month_dir.join("rollout-a.jsonl"), b"{}\n").unwrap();
        std::fs::write(month_dir.join("rollout-a.deleted.jsonl"), b"{}\n").unwrap();
        std::fs::write(month_dir.join("rollout-a.resolved"), b"{}\n").unwrap();

        let source = CollectorSource {
            name: "registry:codex".to_string(),
            path: sessions.join("**").join("rollout-a*"),
            parser: CollectorParser::JsonLines,
            skip_patterns: vec![
                "*.deleted.*".to_string(),
                "*.resolved".to_string(),
                "*.resolved.*".to_string(),
            ],
            agent: Some("codex".to_string()),
            server_name: Some("codex".to_string()),
            provider: None,
            model: None,
            tags: BTreeMap::new(),
        };

        let resolved = resolve_collector_sources_for_scan(&[source]);
        let relative = resolved
            .iter()
            .map(|source| {
                source
                    .path
                    .strip_prefix(dir.path())
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect::<Vec<_>>();

        assert_eq!(
            relative,
            vec!["sessions/2026/02/rollout-a.jsonl".to_string()]
        );
    }

    #[test]
    fn collect_sqlite_events_tracks_incremental_field() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("sessions.db");
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute(
                "CREATE TABLE messages (createdAt INTEGER PRIMARY KEY, body TEXT NOT NULL)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO messages(createdAt, body) VALUES (?1, ?2)",
                params![1_i64, "hello"],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO messages(createdAt, body) VALUES (?1, ?2)",
                params![2_i64, "world"],
            )
            .unwrap();
        }

        let source = CollectorSqliteSource {
            name: "sqlite-source".to_string(),
            db_path: db_path.clone(),
            server_name: None,
            provider: None,
            model: None,
            tags: BTreeMap::new(),
            queries: vec![CollectorSqliteQuery {
                file_type: "messages".to_string(),
                sql: "SELECT createdAt, body FROM messages WHERE createdAt > ? ORDER BY createdAt ASC"
                    .to_string(),
                incremental_field: Some("createdAt".to_string()),
            }],
        };
        let initial =
            collect_sqlite_events(&source, &SqliteScanState::default(), 64 * 1024).unwrap();
        assert_eq!(initial.lines.len(), 2);
        assert_eq!(
            initial.next_state.incremental.get("messages"),
            Some(&serde_json::Value::from(2_i64))
        );

        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute(
                "INSERT INTO messages(createdAt, body) VALUES (?1, ?2)",
                params![3_i64, "again"],
            )
            .unwrap();
        }

        let follow_up = collect_sqlite_events(&source, &initial.next_state, 64 * 1024).unwrap();
        assert_eq!(follow_up.lines.len(), 1);
        assert_eq!(
            follow_up.next_state.incremental.get("messages"),
            Some(&serde_json::Value::from(3_i64))
        );
    }

    #[test]
    fn candidate_history_file_filters_expected_names() {
        assert!(is_candidate_history_file(Path::new("history.jsonl")));
        assert!(is_candidate_history_file(Path::new("chat-session.ndjson")));
        assert!(!is_candidate_history_file(Path::new("events.jsonl")));
        assert!(!is_candidate_history_file(Path::new("history.json")));
    }

    #[test]
    fn discover_history_files_respects_depth_and_patterns() {
        let dir = tempdir().unwrap();
        let root = dir.path().join(".codex");
        std::fs::create_dir_all(root.join("sessions")).unwrap();
        std::fs::create_dir_all(root.join("logs")).unwrap();
        std::fs::write(root.join("sessions/history.jsonl"), b"{}\n").unwrap();
        std::fs::write(root.join("logs/history.jsonl"), b"{}\n").unwrap();
        std::fs::write(root.join("sessions/events.jsonl"), b"{}\n").unwrap();

        let files = discover_history_files_under(&root, 10, 3);
        let mut names = files
            .iter()
            .filter_map(|path| path.file_name().and_then(|value| value.to_str()))
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(names, vec!["history.jsonl"]);
    }
}
