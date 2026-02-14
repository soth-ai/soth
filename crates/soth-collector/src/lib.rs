use anyhow::Context;
use base64::Engine as _;
use rusqlite::{
    params, params_from_iter,
    types::{Value as SqlValue, ValueRef},
    Connection, OpenFlags,
};
use serde::{Deserialize, Serialize};
use soth_core::types::{AgentInfo, DetectionSource, EventSource, WrapDirection, WrapEvent};
use soth_core::EventLogger;
use soth_observe::PiiRedactor;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};
use tracing::{info, warn};

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_MAX_READ_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_LINE_BYTES: usize = 64 * 1024;

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
    pub agent_name: String,
    pub event_source: EventSource,
    pub sources: Vec<CollectorSource>,
    pub sqlite_sources: Vec<CollectorSqliteSource>,
}

#[derive(Debug, Clone)]
pub struct CollectorSource {
    pub name: String,
    pub path: PathBuf,
    pub parser: CollectorParser,
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

        let mut sources = Vec::new();
        if let Ok(sources_raw) = std::env::var("SOTH_COLLECTOR_SOURCES") {
            for raw in sources_raw.split(',') {
                let raw = raw.trim();
                if raw.is_empty() {
                    continue;
                }
                let path = expand_home_path(Path::new(raw));
                let name = path
                    .file_name()
                    .and_then(|v| v.to_str())
                    .unwrap_or("collector-source")
                    .to_string();
                let parser = match path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "jsonl" | "ndjson" => CollectorParser::JsonLines,
                    _ => CollectorParser::TextLines,
                };
                sources.push(CollectorSource {
                    name,
                    path,
                    parser,
                    server_name: None,
                    provider: None,
                    model: None,
                    tags: BTreeMap::new(),
                });
            }
        }

        let sqlite_sources = parse_sqlite_sources_from_env();

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

        Some(Self {
            poll_interval,
            state_path,
            max_read_bytes_per_source,
            max_line_bytes,
            agent_name,
            event_source,
            sources,
            sqlite_sources,
        })
    }
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

pub fn spawn_from_env(
    event_logger: EventLogger,
    global_tags: BTreeMap<String, String>,
) -> Option<CollectorRuntime> {
    let config = CollectorConfig::from_env()?;
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
        poll_secs = collector.config.poll_interval.as_secs(),
        state_path = %collector.config.state_path.display(),
        "Local collector enabled"
    );

    let task = tokio::spawn(async move {
        if let Err(error) = collector.load_state() {
            warn!("Collector state load failed: {}", error);
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
                    if let Err(error) = collector.poll_once(&event_logger) {
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
}

impl CollectorAgent {
    fn new(config: CollectorConfig, global_tags: BTreeMap<String, String>) -> Self {
        Self {
            config,
            global_tags,
            offsets: OffsetState::default(),
            session_id: uuid::Uuid::new_v4().to_string(),
            redactor: PiiRedactor::new().with_preserve_length(false),
        }
    }

    fn load_state(&mut self) -> anyhow::Result<()> {
        self.offsets = OffsetState::load(&self.config.state_path)?;
        Ok(())
    }

    fn save_state(&self) -> anyhow::Result<()> {
        self.offsets.save(&self.config.state_path)
    }

    fn poll_once(&mut self, logger: &EventLogger) -> anyhow::Result<()> {
        let mut state_changed = false;

        for source in &self.config.sources {
            let key = source.path.to_string_lossy().to_string();
            let prior_state = self.offsets.files.get(&key).cloned().unwrap_or_default();
            let outcome = collect_source_events(
                source,
                &prior_state,
                self.config.max_read_bytes_per_source,
                self.config.max_line_bytes,
            )?;
            if outcome.next_state != prior_state {
                self.offsets.files.insert(key, outcome.next_state);
                state_changed = true;
            }

            for source_line in outcome.lines {
                if let Some(event) = self.build_event(source, source_line) {
                    logger.log(&event);
                }
            }
        }

        for source in &self.config.sqlite_sources {
            let key = source.db_path.to_string_lossy().to_string();
            let prior_state = self.offsets.sqlite.get(&key).cloned().unwrap_or_default();
            let outcome = collect_sqlite_events(source, &prior_state, self.config.max_line_bytes)?;
            if outcome.next_state != prior_state {
                self.offsets.sqlite.insert(key, outcome.next_state);
                state_changed = true;
            }

            for source_line in outcome.lines {
                if let Some(event) = self.build_sqlite_event(source, source_line) {
                    logger.log(&event);
                }
            }
        }

        if state_changed {
            self.save_state()?;
        }

        Ok(())
    }

    fn build_event(&self, source: &CollectorSource, line: SourceLine) -> Option<WrapEvent> {
        let trimmed = line.content.trim();
        if trimmed.is_empty() {
            return None;
        }

        let parsed = parse_line(source.parser, trimmed);
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
            self.session_id.clone(),
            server_name,
            direction,
            AgentInfo::new(agent_name, DetectionSource::Environment),
        )
        .with_source(source_kind)
        .with_collector_metadata(source.name.clone(), line.end_offset);

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
        if !tags.is_empty() {
            event = event.with_tags(tags);
        }

        Some(event)
    }

    fn build_sqlite_event(
        &self,
        source: &CollectorSqliteSource,
        line: SqliteSourceLine,
    ) -> Option<WrapEvent> {
        let trimmed = line.content.trim();
        if trimmed.is_empty() {
            return None;
        }

        let parsed = parse_line(CollectorParser::JsonLines, trimmed);
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
            self.session_id.clone(),
            server_name,
            direction,
            AgentInfo::new(agent_name, DetectionSource::Environment),
        )
        .with_source(source_kind)
        .with_collector_metadata(
            format!("{}:{}", source.name, line.file_type),
            line.end_offset,
        );

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
        tags.insert("collector.query_type".to_string(), line.file_type);
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

#[derive(Debug, Default, Deserialize)]
struct LegacyOffsetState {
    #[serde(default)]
    offsets: HashMap<String, u64>,
}

impl OffsetState {
    fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read(path)?;
        let value = serde_json::from_slice::<serde_json::Value>(&data).with_context(|| {
            format!("failed parsing collector offset state: {}", path.display())
        })?;
        if let Ok(parsed) = serde_json::from_value::<Self>(value.clone()) {
            let has_legacy_offsets = value.get("offsets").is_some();
            if !parsed.files.is_empty() || !parsed.sqlite.is_empty() || !has_legacy_offsets {
                return Ok(parsed);
            }
        }
        let legacy = serde_json::from_value::<LegacyOffsetState>(value).with_context(|| {
            format!(
                "failed parsing collector legacy offset state: {}",
                path.display()
            )
        })?;
        let files = legacy
            .offsets
            .into_iter()
            .map(|(path, offset)| (path, FileScanState { offset, mtime: 0 }))
            .collect::<HashMap<_, _>>();
        Ok(Self {
            files,
            sqlite: HashMap::new(),
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
            content.truncate(max_line_bytes);
            content.push_str("… [truncated]");
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
    let conn = Connection::open_with_flags(
        &source.db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
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
    source: Option<EventSource>,
    direction: Option<WrapDirection>,
    provider: Option<String>,
    model: Option<String>,
    method: Option<String>,
    tool_name: Option<String>,
    agent: Option<String>,
    request: Option<String>,
    response: Option<String>,
}

fn parse_line(parser: CollectorParser, line: &str) -> ParsedLine {
    match parser {
        CollectorParser::TextLines => ParsedLine {
            content: line.to_string(),
            source: None,
            direction: None,
            provider: None,
            model: None,
            method: None,
            tool_name: None,
            agent: None,
            request: None,
            response: None,
        },
        CollectorParser::JsonLines => parse_json_line(line).unwrap_or(ParsedLine {
            content: line.to_string(),
            source: None,
            direction: None,
            provider: None,
            model: None,
            method: None,
            tool_name: None,
            agent: None,
            request: None,
            response: None,
        }),
    }
}

fn parse_json_line(line: &str) -> Option<ParsedLine> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let content = serde_json::to_string(&value).ok()?;
    let source = value
        .get("source")
        .and_then(|v| v.as_str())
        .and_then(parse_event_source);
    let direction = value
        .get("direction")
        .and_then(|v| v.as_str())
        .and_then(parse_direction);
    let provider = extract_string(&value, &["provider", "vendor"]);
    let model = extract_string(&value, &["model"]);
    let method = extract_string(&value, &["method", "operation", "rpc_method"]).or_else(|| {
        value
            .get("request")
            .and_then(|v| v.get("method"))
            .and_then(|v| v.as_str())
            .map(|v| v.to_string())
    });
    let tool_name = extract_string(&value, &["tool_name", "tool"]);
    let agent = extract_string(&value, &["agent", "agent_name", "client"]);
    let request = value
        .get("request")
        .and_then(|v| serde_json::to_string(v).ok());
    let response = value
        .get("response")
        .and_then(|v| serde_json::to_string(v).ok());

    Some(ParsedLine {
        content,
        source,
        direction,
        provider,
        model,
        method,
        tool_name,
        agent,
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
    use tempfile::tempdir;

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
    fn offset_state_loads_legacy_offsets() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("collector_state.json");
        std::fs::write(&path, r#"{"offsets":{"/tmp/demo.jsonl":12345}}"#.as_bytes()).unwrap();
        let loaded = OffsetState::load(&path).unwrap();
        let file = loaded.files.get("/tmp/demo.jsonl").unwrap();
        assert_eq!(file.offset, 12345);
        assert_eq!(file.mtime, 0);
        assert!(loaded.sqlite.is_empty());
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
}
