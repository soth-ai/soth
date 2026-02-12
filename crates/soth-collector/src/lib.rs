use anyhow::Context;
use serde::{Deserialize, Serialize};
use soth_core::types::{AgentInfo, DetectionSource, EventSource, WrapDirection, WrapEvent};
use soth_core::EventLogger;
use soth_observe::PiiRedactor;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorParser {
    JsonLines,
    TextLines,
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

        let sources_raw = match std::env::var("SOTH_COLLECTOR_SOURCES") {
            Ok(v) => v,
            Err(_) => {
                warn!(
                    "SOTH_COLLECTOR_ENABLED=true but SOTH_COLLECTOR_SOURCES is empty; collector disabled"
                );
                return None;
            }
        };
        let mut sources = Vec::new();
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

        if sources.is_empty() {
            warn!("SOTH_COLLECTOR_SOURCES has no valid paths; collector disabled");
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
        })
    }
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
        sources = collector.config.sources.len(),
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
            let offset = self.offsets.offsets.get(&key).copied().unwrap_or(0);
            let outcome = collect_source_events(
                source,
                offset,
                self.config.max_read_bytes_per_source,
                self.config.max_line_bytes,
            )?;
            if outcome.next_offset != offset {
                self.offsets.offsets.insert(key, outcome.next_offset);
                state_changed = true;
            }

            for source_line in outcome.lines {
                if let Some(event) = self.build_event(source, source_line) {
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
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct OffsetState {
    #[serde(default)]
    offsets: HashMap<String, u64>,
}

impl OffsetState {
    fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read(path)?;
        let parsed = serde_json::from_slice::<Self>(&data).with_context(|| {
            format!("failed parsing collector offset state: {}", path.display())
        })?;
        Ok(parsed)
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
    next_offset: u64,
    lines: Vec<SourceLine>,
}

#[derive(Debug)]
struct SourceLine {
    content: String,
    end_offset: u64,
}

fn collect_source_events(
    source: &CollectorSource,
    start_offset: u64,
    max_read_bytes: usize,
    max_line_bytes: usize,
) -> anyhow::Result<CollectOutcome> {
    let metadata = match std::fs::metadata(&source.path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CollectOutcome {
                next_offset: 0,
                lines: Vec::new(),
            });
        }
        Err(error) => return Err(error).with_context(|| source.path.display().to_string()),
    };

    let file_len = metadata.len();
    let mut offset = start_offset;
    if file_len < offset {
        // Rotation/truncation: restart from beginning.
        offset = 0;
    }

    if file_len <= offset {
        return Ok(CollectOutcome {
            next_offset: offset,
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
            next_offset: offset,
            lines: Vec::new(),
        });
    }
    buffer.truncate(bytes_read);

    let at_eof = offset + bytes_read as u64 >= file_len;
    let (consumed_bytes, raw_lines) = extract_complete_lines(&buffer, at_eof);
    if consumed_bytes == 0 {
        return Ok(CollectOutcome {
            next_offset: offset,
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
        next_offset: offset + consumed_bytes as u64,
        lines,
    })
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
}
