//! Proxy integration primitives for the SOTH edge runtime.

use crate::normalize::{
    normalize_body, normalize_body_with_stream_parser, BundleStreamFormat, BundleStreamParser,
};
use crate::process_attribution::{
    resolve_process, AppType, ProcessIdentity, ProcessMatchKind, ProcessResolution,
};
use crate::registry::{CaptureMode, EdgeRegistry, InterceptionAction};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use futures::StreamExt;
use http_body_util::BodyExt;
use hudsucker::tokio_tungstenite::tungstenite::Message;
use regex::Regex;
use regex::RegexBuilder;
use serde_json::Value;
use soth_core::{
    config::{ExchangeConfig, ForwardProxyConfig},
    EventLogger, ExchangeBody, ExchangeBodyMode, ExchangeClient, ExchangeEvent, ExchangeFlags,
    ExchangeParse, ExchangeSourceClass, ExchangeTransport, EXCHANGE_CLIENT_APP_TYPE_HOST,
    EXCHANGE_CLIENT_APP_TYPE_NON_HOST, EXCHANGE_CLIENT_APP_TYPE_UNKNOWN,
    EXCHANGE_DECISION_OUTCOME_CAPTURED, EXCHANGE_DECISION_OUTCOME_DISCOVERY_CAPTURE,
    EXCHANGE_DECISION_OUTCOME_METADATA_ONLY, EXCHANGE_DECISION_OUTCOME_SKIPPED,
    EXCHANGE_DECISION_STEP_APP_GATE, EXCHANGE_DECISION_STEP_APP_ORIGIN,
    EXCHANGE_DECISION_STEP_URL_BLACKLIST, EXCHANGE_DECISION_STEP_WHITELIST,
    EXCHANGE_DISCOVERY_KIND_DOMAIN, EXCHANGE_SKIP_REASON_APP_NOT_ALLOWED,
    EXCHANGE_SKIP_REASON_BLACKLISTED, EXCHANGE_SKIP_REASON_NOT_WHITELISTED,
};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};
use uuid::Uuid;

#[cfg(test)]
use http_body_util::Full;

const MAX_TRACKED_WS_CONNECTIONS: usize = 4_096;
const MAX_STORED_WS_TURN_EVENTS: usize = 2_048;
const MAX_STORED_WS_UPGRADE_EVENTS: usize = 2_048;
const MAX_STORED_WS_SESSION_EVENTS: usize = 2_048;
const MAX_STORED_HTTP_EXCHANGE_EVENTS: usize = 2_048;
// TODO(soth-edge): add explicit memory budgeting/sweeper for long-lived/high-churn
// connection state (WS + pending HTTP), beyond fixed entry-count caps.
const DEFAULT_MAX_PENDING_HTTP_CAPTURES: usize = 4_096;
const DEFAULT_HTTP_CAPTURE_BODY_BYTES: usize = 1_048_576;
const TLS_PASSTHROUGH_CACHE_MAX_SIZE: usize = 1_000;
const MAX_WS_MESSAGES_PER_CONNECTION: usize = 1_000;
const REGISTRY_RELOAD_POLL_INTERVAL: Duration = Duration::from_secs(2);
const EDGE_DEFAULT_DETECTION_ID: &str = "agent.soth.app";
const EDGE_DEFAULT_DETECTION_SOURCE: &str = "bundle";

#[derive(Debug, thiserror::Error)]
pub enum EdgeProxyError {
    #[error("{0}")]
    Transport(String),
}

impl EdgeProxyError {
    fn transport(message: impl Into<String>) -> Self {
        Self::Transport(message.into())
    }
}

fn load_edge_registry(cache_path: Option<&Path>) -> Result<Arc<EdgeRegistry>, EdgeProxyError> {
    let Some(path) = cache_path else {
        return Err(EdgeProxyError::transport(
            "registry cache path not configured".to_string(),
        ));
    };

    match load_edge_registry_with_fallback(path) {
        Ok((registry, loaded_path)) => {
            if loaded_path != path {
                warn!(
                    cache = %path.display(),
                    fallback = %loaded_path.display(),
                    "Loaded edge registry from fallback local cache"
                );
            }
            Ok(Arc::new(registry))
        }
        Err(error) => Err(EdgeProxyError::transport(error)),
    }
}

fn load_edge_registry_with_fallback(path: &Path) -> Result<(EdgeRegistry, PathBuf), String> {
    let candidates = registry_cache_candidate_paths(path);
    let mut errors = Vec::new();

    for candidate in candidates {
        match EdgeRegistry::load_from_path(candidate.as_path()) {
            Ok(registry) => return Ok((registry, candidate)),
            Err(error) => errors.push(format!("{}: {}", candidate.display(), error)),
        }
    }

    Err(format!(
        "failed loading edge registry cache from any local cache candidate ({})",
        errors.join("; ")
    ))
}

fn registry_cache_last_good_path(path: &Path) -> PathBuf {
    let stem = path
        .file_stem()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "registry_bundle_cache".to_string());
    let filename = format!("{stem}.last_good.json");
    path.with_file_name(filename)
}

fn registry_cache_candidate_paths(path: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    push_unique_path(&mut candidates, path.to_path_buf());
    push_unique_path(&mut candidates, registry_cache_last_good_path(path));

    for legacy_name in [
        "registry_bundle_cache_edge.json",
        "registry_bundle_cache_proxy.json",
    ] {
        let legacy = path.with_file_name(legacy_name);
        push_unique_path(&mut candidates, legacy.clone());
        push_unique_path(
            &mut candidates,
            registry_cache_last_good_path(legacy.as_path()),
        );
    }

    candidates
}

fn push_unique_path(paths: &mut Vec<PathBuf>, candidate: PathBuf) {
    if !paths.iter().any(|path| path == &candidate) {
        paths.push(candidate);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RegistryCacheFingerprint {
    modified_unix_nanos: u128,
    file_size_bytes: u64,
}

fn registry_cache_fingerprint(path: &Path) -> Option<RegistryCacheFingerprint> {
    let metadata = std::fs::metadata(path).ok()?;
    let modified_unix_nanos = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();

    Some(RegistryCacheFingerprint {
        modified_unix_nanos,
        file_size_bytes: metadata.len(),
    })
}

fn spawn_registry_reload_task(
    detector: Arc<EdgeDetector>,
    tls_passthrough: Arc<Mutex<TlsPassthrough>>,
    edge_registry_cache_path: Option<PathBuf>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    let cache_path = edge_registry_cache_path?;
    Some(tokio::spawn(async move {
        let mut last_seen_fingerprint = registry_cache_fingerprint(cache_path.as_path());
        let mut interval = tokio::time::interval(REGISTRY_RELOAD_POLL_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    let Some(current_fingerprint) = registry_cache_fingerprint(cache_path.as_path()) else {
                        continue;
                    };

                    if last_seen_fingerprint.as_ref() == Some(&current_fingerprint) {
                        continue;
                    }
                    last_seen_fingerprint = Some(current_fingerprint);

                    match load_edge_registry_with_fallback(cache_path.as_path()) {
                        Ok((registry, loaded_path)) => {
                            let registry = Arc::new(registry);
                            let bundle_version = registry.bundle().metadata.bundle_version.clone();
                            let tls_patterns = registry.bundle().filters.domain_patterns.clone();
                            detector.replace_registry(registry);
                            {
                                let mut passthrough = lock_recover(&tls_passthrough);
                                passthrough.replace_patterns(&tls_patterns);
                            }
                            if loaded_path != cache_path {
                                warn!(
                                    cache = %cache_path.display(),
                                    fallback = %loaded_path.display(),
                                    bundle_version = bundle_version.as_str(),
                                    "Primary edge registry cache invalid; reloaded fallback local cache"
                                );
                            } else {
                                info!(
                                    cache = %cache_path.display(),
                                    bundle_version = bundle_version.as_str(),
                                    "Reloaded edge registry cache"
                                );
                            }
                        }
                        Err(error) => {
                            warn!(
                                cache = %cache_path.display(),
                                error = %error,
                                "Failed reloading edge registry cache; continuing with previous in-memory bundle"
                            );
                        }
                    }
                }
            }
        }
    }))
}

pub async fn start_proxy(
    config: ForwardProxyConfig,
    ca_cert_path: &Path,
    ca_key_path: &Path,
    edge_registry_cache_path: Option<PathBuf>,
) -> Result<(), EdgeProxyError> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let _ = shutdown_tx.send(());
    });

    start_proxy_with_shutdown(
        config,
        ca_cert_path,
        ca_key_path,
        async move {
            shutdown_rx.await.ok();
        },
        None,
        edge_registry_cache_path,
        None,
    )
    .await
}

pub async fn start_proxy_with_shutdown<F>(
    config: ForwardProxyConfig,
    ca_cert_path: &Path,
    ca_key_path: &Path,
    shutdown: F,
    event_logger: Option<EventLogger>,
    edge_registry_cache_path: Option<PathBuf>,
    exchange_config: Option<ExchangeConfig>,
) -> Result<(), EdgeProxyError>
where
    F: Future<Output = ()> + Send + 'static,
{
    let ca_cert_pem = std::fs::read_to_string(ca_cert_path)
        .map_err(|error| EdgeProxyError::transport(format!("failed to read CA cert: {error}")))?;
    let ca_key_pem = std::fs::read_to_string(ca_key_path)
        .map_err(|error| EdgeProxyError::transport(format!("failed to read CA key: {error}")))?;

    let key_pair = hudsucker::rcgen::KeyPair::from_pem(&ca_key_pem)
        .map_err(|error| EdgeProxyError::transport(format!("failed to parse CA key: {error}")))?;
    let issuer =
        hudsucker::rcgen::Issuer::from_ca_cert_pem(&ca_cert_pem, key_pair).map_err(|error| {
            EdgeProxyError::transport(format!("failed to create CA issuer: {error}"))
        })?;
    let ca = hudsucker::certificate_authority::RcgenAuthority::new(
        issuer,
        1000,
        hudsucker::rustls::crypto::aws_lc_rs::default_provider(),
    );

    let listen_addr: SocketAddr = config
        .socket_addr()
        .parse()
        .map_err(|error| EdgeProxyError::transport(format!("invalid listen address: {error}")))?;

    {
        let preflight = std::net::TcpListener::bind(listen_addr).map_err(|error| {
            EdgeProxyError::transport(format!(
                "edge proxy preflight bind failed on {}: {}",
                listen_addr, error
            ))
        })?;
        drop(preflight);
    }

    let registry = load_edge_registry(edge_registry_cache_path.as_deref())?;
    let detector = Arc::new(EdgeDetector::new(registry.clone()));
    let process_lookup = crate::process_attribution::ProcessAttribution::new(
        config.process_attribution.enabled,
        config.process_attribution.lookup_timeout,
        config.process_attribution.cache_ttl,
    );
    let mut handler = HudsuckerDetectionHandler::new(detector, process_lookup);
    let capture_limit = usize::try_from(config.capture_max_body_bytes).unwrap_or(usize::MAX);
    handler.set_http_capture_body_limit(capture_limit);
    if let Some(exchange_cfg) = exchange_config.as_ref() {
        handler.set_max_pending_http_captures(exchange_cfg.spool_max_inflight);
    }

    // Edge learned passthrough stays opt-out by default.
    handler.set_tls_passthrough_enabled(false);

    if let Some(logger) = event_logger {
        handler = handler.with_edge_queue_writer(Arc::new(EdgeQueueWriter::new(logger)));
    }

    let mut server = hudsucker::hyper_util::server::conn::auto::Builder::new(
        hudsucker::hyper_util::rt::TokioExecutor::new(),
    );
    server
        .http1()
        .max_headers(512)
        .max_buf_size(1024 * 1024)
        .title_case_headers(true)
        .preserve_header_case(true);
    if config.tls.http2_enabled {
        server
            .http2()
            .max_header_list_size(config.tls.http2_max_header_list_size);
    }

    info!("Starting soth-edge proxy on {}", listen_addr);
    info!("  Engine -> edge");
    info!("  Host filtering mode -> {}", config.hosts.mode);
    info!("  Registry mode -> {}", config.registry_mode);

    let (reload_shutdown_tx, reload_shutdown_rx) = tokio::sync::watch::channel(false);
    let reload_task = spawn_registry_reload_task(
        handler.detector.clone(),
        handler.tls_passthrough.clone(),
        edge_registry_cache_path,
        reload_shutdown_rx,
    );
    let reload_shutdown_for_proxy = reload_shutdown_tx.clone();
    let graceful_shutdown = async move {
        shutdown.await;
        let _ = reload_shutdown_for_proxy.send(true);
    };

    let proxy = hudsucker::Proxy::builder()
        .with_addr(listen_addr)
        .with_ca(ca)
        .with_rustls_connector(hudsucker::rustls::crypto::aws_lc_rs::default_provider())
        .with_upstream_cert_sniffing(true)
        .with_server(server)
        .with_http_handler(handler.clone())
        .with_websocket_handler(handler)
        .with_graceful_shutdown(graceful_shutdown)
        .build()
        .map_err(|error| {
            EdgeProxyError::transport(format!("failed to build edge proxy runtime: {error}"))
        })?;

    let start_result = proxy.start().await;
    let _ = reload_shutdown_tx.send(true);
    if let Some(reload_task) = reload_task {
        let _ = reload_task.await;
    }

    start_result.map_err(|error| {
        EdgeProxyError::transport(format!(
            "edge proxy start failed on {}: {}",
            listen_addr, error
        ))
    })?;

    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrafficClassification {
    ToolUsage,
    UnknownAgent,
    ApplicationUsage,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecisionReason {
    Allowed,
    ProcessAction,
    NotInCatalog,
    UnknownAppPolicy,
    Blacklisted,
    HostOriginNotAllowed,
    CaptureDisabled,
    MethodNotAllowed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectionOutcome {
    pub action: InterceptionAction,
    pub reason: DecisionReason,
    pub classification: TrafficClassification,
    pub capture_mode: CaptureMode,
    pub process: ProcessResolution,
    pub discovery_capture: bool,
    pub blacklisted_keyword: Option<String>,
    pub matched_provider: Option<String>,
    pub matched_application: Option<String>,
    pub response_stream_parser: Option<BundleStreamParser>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebSocketDirection {
    ClientToServer,
    ServerToClient,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebSocketTurnMessage {
    pub direction: WebSocketDirection,
    pub timestamp_ms: u64,
    pub content: String,
    pub is_text: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebSocketTurnEvent {
    pub connection_id: String,
    pub host: String,
    pub path: String,
    pub classification: TrafficClassification,
    pub message_count: usize,
    pub messages: Vec<WebSocketTurnMessage>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebSocketUpgradeEvent {
    pub timestamp_ms: u64,
    pub method: String,
    pub host: String,
    pub path: String,
    pub action: InterceptionAction,
    pub reason: DecisionReason,
    pub classification: TrafficClassification,
    pub capture_mode: CaptureMode,
    pub discovery_capture: bool,
    pub blacklisted_keyword: Option<String>,
    pub matched_provider: Option<String>,
    pub matched_application: Option<String>,
    pub request_headers: HashMap<String, String>,
    pub response_status: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebSocketSessionEvent {
    pub connection_id: String,
    pub host: String,
    pub path: String,
    pub classification: TrafficClassification,
    pub started_at_ms: u64,
    pub ended_at_ms: u64,
    pub duration_ms: u64,
    pub message_count: usize,
    pub messages: Vec<WebSocketTurnMessage>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpExchangeEvent {
    pub exchange_id: String,
    pub request_id: String,
    pub timestamp_ms: u64,
    pub request_is_http2: bool,
    pub method: String,
    pub host: String,
    pub path: String,
    pub detection_id: String,
    pub action: InterceptionAction,
    pub reason: DecisionReason,
    pub classification: TrafficClassification,
    pub capture_mode: CaptureMode,
    pub discovery_capture: bool,
    pub blacklisted_keyword: Option<String>,
    pub matched_provider: Option<String>,
    pub matched_application: Option<String>,
    pub client_bundle_id: Option<String>,
    pub client_process_name: Option<String>,
    pub response_stream_parser: Option<BundleStreamParser>,
    pub request_headers: HashMap<String, String>,
    pub request_body: Option<String>,
    pub request_body_base64: bool,
    pub request_body_truncated: bool,
    pub request_body_error: Option<String>,
    pub response_status: u16,
    pub response_headers: HashMap<String, String>,
    pub response_body: Option<String>,
    pub response_body_base64: bool,
    pub response_body_truncated: bool,
    pub response_body_error: Option<String>,
}

#[derive(Clone)]
pub struct EdgeQueueWriter {
    logger: EventLogger,
}

impl EdgeQueueWriter {
    pub fn new(logger: EventLogger) -> Self {
        Self { logger }
    }

    fn seed_http_exchange_spool(&self, pending: &PendingHttpCapture) -> std::io::Result<()> {
        let snapshot = serde_json::json!({
            "exchange_id": pending.exchange_id,
            "request_id": pending.request_id,
            "status": "inflight",
            "detection_id": pending.detection_id,
            "method": pending.method,
            "host": pending.host,
            "path": pending.path,
            "started_at_ms": pending.started_at_ms,
            "request_is_http2": pending.request_is_http2,
            "capture_mode": capture_mode_label(&pending.capture_mode),
            "discovery_capture": pending.discovery_capture,
            "matched_provider": pending.matched_provider,
            "matched_application": pending.matched_application,
            "client_bundle_id": pending.client_bundle_id,
            "client_process_name": pending.client_process_name,
        });
        let snapshot_json = serde_json::to_string(&snapshot).map_err(|error| {
            std::io::Error::other(format!("serialize edge exchange spool snapshot: {error}"))
        })?;
        let started_at = pending.started_at_ms.to_string();
        self.logger.upsert_exchange_spool(
            pending.exchange_id.as_str(),
            snapshot_json.as_str(),
            started_at.as_str(),
        )
    }

    pub fn enqueue_http_exchange(
        &self,
        event: &HttpExchangeEvent,
        bundle_version: Option<&str>,
    ) -> std::io::Result<()> {
        let exchange = exchange_event_from_http_event(event, bundle_version);
        let payload_json = serde_json::to_string(&exchange)
            .map_err(|error| std::io::Error::other(format!("serialize edge exchange: {error}")))?;
        self.logger.enqueue_exchange_upload_with_blobs(
            exchange.exchange_id.as_str(),
            payload_json.as_str(),
            None,
        )?;
        let _ = self
            .logger
            .finalize_exchange_spool(exchange.exchange_id.as_str(), Some(payload_json.as_str()));
        let _ = self
            .logger
            .delete_exchange_spool(exchange.exchange_id.as_str());
        Ok(())
    }

    pub fn clear_http_exchange_spool(&self, exchange_id: &str) {
        let _ = self.logger.delete_exchange_spool(exchange_id);
    }
}

#[derive(Clone, Debug, Default)]
pub struct WebSocketTurnAggregator {
    sessions: HashMap<String, WebSocketTurnSession>,
}

#[derive(Clone, Debug, Default)]
pub struct WebSocketSessionAggregator {
    sessions: HashMap<String, WebSocketConnectionSession>,
}

#[derive(Clone, Debug)]
struct WebSocketTurnSession {
    host: String,
    path: String,
    classification: TrafficClassification,
    messages: Vec<WebSocketTurnMessage>,
}

#[derive(Clone, Debug)]
struct WebSocketConnectionSession {
    host: String,
    path: String,
    classification: TrafficClassification,
    started_at_ms: u64,
    messages: Vec<WebSocketTurnMessage>,
}

impl WebSocketTurnAggregator {
    pub fn push_message(
        &mut self,
        connection_id: &str,
        host: &str,
        path: &str,
        classification: TrafficClassification,
        direction: WebSocketDirection,
        content: String,
        is_text: bool,
        timestamp_ms: u64,
    ) -> Option<WebSocketTurnEvent> {
        let session = self
            .sessions
            .entry(connection_id.to_string())
            .or_insert_with(|| WebSocketTurnSession {
                host: host.to_string(),
                path: path.to_string(),
                classification,
                messages: Vec::new(),
            });

        session.host = host.to_string();
        session.path = path.to_string();
        session.classification = classification;
        session.messages.push(WebSocketTurnMessage {
            direction,
            timestamp_ms,
            content: content.clone(),
            is_text,
        });

        if direction == WebSocketDirection::ServerToClient && is_ws_turn_complete_payload(&content)
        {
            return self.flush_connection(connection_id);
        }

        None
    }

    pub fn flush_connection(&mut self, connection_id: &str) -> Option<WebSocketTurnEvent> {
        let session = self.sessions.remove(connection_id)?;
        if session.messages.is_empty() {
            return None;
        }

        let message_count = session.messages.len();
        Some(WebSocketTurnEvent {
            connection_id: connection_id.to_string(),
            host: session.host,
            path: session.path,
            classification: session.classification,
            message_count,
            messages: session.messages,
        })
    }
}

impl WebSocketSessionAggregator {
    pub fn push_message(
        &mut self,
        connection_id: &str,
        host: &str,
        path: &str,
        classification: TrafficClassification,
        direction: WebSocketDirection,
        content: String,
        is_text: bool,
        timestamp_ms: u64,
    ) {
        let session = self
            .sessions
            .entry(connection_id.to_string())
            .or_insert_with(|| WebSocketConnectionSession {
                host: host.to_string(),
                path: path.to_string(),
                classification,
                started_at_ms: timestamp_ms,
                messages: Vec::new(),
            });

        session.host = host.to_string();
        session.path = path.to_string();
        session.classification = classification;

        if session.messages.len() >= MAX_WS_MESSAGES_PER_CONNECTION {
            let overflow = session.messages.len() - MAX_WS_MESSAGES_PER_CONNECTION + 1;
            session.messages.drain(0..overflow);
        }

        session.messages.push(WebSocketTurnMessage {
            direction,
            timestamp_ms,
            content,
            is_text,
        });
    }

    pub fn flush_connection(
        &mut self,
        connection_id: &str,
        ended_at_ms: u64,
    ) -> Option<WebSocketSessionEvent> {
        let session = self.sessions.remove(connection_id)?;
        if session.messages.is_empty() {
            return None;
        }

        let message_count = session.messages.len();
        Some(WebSocketSessionEvent {
            connection_id: connection_id.to_string(),
            host: session.host,
            path: session.path,
            classification: session.classification,
            started_at_ms: session.started_at_ms,
            ended_at_ms,
            duration_ms: ended_at_ms.saturating_sub(session.started_at_ms),
            message_count,
            messages: session.messages,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EdgeRequest {
    pub method: String,
    pub host: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub process: ProcessIdentity,
}

impl EdgeRequest {
    pub fn new(
        method: impl Into<String>,
        host: impl Into<String>,
        path: impl Into<String>,
        process: ProcessIdentity,
    ) -> Self {
        Self {
            method: method.into(),
            host: host.into(),
            path: path.into(),
            headers: HashMap::new(),
            process,
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .insert(name.into().to_ascii_lowercase(), value.into());
        self
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    pub fn normalized_host(&self) -> String {
        parse_host_from_authority(&self.host).unwrap_or_else(|| self.host.to_ascii_lowercase())
    }

    pub fn normalized_path(&self) -> String {
        crate::registry::normalize_path(&self.path)
    }
}

#[derive(Clone, Debug)]
pub struct EdgeDetector {
    registry: Arc<RwLock<Arc<EdgeRegistry>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DetectionStage {
    Connect,
    HttpRequest,
}

impl EdgeDetector {
    pub fn new(registry: Arc<EdgeRegistry>) -> Self {
        Self {
            registry: Arc::new(RwLock::new(registry)),
        }
    }

    pub fn registry(&self) -> Arc<EdgeRegistry> {
        read_lock_recover(&self.registry).clone()
    }

    pub fn replace_registry(&self, registry: Arc<EdgeRegistry>) {
        *write_lock_recover(&self.registry) = registry;
    }

    pub fn evaluate(&self, request: &EdgeRequest) -> DetectionOutcome {
        self.evaluate_for_stage(request, DetectionStage::HttpRequest)
    }

    fn evaluate_for_stage(&self, request: &EdgeRequest, stage: DetectionStage) -> DetectionOutcome {
        let registry = self.registry();
        let process = resolve_process(&request.process, registry.as_ref());

        if process.match_kind != ProcessMatchKind::Unknown && !is_intercept_action(process.action) {
            return DetectionOutcome {
                action: process.action,
                reason: DecisionReason::ProcessAction,
                classification: TrafficClassification::Other,
                capture_mode: CaptureMode::MetadataOnly,
                process,
                discovery_capture: false,
                blacklisted_keyword: None,
                matched_provider: None,
                matched_application: None,
                response_stream_parser: None,
            };
        }

        let host = request.normalized_host();
        let path = request.normalized_path();
        let url = format!("{host}{path}");

        let in_catalog = registry.in_ai_catalog(&host);
        let referer_origin = extract_origin_host(request.header("referer"));

        let discovery_capture = !in_catalog
            && process.app_type == AppType::Host
            && referer_origin
                .as_deref()
                .is_some_and(|origin| registry.in_ai_catalog(origin));

        if !in_catalog && !discovery_capture {
            return DetectionOutcome {
                action: registry.non_whitelisted_host_action(),
                reason: DecisionReason::NotInCatalog,
                classification: TrafficClassification::Other,
                capture_mode: CaptureMode::MetadataOnly,
                process,
                discovery_capture: false,
                blacklisted_keyword: None,
                matched_provider: None,
                matched_application: None,
                response_stream_parser: None,
            };
        }

        if process.match_kind == ProcessMatchKind::Unknown && in_catalog {
            let action = registry.whitelisted_unknown_app_action();
            if !is_intercept_action(action) {
                return DetectionOutcome {
                    action,
                    reason: DecisionReason::UnknownAppPolicy,
                    classification: TrafficClassification::Other,
                    capture_mode: CaptureMode::MetadataOnly,
                    process,
                    discovery_capture,
                    blacklisted_keyword: None,
                    matched_provider: None,
                    matched_application: None,
                    response_stream_parser: None,
                };
            }
        }

        if let Some(keyword) = registry.find_blacklisted_keyword(&url) {
            return DetectionOutcome {
                action: InterceptionAction::Skip,
                reason: DecisionReason::Blacklisted,
                classification: TrafficClassification::Other,
                capture_mode: CaptureMode::MetadataOnly,
                process,
                discovery_capture,
                blacklisted_keyword: Some(keyword.to_string()),
                matched_provider: None,
                matched_application: None,
                response_stream_parser: None,
            };
        }

        if matches!(stage, DetectionStage::HttpRequest)
            && process.requires_host_origin_check()
            && !discovery_capture
        {
            let request_origin = extract_origin_host(request.header("origin"))
                .or_else(|| extract_origin_host(request.header("referer")));

            let allowed = request_origin
                .as_deref()
                .is_some_and(|origin| registry.in_ai_catalog(origin));

            if !allowed {
                return DetectionOutcome {
                    action: InterceptionAction::Skip,
                    reason: DecisionReason::HostOriginNotAllowed,
                    classification: TrafficClassification::Other,
                    capture_mode: CaptureMode::MetadataOnly,
                    process,
                    discovery_capture,
                    blacklisted_keyword: None,
                    matched_provider: None,
                    matched_application: None,
                    response_stream_parser: None,
                };
            }
        }

        let provider = registry.match_provider(&host, &path, &request.method.to_ascii_uppercase());
        let application =
            registry.match_application(&host, &path, &request.method.to_ascii_uppercase());

        let primary = provider.as_ref().or(application.as_ref());

        if let Some(matched) = primary {
            let response_stream_parser = registry.stream_parser_for_match(matched);
            if !matched.capture_enabled {
                return DetectionOutcome {
                    action: InterceptionAction::Skip,
                    reason: DecisionReason::CaptureDisabled,
                    classification: TrafficClassification::Other,
                    capture_mode: CaptureMode::MetadataOnly,
                    process,
                    discovery_capture,
                    blacklisted_keyword: None,
                    matched_provider: provider.as_ref().map(|rule| rule.id.clone()),
                    matched_application: application.as_ref().map(|rule| rule.id.clone()),
                    response_stream_parser,
                };
            }

            if !matched.method_allowed {
                return DetectionOutcome {
                    action: InterceptionAction::Skip,
                    reason: DecisionReason::MethodNotAllowed,
                    classification: TrafficClassification::Other,
                    capture_mode: CaptureMode::MetadataOnly,
                    process,
                    discovery_capture,
                    blacklisted_keyword: None,
                    matched_provider: provider.as_ref().map(|rule| rule.id.clone()),
                    matched_application: application.as_ref().map(|rule| rule.id.clone()),
                    response_stream_parser,
                };
            }
        }

        let classification = if provider.is_some() {
            if process.is_known_non_host_app() {
                TrafficClassification::ToolUsage
            } else {
                TrafficClassification::UnknownAgent
            }
        } else if application.is_some() {
            TrafficClassification::ApplicationUsage
        } else {
            TrafficClassification::Other
        };

        let mut capture_mode = process
            .capture_mode
            .clone()
            .unwrap_or(CaptureMode::MetadataOnly);
        if let Some(matched) = primary {
            capture_mode = matched.capture_mode.clone();
        }
        if discovery_capture {
            capture_mode = CaptureMode::MetadataOnly;
        }

        let response_stream_parser =
            primary.and_then(|matched| registry.stream_parser_for_match(matched));

        DetectionOutcome {
            action: InterceptionAction::Intercept,
            reason: DecisionReason::Allowed,
            classification,
            capture_mode,
            process,
            discovery_capture,
            blacklisted_keyword: None,
            matched_provider: provider.as_ref().map(|rule| rule.id.clone()),
            matched_application: application.as_ref().map(|rule| rule.id.clone()),
            response_stream_parser,
        }
    }
}

fn is_intercept_action(action: InterceptionAction) -> bool {
    matches!(
        action,
        InterceptionAction::Intercept | InterceptionAction::Block
    )
}

fn parse_host_from_authority(authority: &str) -> Option<String> {
    let trimmed = authority.trim();
    if trimmed.is_empty() {
        return None;
    }

    let no_scheme = if let Some(idx) = trimmed.find("://") {
        &trimmed[idx + 3..]
    } else if let Some(rest) = trimmed.strip_prefix("//") {
        rest
    } else {
        trimmed
    };

    let host_port = no_scheme.split('/').next().unwrap_or_default();
    let host_port = host_port.rsplit('@').next().unwrap_or(host_port);

    if host_port.is_empty() {
        return None;
    }

    let host = if host_port.starts_with('[') {
        // IPv6 literal: [::1]:443
        let end = host_port.find(']')?;
        host_port[1..end].to_string()
    } else {
        host_port.split(':').next().unwrap_or_default().to_string()
    };

    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

fn extract_origin_host(header_value: Option<&str>) -> Option<String> {
    let raw = header_value?.trim();
    if raw.is_empty() {
        return None;
    }

    parse_host_from_authority(raw)
}

fn websocket_connection_key(client_addr: SocketAddr, host: &str, path: &str) -> String {
    let host = host.to_ascii_lowercase();
    let path = crate::registry::normalize_path(path);
    format!("{client_addr}|{host}{path}")
}

fn websocket_host_key(client_addr: SocketAddr, host: &str) -> String {
    format!("{client_addr}|{}", host.to_ascii_lowercase())
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
}

fn is_websocket_upgrade_request(req: &hudsucker::hyper::Request<hudsucker::Body>) -> bool {
    let upgrade = req
        .headers()
        .get(hudsucker::hyper::header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();

    let connection = req
        .headers()
        .get(hudsucker::hyper::header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();

    let has_upgrade_token = connection
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));

    let has_ws_key = req
        .headers()
        .contains_key(hudsucker::hyper::header::SEC_WEBSOCKET_KEY);

    upgrade.eq_ignore_ascii_case("websocket") || (has_upgrade_token && has_ws_key)
}

#[derive(Clone, Debug, Default)]
struct TlsPassthrough {
    patterns: Vec<Regex>,
    learned_hosts: HashSet<String>,
    result_cache: HashMap<String, bool>,
    cache_order: VecDeque<String>,
}

impl TlsPassthrough {
    fn from_patterns(patterns: &[String]) -> Self {
        Self {
            patterns: compile_tls_passthrough_patterns(patterns),
            learned_hosts: HashSet::new(),
            result_cache: HashMap::new(),
            cache_order: VecDeque::new(),
        }
    }

    fn replace_patterns(&mut self, patterns: &[String]) {
        self.patterns = compile_tls_passthrough_patterns(patterns);
        self.result_cache.clear();
        self.cache_order.clear();
    }

    fn should_passthrough(&mut self, host: &str) -> bool {
        let normalized = host.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return false;
        }

        if let Some(cached) = self.result_cache.get(&normalized).copied() {
            self.touch_cache_key(&normalized);
            return cached;
        }

        let matched = self.learned_hosts.contains(&normalized)
            || self
                .patterns
                .iter()
                .any(|pattern| pattern.is_match(&normalized));

        self.insert_cache(normalized, matched);
        matched
    }

    fn learned_hosts(&self) -> Vec<String> {
        let mut hosts = self.learned_hosts.iter().cloned().collect::<Vec<_>>();
        hosts.sort();
        hosts
    }

    fn add_host(&mut self, host: &str) {
        let normalized = host.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return;
        }

        self.learned_hosts.insert(normalized);
        self.result_cache.clear();
        self.cache_order.clear();
    }

    fn record_tls_failure(&mut self, host: &str, error: &str, whitelisted: bool) {
        if whitelisted {
            return;
        }

        let indicators = [
            "certificate verify failed",
            "unknown ca",
            "bad certificate",
            "certificate_unknown",
            "self signed certificate",
            "client disconnected during the handshake",
            "certificate pinning",
            "handshake failure",
        ];

        let lower_error = error.to_ascii_lowercase();
        if indicators
            .iter()
            .any(|indicator| lower_error.contains(indicator))
        {
            self.add_host(host);
        }
    }

    fn touch_cache_key(&mut self, key: &str) {
        if let Some(pos) = self.cache_order.iter().position(|entry| entry == key) {
            self.cache_order.remove(pos);
        }
        self.cache_order.push_back(key.to_string());
    }

    fn insert_cache(&mut self, key: String, value: bool) {
        self.result_cache.insert(key.clone(), value);
        self.touch_cache_key(&key);

        while self.result_cache.len() > TLS_PASSTHROUGH_CACHE_MAX_SIZE {
            if let Some(oldest) = self.cache_order.pop_front() {
                self.result_cache.remove(&oldest);
            } else {
                break;
            }
        }
    }
}

fn compile_tls_passthrough_patterns(patterns: &[String]) -> Vec<Regex> {
    let mut compiled = Vec::new();

    for pattern in patterns {
        if pattern.trim().is_empty() {
            continue;
        }

        if let Ok(regex) = RegexBuilder::new(pattern).case_insensitive(true).build() {
            compiled.push(regex);
        }
    }

    compiled
}

#[derive(Clone, Debug)]
struct WebSocketCaptureDecision {
    capture: bool,
    classification: TrafficClassification,
    host: String,
    path: String,
}

#[derive(Clone, Debug)]
struct PendingHttpCapture {
    exchange_id: String,
    request_id: String,
    started_at_ms: u64,
    request_is_http2: bool,
    method: String,
    host: String,
    path: String,
    detection_id: String,
    action: InterceptionAction,
    reason: DecisionReason,
    classification: TrafficClassification,
    capture_mode: CaptureMode,
    discovery_capture: bool,
    blacklisted_keyword: Option<String>,
    matched_provider: Option<String>,
    matched_application: Option<String>,
    client_bundle_id: Option<String>,
    client_process_name: Option<String>,
    response_stream_parser: Option<BundleStreamParser>,
    request_headers: HashMap<String, String>,
    request_body: Option<String>,
    request_body_base64: bool,
    request_body_truncated: bool,
    request_body_error: Option<String>,
}

#[derive(Clone, Debug)]
struct WebSocketContextInfo {
    client_addr: SocketAddr,
    host: String,
    path: String,
    direction: WebSocketDirection,
    connection_key: String,
    host_key: String,
}

fn websocket_context_info(ctx: &hudsucker::WebSocketContext) -> Option<WebSocketContextInfo> {
    let direction = if matches!(ctx, hudsucker::WebSocketContext::ClientToServer { .. }) {
        WebSocketDirection::ClientToServer
    } else {
        WebSocketDirection::ServerToClient
    };

    let debug_repr = format!("{ctx:?}");
    let (src, dst) = parse_websocket_context_endpoints(&debug_repr)?;

    let src_addr = src.parse::<SocketAddr>().ok();
    let dst_addr = dst.parse::<SocketAddr>().ok();

    let (client_addr, uri_raw) = match (src_addr, dst_addr) {
        (Some(addr), None) => (addr, dst.as_str()),
        (None, Some(addr)) => (addr, src.as_str()),
        (Some(addr), Some(_)) => (addr, dst.as_str()),
        (None, None) => return None,
    };

    let (host, path) = parse_ws_host_and_path(uri_raw)?;
    let connection_key = websocket_connection_key(client_addr, &host, &path);
    let host_key = websocket_host_key(client_addr, &host);

    Some(WebSocketContextInfo {
        client_addr,
        host,
        path,
        direction,
        connection_key,
        host_key,
    })
}

fn parse_websocket_context_endpoints(debug_repr: &str) -> Option<(String, String)> {
    let src_marker = "src: ";
    let dst_marker = ", dst: ";

    let src_start = debug_repr.find(src_marker)? + src_marker.len();
    let dst_split = debug_repr[src_start..].find(dst_marker)?;
    let src_end = src_start + dst_split;

    let tail = &debug_repr[src_end + dst_marker.len()..];
    let tail_end = tail.rfind('}')?;

    let src = debug_repr[src_start..src_end].trim().to_string();
    let dst = tail[..tail_end].trim().to_string();

    if src.is_empty() || dst.is_empty() {
        None
    } else {
        Some((src, dst))
    }
}

fn parse_ws_host_and_path(uri_raw: &str) -> Option<(String, String)> {
    let trimmed = uri_raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(uri) = trimmed.parse::<hudsucker::hyper::Uri>() {
        if let Some(host) = uri.host() {
            let path = uri.path_and_query().map_or("/", |pq| pq.as_str());
            return Some((
                host.to_ascii_lowercase(),
                crate::registry::normalize_path(path),
            ));
        }

        if let Some(authority) = uri.authority() {
            let host = parse_host_from_authority(authority.as_str())?;
            let path = uri.path_and_query().map_or("/", |pq| pq.as_str());
            return Some((host, crate::registry::normalize_path(path)));
        }
    }

    let host = parse_host_from_authority(trimmed)?;

    let no_scheme = if let Some(idx) = trimmed.find("://") {
        &trimmed[idx + 3..]
    } else {
        trimmed
    };

    let path = if let Some(idx) = no_scheme.find('/') {
        &no_scheme[idx..]
    } else {
        "/"
    };

    Some((host, crate::registry::normalize_path(path)))
}

fn websocket_message_content(message: &Message) -> (String, bool) {
    match message {
        Message::Text(text) => (normalize_body(text.as_bytes(), None), true),
        Message::Binary(bytes) => (normalize_body(bytes.as_ref(), None), false),
        Message::Ping(payload) => (
            serde_json::json!({
                "type": "ping",
                "payload_base64": BASE64_STANDARD.encode(payload.as_ref())
            })
            .to_string(),
            false,
        ),
        Message::Pong(payload) => (
            serde_json::json!({
                "type": "pong",
                "payload_base64": BASE64_STANDARD.encode(payload.as_ref())
            })
            .to_string(),
            false,
        ),
        Message::Close(frame) => {
            let value = match frame {
                Some(frame) => serde_json::json!({
                    "type": "close",
                    "code": u16::from(frame.code),
                    "reason": frame.reason.to_string(),
                }),
                None => serde_json::json!({ "type": "close" }),
            };

            (value.to_string(), false)
        }
        _ => (serde_json::json!({ "type": "frame" }).to_string(), false),
    }
}

fn is_ws_turn_complete_payload(content: &str) -> bool {
    let trimmed = content.trim();
    if trimmed == "[DONE]" {
        return true;
    }

    let Ok(data) = serde_json::from_str::<Value>(trimmed) else {
        return false;
    };

    let Some(obj) = data.as_object() else {
        return false;
    };

    let msg_type = obj
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();

    if matches!(msg_type.as_str(), "ping" | "pong" | "heartbeat" | "ack") {
        return false;
    }

    let stream_id = obj
        .get("streamId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();

    if stream_id == "heartbeat" {
        return false;
    }

    let completion_values = [
        "done",
        "end",
        "complete",
        "message_stop",
        "finished",
        "stop",
        "final",
    ];

    for field in ["event", "type"] {
        if let Some(value) = obj.get(field).and_then(Value::as_str) {
            let value = value.to_ascii_lowercase();
            if completion_values.contains(&value.as_str()) {
                return true;
            }
        }
    }

    for field in [
        "finished",
        "done",
        "complete",
        "is_finished",
        "is_final",
        "is_done",
    ] {
        if obj.get(field).and_then(Value::as_bool) == Some(true) {
            return true;
        }
    }

    if obj.get("data").and_then(Value::as_str) == Some("[DONE]") {
        return true;
    }

    if let Some(payload) = obj.get("payload").and_then(Value::as_object) {
        if payload.get("ok").and_then(Value::as_bool) == Some(true) {
            if let Some(inner_payload) = payload.get("payload").and_then(Value::as_object) {
                if let Some(inner_type) = inner_payload.get("type").and_then(Value::as_str) {
                    let inner_type = inner_type.to_ascii_lowercase();
                    if completion_values.contains(&inner_type.as_str()) {
                        return true;
                    }
                }

                if inner_payload.get("done").and_then(Value::as_bool) == Some(true)
                    || inner_payload.get("finished").and_then(Value::as_bool) == Some(true)
                {
                    return true;
                }
            }
        }

        if let Some(payload_type) = payload.get("type").and_then(Value::as_str) {
            let payload_type = payload_type.to_ascii_lowercase();
            if completion_values.contains(&payload_type.as_str()) {
                return true;
            }
        }

        if let Some(payload_status) = payload.get("status").and_then(Value::as_str) {
            let payload_status = payload_status.to_ascii_lowercase();
            if matches!(
                payload_status.as_str(),
                "done" | "complete" | "finished" | "success" | "ok"
            ) {
                return true;
            }
        }
    }

    if let Some(control_flags) = obj.get("controlFlags").and_then(Value::as_i64) {
        if control_flags > 0 && !stream_id.is_empty() && stream_id != "heartbeat" {
            if matches!(
                control_flags,
                2 | 3 | 4 | 5 | 6 | 7 | 10 | 11 | 12 | 13 | 14 | 15
            ) {
                return true;
            }
        }
    }

    if let Some(status) = obj.get("status").and_then(Value::as_object) {
        if status.get("ok").and_then(Value::as_bool) == Some(true) {
            return true;
        }

        if status
            .get("code")
            .and_then(Value::as_str)
            .is_some_and(|value| value.eq_ignore_ascii_case("OK"))
        {
            return true;
        }
    }

    false
}

pub trait ProcessLookup: Clone + Send + Sync + 'static {
    fn resolve(&self, client_addr: SocketAddr) -> ProcessIdentity;
}

#[derive(Clone, Debug, Default)]
pub struct NoopProcessLookup;

impl ProcessLookup for NoopProcessLookup {
    fn resolve(&self, _client_addr: SocketAddr) -> ProcessIdentity {
        ProcessIdentity::default()
    }
}

impl ProcessLookup for crate::process_attribution::ProcessAttribution {
    fn resolve(&self, client_addr: SocketAddr) -> ProcessIdentity {
        self.resolve_process(client_addr)
    }
}

#[derive(Clone)]
pub struct HudsuckerDetectionHandler<L: ProcessLookup = NoopProcessLookup> {
    detector: Arc<EdgeDetector>,
    process_lookup: L,
    tls_passthrough: Arc<Mutex<TlsPassthrough>>,
    tls_passthrough_enabled: Arc<Mutex<bool>>,
    websocket_decisions: Arc<Mutex<HashMap<String, WebSocketCaptureDecision>>>,
    websocket_turn_aggregator: Arc<Mutex<WebSocketTurnAggregator>>,
    websocket_session_aggregator: Arc<Mutex<WebSocketSessionAggregator>>,
    websocket_upgrade_events: Arc<Mutex<Vec<WebSocketUpgradeEvent>>>,
    websocket_turn_events: Arc<Mutex<Vec<WebSocketTurnEvent>>>,
    websocket_session_events: Arc<Mutex<Vec<WebSocketSessionEvent>>>,
    http_exchange_events: Arc<Mutex<Vec<HttpExchangeEvent>>>,
    pending_http_captures: Arc<Mutex<HashMap<String, PendingHttpCapture>>>,
    pending_http_capture_order: Arc<Mutex<VecDeque<String>>>,
    active_http_request_id: Option<String>,
    http_request_sequence: Arc<AtomicU64>,
    max_pending_http_captures: usize,
    max_http_capture_body_bytes: usize,
    edge_queue_writer: Option<Arc<EdgeQueueWriter>>,
}

impl<L: ProcessLookup> HudsuckerDetectionHandler<L> {
    pub fn new(detector: Arc<EdgeDetector>, process_lookup: L) -> Self {
        let tls_patterns = detector.registry().bundle().filters.domain_patterns.clone();
        Self {
            detector,
            process_lookup,
            tls_passthrough: Arc::new(Mutex::new(TlsPassthrough::from_patterns(&tls_patterns))),
            tls_passthrough_enabled: Arc::new(Mutex::new(false)),
            websocket_decisions: Arc::new(Mutex::new(HashMap::new())),
            websocket_turn_aggregator: Arc::new(Mutex::new(WebSocketTurnAggregator::default())),
            websocket_session_aggregator: Arc::new(Mutex::new(
                WebSocketSessionAggregator::default(),
            )),
            websocket_upgrade_events: Arc::new(Mutex::new(Vec::new())),
            websocket_turn_events: Arc::new(Mutex::new(Vec::new())),
            websocket_session_events: Arc::new(Mutex::new(Vec::new())),
            http_exchange_events: Arc::new(Mutex::new(Vec::new())),
            pending_http_captures: Arc::new(Mutex::new(HashMap::new())),
            pending_http_capture_order: Arc::new(Mutex::new(VecDeque::new())),
            active_http_request_id: None,
            http_request_sequence: Arc::new(AtomicU64::new(1)),
            max_pending_http_captures: DEFAULT_MAX_PENDING_HTTP_CAPTURES,
            max_http_capture_body_bytes: DEFAULT_HTTP_CAPTURE_BODY_BYTES,
            edge_queue_writer: None,
        }
    }

    pub fn with_edge_queue_writer(mut self, writer: Arc<EdgeQueueWriter>) -> Self {
        self.edge_queue_writer = Some(writer);
        self
    }

    pub fn set_edge_queue_writer(&mut self, writer: Option<Arc<EdgeQueueWriter>>) {
        self.edge_queue_writer = writer;
    }

    pub fn set_http_capture_body_limit(&mut self, max_bytes: usize) {
        self.max_http_capture_body_bytes = max_bytes.max(1);
    }

    pub fn set_max_pending_http_captures(&mut self, max_pending: usize) {
        self.max_pending_http_captures = max_pending.max(1);
    }

    pub fn drain_websocket_upgrade_events(&self) -> Vec<WebSocketUpgradeEvent> {
        let mut events = lock_recover(&self.websocket_upgrade_events);
        std::mem::take(events.as_mut())
    }

    pub fn drain_websocket_turn_events(&self) -> Vec<WebSocketTurnEvent> {
        let mut events = lock_recover(&self.websocket_turn_events);
        std::mem::take(events.as_mut())
    }

    pub fn drain_websocket_session_events(&self) -> Vec<WebSocketSessionEvent> {
        let mut events = lock_recover(&self.websocket_session_events);
        std::mem::take(events.as_mut())
    }

    pub fn drain_http_exchange_events(&self) -> Vec<HttpExchangeEvent> {
        let mut events = lock_recover(&self.http_exchange_events);
        std::mem::take(events.as_mut())
    }

    pub fn learn_tls_passthrough_host(&self, host: &str) {
        let mut passthrough = lock_recover(&self.tls_passthrough);
        passthrough.add_host(host);
    }

    pub fn set_tls_passthrough_enabled(&self, enabled: bool) {
        let mut flag = lock_recover(&self.tls_passthrough_enabled);
        *flag = enabled;
    }

    pub fn tls_passthrough_enabled(&self) -> bool {
        *lock_recover(&self.tls_passthrough_enabled)
    }

    pub fn record_tls_connect_failure(&self, host: &str, error: &str) {
        let whitelisted = self.detector.registry().in_ai_catalog(host);
        let mut passthrough = lock_recover(&self.tls_passthrough);
        passthrough.record_tls_failure(host, error, whitelisted);
    }

    pub fn learned_tls_passthrough_hosts(&self) -> Vec<String> {
        let passthrough = lock_recover(&self.tls_passthrough);
        passthrough.learned_hosts()
    }

    fn should_passthrough_tls_host(&self, host: &str) -> bool {
        if !self.tls_passthrough_enabled() {
            return false;
        }

        let mut passthrough = lock_recover(&self.tls_passthrough);
        passthrough.should_passthrough(host)
    }

    fn build_request(
        &self,
        client_addr: SocketAddr,
        req: &hudsucker::hyper::Request<hudsucker::Body>,
    ) -> EdgeRequest {
        let host = req
            .uri()
            .authority()
            .map(|a| a.host().to_string())
            .or_else(|| {
                req.headers()
                    .get(hudsucker::hyper::header::HOST)
                    .and_then(|value| value.to_str().ok())
                    .and_then(parse_host_from_authority)
            })
            .unwrap_or_default();

        let path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());

        let mut edge_request = EdgeRequest::new(
            req.method().as_str(),
            host,
            path,
            self.process_lookup.resolve(client_addr),
        );

        for (name, value) in req.headers() {
            if let Ok(value) = value.to_str() {
                edge_request
                    .headers
                    .insert(name.as_str().to_ascii_lowercase(), value.to_string());
            }
        }

        edge_request
    }

    fn remember_websocket_decision(
        &self,
        client_addr: SocketAddr,
        request: &EdgeRequest,
        outcome: &DetectionOutcome,
    ) {
        let host = request.normalized_host();
        let path = request.normalized_path();

        let decision = WebSocketCaptureDecision {
            capture: is_intercept_action(outcome.action),
            classification: outcome.classification,
            host: host.clone(),
            path: path.clone(),
        };

        let connection_key = websocket_connection_key(client_addr, &host, &path);
        let host_key = websocket_host_key(client_addr, &host);

        let mut decisions = lock_recover(&self.websocket_decisions);
        while decisions.len() >= MAX_TRACKED_WS_CONNECTIONS {
            if let Some(first) = decisions.keys().next().cloned() {
                decisions.remove(&first);
            } else {
                break;
            }
        }

        decisions.insert(connection_key, decision.clone());
        decisions.insert(host_key, decision);
    }

    fn resolve_websocket_decision(
        &self,
        context_info: &WebSocketContextInfo,
    ) -> Option<WebSocketCaptureDecision> {
        let decisions = lock_recover(&self.websocket_decisions);
        decisions
            .get(&context_info.connection_key)
            .cloned()
            .or_else(|| decisions.get(&context_info.host_key).cloned())
    }

    fn remove_websocket_decision(&self, client_addr: SocketAddr, host: &str, path: &str) {
        let mut decisions = lock_recover(&self.websocket_decisions);
        decisions.remove(&websocket_connection_key(client_addr, host, path));
        decisions.remove(&websocket_host_key(client_addr, host));
    }

    fn push_websocket_upgrade_event(&self, event: WebSocketUpgradeEvent) {
        let mut events = lock_recover(&self.websocket_upgrade_events);
        events.push(event);
        if events.len() > MAX_STORED_WS_UPGRADE_EVENTS {
            let overflow = events.len() - MAX_STORED_WS_UPGRADE_EVENTS;
            events.drain(0..overflow);
        }
    }

    fn push_websocket_turn_event(&self, event: WebSocketTurnEvent) {
        let mut events = lock_recover(&self.websocket_turn_events);
        events.push(event);

        if events.len() > MAX_STORED_WS_TURN_EVENTS {
            let overflow = events.len() - MAX_STORED_WS_TURN_EVENTS;
            events.drain(0..overflow);
        }
    }

    fn push_websocket_session_event(&self, event: WebSocketSessionEvent) {
        let mut events = lock_recover(&self.websocket_session_events);
        events.push(event);
        if events.len() > MAX_STORED_WS_SESSION_EVENTS {
            let overflow = events.len() - MAX_STORED_WS_SESSION_EVENTS;
            events.drain(0..overflow);
        }
    }

    fn push_http_exchange_event(&self, event: HttpExchangeEvent) {
        let bundle_version = non_empty_string(
            self.detector
                .registry()
                .bundle()
                .metadata
                .bundle_version
                .as_str(),
        );
        push_http_exchange_event(
            &self.http_exchange_events,
            self.edge_queue_writer.as_deref(),
            bundle_version.as_deref(),
            event,
        );
    }

    fn insert_pending_http_capture(&self, pending: PendingHttpCapture) {
        let request_id = pending.request_id.clone();
        let mut evicted = Vec::new();

        {
            let mut captures = lock_recover(&self.pending_http_captures);
            let mut order = lock_recover(&self.pending_http_capture_order);

            if !captures.contains_key(&request_id) {
                order.push_back(request_id.clone());
            }

            captures.insert(request_id, pending);

            while captures.len() > self.max_pending_http_captures {
                let Some(oldest_request_id) = order.pop_front() else {
                    break;
                };
                if let Some(oldest_pending) = captures.remove(&oldest_request_id) {
                    evicted.push(oldest_pending);
                }
            }
        }

        if let Some(writer) = self.edge_queue_writer.as_deref() {
            for pending in evicted {
                writer.clear_http_exchange_spool(pending.exchange_id.as_str());
            }
        }
    }

    fn take_pending_http_capture(&self, request_id: &str) -> Option<PendingHttpCapture> {
        let mut captures = lock_recover(&self.pending_http_captures);
        let removed = captures.remove(request_id);
        drop(captures);

        if removed.is_some() {
            let mut order = lock_recover(&self.pending_http_capture_order);
            if let Some(pos) = order.iter().position(|entry| entry == request_id) {
                order.remove(pos);
            }
        }

        removed
    }

    fn update_pending_request_capture_success(
        pending_http_captures: &Arc<Mutex<HashMap<String, PendingHttpCapture>>>,
        request_id: &str,
        request_body: String,
        request_body_base64: bool,
        request_body_truncated: bool,
    ) {
        let mut captures = lock_recover(pending_http_captures);
        if let Some(pending) = captures.get_mut(request_id) {
            pending.request_body = Some(request_body);
            pending.request_body_base64 = request_body_base64;
            pending.request_body_truncated = request_body_truncated;
            pending.request_body_error = None;
        }
    }

    fn update_pending_request_capture_error(
        pending_http_captures: &Arc<Mutex<HashMap<String, PendingHttpCapture>>>,
        request_id: &str,
        error: String,
        request_body_truncated: bool,
    ) {
        let mut captures = lock_recover(pending_http_captures);
        if let Some(pending) = captures.get_mut(request_id) {
            pending.request_body = None;
            pending.request_body_base64 = false;
            pending.request_body_truncated = request_body_truncated;
            pending.request_body_error = Some(error);
        }
    }

    fn build_pending_http_capture(
        request_id: String,
        request: &EdgeRequest,
        outcome: &DetectionOutcome,
        registry: &EdgeRegistry,
        request_is_http2: bool,
    ) -> PendingHttpCapture {
        PendingHttpCapture {
            exchange_id: Uuid::new_v4().to_string(),
            request_id,
            started_at_ms: now_unix_ms(),
            request_is_http2,
            method: request.method.to_ascii_uppercase(),
            host: request.normalized_host(),
            path: request.normalized_path(),
            detection_id: detection_id_for_outcome(registry, outcome),
            action: outcome.action,
            reason: outcome.reason,
            classification: outcome.classification,
            capture_mode: outcome.capture_mode.clone(),
            discovery_capture: outcome.discovery_capture,
            blacklisted_keyword: outcome.blacklisted_keyword.clone(),
            matched_provider: outcome.matched_provider.clone(),
            matched_application: outcome.matched_application.clone(),
            client_bundle_id: request.process.bundle_id.clone(),
            client_process_name: request.process.process_name.clone(),
            response_stream_parser: outcome.response_stream_parser.clone(),
            request_headers: request.headers.clone(),
            request_body: None,
            request_body_base64: false,
            request_body_truncated: false,
            request_body_error: None,
        }
    }

    fn build_websocket_upgrade_event(
        request: &EdgeRequest,
        outcome: &DetectionOutcome,
    ) -> WebSocketUpgradeEvent {
        WebSocketUpgradeEvent {
            timestamp_ms: now_unix_ms(),
            method: request.method.to_ascii_uppercase(),
            host: request.normalized_host(),
            path: request.normalized_path(),
            action: outcome.action,
            reason: outcome.reason,
            classification: outcome.classification,
            capture_mode: outcome.capture_mode.clone(),
            discovery_capture: outcome.discovery_capture,
            blacklisted_keyword: outcome.blacklisted_keyword.clone(),
            matched_provider: outcome.matched_provider.clone(),
            matched_application: outcome.matched_application.clone(),
            request_headers: request.headers.clone(),
            response_status: hudsucker::hyper::StatusCode::SWITCHING_PROTOCOLS.as_u16(),
        }
    }

    fn next_http_request_id(&self, client_addr: SocketAddr) -> String {
        let sequence = self.http_request_sequence.fetch_add(1, Ordering::Relaxed);
        format!("{client_addr}-{}-{sequence}", now_unix_ms())
    }

    fn observe_websocket_message(
        &mut self,
        context_info: Option<WebSocketContextInfo>,
        msg: &Message,
    ) {
        if let Some(context_info) = context_info {
            let is_close = matches!(msg, Message::Close(_));
            if let Some(decision) = self.resolve_websocket_decision(&context_info) {
                if decision.capture {
                    let (content, is_text) = websocket_message_content(msg);
                    let timestamp_ms = now_unix_ms();

                    let mut turn_emitted = false;
                    if !is_close {
                        let maybe_turn_event = {
                            let mut aggregator = lock_recover(&self.websocket_turn_aggregator);
                            aggregator.push_message(
                                &context_info.connection_key,
                                &decision.host,
                                &decision.path,
                                decision.classification,
                                context_info.direction,
                                content.clone(),
                                is_text,
                                timestamp_ms,
                            )
                        };

                        if let Some(turn_event) = maybe_turn_event {
                            self.push_websocket_turn_event(turn_event);
                            turn_emitted = true;
                        }
                    }

                    {
                        let mut aggregator = lock_recover(&self.websocket_session_aggregator);
                        aggregator.push_message(
                            &context_info.connection_key,
                            &decision.host,
                            &decision.path,
                            decision.classification,
                            context_info.direction,
                            content,
                            is_text,
                            timestamp_ms,
                        );
                    }

                    if is_close {
                        if !turn_emitted {
                            let maybe_turn_event = {
                                let mut aggregator = lock_recover(&self.websocket_turn_aggregator);
                                aggregator.flush_connection(&context_info.connection_key)
                            };

                            if let Some(turn_event) = maybe_turn_event {
                                self.push_websocket_turn_event(turn_event);
                            }
                        }

                        let maybe_session_event = {
                            let mut aggregator = lock_recover(&self.websocket_session_aggregator);
                            aggregator.flush_connection(&context_info.connection_key, timestamp_ms)
                        };

                        if let Some(session_event) = maybe_session_event {
                            self.push_websocket_session_event(session_event);
                        }

                        self.remove_websocket_decision(
                            context_info.client_addr,
                            &context_info.host,
                            &context_info.path,
                        );
                    }
                } else if is_close {
                    self.remove_websocket_decision(
                        context_info.client_addr,
                        &context_info.host,
                        &context_info.path,
                    );
                }
            }
        }
    }
}

impl<L: ProcessLookup> hudsucker::HttpHandler for HudsuckerDetectionHandler<L> {
    fn handle_tls_failure(
        &mut self,
        _ctx: &hudsucker::HttpContext,
        authority: Option<&hudsucker::hyper::http::uri::Authority>,
        _stage: hudsucker::TlsFailureStage,
        error: &str,
    ) -> impl Future<Output = ()> + Send {
        if let Some(authority) = authority {
            self.record_tls_connect_failure(authority.host(), error);
        }
        async {}
    }

    fn should_intercept(
        &mut self,
        ctx: &hudsucker::HttpContext,
        req: &hudsucker::hyper::Request<hudsucker::Body>,
    ) -> impl Future<Output = bool> + Send {
        let edge_request = self.build_request(ctx.client_addr, req);
        let outcome = self
            .detector
            .evaluate_for_stage(&edge_request, DetectionStage::Connect);
        let host = edge_request.normalized_host();

        let should_intercept = if matches!(outcome.action, InterceptionAction::Block) {
            true
        } else if req.method() == hudsucker::hyper::Method::CONNECT
            && self.should_passthrough_tls_host(&host)
        {
            false
        } else {
            is_intercept_action(outcome.action)
        };

        async move { should_intercept }
    }

    fn handle_request(
        &mut self,
        ctx: &hudsucker::HttpContext,
        req: hudsucker::hyper::Request<hudsucker::Body>,
    ) -> impl Future<Output = hudsucker::RequestOrResponse> + Send {
        let edge_request = self.build_request(ctx.client_addr, &req);
        let outcome = self
            .detector
            .evaluate_for_stage(&edge_request, DetectionStage::HttpRequest);
        let is_connect = req.method() == hudsucker::hyper::Method::CONNECT;
        let is_websocket_upgrade = is_websocket_upgrade_request(&req);

        if is_websocket_upgrade {
            self.remember_websocket_decision(ctx.client_addr, &edge_request, &outcome);

            if matches!(outcome.action, InterceptionAction::Intercept) {
                self.push_websocket_upgrade_event(Self::build_websocket_upgrade_event(
                    &edge_request,
                    &outcome,
                ));
            }
        }

        let pending = if !is_connect && !is_websocket_upgrade {
            let request_id = self.next_http_request_id(ctx.client_addr);
            let request_is_http2 = matches!(req.version(), hudsucker::hyper::Version::HTTP_2);
            Some(Self::build_pending_http_capture(
                request_id,
                &edge_request,
                &outcome,
                self.detector.registry().as_ref(),
                request_is_http2,
            ))
        } else {
            None
        };

        let is_blocked = matches!(outcome.action, InterceptionAction::Block);
        self.active_http_request_id = if is_blocked {
            None
        } else {
            pending.as_ref().map(|capture| capture.request_id.clone())
        };

        if matches!(outcome.action, InterceptionAction::Block) {
            if let Some(pending) = pending.as_ref() {
                self.push_http_exchange_event(build_http_exchange_event(
                    pending,
                    hudsucker::hyper::StatusCode::FORBIDDEN.as_u16(),
                    HashMap::new(),
                    Some("blocked by soth-edge policy".to_string()),
                    false,
                    false,
                    None,
                ));
            }
        }

        let pending_http_captures = self.pending_http_captures.clone();
        let max_http_capture_body_bytes = self.max_http_capture_body_bytes;
        let should_capture_request_body = pending.as_ref().is_some_and(should_capture_full_body);
        let should_track_pending = !is_blocked;
        if should_track_pending {
            if let Some(initial_pending) = pending.clone() {
                if let Some(writer) = self.edge_queue_writer.as_deref() {
                    let _ = writer.seed_http_exchange_spool(&initial_pending);
                }
                self.insert_pending_http_capture(initial_pending);
            }
        }

        async move {
            if matches!(outcome.action, InterceptionAction::Block) {
                let response = hudsucker::hyper::Response::builder()
                    .status(hudsucker::hyper::StatusCode::FORBIDDEN)
                    .body(hudsucker::Body::from("blocked by soth-edge policy"))
                    .expect("static response should always build");
                return hudsucker::RequestOrResponse::Response(response);
            }

            let mut req = req;
            if should_capture_request_body && should_track_pending {
                if let Some(pending) = pending.as_ref() {
                    let request_id = pending.request_id.clone();
                    let content_type = pending.request_headers.get("content-type").cloned();

                    let (parts, body) = req.into_parts();
                    let stream = futures::stream::try_unfold(
                        (
                            body.into_data_stream(),
                            Vec::new(),
                            false,
                            request_id,
                            content_type,
                            pending_http_captures,
                            max_http_capture_body_bytes,
                        ),
                        |(
                            mut stream,
                            mut captured,
                            mut truncated,
                            request_id,
                            content_type,
                            pending_http_captures,
                            max_http_capture_body_bytes,
                        )| async move {
                            match stream.next().await {
                                Some(Ok(chunk)) => {
                                    if captured.len() < max_http_capture_body_bytes {
                                        let remaining =
                                            max_http_capture_body_bytes - captured.len();
                                        if chunk.len() <= remaining {
                                            captured.extend_from_slice(chunk.as_ref());
                                        } else {
                                            captured
                                                .extend_from_slice(&chunk.as_ref()[..remaining]);
                                            truncated = true;
                                        }
                                    } else {
                                        truncated = true;
                                    }

                                    Ok(Some((
                                        chunk,
                                        (
                                            stream,
                                            captured,
                                            truncated,
                                            request_id,
                                            content_type,
                                            pending_http_captures,
                                            max_http_capture_body_bytes,
                                        ),
                                    )))
                                }
                                Some(Err(error)) => {
                                    Self::update_pending_request_capture_error(
                                        &pending_http_captures,
                                        request_id.as_str(),
                                        error.to_string(),
                                        truncated,
                                    );
                                    Err(error)
                                }
                                None => {
                                    let (request_body, request_body_base64, request_body_truncated) =
                                        capture_normalized_body(
                                            captured.as_slice(),
                                            content_type.as_deref(),
                                            None,
                                            max_http_capture_body_bytes,
                                        );

                                    Self::update_pending_request_capture_success(
                                        &pending_http_captures,
                                        request_id.as_str(),
                                        request_body,
                                        request_body_base64,
                                        request_body_truncated || truncated,
                                    );
                                    Ok(None)
                                }
                            }
                        },
                    );

                    req = hudsucker::hyper::Request::from_parts(
                        parts,
                        hudsucker::Body::from_stream(stream),
                    );
                }
            }

            hudsucker::RequestOrResponse::Request(req)
        }
    }

    fn handle_response(
        &mut self,
        _ctx: &hudsucker::HttpContext,
        res: hudsucker::hyper::Response<hudsucker::Body>,
    ) -> impl Future<Output = hudsucker::hyper::Response<hudsucker::Body>> + Send {
        let pending = self
            .active_http_request_id
            .take()
            .and_then(|request_id| self.take_pending_http_capture(request_id.as_str()));
        let http_exchange_events = self.http_exchange_events.clone();
        let edge_queue_writer = self.edge_queue_writer.clone();
        let max_http_capture_body_bytes = self.max_http_capture_body_bytes;
        let bundle_version = non_empty_string(
            self.detector
                .registry()
                .bundle()
                .metadata
                .bundle_version
                .as_str(),
        );

        async move {
            let Some(pending) = pending else {
                return res;
            };

            let response_status = res.status().as_u16();
            let response_headers = headers_to_strings(res.headers());
            let content_type = response_headers
                .get("content-type")
                .map(|value| value.to_ascii_lowercase());

            let should_capture_response_body = should_capture_full_body(&pending);

            if !should_capture_response_body {
                push_http_exchange_event(
                    &http_exchange_events,
                    edge_queue_writer.as_deref(),
                    bundle_version.as_deref(),
                    build_http_exchange_event(
                        &pending,
                        response_status,
                        response_headers,
                        None,
                        false,
                        false,
                        None,
                    ),
                );
                return res;
            }

            let (parts, body) = res.into_parts();
            let response_headers_for_capture = response_headers.clone();
            let content_type_for_capture = content_type.clone();

            let stream = futures::stream::try_unfold(
                (
                    body.into_data_stream(),
                    Vec::new(),
                    false,
                    pending,
                    response_status,
                    response_headers_for_capture,
                    content_type_for_capture,
                    http_exchange_events,
                    edge_queue_writer,
                    bundle_version,
                    max_http_capture_body_bytes,
                ),
                |(
                    mut stream,
                    mut captured,
                    mut truncated,
                    pending,
                    response_status,
                    response_headers,
                    content_type,
                    http_exchange_events,
                    edge_queue_writer,
                    bundle_version,
                    max_http_capture_body_bytes,
                )| async move {
                    match stream.next().await {
                        Some(Ok(chunk)) => {
                            if captured.len() < max_http_capture_body_bytes {
                                let remaining = max_http_capture_body_bytes - captured.len();
                                if chunk.len() <= remaining {
                                    captured.extend_from_slice(chunk.as_ref());
                                } else {
                                    captured.extend_from_slice(&chunk.as_ref()[..remaining]);
                                    truncated = true;
                                }
                            } else {
                                truncated = true;
                            }

                            Ok(Some((
                                chunk,
                                (
                                    stream,
                                    captured,
                                    truncated,
                                    pending,
                                    response_status,
                                    response_headers,
                                    content_type,
                                    http_exchange_events,
                                    edge_queue_writer,
                                    bundle_version,
                                    max_http_capture_body_bytes,
                                ),
                            )))
                        }
                        Some(Err(error)) => {
                            push_http_exchange_event(
                                &http_exchange_events,
                                edge_queue_writer.as_deref(),
                                bundle_version.as_deref(),
                                build_http_exchange_event(
                                    &pending,
                                    response_status,
                                    response_headers,
                                    None,
                                    false,
                                    truncated,
                                    Some(error.to_string()),
                                ),
                            );
                            Err(error)
                        }
                        None => {
                            let (response_body, response_body_base64, response_body_truncated) =
                                capture_normalized_body(
                                    captured.as_slice(),
                                    content_type.as_deref(),
                                    pending.response_stream_parser.as_ref(),
                                    max_http_capture_body_bytes,
                                );

                            push_http_exchange_event(
                                &http_exchange_events,
                                edge_queue_writer.as_deref(),
                                bundle_version.as_deref(),
                                build_http_exchange_event(
                                    &pending,
                                    response_status,
                                    response_headers,
                                    Some(response_body),
                                    response_body_base64,
                                    response_body_truncated || truncated,
                                    None,
                                ),
                            );

                            Ok(None)
                        }
                    }
                },
            );

            let body = hudsucker::Body::from_stream(stream);

            hudsucker::hyper::Response::from_parts(parts, body)
        }
    }

    fn handle_error(
        &mut self,
        _ctx: &hudsucker::HttpContext,
        err: hudsucker::hyper_util::client::legacy::Error,
    ) -> impl Future<Output = hudsucker::hyper::Response<hudsucker::Body>> + Send {
        let pending = self
            .active_http_request_id
            .take()
            .and_then(|request_id| self.take_pending_http_capture(request_id.as_str()));
        let http_exchange_events = self.http_exchange_events.clone();
        let tls_passthrough = self.tls_passthrough.clone();
        let registry = self.detector.registry().clone();
        let edge_queue_writer = self.edge_queue_writer.clone();
        let bundle_version = non_empty_string(
            self.detector
                .registry()
                .bundle()
                .metadata
                .bundle_version
                .as_str(),
        );

        async move {
            let error_text = err.to_string();

            if let Some(pending) = pending {
                let whitelisted = registry.in_ai_catalog(&pending.host);
                {
                    let mut passthrough = lock_recover(&tls_passthrough);
                    passthrough.record_tls_failure(&pending.host, &error_text, whitelisted);
                }

                push_http_exchange_event(
                    &http_exchange_events,
                    edge_queue_writer.as_deref(),
                    bundle_version.as_deref(),
                    build_http_exchange_event(
                        &pending,
                        hudsucker::hyper::StatusCode::BAD_GATEWAY.as_u16(),
                        HashMap::new(),
                        None,
                        false,
                        false,
                        Some(error_text),
                    ),
                );
            }

            hudsucker::hyper::Response::builder()
                .status(hudsucker::hyper::StatusCode::BAD_GATEWAY)
                .body(hudsucker::Body::empty())
                .expect("static response should always build")
        }
    }
}

impl<L: ProcessLookup> hudsucker::WebSocketHandler for HudsuckerDetectionHandler<L> {
    fn handle_message(
        &mut self,
        ctx: &hudsucker::WebSocketContext,
        msg: Message,
    ) -> impl Future<Output = Option<Message>> + Send {
        self.observe_websocket_message(websocket_context_info(ctx), &msg);

        async move { Some(msg) }
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn read_lock_recover<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn write_lock_recover<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn push_http_exchange_event(
    events: &Arc<Mutex<Vec<HttpExchangeEvent>>>,
    edge_queue_writer: Option<&EdgeQueueWriter>,
    bundle_version: Option<&str>,
    event: HttpExchangeEvent,
) {
    {
        let mut events = lock_recover(events);
        events.push(event.clone());
        if events.len() > MAX_STORED_HTTP_EXCHANGE_EVENTS {
            let overflow = events.len() - MAX_STORED_HTTP_EXCHANGE_EVENTS;
            events.drain(0..overflow);
        }
    }

    if let Some(writer) = edge_queue_writer {
        if matches!(event.reason, DecisionReason::Blacklisted) {
            writer.clear_http_exchange_spool(event.exchange_id.as_str());
        } else {
            let _ = writer.enqueue_http_exchange(&event, bundle_version);
        }
    }
}

fn build_http_exchange_event(
    pending: &PendingHttpCapture,
    response_status: u16,
    response_headers: HashMap<String, String>,
    response_body: Option<String>,
    response_body_base64: bool,
    response_body_truncated: bool,
    response_body_error: Option<String>,
) -> HttpExchangeEvent {
    HttpExchangeEvent {
        exchange_id: pending.exchange_id.clone(),
        request_id: pending.request_id.clone(),
        timestamp_ms: now_unix_ms(),
        request_is_http2: pending.request_is_http2,
        method: pending.method.clone(),
        host: pending.host.clone(),
        path: pending.path.clone(),
        detection_id: pending.detection_id.clone(),
        action: pending.action,
        reason: pending.reason,
        classification: pending.classification,
        capture_mode: pending.capture_mode.clone(),
        discovery_capture: pending.discovery_capture,
        blacklisted_keyword: pending.blacklisted_keyword.clone(),
        matched_provider: pending.matched_provider.clone(),
        matched_application: pending.matched_application.clone(),
        client_bundle_id: pending.client_bundle_id.clone(),
        client_process_name: pending.client_process_name.clone(),
        response_stream_parser: pending.response_stream_parser.clone(),
        request_headers: pending.request_headers.clone(),
        request_body: pending.request_body.clone(),
        request_body_base64: pending.request_body_base64,
        request_body_truncated: pending.request_body_truncated,
        request_body_error: pending.request_body_error.clone(),
        response_status,
        response_headers,
        response_body,
        response_body_base64,
        response_body_truncated,
        response_body_error,
    }
}

fn exchange_event_from_http_event(
    event: &HttpExchangeEvent,
    bundle_version: Option<&str>,
) -> ExchangeEvent {
    let request_mode = exchange_body_mode_for_http_event(
        event.capture_mode.clone(),
        event.discovery_capture,
        event.request_body.as_ref(),
    );
    let response_mode = exchange_body_mode_for_http_event(
        event.capture_mode.clone(),
        event.discovery_capture,
        event.response_body.as_ref(),
    );
    let source_class = exchange_source_class_for_http_event(event.classification);
    let transport = exchange_transport_for_http_event(event);

    let mut exchange = ExchangeEvent::new(
        event.exchange_id.clone(),
        source_class,
        transport,
        request_mode,
        response_mode,
    );

    exchange.provider = event
        .matched_provider
        .as_deref()
        .and_then(non_empty_string)
        .or_else(|| {
            event
                .matched_application
                .as_deref()
                .and_then(non_empty_string)
        });
    exchange.agent = event
        .matched_application
        .as_deref()
        .and_then(non_empty_string)
        .or_else(|| event.matched_provider.as_deref().and_then(non_empty_string));
    exchange.endpoint = Some(format!("{}{}", event.host, event.path));
    exchange.method = Some(event.method.clone());
    exchange.status_code = Some(event.response_status);
    exchange.trace_id = Some(event.request_id.clone());
    exchange.detection_id = Some(event.detection_id.clone());
    exchange.detection_bundle_version = bundle_version
        .and_then(non_empty_string)
        .or_else(|| Some("soth-edge".to_string()));

    exchange.request.headers = exchange_headers_from_http_headers(&event.request_headers);
    exchange.response.headers = exchange_headers_from_http_headers(&event.response_headers);

    populate_exchange_body_from_http_event(
        &mut exchange.request.body,
        event.request_body.as_ref(),
        event
            .request_headers
            .get("content-type")
            .map(String::as_str),
        event.request_body_truncated,
    );
    populate_exchange_body_from_http_event(
        &mut exchange.response.body,
        event.response_body.as_ref(),
        event
            .response_headers
            .get("content-type")
            .map(String::as_str),
        event.response_body_truncated,
    );

    exchange.flags = ExchangeFlags {
        truncated: event.request_body_truncated || event.response_body_truncated,
        metadata_only: event.capture_mode != CaptureMode::Full || event.discovery_capture,
        discovery_capture: event.discovery_capture,
        blacklist_match: event.blacklisted_keyword.is_some(),
        pii_detected: false,
    };

    exchange.client = Some(ExchangeClient {
        pid: None,
        device_id: None,
        bundle_id: event.client_bundle_id.clone(),
        process_name: event.client_process_name.clone(),
        app_type: Some(exchange_client_app_type_for_http_event(event.classification).to_string()),
        host_origin: extract_origin_host(event.request_headers.get("origin").map(String::as_str)),
        referrer_origin: extract_origin_host(
            event.request_headers.get("referer").map(String::as_str),
        ),
    });

    exchange.parse = Some(ExchangeParse {
        detection_id: exchange.detection_id.clone(),
        detection_bundle_version: exchange.detection_bundle_version.clone(),
        parser_version: Some("soth-edge-http-v1".to_string()),
        bundle_version: exchange.detection_bundle_version.clone(),
        parse_confidence: Some(1.0),
        detection_reason: Some(decision_reason_code(event.reason).to_string()),
        detection_source: Some(EDGE_DEFAULT_DETECTION_SOURCE.to_string()),
        decision_step: Some(decision_step_for_reason(event.reason).to_string()),
        decision_outcome: Some(decision_outcome_for_event(event).to_string()),
        skip_reason: skip_reason_for_event(event.reason).map(str::to_string),
        discovery_kind: event
            .discovery_capture
            .then(|| EXCHANGE_DISCOVERY_KIND_DOMAIN.to_string()),
    });

    exchange
}

fn exchange_headers_from_http_headers(
    headers: &HashMap<String, String>,
) -> Option<BTreeMap<String, String>> {
    if headers.is_empty() {
        return None;
    }

    let mut out = BTreeMap::new();
    for (name, value) in headers {
        out.insert(name.clone(), value.clone());
    }
    Some(out)
}

fn populate_exchange_body_from_http_event(
    body: &mut ExchangeBody,
    inline: Option<&String>,
    content_type: Option<&str>,
    truncated: bool,
) {
    body.inline = inline.cloned();
    body.bytes_raw = inline.map(|value| value.len() as u64);
    body.content_type = content_type.map(|value| value.to_string());
    body.truncated_reason = if truncated {
        Some("capture_limit".to_string())
    } else {
        None
    };
}

fn exchange_body_mode_for_http_event(
    capture_mode: CaptureMode,
    discovery_capture: bool,
    inline: Option<&String>,
) -> ExchangeBodyMode {
    if capture_mode != CaptureMode::Full || discovery_capture {
        return ExchangeBodyMode::MetadataOnly;
    }

    if inline.is_some() {
        ExchangeBodyMode::Inline
    } else {
        ExchangeBodyMode::MetadataOnly
    }
}

fn exchange_source_class_for_http_event(
    classification: TrafficClassification,
) -> ExchangeSourceClass {
    match classification {
        TrafficClassification::ToolUsage | TrafficClassification::UnknownAgent => {
            ExchangeSourceClass::AiInference
        }
        TrafficClassification::ApplicationUsage | TrafficClassification::Other => {
            ExchangeSourceClass::AgentApp
        }
    }
}

fn exchange_transport_for_http_event(event: &HttpExchangeEvent) -> ExchangeTransport {
    if looks_like_jsonrpc_http_event(event) {
        return ExchangeTransport::Jsonrpc;
    }

    if let Some(parser) = event.response_stream_parser.as_ref() {
        match parser.format {
            BundleStreamFormat::Sse => return ExchangeTransport::Sse,
            BundleStreamFormat::Ndjson | BundleStreamFormat::LengthPrefixed => {
                return ExchangeTransport::Ndjson;
            }
            BundleStreamFormat::Websocket | BundleStreamFormat::Unknown => {}
        }
    }

    let content_type = event
        .response_headers
        .get("content-type")
        .map(|value| value.to_ascii_lowercase());
    if content_type
        .as_deref()
        .is_some_and(|value| value.contains("text/event-stream"))
    {
        ExchangeTransport::Sse
    } else if content_type.as_deref().is_some_and(|value| {
        value.contains("application/x-ndjson") || value.contains("application/ndjson")
    }) {
        ExchangeTransport::Ndjson
    } else if event.request_is_http2 {
        ExchangeTransport::Http2
    } else {
        ExchangeTransport::Https
    }
}

fn looks_like_jsonrpc_http_event(event: &HttpExchangeEvent) -> bool {
    let path = event.path.to_ascii_lowercase();
    if path.contains("jsonrpc") || path.ends_with("/rpc") {
        return true;
    }

    [
        event.request_body.as_deref(),
        event.response_body.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|body| {
        let body = body.to_ascii_lowercase();
        body.contains("\"jsonrpc\"")
            && (body.contains("\"method\"")
                || body.contains("\"id\"")
                || body.contains("\"result\"")
                || body.contains("\"error\""))
    })
}

fn exchange_client_app_type_for_http_event(classification: TrafficClassification) -> &'static str {
    match classification {
        TrafficClassification::ApplicationUsage => EXCHANGE_CLIENT_APP_TYPE_HOST,
        TrafficClassification::ToolUsage => EXCHANGE_CLIENT_APP_TYPE_NON_HOST,
        TrafficClassification::UnknownAgent | TrafficClassification::Other => {
            EXCHANGE_CLIENT_APP_TYPE_UNKNOWN
        }
    }
}

fn decision_reason_code(reason: DecisionReason) -> &'static str {
    match reason {
        DecisionReason::Allowed => "allowed",
        DecisionReason::ProcessAction => "process_action",
        DecisionReason::NotInCatalog => "not_in_catalog",
        DecisionReason::UnknownAppPolicy => "unknown_app_policy",
        DecisionReason::Blacklisted => "blacklisted",
        DecisionReason::HostOriginNotAllowed => "host_origin_not_allowed",
        DecisionReason::CaptureDisabled => "capture_disabled",
        DecisionReason::MethodNotAllowed => "method_not_allowed",
    }
}

fn decision_step_for_reason(reason: DecisionReason) -> &'static str {
    match reason {
        DecisionReason::ProcessAction => EXCHANGE_DECISION_STEP_APP_GATE,
        DecisionReason::Blacklisted => EXCHANGE_DECISION_STEP_URL_BLACKLIST,
        DecisionReason::HostOriginNotAllowed => EXCHANGE_DECISION_STEP_APP_ORIGIN,
        DecisionReason::Allowed
        | DecisionReason::NotInCatalog
        | DecisionReason::UnknownAppPolicy
        | DecisionReason::CaptureDisabled
        | DecisionReason::MethodNotAllowed => EXCHANGE_DECISION_STEP_WHITELIST,
    }
}

fn decision_outcome_for_event(event: &HttpExchangeEvent) -> &'static str {
    if !matches!(event.action, InterceptionAction::Intercept) {
        return EXCHANGE_DECISION_OUTCOME_SKIPPED;
    }

    if event.discovery_capture {
        return EXCHANGE_DECISION_OUTCOME_DISCOVERY_CAPTURE;
    }

    if event.capture_mode == CaptureMode::MetadataOnly {
        EXCHANGE_DECISION_OUTCOME_METADATA_ONLY
    } else {
        EXCHANGE_DECISION_OUTCOME_CAPTURED
    }
}

fn skip_reason_for_event(reason: DecisionReason) -> Option<&'static str> {
    match reason {
        DecisionReason::NotInCatalog => Some(EXCHANGE_SKIP_REASON_NOT_WHITELISTED),
        DecisionReason::Blacklisted => Some(EXCHANGE_SKIP_REASON_BLACKLISTED),
        DecisionReason::ProcessAction
        | DecisionReason::UnknownAppPolicy
        | DecisionReason::HostOriginNotAllowed
        | DecisionReason::CaptureDisabled
        | DecisionReason::MethodNotAllowed => Some(EXCHANGE_SKIP_REASON_APP_NOT_ALLOWED),
        DecisionReason::Allowed => None,
    }
}

fn non_empty_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn capture_mode_label(mode: &CaptureMode) -> &'static str {
    match mode {
        CaptureMode::Full => "full",
        CaptureMode::MetadataOnly => "metadata_only",
    }
}

fn detection_id_for_outcome(registry: &EdgeRegistry, outcome: &DetectionOutcome) -> String {
    let target_id = detection_target_id_for_outcome(outcome);
    if let Some(target_id) = target_id {
        if let Some(detection_id) = registry.detection_id_for_target(target_id) {
            return detection_id;
        }

        if let Some(fallback_detection_id) = fallback_detection_id_for_target(target_id, outcome) {
            return fallback_detection_id;
        }
    }

    EDGE_DEFAULT_DETECTION_ID.to_string()
}

fn detection_target_id_for_outcome(outcome: &DetectionOutcome) -> Option<&str> {
    match outcome.classification {
        TrafficClassification::ApplicationUsage => outcome
            .matched_application
            .as_deref()
            .or(outcome.matched_provider.as_deref()),
        TrafficClassification::ToolUsage
        | TrafficClassification::UnknownAgent
        | TrafficClassification::Other => outcome
            .matched_provider
            .as_deref()
            .or(outcome.matched_application.as_deref()),
    }
}

fn fallback_detection_id_for_target(target_id: &str, outcome: &DetectionOutcome) -> Option<String> {
    let segment = normalize_detection_segment(target_id)?;
    let is_application =
        if outcome.matched_application.is_some() && outcome.matched_provider.is_none() {
            true
        } else if outcome.matched_provider.is_some() && outcome.matched_application.is_none() {
            false
        } else {
            matches!(
                outcome.classification,
                TrafficClassification::ApplicationUsage
            )
        };

    if is_application {
        Some(format!("agent.{segment}.app"))
    } else {
        Some(format!("ai.{segment}.service"))
    }
}

fn normalize_detection_segment(value: &str) -> Option<String> {
    let mut out = String::new();
    let mut last_was_separator = false;

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_was_separator = false;
            continue;
        }

        if !last_was_separator {
            out.push('.');
            last_was_separator = true;
        }
    }

    let normalized = out.trim_matches('.').to_string();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn should_capture_full_body(pending: &PendingHttpCapture) -> bool {
    matches!(pending.action, InterceptionAction::Intercept)
        && pending.capture_mode == CaptureMode::Full
        && !pending.discovery_capture
}

fn headers_to_strings(headers: &hudsucker::hyper::HeaderMap) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (name, value) in headers {
        let key = name.as_str().to_ascii_lowercase();
        let rendered = match value.to_str() {
            Ok(raw) => raw.to_string(),
            Err(_) => BASE64_STANDARD.encode(value.as_bytes()),
        };

        out.entry(key)
            .and_modify(|existing: &mut String| {
                if !existing.is_empty() {
                    existing.push_str(", ");
                }
                existing.push_str(&rendered);
            })
            .or_insert(rendered);
    }
    out
}

fn capture_normalized_body(
    bytes: &[u8],
    content_type: Option<&str>,
    stream_parser: Option<&BundleStreamParser>,
    max_capture_body_bytes: usize,
) -> (String, bool, bool) {
    let max_capture_body_bytes = max_capture_body_bytes.max(1);
    let truncated = bytes.len() > max_capture_body_bytes;
    let slice = if truncated {
        &bytes[..max_capture_body_bytes]
    } else {
        bytes
    };

    let normalized = normalize_body_with_stream_parser(slice, content_type, stream_parser);
    let base64 = normalized_body_is_base64_payload(&normalized);
    (normalized, base64, truncated)
}

fn normalized_body_is_base64_payload(body: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return false;
    };

    value
        .as_object()
        .is_some_and(|obj| obj.contains_key("_binary_base64") || obj.contains_key("_raw_base64"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::EdgeRegistry;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use http_body_util::BodyExt;
    use std::convert::Infallible;
    use std::io::Write;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    fn detector() -> EdgeDetector {
        let registry = Arc::new(
            EdgeRegistry::from_json_str(include_str!("../bundle.json"))
                .expect("bundle should parse"),
        );
        EdgeDetector::new(registry)
    }

    #[test]
    fn load_edge_registry_falls_back_to_last_good_cache() {
        let dir = tempdir().expect("tempdir");
        let primary = dir.path().join("registry_bundle_cache.json");
        let fallback = registry_cache_last_good_path(primary.as_path());

        std::fs::write(&primary, "{").expect("write malformed primary cache");
        std::fs::write(&fallback, include_str!("../bundle.json"))
            .expect("write fallback cache bundle");

        let registry = load_edge_registry(Some(primary.as_path()))
            .expect("loader should fallback to last-known-good cache");

        assert!(registry.in_ai_catalog("api.openai.com"));
    }

    #[test]
    fn load_edge_registry_reads_legacy_cache_name_during_single_cache_migration() {
        let dir = tempdir().expect("tempdir");
        let primary = dir.path().join("registry_bundle_cache.json");
        let legacy = dir.path().join("registry_bundle_cache_edge.json");

        std::fs::write(&legacy, include_str!("../bundle.json")).expect("write legacy cache bundle");

        let registry = load_edge_registry(Some(primary.as_path()))
            .expect("loader should read legacy cache during migration");

        assert!(registry.in_ai_catalog("api.openai.com"));
    }

    #[test]
    fn known_app_hitting_provider_is_tool_usage() {
        let detector = detector();
        let request = EdgeRequest::new(
            "POST",
            "api.anthropic.com",
            "/v1/messages",
            ProcessIdentity::new(Some("com.anthropic.claudefordesktop".to_string()), None),
        );

        let outcome = detector.evaluate(&request);
        assert_eq!(outcome.action, InterceptionAction::Intercept);
        assert_eq!(outcome.reason, DecisionReason::Allowed);
        assert_eq!(outcome.classification, TrafficClassification::ToolUsage);
        assert_eq!(outcome.matched_provider.as_deref(), Some("anthropic"));
    }

    #[test]
    fn unknown_process_hitting_provider_is_unknown_agent() {
        let detector = detector();
        let request = EdgeRequest::new(
            "POST",
            "api.openai.com",
            "/v1/chat/completions",
            ProcessIdentity::default(),
        );

        let outcome = detector.evaluate(&request);
        assert_eq!(outcome.reason, DecisionReason::Allowed);
        assert_eq!(outcome.classification, TrafficClassification::UnknownAgent);
        assert_eq!(outcome.matched_provider.as_deref(), Some("openai"));
    }

    #[test]
    fn browser_hitting_application_domain_is_application_usage() {
        let detector = detector();
        let request = EdgeRequest::new(
            "POST",
            "claude.ai",
            "/api/organizations/org-1/completion",
            ProcessIdentity::new(Some("com.apple.Safari".to_string()), None),
        )
        .with_header("origin", "https://claude.ai");

        let outcome = detector.evaluate(&request);
        assert_eq!(outcome.reason, DecisionReason::Allowed);
        assert_eq!(
            outcome.classification,
            TrafficClassification::ApplicationUsage
        );
        assert_eq!(outcome.matched_application.as_deref(), Some("claude"));
    }

    #[test]
    fn application_detection_id_comes_from_bundle_detection_index() {
        let detector = detector();
        let request = EdgeRequest::new(
            "POST",
            "chatgpt.com",
            "/backend-api/f/conversation",
            ProcessIdentity::new(Some("com.apple.Safari".to_string()), None),
        )
        .with_header("origin", "https://chatgpt.com");

        let outcome = detector.evaluate(&request);
        assert_eq!(outcome.reason, DecisionReason::Allowed);
        assert_eq!(
            outcome.classification,
            TrafficClassification::ApplicationUsage
        );
        assert_eq!(outcome.matched_application.as_deref(), Some("chatgpt"));

        let detection_id = detection_id_for_outcome(detector.registry().as_ref(), &outcome);
        assert_eq!(detection_id, "agent.chatgpt.app");
    }

    #[test]
    fn browser_origin_not_in_catalog_is_rejected() {
        let detector = detector();
        let request = EdgeRequest::new(
            "GET",
            "claude.ai",
            "/",
            ProcessIdentity::new(Some("com.apple.Safari".to_string()), None),
        )
        .with_header("origin", "https://example.invalid");

        let outcome = detector.evaluate(&request);
        assert_eq!(outcome.reason, DecisionReason::HostOriginNotAllowed);
        assert_eq!(outcome.action, InterceptionAction::Skip);
    }

    #[test]
    fn browser_connect_defers_origin_check_until_http_request() {
        let detector = detector();
        let request = EdgeRequest::new(
            "CONNECT",
            "claude.ai:443",
            "/",
            ProcessIdentity::new(Some("com.apple.Safari".to_string()), None),
        );

        let outcome = detector.evaluate_for_stage(&request, DetectionStage::Connect);
        assert_eq!(outcome.reason, DecisionReason::Allowed);
        assert_eq!(outcome.action, InterceptionAction::Intercept);
    }

    #[test]
    fn browser_domain_discovery_capture_is_enabled_for_catalog_referer() {
        let detector = detector();
        let request = EdgeRequest::new(
            "GET",
            "new-subdomain.unknown.test",
            "/resource",
            ProcessIdentity::new(Some("com.apple.Safari".to_string()), None),
        )
        .with_header("referer", "https://claude.ai/chat");

        let outcome = detector.evaluate(&request);
        assert_eq!(outcome.reason, DecisionReason::Allowed);
        assert!(outcome.discovery_capture);
        assert_eq!(outcome.capture_mode, CaptureMode::MetadataOnly);
    }

    #[test]
    fn blacklist_blocks_noise_paths() {
        let detector = detector();
        let request = EdgeRequest::new(
            "GET",
            "api.openai.com",
            "/telemetry/events",
            ProcessIdentity::new(Some("com.anthropic.claudefordesktop".to_string()), None),
        );

        let outcome = detector.evaluate(&request);
        assert_eq!(outcome.reason, DecisionReason::Blacklisted);
        assert_eq!(outcome.action, InterceptionAction::Skip);
        assert_eq!(outcome.blacklisted_keyword.as_deref(), Some("telemetry"));
    }

    #[test]
    fn websocket_completion_detector_matches_turn_done_markers() {
        assert!(is_ws_turn_complete_payload("[DONE]"));
        assert!(is_ws_turn_complete_payload(r#"{"data":"[DONE]"}"#));
        assert!(is_ws_turn_complete_payload(r#"{"type":"message_stop"}"#));
        assert!(is_ws_turn_complete_payload(
            r#"{"payload":{"ok":true,"payload":{"done":true}}}"#
        ));
        assert!(!is_ws_turn_complete_payload(r#"{"type":"heartbeat"}"#));
        assert!(!is_ws_turn_complete_payload(r#"{"type":"delta"}"#));
    }

    #[test]
    fn websocket_turn_aggregator_emits_on_server_completion() {
        let mut aggregator = WebSocketTurnAggregator::default();

        let first = aggregator.push_message(
            "conn",
            "api.openai.com",
            "/v1/realtime",
            TrafficClassification::ToolUsage,
            WebSocketDirection::ClientToServer,
            r#"{"type":"input","text":"hi"}"#.to_string(),
            true,
            1,
        );
        assert!(first.is_none());

        let second = aggregator.push_message(
            "conn",
            "api.openai.com",
            "/v1/realtime",
            TrafficClassification::ToolUsage,
            WebSocketDirection::ServerToClient,
            r#"{"type":"delta","text":"hello"}"#.to_string(),
            true,
            2,
        );
        assert!(second.is_none());

        let turn = aggregator.push_message(
            "conn",
            "api.openai.com",
            "/v1/realtime",
            TrafficClassification::ToolUsage,
            WebSocketDirection::ServerToClient,
            r#"{"type":"message_stop"}"#.to_string(),
            true,
            3,
        );

        let turn = turn.expect("turn completion should emit an aggregate");
        assert_eq!(turn.host, "api.openai.com");
        assert_eq!(turn.path, "/v1/realtime");
        assert_eq!(turn.classification, TrafficClassification::ToolUsage);
        assert_eq!(turn.message_count, 3);
        assert_eq!(turn.messages.len(), 3);
        assert_eq!(
            turn.messages[0].direction,
            WebSocketDirection::ClientToServer
        );
        assert_eq!(
            turn.messages[2].direction,
            WebSocketDirection::ServerToClient
        );
    }

    #[test]
    fn websocket_session_aggregator_flushes_on_close_with_duration_and_message_cap() {
        let mut aggregator = WebSocketSessionAggregator::default();

        for idx in 0..(MAX_WS_MESSAGES_PER_CONNECTION + 5) {
            aggregator.push_message(
                "conn",
                "api.openai.com",
                "/v1/realtime",
                TrafficClassification::ToolUsage,
                if idx % 2 == 0 {
                    WebSocketDirection::ClientToServer
                } else {
                    WebSocketDirection::ServerToClient
                },
                format!(r#"{{"idx":{idx}}}"#),
                true,
                idx as u64,
            );
        }

        let event = aggregator
            .flush_connection("conn", (MAX_WS_MESSAGES_PER_CONNECTION + 10) as u64)
            .expect("close should emit a websocket session event");

        assert_eq!(event.host, "api.openai.com");
        assert_eq!(event.path, "/v1/realtime");
        assert_eq!(event.classification, TrafficClassification::ToolUsage);
        assert_eq!(event.message_count, MAX_WS_MESSAGES_PER_CONNECTION);
        assert_eq!(event.messages.len(), MAX_WS_MESSAGES_PER_CONNECTION);
        assert_eq!(event.started_at_ms, 0);
        assert_eq!(
            event.ended_at_ms,
            (MAX_WS_MESSAGES_PER_CONNECTION + 10) as u64
        );
        assert_eq!(
            event.duration_ms,
            (MAX_WS_MESSAGES_PER_CONNECTION + 10) as u64
        );
        assert_eq!(event.messages[0].timestamp_ms, 5);
    }

    #[test]
    fn websocket_upgrade_event_is_recorded_for_intercepted_upgrade_request() {
        futures::executor::block_on(async {
            let detector = Arc::new(detector());
            let lookup = StaticProcessLookup {
                identity: ProcessIdentity::new(
                    Some("com.anthropic.claudefordesktop".to_string()),
                    None,
                ),
            };
            let mut handler = HudsuckerDetectionHandler::new(detector, lookup);

            let ctx =
                test_http_context("127.0.0.1:52111".parse().expect("socket addr should parse"));
            let request = hudsucker::hyper::Request::builder()
                .method(hudsucker::hyper::Method::GET)
                .uri("/v1/messages")
                .header(hudsucker::hyper::header::HOST, "api.anthropic.com")
                .header(hudsucker::hyper::header::CONNECTION, "Upgrade")
                .header(hudsucker::hyper::header::UPGRADE, "websocket")
                .header(
                    hudsucker::hyper::header::SEC_WEBSOCKET_KEY,
                    "dGhlIHNhbXBsZSBub25jZQ==",
                )
                .body(hudsucker::Body::empty())
                .expect("websocket request should build");

            let result = hudsucker::HttpHandler::handle_request(&mut handler, &ctx, request).await;
            assert!(matches!(result, hudsucker::RequestOrResponse::Request(_)));

            let events = handler.drain_websocket_upgrade_events();
            assert_eq!(events.len(), 1);
            let event = &events[0];
            assert_eq!(event.method, "GET");
            assert_eq!(event.host, "api.anthropic.com");
            assert_eq!(event.path, "/v1/messages");
            assert_eq!(
                event.response_status,
                hudsucker::hyper::StatusCode::SWITCHING_PROTOCOLS.as_u16()
            );
            assert_eq!(event.classification, TrafficClassification::ToolUsage);
            assert!(event.request_headers.contains_key("sec-websocket-key"));
        });
    }

    #[test]
    fn websocket_context_parser_extracts_endpoints() {
        let parsed = parse_websocket_context_endpoints(
            "ServerToClient { src: ws://example.com/socket, dst: 127.0.0.1:51504 }",
        )
        .expect("context debug parser should work");

        assert_eq!(parsed.0, "ws://example.com/socket");
        assert_eq!(parsed.1, "127.0.0.1:51504");
    }

    #[test]
    fn response_body_capture_helper_handles_text_binary_and_truncation() {
        let (text, is_base64, truncated) = capture_normalized_body(
            br#"{"ok":true}"#,
            Some("application/json"),
            None,
            DEFAULT_HTTP_CAPTURE_BODY_BYTES,
        );
        assert_eq!(text, r#"{"ok":true}"#);
        assert!(!is_base64);
        assert!(!truncated);

        let (binary, is_base64, truncated) = capture_normalized_body(
            &[0, 159, 146, 150],
            Some("application/octet-stream"),
            None,
            DEFAULT_HTTP_CAPTURE_BODY_BYTES,
        );
        assert_eq!(
            binary,
            serde_json::json!({
                "_binary_base64": BASE64_STANDARD.encode([0, 159, 146, 150]),
            })
            .to_string()
        );
        assert!(is_base64);
        assert!(!truncated);

        let oversized = vec![b'a'; DEFAULT_HTTP_CAPTURE_BODY_BYTES + 10];
        let (captured, _, truncated) = capture_normalized_body(
            &oversized,
            Some("text/plain"),
            None,
            DEFAULT_HTTP_CAPTURE_BODY_BYTES,
        );
        assert!(!captured.is_empty());
        assert!(truncated);
    }

    #[test]
    fn response_body_capture_helper_normalizes_compressed_payload() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(br#"{"stream":true}"#)
            .expect("gzip encoder should accept bytes");
        let payload = encoder.finish().expect("gzip encoder should finish");

        let (captured, is_base64, truncated) = capture_normalized_body(
            payload.as_slice(),
            Some("application/json"),
            None,
            DEFAULT_HTTP_CAPTURE_BODY_BYTES,
        );
        assert_eq!(captured, r#"{"stream":true}"#);
        assert!(!is_base64);
        assert!(!truncated);
    }

    #[test]
    fn response_body_capture_helper_applies_bundle_stream_parser() {
        let parser = BundleStreamParser::sse(
            vec!["data: ".to_string()],
            vec!["[DONE]".to_string(), "v1".to_string()],
        );
        let body = br#"data: v1
data: {"content":"hello"}
data: [DONE]
"#;

        let (captured, is_base64, truncated) = capture_normalized_body(
            body,
            Some("text/event-stream; charset=utf-8"),
            Some(&parser),
            DEFAULT_HTTP_CAPTURE_BODY_BYTES,
        );

        assert_eq!(captured, r#"{"content":"hello"}"#);
        assert!(!is_base64);
        assert!(!truncated);
    }

    #[test]
    fn headers_to_strings_merges_duplicate_headers() {
        let mut headers = hudsucker::hyper::HeaderMap::new();
        headers.append(
            hudsucker::hyper::header::SET_COOKIE,
            hudsucker::hyper::header::HeaderValue::from_static("a=1"),
        );
        headers.append(
            hudsucker::hyper::header::SET_COOKIE,
            hudsucker::hyper::header::HeaderValue::from_static("b=2"),
        );

        let mapped = headers_to_strings(&headers);
        assert_eq!(
            mapped.get("set-cookie").map(String::as_str),
            Some("a=1, b=2")
        );
    }

    #[test]
    fn tls_passthrough_matches_static_patterns_and_learned_hosts() {
        let mut passthrough =
            TlsPassthrough::from_patterns(&[String::from("^api\\.anthropic\\.com$")]);
        assert!(passthrough.should_passthrough("api.anthropic.com"));
        assert!(!passthrough.should_passthrough("api.openai.com"));

        passthrough.add_host("api.openai.com");
        assert!(passthrough.should_passthrough("api.openai.com"));
    }

    #[test]
    fn tls_passthrough_ignores_whitelisted_failure_but_learns_non_whitelisted() {
        let mut passthrough = TlsPassthrough::default();
        passthrough.record_tls_failure("api.anthropic.com", "certificate verify failed", true);
        assert!(!passthrough.should_passthrough("api.anthropic.com"));

        passthrough.record_tls_failure(
            "not-in-catalog.example",
            "client disconnected during the handshake",
            false,
        );
        assert!(passthrough.should_passthrough("not-in-catalog.example"));
    }

    #[derive(Clone)]
    struct StaticProcessLookup {
        identity: ProcessIdentity,
    }

    impl ProcessLookup for StaticProcessLookup {
        fn resolve(&self, _client_addr: SocketAddr) -> ProcessIdentity {
            self.identity.clone()
        }
    }

    #[derive(Clone, Copy)]
    struct HttpOnlyTestAuthority;

    impl hudsucker::certificate_authority::CertificateAuthority for HttpOnlyTestAuthority {
        fn gen_server_config(
            &self,
            _authority: &hudsucker::hyper::http::uri::Authority,
        ) -> impl Future<Output = Arc<hudsucker::rustls::ServerConfig>> + Send {
            async { panic!("TLS interception is not expected in this HTTP-only integration test") }
        }
    }

    async fn start_test_http_upstream() -> Option<(SocketAddr, oneshot::Sender<()>)> {
        let listener = match TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return None,
            Err(error) => panic!("upstream listener should bind: {error}"),
        };
        let addr = listener
            .local_addr()
            .expect("upstream listener should have a local addr");
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        break;
                    }
                    accepted = listener.accept() => {
                        let Ok((stream, _peer)) = accepted else {
                            break;
                        };

                        let service = hudsucker::hyper::service::service_fn(
                            |_req: hudsucker::hyper::Request<hudsucker::hyper::body::Incoming>| async move {
                                Ok::<_, Infallible>(
                                    hudsucker::hyper::Response::builder()
                                        .status(hudsucker::hyper::StatusCode::OK)
                                        .header(hudsucker::hyper::header::CONTENT_TYPE, "application/json")
                                        .body(hudsucker::Body::from(r#"{"ok":true}"#))
                                        .expect("upstream response should build"),
                                )
                            },
                        );

                        tokio::spawn(async move {
                            let _ = hudsucker::hyper_util::server::conn::auto::Builder::new(
                                hudsucker::hyper_util::rt::TokioExecutor::new(),
                            )
                            .serve_connection_with_upgrades(
                                hudsucker::hyper_util::rt::TokioIo::new(stream),
                                service,
                            )
                            .await;
                        });
                    }
                }
            }
        });

        Some((addr, shutdown_tx))
    }

    async fn start_test_proxy(
        handler: HudsuckerDetectionHandler<StaticProcessLookup>,
    ) -> Option<(SocketAddr, oneshot::Sender<()>)> {
        let listener = match TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return None,
            Err(error) => panic!("proxy listener should bind: {error}"),
        };
        let addr = listener
            .local_addr()
            .expect("proxy listener should have a local addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let proxy = hudsucker::Proxy::builder()
            .with_listener(listener)
            .with_ca(HttpOnlyTestAuthority)
            .with_http_connector(
                hudsucker::hyper_util::client::legacy::connect::HttpConnector::new(),
            )
            .with_http_handler(handler.clone())
            .with_websocket_handler(handler)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .build()
            .expect("proxy should build");

        tokio::spawn(async move {
            let _ = proxy.start().await;
        });

        Some((addr, shutdown_tx))
    }

    fn test_http_context(client_addr: SocketAddr) -> hudsucker::HttpContext {
        // SAFETY: hudsucker 0.24.0 exposes `HttpContext` as non_exhaustive with no
        // constructor, but currently it only contains `client_addr`.
        unsafe {
            let mut ctx = std::mem::MaybeUninit::<hudsucker::HttpContext>::zeroed();
            std::ptr::addr_of_mut!((*ctx.as_mut_ptr()).client_addr).write(client_addr);
            ctx.assume_init()
        }
    }

    fn capture_http_exchange_event_from_response(
        response_content_type: &str,
        response_body: Vec<u8>,
    ) -> HttpExchangeEvent {
        futures::executor::block_on(async {
            let detector = Arc::new(detector());
            let lookup = StaticProcessLookup {
                identity: ProcessIdentity::new(
                    Some("com.anthropic.claudefordesktop".to_string()),
                    None,
                ),
            };
            let mut handler = HudsuckerDetectionHandler::new(detector, lookup);
            let ctx =
                test_http_context("127.0.0.1:51900".parse().expect("socket addr should parse"));

            let request = hudsucker::hyper::Request::builder()
                .method(hudsucker::hyper::Method::POST)
                .uri("/v1/messages")
                .header(hudsucker::hyper::header::HOST, "api.anthropic.com")
                .header(hudsucker::hyper::header::CONTENT_TYPE, "application/json")
                .body(hudsucker::Body::from(r#"{"input":"hi"}"#.to_string()))
                .expect("request should build");

            let forwarded_request =
                match hudsucker::HttpHandler::handle_request(&mut handler, &ctx, request).await {
                    hudsucker::RequestOrResponse::Request(req) => req,
                    hudsucker::RequestOrResponse::Response(_) => {
                        panic!("request should be forwarded for anthropic")
                    }
                };

            let (_request_parts, req_body) = forwarded_request.into_parts();
            let forwarded_request_bytes = req_body
                .collect()
                .await
                .expect("forwarded request body should be readable")
                .to_bytes();
            assert_eq!(forwarded_request_bytes.as_ref(), br#"{"input":"hi"}"#);

            let response = hudsucker::hyper::Response::builder()
                .status(hudsucker::hyper::StatusCode::OK)
                .header(
                    hudsucker::hyper::header::CONTENT_TYPE,
                    response_content_type,
                )
                .body(hudsucker::Body::from(Full::new(
                    hudsucker::hyper::body::Bytes::from(response_body.clone()),
                )))
                .expect("response should build");

            let proxied_response =
                hudsucker::HttpHandler::handle_response(&mut handler, &ctx, response).await;

            let (_response_parts, body) = proxied_response.into_parts();
            let proxied_response_bytes = body
                .collect()
                .await
                .expect("proxied response body should be readable")
                .to_bytes();
            assert_eq!(proxied_response_bytes.as_ref(), response_body.as_slice());

            let mut events = handler.drain_http_exchange_events();
            assert_eq!(events.len(), 1);
            events.remove(0)
        })
    }

    fn grpc_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(5 + payload.len());
        frame.push(0);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn handler_captures_normalized_request_and_response_bodies_end_to_end() {
        futures::executor::block_on(async {
            let detector = Arc::new(detector());
            let lookup = StaticProcessLookup {
                identity: ProcessIdentity::new(
                    Some("com.anthropic.claudefordesktop".to_string()),
                    None,
                ),
            };

            let mut handler = HudsuckerDetectionHandler::new(detector, lookup);
            let ctx =
                test_http_context("127.0.0.1:51777".parse().expect("socket addr should parse"));

            let request = hudsucker::hyper::Request::builder()
                .method(hudsucker::hyper::Method::POST)
                .uri("/v1/messages")
                .header(hudsucker::hyper::header::HOST, "api.anthropic.com")
                .header(hudsucker::hyper::header::CONTENT_TYPE, "application/json")
                .body(hudsucker::Body::from(r#"{"input":"hi"}"#.to_string()))
                .expect("request should build");

            let forwarded_request =
                match hudsucker::HttpHandler::handle_request(&mut handler, &ctx, request).await {
                    hudsucker::RequestOrResponse::Request(req) => req,
                    hudsucker::RequestOrResponse::Response(_) => {
                        panic!("request should be forwarded for anthropic")
                    }
                };

            let (_req_parts, req_body) = forwarded_request.into_parts();
            let req_bytes = req_body
                .collect()
                .await
                .expect("forwarded request body should be readable")
                .to_bytes();
            assert_eq!(req_bytes.as_ref(), br#"{"input":"hi"}"#);

            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(br#"{"output":"hello"}"#)
                .expect("gzip encoder should accept input");
            let compressed_response = encoder.finish().expect("gzip encoder should finish");

            let response = hudsucker::hyper::Response::builder()
                .status(hudsucker::hyper::StatusCode::OK)
                .header(hudsucker::hyper::header::CONTENT_TYPE, "application/json")
                .body(hudsucker::Body::from(Full::new(
                    hudsucker::hyper::body::Bytes::from(compressed_response.clone()),
                )))
                .expect("response should build");

            let proxied_response =
                hudsucker::HttpHandler::handle_response(&mut handler, &ctx, response).await;

            let (_parts, body) = proxied_response.into_parts();
            let proxied_bytes = body
                .collect()
                .await
                .expect("proxied response body should be readable")
                .to_bytes();
            assert_eq!(proxied_bytes.as_ref(), compressed_response.as_slice());

            let events = handler.drain_http_exchange_events();
            assert_eq!(events.len(), 1);

            let event = &events[0];
            assert_eq!(event.host, "api.anthropic.com");
            assert_eq!(event.path, "/v1/messages");
            assert_eq!(event.capture_mode, CaptureMode::Full);
            assert_eq!(event.request_body.as_deref(), Some(r#"{"input":"hi"}"#));
            assert!(!event.request_body_base64);
            assert!(!event.request_body_truncated);
            assert!(event.request_body_error.is_none());
            assert_eq!(
                event.response_body.as_deref(),
                Some(r#"{"output":"hello"}"#)
            );
            assert!(!event.response_body_base64);
            assert!(!event.response_body_truncated);
            assert!(event.response_body_error.is_none());
        });
    }

    #[test]
    fn handler_normalizes_sse_stream_responses_end_to_end() {
        let event = capture_http_exchange_event_from_response(
            "text/event-stream; charset=utf-8",
            br#"event: message
data: {"type":"delta"}
data: {"text":"hello"}
data: [DONE]
"#
            .to_vec(),
        );

        assert_eq!(event.host, "api.anthropic.com");
        assert_eq!(event.path, "/v1/messages");
        assert_eq!(
            event.response_body.as_deref(),
            Some(r#"{"type":"delta"}{"text":"hello"}"#)
        );
        assert!(!event.response_body_base64);
        assert!(!event.response_body_truncated);
        assert!(event.response_body_error.is_none());
    }

    #[test]
    fn handler_normalizes_anti_hijack_json_stream_end_to_end() {
        let event = capture_http_exchange_event_from_response(
            "application/json",
            b"for(;;);8\n{\"a\":1}\n".to_vec(),
        );

        assert_eq!(event.host, "api.anthropic.com");
        assert_eq!(event.path, "/v1/messages");
        assert_eq!(event.response_body.as_deref(), Some(r#"[{"a":1}]"#));
        assert!(!event.response_body_base64);
        assert!(!event.response_body_truncated);
        assert!(event.response_body_error.is_none());
    }

    #[test]
    fn handler_normalizes_grpc_response_body_end_to_end() {
        let event = capture_http_exchange_event_from_response(
            "application/grpc",
            grpc_frame(&[0x0a, 0x02, b'o', b'k']),
        );

        let body = event
            .response_body
            .as_ref()
            .expect("grpc response should be captured");
        let parsed: serde_json::Value =
            serde_json::from_str(body).expect("grpc response should normalize as json");
        assert_eq!(
            parsed.get("1").and_then(serde_json::Value::as_str),
            Some("ok")
        );
        assert!(!event.response_body_base64);
        assert!(!event.response_body_truncated);
        assert!(event.response_body_error.is_none());
    }

    #[test]
    fn handler_websocket_lifecycle_emits_turn_and_session_events_end_to_end() {
        futures::executor::block_on(async {
            let detector = Arc::new(detector());
            let lookup = StaticProcessLookup {
                identity: ProcessIdentity::new(
                    Some("com.anthropic.claudefordesktop".to_string()),
                    None,
                ),
            };
            let mut handler = HudsuckerDetectionHandler::new(detector, lookup);

            let client_addr: SocketAddr =
                "127.0.0.1:52112".parse().expect("socket addr should parse");
            let http_ctx = test_http_context(client_addr);
            let upgrade_request = hudsucker::hyper::Request::builder()
                .method(hudsucker::hyper::Method::GET)
                .uri("/v1/messages")
                .header(hudsucker::hyper::header::HOST, "api.anthropic.com")
                .header(hudsucker::hyper::header::CONNECTION, "Upgrade")
                .header(hudsucker::hyper::header::UPGRADE, "websocket")
                .header(
                    hudsucker::hyper::header::SEC_WEBSOCKET_KEY,
                    "dGhlIHNhbXBsZSBub25jZQ==",
                )
                .body(hudsucker::Body::empty())
                .expect("websocket request should build");

            let result =
                hudsucker::HttpHandler::handle_request(&mut handler, &http_ctx, upgrade_request)
                    .await;
            assert!(matches!(result, hudsucker::RequestOrResponse::Request(_)));

            let base_context = WebSocketContextInfo {
                client_addr,
                host: "api.anthropic.com".to_string(),
                path: "/v1/messages".to_string(),
                connection_key: websocket_connection_key(
                    client_addr,
                    "api.anthropic.com",
                    "/v1/messages",
                ),
                host_key: websocket_host_key(client_addr, "api.anthropic.com"),
                direction: WebSocketDirection::ClientToServer,
            };

            let c2s = WebSocketContextInfo {
                direction: WebSocketDirection::ClientToServer,
                ..base_context.clone()
            };
            let s2c = WebSocketContextInfo {
                direction: WebSocketDirection::ServerToClient,
                ..base_context
            };

            handler.observe_websocket_message(
                Some(c2s),
                &Message::Text(r#"{"type":"input","text":"hi"}"#.into()),
            );
            handler.observe_websocket_message(
                Some(s2c.clone()),
                &Message::Text(r#"{"type":"message_stop"}"#.into()),
            );
            handler.observe_websocket_message(Some(s2c.clone()), &Message::Close(None));

            let turn_events = handler.drain_websocket_turn_events();
            assert_eq!(turn_events.len(), 1);
            let turn = &turn_events[0];
            assert_eq!(turn.host, "api.anthropic.com");
            assert_eq!(turn.path, "/v1/messages");
            assert_eq!(turn.message_count, 2);
            assert_eq!(turn.messages.len(), 2);

            let session_events = handler.drain_websocket_session_events();
            assert_eq!(session_events.len(), 1);
            let session = &session_events[0];
            assert_eq!(session.host, "api.anthropic.com");
            assert_eq!(session.path, "/v1/messages");
            assert_eq!(session.message_count, 3);
            assert_eq!(session.messages.len(), 3);
            assert!(session.ended_at_ms >= session.started_at_ms);
            assert_eq!(
                session.duration_ms,
                session.ended_at_ms.saturating_sub(session.started_at_ms)
            );
            assert_eq!(session.messages[2].content, r#"{"type":"close"}"#);

            handler.observe_websocket_message(
                Some(s2c),
                &Message::Text(r#"{"type":"message_stop"}"#.into()),
            );

            assert!(handler.drain_websocket_turn_events().is_empty());
            assert!(handler.drain_websocket_session_events().is_empty());
        });
    }

    #[test]
    fn concurrent_http_request_response_correlation_uses_request_id_map() {
        futures::executor::block_on(async {
            let detector = Arc::new(detector());
            let lookup = StaticProcessLookup {
                identity: ProcessIdentity::new(
                    Some("com.anthropic.claudefordesktop".to_string()),
                    None,
                ),
            };

            let base_handler = HudsuckerDetectionHandler::new(detector, lookup);
            let mut first_handler = base_handler.clone();
            let mut second_handler = base_handler.clone();

            let ctx =
                test_http_context("127.0.0.1:53111".parse().expect("socket addr should parse"));

            let first_request = hudsucker::hyper::Request::builder()
                .method(hudsucker::hyper::Method::POST)
                .uri("/v1/messages")
                .header(hudsucker::hyper::header::HOST, "api.anthropic.com")
                .header(hudsucker::hyper::header::CONTENT_TYPE, "application/json")
                .body(hudsucker::Body::from(r#"{"input":"one"}"#.to_string()))
                .expect("first request should build");

            let second_request = hudsucker::hyper::Request::builder()
                .method(hudsucker::hyper::Method::POST)
                .uri("/v1/messages")
                .header(hudsucker::hyper::header::HOST, "api.anthropic.com")
                .header(hudsucker::hyper::header::CONTENT_TYPE, "application/json")
                .body(hudsucker::Body::from(r#"{"input":"two"}"#.to_string()))
                .expect("second request should build");

            let forwarded_first_request = match hudsucker::HttpHandler::handle_request(
                &mut first_handler,
                &ctx,
                first_request,
            )
            .await
            {
                hudsucker::RequestOrResponse::Request(req) => req,
                hudsucker::RequestOrResponse::Response(_) => {
                    panic!("first request should be forwarded")
                }
            };
            let forwarded_second_request = match hudsucker::HttpHandler::handle_request(
                &mut second_handler,
                &ctx,
                second_request,
            )
            .await
            {
                hudsucker::RequestOrResponse::Request(req) => req,
                hudsucker::RequestOrResponse::Response(_) => {
                    panic!("second request should be forwarded")
                }
            };

            assert!(first_handler.active_http_request_id.is_some());
            assert!(second_handler.active_http_request_id.is_some());
            let captures = lock_recover(&base_handler.pending_http_captures);
            assert_eq!(captures.len(), 2);
            drop(captures);

            let (_first_parts, first_body) = forwarded_first_request.into_parts();
            let first_body = first_body
                .collect()
                .await
                .expect("first forwarded request body should be readable")
                .to_bytes();
            assert_eq!(first_body.as_ref(), br#"{"input":"one"}"#);

            let (_second_parts, second_body) = forwarded_second_request.into_parts();
            let second_body = second_body
                .collect()
                .await
                .expect("second forwarded request body should be readable")
                .to_bytes();
            assert_eq!(second_body.as_ref(), br#"{"input":"two"}"#);

            let second_response = hudsucker::hyper::Response::builder()
                .status(hudsucker::hyper::StatusCode::OK)
                .header(hudsucker::hyper::header::CONTENT_TYPE, "application/json")
                .body(hudsucker::Body::from(Full::new(
                    hudsucker::hyper::body::Bytes::from_static(br#"{"output":"two"}"#),
                )))
                .expect("second response should build");
            let proxied_second_response =
                hudsucker::HttpHandler::handle_response(&mut second_handler, &ctx, second_response)
                    .await;
            let (_parts, body) = proxied_second_response.into_parts();
            let _ = body
                .collect()
                .await
                .expect("second proxied body should be readable")
                .to_bytes();

            let first_response = hudsucker::hyper::Response::builder()
                .status(hudsucker::hyper::StatusCode::OK)
                .header(hudsucker::hyper::header::CONTENT_TYPE, "application/json")
                .body(hudsucker::Body::from(Full::new(
                    hudsucker::hyper::body::Bytes::from_static(br#"{"output":"one"}"#),
                )))
                .expect("first response should build");
            let proxied_first_response =
                hudsucker::HttpHandler::handle_response(&mut first_handler, &ctx, first_response)
                    .await;
            let (_parts, body) = proxied_first_response.into_parts();
            let _ = body
                .collect()
                .await
                .expect("first proxied body should be readable")
                .to_bytes();

            let events = base_handler.drain_http_exchange_events();
            assert_eq!(events.len(), 2);

            let first_event = events
                .iter()
                .find(|event| event.request_body.as_deref() == Some(r#"{"input":"one"}"#))
                .expect("first request event should exist");
            let second_event = events
                .iter()
                .find(|event| event.request_body.as_deref() == Some(r#"{"input":"two"}"#))
                .expect("second request event should exist");

            assert_eq!(
                first_event.response_body.as_deref(),
                Some(r#"{"output":"one"}"#)
            );
            assert_eq!(
                second_event.response_body.as_deref(),
                Some(r#"{"output":"two"}"#)
            );
            assert_ne!(first_event.request_id, second_event.request_id);
        });
    }

    #[test]
    fn edge_queue_writer_enqueues_http_exchange_to_upload_queue() {
        futures::executor::block_on(async {
            let temp_dir = tempfile::tempdir().expect("temp dir should be created");
            let logger_path = temp_dir.path().join("events.db");
            let logger = EventLogger::new(logger_path).expect("event logger should initialize");
            let queue_writer = Arc::new(EdgeQueueWriter::new(logger.clone()));

            let detector = Arc::new(detector());
            let lookup = StaticProcessLookup {
                identity: ProcessIdentity::new(
                    Some("com.anthropic.claudefordesktop".to_string()),
                    None,
                ),
            };
            let mut handler = HudsuckerDetectionHandler::new(detector, lookup)
                .with_edge_queue_writer(queue_writer);

            let ctx =
                test_http_context("127.0.0.1:53112".parse().expect("socket addr should parse"));
            let request = hudsucker::hyper::Request::builder()
                .method(hudsucker::hyper::Method::POST)
                .uri("/v1/messages")
                .header(hudsucker::hyper::header::HOST, "api.anthropic.com")
                .header(hudsucker::hyper::header::CONTENT_TYPE, "application/json")
                .body(hudsucker::Body::from(r#"{"input":"hi"}"#.to_string()))
                .expect("request should build");

            let forwarded_request =
                match hudsucker::HttpHandler::handle_request(&mut handler, &ctx, request).await {
                    hudsucker::RequestOrResponse::Request(req) => req,
                    hudsucker::RequestOrResponse::Response(_) => {
                        panic!("request should be forwarded for anthropic")
                    }
                };
            assert!(handler.active_http_request_id.is_some());
            let captures = lock_recover(&handler.pending_http_captures);
            assert_eq!(captures.len(), 1);
            let seeded_exchange_id = captures
                .values()
                .next()
                .map(|pending| pending.exchange_id.clone())
                .expect("pending capture should have exchange id");
            drop(captures);
            let seeded_spool = logger
                .load_exchange_spool_pending(10)
                .expect("exchange spool should be readable");
            assert_eq!(seeded_spool.len(), 1);
            assert_eq!(seeded_spool[0].exchange_id, seeded_exchange_id);

            let (_request_parts, request_body) = forwarded_request.into_parts();
            let forwarded_request_bytes = request_body
                .collect()
                .await
                .expect("forwarded request body should be readable")
                .to_bytes();
            assert_eq!(forwarded_request_bytes.as_ref(), br#"{"input":"hi"}"#);

            let response = hudsucker::hyper::Response::builder()
                .status(hudsucker::hyper::StatusCode::OK)
                .header(hudsucker::hyper::header::CONTENT_TYPE, "application/json")
                .body(hudsucker::Body::from(Full::new(
                    hudsucker::hyper::body::Bytes::from_static(br#"{"output":"hello"}"#),
                )))
                .expect("response should build");
            let proxied_response =
                hudsucker::HttpHandler::handle_response(&mut handler, &ctx, response).await;
            let (_parts, body) = proxied_response.into_parts();
            let _ = body
                .collect()
                .await
                .expect("proxied body should be readable")
                .to_bytes();

            let mut events = handler.drain_http_exchange_events();
            assert_eq!(events.len(), 1);
            let event = events.remove(0);
            assert!(Uuid::parse_str(event.exchange_id.as_str()).is_ok());

            let queued = logger
                .load_exchange_upload_queue_ready(10)
                .expect("upload queue should be readable");
            assert_eq!(queued.len(), 1);
            assert_eq!(queued[0].exchange_id, event.exchange_id);
            let pending_spool_after_enqueue = logger
                .load_exchange_spool_pending(10)
                .expect("exchange spool should be readable after enqueue");
            assert!(pending_spool_after_enqueue.is_empty());

            let exchange: soth_core::ExchangeEvent = serde_json::from_str(&queued[0].payload_json)
                .expect("queued payload should deserialize as exchange event");
            assert_eq!(exchange.exchange_id, event.exchange_id);
            assert_eq!(
                exchange.trace_id.as_deref(),
                Some(event.request_id.as_str())
            );
            assert_eq!(exchange.method.as_deref(), Some("POST"));
            assert_eq!(exchange.status_code, Some(200));
            assert_eq!(exchange.provider.as_deref(), Some("anthropic"));
            assert_eq!(exchange.agent.as_deref(), Some("claude"));
            assert_eq!(
                exchange.detection_id.as_deref(),
                Some("ai.anthropic.service")
            );
            assert_eq!(
                exchange
                    .parse
                    .as_ref()
                    .and_then(|parse| parse.detection_source.as_deref()),
                Some("bundle")
            );
            assert_eq!(
                exchange.request.body.inline.as_deref(),
                Some(r#"{"input":"hi"}"#)
            );
            assert_eq!(
                exchange.response.body.inline.as_deref(),
                Some(r#"{"output":"hello"}"#)
            );
            assert_eq!(
                exchange
                    .client
                    .as_ref()
                    .and_then(|client| client.bundle_id.as_deref()),
                Some("com.anthropic.claudefordesktop")
            );
            assert_eq!(
                exchange
                    .client
                    .as_ref()
                    .and_then(|client| client.process_name.as_deref()),
                None
            );
        });
    }

    #[test]
    fn edge_queue_writer_does_not_enqueue_blacklisted_http_exchange() {
        futures::executor::block_on(async {
            let temp_dir = tempfile::tempdir().expect("temp dir should be created");
            let logger_path = temp_dir.path().join("events.db");
            let logger = EventLogger::new(logger_path).expect("event logger should initialize");
            let queue_writer = Arc::new(EdgeQueueWriter::new(logger.clone()));

            let detector = Arc::new(detector());
            let lookup = StaticProcessLookup {
                identity: ProcessIdentity::new(
                    Some("com.anthropic.claudefordesktop".to_string()),
                    None,
                ),
            };
            let mut handler = HudsuckerDetectionHandler::new(detector, lookup)
                .with_edge_queue_writer(queue_writer);

            let ctx =
                test_http_context("127.0.0.1:53115".parse().expect("socket addr should parse"));
            let request = hudsucker::hyper::Request::builder()
                .method(hudsucker::hyper::Method::POST)
                .uri("/v1/telemetry/events")
                .header(hudsucker::hyper::header::HOST, "api.anthropic.com")
                .header(hudsucker::hyper::header::CONTENT_TYPE, "application/json")
                .body(hudsucker::Body::from(r#"{"input":"hi"}"#.to_string()))
                .expect("request should build");

            let forwarded_request =
                match hudsucker::HttpHandler::handle_request(&mut handler, &ctx, request).await {
                    hudsucker::RequestOrResponse::Request(req) => req,
                    hudsucker::RequestOrResponse::Response(_) => {
                        panic!("request should be forwarded for blacklisted check")
                    }
                };
            let (_request_parts, request_body) = forwarded_request.into_parts();
            let _ = request_body
                .collect()
                .await
                .expect("forwarded request body should be readable")
                .to_bytes();

            let response = hudsucker::hyper::Response::builder()
                .status(hudsucker::hyper::StatusCode::OK)
                .header(hudsucker::hyper::header::CONTENT_TYPE, "application/json")
                .body(hudsucker::Body::from(Full::new(
                    hudsucker::hyper::body::Bytes::from_static(br#"{"output":"ignored"}"#),
                )))
                .expect("response should build");
            let proxied_response =
                hudsucker::HttpHandler::handle_response(&mut handler, &ctx, response).await;
            let (_parts, body) = proxied_response.into_parts();
            let _ = body
                .collect()
                .await
                .expect("proxied body should be readable")
                .to_bytes();

            let mut events = handler.drain_http_exchange_events();
            assert_eq!(events.len(), 1);
            let event = events.remove(0);
            assert_eq!(event.reason, DecisionReason::Blacklisted);
            assert_eq!(event.action, InterceptionAction::Skip);

            let queued = logger
                .load_exchange_upload_queue_ready(10)
                .expect("upload queue should be readable");
            assert!(queued.is_empty());

            let pending_spool = logger
                .load_exchange_spool_pending(10)
                .expect("exchange spool should be readable");
            assert!(pending_spool.is_empty());
        });
    }

    #[test]
    fn pending_capture_eviction_is_fifo_and_cleans_spool_rows() {
        futures::executor::block_on(async {
            let temp_dir = tempfile::tempdir().expect("temp dir should be created");
            let logger_path = temp_dir.path().join("events.db");
            let logger = EventLogger::new(logger_path).expect("event logger should initialize");
            let queue_writer = Arc::new(EdgeQueueWriter::new(logger.clone()));

            let detector = Arc::new(detector());
            let lookup = StaticProcessLookup {
                identity: ProcessIdentity::new(
                    Some("com.anthropic.claudefordesktop".to_string()),
                    None,
                ),
            };
            let mut handler = HudsuckerDetectionHandler::new(detector, lookup)
                .with_edge_queue_writer(queue_writer);
            handler.set_max_pending_http_captures(2);

            let ctx =
                test_http_context("127.0.0.1:53117".parse().expect("socket addr should parse"));

            async fn send_request_and_capture_exchange_id(
                handler: &mut HudsuckerDetectionHandler<StaticProcessLookup>,
                ctx: &hudsucker::HttpContext,
                body: &str,
            ) -> (String, String) {
                let request = hudsucker::hyper::Request::builder()
                    .method(hudsucker::hyper::Method::POST)
                    .uri("/v1/messages")
                    .header(hudsucker::hyper::header::HOST, "api.anthropic.com")
                    .header(hudsucker::hyper::header::CONTENT_TYPE, "application/json")
                    .body(hudsucker::Body::from(body.to_string()))
                    .expect("request should build");

                let forwarded_request =
                    match hudsucker::HttpHandler::handle_request(handler, ctx, request).await {
                        hudsucker::RequestOrResponse::Request(req) => req,
                        hudsucker::RequestOrResponse::Response(_) => {
                            panic!("request should be forwarded for anthropic")
                        }
                    };

                let (_parts, body_stream) = forwarded_request.into_parts();
                let _ = body_stream
                    .collect()
                    .await
                    .expect("forwarded request body should be readable")
                    .to_bytes();

                let request_id = handler
                    .active_http_request_id
                    .clone()
                    .expect("active request id should be set");
                let captures = lock_recover(&handler.pending_http_captures);
                let exchange_id = captures
                    .get(request_id.as_str())
                    .map(|pending| pending.exchange_id.clone())
                    .expect("pending capture should exist");
                drop(captures);
                (request_id, exchange_id)
            }

            let (first_request_id, first_exchange_id) =
                send_request_and_capture_exchange_id(&mut handler, &ctx, r#"{"input":"one"}"#)
                    .await;
            let (second_request_id, second_exchange_id) =
                send_request_and_capture_exchange_id(&mut handler, &ctx, r#"{"input":"two"}"#)
                    .await;
            let (third_request_id, third_exchange_id) =
                send_request_and_capture_exchange_id(&mut handler, &ctx, r#"{"input":"three"}"#)
                    .await;

            let captures = lock_recover(&handler.pending_http_captures);
            assert_eq!(captures.len(), 2);
            assert!(!captures.contains_key(first_request_id.as_str()));
            assert!(captures.contains_key(second_request_id.as_str()));
            assert!(captures.contains_key(third_request_id.as_str()));
            drop(captures);

            let pending_spool = logger
                .load_exchange_spool_pending(10)
                .expect("exchange spool should be readable");
            assert_eq!(pending_spool.len(), 2);
            let pending_ids = pending_spool
                .iter()
                .map(|row| row.exchange_id.clone())
                .collect::<Vec<_>>();
            assert!(!pending_ids.contains(&first_exchange_id));
            assert!(pending_ids.contains(&second_exchange_id));
            assert!(pending_ids.contains(&third_exchange_id));
        });
    }

    #[test]
    fn request_body_capture_streaming_respects_configured_cap() {
        futures::executor::block_on(async {
            let detector = Arc::new(detector());
            let lookup = StaticProcessLookup {
                identity: ProcessIdentity::new(
                    Some("com.anthropic.claudefordesktop".to_string()),
                    None,
                ),
            };
            let mut handler = HudsuckerDetectionHandler::new(detector, lookup);
            handler.set_http_capture_body_limit(16);

            let ctx =
                test_http_context("127.0.0.1:53118".parse().expect("socket addr should parse"));

            let request_body = hudsucker::Body::from_stream(futures::stream::iter(vec![
                Ok::<_, std::io::Error>(hudsucker::hyper::body::Bytes::from_static(b"abcdefghij")),
                Ok::<_, std::io::Error>(hudsucker::hyper::body::Bytes::from_static(b"klmnopqrst")),
                Ok::<_, std::io::Error>(hudsucker::hyper::body::Bytes::from_static(b"uvwxyz")),
            ]));

            let request = hudsucker::hyper::Request::builder()
                .method(hudsucker::hyper::Method::POST)
                .uri("/v1/messages")
                .header(hudsucker::hyper::header::HOST, "api.anthropic.com")
                .header(hudsucker::hyper::header::CONTENT_TYPE, "text/plain")
                .body(request_body)
                .expect("streaming request should build");

            let forwarded_request =
                match hudsucker::HttpHandler::handle_request(&mut handler, &ctx, request).await {
                    hudsucker::RequestOrResponse::Request(req) => req,
                    hudsucker::RequestOrResponse::Response(_) => {
                        panic!("request should be forwarded for anthropic")
                    }
                };

            let (_req_parts, req_body) = forwarded_request.into_parts();
            let req_bytes = req_body
                .collect()
                .await
                .expect("forwarded request body should be readable")
                .to_bytes();
            assert_eq!(req_bytes.as_ref(), b"abcdefghijklmnopqrstuvwxyz");

            let response = hudsucker::hyper::Response::builder()
                .status(hudsucker::hyper::StatusCode::OK)
                .header(hudsucker::hyper::header::CONTENT_TYPE, "application/json")
                .body(hudsucker::Body::from(Full::new(
                    hudsucker::hyper::body::Bytes::from_static(br#"{"ok":true}"#),
                )))
                .expect("response should build");
            let proxied_response =
                hudsucker::HttpHandler::handle_response(&mut handler, &ctx, response).await;
            let (_parts, body) = proxied_response.into_parts();
            let _ = body
                .collect()
                .await
                .expect("proxied response body should be readable")
                .to_bytes();

            let mut events = handler.drain_http_exchange_events();
            assert_eq!(events.len(), 1);
            let event = events.remove(0);
            assert_eq!(event.request_body.as_deref(), Some("abcdefghijklmnop"));
            assert!(event.request_body_truncated);
            assert!(event.request_body_error.is_none());
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn proxy_socket_level_http_interception_end_to_end() {
        let detector = Arc::new(detector());
        let lookup = StaticProcessLookup {
            identity: ProcessIdentity::new(Some("com.apple.Safari".to_string()), None),
        };
        let handler = HudsuckerDetectionHandler::new(detector, lookup);

        let Some((upstream_addr, upstream_shutdown)) = start_test_http_upstream().await else {
            return;
        };
        let Some((proxy_addr, proxy_shutdown)) = start_test_proxy(handler.clone()).await else {
            let _ = upstream_shutdown.send(());
            return;
        };

        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = reqwest::Client::builder()
            .proxy(
                reqwest::Proxy::http(format!("http://{proxy_addr}"))
                    .expect("proxy URL should be valid"),
            )
            .build()
            .expect("reqwest client should build");

        let response = client
            .get(format!("http://{upstream_addr}/v1/messages"))
            .header("referer", "https://claude.ai/chat")
            .send()
            .await
            .expect("proxied request should succeed");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let body = response
            .text()
            .await
            .expect("proxied response body should be readable");
        assert_eq!(body, r#"{"ok":true}"#);

        let mut events = Vec::new();
        for _ in 0..40 {
            events = handler.drain_http_exchange_events();
            if !events.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.method, "GET");
        assert_eq!(event.path, "/v1/messages");
        assert_eq!(event.action, InterceptionAction::Intercept);
        assert_eq!(event.reason, DecisionReason::Allowed);
        assert_eq!(event.capture_mode, CaptureMode::MetadataOnly);
        assert!(event.discovery_capture);
        assert_eq!(event.response_status, 200);
        assert!(event.host == "127.0.0.1" || event.host == "localhost");
        assert!(event.request_body.is_none());
        assert!(event.response_body.is_none());

        let _ = proxy_shutdown.send(());
        let _ = upstream_shutdown.send(());
    }

    #[test]
    fn should_intercept_does_not_passthrough_when_tls_passthrough_disabled() {
        futures::executor::block_on(async {
            let detector = Arc::new(detector());
            let lookup = StaticProcessLookup {
                identity: ProcessIdentity::new(
                    Some("com.anthropic.claudefordesktop".to_string()),
                    None,
                ),
            };
            let mut handler = HudsuckerDetectionHandler::new(detector, lookup);

            handler.learn_tls_passthrough_host("api.anthropic.com");

            let ctx =
                test_http_context("127.0.0.1:51888".parse().expect("socket addr should parse"));
            let connect_req = hudsucker::hyper::Request::builder()
                .method(hudsucker::hyper::Method::CONNECT)
                .uri("api.anthropic.com:443")
                .body(hudsucker::Body::empty())
                .expect("connect request should build");

            let intercept =
                hudsucker::HttpHandler::should_intercept(&mut handler, &ctx, &connect_req).await;
            assert!(intercept);
        });
    }

    #[test]
    fn should_intercept_respects_learned_tls_passthrough_host_when_enabled() {
        futures::executor::block_on(async {
            let detector = Arc::new(detector());
            let lookup = StaticProcessLookup {
                identity: ProcessIdentity::new(
                    Some("com.anthropic.claudefordesktop".to_string()),
                    None,
                ),
            };
            let mut handler = HudsuckerDetectionHandler::new(detector, lookup);

            handler.set_tls_passthrough_enabled(true);
            handler.learn_tls_passthrough_host("api.anthropic.com");

            let ctx =
                test_http_context("127.0.0.1:51889".parse().expect("socket addr should parse"));
            let connect_req = hudsucker::hyper::Request::builder()
                .method(hudsucker::hyper::Method::CONNECT)
                .uri("api.anthropic.com:443")
                .body(hudsucker::Body::empty())
                .expect("connect request should build");

            let intercept =
                hudsucker::HttpHandler::should_intercept(&mut handler, &ctx, &connect_req).await;
            assert!(!intercept);
        });
    }

    #[test]
    fn record_tls_connect_failure_adds_learned_host_for_pinning_indicators() {
        let detector = Arc::new(detector());
        let lookup = StaticProcessLookup {
            identity: ProcessIdentity::new(
                Some("com.anthropic.claudefordesktop".to_string()),
                None,
            ),
        };
        let handler = HudsuckerDetectionHandler::new(detector, lookup);

        handler.record_tls_connect_failure(
            "noncatalog.certpinned.example",
            "certificate verify failed",
        );

        assert!(handler
            .learned_tls_passthrough_hosts()
            .iter()
            .any(|host| host == "noncatalog.certpinned.example"));
    }
}
