//! Wrap command - Wrap MCP servers for interception
//!
//! Usage:
//!   soth wrap -- npx -y @modelcontextprotocol/server-postgres
//!   soth wrap --name "postgres-prod" -- npx -y @modelcontextprotocol/server-postgres
//!   soth wrap --record -- npx -y @modelcontextprotocol/server-postgres

pub mod agent_detect;

use crate::cli_config;
use crate::commands::cloud_hooks;
use crate::commands::enforcement;
use anyhow::{Context, Result};
use clap::Args;
use soth_core::config::SothConfig;
use soth_core::types::{AgentInfo, DetectionSource, TrafficEnvelope, WrapDirection, WrapEvent};
use soth_core::{
    generate_session_name, EventLogger, ExchangeSourceClass, MessageDirection, SessionRecorder,
    SessionStorage,
};
use soth_oisp::types::provider::EntryType;
use soth_oisp::{DetectionContext, OispEngine};
use soth_proxy::pipeline::middleware::RequestContext as PipelineRequestContext;
use soth_proxy::transport::pii_enrichment::PiiEventEnricher;
use soth_proxy::{JsonRpcError, JsonRpcMessage, JsonRpcResponse, RequestId};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, warn};

/// Arguments for the wrap command
#[derive(Args, Debug)]
pub struct WrapArgs {
    /// Human-readable name for this server
    #[arg(long)]
    pub name: Option<String>,

    /// Override agent detection with a specific agent name
    #[arg(long)]
    pub agent: Option<String>,

    /// Config file path (optional, for policy/observe settings)
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Disable event logging
    #[arg(long)]
    pub no_log: bool,

    /// Record full session for replay (stores complete message payloads)
    #[arg(long)]
    pub record: bool,

    /// Session name for recording (auto-generated if not specified)
    #[arg(long)]
    pub session_name: Option<String>,

    /// Continue forwarding original traffic when enforcement runtime errors occur
    #[arg(long)]
    pub fail_open: bool,

    /// Command and arguments to wrap (after --)
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

/// Session state shared across tasks
struct WrapSession {
    session_id: String,
    server_name: String,
    agent: RwLock<AgentInfo>,
    detection_metadata: RwLock<WrapDetectionMetadata>,
    oisp_engine: Option<Arc<OispEngine>>,
    env_keys: Arc<Vec<String>>,
    event_logger: Option<EventLogger>,
    exchange_v2: soth_core::config::types::ExchangeV2Config,
    request_contexts: RwLock<std::collections::HashMap<String, WrapRequestContext>>,
    enforcement: Option<Arc<WrapEnforcement>>,
    fail_open: bool,
    pii_enricher: PiiEventEnricher,
    /// Session recorder for full message capture (optional)
    recorder: Option<Arc<SessionRecorder>>,
}

struct WrapRequestContext {
    started_at: Instant,
    method: Option<String>,
    tool_name: Option<String>,
    pipeline_ctx: Option<PipelineRequestContext>,
    envelope: Option<TrafficEnvelope>,
}

struct WrapEnforcement {
    runtime: enforcement::WrapEnforcementRuntime,
}

struct InboundProcessResult {
    forward_to_server: Option<String>,
    immediate_response_to_client: Option<String>,
}

struct OutboundProcessResult {
    forward_to_client: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct WrapDetectionMetadata {
    detection_reason: Option<String>,
    parse_confidence: Option<f64>,
    target_entity_id: Option<String>,
    detection_source: Option<String>,
    shadow_agent: Option<String>,
    shadow_detection_reason: Option<String>,
    shadow_parse_confidence: Option<f64>,
    shadow_mismatch: bool,
}

#[derive(Debug, Clone)]
struct WrapDetectionResolution {
    agent: AgentInfo,
    metadata: WrapDetectionMetadata,
}

fn detection_source_rank(source: DetectionSource) -> u8 {
    match source {
        DetectionSource::CommandLine => 4,
        DetectionSource::McpInitialize => 3,
        DetectionSource::Environment => 2,
        DetectionSource::ProcessTree => 1,
        DetectionSource::Unknown => 0,
    }
}

fn should_promote_agent(current: &AgentInfo, candidate: &AgentInfo) -> bool {
    // Never override explicit operator input.
    if matches!(current.detected_from, DetectionSource::CommandLine) {
        return false;
    }

    let current_rank = detection_source_rank(current.detected_from);
    let candidate_rank = detection_source_rank(candidate.detected_from);
    if candidate_rank > current_rank {
        return true;
    }

    // If we already trust initialize info, allow enrichments like version fill.
    candidate_rank == current_rank
        && matches!(candidate.detected_from, DetectionSource::McpInitialize)
        && current.version.is_none()
        && candidate.version.is_some()
}

fn detection_reason_from_source(source: DetectionSource) -> String {
    format!("{source:?}").to_ascii_lowercase()
}

fn detection_confidence_from_source(source: DetectionSource) -> f64 {
    match source {
        DetectionSource::CommandLine => 1.0,
        DetectionSource::McpInitialize => 0.92,
        DetectionSource::Environment => 0.85,
        DetectionSource::ProcessTree => 0.72,
        DetectionSource::Unknown => 0.0,
    }
}

fn legacy_detection_metadata(agent: &AgentInfo) -> WrapDetectionMetadata {
    WrapDetectionMetadata {
        detection_reason: Some(detection_reason_from_source(agent.detected_from)),
        parse_confidence: Some(detection_confidence_from_source(agent.detected_from)),
        target_entity_id: None,
        detection_source: Some("legacy_fallback".to_string()),
        shadow_agent: None,
        shadow_detection_reason: None,
        shadow_parse_confidence: None,
        shadow_mismatch: false,
    }
}

fn collect_environment_keys() -> Arc<Vec<String>> {
    let mut keys = std::env::vars()
        .map(|(key, _)| key)
        .filter(|key| !key.trim().is_empty())
        .collect::<Vec<String>>();
    keys.sort();
    keys.dedup();
    Arc::new(keys)
}

fn resolve_registry_bundle_cache_path(config: &SothConfig) -> PathBuf {
    if let Some(config_cache_path) = config.cloud.cache_path.as_ref() {
        if let Some(parent) = config_cache_path.parent() {
            return parent.join("registry_bundle_cache.json");
        }
    }
    dirs::home_dir()
        .map(|home| home.join(".soth").join("registry_bundle_cache.json"))
        .unwrap_or_else(|| PathBuf::from(".soth/registry_bundle_cache.json"))
}

fn load_wrap_oisp_engine(config: &SothConfig) -> Option<Arc<OispEngine>> {
    let cache_path = resolve_registry_bundle_cache_path(config);
    let engine = match OispEngine::load_from_registry_cache(cache_path.as_path()) {
        Ok(Some(engine)) => match engine.with_embedded_overlay() {
            Ok(overlaid) => {
                info!(
                    cache = %cache_path.display(),
                    bundle_version = %overlaid.bundle_version(),
                    providers = overlaid.provider_count(),
                    "Loaded OISP bundle for wrap detection (embedded overlay applied)"
                );
                overlaid
            }
            Err(error) => {
                warn!(
                    cache = %cache_path.display(),
                    error = %error,
                    "Failed applying embedded overlay for wrap detection; using cache bundle as-is"
                );
                engine
            }
        },
        Ok(None) => {
            warn!(
                cache = %cache_path.display(),
                "Wrap detection registry cache missing; using embedded minimal bundle"
            );
            match OispEngine::load_embedded_minimal_bundle() {
                Ok(engine) => engine,
                Err(error) => {
                    warn!(
                        error = %error,
                        "Embedded fallback bundle unavailable for wrap detection"
                    );
                    return None;
                }
            }
        }
        Err(error) => {
            warn!(
                cache = %cache_path.display(),
                error = %error,
                "Failed loading wrap detection registry cache; using embedded minimal bundle"
            );
            match OispEngine::load_embedded_minimal_bundle() {
                Ok(engine) => engine,
                Err(error) => {
                    warn!(
                        error = %error,
                        "Embedded fallback bundle unavailable for wrap detection"
                    );
                    return None;
                }
            }
        }
    };

    Some(Arc::new(engine))
}

fn build_bundle_detection_context(
    params: Option<&serde_json::Value>,
    env_keys: &[String],
) -> DetectionContext {
    let client_name = params
        .and_then(|value| value.get("clientInfo"))
        .and_then(|info| info.get("name"))
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);
    let client_version = params
        .and_then(|value| value.get("clientInfo"))
        .and_then(|info| info.get("version"))
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned);

    DetectionContext {
        client_name,
        client_version,
        env_keys: env_keys.to_vec(),
        ..DetectionContext::default()
    }
}

fn evaluate_bundle_detection(
    oisp_engine: &OispEngine,
    params: Option<&serde_json::Value>,
    env_keys: &[String],
    legacy_agent: &AgentInfo,
) -> Option<WrapDetectionResolution> {
    let context = build_bundle_detection_context(params, env_keys);
    let scoped = oisp_engine
        .evaluate_detection_across_entry_types(&context, &[EntryType::AgentApp, EntryType::Mcp])?;
    let detected_name = scoped
        .outcome
        .agent
        .clone()
        .unwrap_or(scoped.provider_id.clone());
    let normalized = agent_detect::canonicalize_agent_name(detected_name.as_str());
    let mut agent = AgentInfo::new(normalized, DetectionSource::McpInitialize);
    if let Some(version) = context.client_version {
        agent = agent.with_version(version);
    }

    let legacy_reason = detection_reason_from_source(legacy_agent.detected_from);
    let legacy_confidence = detection_confidence_from_source(legacy_agent.detected_from);
    let shadow_mismatch = !legacy_agent.name.eq_ignore_ascii_case(agent.name.as_str());

    Some(WrapDetectionResolution {
        agent,
        metadata: WrapDetectionMetadata {
            detection_reason: Some(scoped.outcome.detection_reason),
            parse_confidence: Some(scoped.outcome.parse_confidence),
            target_entity_id: scoped.outcome.target_entity_id,
            detection_source: Some("bundle".to_string()),
            shadow_agent: Some(legacy_agent.name.clone()),
            shadow_detection_reason: Some(legacy_reason),
            shadow_parse_confidence: Some(legacy_confidence),
            shadow_mismatch,
        },
    })
}

impl WrapSession {
    fn new(
        server_name: String,
        agent: AgentInfo,
        detection_metadata: WrapDetectionMetadata,
        oisp_engine: Option<Arc<OispEngine>>,
        env_keys: Arc<Vec<String>>,
        event_logger: Option<EventLogger>,
        exchange_v2: soth_core::config::types::ExchangeV2Config,
        enforcement: Option<Arc<WrapEnforcement>>,
        fail_open: bool,
        pii_enricher: PiiEventEnricher,
        record: bool,
        session_name: Option<String>,
    ) -> Result<Self> {
        let session_id = uuid::Uuid::new_v4().to_string();

        // Create session recorder if recording is enabled
        let recorder = if record {
            // Use provided name, or generate a beautiful adjective-noun name
            let name = session_name.unwrap_or_else(generate_session_name);
            info!("Recording session: {}", name);
            Some(Arc::new(SessionRecorder::new(
                session_id.clone(),
                name,
                server_name.clone(),
            )))
        } else {
            None
        };

        Ok(Self {
            session_id,
            server_name,
            agent: RwLock::new(agent),
            detection_metadata: RwLock::new(detection_metadata),
            oisp_engine,
            env_keys,
            event_logger,
            exchange_v2,
            enforcement,
            fail_open,
            pii_enricher,
            request_contexts: RwLock::new(std::collections::HashMap::new()),
            recorder,
        })
    }

    async fn log_event(&self, event: &WrapEvent) {
        if let Some(ref logger) = self.event_logger {
            let mut event = event.clone();
            self.pii_enricher.enrich(&mut event);
            logger.log(&event);
            if self.exchange_v2.enabled {
                if let Err(error) = logger.enqueue_exchange_from_wrap_event(
                    &event,
                    &self.exchange_v2,
                    Some(ExchangeSourceClass::Mcp),
                ) {
                    warn!(
                        event_id = %event.id,
                        error = %error,
                        "Failed to enqueue wrap exchange.v2 payload"
                    );
                }
            }
        }
    }

    /// Record a message for session replay
    async fn record_message(&self, content: &str, direction: MessageDirection) {
        if let Some(ref recorder) = self.recorder {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
                if let Err(e) = recorder.record_message(json, direction).await {
                    debug!("Failed to record message: {}", e);
                }
            }
        }
    }

    async fn update_agent(&self, agent: AgentInfo) {
        let mut current = self.agent.write().await;
        if should_promote_agent(&current, &agent) {
            *current = agent.clone();
        }
        let effective_agent = current.clone();
        drop(current);

        // Also update recorder's agent info
        if let Some(ref recorder) = self.recorder {
            recorder
                .set_agent_info(effective_agent.name, effective_agent.version)
                .await;
        }
    }

    async fn update_detection_metadata(&self, metadata: WrapDetectionMetadata) {
        let mut current = self.detection_metadata.write().await;
        *current = metadata;
    }

    async fn add_detection_tags(&self, event: &mut WrapEvent) {
        let metadata = self.detection_metadata.read().await.clone();
        let mut tags = event.tags.clone().unwrap_or_default();

        if let Some(source) = metadata.detection_source {
            tags.insert("detection.source".to_string(), source);
        }
        if let Some(reason) = metadata.detection_reason {
            tags.insert("detection.reason".to_string(), reason);
        }
        if let Some(confidence) = metadata.parse_confidence {
            tags.insert(
                "detection.parse_confidence".to_string(),
                format!("{confidence:.4}"),
            );
        }
        if let Some(entity_id) = metadata.target_entity_id {
            tags.insert("detection.target_entity_id".to_string(), entity_id);
        }
        if let Some(shadow_agent) = metadata.shadow_agent {
            tags.insert("detection.shadow_agent".to_string(), shadow_agent);
        }
        if let Some(shadow_reason) = metadata.shadow_detection_reason {
            tags.insert("detection.shadow_reason".to_string(), shadow_reason);
        }
        if let Some(shadow_confidence) = metadata.shadow_parse_confidence {
            tags.insert(
                "detection.shadow_parse_confidence".to_string(),
                format!("{shadow_confidence:.4}"),
            );
        }
        if metadata.shadow_mismatch {
            tags.insert("detection.shadow_mismatch".to_string(), "true".to_string());
        }

        if !tags.is_empty() {
            event.tags = Some(tags);
        }
    }

    async fn record_request_context(
        &self,
        id: &str,
        method: Option<&str>,
        tool_name: Option<&str>,
        pipeline_ctx: Option<PipelineRequestContext>,
        envelope: Option<TrafficEnvelope>,
    ) {
        let mut contexts = self.request_contexts.write().await;
        contexts.insert(
            id.to_string(),
            WrapRequestContext {
                started_at: Instant::now(),
                method: method.map(ToOwned::to_owned),
                tool_name: tool_name.map(ToOwned::to_owned),
                pipeline_ctx,
                envelope,
            },
        );
    }

    async fn take_request_context(&self, id: &str) -> Option<WrapRequestContext> {
        let mut contexts = self.request_contexts.write().await;
        contexts.remove(id)
    }

    /// Finalize the session recording and save to disk
    async fn finalize_recording(&self) -> Result<Option<PathBuf>> {
        if let Some(ref recorder) = self.recorder {
            // Clone the recorder to finalize (consumes it)
            let recorder_clone =
                Arc::try_unwrap(recorder.clone()).unwrap_or_else(|arc| (*arc).clone());

            let session = recorder_clone.finalize().await?;
            let storage = SessionStorage::new()?;
            let path = storage.save(&session)?;

            info!(
                "Session recorded: {} ({} messages)",
                session.name,
                session.messages.len()
            );

            return Ok(Some(path));
        }
        Ok(None)
    }
}

fn load_wrap_config(path: Option<&PathBuf>) -> Result<SothConfig> {
    cli_config::load_effective_config(path, None).context("Failed to load wrap config")
}

fn extract_request_id_for_error(msg: &serde_json::Value) -> Option<RequestId> {
    let id = msg.get("id")?;
    if id.is_null() {
        return Some(RequestId::Null);
    }
    if let Some(num) = id.as_i64() {
        return Some(RequestId::Number(num));
    }
    if let Some(s) = id.as_str() {
        return Some(RequestId::String(s.to_string()));
    }
    None
}

fn extract_context_id(id: &serde_json::Value) -> Option<String> {
    if let Some(num) = id.as_i64() {
        return Some(num.to_string());
    }
    if let Some(s) = id.as_str() {
        return Some(s.to_string());
    }
    None
}

fn extract_metadata_value(root: &serde_json::Value, key: &str) -> Option<serde_json::Value> {
    let key_lower = key.to_ascii_lowercase();
    let key_underscore = key_lower.replace('-', "_");
    let key_dash = key_underscore.replace('_', "-");

    let keys = [
        key,
        key_lower.as_str(),
        key_underscore.as_str(),
        key_dash.as_str(),
    ];
    let candidates = [
        root.get("meta"),
        root.get("_meta"),
        root.get("metadata"),
        root.get("params").and_then(|p| p.get("meta")),
        root.get("params").and_then(|p| p.get("_meta")),
        root.get("params").and_then(|p| p.get("metadata")),
        root.get("params").and_then(|p| p.get("headers")),
        Some(root),
    ];

    for candidate in candidates.into_iter().flatten() {
        for k in keys {
            if let Some(v) = candidate.get(k) {
                return Some(v.clone());
            }
        }
    }
    None
}

fn enrich_identity_metadata(
    parsed: &serde_json::Value,
    did_key: &str,
    signature_key: &str,
    ctx: &mut PipelineRequestContext,
) {
    if let Some(did) = extract_metadata_value(parsed, did_key) {
        ctx.metadata.insert(did_key.to_string(), did);
    }
    if let Some(sig) = extract_metadata_value(parsed, signature_key) {
        ctx.metadata.insert(signature_key.to_string(), sig);
    }
}

fn apply_enforcement_metadata(event: &mut WrapEvent, ctx: &PipelineRequestContext) {
    if let Some(action) = ctx.metadata.get("policy_action").and_then(|v| v.as_str()) {
        let reason = ctx
            .metadata
            .get("policy_reason")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let allowed = !action.eq_ignore_ascii_case("deny");
        event.policy_allowed = Some(allowed);
        event.policy_reason = reason;
    }
    if let Some(policy_version) = ctx.metadata.get("policy_version").and_then(|v| v.as_str()) {
        event.policy_version = Some(policy_version.to_string());
    }

    let input_tokens = ctx
        .metadata
        .get("budget_input_tokens")
        .and_then(|v| v.as_u64());
    let output_tokens = ctx
        .metadata
        .get("budget_output_tokens")
        .and_then(|v| v.as_u64());
    if let (Some(input_tokens), Some(output_tokens)) = (input_tokens, output_tokens) {
        event.input_tokens = Some(input_tokens);
        event.output_tokens = Some(output_tokens);
        event.token_count = Some(input_tokens + output_tokens);
    } else if let Some(input_tokens) = input_tokens {
        event.token_count = Some(input_tokens);
    }

    if let Some(cost) = ctx.metadata.get("budget_cost").and_then(|v| v.as_f64()) {
        event.cost_usd = Some(cost);
    }
}

/// Run the wrap command
pub async fn run(args: WrapArgs) -> Result<()> {
    let WrapArgs {
        name,
        agent,
        config,
        no_log,
        record,
        session_name,
        command,
        fail_open,
    } = args;

    if command.is_empty() {
        anyhow::bail!("No command specified. Usage: soth wrap -- <command> [args...]");
    }

    let (cmd, cmd_args) = (&command[0], &command[1..]);

    // Derive server name
    let server_name = name.unwrap_or_else(|| derive_server_name(cmd, cmd_args));

    // Get initial agent info from legacy detector (used as shadow baseline).
    let legacy_initial_agent = if let Some(ref agent_name) = agent {
        AgentInfo::new(agent_name.clone(), DetectionSource::CommandLine)
    } else {
        agent_detect::detect_agent()
    };

    let config = load_wrap_config(config.as_ref())?;
    let oisp_engine = load_wrap_oisp_engine(&config);
    let env_keys = collect_environment_keys();
    let initial_resolution = if matches!(
        legacy_initial_agent.detected_from,
        DetectionSource::CommandLine
    ) {
        WrapDetectionResolution {
            agent: legacy_initial_agent.clone(),
            metadata: legacy_detection_metadata(&legacy_initial_agent),
        }
    } else if let Some(engine) = oisp_engine.as_ref() {
        evaluate_bundle_detection(engine, None, env_keys.as_ref(), &legacy_initial_agent)
            .unwrap_or_else(|| WrapDetectionResolution {
                agent: legacy_initial_agent.clone(),
                metadata: legacy_detection_metadata(&legacy_initial_agent),
            })
    } else {
        WrapDetectionResolution {
            agent: legacy_initial_agent.clone(),
            metadata: legacy_detection_metadata(&legacy_initial_agent),
        }
    };

    let pii_enricher = PiiEventEnricher::from_observe_config(&config.observe);
    let enforcement = enforcement::build_wrap_enforcement_runtime(&config)?
        .map(|runtime| Arc::new(WrapEnforcement { runtime }));
    if enforcement.is_some() {
        info!(
            "Wrap enforcement enabled (crypto_identity_enabled={}, crypto_identity_mode={}, policy_enabled={}, budget_enabled={})",
            config.crypto_identity.enabled,
            config.crypto_identity.mode,
            config.policy.enabled,
            config.budget.enabled
        );
    } else {
        info!("Wrap enforcement disabled (identity/policy/budget all off)");
    }

    // Set up log path
    let event_logger = if no_log {
        None
    } else {
        Some(
            EventLogger::with_default_path_from_runtime_config(
                config.observe.storage.inline_threshold_bytes,
                &config.crypto_identity,
            )
            .context("Failed to initialize event logger")?,
        )
    };
    let event_db_path = event_logger.as_ref().map(|logger| logger.path().clone());
    let mut cloud_runtime = cloud_hooks::spawn_cloud_pull_runtime(&config, event_db_path);

    let session = Arc::new(WrapSession::new(
        server_name.clone(),
        initial_resolution.agent,
        initial_resolution.metadata,
        oisp_engine,
        env_keys,
        event_logger,
        config.exchange_v2.clone(),
        enforcement,
        fail_open,
        pii_enricher,
        record,
        session_name,
    )?);

    info!(
        "Wrapping server '{}' (session: {}{})",
        server_name,
        session.session_id,
        if record { ", recording" } else { "" }
    );

    // Spawn the upstream MCP server
    let mut child = spawn_server(cmd, cmd_args)?;

    let child_stdin = child.stdin.take().context("Failed to get child stdin")?;
    let child_stdout = child.stdout.take().context("Failed to get child stdout")?;

    // Set up channels for bidirectional communication
    let (to_server_tx, to_server_rx) = mpsc::channel::<String>(100);
    let (from_server_tx, from_server_rx) = mpsc::channel::<String>(100);

    // Task: Read from our stdin, process, send to server
    let session_clone = session.clone();
    let from_server_tx_clone = from_server_tx.clone();
    let stdin_task = tokio::spawn(async move {
        read_from_stdin(session_clone, to_server_tx, from_server_tx_clone).await;
    });

    // Task: Write to server stdin
    let write_to_server_task = tokio::spawn(async move {
        write_to_child(child_stdin, to_server_rx).await;
    });

    // Task: Read from server stdout, process, send to our stdout
    let session_clone = session.clone();
    let read_from_server_task = tokio::spawn(async move {
        read_from_child(session_clone, child_stdout, from_server_tx).await;
    });

    // Task: Write to our stdout
    let write_to_stdout_task = tokio::spawn(async move {
        write_to_stdout(from_server_rx).await;
    });

    let mut stdin_task = stdin_task;
    let mut write_to_server_task = write_to_server_task;
    let mut read_from_server_task = read_from_server_task;
    let mut write_to_stdout_task = write_to_stdout_task;
    let mut child_exited = false;
    let mut stdin_joined = false;
    let mut read_joined = false;

    // Primary shutdown trigger. We intentionally do not stop immediately on
    // stdin EOF; instead we let the upstream process flush responses.
    tokio::select! {
        status = child.wait() => {
            child_exited = true;
            info!("Server process exited: {:?}", status);
        }
        result = &mut stdin_task => {
            stdin_joined = true;
            if let Err(e) = result {
                error!("Stdin task failed: {}", e);
            } else {
                debug!("Stdin task finished");
            }
        }
        result = &mut read_from_server_task => {
            read_joined = true;
            if let Err(e) = result {
                error!("Read-from-server task failed: {}", e);
            } else {
                debug!("Read-from-server task finished");
            }
        }
    }

    // If upstream is gone (or closed stdout), stop reading stdin so the channel
    // to child writer closes and shutdown can complete.
    if (child_exited || read_joined) && !stdin_joined {
        stdin_task.abort();
        let _ = stdin_task.await;
    }

    if !write_to_server_task.is_finished() {
        if timeout(Duration::from_secs(2), &mut write_to_server_task)
            .await
            .is_err()
        {
            write_to_server_task.abort();
            let _ = write_to_server_task.await;
        }
    }

    if !child_exited {
        if timeout(Duration::from_secs(3), child.wait()).await.is_err() {
            debug!("Server did not exit after stdin closed, terminating");
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
    }

    if !read_joined {
        if timeout(Duration::from_secs(2), &mut read_from_server_task)
            .await
            .is_err()
        {
            read_from_server_task.abort();
            let _ = read_from_server_task.await;
        }
    }

    if !write_to_stdout_task.is_finished() {
        if timeout(Duration::from_secs(2), &mut write_to_stdout_task)
            .await
            .is_err()
        {
            write_to_stdout_task.abort();
            let _ = write_to_stdout_task.await;
        }
    }

    // Finalize session recording if enabled
    if let Some(path) = session.finalize_recording().await? {
        eprintln!("Session saved to: {}", path.display());
    }

    if let Some(runtime) = cloud_runtime.take() {
        let _ = runtime.shutdown_tx.send(());
        let _ = runtime.task.await;
    }

    Ok(())
}

fn spawn_server(cmd: &str, args: &[String]) -> Result<Child> {
    Command::new(cmd)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit()) // Pass through stderr
        .spawn()
        .with_context(|| format!("Failed to spawn server: {} {:?}", cmd, args))
}

async fn read_from_stdin(
    session: Arc<WrapSession>,
    to_server_tx: mpsc::Sender<String>,
    to_client_tx: mpsc::Sender<String>,
) {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                debug!("EOF on stdin");
                break;
            }
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                let result = process_inbound_message(&session, trimmed).await;

                if let Some(immediate) = result.immediate_response_to_client {
                    if to_client_tx.send(format!("{}\n", immediate)).await.is_err() {
                        break;
                    }
                }

                if let Some(forward) = result.forward_to_server {
                    if to_server_tx.send(format!("{}\n", forward)).await.is_err() {
                        break;
                    }
                }
            }
            Err(e) => {
                error!("Stdin read error: {}", e);
                break;
            }
        }
    }
}

async fn write_to_child(mut writer: tokio::process::ChildStdin, mut rx: mpsc::Receiver<String>) {
    while let Some(line) = rx.recv().await {
        if writer.write_all(line.as_bytes()).await.is_err() {
            break;
        }
        if writer.flush().await.is_err() {
            break;
        }
    }
}

async fn read_from_child(
    session: Arc<WrapSession>,
    stdout: tokio::process::ChildStdout,
    tx: mpsc::Sender<String>,
) {
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                debug!("EOF from server");
                break;
            }
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                let result = process_outbound_message(&session, trimmed).await;

                if let Some(forward) = result.forward_to_client {
                    if tx.send(format!("{}\n", forward)).await.is_err() {
                        break;
                    }
                }
            }
            Err(e) => {
                error!("Server stdout read error: {}", e);
                break;
            }
        }
    }
}

async fn write_to_stdout(mut rx: mpsc::Receiver<String>) {
    let mut stdout = tokio::io::stdout();

    while let Some(line) = rx.recv().await {
        if stdout.write_all(line.as_bytes()).await.is_err() {
            break;
        }
        if stdout.flush().await.is_err() {
            break;
        }
    }
}

async fn process_inbound_message(session: &WrapSession, content: &str) -> InboundProcessResult {
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(content);
    let mut forward_content = Some(content.to_string());
    let mut immediate_response_to_client = None;

    let agent = session.agent.read().await.clone();
    let mut event = WrapEvent::new(
        &session.session_id,
        &session.server_name,
        WrapDirection::In,
        agent,
    );

    if let Ok(msg) = &parsed {
        let mut request_method: Option<&str> = None;
        let mut request_tool_name: Option<&str> = None;
        let mut pipeline_ctx = None;
        let request_id = msg.get("id").and_then(extract_context_id);

        // Extract method
        if let Some(method) = msg.get("method").and_then(|m| m.as_str()) {
            request_method = Some(method);
            event = event.with_method(method);

            // Handle initialize message - extract agent info
            if method == "initialize" {
                if let Some(params) = msg.get("params") {
                    let legacy_initialize_agent = agent_detect::detect_from_initialize(params);
                    let legacy_shadow = match legacy_initialize_agent.as_ref() {
                        Some(agent) => agent.clone(),
                        None => session.agent.read().await.clone(),
                    };

                    if let Some(engine) = session.oisp_engine.as_ref() {
                        if let Some(resolution) = evaluate_bundle_detection(
                            engine,
                            Some(params),
                            session.env_keys.as_ref(),
                            &legacy_shadow,
                        ) {
                            session.update_agent(resolution.agent).await;
                            session.update_detection_metadata(resolution.metadata).await;
                        } else if let Some(agent) = legacy_initialize_agent {
                            session.update_agent(agent.clone()).await;
                            session
                                .update_detection_metadata(legacy_detection_metadata(&agent))
                                .await;
                        }
                    } else if let Some(agent) = legacy_initialize_agent {
                        session.update_agent(agent.clone()).await;
                        session
                            .update_detection_metadata(legacy_detection_metadata(&agent))
                            .await;
                    }
                    // Update event with latest agent info.
                    event.agent = session.agent.read().await.clone();
                }
            }

            // Handle tools/call - extract tool name
            if method == "tools/call" {
                if let Some(params) = msg.get("params") {
                    if let Some(name) = params.get("name").and_then(|n| n.as_str()) {
                        request_tool_name = Some(name);
                        event = event.with_tool_name(name);
                    }
                }
            }
        }

        let did_key = session
            .enforcement
            .as_ref()
            .map(|e| e.runtime.did_metadata_key.as_str())
            .unwrap_or("X-Agent-DID");
        let signature_key = session
            .enforcement
            .as_ref()
            .map(|e| e.runtime.signature_metadata_key.as_str())
            .unwrap_or("X-Agent-Signature");
        let did = extract_metadata_value(msg, did_key)
            .and_then(|value| value.as_str().map(ToString::to_string));
        let signature = extract_metadata_value(msg, signature_key).map(|value| {
            value
                .as_str()
                .map(ToString::to_string)
                .unwrap_or_else(|| value.to_string())
        });
        let method_for_envelope = request_method.unwrap_or("unknown");
        let envelope = TrafficEnvelope::mcp_stdio(
            &session.session_id,
            request_id.clone(),
            method_for_envelope.to_string(),
            Some(event.agent.name.as_str()),
            did.as_deref(),
            signature.as_deref(),
            Some(content),
        );
        event = event.with_traffic_envelope(envelope.clone());
        let traffic_envelope = Some(envelope);

        if let Some(ref enforcement) = session.enforcement {
            if let Ok(jsonrpc_msg) = JsonRpcMessage::from_json_str(content) {
                if matches!(jsonrpc_msg, JsonRpcMessage::Request(_)) {
                    let mut req_ctx = PipelineRequestContext::new(session.session_id.clone());
                    req_ctx.agent_id = Some(event.agent.name.clone());
                    if let Some(ref envelope) = traffic_envelope {
                        if let Ok(value) = serde_json::to_value(envelope) {
                            req_ctx
                                .metadata
                                .insert("traffic_envelope".to_string(), value);
                        }
                        req_ctx.metadata.insert(
                            "traffic_envelope_id".to_string(),
                            serde_json::json!(envelope.envelope_id.clone()),
                        );
                    }
                    enrich_identity_metadata(
                        msg,
                        &enforcement.runtime.did_metadata_key,
                        &enforcement.runtime.signature_metadata_key,
                        &mut req_ctx,
                    );

                    match enforcement
                        .runtime
                        .pipeline
                        .process(&mut req_ctx, jsonrpc_msg)
                        .await
                    {
                        Ok(Some(JsonRpcMessage::Request(req))) => {
                            if let Ok(serialized) = serde_json::to_string(&req) {
                                forward_content = Some(serialized);
                            }
                            apply_enforcement_metadata(&mut event, &req_ctx);
                            pipeline_ctx = Some(req_ctx);
                        }
                        Ok(Some(JsonRpcMessage::Response(resp))) => {
                            forward_content = None;
                            if let Ok(serialized) = serde_json::to_string(&resp) {
                                immediate_response_to_client = Some(serialized.clone());
                            }
                            apply_enforcement_metadata(&mut event, &req_ctx);
                            event = event.with_policy(
                                false,
                                Some("Request denied by enforcement".to_string()),
                            );
                            pipeline_ctx = Some(req_ctx);
                        }
                        Ok(None) => {
                            forward_content = None;
                            apply_enforcement_metadata(&mut event, &req_ctx);
                            pipeline_ctx = Some(req_ctx);
                        }
                        Err(e) => {
                            error!("Wrap enforcement error (request): {}", e);
                            if !session.fail_open {
                                forward_content = None;
                                if let Some(id) = extract_request_id_for_error(msg) {
                                    let response = JsonRpcResponse::error(
                                        id,
                                        JsonRpcError::new(
                                            -32603,
                                            format!("Enforcement runtime error: {}", e),
                                        ),
                                    );
                                    if let Ok(serialized) = serde_json::to_string(&response) {
                                        immediate_response_to_client = Some(serialized);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Record request time for latency calculation
        if forward_content.is_some() {
            if let Some(id_str) = request_id.as_deref() {
                session
                    .record_request_context(
                        id_str,
                        request_method,
                        request_tool_name,
                        pipeline_ctx,
                        traffic_envelope.clone(),
                    )
                    .await;
            }
        }

        // Add full content and preview
        event = event
            .with_content(content)
            .with_content_preview(truncate_content(content, 200));
    }

    // Record full message for session replay
    session
        .record_message(content, MessageDirection::ToServer)
        .await;

    session.add_detection_tags(&mut event).await;
    session.log_event(&event).await;
    debug!(
        "→ {} {}",
        event.method.as_deref().unwrap_or("-"),
        event.tool_name.as_deref().unwrap_or("")
    );

    InboundProcessResult {
        forward_to_server: forward_content,
        immediate_response_to_client,
    }
}

async fn process_outbound_message(session: &WrapSession, content: &str) -> OutboundProcessResult {
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(content);
    let mut forward_content = Some(content.to_string());

    let agent = session.agent.read().await.clone();
    let mut event = WrapEvent::new(
        &session.session_id,
        &session.server_name,
        WrapDirection::Out,
        agent,
    );

    if let Ok(msg) = &parsed {
        // Check if it's a response (has result or error)
        let is_response = msg.get("result").is_some() || msg.get("error").is_some();

        if is_response {
            // Calculate latency
            if let Some(id) = msg.get("id") {
                if let Some(id_str) = extract_context_id(id) {
                    if let Some(mut ctx) = session.take_request_context(&id_str).await {
                        event = event.with_latency(ctx.started_at.elapsed().as_millis() as u64);
                        if let Some(method) = ctx.method.as_deref() {
                            event = event.with_method(method);
                        }
                        if let Some(tool_name) = ctx.tool_name.as_deref() {
                            event = event.with_tool_name(tool_name);
                        }
                        if let Some(envelope) = ctx.envelope.clone() {
                            event = event.with_traffic_envelope(envelope);
                        }
                        if let (Some(enforcement), Some(pipeline_ctx)) =
                            (session.enforcement.as_ref(), ctx.pipeline_ctx.as_mut())
                        {
                            if let Ok(jsonrpc_msg) = JsonRpcMessage::from_json_str(content) {
                                match enforcement
                                    .runtime
                                    .pipeline
                                    .process(pipeline_ctx, jsonrpc_msg)
                                    .await
                                {
                                    Ok(Some(JsonRpcMessage::Response(resp))) => {
                                        if let Ok(serialized) = serde_json::to_string(&resp) {
                                            forward_content = Some(serialized);
                                        }
                                        apply_enforcement_metadata(&mut event, pipeline_ctx);
                                    }
                                    Ok(Some(JsonRpcMessage::Request(_))) => {}
                                    Ok(None) => {
                                        forward_content = None;
                                        apply_enforcement_metadata(&mut event, pipeline_ctx);
                                    }
                                    Err(e) => {
                                        error!("Wrap enforcement error (response): {}", e);
                                        if !session.fail_open {
                                            forward_content = None;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // If we could not correlate, still classify explicit errors.
            if msg.get("error").is_some() && event.method.is_none() {
                event = event.with_method("error");
            }
        } else {
            // It's a notification from server
            if let Some(method) = msg.get("method").and_then(|m| m.as_str()) {
                event = event.with_method(method);
            }
        }

        if event.traffic_envelope.is_none() {
            let request_id = msg.get("id").and_then(extract_context_id);
            let method = event
                .method
                .clone()
                .unwrap_or_else(|| "response".to_string());
            let envelope = TrafficEnvelope::mcp_stdio(
                &session.session_id,
                request_id,
                method,
                Some(event.agent.name.as_str()),
                None,
                None,
                Some(content),
            );
            event = event.with_traffic_envelope(envelope);
        }

        // Add full content and preview
        event = event
            .with_content(content)
            .with_content_preview(truncate_content(content, 200));
    }

    // Record full message for session replay
    session
        .record_message(content, MessageDirection::ToClient)
        .await;

    session.add_detection_tags(&mut event).await;
    session.log_event(&event).await;
    debug!(
        "← {} ({}ms)",
        event.method.as_deref().unwrap_or("response"),
        event.latency_ms.unwrap_or(0)
    );

    OutboundProcessResult {
        forward_to_client: forward_content,
    }
}

fn derive_server_name(cmd: &str, args: &[String]) -> String {
    // Try to find a meaningful name from the command
    let cmd_lower = cmd.to_lowercase();

    // If using npx, look at the package name
    if cmd_lower.contains("npx") {
        for arg in args {
            if arg.starts_with("@") || (!arg.starts_with("-") && arg.contains("/")) {
                // Extract the package name
                let name = arg
                    .trim_start_matches("@")
                    .split('/')
                    .last()
                    .unwrap_or(arg)
                    .trim_start_matches("server-")
                    .trim_end_matches("-server");
                return name.to_string();
            }
        }
    }

    // If using uvx or pipx, similar logic
    if cmd_lower.contains("uvx") || cmd_lower.contains("pipx") {
        for arg in args {
            if !arg.starts_with("-") {
                return arg
                    .trim_start_matches("mcp-")
                    .trim_end_matches("-mcp")
                    .to_string();
            }
        }
    }

    // Default: use the command name
    std::path::Path::new(cmd)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string()
}

fn truncate_content(content: &str, max_len: usize) -> String {
    if content.len() <= max_len {
        content.to_string()
    } else {
        format!("{}...", &content[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use soth_proxy::pipeline::middleware::RequestContext as PipelineCtx;

    #[test]
    fn test_derive_server_name_npx() {
        let name = derive_server_name(
            "npx",
            &[
                "-y".to_string(),
                "@modelcontextprotocol/server-postgres".to_string(),
            ],
        );
        assert_eq!(name, "postgres");
    }

    #[test]
    fn test_derive_server_name_npx_filesystem() {
        let name = derive_server_name(
            "npx",
            &[
                "-y".to_string(),
                "@modelcontextprotocol/server-filesystem".to_string(),
                "/tmp".to_string(),
            ],
        );
        assert_eq!(name, "filesystem");
    }

    #[test]
    fn test_derive_server_name_uvx() {
        let name = derive_server_name("uvx", &["mcp-server-git".to_string()]);
        assert_eq!(name, "server-git");
    }

    #[test]
    fn test_derive_server_name_direct() {
        let name = derive_server_name("/usr/local/bin/my-mcp-server", &[]);
        assert_eq!(name, "my-mcp-server");
    }

    #[test]
    fn test_truncate_content() {
        assert_eq!(truncate_content("short", 10), "short");
        assert_eq!(
            truncate_content("this is a longer string", 10),
            "this is a ..."
        );
    }

    #[test]
    fn test_extract_metadata_value_from_nested_meta() {
        let payload = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "_meta": {
                    "X-Agent-DID": "did:key:z6MkTest",
                    "X-Agent-Signature": { "algorithm": "Ed25519", "value": "abc", "signer": "did:key:z6MkTest", "created": "2026-02-07T00:00:00Z" }
                }
            },
            "id": 1
        });

        assert_eq!(
            extract_metadata_value(&payload, "X-Agent-DID")
                .and_then(|v| v.as_str().map(ToOwned::to_owned)),
            Some("did:key:z6MkTest".to_string())
        );
        assert!(extract_metadata_value(&payload, "X-Agent-Signature").is_some());
    }

    #[test]
    fn test_apply_enforcement_metadata_updates_event() {
        let mut event = WrapEvent::new(
            "session-1",
            "server",
            WrapDirection::Out,
            AgentInfo::new("test-agent", DetectionSource::CommandLine),
        );
        let mut ctx = PipelineCtx::new("session-1");
        ctx.metadata
            .insert("policy_action".to_string(), json!("Deny"));
        ctx.metadata
            .insert("policy_reason".to_string(), json!("blocked"));
        ctx.metadata
            .insert("policy_version".to_string(), json!("v12"));
        ctx.metadata
            .insert("budget_input_tokens".to_string(), json!(10));
        ctx.metadata
            .insert("budget_output_tokens".to_string(), json!(5));
        ctx.metadata.insert("budget_cost".to_string(), json!(0.42));

        apply_enforcement_metadata(&mut event, &ctx);

        assert_eq!(event.policy_allowed, Some(false));
        assert_eq!(event.policy_reason, Some("blocked".to_string()));
        assert_eq!(event.policy_version, Some("v12".to_string()));
        assert_eq!(event.input_tokens, Some(10));
        assert_eq!(event.output_tokens, Some(5));
        assert_eq!(event.token_count, Some(15));
        assert_eq!(event.cost_usd, Some(0.42));
    }

    #[test]
    fn test_should_promote_agent_process_tree_to_initialize() {
        let current = AgentInfo::new("Claude", DetectionSource::ProcessTree);
        let candidate =
            AgentInfo::new("Claude Code", DetectionSource::McpInitialize).with_version("1.2.3");
        assert!(should_promote_agent(&current, &candidate));
    }

    #[test]
    fn test_should_not_promote_over_command_line_override() {
        let current = AgentInfo::new("Manual Agent", DetectionSource::CommandLine);
        let candidate = AgentInfo::new("Claude Code", DetectionSource::McpInitialize);
        assert!(!should_promote_agent(&current, &candidate));
    }

    #[test]
    fn test_should_promote_initialize_when_version_is_missing() {
        let current = AgentInfo::new("Claude Code", DetectionSource::McpInitialize);
        let candidate =
            AgentInfo::new("Claude Code", DetectionSource::McpInitialize).with_version("1.2.3");
        assert!(should_promote_agent(&current, &candidate));
    }
}
