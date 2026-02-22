use anyhow::{anyhow, Result};
use serde::Serialize;
use soth_core::config::SothConfig;
use tokio::task::JoinHandle;
use tracing::warn;

use crate::cli_config;
use soth_core::config::{BudgetLimit, RegistryMode};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::info;

pub struct CloudPullRuntime {
    pub shutdown_tx: tokio::sync::oneshot::Sender<()>,
    pub task: JoinHandle<()>,
    _singleton_lock: CloudRuntimeSingletonLock,
}

const STARTUP_REGISTRY_REFRESH_TIMEOUT: Duration = Duration::from_secs(8);

const FINAL_CLOUD_SYNC_TIMEOUT: Duration = Duration::from_secs(4);
const FINAL_CLOUD_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(2);
const FINAL_CLOUD_SYNC_MAX_ROUNDS: usize = 3;
const CLOUD_BACKOFF_MAX_CAP: Duration = Duration::from_secs(15 * 60);
const CLOUD_RUNTIME_LOCK_FILE: &str = "cloud.pull.runtime.lock";
const REGISTRY_BUNDLE_DEGRADED_MAX_AGE_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryRuntimeSource {
    HealthyCloud,
    DegradedCached,
    DegradedEmbedded,
}

impl RegistryRuntimeSource {
    fn as_label(self) -> &'static str {
        match self {
            Self::HealthyCloud => "healthy_cloud",
            Self::DegradedCached => "degraded_cached",
            Self::DegradedEmbedded => "degraded_embedded",
        }
    }

    fn as_metric(self) -> soth_helper::metrics::RegistryBundleSourceState {
        match self {
            Self::HealthyCloud => soth_helper::metrics::RegistryBundleSourceState::HealthyCloud,
            Self::DegradedCached => soth_helper::metrics::RegistryBundleSourceState::DegradedCached,
            Self::DegradedEmbedded => {
                soth_helper::metrics::RegistryBundleSourceState::DegradedEmbedded
            }
        }
    }
}

fn resolve_registry_runtime_source(registry_cache_path: &Path) -> RegistryRuntimeSource {
    match soth_sync::cache::load_registry_bundle_cache(registry_cache_path) {
        Ok(Some(_)) => RegistryRuntimeSource::DegradedCached,
        _ => RegistryRuntimeSource::DegradedEmbedded,
    }
}

fn resolve_registry_runtime_source_after_success(
    registry_cache_path: &Path,
) -> RegistryRuntimeSource {
    let status = soth_sync::cache::registry_bundle_runtime_status(
        registry_cache_path,
        Duration::from_secs(REGISTRY_BUNDLE_DEGRADED_MAX_AGE_SECS),
    );
    if !status.cache_present {
        return RegistryRuntimeSource::DegradedEmbedded;
    }
    if status.stale {
        RegistryRuntimeSource::DegradedCached
    } else {
        RegistryRuntimeSource::HealthyCloud
    }
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Serialize)]
struct RegistryRuntimeStateSnapshot {
    schema_version: u32,
    source: String,
    consecutive_failures: u64,
    updated_at_unix_secs: u64,
    last_success_unix_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_age_seconds: Option<u64>,
    degraded_stale: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    validation_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    validation_failed_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_error: Option<String>,
}

fn registry_runtime_state_path() -> PathBuf {
    dirs::home_dir()
        .map(|home| {
            home.join(".soth")
                .join("runtime")
                .join("registry_runtime_state.json")
        })
        .unwrap_or_else(|| PathBuf::from(".soth/runtime/registry_runtime_state.json"))
}

fn persist_registry_runtime_state(
    registry_cache_path: &Path,
    source: RegistryRuntimeSource,
    consecutive_failures: u64,
    last_success_unix_secs: u64,
    detail: Option<&str>,
) {
    let runtime_status = soth_sync::cache::registry_bundle_runtime_status(
        registry_cache_path,
        Duration::from_secs(REGISTRY_BUNDLE_DEGRADED_MAX_AGE_SECS),
    );
    let snapshot = RegistryRuntimeStateSnapshot {
        schema_version: 2,
        source: source.as_label().to_string(),
        consecutive_failures,
        updated_at_unix_secs: current_unix_secs(),
        last_success_unix_secs,
        detail: detail.map(|value| value.to_string()),
        bundle_hash: runtime_status.bundle_hash,
        bundle_version: runtime_status.bundle_version,
        bundle_age_seconds: runtime_status.bundle_age_seconds,
        degraded_stale: runtime_status.stale,
        validation_status: runtime_status.validation_status,
        validation_failed_reason: runtime_status.validation_failed_reason,
        cache_error: runtime_status.cache_error,
    };
    let path = registry_runtime_state_path();
    if let Some(parent) = path.parent() {
        if let Err(error) = std::fs::create_dir_all(parent) {
            warn!(
                path = %path.display(),
                error = %error,
                "Failed creating registry runtime state directory"
            );
            return;
        }
    }
    match serde_json::to_vec_pretty(&snapshot) {
        Ok(body) => {
            if let Err(error) = std::fs::write(&path, body) {
                warn!(
                    path = %path.display(),
                    error = %error,
                    "Failed writing registry runtime state snapshot"
                );
            }
        }
        Err(error) => {
            warn!(
                path = %path.display(),
                error = %error,
                "Failed serializing registry runtime state snapshot"
            );
        }
    }
}

pub fn apply_cached_controls(config: &mut SothConfig) -> Result<()> {
    use soth_sync::cache;

    if !config.cloud.enabled {
        return Ok(());
    }
    if config.cloud.api_key.is_none() {
        warn!("cloud.enabled=true but cloud.api_key is missing; cloud hooks disabled");
        config.cloud.enabled = false;
        return Ok(());
    }

    let cache_path = resolve_cache_path(config);
    let Some(cached) = cache::load_config_cache(&cache_path)? else {
        return Ok(());
    };

    apply_budget_from_cache(config, &cached.budget.limits);
    apply_policy_from_cache(config, &cached.config_version, &cached.policies)?;
    apply_registry_mode_from_cache(config, cached.registry_mode.as_deref());

    info!(
        config_version = %cached.config_version,
        policies = cached.policies.len(),
        budget_limits = cached.budget.limits.len(),
        "Applied cached cloud controls"
    );
    Ok(())
}

pub async fn refresh_registry_bundle_on_start(config: &SothConfig) {
    use soth_sync::registry_puller::RegistryPuller;

    if !config.cloud.enabled {
        return;
    }

    let Some(api_key) = config.cloud.api_key.clone() else {
        warn!("cloud.enabled=true but cloud.api_key is missing; skipping startup registry refresh");
        return;
    };

    let cache_path = resolve_cache_path(config);
    let registry_cache_path = resolve_registry_cache_path(config, &cache_path);
    let mut runtime_source = resolve_registry_runtime_source(&registry_cache_path);
    let mut consecutive_failures = 0_u64;
    let mut last_success_unix_secs = 0_u64;

    soth_helper::metrics::set_registry_source_state(runtime_source.as_metric());
    soth_helper::metrics::set_registry_refresh_consecutive_failures(consecutive_failures);
    persist_registry_runtime_state(
        &registry_cache_path,
        runtime_source,
        consecutive_failures,
        last_success_unix_secs,
        Some("startup_init"),
    );

    let puller = RegistryPuller::new(config.cloud.endpoint.clone(), api_key, registry_cache_path)
        .with_bundle_type(config.forward_proxy.engine.registry_bundle_type())
        .with_fallback_endpoints(config.cloud.registry_bundle_fallback_endpoints.clone());

    match tokio::time::timeout(STARTUP_REGISTRY_REFRESH_TIMEOUT, puller.refresh_now()).await {
        Ok(Ok(outcome)) => {
            runtime_source = resolve_registry_runtime_source_after_success(puller.cache_path());
            consecutive_failures = 0;
            last_success_unix_secs = current_unix_secs();
            soth_helper::metrics::set_registry_source_state(runtime_source.as_metric());
            soth_helper::metrics::set_registry_refresh_consecutive_failures(consecutive_failures);
            soth_helper::metrics::set_registry_refresh_last_success_unix_secs(
                last_success_unix_secs,
            );
            persist_registry_runtime_state(
                puller.cache_path(),
                runtime_source,
                consecutive_failures,
                last_success_unix_secs,
                Some("startup_refresh_success"),
            );
            info!(
                source = runtime_source.as_label(),
                checked = outcome.checked,
                downloaded = outcome.downloaded,
                bundle_version = outcome.version.as_deref().unwrap_or("unknown"),
                "Startup registry bundle refresh completed"
            );
        }
        Ok(Err(error)) => {
            consecutive_failures = consecutive_failures.saturating_add(1);
            runtime_source = resolve_registry_runtime_source(puller.cache_path());
            soth_helper::metrics::set_registry_source_state(runtime_source.as_metric());
            soth_helper::metrics::set_registry_refresh_consecutive_failures(consecutive_failures);
            persist_registry_runtime_state(
                puller.cache_path(),
                runtime_source,
                consecutive_failures,
                last_success_unix_secs,
                Some("startup_refresh_failed"),
            );
            warn!(
                source = runtime_source.as_label(),
                consecutive_failures = consecutive_failures,
                error = %format!("{:#}", error),
                "Startup registry bundle refresh failed; continuing with cached bundle"
            );
        }
        Err(_) => {
            consecutive_failures = consecutive_failures.saturating_add(1);
            runtime_source = resolve_registry_runtime_source(puller.cache_path());
            soth_helper::metrics::set_registry_source_state(runtime_source.as_metric());
            soth_helper::metrics::set_registry_refresh_consecutive_failures(consecutive_failures);
            persist_registry_runtime_state(
                puller.cache_path(),
                runtime_source,
                consecutive_failures,
                last_success_unix_secs,
                Some("startup_refresh_timeout"),
            );
            warn!(
                source = runtime_source.as_label(),
                consecutive_failures = consecutive_failures,
                timeout_secs = STARTUP_REGISTRY_REFRESH_TIMEOUT.as_secs(),
                "Startup registry bundle refresh timed out; continuing with cached bundle"
            );
        }
    }
}

pub fn spawn_cloud_pull_runtime(
    config: &SothConfig,
    event_db_path: Option<PathBuf>,
) -> Option<CloudPullRuntime> {
    use soth_sync::agent::{SyncAgent, SyncAgentConfig};
    use soth_sync::config_puller::ConfigPuller;
    use soth_sync::registry_puller::RegistryPuller;

    if !config.cloud.enabled {
        return None;
    }

    let singleton_lock = match try_acquire_cloud_runtime_singleton_lock() {
        Ok(Some(lock)) => lock,
        Ok(None) => {
            info!(
                "Cloud runtime already active in another process; skipping duplicate runtime startup"
            );
            return None;
        }
        Err(error) => {
            warn!(
                "Failed to acquire cloud runtime singleton lock; skipping cloud runtime: {:#}",
                error
            );
            return None;
        }
    };

    let api_key = config.cloud.api_key.clone()?;
    let endpoint = config.cloud.endpoint.clone();
    let cache_path = resolve_cache_path(config);
    let registry_cache_path = resolve_registry_cache_path(config, &cache_path);
    let sync_interval_secs = config.cloud.sync_interval_secs.max(5);
    let interval_secs = config.cloud.config_pull_interval_secs.max(15);
    let debounce_secs = config.cloud.config_debounce_secs.max(1);
    let mut global_tags = config.cloud.tags.clone();
    if !global_tags.contains_key("device_id") {
        if let Some(device_id) = cli_config::read_client_device_id() {
            global_tags.insert("device_id".to_string(), device_id);
        }
    }
    let frontload_exchange_upload_path = std::env::var("SOTH_CLOUD_FRONTLOAD_UPLOAD_PATH")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| config.cloud.frontload_exchange_upload_path.clone());
    let registry_puller = RegistryPuller::new(
        endpoint.clone(),
        api_key.clone(),
        registry_cache_path.clone(),
    )
    .with_bundle_type(config.forward_proxy.engine.registry_bundle_type())
    .with_fallback_endpoints(config.cloud.registry_bundle_fallback_endpoints.clone());
    let puller = ConfigPuller::new(endpoint, api_key, cache_path)
        .with_registry_puller(registry_puller)
        .with_debounce(std::time::Duration::from_secs(debounce_secs));
    let sync_agent = event_db_path.and_then(|event_db_path| {
        if !event_db_path.exists() {
            warn!(
                "Cloud sync disabled: event DB not found at {}",
                event_db_path.display()
            );
            return None;
        }
        let sync_config = SyncAgentConfig {
            endpoint: config.cloud.endpoint.clone(),
            api_key: config.cloud.api_key.clone().unwrap_or_default(),
            event_db_path,
            cache_path: puller.cache_path().clone(),
            registry_cache_path: Some(registry_cache_path.clone()),
            agent_instance_id: build_agent_instance_id(),
            proxy_version: env!("CARGO_PKG_VERSION").to_string(),
            retry_queue_dir: default_retry_queue_dir(),
            retry_queue_max_bytes: 500 * 1024 * 1024,
            sync_interval: std::time::Duration::from_secs(sync_interval_secs),
            batch_size: config.cloud.metadata_max_events_per_batch.max(1),
            body_batch_size: 64,
            body_upload_enabled: config.cloud.body_upload_enabled,
            metadata_max_events_per_batch: config.cloud.metadata_max_events_per_batch.max(1),
            metadata_max_compressed_batch_bytes: config
                .cloud
                .metadata_max_compressed_batch_bytes
                .max(1) as usize,
            frontload_enabled: config.cloud.frontload_enabled,
            frontload_max_events_per_batch: config.cloud.frontload_max_events_per_batch.max(1),
            frontload_max_compressed_batch_bytes: config
                .cloud
                .frontload_max_compressed_batch_bytes
                .max(1) as usize,
            frontload_hard_events_cap: config.cloud.frontload_hard_events_cap.max(1),
            frontload_hard_compressed_cap_bytes: config
                .cloud
                .frontload_hard_compressed_cap_bytes
                .max(1) as usize,
            frontload_exchange_upload_path: frontload_exchange_upload_path.clone(),
            body_upload_max_bytes: config.cloud.body_upload_max_bytes.max(1) as usize,
            global_tags: global_tags.clone(),
            heartbeat_telemetry: Some(std::sync::Arc::new(|| {
                let snapshot = soth_helper::metrics::heartbeat_telemetry_snapshot();
                if snapshot.counters.values().all(|value| *value == 0) {
                    None
                } else {
                    Some(snapshot)
                }
            })),
        };
        match SyncAgent::new(sync_config, Some(puller.clone())) {
            Ok(agent) => Some(agent),
            Err(error) => {
                warn!("Failed to initialize cloud sync agent: {:#}", error);
                None
            }
        }
    });

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let config_pull_base = std::time::Duration::from_secs(interval_secs);
        let sync_base = std::time::Duration::from_secs(sync_interval_secs);
        let heartbeat_base = std::time::Duration::from_secs(sync_interval_secs.max(30));
        let mut config_pull_backoff =
            ExponentialBackoff::new(config_pull_base, bounded_backoff_max(config_pull_base));
        let mut sync_backoff = ExponentialBackoff::new(sync_base, bounded_backoff_max(sync_base));
        let mut heartbeat_backoff =
            ExponentialBackoff::new(heartbeat_base, bounded_backoff_max(heartbeat_base));

        let mut registry_source = resolve_registry_runtime_source(&registry_cache_path);
        let mut registry_consecutive_failures = 0_u64;
        let mut registry_last_success_unix_secs = 0_u64;
        soth_helper::metrics::set_registry_source_state(registry_source.as_metric());
        soth_helper::metrics::set_registry_refresh_consecutive_failures(
            registry_consecutive_failures,
        );
        persist_registry_runtime_state(
            &registry_cache_path,
            registry_source,
            registry_consecutive_failures,
            registry_last_success_unix_secs,
            Some("runtime_init"),
        );
        info!(
            source = registry_source.as_label(),
            "Registry runtime source initialized"
        );

        if let Err(error) = puller.pull_once().await {
            let retry_in = config_pull_backoff.record_failure();
            registry_consecutive_failures = registry_consecutive_failures.saturating_add(1);
            soth_helper::metrics::set_registry_refresh_consecutive_failures(
                registry_consecutive_failures,
            );
            let degraded = resolve_registry_runtime_source(&registry_cache_path);
            if degraded != registry_source {
                warn!(
                    previous_source = registry_source.as_label(),
                    source = degraded.as_label(),
                    "Registry runtime source transitioned after initial pull failure"
                );
            }
            registry_source = degraded;
            soth_helper::metrics::set_registry_source_state(registry_source.as_metric());
            persist_registry_runtime_state(
                &registry_cache_path,
                registry_source,
                registry_consecutive_failures,
                registry_last_success_unix_secs,
                Some("initial_pull_failed"),
            );
            warn!(
                source = registry_source.as_label(),
                consecutive_failures = registry_consecutive_failures,
                retry_in_secs = retry_in.as_secs(),
                "Initial cloud config pull failed: {:#}",
                error
            );
        } else {
            config_pull_backoff.record_success();
            let next_source = resolve_registry_runtime_source_after_success(&registry_cache_path);
            if registry_source != next_source {
                info!(
                    previous_source = registry_source.as_label(),
                    source = next_source.as_label(),
                    "Registry runtime source transitioned after pull success"
                );
            }
            registry_source = next_source;
            registry_consecutive_failures = 0;
            soth_helper::metrics::set_registry_source_state(registry_source.as_metric());
            soth_helper::metrics::set_registry_refresh_consecutive_failures(
                registry_consecutive_failures,
            );
            registry_last_success_unix_secs = current_unix_secs();
            soth_helper::metrics::set_registry_refresh_last_success_unix_secs(
                registry_last_success_unix_secs,
            );
            persist_registry_runtime_state(
                &registry_cache_path,
                registry_source,
                registry_consecutive_failures,
                registry_last_success_unix_secs,
                Some("initial_pull_success"),
            );
        }
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut sync_interval =
            tokio::time::interval(std::time::Duration::from_secs(sync_interval_secs));
        sync_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut heartbeat_interval =
            tokio::time::interval(std::time::Duration::from_secs(sync_interval_secs.max(30)));
        heartbeat_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        sync_interval.tick().await;
        heartbeat_interval.tick().await;
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    if let Some(agent) = &sync_agent {
                        match tokio::time::timeout(
                            FINAL_CLOUD_SYNC_TIMEOUT,
                            agent.flush_for_shutdown(FINAL_CLOUD_SYNC_MAX_ROUNDS),
                        ).await {
                            Ok(Ok(summary)) => {
                                if summary.exchange_sent > 0
                                    || summary.exchange_blob_uploaded > 0
                                    || summary.exchange_retry_deferred > 0
                                    || summary.exchange_dropped > 0
                                {
                                    info!(
                                        exchange_sent = summary.exchange_sent,
                                        exchange_blob_uploaded = summary.exchange_blob_uploaded,
                                        exchange_retry_deferred = summary.exchange_retry_deferred,
                                        exchange_dropped = summary.exchange_dropped,
                                        "Final cloud sync flush on shutdown"
                                    );
                                }
                            }
                            Ok(Err(error)) => warn!("Final cloud sync flush failed: {:#}", error),
                            Err(_) => warn!("Final cloud sync flush timed out"),
                        }
                        match tokio::time::timeout(
                            FINAL_CLOUD_HEARTBEAT_TIMEOUT,
                            agent.send_heartbeat(),
                        ).await {
                            Ok(Ok(_)) => {}
                            Ok(Err(error)) => warn!("Final cloud heartbeat failed: {:#}", error),
                            Err(_) => warn!("Final cloud heartbeat timed out"),
                        }
                    }
                    break
                },
                _ = interval.tick() => {
                    if !config_pull_backoff.is_ready() {
                        continue;
                    }
                    if let Err(error) = puller.pull_once().await {
                        let retry_in = config_pull_backoff.record_failure();
                        registry_consecutive_failures = registry_consecutive_failures.saturating_add(1);
                        soth_helper::metrics::set_registry_refresh_consecutive_failures(
                            registry_consecutive_failures,
                        );
                        let degraded = resolve_registry_runtime_source(&registry_cache_path);
                        if degraded != registry_source {
                            warn!(
                                previous_source = registry_source.as_label(),
                                source = degraded.as_label(),
                                "Registry runtime source transitioned after periodic pull failure"
                            );
                        }
                        registry_source = degraded;
                        soth_helper::metrics::set_registry_source_state(registry_source.as_metric());
                        persist_registry_runtime_state(
                            &registry_cache_path,
                            registry_source,
                            registry_consecutive_failures,
                            registry_last_success_unix_secs,
                            Some("periodic_pull_failed"),
                        );
                        warn!(
                            source = registry_source.as_label(),
                            consecutive_failures = registry_consecutive_failures,
                            retry_in_secs = retry_in.as_secs(),
                            "Periodic cloud config pull failed: {:#}",
                            error
                        );
                    } else {
                        config_pull_backoff.record_success();
                        let next_source =
                            resolve_registry_runtime_source_after_success(&registry_cache_path);
                        if registry_source != next_source {
                            info!(
                                previous_source = registry_source.as_label(),
                                source = next_source.as_label(),
                                "Registry runtime source transitioned after pull success"
                            );
                        }
                        registry_source = next_source;
                        registry_consecutive_failures = 0;
                        soth_helper::metrics::set_registry_source_state(registry_source.as_metric());
                        soth_helper::metrics::set_registry_refresh_consecutive_failures(
                            registry_consecutive_failures,
                        );
                        registry_last_success_unix_secs = current_unix_secs();
                        soth_helper::metrics::set_registry_refresh_last_success_unix_secs(
                            registry_last_success_unix_secs,
                        );
                        persist_registry_runtime_state(
                            &registry_cache_path,
                            registry_source,
                            registry_consecutive_failures,
                            registry_last_success_unix_secs,
                            Some("periodic_pull_success"),
                        );
                    }
                }
                _ = sync_interval.tick() => {
                    if let Some(agent) = &sync_agent {
                        if !sync_backoff.is_ready() {
                            continue;
                        }
                        match agent.tick().await {
                            Ok(summary) => {
                                sync_backoff.record_success();
                                if summary.exchange_sent > 0
                                    || summary.exchange_blob_uploaded > 0
                                    || summary.exchange_retry_deferred > 0
                                    || summary.exchange_dropped > 0
                                {
                                    info!(
                                        exchange_sent = summary.exchange_sent,
                                        exchange_blob_uploaded = summary.exchange_blob_uploaded,
                                        exchange_retry_deferred = summary.exchange_retry_deferred,
                                        exchange_dropped = summary.exchange_dropped,
                                        "Cloud sync tick"
                                    );
                                }
                            }
                            Err(error) => {
                                let retry_in = sync_backoff.record_failure();
                                warn!(
                                    retry_in_secs = retry_in.as_secs(),
                                    "Cloud sync tick failed: {:#}",
                                    error
                                );
                            }
                        }
                    }
                }
                _ = heartbeat_interval.tick() => {
                    if let Some(agent) = &sync_agent {
                        if !heartbeat_backoff.is_ready() {
                            continue;
                        }
                        if let Err(error) = agent.send_heartbeat().await {
                            let retry_in = heartbeat_backoff.record_failure();
                            warn!(
                                retry_in_secs = retry_in.as_secs(),
                                "Cloud heartbeat failed: {:#}",
                                error
                            );
                        } else {
                            heartbeat_backoff.record_success();
                        }
                    }
                }
            }
        }
    });

    Some(CloudPullRuntime {
        shutdown_tx,
        task,
        _singleton_lock: singleton_lock,
    })
}

struct CloudRuntimeSingletonLock {
    #[allow(dead_code)]
    file: File,
}

impl Drop for CloudRuntimeSingletonLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

fn try_acquire_cloud_runtime_singleton_lock() -> Result<Option<CloudRuntimeSingletonLock>> {
    let path = cloud_runtime_lock_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&path)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(anyhow!(
                "failed acquiring cloud runtime singleton lock {}: {}",
                path.display(),
                error
            ));
        }
    }
    Ok(Some(CloudRuntimeSingletonLock { file }))
}

fn cloud_runtime_lock_path() -> PathBuf {
    dirs::home_dir()
        .map(|home| home.join(".soth").join("run").join(CLOUD_RUNTIME_LOCK_FILE))
        .unwrap_or_else(|| PathBuf::from(".soth/run").join(CLOUD_RUNTIME_LOCK_FILE))
}

#[derive(Debug, Clone)]
struct ExponentialBackoff {
    base: Duration,
    max: Duration,
    failures: u32,
    blocked_until: Option<Instant>,
}

impl ExponentialBackoff {
    fn new(base: Duration, max: Duration) -> Self {
        let safe_base = std::cmp::max(base, Duration::from_secs(1));
        let safe_max = std::cmp::max(max, safe_base);
        Self {
            base: safe_base,
            max: safe_max,
            failures: 0,
            blocked_until: None,
        }
    }

    fn is_ready(&self) -> bool {
        self.blocked_until
            .map(|deadline| Instant::now() >= deadline)
            .unwrap_or(true)
    }

    fn record_success(&mut self) {
        self.failures = 0;
        self.blocked_until = None;
    }

    fn record_failure(&mut self) -> Duration {
        self.failures = self.failures.saturating_add(1);
        let shift = self.failures.saturating_sub(1).min(10);
        let multiplier = 1_u32 << shift;
        let base_delay = self
            .base
            .checked_mul(multiplier)
            .unwrap_or(self.max)
            .min(self.max);
        // Add small bounded jitter (80-120%) to avoid synchronized retry bursts.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0);
        let jitter_percent = 80 + (nanos % 41); // 80..120
        let jittered = base_delay
            .as_millis()
            .saturating_mul(jitter_percent as u128)
            / 100;
        let delay = Duration::from_millis(jittered as u64).min(self.max);
        self.blocked_until = Some(Instant::now() + delay);
        delay
    }
}

fn bounded_backoff_max(base: Duration) -> Duration {
    std::cmp::max(
        base,
        std::cmp::min(
            base.checked_mul(32).unwrap_or(CLOUD_BACKOFF_MAX_CAP),
            CLOUD_BACKOFF_MAX_CAP,
        ),
    )
}

fn apply_budget_from_cache(config: &mut SothConfig, limits: &[soth_core::api::ConfigBudgetLimit]) {
    let mapped: Vec<BudgetLimit> = limits.iter().filter_map(map_cloud_budget_limit).collect();
    if mapped.is_empty() {
        return;
    }
    config.budget.enabled = true;
    config.budget.limits = mapped;
}

fn map_cloud_budget_limit(limit: &soth_core::api::ConfigBudgetLimit) -> Option<BudgetLimit> {
    let effective_daily = effective_daily_limit(limit);
    match limit.scope.as_str() {
        "model" => Some(BudgetLimit {
            scope: "per_model".to_string(),
            daily: effective_daily,
            weekly: limit.weekly_usd,
            monthly: limit.monthly_usd,
            agent_id: None,
            model: limit.model.clone(),
        }),
        "org" | "team" | "user" => Some(BudgetLimit {
            scope: "global".to_string(),
            daily: effective_daily,
            weekly: limit.weekly_usd,
            monthly: limit.monthly_usd,
            agent_id: None,
            model: None,
        }),
        _ => None,
    }
}

fn apply_policy_from_cache(
    config: &mut SothConfig,
    version: &str,
    policies: &[soth_core::api::ConfigPolicy],
) -> Result<()> {
    if policies.is_empty() {
        return Ok(());
    }
    let local_policy_dir = config.policy.policy_dir.clone();
    let dir = materialize_effective_policy_dir(version, policies, local_policy_dir.as_deref())?;
    config.policy.enabled = true;
    config.policy.policy_dir = Some(dir);
    Ok(())
}

fn apply_registry_mode_from_cache(config: &mut SothConfig, mode: Option<&str>) {
    let Some(mode) = mode else {
        return;
    };
    let normalized = mode.trim().to_ascii_lowercase();
    config.forward_proxy.registry_mode = match normalized.as_str() {
        "bundle_only" | "strict" | "registry" => RegistryMode::BundleOnly,
        _ => RegistryMode::BundleOnly,
    };
}

fn materialize_effective_policy_dir(
    version: &str,
    policies: &[soth_core::api::ConfigPolicy],
    local_policy_dir: Option<&Path>,
) -> Result<PathBuf> {
    let base = if let Some(home) = dirs::home_dir() {
        home.join(".soth")
            .join("runtime")
            .join("effective-policies")
    } else {
        PathBuf::from(".soth/runtime/effective-policies")
    };
    let version_slug = slugify(version);
    let dir = base.join(version_slug);
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;

    for (idx, policy) in policies.iter().enumerate() {
        let filename = format!(
            "cloud_{idx:03}_{}_{}.rego",
            slugify(&policy.scope),
            slugify(&policy.name)
        );
        std::fs::write(dir.join(filename), &policy.rego)?;
    }

    if let Some(local) = local_policy_dir {
        if local.exists() {
            let copied = copy_local_policy_files(local, &dir)?;
            info!(
                local_policy_dir = %local.display(),
                copied_files = copied,
                "Merged local policies into effective cloud policy directory"
            );
        }
    }

    Ok(dir)
}

fn copy_local_policy_files(local_dir: &Path, destination_dir: &Path) -> Result<usize> {
    let mut copied = 0usize;
    for entry in std::fs::read_dir(local_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if extension != "rego" && extension != "yaml" && extension != "yml" {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("policy");
        let merged_name = format!("local_{:03}_{}", copied, file_name);
        std::fs::copy(&path, destination_dir.join(merged_name))?;
        copied += 1;
    }
    Ok(copied)
}

fn effective_daily_limit(limit: &soth_core::api::ConfigBudgetLimit) -> Option<f64> {
    match (limit.daily_usd, limit.remaining_usd) {
        (Some(daily), Some(remaining)) => Some(daily.min(remaining).max(0.0)),
        (Some(daily), None) => Some(daily.max(0.0)),
        (None, Some(remaining)) => Some(remaining.max(0.0)),
        (None, None) => None,
    }
}

fn resolve_cache_path(config: &SothConfig) -> PathBuf {
    if let Some(path) = config.cloud.cache_path.as_ref() {
        return path.clone();
    }
    default_cache_path()
}

fn resolve_registry_cache_path(config: &SothConfig, config_cache_path: &Path) -> PathBuf {
    let cache_name = config.forward_proxy.engine.registry_bundle_cache_filename();
    if config.cloud.cache_path.is_some() {
        if let Some(parent) = config_cache_path.parent() {
            return parent.join(cache_name);
        }
    }
    dirs::home_dir()
        .map(|home| home.join(".soth").join(cache_name))
        .unwrap_or_else(|| PathBuf::from(".soth").join(cache_name))
}

fn default_cache_path() -> PathBuf {
    soth_sync::cache::default_cache_path()
}

fn slugify(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    out.trim_matches('_').to_string()
}

fn default_retry_queue_dir() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        return home.join(".soth").join("sync").join("upload_queue");
    }
    PathBuf::from(".soth/sync/upload_queue")
}

fn build_agent_instance_id() -> String {
    let host = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "edge".to_string());
    format!("{}-{}-{}", host, std::process::id(), uuid::Uuid::new_v4())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_daily_prefers_remaining_when_lower() {
        let limit = soth_core::api::ConfigBudgetLimit {
            scope: "org".to_string(),
            model: None,
            daily_usd: Some(100.0),
            weekly_usd: None,
            monthly_usd: None,
            remaining_usd: Some(12.5),
        };
        assert_eq!(effective_daily_limit(&limit), Some(12.5));
    }

    #[test]
    fn effective_daily_uses_remaining_when_daily_missing() {
        let limit = soth_core::api::ConfigBudgetLimit {
            scope: "org".to_string(),
            model: None,
            daily_usd: None,
            weekly_usd: None,
            monthly_usd: None,
            remaining_usd: Some(7.0),
        };
        assert_eq!(effective_daily_limit(&limit), Some(7.0));
    }
}
