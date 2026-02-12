use anyhow::Result;
use soth_core::config::SothConfig;
use tokio::task::JoinHandle;
use tracing::warn;

#[cfg(feature = "cloud-sync")]
use soth_core::config::BudgetLimit;
#[cfg(feature = "cloud-sync")]
use std::path::{Path, PathBuf};
#[cfg(feature = "cloud-sync")]
use tracing::info;

pub struct CloudPullRuntime {
    pub shutdown_tx: tokio::sync::oneshot::Sender<()>,
    pub task: JoinHandle<()>,
}

#[cfg(feature = "cloud-sync")]
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

    info!(
        config_version = %cached.config_version,
        policies = cached.policies.len(),
        budget_limits = cached.budget.limits.len(),
        "Applied cached cloud controls"
    );
    Ok(())
}

#[cfg(not(feature = "cloud-sync"))]
pub fn apply_cached_controls(config: &mut SothConfig) -> Result<()> {
    if config.cloud.enabled {
        warn!("cloud.enabled=true but soth-cli built without `cloud-sync` feature; skipping cloud hooks");
    }
    Ok(())
}

#[cfg(feature = "cloud-sync")]
pub fn spawn_cloud_pull_runtime(
    config: &SothConfig,
    event_db_path: Option<PathBuf>,
) -> Option<CloudPullRuntime> {
    use soth_sync::agent::{SyncAgent, SyncAgentConfig};
    use soth_sync::config_puller::ConfigPuller;

    if !config.cloud.enabled {
        return None;
    }

    let api_key = config.cloud.api_key.clone()?;
    let endpoint = config.cloud.endpoint.clone();
    let cache_path = resolve_cache_path(config);
    let sync_interval_secs = config.cloud.sync_interval_secs.max(5);
    let interval_secs = config.cloud.config_pull_interval_secs.max(15);
    let debounce_secs = config.cloud.config_debounce_secs.max(1);
    let puller = ConfigPuller::new(endpoint, api_key, cache_path)
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
            agent_instance_id: build_agent_instance_id(),
            proxy_version: env!("CARGO_PKG_VERSION").to_string(),
            retry_queue_dir: default_retry_queue_dir(),
            retry_queue_max_bytes: 500 * 1024 * 1024,
            sync_interval: std::time::Duration::from_secs(sync_interval_secs),
            batch_size: 100,
            body_batch_size: 64,
            body_upload_enabled: config.cloud.body_upload_enabled,
            global_tags: config.cloud.tags.clone(),
        };
        match SyncAgent::new(sync_config, Some(puller.clone())) {
            Ok(agent) => Some(agent),
            Err(error) => {
                warn!("Failed to initialize cloud sync agent: {}", error);
                None
            }
        }
    });

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        if let Err(error) = puller.pull_once().await {
            warn!("Initial cloud config pull failed: {}", error);
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
                _ = &mut shutdown_rx => break,
                _ = interval.tick() => {
                    if let Err(error) = puller.pull_once().await {
                        warn!("Periodic cloud config pull failed: {}", error);
                    }
                }
                _ = sync_interval.tick() => {
                    if let Some(agent) = &sync_agent {
                        match agent.tick().await {
                            Ok(summary) => {
                                if summary.metadata_sent > 0
                                    || summary.body_uploaded > 0
                                    || summary.retry_uploaded > 0
                                {
                                    info!(
                                        metadata_sent = summary.metadata_sent,
                                        body_uploaded = summary.body_uploaded,
                                        retry_uploaded = summary.retry_uploaded,
                                        "Cloud sync tick"
                                    );
                                }
                            }
                            Err(error) => warn!("Cloud sync tick failed: {}", error),
                        }
                    }
                }
                _ = heartbeat_interval.tick() => {
                    if let Some(agent) = &sync_agent {
                        if let Err(error) = agent.send_heartbeat().await {
                            warn!("Cloud heartbeat failed: {}", error);
                        }
                    }
                }
            }
        }
    });

    Some(CloudPullRuntime { shutdown_tx, task })
}

#[cfg(not(feature = "cloud-sync"))]
pub fn spawn_cloud_pull_runtime(
    _config: &SothConfig,
    _event_db_path: Option<std::path::PathBuf>,
) -> Option<CloudPullRuntime> {
    None
}

#[cfg(feature = "cloud-sync")]
fn apply_budget_from_cache(config: &mut SothConfig, limits: &[soth_core::api::ConfigBudgetLimit]) {
    let mapped: Vec<BudgetLimit> = limits.iter().filter_map(map_cloud_budget_limit).collect();
    if mapped.is_empty() {
        return;
    }
    config.budget.enabled = true;
    config.budget.limits = mapped;
}

#[cfg(feature = "cloud-sync")]
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

#[cfg(feature = "cloud-sync")]
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

#[cfg(feature = "cloud-sync")]
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

#[cfg(feature = "cloud-sync")]
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

#[cfg(feature = "cloud-sync")]
fn effective_daily_limit(limit: &soth_core::api::ConfigBudgetLimit) -> Option<f64> {
    match (limit.daily_usd, limit.remaining_usd) {
        (Some(daily), Some(remaining)) => Some(daily.min(remaining).max(0.0)),
        (Some(daily), None) => Some(daily.max(0.0)),
        (None, Some(remaining)) => Some(remaining.max(0.0)),
        (None, None) => None,
    }
}

#[cfg(feature = "cloud-sync")]
fn resolve_cache_path(config: &SothConfig) -> PathBuf {
    if let Some(path) = config.cloud.cache_path.as_ref() {
        return path.clone();
    }
    default_cache_path()
}

#[cfg(feature = "cloud-sync")]
fn default_cache_path() -> PathBuf {
    soth_sync::cache::default_cache_path()
}

#[cfg(feature = "cloud-sync")]
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

#[cfg(feature = "cloud-sync")]
fn default_retry_queue_dir() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        return home.join(".soth").join("sync").join("upload_queue");
    }
    PathBuf::from(".soth/sync/upload_queue")
}

#[cfg(feature = "cloud-sync")]
fn build_agent_instance_id() -> String {
    let host = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "edge".to_string());
    format!("{}-{}-{}", host, std::process::id(), uuid::Uuid::new_v4())
}

#[cfg(all(test, feature = "cloud-sync"))]
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
