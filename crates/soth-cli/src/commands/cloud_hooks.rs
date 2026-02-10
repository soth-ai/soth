use anyhow::Result;
use soth_core::config::SothConfig;
use tokio::task::JoinHandle;
use tracing::warn;

#[cfg(feature = "cloud-sync")]
use soth_core::config::BudgetLimit;
#[cfg(feature = "cloud-sync")]
use std::path::PathBuf;
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
pub fn spawn_cloud_pull_runtime(config: &SothConfig) -> Option<CloudPullRuntime> {
    use soth_sync::config_puller::ConfigPuller;

    if !config.cloud.enabled {
        return None;
    }

    let api_key = config.cloud.api_key.clone()?;
    let endpoint = config.cloud.endpoint.clone();
    let cache_path = resolve_cache_path(config);
    let interval_secs = config.cloud.config_pull_interval_secs.max(15);
    let puller = ConfigPuller::new(endpoint, api_key, cache_path);

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        if let Err(error) = puller.pull_once().await {
            warn!("Initial cloud config pull failed: {}", error);
        }
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                _ = interval.tick() => {
                    if let Err(error) = puller.pull_once().await {
                        warn!("Periodic cloud config pull failed: {}", error);
                    }
                }
            }
        }
    });

    Some(CloudPullRuntime { shutdown_tx, task })
}

#[cfg(not(feature = "cloud-sync"))]
pub fn spawn_cloud_pull_runtime(_config: &SothConfig) -> Option<CloudPullRuntime> {
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
    match limit.scope.as_str() {
        "model" => Some(BudgetLimit {
            scope: "per_model".to_string(),
            daily: limit.daily_usd,
            weekly: limit.weekly_usd,
            monthly: limit.monthly_usd,
            agent_id: None,
            model: limit.model.clone(),
        }),
        "org" | "team" | "user" => Some(BudgetLimit {
            scope: "global".to_string(),
            daily: limit.daily_usd,
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
    if config.policy.policy_dir.is_some() {
        warn!("Cloud policies available but local policy_dir already configured; skipping cloud policy overlay");
        return Ok(());
    }

    let dir = materialize_cloud_policy_dir(version, policies)?;
    config.policy.enabled = true;
    config.policy.policy_dir = Some(dir);
    Ok(())
}

#[cfg(feature = "cloud-sync")]
fn materialize_cloud_policy_dir(
    version: &str,
    policies: &[soth_core::api::ConfigPolicy],
) -> Result<PathBuf> {
    let base = if let Some(home) = dirs::home_dir() {
        home.join(".soth").join("runtime").join("cloud-policies")
    } else {
        PathBuf::from(".soth/runtime/cloud-policies")
    };
    let version_slug = slugify(version);
    let dir = base.join(version_slug);
    std::fs::create_dir_all(&dir)?;

    for (idx, policy) in policies.iter().enumerate() {
        let filename = format!(
            "{idx:03}_{}_{}.rego",
            slugify(&policy.scope),
            slugify(&policy.name)
        );
        std::fs::write(dir.join(filename), &policy.rego)?;
    }

    Ok(dir)
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
