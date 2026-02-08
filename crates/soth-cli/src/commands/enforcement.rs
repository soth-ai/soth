//! Shared enforcement runtime builders used by proxy and wrap commands.

use anyhow::Context;
use soth_budget::BudgetTracker;
use soth_core::config::SothConfig;
use soth_core::types::policy::PolicyInputBuilder;
use soth_identity::TrustStore;
use soth_policy::{CacheConfig as PolicyCacheConfig, PolicyEngine, PolicyLoader};
use soth_proxy::metrics;
use soth_proxy::pipeline::budget::{BudgetConfig, BudgetLayer};
use soth_proxy::pipeline::identity::{IdentityConfig, IdentityLayer, IdentityMode};
use soth_proxy::pipeline::policy::{PolicyConfig, PolicyLayer, PolicyMode};
use soth_proxy::pipeline::{Pipeline, PipelineBuilder};
use soth_proxy::transport::hudsucker_proxy::{ProxyEnforcer, ProxyIdentityMode, ProxyPolicyMode};
use std::collections::HashMap;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

pub struct WrapEnforcementRuntime {
    pub pipeline: Arc<Pipeline>,
    pub did_metadata_key: String,
    pub signature_metadata_key: String,
}

#[derive(Clone)]
struct PolicyArtifacts {
    modules: HashMap<String, String>,
    data: Option<soth_core::types::policy::PolicyData>,
    fingerprint: String,
}

fn resolve_trust_store_file(path: &Path) -> PathBuf {
    if path.extension().is_some() {
        path.to_path_buf()
    } else {
        path.join("trust_store")
    }
}

fn collect_trusted_dids(config: &SothConfig) -> anyhow::Result<HashSet<String>> {
    let mut trusted_dids: HashSet<String> = HashSet::new();
    for did in &config.identity.allowed_dids {
        trusted_dids.insert(did.clone());
    }

    if let Some(path) = &config.identity.trust_store_path {
        let trust_store_file = resolve_trust_store_file(path);
        if trust_store_file.exists() {
            let store = TrustStore::new(&trust_store_file)?;
            for did in store.list() {
                trusted_dids.insert(did.to_string());
            }
        }
    }

    Ok(trusted_dids)
}

fn load_policy_artifacts(config: &SothConfig) -> anyhow::Result<PolicyArtifacts> {
    let mut modules = HashMap::new();

    if let Some(policy_dir) = &config.policy.policy_dir {
        if policy_dir.exists() {
            if let Ok(rego_modules) = PolicyLoader::load_rego_dir(policy_dir) {
                modules.extend(rego_modules);
            }
            if let Ok(yaml_modules) = PolicyLoader::load_yaml_dir(policy_dir) {
                modules.extend(yaml_modules);
            }
        }
    }

    let data = if let Some(data_file) = &config.policy.data_file {
        Some(match data_file.extension().and_then(|e| e.to_str()) {
            Some("yaml") | Some("yml") => PolicyLoader::load_policy_data_yaml(data_file)?,
            _ => PolicyLoader::load_policy_data(data_file)?,
        })
    } else {
        None
    };

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    let mut keys: Vec<_> = modules.keys().cloned().collect();
    keys.sort();
    for key in keys {
        key.hash(&mut hasher);
        if let Some(module) = modules.get(&key) {
            module.hash(&mut hasher);
        }
    }
    if let Some(ref data) = data {
        serde_json::to_string(data)
            .unwrap_or_default()
            .hash(&mut hasher);
    }

    Ok(PolicyArtifacts {
        modules,
        data,
        fingerprint: format!("{:016x}", hasher.finish()),
    })
}

fn validate_policy_artifacts(
    cache_config: PolicyCacheConfig,
    artifacts: &PolicyArtifacts,
) -> anyhow::Result<()> {
    let probe_engine = PolicyEngine::with_cache_config(cache_config);
    if let Some(ref data) = artifacts.data {
        probe_engine.set_policy_data(data.clone())?;
    }
    if !artifacts.modules.is_empty() {
        probe_engine.load_modules(artifacts.modules.clone())?;
    }

    // Validate by executing one probe evaluation.
    let probe_input = PolicyInputBuilder::new()
        .session_id("policy-reload-probe")
        .method("tools/call")
        .tool("health/probe")
        .build();
    probe_engine
        .evaluate(&probe_input)
        .map_err(|e| anyhow::anyhow!("policy artifact validation failed: {e}"))?;

    Ok(())
}

fn apply_policy_artifacts(
    engine: &PolicyEngine,
    artifacts: &PolicyArtifacts,
) -> anyhow::Result<()> {
    if let Some(ref data) = artifacts.data {
        engine.set_policy_data(data.clone())?;
    }
    engine.load_modules(artifacts.modules.clone())?;
    Ok(())
}

fn build_policy_engine(config: &SothConfig) -> anyhow::Result<Option<PolicyEngine>> {
    if !config.policy.enabled {
        return Ok(None);
    }

    let cache_config: PolicyCacheConfig = config.policy.cache.clone().into();
    let engine = PolicyEngine::with_cache_config(cache_config);
    let artifacts = load_policy_artifacts(config)?;

    if let Err(error) = validate_policy_artifacts(config.policy.cache.clone().into(), &artifacts) {
        metrics::record_policy_reload(false);
        return Err(error);
    }

    if let Err(error) = apply_policy_artifacts(&engine, &artifacts) {
        metrics::record_policy_reload(false);
        return Err(error);
    }

    metrics::record_policy_reload(true);
    metrics::set_policy_active_version(&engine.active_policy_version());
    Ok(Some(engine))
}

pub fn spawn_policy_hot_reload(
    config: &SothConfig,
    engine: Arc<PolicyEngine>,
) -> Option<JoinHandle<()>> {
    if !config.policy.enabled || !config.policy.watch_for_changes {
        return None;
    }

    let policy_config = config.clone();
    Some(tokio::spawn(async move {
        let mut current_fingerprint = match load_policy_artifacts(&policy_config) {
            Ok(artifacts) => artifacts.fingerprint,
            Err(error) => {
                warn!("Policy hot reload startup snapshot failed: {}", error);
                String::new()
            }
        };

        info!("Policy hot reload watcher started");
        let mut ticker = tokio::time::interval(Duration::from_secs(2));
        loop {
            ticker.tick().await;
            let artifacts = match load_policy_artifacts(&policy_config) {
                Ok(artifacts) => artifacts,
                Err(error) => {
                    warn!("Policy hot reload: failed to load artifacts: {}", error);
                    continue;
                }
            };
            if artifacts.fingerprint == current_fingerprint {
                continue;
            }

            match validate_policy_artifacts(policy_config.policy.cache.clone().into(), &artifacts) {
                Ok(()) => match apply_policy_artifacts(&engine, &artifacts) {
                    Ok(()) => {
                        metrics::record_policy_reload(true);
                        let active_version = engine.active_policy_version();
                        metrics::set_policy_active_version(&active_version);
                        info!(
                            "Policy hot reload applied successfully (version={})",
                            active_version
                        );
                        current_fingerprint = artifacts.fingerprint;
                    }
                    Err(error) => {
                        metrics::record_policy_reload(false);
                        warn!(
                            "Policy hot reload candidate rejected during activation (rollback kept): {}",
                            error
                        );
                    }
                },
                Err(error) => {
                    metrics::record_policy_reload(false);
                    warn!(
                        "Policy hot reload candidate rejected during validation (rollback kept): {}",
                        error
                    );
                }
            }
            debug!(
                active_version = %engine.active_policy_version(),
                "Policy hot reload tick complete"
            );
        }
    }))
}

fn build_budget_tracker(config: &SothConfig) -> anyhow::Result<Option<BudgetTracker>> {
    if !config.budget.enabled {
        return Ok(None);
    }

    let tracker = BudgetTracker::new();
    for limit in &config.budget.limits {
        match limit.scope.as_str() {
            "global" => tracker.set_global_budget(limit.daily, limit.weekly, limit.monthly),
            "per_agent" => {
                let agent_id = limit.agent_id.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("budget limit scope=per_agent requires agent_id")
                })?;
                tracker.set_agent_budget(agent_id, limit.daily, limit.weekly, limit.monthly);
            }
            "per_session" => {
                tracker.set_session_budget(limit.daily, limit.weekly, limit.monthly);
            }
            "per_model" => {
                let model = limit.model.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("budget limit scope=per_model requires model")
                })?;
                tracker.set_model_budget(model, limit.daily, limit.weekly, limit.monthly);
            }
            other => {
                return Err(anyhow::anyhow!("unsupported budget limit scope: {other}"));
            }
        }
    }

    Ok(Some(tracker))
}

pub fn build_proxy_enforcer(config: &SothConfig) -> anyhow::Result<ProxyEnforcer> {
    let identity_mode = match config.identity.mode.as_str() {
        "disabled" => ProxyIdentityMode::Disabled,
        "required" => ProxyIdentityMode::Required,
        _ => ProxyIdentityMode::Optional,
    };

    let trusted_dids = collect_trusted_dids(config)?;

    let mut enforcer = ProxyEnforcer::new()
        .with_identity_mode(identity_mode, trusted_dids)
        .with_identity_headers("X-Agent-DID", "X-Agent-Signature");

    if let Some(engine) = build_policy_engine(config)? {
        let policy_mode = match config.policy.mode.as_str() {
            "audit" => ProxyPolicyMode::Audit,
            "enforce" => ProxyPolicyMode::Enforce,
            _ => ProxyPolicyMode::Enforce,
        };
        enforcer = enforcer.with_policy(policy_mode, engine);
    }

    if let Some(tracker) = build_budget_tracker(config)? {
        enforcer = enforcer.with_budget(tracker, true, "gpt-4o");
    }

    Ok(enforcer)
}

pub fn build_wrap_enforcement_runtime(
    config: &SothConfig,
) -> anyhow::Result<Option<WrapEnforcementRuntime>> {
    let mut pipeline_builder = PipelineBuilder::new();
    let mut enabled = false;

    let identity_mode = match config.identity.mode.as_str() {
        "disabled" => IdentityMode::Disabled,
        "required" => IdentityMode::Required,
        _ => IdentityMode::Optional,
    };
    let identity_config = IdentityConfig::default();
    if identity_mode != IdentityMode::Disabled {
        enabled = true;
        let mut trust_store = TrustStore::in_memory();
        for did in collect_trusted_dids(config)? {
            trust_store
                .trust(&did)
                .with_context(|| format!("Failed to trust DID from config: {did}"))?;
        }
        let layer = IdentityLayer::with_trust_store(
            IdentityConfig {
                mode: identity_mode,
                ..identity_config.clone()
            },
            trust_store,
        );
        pipeline_builder = pipeline_builder.layer(layer);
    }

    if let Some(engine) = build_policy_engine(config)? {
        enabled = true;
        let policy_mode = match config.policy.mode.as_str() {
            "disabled" => PolicyMode::Disabled,
            "audit" => PolicyMode::Audit,
            _ => PolicyMode::Enforce,
        };
        let layer = PolicyLayer::with_engine(
            PolicyConfig {
                mode: policy_mode,
                ..PolicyConfig::default()
            },
            engine,
        );
        pipeline_builder = pipeline_builder.layer(layer);
    }

    if let Some(tracker) = build_budget_tracker(config)? {
        enabled = true;
        let layer = BudgetLayer::with_tracker(
            BudgetConfig {
                enabled: true,
                block_on_exceeded: true,
                default_model: "gpt-4o".to_string(),
            },
            tracker,
        );
        pipeline_builder = pipeline_builder.layer(layer);
    }

    if !enabled {
        return Ok(None);
    }

    Ok(Some(WrapEnforcementRuntime {
        pipeline: Arc::new(pipeline_builder.build()),
        did_metadata_key: identity_config.did_header,
        signature_metadata_key: identity_config.signature_header,
    }))
}
