//! Shared enforcement runtime builders used by proxy and wrap commands.

use anyhow::Context;
use soth_budget::BudgetTracker;
use soth_core::config::SothConfig;
use soth_identity::TrustStore;
use soth_policy::{CacheConfig as PolicyCacheConfig, PolicyEngine, PolicyLoader};
use soth_proxy::pipeline::budget::{BudgetConfig, BudgetLayer};
use soth_proxy::pipeline::identity::{IdentityConfig, IdentityLayer, IdentityMode};
use soth_proxy::pipeline::policy::{PolicyConfig, PolicyLayer, PolicyMode};
use soth_proxy::pipeline::{Pipeline, PipelineBuilder};
use soth_proxy::transport::hudsucker_proxy::{ProxyEnforcer, ProxyIdentityMode, ProxyPolicyMode};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct WrapEnforcementRuntime {
    pub pipeline: Arc<Pipeline>,
    pub did_metadata_key: String,
    pub signature_metadata_key: String,
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

fn build_policy_engine(config: &SothConfig) -> anyhow::Result<Option<PolicyEngine>> {
    if !config.policy.enabled {
        return Ok(None);
    }

    let cache_config: PolicyCacheConfig = config.policy.cache.clone().into();
    let engine = PolicyEngine::with_cache_config(cache_config);

    if let Some(data_file) = &config.policy.data_file {
        let data = match data_file.extension().and_then(|e| e.to_str()) {
            Some("yaml") | Some("yml") => PolicyLoader::load_policy_data_yaml(data_file)?,
            _ => PolicyLoader::load_policy_data(data_file)?,
        };
        engine.set_policy_data(data)?;
    }

    if let Some(policy_dir) = &config.policy.policy_dir {
        let mut modules = std::collections::HashMap::new();

        if policy_dir.exists() {
            if let Ok(rego_modules) = PolicyLoader::load_rego_dir(policy_dir) {
                modules.extend(rego_modules);
            }
            if let Ok(yaml_modules) = PolicyLoader::load_yaml_dir(policy_dir) {
                modules.extend(yaml_modules);
            }
        }

        if !modules.is_empty() {
            engine.load_modules(modules)?;
        }
    }

    Ok(Some(engine))
}

fn build_budget_tracker(config: &SothConfig) -> Option<BudgetTracker> {
    if !config.budget.enabled {
        return None;
    }

    let tracker = BudgetTracker::new();
    for limit in &config.budget.limits {
        match limit.scope.as_str() {
            "global" => tracker.set_global_budget(limit.daily, limit.weekly, limit.monthly),
            "per_agent" => {
                if let Some(agent_id) = &limit.agent_id {
                    tracker.set_agent_budget(agent_id, limit.daily, limit.weekly, limit.monthly);
                }
            }
            _ => {}
        }
    }

    Some(tracker)
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

    if let Some(tracker) = build_budget_tracker(config) {
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

    if let Some(tracker) = build_budget_tracker(config) {
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
