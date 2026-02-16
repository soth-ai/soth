//! Shared enforcement runtime builders used by proxy and wrap commands.

use anyhow::Context;
use soth_budget::BudgetTracker;
use soth_core::config::SothConfig;
use soth_core::types::policy::PolicyInputBuilder;
use soth_crypto::identity::TrustStore;
use soth_oisp::OispEngine;
use soth_policy::{CacheConfig as PolicyCacheConfig, PolicyEngine, PolicyLoader};
use soth_proxy::metrics;
use soth_proxy::pipeline::budget::{BudgetConfig, BudgetLayer};
use soth_proxy::pipeline::identity::{IdentityConfig, IdentityLayer, IdentityMode};
use soth_proxy::pipeline::policy::{PolicyConfig, PolicyLayer, PolicyMode};
use soth_proxy::pipeline::{Pipeline, PipelineBuilder};
use soth_proxy::transport::proxy::{ProxyEnforcer, ProxyIdentityMode, ProxyPolicyMode};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CryptoRolloutMode {
    Disabled,
    Audit,
    EnforceSelected,
    EnforceGlobal,
}

#[derive(Debug, Clone)]
struct CryptoIdentityRollout {
    mode: CryptoRolloutMode,
    principals: HashSet<String>,
}

impl CryptoIdentityRollout {
    fn from_config(config: &SothConfig) -> Self {
        if !config.crypto_identity.enabled {
            return Self {
                mode: CryptoRolloutMode::Disabled,
                principals: HashSet::new(),
            };
        }

        let normalized_mode = config.crypto_identity.mode.trim().to_ascii_lowercase();
        if normalized_mode != "audit" && normalized_mode != "enforce" {
            warn!(
                "Unsupported crypto_identity.mode='{}'; falling back to audit",
                config.crypto_identity.mode
            );
        }

        if normalized_mode == "enforce" {
            let principals = normalize_principals(&config.crypto_identity.enforce_principals);
            if principals.is_empty() {
                return Self {
                    mode: CryptoRolloutMode::EnforceGlobal,
                    principals,
                };
            }
            return Self {
                mode: CryptoRolloutMode::EnforceSelected,
                principals,
            };
        }

        Self {
            mode: CryptoRolloutMode::Audit,
            principals: HashSet::new(),
        }
    }

    fn proxy_identity_mode(&self) -> ProxyIdentityMode {
        match self.mode {
            CryptoRolloutMode::Disabled => ProxyIdentityMode::Disabled,
            CryptoRolloutMode::Audit | CryptoRolloutMode::EnforceSelected => {
                ProxyIdentityMode::Optional
            }
            CryptoRolloutMode::EnforceGlobal => ProxyIdentityMode::Required,
        }
    }

    fn wrap_identity_mode(&self) -> IdentityMode {
        match self.mode {
            CryptoRolloutMode::Disabled => IdentityMode::Disabled,
            CryptoRolloutMode::Audit | CryptoRolloutMode::EnforceSelected => IdentityMode::Optional,
            CryptoRolloutMode::EnforceGlobal => IdentityMode::Required,
        }
    }

    fn required_principals(&self) -> HashSet<String> {
        if self.mode == CryptoRolloutMode::EnforceSelected {
            self.principals.clone()
        } else {
            HashSet::new()
        }
    }
}

fn normalize_principals(principals: &[String]) -> HashSet<String> {
    let mut normalized = HashSet::new();
    for principal in principals {
        let trimmed = principal.trim();
        if trimmed.is_empty() {
            continue;
        }
        normalized.insert(trimmed.to_string());
        normalized.insert(trimmed.to_ascii_lowercase());
    }
    normalized
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

fn load_budget_oisp_engine(config: &SothConfig) -> Option<Arc<OispEngine>> {
    let cache_path = resolve_registry_bundle_cache_path(config);
    match OispEngine::load_from_registry_cache(cache_path.as_path()) {
        Ok(Some(engine)) => {
            info!(
                cache = %cache_path.display(),
                bundle_version = %engine.bundle_version(),
                "Loaded OISP bundle for wrap budget pricing"
            );
            Some(Arc::new(engine))
        }
        Ok(None) => {
            warn!(
                cache = %cache_path.display(),
                "Wrap budget pricing bundle unavailable; budget cost metadata disabled"
            );
            None
        }
        Err(error) => {
            warn!(
                cache = %cache_path.display(),
                error = %error,
                "Failed loading bundle for wrap budget pricing; budget cost metadata disabled"
            );
            None
        }
    }
}

pub fn build_proxy_enforcer(config: &SothConfig) -> anyhow::Result<ProxyEnforcer> {
    let rollout = CryptoIdentityRollout::from_config(config);
    let identity_mode = rollout.proxy_identity_mode();
    let required_principals = rollout.required_principals();
    match rollout.mode {
        CryptoRolloutMode::Disabled => info!("Crypto identity rollout: disabled"),
        CryptoRolloutMode::Audit => info!("Crypto identity rollout: audit"),
        CryptoRolloutMode::EnforceSelected => info!(
            "Crypto identity rollout: enforce selected principals ({})",
            required_principals.len()
        ),
        CryptoRolloutMode::EnforceGlobal => info!("Crypto identity rollout: enforce global"),
    }

    let trusted_dids = collect_trusted_dids(config)?;

    let mut enforcer = ProxyEnforcer::new()
        .with_identity_mode(identity_mode, trusted_dids)
        .with_required_principals(required_principals)
        .with_identity_headers("X-Agent-DID", "X-Agent-Signature")
        .with_fail_open(
            config.production.fail_open.enabled,
            config.production.fail_open.enforcement_timeout,
            config.production.fail_open.policy_fail_open,
            config.production.fail_open.budget_fail_open,
        );

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

    let rollout = CryptoIdentityRollout::from_config(config);
    let identity_mode = rollout.wrap_identity_mode();
    let required_principals = rollout.required_principals();
    let identity_config = IdentityConfig {
        mode: identity_mode,
        required_principals: required_principals.clone(),
        ..IdentityConfig::default()
    };
    match rollout.mode {
        CryptoRolloutMode::Disabled => info!("Wrap crypto identity rollout: disabled"),
        CryptoRolloutMode::Audit => info!("Wrap crypto identity rollout: audit"),
        CryptoRolloutMode::EnforceSelected => info!(
            "Wrap crypto identity rollout: enforce selected principals ({})",
            required_principals.len()
        ),
        CryptoRolloutMode::EnforceGlobal => info!("Wrap crypto identity rollout: enforce global"),
    }
    if identity_mode != IdentityMode::Disabled {
        enabled = true;
        let mut trust_store = TrustStore::in_memory();
        for did in collect_trusted_dids(config)? {
            trust_store
                .trust(&did)
                .with_context(|| format!("Failed to trust DID from config: {did}"))?;
        }
        let layer = IdentityLayer::with_trust_store(identity_config.clone(), trust_store);
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
        let mut layer = BudgetLayer::with_tracker(
            BudgetConfig {
                enabled: true,
                block_on_exceeded: true,
                default_model: "gpt-4o".to_string(),
            },
            tracker,
        );
        if let Some(engine) = load_budget_oisp_engine(config) {
            layer = layer.with_oisp_engine(engine);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollout_disabled_when_crypto_identity_disabled() {
        let config = SothConfig::default();
        let rollout = CryptoIdentityRollout::from_config(&config);
        assert_eq!(rollout.mode, CryptoRolloutMode::Disabled);
        assert_eq!(rollout.proxy_identity_mode(), ProxyIdentityMode::Disabled);
        assert_eq!(rollout.wrap_identity_mode(), IdentityMode::Disabled);
    }

    #[test]
    fn rollout_audit_when_enabled_in_audit_mode() {
        let mut config = SothConfig::default();
        config.crypto_identity.enabled = true;
        config.crypto_identity.mode = "audit".to_string();

        let rollout = CryptoIdentityRollout::from_config(&config);
        assert_eq!(rollout.mode, CryptoRolloutMode::Audit);
        assert_eq!(rollout.proxy_identity_mode(), ProxyIdentityMode::Optional);
        assert_eq!(rollout.wrap_identity_mode(), IdentityMode::Optional);
        assert!(rollout.required_principals().is_empty());
    }

    #[test]
    fn rollout_enforce_selected_when_principals_present() {
        let mut config = SothConfig::default();
        config.crypto_identity.enabled = true;
        config.crypto_identity.mode = "enforce".to_string();
        config.crypto_identity.enforce_principals = vec!["Codex".to_string()];

        let rollout = CryptoIdentityRollout::from_config(&config);
        assert_eq!(rollout.mode, CryptoRolloutMode::EnforceSelected);
        assert_eq!(rollout.proxy_identity_mode(), ProxyIdentityMode::Optional);
        assert_eq!(rollout.wrap_identity_mode(), IdentityMode::Optional);
        let required = rollout.required_principals();
        assert!(required.contains("Codex"));
        assert!(required.contains("codex"));
    }

    #[test]
    fn rollout_enforce_global_when_principals_empty() {
        let mut config = SothConfig::default();
        config.crypto_identity.enabled = true;
        config.crypto_identity.mode = "enforce".to_string();
        config.crypto_identity.enforce_principals.clear();

        let rollout = CryptoIdentityRollout::from_config(&config);
        assert_eq!(rollout.mode, CryptoRolloutMode::EnforceGlobal);
        assert_eq!(rollout.proxy_identity_mode(), ProxyIdentityMode::Required);
        assert_eq!(rollout.wrap_identity_mode(), IdentityMode::Required);
    }
}
