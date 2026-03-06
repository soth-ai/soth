use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use soth_core::{
    normalize_bundle_host_pattern, AppType, BlacklistMatchType, EntityCatalog, EntityTrafficRules,
    GateConfig, GateDefaults, GatingBundle, HostRule, IdentityEntry, IdentityIndex,
    NonCatalogedAction, PathRules, ProcessAction, Stage0Config, Stage1Config, Stage2Config,
    Stage3Config, Stage4Config, Stage5Config, UnknownAppAction,
};
use soth_policy::sync_policy::{load_bundle_from_bytes, PolicyBundle, PolicyBundleMetadata};

use crate::error::BundleError;
use crate::manifest::{BundleManifest, OrgSignedConfig};
use crate::scope_check;
use crate::verify;
use crate::{BundleMeta, LoadedBundle, VerificationOptions};

pub fn load_from_dir(
    bundle_dir: &Path,
    vendor_pubkey: &[u8; 32],
    org_config: &OrgSignedConfig,
) -> Result<LoadedBundle, BundleError> {
    load_from_dir_with_options(
        bundle_dir,
        vendor_pubkey,
        org_config,
        VerificationOptions::default(),
    )
}

pub fn load_from_dir_with_options(
    bundle_dir: &Path,
    vendor_pubkey: &[u8; 32],
    org_config: &OrgSignedConfig,
    verification: VerificationOptions,
) -> Result<LoadedBundle, BundleError> {
    let manifest_path = bundle_dir.join("manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path)?;
    let manifest: BundleManifest = serde_json::from_slice(manifest_bytes.as_slice())?;

    let mut asset_bytes = HashMap::with_capacity(manifest.assets.len());
    for entry in &manifest.assets {
        let path = bundle_dir.join(entry.path.as_str());
        let bytes = std::fs::read(path)?;
        asset_bytes.insert(entry.path.clone(), bytes);
    }

    load_verified(
        manifest,
        asset_bytes,
        vendor_pubkey,
        org_config,
        verification,
    )
}

pub fn load_from_bytes(
    manifest_bytes: &[u8],
    assets: HashMap<String, Vec<u8>>,
    vendor_pubkey: &[u8; 32],
    org_config: &OrgSignedConfig,
) -> Result<LoadedBundle, BundleError> {
    load_from_bytes_with_options(
        manifest_bytes,
        assets,
        vendor_pubkey,
        org_config,
        VerificationOptions::default(),
    )
}

pub fn load_from_bytes_with_options(
    manifest_bytes: &[u8],
    assets: HashMap<String, Vec<u8>>,
    vendor_pubkey: &[u8; 32],
    org_config: &OrgSignedConfig,
    verification: VerificationOptions,
) -> Result<LoadedBundle, BundleError> {
    let manifest: BundleManifest = serde_json::from_slice(manifest_bytes)?;
    load_verified(manifest, assets, vendor_pubkey, org_config, verification)
}

pub(crate) fn load_verified(
    manifest: BundleManifest,
    assets: HashMap<String, Vec<u8>>,
    vendor_pubkey: &[u8; 32],
    org_config: &OrgSignedConfig,
    verification: VerificationOptions,
) -> Result<LoadedBundle, BundleError> {
    let trust_level =
        verify::verify_bundle_with_options(&manifest, &assets, Some(vendor_pubkey), verification)?;
    scope_check::check_scope(&manifest.scope, org_config)?;

    let policy = load_policy_bundle(&assets)?;
    let detect = load_detect_bundle(&assets)?;
    let gating = load_gating_bundle(&assets, detect.as_ref())?;
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let classify = soth_classify::load_bundle_from_bytes(manifest_bytes.as_slice(), assets)
        .map_err(|error| BundleError::ClassifyLoadFailed(error.to_string()))?;
    let issued_at = manifest
        .issued_at
        .or_else(|| u64::try_from(manifest.created_at).ok())
        .unwrap_or_else(|| Utc::now().timestamp().max(0) as u64);
    let meta = BundleMeta {
        bundle_id: manifest
            .bundle_id
            .clone()
            .unwrap_or_else(|| manifest.version.clone()),
        model_version: manifest
            .model_version
            .clone()
            .unwrap_or_else(|| classify.bundle_version.clone()),
        policy_version: manifest
            .policy_version
            .clone()
            .unwrap_or_else(|| policy.metadata.bundle_version.clone()),
        org_id: manifest
            .org_id
            .clone()
            .unwrap_or_else(|| policy.metadata.org_id.clone()),
        issued_at,
        expires_at: manifest.expires_at,
        vendor_sig: if manifest.vendor_sig.trim().is_empty() {
            None
        } else {
            Some(manifest.vendor_sig.clone())
        },
        org_approval_sig: manifest.org_approval_sig.clone(),
    };

    Ok(LoadedBundle {
        version: manifest.version.clone(),
        installed_at: Utc::now().timestamp(),
        meta,
        trust_level,
        classify,
        policy,
        detect,
        gating,
        manifest,
    })
}

fn extract_section(assets: &HashMap<String, Vec<u8>>, prefix: &str) -> HashMap<String, Vec<u8>> {
    let mut section = HashMap::new();
    for (path, bytes) in assets {
        if let Some(stripped) = path.strip_prefix(prefix) {
            section.insert(stripped.to_string(), bytes.clone());
        }
    }
    section
}

fn load_policy_bundle(assets: &HashMap<String, Vec<u8>>) -> Result<Arc<PolicyBundle>, BundleError> {
    let section = extract_section(assets, "policy/");
    let payload = if let Some(bytes) = section.get("policy_bundle.json") {
        bytes
    } else if let Some(bytes) = section.get("bundle.json") {
        bytes
    } else if let Some(bytes) = assets.get("policy_bundle.json") {
        bytes
    } else {
        return Ok(Arc::new(empty_policy_bundle()));
    };

    let loaded = load_bundle_from_bytes(payload.as_slice())
        .map_err(|error| BundleError::PolicyLoadFailed(error.to_string()))?;
    // Pre-compile policy rule set once at load/install time for request-path latency.
    soth_policy::warm(&loaded);
    Ok(Arc::new(loaded))
}

fn load_detect_bundle(
    assets: &HashMap<String, Vec<u8>>,
) -> Result<Arc<soth_detect::OwnedDetectBundle>, BundleError> {
    let section = extract_section(assets, "detect/");
    if let Some(bytes) = section.get("bundle.json") {
        let bundle: soth_detect::OwnedDetectBundle = serde_json::from_slice(bytes.as_slice())
            .map_err(|error| BundleError::DetectLoadFailed(error.to_string()))?;
        return Ok(Arc::new(bundle));
    }
    if section.is_empty() && !assets.contains_key("detect_bundle.json") {
        return Ok(Arc::new(soth_detect::OwnedDetectBundle::default()));
    }
    if let Some(bytes) = assets.get("detect_bundle.json") {
        let bundle: soth_detect::OwnedDetectBundle = serde_json::from_slice(bytes.as_slice())
            .map_err(|error| BundleError::DetectLoadFailed(error.to_string()))?;
        return Ok(Arc::new(bundle));
    }
    Ok(Arc::new(soth_detect::OwnedDetectBundle::default()))
}

fn load_gating_bundle(
    assets: &HashMap<String, Vec<u8>>,
    detect: &soth_detect::OwnedDetectBundle,
) -> Result<Arc<GatingBundle>, BundleError> {
    let section = extract_section(assets, "gating/");
    if let Some(bytes) = section.get("bundle.json") {
        let mut bundle: GatingBundle = serde_json::from_slice(bytes.as_slice())
            .map_err(|error| BundleError::DetectLoadFailed(error.to_string()))?;
        bundle.normalize_host_patterns_in_place();
        return Ok(Arc::new(bundle));
    }
    if let Some(bytes) = assets.get("gating_bundle.json") {
        let mut bundle: GatingBundle = serde_json::from_slice(bytes.as_slice())
            .map_err(|error| BundleError::DetectLoadFailed(error.to_string()))?;
        bundle.normalize_host_patterns_in_place();
        return Ok(Arc::new(bundle));
    }

    // Compatibility fallback until server emits signed gating/ section.
    Ok(Arc::new(gating_from_detect(detect)))
}

fn gating_from_detect(detect: &soth_detect::OwnedDetectBundle) -> GatingBundle {
    let mut providers_by_id = HashMap::<String, HashSet<String>>::new();
    for (host, provider_key) in &detect.domain_index {
        let provider_id = detect
            .llm_providers
            .get(provider_key)
            .and_then(|entry| entry.provider_id.clone())
            .unwrap_or_else(|| provider_key.to_string());
        if let Some(pattern) = normalize_bundle_host_pattern(host) {
            providers_by_id
                .entry(provider_id)
                .or_default()
                .insert(pattern);
        }
    }

    let providers = providers_by_id
        .into_iter()
        .map(|(entity_id, hosts)| EntityTrafficRules {
            entity_id: entity_id.clone(),
            capture_mode: detect
                .capture_rules
                .mode_for(&soth_detect::Provider::new(entity_id.as_str())),
            hosts: hosts
                .into_iter()
                .filter(|pattern| !pattern.is_empty())
                .map(|pattern| HostRule {
                    pattern,
                    methods: Vec::new(),
                    paths: PathRules::default(),
                    priority: None,
                })
                .collect(),
            api_format: None,
            entity_type: None,
            pricing: None,
            capture: None,
            detection: None,
        })
        .collect::<Vec<_>>();

    let mut hosts_index = HashMap::new();
    let mut non_hosts_index = HashMap::new();
    for (identity, policy) in &detect.app_policies {
        let app_type = match policy.app_kind {
            soth_core::AppKind::Browser => AppType::Host,
            soth_core::AppKind::AgentApp | soth_core::AppKind::Ide | soth_core::AppKind::Cli => {
                AppType::NonHost
            }
            soth_core::AppKind::Unknown => AppType::Unknown,
        };
        let entry = IdentityEntry {
            entity_id: policy.app_id.clone(),
            app_type,
            capture_mode: policy
                .capture_mode
                .as_deref()
                .and_then(parse_capture_mode)
                .unwrap_or(soth_core::CaptureMode::MetadataOnly),
            action: policy
                .action
                .as_deref()
                .and_then(parse_process_action)
                .unwrap_or(ProcessAction::Intercept),
            enabled: policy.enabled,
            host_filter: policy.host_filter.clone(),
            host_list_ref: policy.host_list_ref.clone(),
        };
        if app_type == AppType::Host {
            hosts_index.insert(identity.to_ascii_lowercase(), entry.clone());
        } else {
            non_hosts_index.insert(identity.to_ascii_lowercase(), entry.clone());
        }
    }
    for identity in &detect.browser_policies.allowed_apps {
        hosts_index
            .entry(identity.to_ascii_lowercase())
            .or_insert(IdentityEntry {
                entity_id: identity.clone(),
                app_type: AppType::Host,
                capture_mode: soth_core::CaptureMode::MetadataOnly,
                action: ProcessAction::Intercept,
                enabled: None,
                host_filter: None,
                host_list_ref: None,
            });
    }

    let tls_intercept_hosts = detect
        .domain_index
        .keys()
        .filter_map(|host| normalize_bundle_host_pattern(host))
        .collect::<HashSet<_>>();
    let passthrough_domains = detect
        .passthrough_domains
        .iter()
        .filter_map(|host| normalize_bundle_host_pattern(host))
        .collect::<HashSet<_>>();

    let allowed_host_origins = detect
        .domain_index
        .keys()
        .filter_map(|host| normalize_bundle_host_pattern(host))
        .collect::<HashSet<_>>();

    let mut bundle = GatingBundle {
        identity_index: IdentityIndex {
            hosts: hosts_index,
            non_hosts: non_hosts_index,
        },
        gates: GateConfig {
            order: vec![
                soth_core::GateStage::Stage0Tls,
                soth_core::GateStage::Stage1AppOrigin,
                soth_core::GateStage::Stage2Whitelist,
                soth_core::GateStage::Stage3Blacklist,
                soth_core::GateStage::Stage4AppType,
                soth_core::GateStage::Stage5HostOrigin,
                soth_core::GateStage::Intercept,
            ],
            defaults: GateDefaults {
                sensor_enabled: true,
                fail_open_on_config_error: true,
                unknown_app_action: UnknownAppAction::Skip,
                non_cataloged_host_action: NonCatalogedAction::Skip,
                discovery: soth_core::DiscoveryConfig::default(),
                source_unknown_app_action: None,
                source_whitelisted_unknown_app_action: None,
                source_non_whitelisted_host_action: None,
                source_browser_default_action: None,
            },
            stage0_tls: Stage0Config {
                tls_intercept_hosts,
                passthrough_domains,
                enable_discovery: false,
            },
            stage1_app_origin: Stage1Config {
                skip_if_unresolved_process: true,
            },
            stage2_whitelist: Stage2Config {
                allow_empty_means_allow_all_except_denied: true,
            },
            stage3_blacklist: Stage3Config {
                blacklisted_keywords: detect.filters.path_keywords.clone(),
                blacklisted_path_substrings: detect.filters.path_keywords.clone(),
                blacklisted_host_substrings: Vec::new(),
                graphql_operation_blacklist: Vec::new(),
                graphql_operation_blacklist_enabled: false,
                match_type: BlacklistMatchType::CaseInsensitiveSubstring,
            },
            stage4_app_type: Stage4Config {
                derive_from_identity_index: true,
            },
            stage5_host_origin: Stage5Config {
                allowed_host_origins,
                skip_for_discovery_capture: true,
            },
        },
        entities: EntityCatalog {
            providers,
            web_apps: Vec::new(),
            native_apps: Vec::new(),
        },
    };
    bundle.normalize_host_patterns_in_place();
    bundle
}

fn parse_capture_mode(raw: &str) -> Option<soth_core::CaptureMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "full" => Some(soth_core::CaptureMode::Full),
        "sensitive_artifacts" => Some(soth_core::CaptureMode::SensitiveArtifacts),
        "full_content" => Some(soth_core::CaptureMode::FullContent),
        "metadata_only" => Some(soth_core::CaptureMode::MetadataOnly),
        _ => None,
    }
}

fn parse_process_action(raw: &str) -> Option<ProcessAction> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "intercept" => Some(ProcessAction::Intercept),
        "skip" | "passthrough" => Some(ProcessAction::Skip),
        "block" => Some(ProcessAction::Block),
        _ => None,
    }
}

fn empty_policy_bundle() -> PolicyBundle {
    use soth_policy::sync_policy::{BudgetLimits, CompiledRuleSet, OrgPatterns};
    PolicyBundle {
        metadata: PolicyBundleMetadata {
            bundle_version: "fallback-0.0.0".to_string(),
            schema_version: "1".to_string(),
            org_id: "unknown".to_string(),
            signed_at: 0,
        },
        system_rules: Arc::new(CompiledRuleSet::default()),
        org_rules: Arc::new(CompiledRuleSet::default()),
        org_patterns: Arc::new(OrgPatterns::default()),
        budget_limits: BudgetLimits::default(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use soth_policy::sync_policy::{
        BudgetLimits, OrgPatterns, PolicyBundleMetadata, PolicyBundlePayload, RuleAction,
        RuleDefinition, SignedPolicyBundle,
    };

    use super::*;
    use crate::manifest::{canonical_manifest_bytes, AssetEntry, BundleScope};
    use crate::verify::sha256_hex;

    fn signed_policy_bundle_bytes() -> Vec<u8> {
        let payload = PolicyBundlePayload {
            metadata: PolicyBundleMetadata {
                bundle_version: "policy-v1".to_string(),
                schema_version: "1".to_string(),
                org_id: "demo-org".to_string(),
                signed_at: 1_772_000_001,
            },
            system_rules: vec![RuleDefinition {
                rule_id: "sys-allow".to_string(),
                rule_name: "allow".to_string(),
                cel_expr: "false".to_string(),
                action: RuleAction::Flag {
                    reason: "flag".to_string(),
                },
            }],
            org_rules: Vec::new(),
            org_patterns: OrgPatterns::default(),
            budget_limits: BudgetLimits::default(),
        };
        let key = SigningKey::from_bytes(&[13u8; 32]);
        let payload_bytes = serde_json::to_vec(&payload).expect("serialize payload");
        let signature = key.sign(payload_bytes.as_slice());
        let envelope = SignedPolicyBundle {
            payload,
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            public_key: base64::engine::general_purpose::STANDARD
                .encode(key.verifying_key().to_bytes()),
        };
        serde_json::to_vec(&envelope).expect("serialize envelope")
    }

    fn signed_manifest_bytes(
        assets: &HashMap<String, Vec<u8>>,
        scope: BundleScope,
        vendor: &SigningKey,
    ) -> Vec<u8> {
        let mut entries: Vec<AssetEntry> = assets
            .iter()
            .map(|(path, bytes)| AssetEntry {
                path: path.clone(),
                sha256: sha256_hex(bytes.as_slice()),
                size_bytes: bytes.len() as u64,
            })
            .collect();
        entries.sort_by(|left, right| left.path.cmp(&right.path));

        let mut manifest = BundleManifest {
            version: "bundle-v1".to_string(),
            created_at: 1_772_000_100,
            bundle_id: None,
            model_version: None,
            policy_version: None,
            org_id: None,
            issued_at: None,
            expires_at: None,
            vendor_sig: String::new(),
            org_approval_sig: None,
            assets: entries,
            scope,
        };
        let canonical = canonical_manifest_bytes(&manifest).expect("canonical");
        manifest.vendor_sig = hex::encode(vendor.sign(canonical.as_slice()).to_bytes());
        serde_json::to_vec(&manifest).expect("serialize manifest")
    }

    #[test]
    fn load_from_bytes_success() {
        let vendor = SigningKey::from_bytes(&[31u8; 32]);
        let policy_bytes = signed_policy_bundle_bytes();
        let detect_bytes =
            serde_json::to_vec(&soth_detect::OwnedDetectBundle::default()).expect("detect json");

        let assets = HashMap::from([
            ("policy/policy_bundle.json".to_string(), policy_bytes),
            ("detect/bundle.json".to_string(), detect_bytes),
            (
                "classify/embedding.onnx".to_string(),
                b"stub-model".to_vec(),
            ),
        ]);
        let manifest_bytes = signed_manifest_bytes(&assets, BundleScope::default(), &vendor);
        let org = OrgSignedConfig {
            allows_https_intercept: false,
            allows_http_intercept: false,
            process_filter: None,
            allowed_capture_modes: Vec::new(),
        };
        let loaded = load_from_bytes(
            manifest_bytes.as_slice(),
            assets,
            &vendor.verifying_key().to_bytes(),
            &org,
        )
        .expect("bundle should load");

        assert_eq!(loaded.version, "bundle-v1");
        assert_eq!(loaded.policy.metadata.bundle_version, "policy-v1");
        assert_eq!(loaded.detect.rest_formats.len(), 0);
    }

    #[test]
    fn rejects_scope_expansion() {
        let vendor = SigningKey::from_bytes(&[32u8; 32]);
        let assets = HashMap::from([(
            "policy/policy_bundle.json".to_string(),
            signed_policy_bundle_bytes(),
        )]);
        let scope = BundleScope {
            intercept_https: true,
            intercept_http: false,
            process_filter: None,
            capture_modes: Vec::new(),
        };
        let manifest_bytes = signed_manifest_bytes(&assets, scope, &vendor);
        let org = OrgSignedConfig {
            allows_https_intercept: false,
            allows_http_intercept: false,
            process_filter: None,
            allowed_capture_modes: Vec::new(),
        };
        let err = match load_from_bytes(
            manifest_bytes.as_slice(),
            assets,
            &vendor.verifying_key().to_bytes(),
            &org,
        ) {
            Ok(_) => panic!("scope expansion should fail"),
            Err(err) => err,
        };
        assert!(matches!(err, BundleError::ScopeExpansionRefused { .. }));
    }

    #[test]
    fn detect_fallback_normalizes_passthrough_patterns() {
        let mut detect = soth_detect::OwnedDetectBundle::default();
        detect
            .passthrough_domains
            .push("^.*\\.manus\\.computer$".to_string());
        detect
            .passthrough_domains
            .push("api.apple-cloudkit.com:".to_string());

        let bundle = gating_from_detect(&detect);
        let passthrough = &bundle.gates.stage0_tls.passthrough_domains;
        assert!(passthrough.contains("*.manus.computer"));
        assert!(passthrough.contains("api.apple-cloudkit.com"));
    }

    #[test]
    fn detect_fallback_uses_app_policy_action_and_capture_fields() {
        let mut detect = soth_detect::OwnedDetectBundle::default();
        detect.app_policies.insert(
            "cursor".to_string(),
            soth_detect::AppPolicy {
                app_id: "cursor".to_string(),
                display_name: Some("Cursor".to_string()),
                app_kind: soth_core::AppKind::Ide,
                action: Some("block".to_string()),
                capture_mode: Some("full".to_string()),
                enabled: Some(true),
                host_filter: Some("api.openai.com".to_string()),
                host_list_ref: Some("ai_catalog".to_string()),
            },
        );

        let bundle = gating_from_detect(&detect);
        let entry = bundle
            .identity_index
            .non_hosts
            .get("cursor")
            .expect("cursor identity should exist");

        assert_eq!(entry.action, ProcessAction::Block);
        assert_eq!(entry.capture_mode, soth_core::CaptureMode::Full);
        assert_eq!(entry.enabled, Some(true));
        assert_eq!(entry.host_filter.as_deref(), Some("api.openai.com"));
        assert_eq!(entry.host_list_ref.as_deref(), Some("ai_catalog"));
    }

    #[test]
    fn load_from_bytes_normalizes_identity_index_keys_in_gating_bundle() {
        let vendor = SigningKey::from_bytes(&[33u8; 32]);
        let mut gating = GatingBundle::default();
        gating.identity_index.hosts.insert(
            "com.google.Chrome".to_string(),
            IdentityEntry {
                entity_id: "chrome".to_string(),
                app_type: AppType::Host,
                capture_mode: soth_core::CaptureMode::MetadataOnly,
                action: ProcessAction::Intercept,
                enabled: None,
                host_filter: None,
                host_list_ref: None,
            },
        );
        gating.identity_index.non_hosts.insert(
            " Cursor ".to_string(),
            IdentityEntry {
                entity_id: "cursor".to_string(),
                app_type: AppType::NonHost,
                capture_mode: soth_core::CaptureMode::MetadataOnly,
                action: ProcessAction::Intercept,
                enabled: None,
                host_filter: None,
                host_list_ref: None,
            },
        );
        let gating_bytes = serde_json::to_vec(&gating).expect("gating json");

        let assets = HashMap::from([
            (
                "policy/policy_bundle.json".to_string(),
                signed_policy_bundle_bytes(),
            ),
            ("gating/bundle.json".to_string(), gating_bytes),
            (
                "classify/embedding.onnx".to_string(),
                b"stub-model".to_vec(),
            ),
        ]);
        let manifest_bytes = signed_manifest_bytes(&assets, BundleScope::default(), &vendor);
        let org = OrgSignedConfig {
            allows_https_intercept: false,
            allows_http_intercept: false,
            process_filter: None,
            allowed_capture_modes: Vec::new(),
        };

        let loaded = load_from_bytes(
            manifest_bytes.as_slice(),
            assets,
            &vendor.verifying_key().to_bytes(),
            &org,
        )
        .expect("bundle should load");

        assert!(loaded
            .gating
            .identity_index
            .hosts
            .contains_key("com.google.chrome"));
        assert!(!loaded
            .gating
            .identity_index
            .hosts
            .contains_key("com.google.Chrome"));
        assert!(loaded
            .gating
            .identity_index
            .non_hosts
            .contains_key("cursor"));
        assert!(!loaded
            .gating
            .identity_index
            .non_hosts
            .contains_key(" Cursor "));
    }
}
