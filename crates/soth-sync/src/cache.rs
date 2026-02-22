use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use soth_core::api::{ConfigResponse, RegistryBundleManifest, RegistryVersionResponse};
use soth_oisp::types::bundle::parse_compiled_bundle;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedConfigEnvelope {
    pub fetched_at: String,
    pub config: ConfigResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedRegistryBundleEnvelope {
    #[serde(default = "registry_cache_schema_version")]
    pub schema_version: u32,
    pub fetched_at: String,
    pub etag: String,
    pub metadata: RegistryVersionResponse,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<RegistryBundleManifest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_failed_reason: Option<String>,
    pub bundle: Value,
}

#[derive(Debug, Clone, Default)]
pub struct RegistryBundleRuntimeStatus {
    pub cache_present: bool,
    pub bundle_hash: Option<String>,
    pub bundle_version: Option<String>,
    pub fetched_at: Option<String>,
    pub bundle_age_seconds: Option<u64>,
    pub stale: bool,
    pub validation_status: Option<String>,
    pub validation_failed_reason: Option<String>,
    pub cache_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegistryCacheValidationStatusEnvelope {
    #[serde(default = "registry_cache_schema_version")]
    schema_version: u32,
    updated_at: String,
    validation_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    validation_failed_reason: Option<String>,
}

pub fn registry_cache_schema_version() -> u32 {
    1
}

pub fn default_cache_path() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".soth").join("cloud_config_cache.json")
    } else {
        PathBuf::from(".soth/cloud_config_cache.json")
    }
}

pub fn default_registry_cache_path() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".soth").join("registry_bundle_cache.json")
    } else {
        PathBuf::from(".soth/registry_bundle_cache.json")
    }
}

pub fn registry_bundle_runtime_status(
    path: &Path,
    stale_after: std::time::Duration,
) -> RegistryBundleRuntimeStatus {
    let sidecar = load_registry_cache_validation_status(path)
        .ok()
        .and_then(|value| value);
    match load_registry_bundle_cache(path) {
        Ok(Some(cache)) => {
            let bundle_age_seconds = parse_bundle_age_seconds(cache.fetched_at.as_str());
            let stale = bundle_age_seconds
                .map(|age| age > stale_after.as_secs())
                .unwrap_or(false);
            RegistryBundleRuntimeStatus {
                cache_present: true,
                bundle_hash: cache.bundle_hash.clone(),
                bundle_version: Some(cache.metadata.version.clone()),
                fetched_at: Some(cache.fetched_at),
                bundle_age_seconds,
                stale,
                validation_status: sidecar
                    .as_ref()
                    .map(|state| state.validation_status.clone())
                    .or(cache.validation_status.clone()),
                validation_failed_reason: sidecar
                    .as_ref()
                    .and_then(|state| state.validation_failed_reason.clone())
                    .or(cache.validation_failed_reason.clone()),
                cache_error: None,
            }
        }
        Ok(None) => {
            let mut status = RegistryBundleRuntimeStatus {
                cache_present: false,
                ..RegistryBundleRuntimeStatus::default()
            };
            if let Some(sidecar) = sidecar {
                status.validation_status = Some(sidecar.validation_status);
                status.validation_failed_reason = sidecar.validation_failed_reason;
                if status.validation_status.as_deref() == Some("failed") {
                    status.stale = true;
                }
            }
            status
        }
        Err(error) => {
            let mut status = RegistryBundleRuntimeStatus {
                cache_present: false,
                stale: true,
                cache_error: Some(error.to_string()),
                ..RegistryBundleRuntimeStatus::default()
            };
            if let Some(sidecar) = sidecar {
                status.validation_status = Some(sidecar.validation_status);
                status.validation_failed_reason = sidecar.validation_failed_reason;
            }
            status
        }
    }
}

pub fn load_config_cache(path: &Path) -> anyhow::Result<Option<ConfigResponse>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading cloud cache {}", path.display()))?;
    let envelope: CachedConfigEnvelope = serde_json::from_str(&content)
        .with_context(|| format!("failed parsing cloud cache {}", path.display()))?;
    Ok(Some(envelope.config))
}

pub fn save_config_cache(path: &Path, config: &ConfigResponse) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating cloud cache parent directory {}",
                parent.display()
            )
        })?;
    }
    let envelope = CachedConfigEnvelope {
        fetched_at: Utc::now().to_rfc3339(),
        config: config.clone(),
    };
    let payload = serde_json::to_string_pretty(&envelope)
        .context("failed serializing cached cloud config")?;
    std::fs::write(path, payload)
        .with_context(|| format!("failed writing cloud cache {}", path.display()))?;
    Ok(())
}

pub fn load_registry_bundle_cache(
    path: &Path,
) -> anyhow::Result<Option<CachedRegistryBundleEnvelope>> {
    match load_registry_bundle_cache_at(path) {
        Ok(Some(envelope)) => Ok(Some(envelope)),
        Ok(None) => load_registry_bundle_cache_at(&registry_cache_last_good_path(path)),
        Err(primary_error) => {
            let fallback_path = registry_cache_last_good_path(path);
            if !fallback_path.exists() {
                return Err(primary_error);
            }
            match load_registry_bundle_cache_at(&fallback_path) {
                Ok(Some(envelope)) => Ok(Some(envelope)),
                Ok(None) => Err(primary_error),
                Err(fallback_error) => Err(anyhow::anyhow!(
                    "primary registry cache invalid ({primary_error}); last-known-good cache invalid ({fallback_error})"
                )),
            }
        }
    }
}

pub fn save_registry_bundle_cache(
    path: &Path,
    metadata: &RegistryVersionResponse,
    etag: &str,
    bundle_bytes: &[u8],
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating registry cache parent directory {}",
                parent.display()
            )
        })?;
    }

    let raw_bundle: Value = serde_json::from_slice(bundle_bytes)
        .context("failed parsing registry bundle payload as JSON")?;
    let bundle = normalize_registry_bundle_payload(raw_bundle);
    validate_registry_bundle_payload(&bundle)
        .context("registry bundle payload failed schema validation")?;
    let bundle_hash = derive_bundle_hash(metadata, etag, bundle_bytes)
        .or_else(|| derive_bundle_hash_from_json(&bundle));
    let manifest = metadata.manifest.clone().or_else(|| {
        Some(RegistryBundleManifest {
            bundle_hash: bundle_hash.clone(),
            bundle_version: Some(metadata.version.clone()),
            published_at: Some(metadata.compiled_at.clone()),
            diff_from: None,
            components: Vec::new(),
            changed_sections: std::collections::HashMap::new(),
            integrity: None,
        })
    });
    let envelope = CachedRegistryBundleEnvelope {
        schema_version: registry_cache_schema_version(),
        fetched_at: Utc::now().to_rfc3339(),
        etag: etag.to_string(),
        metadata: metadata.clone(),
        bundle_hash,
        manifest,
        validation_status: Some("ok".to_string()),
        validation_failed_reason: None,
        bundle,
    };

    let payload = serde_json::to_string_pretty(&envelope)
        .context("failed serializing cached registry bundle")?;
    write_atomic(path, payload.as_bytes())
        .with_context(|| format!("failed writing registry cache {}", path.display()))?;
    let last_good_path = registry_cache_last_good_path(path);
    let payload_last_good = serde_json::to_string_pretty(&envelope)
        .context("failed serializing last-known-good registry bundle")?;
    write_atomic(&last_good_path, payload_last_good.as_bytes()).with_context(|| {
        format!(
            "failed writing last-known-good registry cache {}",
            last_good_path.display()
        )
    })?;
    let _ = mark_registry_validation_success(path);
    Ok(())
}

pub fn mark_registry_validation_success(path: &Path) -> anyhow::Result<()> {
    write_registry_cache_validation_status(path, "ok", None)
}

pub fn mark_registry_validation_failed(path: &Path, reason: &str) -> anyhow::Result<()> {
    let reason = reason.trim();
    let normalized_reason = if reason.is_empty() {
        "unknown".to_string()
    } else {
        reason.to_string()
    };
    write_registry_cache_validation_status(path, "failed", Some(normalized_reason.as_str()))
}

fn validate_registry_bundle_payload(bundle: &Value) -> anyhow::Result<()> {
    validate_registry_bundle_contract(bundle)
        .context("bundle payload failed contract validation")?;
    if is_edge_bundle_shape(bundle) {
        return Ok(());
    }
    parse_compiled_bundle(bundle)
        .context("bundle payload must match supported OISP bundle schema")?;
    Ok(())
}

fn validate_registry_bundle_contract(bundle: &Value) -> anyhow::Result<()> {
    let object = bundle
        .as_object()
        .context("bundle payload root must be a JSON object")?;

    let schema_version = object
        .get("schema_version")
        .and_then(Value::as_u64)
        .context("bundle payload missing required `schema_version`")?;
    if schema_version == 0 {
        anyhow::bail!("bundle payload `schema_version` must be greater than 0");
    }

    if is_edge_bundle_shape_object(object) {
        return validate_edge_bundle_contract_object(object);
    }

    if let Some(filters) = object.get("filters").and_then(Value::as_object) {
        for key in ["whitelist", "blacklist", "passthrough", "noise_keywords"] {
            let value = filters
                .get(key)
                .with_context(|| format!("bundle payload filters missing required `{key}`"))?;
            if !value.is_array() {
                anyhow::bail!("bundle payload filters.{key} must be an array");
            }
        }
        return Ok(());
    }

    let alias_sets = [
        (
            "whitelistedDomains",
            lookup_registry_filter_alias(object, "whitelistedDomains"),
        ),
        (
            "passthroughDomains",
            lookup_registry_filter_alias(object, "passthroughDomains"),
        ),
        (
            "blacklistedWords",
            lookup_registry_filter_alias(object, "blacklistedWords"),
        ),
    ];
    if alias_sets.iter().all(|(_, value)| value.is_none()) {
        anyhow::bail!(
            "bundle payload missing required `filters` object (or sensor-config aliases)"
        );
    }
    for (key, value) in alias_sets {
        if let Some(value) = value {
            if !value.is_array() {
                anyhow::bail!("bundle payload `{key}` must be an array");
            }
        }
    }

    Ok(())
}

fn is_edge_bundle_shape(bundle: &Value) -> bool {
    bundle.as_object().is_some_and(is_edge_bundle_shape_object)
}

fn is_edge_bundle_shape_object(object: &serde_json::Map<String, Value>) -> bool {
    let has_metadata_bundle_version = object
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("bundle_version"))
        .and_then(Value::as_str)
        .is_some();
    let has_edge_targets =
        object.get("llm_providers").is_some() || object.get("applications").is_some();
    has_metadata_bundle_version && has_edge_targets
}

fn validate_edge_bundle_contract_object(
    object: &serde_json::Map<String, Value>,
) -> anyhow::Result<()> {
    let metadata = object
        .get("metadata")
        .and_then(Value::as_object)
        .context("edge bundle payload missing required `metadata` object")?;
    let bundle_version = metadata
        .get("bundle_version")
        .and_then(Value::as_str)
        .context("edge bundle payload missing required `metadata.bundle_version`")?;
    if bundle_version.trim().is_empty() {
        anyhow::bail!("edge bundle payload `metadata.bundle_version` must not be empty");
    }

    for key in [
        "llm_providers",
        "applications",
        "catalogs",
        "interception",
        "detection_index",
        "formats",
    ] {
        let value = object
            .get(key)
            .with_context(|| format!("edge bundle payload missing required `{key}` object"))?;
        if !value.is_object() {
            anyhow::bail!("edge bundle payload `{key}` must be a JSON object");
        }
    }

    if let Some(ai_catalog) = object
        .get("catalogs")
        .and_then(Value::as_object)
        .and_then(|catalogs| catalogs.get("ai_catalog"))
    {
        if !ai_catalog.is_array() {
            anyhow::bail!("edge bundle payload `catalogs.ai_catalog` must be an array");
        }
    }

    let filters = object
        .get("filters")
        .and_then(Value::as_object)
        .context("edge bundle payload missing required `filters` object")?;
    for key in ["domain_patterns", "path_patterns", "keywords"] {
        let value = filters
            .get(key)
            .with_context(|| format!("edge bundle payload filters missing required `{key}`"))?;
        if !value.is_array() {
            anyhow::bail!("edge bundle payload filters.{key} must be an array");
        }
    }

    Ok(())
}

fn lookup_registry_filter_alias<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Option<&'a Value> {
    object.get(key).or_else(|| {
        object
            .get("data")
            .and_then(Value::as_object)
            .and_then(|data| data.get(key))
    })
}

fn normalize_registry_bundle_payload(bundle: Value) -> Value {
    let Some(object) = bundle.as_object() else {
        return bundle;
    };

    if let Some(inner) = object.get("bundle").cloned() {
        return inner;
    }
    if let Some(inner) = object.get("compiled_bundle").cloned() {
        return inner;
    }
    if let Some(data) = object.get("data") {
        if let Some(inner) = data
            .as_object()
            .and_then(|value| value.get("bundle"))
            .cloned()
        {
            return inner;
        }
        if let Some(inner) = data
            .as_object()
            .and_then(|value| value.get("compiled_bundle"))
            .cloned()
        {
            return inner;
        }
    }

    bundle
}

fn registry_cache_last_good_path(path: &Path) -> PathBuf {
    let filename = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "registry_bundle_cache.json".to_string());
    let fallback_filename = format!("{filename}.last_good");
    match path.parent() {
        Some(parent) => parent.join(fallback_filename),
        None => PathBuf::from(fallback_filename),
    }
}

fn registry_cache_validation_status_path(path: &Path) -> PathBuf {
    let filename = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "registry_bundle_cache.json".to_string());
    let status_filename = format!("{filename}.status");
    match path.parent() {
        Some(parent) => parent.join(status_filename),
        None => PathBuf::from(status_filename),
    }
}

fn load_registry_bundle_cache_at(
    path: &Path,
) -> anyhow::Result<Option<CachedRegistryBundleEnvelope>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading registry cache {}", path.display()))?;
    let (mut envelope, legacy_raw_fallback) = match serde_json::from_str(&content) {
        Ok(envelope) => (envelope, false),
        Err(envelope_error) => (
            parse_legacy_raw_registry_cache(path, &content).map_err(|legacy_error| {
                anyhow::anyhow!(
                    "failed parsing registry cache {} (envelope: {}; raw_bundle: {})",
                    path.display(),
                    envelope_error,
                    legacy_error
                )
            })?,
            true,
        ),
    };
    if envelope.schema_version != registry_cache_schema_version() {
        anyhow::bail!(
            "unsupported registry cache schema_version {} (expected {})",
            envelope.schema_version,
            registry_cache_schema_version()
        );
    }
    envelope.bundle = normalize_registry_bundle_payload(envelope.bundle);
    if !legacy_raw_fallback {
        validate_registry_bundle_payload(&envelope.bundle)
            .context("cached registry bundle payload failed schema validation")?;
    }
    if envelope.bundle_hash.is_none() {
        envelope.bundle_hash = derive_bundle_hash(
            &envelope.metadata,
            envelope.etag.as_str(),
            &serde_json::to_vec(&envelope.bundle).context("failed serializing bundle payload")?,
        )
        .or_else(|| derive_bundle_hash_from_json(&envelope.bundle));
    }
    if envelope.manifest.is_none() {
        envelope.manifest = Some(RegistryBundleManifest {
            bundle_hash: envelope.bundle_hash.clone(),
            bundle_version: Some(envelope.metadata.version.clone()),
            published_at: Some(envelope.metadata.compiled_at.clone()),
            diff_from: None,
            components: Vec::new(),
            changed_sections: std::collections::HashMap::new(),
            integrity: None,
        });
    }
    if envelope.validation_status.is_none() {
        envelope.validation_status = Some("ok".to_string());
    }
    Ok(Some(envelope))
}

fn parse_legacy_raw_registry_cache(
    path: &Path,
    content: &str,
) -> anyhow::Result<CachedRegistryBundleEnvelope> {
    let raw_bundle: Value = serde_json::from_str(content)
        .with_context(|| format!("failed parsing legacy registry cache {}", path.display()))?;
    let bundle = normalize_registry_bundle_payload(raw_bundle);
    let bundle_object = bundle
        .as_object()
        .context("legacy raw registry cache must be a JSON object")?;

    let bundle_hash = derive_bundle_hash_from_json(&bundle);
    let sha256 = bundle_hash.clone().unwrap_or_else(|| {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    });

    let version = bundle_object
        .get("version")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            bundle_object
                .get("metadata")
                .and_then(Value::as_object)
                .and_then(|meta| meta.get("bundle_version"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "legacy-raw-cache".to_string());

    let compiled_at = bundle_object
        .get("compiled_at")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            bundle_object
                .get("metadata")
                .and_then(Value::as_object)
                .and_then(|meta| meta.get("compiled_at"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| Utc::now().to_rfc3339());

    let provider_count = bundle_object
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|meta| meta.get("stats"))
        .and_then(Value::as_object)
        .and_then(|stats| stats.get("provider_count"))
        .and_then(Value::as_u64)
        .or_else(|| {
            bundle_object
                .get("providers")
                .and_then(Value::as_object)
                .map(|providers| providers.len() as u64)
        })
        .or_else(|| {
            let llm_count = bundle_object
                .get("llm_providers")
                .and_then(Value::as_object)
                .map(|providers| providers.len() as u64)
                .unwrap_or(0);
            let app_count = bundle_object
                .get("applications")
                .and_then(Value::as_object)
                .map(|apps| apps.len() as u64)
                .unwrap_or(0);
            if llm_count == 0 && app_count == 0 {
                None
            } else {
                Some(llm_count + app_count)
            }
        })
        .unwrap_or(0);

    let domain_count = bundle_object
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|meta| meta.get("stats"))
        .and_then(Value::as_object)
        .and_then(|stats| stats.get("domain_count"))
        .and_then(Value::as_u64)
        .or_else(|| {
            bundle_object
                .get("domain_index")
                .and_then(Value::as_array)
                .map(|domains| domains.len() as u64)
        })
        .unwrap_or(0);

    let format_count = bundle_object
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|meta| meta.get("stats"))
        .and_then(Value::as_object)
        .and_then(|stats| stats.get("format_count"))
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let bundle_type = bundle_object
        .get("bundle_type")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "edge".to_string());

    let manifest = Some(RegistryBundleManifest {
        bundle_hash: bundle_hash.clone(),
        bundle_version: Some(version.clone()),
        published_at: Some(compiled_at.clone()),
        diff_from: None,
        components: Vec::new(),
        changed_sections: std::collections::HashMap::new(),
        integrity: None,
    });

    Ok(CachedRegistryBundleEnvelope {
        schema_version: registry_cache_schema_version(),
        fetched_at: Utc::now().to_rfc3339(),
        etag: bundle_hash.clone().unwrap_or_else(|| sha256.clone()),
        metadata: RegistryVersionResponse {
            bundle_type,
            version,
            sha256,
            bundle_hash: bundle_hash.clone(),
            compiled_at,
            provider_count,
            domain_count,
            format_count,
            size_bytes: content.as_bytes().len() as u64,
            manifest: manifest.clone(),
            channel: None,
        },
        bundle_hash,
        manifest,
        validation_status: Some("ok".to_string()),
        validation_failed_reason: None,
        bundle,
    })
}

fn load_registry_cache_validation_status(
    path: &Path,
) -> anyhow::Result<Option<RegistryCacheValidationStatusEnvelope>> {
    let status_path = registry_cache_validation_status_path(path);
    if !status_path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&status_path).with_context(|| {
        format!(
            "failed reading registry cache validation status {}",
            status_path.display()
        )
    })?;
    let mut status: RegistryCacheValidationStatusEnvelope = serde_json::from_str(&content)
        .with_context(|| {
            format!(
                "failed parsing registry cache validation status {}",
                status_path.display()
            )
        })?;
    if status.schema_version != registry_cache_schema_version() {
        anyhow::bail!(
            "unsupported registry validation status schema_version {} (expected {})",
            status.schema_version,
            registry_cache_schema_version()
        );
    }
    status.validation_status = status.validation_status.trim().to_ascii_lowercase();
    if status.validation_status.is_empty() {
        status.validation_status = "ok".to_string();
    }
    if status.validation_status != "failed" {
        status.validation_failed_reason = None;
    }
    Ok(Some(status))
}

fn write_registry_cache_validation_status(
    path: &Path,
    validation_status: &str,
    validation_failed_reason: Option<&str>,
) -> anyhow::Result<()> {
    let status_path = registry_cache_validation_status_path(path);
    let status = RegistryCacheValidationStatusEnvelope {
        schema_version: registry_cache_schema_version(),
        updated_at: Utc::now().to_rfc3339(),
        validation_status: validation_status.trim().to_ascii_lowercase(),
        validation_failed_reason: validation_failed_reason.and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }),
    };
    let payload = serde_json::to_string_pretty(&status)
        .context("failed serializing registry cache validation status")?;
    write_atomic(&status_path, payload.as_bytes()).with_context(|| {
        format!(
            "failed writing registry cache validation status {}",
            status_path.display()
        )
    })
}

fn write_atomic(path: &Path, payload: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating registry cache parent directory {}",
                parent.display()
            )
        })?;
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let tmp_path = path.with_extension(format!("{}.{}.tmp", std::process::id(), nonce));

    {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)
            .with_context(|| format!("failed opening temp cache file {}", tmp_path.display()))?;
        file.write_all(payload)
            .with_context(|| format!("failed writing temp cache file {}", tmp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed syncing temp cache file {}", tmp_path.display()))?;
    }

    std::fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "failed promoting temp cache file {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;

    Ok(())
}

fn derive_bundle_hash(
    metadata: &RegistryVersionResponse,
    etag: &str,
    bundle_bytes: &[u8],
) -> Option<String> {
    normalize_hash(metadata.bundle_hash.as_deref())
        .or_else(|| normalize_hash(Some(metadata.sha256.as_str())))
        .or_else(|| normalize_hash(Some(etag)))
        .or_else(|| {
            let digest = format!("{:x}", Sha256::digest(bundle_bytes));
            normalize_hash(Some(digest.as_str()))
        })
}

fn derive_bundle_hash_from_json(bundle: &Value) -> Option<String> {
    let bytes = serde_json::to_vec(bundle).ok()?;
    let digest = format!("{:x}", Sha256::digest(bytes));
    normalize_hash(Some(digest.as_str()))
}

fn normalize_hash(value: Option<&str>) -> Option<String> {
    let raw = value?.trim().trim_matches('"');
    let raw = raw
        .strip_prefix("W/")
        .or_else(|| raw.strip_prefix("w/"))
        .unwrap_or(raw)
        .trim();
    let normalized = raw.to_ascii_lowercase();
    if normalized.len() == 64 && normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        Some(normalized)
    } else {
        None
    }
}

fn parse_bundle_age_seconds(fetched_at: &str) -> Option<u64> {
    let fetched_at = fetched_at.trim();
    if fetched_at.is_empty() {
        return None;
    }
    let parsed = DateTime::parse_from_rfc3339(fetched_at).ok()?;
    let parsed_utc = parsed.with_timezone(&Utc);
    let delta = Utc::now().signed_duration_since(parsed_utc);
    if delta.num_seconds() < 0 {
        Some(0)
    } else {
        Some(delta.num_seconds() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_registry_metadata(version: &str) -> RegistryVersionResponse {
        RegistryVersionResponse {
            bundle_type: "local".to_string(),
            version: version.to_string(),
            sha256: "abc123".to_string(),
            bundle_hash: None,
            compiled_at: "2026-02-13T00:00:00Z".to_string(),
            provider_count: 1,
            domain_count: 3,
            format_count: 1,
            size_bytes: 128,
            manifest: None,
            channel: None,
        }
    }

    #[test]
    fn save_registry_bundle_cache_accepts_compiled_bundle_shape() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache.json");
        let metadata = sample_registry_metadata("v1");
        let bundle = serde_json::json!({
            "schema_version": 2,
            "version": "v1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "cloud",
            "providers": {
                "openai": {
                    "id": "openai",
                    "name": "OpenAI",
                    "type": "ai-inference",
                    "domains": ["api.openai.com"]
                }
            },
            "domain_index": [],
            "filters": {
                "whitelist": [],
                "blacklist": [],
                "passthrough": [],
                "noise_keywords": []
            },
            "pricing": {}
        });

        save_registry_bundle_cache(&path, &metadata, "etag-1", bundle.to_string().as_bytes())
            .unwrap();

        let loaded = load_registry_bundle_cache(&path).unwrap().unwrap();
        assert_eq!(loaded.schema_version, registry_cache_schema_version());
        assert_eq!(loaded.metadata.version, "v1");
    }

    #[test]
    fn save_registry_bundle_cache_accepts_catalog_shape() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache.json");
        let metadata = sample_registry_metadata("catalog-v1");
        let bundle = serde_json::json!({
            "schema_version": 2,
            "version": "catalog-v1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "local",
            "domain_index": {
                "api.openai.com": {
                    "category": "ai-inference",
                    "pattern_type": "exact",
                    "provider": "openai"
                }
            },
            "providers": {
                "openai": {
                    "name": "OpenAI",
                    "category": "ai-inference",
                    "api_domains": ["api.openai.com"]
                }
            },
            "interception_patterns": {
                "api.openai.com": [
                    { "action": "intercept", "path": "/v1/chat/completions" }
                ]
            },
            "filters": {
                "whitelist": ["api.openai.com"],
                "blacklist": [],
                "passthrough": [],
                "noise_keywords": []
            }
        });

        save_registry_bundle_cache(&path, &metadata, "etag-1", bundle.to_string().as_bytes())
            .unwrap();

        let loaded = load_registry_bundle_cache(&path).unwrap().unwrap();
        assert_eq!(loaded.schema_version, registry_cache_schema_version());
        assert_eq!(loaded.metadata.version, "catalog-v1");
    }

    #[test]
    fn load_registry_bundle_cache_rejects_malformed_bundle_payload() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache.json");
        let metadata = sample_registry_metadata("v1");
        let malformed = serde_json::json!({
            "schema_version": registry_cache_schema_version(),
            "fetched_at": "2026-02-13T00:00:00Z",
            "etag": "etag-1",
            "metadata": metadata,
            "bundle": {
                "version": "v1",
                "providers": []
            }
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&malformed).unwrap()).unwrap();

        let err = load_registry_bundle_cache(&path).unwrap_err();
        assert!(err
            .to_string()
            .contains("cached registry bundle payload failed schema validation"));
    }

    #[test]
    fn save_registry_bundle_cache_rejects_missing_canonical_filters() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache.json");
        let metadata = sample_registry_metadata("v1");
        let bundle = serde_json::json!({
            "schema_version": 2,
            "version": "v1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "cloud",
            "providers": {
                "openai": {
                    "id": "openai",
                    "name": "OpenAI",
                    "type": "ai-inference",
                    "domains": ["api.openai.com"]
                }
            },
            "domain_index": [],
            "filters": {
                "whitelist": []
            },
            "pricing": {}
        });

        let err =
            save_registry_bundle_cache(&path, &metadata, "etag-1", bundle.to_string().as_bytes())
                .unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("registry bundle payload failed schema validation")
                || message.contains("bundle payload failed contract validation")
                || message.contains("filters missing required"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn save_registry_bundle_cache_accepts_sensor_filter_aliases_without_filters_object() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache.json");
        let metadata = sample_registry_metadata("v1");
        let bundle = serde_json::json!({
            "schema_version": 3,
            "version": "v1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "cloud",
            "providers": {
                "openai": {
                    "id": "openai",
                    "name": "OpenAI",
                    "type": "ai-inference",
                    "domains": ["api.openai.com"]
                }
            },
            "domain_index": [
                { "host": "api.openai.com", "provider_id": "openai", "entry_type": "ai-inference" }
            ],
            "pricing": {},
            "whitelistedDomains": ["api.openai.com"],
            "passthroughDomains": ["metrics.openai.com"],
            "blacklistedWords": ["telemetry"]
        });

        save_registry_bundle_cache(&path, &metadata, "etag-1", bundle.to_string().as_bytes())
            .unwrap();

        let loaded = load_registry_bundle_cache(&path).unwrap().unwrap();
        assert_eq!(loaded.metadata.version, "v1");
    }

    #[test]
    fn save_registry_bundle_cache_accepts_wrapped_bundle_payload() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache.json");
        let metadata = sample_registry_metadata("wrapped-v1");
        let wrapped = serde_json::json!({
            "bundle": {
                "schema_version": 2,
                "version": "wrapped-v1",
                "compiled_at": "2026-02-13T00:00:00Z",
                "bundle_type": "cloud",
                "providers": {
                    "openai": {
                        "id": "openai",
                        "name": "OpenAI",
                        "type": "ai-inference",
                        "domains": ["api.openai.com"]
                    }
                },
                "domain_index": [],
                "filters": {
                    "whitelist": [],
                    "blacklist": [],
                    "passthrough": [],
                    "noise_keywords": []
                },
                "pricing": {}
            }
        });

        save_registry_bundle_cache(&path, &metadata, "etag-1", wrapped.to_string().as_bytes())
            .unwrap();

        let loaded = load_registry_bundle_cache(&path).unwrap().unwrap();
        assert_eq!(loaded.metadata.version, "wrapped-v1");
        assert_eq!(
            loaded
                .bundle
                .get("version")
                .and_then(serde_json::Value::as_str),
            Some("wrapped-v1")
        );
    }

    #[test]
    fn save_registry_bundle_cache_accepts_edge_bundle_shape_without_legacy_filters() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache.json");
        let metadata = sample_registry_metadata("edge-v4");
        let bundle = serde_json::json!({
            "schema_version": 4,
            "metadata": {
                "bundle_version": "edge-v4",
                "compiled_at": "2026-02-22T00:00:00Z"
            },
            "llm_providers": {},
            "applications": {},
            "catalogs": {
                "ai_catalog": []
            },
            "interception": {
                "defaults": {
                    "unknown_app_action": "skip"
                },
                "browser_policies": {
                    "default_action": "intercept",
                    "allowed_browsers": [],
                    "allowed_apps": []
                },
                "app_policies": {}
            },
            "detection_index": {},
            "formats": {},
            "filters": {
                "domain_patterns": [],
                "path_patterns": [],
                "keywords": []
            }
        });

        save_registry_bundle_cache(&path, &metadata, "etag-edge", bundle.to_string().as_bytes())
            .unwrap();

        let loaded = load_registry_bundle_cache(&path).unwrap().unwrap();
        assert_eq!(loaded.metadata.version, "edge-v4");
        assert_eq!(
            loaded
                .bundle
                .get("schema_version")
                .and_then(serde_json::Value::as_u64),
            Some(4)
        );
    }

    #[test]
    fn load_registry_bundle_cache_accepts_legacy_raw_edge_bundle_shape() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache_edge.json");
        let raw = serde_json::json!({
            "schema_version": 4,
            "metadata": {
                "bundle_version": "2026.02.21-190229-bf3c2d11",
                "compiled_at": "2026-02-21T19:02:29.496270+00:00",
                "stats": {
                    "provider_count": 192,
                    "domain_count": 190
                }
            },
            "llm_providers": {
                "openai": {
                    "id": "openai",
                    "name": "OpenAI"
                }
            },
            "applications": {
                "chatgpt": {
                    "id": "chatgpt",
                    "name": "ChatGPT"
                }
            }
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&raw).unwrap()).unwrap();

        let loaded = load_registry_bundle_cache(&path)
            .unwrap()
            .expect("legacy raw cache should parse");
        assert_eq!(loaded.metadata.version, "2026.02.21-190229-bf3c2d11");
        assert_eq!(loaded.metadata.bundle_type, "edge");
        assert_eq!(loaded.metadata.provider_count, 192);
        assert_eq!(loaded.metadata.domain_count, 190);
        assert_eq!(
            loaded
                .bundle
                .get("schema_version")
                .and_then(serde_json::Value::as_u64),
            Some(4)
        );
        assert_eq!(loaded.validation_status.as_deref(), Some("ok"));
    }

    #[test]
    fn load_registry_bundle_cache_falls_back_to_last_good_when_primary_invalid() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache.json");
        let metadata = sample_registry_metadata("v1");
        let valid_bundle = serde_json::json!({
            "schema_version": 2,
            "version": "v1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "cloud",
            "providers": {
                "openai": {
                    "id": "openai",
                    "name": "OpenAI",
                    "type": "ai-inference",
                    "domains": ["api.openai.com"]
                }
            },
            "domain_index": [],
            "filters": {
                "whitelist": [],
                "blacklist": [],
                "passthrough": [],
                "noise_keywords": []
            },
            "pricing": {}
        });
        save_registry_bundle_cache(
            &path,
            &metadata,
            "etag-1",
            valid_bundle.to_string().as_bytes(),
        )
        .unwrap();

        let broken_primary = serde_json::json!({
            "schema_version": 1,
            "fetched_at": "2026-02-13T00:00:00Z",
            "etag": "etag-bad",
            "metadata": metadata,
            "bundle": { "version": "broken" }
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&broken_primary).unwrap()).unwrap();

        let loaded = load_registry_bundle_cache(&path).unwrap().unwrap();
        assert_eq!(loaded.metadata.version, "v1");
        assert_eq!(
            loaded
                .bundle
                .get("version")
                .and_then(serde_json::Value::as_str),
            Some("v1")
        );
    }

    #[test]
    fn save_registry_bundle_cache_accepts_cloud_contract_fixture() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache.json");
        let metadata = sample_registry_metadata("cloud-contract-fixture-v2");
        let fixture = include_str!("../tests/fixtures/cloud_bundle_contract_v2.json");
        let fixture_json: serde_json::Value = serde_json::from_str(fixture).unwrap();

        save_registry_bundle_cache(
            &path,
            &metadata,
            "etag-fixture",
            fixture_json.to_string().as_bytes(),
        )
        .unwrap();

        let loaded = load_registry_bundle_cache(&path).unwrap().unwrap();
        assert_eq!(loaded.metadata.version, "cloud-contract-fixture-v2");
        assert_eq!(
            loaded
                .bundle
                .get("schema_version")
                .and_then(serde_json::Value::as_u64),
            Some(2)
        );
        assert_eq!(
            loaded
                .bundle
                .get("filters")
                .and_then(|filters| filters.get("blacklist"))
                .and_then(serde_json::Value::as_array)
                .map(|values| values.len()),
            Some(1)
        );
    }

    #[test]
    fn registry_bundle_runtime_status_reports_cache_and_age() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache.json");
        let metadata = sample_registry_metadata("runtime-status-v1");
        let bundle = serde_json::json!({
            "schema_version": 2,
            "version": "runtime-status-v1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "cloud",
            "providers": {
                "openai": {
                    "id": "openai",
                    "name": "OpenAI",
                    "type": "ai-inference",
                    "domains": ["api.openai.com"]
                }
            },
            "domain_index": [],
            "filters": {
                "whitelist": [],
                "blacklist": [],
                "passthrough": [],
                "noise_keywords": []
            },
            "pricing": {}
        });

        save_registry_bundle_cache(&path, &metadata, "etag-1", bundle.to_string().as_bytes())
            .unwrap();

        let status =
            registry_bundle_runtime_status(&path, std::time::Duration::from_secs(24 * 60 * 60));
        assert!(status.cache_present);
        assert_eq!(status.bundle_version.as_deref(), Some("runtime-status-v1"));
        assert!(status.bundle_age_seconds.is_some());
        assert!(!status.stale);
        assert!(status.cache_error.is_none());
    }

    #[test]
    fn registry_bundle_runtime_status_marks_stale_cache() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache.json");
        let metadata = sample_registry_metadata("stale-v1");
        let bundle = serde_json::json!({
            "schema_version": 2,
            "version": "stale-v1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "cloud",
            "providers": {
                "openai": {
                    "id": "openai",
                    "name": "OpenAI",
                    "type": "ai-inference",
                    "domains": ["api.openai.com"]
                }
            },
            "domain_index": [],
            "filters": {
                "whitelist": [],
                "blacklist": [],
                "passthrough": [],
                "noise_keywords": []
            },
            "pricing": {}
        });
        save_registry_bundle_cache(&path, &metadata, "etag-1", bundle.to_string().as_bytes())
            .unwrap();

        let mut cached = load_registry_bundle_cache(&path).unwrap().unwrap();
        cached.fetched_at = "2024-01-01T00:00:00Z".to_string();
        std::fs::write(&path, serde_json::to_vec_pretty(&cached).unwrap()).unwrap();

        let status = registry_bundle_runtime_status(&path, std::time::Duration::from_secs(60));
        assert!(status.cache_present);
        assert!(status.stale);
        assert!(status.bundle_age_seconds.unwrap_or(0) > 60);
    }

    #[test]
    fn registry_bundle_runtime_status_surfaces_validation_failure_without_cache() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache.json");
        mark_registry_validation_failed(&path, "integrity_verification_failed:sha_mismatch")
            .unwrap();

        let status =
            registry_bundle_runtime_status(&path, std::time::Duration::from_secs(24 * 60 * 60));
        assert!(!status.cache_present);
        assert_eq!(status.validation_status.as_deref(), Some("failed"));
        assert_eq!(
            status.validation_failed_reason.as_deref(),
            Some("integrity_verification_failed:sha_mismatch")
        );
        assert!(status.stale);
    }

    #[test]
    fn save_registry_bundle_cache_marks_validation_success() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache.json");
        mark_registry_validation_failed(&path, "cache_write_failed:disk_full").unwrap();

        let metadata = sample_registry_metadata("validation-ok-v1");
        let bundle = serde_json::json!({
            "schema_version": 2,
            "version": "validation-ok-v1",
            "compiled_at": "2026-02-13T00:00:00Z",
            "bundle_type": "cloud",
            "providers": {
                "openai": {
                    "id": "openai",
                    "name": "OpenAI",
                    "type": "ai-inference",
                    "domains": ["api.openai.com"]
                }
            },
            "domain_index": [],
            "filters": {
                "whitelist": [],
                "blacklist": [],
                "passthrough": [],
                "noise_keywords": []
            },
            "pricing": {}
        });

        save_registry_bundle_cache(&path, &metadata, "etag-1", bundle.to_string().as_bytes())
            .unwrap();

        let status =
            registry_bundle_runtime_status(&path, std::time::Duration::from_secs(24 * 60 * 60));
        assert!(status.cache_present);
        assert_eq!(status.validation_status.as_deref(), Some("ok"));
        assert!(status.validation_failed_reason.is_none());
    }
}
