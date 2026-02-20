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
                validation_status: cache.validation_status.clone(),
                validation_failed_reason: cache.validation_failed_reason.clone(),
                cache_error: None,
            }
        }
        Ok(None) => RegistryBundleRuntimeStatus {
            cache_present: false,
            ..RegistryBundleRuntimeStatus::default()
        },
        Err(error) => RegistryBundleRuntimeStatus {
            cache_present: false,
            stale: true,
            cache_error: Some(error.to_string()),
            ..RegistryBundleRuntimeStatus::default()
        },
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
    Ok(())
}

fn validate_registry_bundle_payload(bundle: &Value) -> anyhow::Result<()> {
    validate_registry_bundle_contract(bundle)
        .context("bundle payload failed contract validation")?;
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

    let filters = object
        .get("filters")
        .and_then(Value::as_object)
        .context("bundle payload missing required `filters` object")?;

    for key in ["whitelist", "blacklist", "passthrough", "noise_keywords"] {
        let value = filters
            .get(key)
            .with_context(|| format!("bundle payload filters missing required `{key}`"))?;
        if !value.is_array() {
            anyhow::bail!("bundle payload filters.{key} must be an array");
        }
    }

    Ok(())
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

fn load_registry_bundle_cache_at(
    path: &Path,
) -> anyhow::Result<Option<CachedRegistryBundleEnvelope>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading registry cache {}", path.display()))?;
    let mut envelope: CachedRegistryBundleEnvelope = serde_json::from_str(&content)
        .with_context(|| format!("failed parsing registry cache {}", path.display()))?;
    if envelope.schema_version != registry_cache_schema_version() {
        anyhow::bail!(
            "unsupported registry cache schema_version {} (expected {})",
            envelope.schema_version,
            registry_cache_schema_version()
        );
    }
    envelope.bundle = normalize_registry_bundle_payload(envelope.bundle);
    validate_registry_bundle_payload(&envelope.bundle)
        .context("cached registry bundle payload failed schema validation")?;
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
}
