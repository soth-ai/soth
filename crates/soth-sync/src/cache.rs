use anyhow::Context;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use soth_core::api::{ConfigResponse, RegistryVersionResponse};
use soth_oisp::types::bundle::parse_compiled_bundle;
use std::path::{Path, PathBuf};

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
    pub bundle: Value,
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
    let envelope = CachedRegistryBundleEnvelope {
        schema_version: registry_cache_schema_version(),
        fetched_at: Utc::now().to_rfc3339(),
        etag: etag.to_string(),
        metadata: metadata.clone(),
        bundle,
    };

    let payload = serde_json::to_string_pretty(&envelope)
        .context("failed serializing cached registry bundle")?;
    std::fs::write(path, payload)
        .with_context(|| format!("failed writing registry cache {}", path.display()))?;
    let last_good_path = registry_cache_last_good_path(path);
    let payload_last_good = serde_json::to_string_pretty(&envelope)
        .context("failed serializing last-known-good registry bundle")?;
    std::fs::write(&last_good_path, payload_last_good).with_context(|| {
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
    Ok(Some(envelope))
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
            compiled_at: "2026-02-13T00:00:00Z".to_string(),
            provider_count: 1,
            domain_count: 3,
            format_count: 1,
            size_bytes: 128,
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
}
