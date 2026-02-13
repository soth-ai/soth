use anyhow::Context;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Map;
use serde_json::Value;
use soth_core::api::{ConfigResponse, RegistryVersionResponse};
use soth_oisp_types::bundle::parse_compiled_bundle;
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
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading registry cache {}", path.display()))?;
    let envelope: CachedRegistryBundleEnvelope = serde_json::from_str(&content)
        .with_context(|| format!("failed parsing registry cache {}", path.display()))?;
    if envelope.schema_version != registry_cache_schema_version() {
        anyhow::bail!(
            "unsupported registry cache schema_version {} (expected {})",
            envelope.schema_version,
            registry_cache_schema_version()
        );
    }
    validate_registry_bundle_payload(&envelope.bundle)
        .context("cached registry bundle payload failed schema validation")?;
    validate_compiled_bundle_if_present(&envelope.bundle)
        .context("cached registry bundle failed typed validation")?;
    Ok(Some(envelope))
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

    let bundle: Value = serde_json::from_slice(bundle_bytes)
        .context("failed parsing registry bundle payload as JSON")?;
    validate_registry_bundle_payload(&bundle)
        .context("registry bundle payload failed schema validation")?;
    validate_compiled_bundle_if_present(&bundle)
        .context("registry bundle failed typed validation")?;
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
    Ok(())
}

fn validate_registry_bundle_payload(bundle: &Value) -> anyhow::Result<()> {
    let object = bundle
        .as_object()
        .context("bundle root must be a JSON object")?;

    if is_compiled_bundle_schema(object)
        || is_registry_catalog_schema(object)
        || is_domain_lists_schema(object)
    {
        return Ok(());
    }

    anyhow::bail!(
        "bundle payload did not match supported schemas (compiled_bundle, registry_catalog, or domain_lists)"
    );
}

fn is_compiled_bundle_schema(object: &Map<String, Value>) -> bool {
    let version_ok = object
        .get("version")
        .and_then(|value| value.as_str())
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    let providers_ok = object
        .get("providers")
        .and_then(|value| value.as_object())
        .is_some();
    let domain_index_ok = object
        .get("domain_index")
        .and_then(|value| value.as_array())
        .is_some();
    version_ok && providers_ok && domain_index_ok
}

fn is_domain_lists_schema(object: &Map<String, Value>) -> bool {
    is_string_array_field(object, "ai_inference")
        && is_string_array_field(object, "mcp")
        && is_string_array_field(object, "agent_apps")
}

fn is_registry_catalog_schema(object: &Map<String, Value>) -> bool {
    let version_ok = object
        .get("version")
        .and_then(|value| value.as_str())
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    let providers_ok = object
        .get("providers")
        .and_then(|value| value.as_object())
        .is_some();
    let domain_index_ok = object
        .get("domain_index")
        .and_then(|value| value.as_object())
        .is_some();
    version_ok && providers_ok && domain_index_ok
}

fn is_string_array_field(object: &Map<String, Value>, field: &str) -> bool {
    object
        .get(field)
        .and_then(|value| value.as_array())
        .map(|values| values.iter().all(|item| item.as_str().is_some()))
        .unwrap_or(false)
}

fn validate_compiled_bundle_if_present(bundle: &Value) -> anyhow::Result<()> {
    let object = match bundle.as_object() {
        Some(object) => object,
        None => return Ok(()),
    };
    if is_compiled_bundle_schema(object) {
        parse_compiled_bundle(bundle).context("typed compiled bundle parse failed")?;
    }
    Ok(())
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
            "filters": {},
            "pricing": {}
        });

        save_registry_bundle_cache(&path, &metadata, "etag-1", bundle.to_string().as_bytes())
            .unwrap();

        let loaded = load_registry_bundle_cache(&path).unwrap().unwrap();
        assert_eq!(loaded.schema_version, registry_cache_schema_version());
        assert_eq!(loaded.metadata.version, "v1");
    }

    #[test]
    fn save_registry_bundle_cache_accepts_registry_catalog_shape() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("registry_bundle_cache.json");
        let metadata = sample_registry_metadata("catalog-v1");
        let bundle = serde_json::json!({
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
}
