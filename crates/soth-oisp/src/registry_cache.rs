use crate::types::bundle::parse_compiled_bundle;
use crate::OispEngine;
use anyhow::Context;
use serde_json::Value;
use std::path::Path;

pub(crate) fn load_from_registry_cache_path(path: &Path) -> anyhow::Result<Option<OispEngine>> {
    if !path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading registry cache {}", path.display()))?;
    let root: Value = serde_json::from_str(&content)
        .with_context(|| format!("failed parsing registry cache {}", path.display()))?;
    let bundle_value = extract_compiled_bundle_value(&root)
        .context("registry cache missing compiled bundle payload")?;
    Ok(Some(build_engine_from_bundle_value(&bundle_value)?))
}

fn extract_compiled_bundle_value(root: &Value) -> anyhow::Result<Value> {
    if parse_compiled_bundle(root).is_ok() {
        return Ok(root.clone());
    }

    let object = root
        .as_object()
        .context("registry cache root must be an object")?;
    if let Some(inner) = object.get("bundle").cloned() {
        return Ok(inner);
    }
    anyhow::bail!("registry cache envelope does not contain required `bundle` field");
}

fn build_engine_from_bundle_value(bundle_value: &Value) -> anyhow::Result<OispEngine> {
    validate_runtime_bundle_contract(bundle_value)
        .context("bundle payload failed runtime contract validation")?;
    let bundle = parse_compiled_bundle(bundle_value).context("failed parsing OISP bundle")?;
    OispEngine::new(bundle).context("failed constructing OISP engine")
}

fn validate_runtime_bundle_contract(bundle_value: &Value) -> anyhow::Result<()> {
    let object = bundle_value
        .as_object()
        .context("bundle payload root must be an object")?;

    let schema_version = object
        .get("schema_version")
        .and_then(Value::as_u64)
        .context("bundle payload missing required `schema_version`")?;
    if schema_version == 0 {
        anyhow::bail!("bundle payload `schema_version` must be greater than 0");
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
    anyhow::bail!("bundle payload missing required `filters` object");
}
