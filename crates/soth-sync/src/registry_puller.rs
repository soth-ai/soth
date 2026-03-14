use crate::api_types::{RegistryBundleFetchQuery, RegistryVersionResponse};
use anyhow::Context;
use base64::Engine;
use chrono::Utc;
use reqwest::header::{HeaderMap, ETAG, IF_NONE_MATCH};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::cache;
use crate::http_client::SothHttpClient;
use soth_core::normalize_bundle_host_pattern;

#[derive(Debug, Clone)]
pub struct RegistryPullOutcome {
    pub checked: bool,
    pub downloaded: bool,
    pub version: Option<String>,
}

#[derive(Clone)]
pub struct RegistryPuller {
    endpoint: String,
    fallback_endpoints: Vec<String>,
    api_key: String,
    device_id_hash: Option<String>,
    cache_path: PathBuf,
    bundle_type: String,
    bundle_watcher: Option<Arc<dyn BundleWatcher>>,
}

pub trait BundleWatcher: Send + Sync {
    fn install_bundle(
        &self,
        manifest_bytes: &[u8],
        assets: HashMap<String, Vec<u8>>,
    ) -> anyhow::Result<String>;

    fn install(
        &self,
        manifest_bytes: &[u8],
        assets: HashMap<String, Vec<u8>>,
    ) -> anyhow::Result<String> {
        self.install_bundle(manifest_bytes, assets)
    }

    fn allow_registry_projection_install(&self) -> bool {
        false
    }
}

impl RegistryPuller {
    pub fn new(
        endpoint: impl Into<String>,
        api_key: impl Into<String>,
        cache_path: PathBuf,
    ) -> Self {
        let endpoint = endpoint.into().trim_end_matches('/').to_string();
        Self {
            endpoint,
            fallback_endpoints: Vec::new(),
            api_key: api_key.into(),
            device_id_hash: None,
            cache_path,
            bundle_type: "local".to_string(),
            bundle_watcher: None,
        }
    }

    pub fn with_bundle_type(mut self, bundle_type: impl Into<String>) -> Self {
        self.bundle_type = bundle_type.into();
        self
    }

    pub fn with_bundle_watcher(mut self, watcher: Arc<dyn BundleWatcher>) -> Self {
        self.bundle_watcher = Some(watcher);
        self
    }

    pub fn with_device_id_hash(mut self, device_id_hash: impl Into<String>) -> Self {
        let normalized = device_id_hash.into();
        self.device_id_hash = normalize_optional(Some(normalized.as_str()));
        self
    }

    pub fn with_fallback_endpoints<I, S>(mut self, endpoints: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.fallback_endpoints = endpoints
            .into_iter()
            .map(|value| value.into().trim().trim_end_matches('/').to_string())
            .filter(|value| !value.is_empty() && value != &self.endpoint)
            .collect();
        self
    }

    pub fn cache_path(&self) -> &PathBuf {
        &self.cache_path
    }

    fn endpoint_candidates(&self) -> Vec<&str> {
        let mut endpoints = Vec::with_capacity(1 + self.fallback_endpoints.len());
        endpoints.push(self.endpoint.as_str());
        for endpoint in &self.fallback_endpoints {
            let candidate = endpoint.as_str();
            if !endpoints.contains(&candidate) {
                endpoints.push(candidate);
            }
        }
        endpoints
    }

    fn cloud_client_for_endpoint(&self, endpoint: &str) -> SothHttpClient {
        SothHttpClient::new(endpoint.to_string(), self.api_key.clone())
    }

    pub async fn sync_from_hint(
        &self,
        expected_bundle_version: Option<&str>,
    ) -> anyhow::Result<RegistryPullOutcome> {
        let expected_bundle_version = normalize_optional(expected_bundle_version);

        let cached = match cache::load_registry_bundle_cache(&self.cache_path) {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!(
                    "Failed reading cached registry bundle {}; continuing without cache: {}",
                    self.cache_path.display(),
                    err
                );
                None
            }
        };
        let cached_version = cached.as_ref().map(|value| value.metadata.version.as_str());

        if should_skip_pull(expected_bundle_version.as_deref(), cached_version) {
            return Ok(RegistryPullOutcome {
                checked: false,
                downloaded: false,
                version: expected_bundle_version.or_else(|| cached_version.map(str::to_string)),
            });
        }

        let if_none_match = cached.as_ref().map(|value| value.etag.as_str());
        self.pull_with_fallbacks(if_none_match, &RegistryBundleFetchQuery::Full)
            .await
            .or_else(|error| {
                if expected_bundle_version.is_some() {
                    Ok(RegistryPullOutcome {
                        checked: false,
                        downloaded: false,
                        version: expected_bundle_version,
                    })
                } else {
                    Err(error)
                }
            })
    }

    /// Force a registry refresh attempt against cloud.
    ///
    /// Unlike `sync_from_hint`, this always checks `/v1/edge/bundle/current`
    /// and uses ETag revalidation to avoid unnecessary downloads.
    pub async fn refresh_now(&self) -> anyhow::Result<RegistryPullOutcome> {
        let cached = match cache::load_registry_bundle_cache(&self.cache_path) {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!(
                    "Failed reading cached registry bundle {}; continuing without cache: {}",
                    self.cache_path.display(),
                    err
                );
                None
            }
        };

        let if_none_match = cached.as_ref().map(|value| value.etag.as_str());
        self.pull_with_fallbacks(if_none_match, &RegistryBundleFetchQuery::Full)
            .await
    }

    /// Force a registry refresh with explicit bundle query semantics.
    ///
    /// This allows section/diff fetches on the same endpoint contract while
    /// preserving default full-bundle behavior for existing callers.
    pub async fn refresh_with_query(
        &self,
        fetch_query: RegistryBundleFetchQuery,
    ) -> anyhow::Result<RegistryPullOutcome> {
        let cached = match cache::load_registry_bundle_cache(&self.cache_path) {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!(
                    "Failed reading cached registry bundle {}; continuing without cache: {}",
                    self.cache_path.display(),
                    err
                );
                None
            }
        };

        let if_none_match = cached.as_ref().map(|value| value.etag.as_str());
        self.pull_with_fallbacks(if_none_match, &fetch_query).await
    }

    async fn pull_with_fallbacks(
        &self,
        if_none_match: Option<&str>,
        fetch_query: &RegistryBundleFetchQuery,
    ) -> anyhow::Result<RegistryPullOutcome> {
        let mut last_error: Option<anyhow::Error> = None;
        for endpoint in self.endpoint_candidates() {
            match self.pull_once(endpoint, if_none_match, fetch_query).await {
                Ok(Some(outcome)) => return Ok(outcome),
                Ok(None) => continue,
                Err(error) => {
                    last_error = Some(
                        error.context(format!("registry pull failed via endpoint {}", endpoint)),
                    );
                    if endpoint != self.endpoint {
                        tracing::warn!(
                            endpoint = endpoint,
                            "Registry pull fallback endpoint failed"
                        );
                    }
                }
            }
        }

        if let Some(error) = last_error {
            Err(error)
        } else {
            Ok(RegistryPullOutcome {
                checked: false,
                downloaded: false,
                version: None,
            })
        }
    }

    async fn pull_once(
        &self,
        endpoint: &str,
        if_none_match: Option<&str>,
        fetch_query: &RegistryBundleFetchQuery,
    ) -> anyhow::Result<Option<RegistryPullOutcome>> {
        let result = self
            .fetch_bundle_current(endpoint, if_none_match, fetch_query)
            .await?;
        self.handle_bundle_fetch_result(endpoint, result, Some("v1_bundle_current"))
            .await
            .map(Some)
    }

    async fn handle_bundle_fetch_result(
        &self,
        endpoint: &str,
        result: BundleFetchResultWithMetadata,
        source: Option<&str>,
    ) -> anyhow::Result<RegistryPullOutcome> {
        match result {
            BundleFetchResultWithMetadata::NotModified { version } => {
                if let Err(error) = cache::mark_registry_validation_success(&self.cache_path) {
                    tracing::warn!(
                        error = %error,
                        "Failed updating registry cache validation status after 304 revalidation"
                    );
                }
                Ok(RegistryPullOutcome {
                    checked: true,
                    downloaded: false,
                    version,
                })
            }
            BundleFetchResultWithMetadata::Downloaded {
                bytes,
                etag,
                metadata,
            } => {
                let verified_metadata = verify_bundle_integrity(&metadata, &bytes, Some(&etag))
                    .inspect_err(|error| {
                        if let Err(status_error) = cache::mark_registry_validation_failed(
                            &self.cache_path,
                            &format!("integrity_verification_failed:{error}"),
                        ) {
                            tracing::warn!(
                                error = %status_error,
                                "Failed persisting registry validation status after integrity failure"
                            );
                        }
                    })?;

                let bundle_hash = normalize_optional(verified_metadata.bundle_hash.as_deref())
                    .or_else(|| normalize_optional(Some(verified_metadata.sha256.as_str())));

                match self.maybe_install_channel2_bundle(&bytes) {
                    Ok(Some(installed_version)) => {
                        self.send_bundle_install_ack(
                            endpoint,
                            installed_version.as_str(),
                            bundle_hash.as_deref(),
                            "installed",
                            source,
                        )
                        .await;
                        if endpoint != self.endpoint {
                            tracing::warn!(
                                endpoint = endpoint,
                                bundle_version = installed_version.as_str(),
                                "Channel 2 bundle install succeeded via fallback endpoint"
                            );
                        }
                        Ok(RegistryPullOutcome {
                            checked: true,
                            downloaded: true,
                            version: Some(installed_version),
                        })
                    }
                    Ok(None) => {
                        cache::save_registry_bundle_cache(
                            &self.cache_path,
                            &verified_metadata,
                            &etag,
                            &bytes,
                        )
                        .inspect_err(|error| {
                            if let Err(status_error) = cache::mark_registry_validation_failed(
                                &self.cache_path,
                                &format!("cache_write_failed:{error}"),
                            ) {
                                tracing::warn!(
                                    error = %status_error,
                                    "Failed persisting registry validation status after cache write failure"
                                );
                            }
                        })?;
                        let projected_install = self
                            .maybe_install_registry_projection_bundle(&verified_metadata, &bytes)
                            .inspect_err(|error| {
                                tracing::warn!(
                                    error = %error,
                                    "Registry bundle projection install failed"
                                );
                            })?;
                        let (ack_bundle_version, install_status, outcome_version) =
                            if let Some(installed_version) = projected_install {
                                (installed_version.clone(), "installed", installed_version)
                            } else {
                                (
                                    verified_metadata.version.clone(),
                                    "unknown",
                                    verified_metadata.version.clone(),
                                )
                            };
                        self.send_bundle_install_ack(
                            endpoint,
                            ack_bundle_version.as_str(),
                            bundle_hash.as_deref(),
                            install_status,
                            source,
                        )
                        .await;
                        if endpoint != self.endpoint {
                            tracing::warn!(
                                endpoint = endpoint,
                                bundle_version = outcome_version.as_str(),
                                install_status = install_status,
                                "Registry bundle refresh succeeded via fallback endpoint"
                            );
                        }
                        Ok(RegistryPullOutcome {
                            checked: true,
                            downloaded: true,
                            version: Some(outcome_version),
                        })
                    }
                    Err(error) => {
                        self.send_bundle_install_ack(
                            endpoint,
                            verified_metadata.version.as_str(),
                            bundle_hash.as_deref(),
                            "failed",
                            source,
                        )
                        .await;
                        Err(error.context("installing channel 2 intelligence bundle"))
                    }
                }
            }
        }
    }

    async fn fetch_bundle_current(
        &self,
        endpoint: &str,
        if_none_match: Option<&str>,
        fetch_query: &RegistryBundleFetchQuery,
    ) -> anyhow::Result<BundleFetchResultWithMetadata> {
        let cloud = self.cloud_client_for_endpoint(endpoint);
        let url = cloud.url("/v1/edge/bundle/current");
        let mut query_params = vec![("type", self.bundle_type.clone())];
        query_params.extend(build_bundle_query_pairs(fetch_query));
        let mut request = cloud.get("/v1/edge/bundle/current").query(&query_params);

        if let Some(if_none_match) = if_none_match {
            request = request.header(IF_NONE_MATCH, if_none_match);
        }

        let response = request
            .send()
            .await
            .with_context(|| format!("cloud v1 bundle current pull failed for {url}"))?;

        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            let version = response
                .headers()
                .get("x-soth-bundle-version")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| normalize_optional(Some(value)));
            return Ok(BundleFetchResultWithMetadata::NotModified { version });
        }

        if !response.status().is_success() {
            anyhow::bail!(
                "cloud v1 bundle current pull failed for {url} with status {}",
                response.status()
            );
        }

        let headers = response.headers().clone();
        let etag = extract_required_etag(&headers)?;

        let bytes = response
            .bytes()
            .await
            .context("failed reading cloud v1 bundle current response bytes")?
            .to_vec();

        let metadata = build_current_bundle_metadata(
            headers.clone(),
            bytes.as_slice(),
            self.bundle_type.as_str(),
        );

        Ok(BundleFetchResultWithMetadata::Downloaded {
            bytes,
            etag,
            metadata,
        })
    }

    async fn send_bundle_install_ack(
        &self,
        endpoint: &str,
        bundle_version: &str,
        bundle_hash: Option<&str>,
        install_status: &str,
        source: Option<&str>,
    ) {
        let Some(device_id_hash) = self.device_id_hash.as_deref() else {
            return;
        };
        let payload = RegistryBundleAckRequest {
            device_id_hash: device_id_hash.to_string(),
            bundle_type: Some(self.bundle_type.clone()),
            bundle_version: bundle_version.to_string(),
            bundle_hash: normalize_optional(bundle_hash),
            install_status: Some(install_status.to_string()),
            installed_at: Some(Utc::now().to_rfc3339()),
            metadata: source
                .map(|value| {
                    let mut metadata = HashMap::new();
                    metadata.insert("source".to_string(), value.to_string());
                    metadata
                })
                .unwrap_or_default(),
        };

        let ack_result = self
            .post_bundle_ack(endpoint, "/v1/edge/bundle/ack", &payload)
            .await;

        match ack_result {
            Ok(()) => {}
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    endpoint = endpoint,
                    bundle_version = bundle_version,
                    install_status = install_status,
                    "Failed to acknowledge bundle install"
                );
            }
        }
    }

    async fn post_bundle_ack(
        &self,
        endpoint: &str,
        path: &str,
        payload: &RegistryBundleAckRequest,
    ) -> anyhow::Result<()> {
        let cloud = self.cloud_client_for_endpoint(endpoint);
        let url = cloud.url(path);
        let response = cloud
            .post(path)
            .json(payload)
            .send()
            .await
            .with_context(|| format!("bundle ack request failed for {url}"))?;

        if !response.status().is_success() {
            anyhow::bail!(
                "bundle ack request failed for {url} with status {}",
                response.status()
            );
        }
        Ok(())
    }

    fn maybe_install_channel2_bundle(&self, bytes: &[u8]) -> anyhow::Result<Option<String>> {
        let Some(hook) = self.bundle_watcher.as_ref() else {
            return Ok(None);
        };
        let Some((manifest_bytes, assets)) = parse_channel2_bundle_payload(bytes) else {
            return Ok(None);
        };
        let version = hook
            .install(manifest_bytes.as_slice(), assets)
            .context("installing channel 2 intelligence bundle")?;
        Ok(Some(version))
    }

    fn maybe_install_registry_projection_bundle(
        &self,
        metadata: &RegistryVersionResponse,
        bytes: &[u8],
    ) -> anyhow::Result<Option<String>> {
        let Some(hook) = self.bundle_watcher.as_ref() else {
            return Ok(None);
        };
        if !hook.allow_registry_projection_install() {
            return Ok(None);
        }

        let bundle_dir = self
            .cache_path
            .parent()
            .context("registry cache path has no parent directory for bundle projection")?;
        let raw_payload: Value = serde_json::from_slice(bytes)
            .context("failed parsing registry bundle projection payload as JSON")?;
        let normalized_bundle = normalize_registry_bundle_payload(raw_payload);
        let (manifest_bytes, assets) =
            build_projected_runtime_bundle(bundle_dir, metadata, &normalized_bundle)?;
        let version = hook
            .install(manifest_bytes.as_slice(), assets)
            .context("installing projected registry bundle")?;
        Ok(Some(version))
    }
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
    if let Some(data) = object.get("data").and_then(Value::as_object) {
        if let Some(inner) = data.get("bundle").cloned() {
            return inner;
        }
        if let Some(inner) = data.get("compiled_bundle").cloned() {
            return inner;
        }
    }
    bundle
}

fn build_projected_runtime_bundle(
    bundle_dir: &Path,
    metadata: &RegistryVersionResponse,
    normalized_bundle: &Value,
) -> anyhow::Result<(Vec<u8>, HashMap<String, Vec<u8>>)> {
    let manifest_path = bundle_dir.join("manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path).with_context(|| {
        format!(
            "failed reading existing runtime bundle manifest {}",
            manifest_path.display()
        )
    })?;
    let mut manifest: Value = serde_json::from_slice(manifest_bytes.as_slice())
        .context("failed parsing existing runtime bundle manifest JSON")?;
    let manifest_obj = manifest
        .as_object_mut()
        .context("existing runtime bundle manifest must be a JSON object")?;

    let mut assets = HashMap::new();
    for path in manifest_asset_paths(manifest_obj)? {
        if path == "detect/bundle.json"
            || path == "gating/bundle.json"
            || path == "registry/raw_bundle.json"
        {
            continue;
        }
        let asset_path = bundle_dir.join(path.as_str());
        let bytes = std::fs::read(&asset_path).with_context(|| {
            format!(
                "failed reading existing bundle asset required for projection {}",
                asset_path.display()
            )
        })?;
        assets.insert(path, bytes);
    }

    let current_detect_path = bundle_dir.join("detect/bundle.json");
    let current_detect = std::fs::read(&current_detect_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(bytes.as_slice()).ok());
    let passthrough_domains = current_detect
        .as_ref()
        .map(extract_passthrough_domains)
        .unwrap_or_default();

    let projected_detect = project_detect_bundle(normalized_bundle, passthrough_domains.as_slice());
    let projected_gating = project_gating_bundle(normalized_bundle, &projected_detect);
    let raw_registry_bundle =
        serde_json::to_vec(normalized_bundle).context("failed serializing raw registry bundle")?;

    let detect_bytes = serde_json::to_vec(&projected_detect)
        .context("failed serializing projected detect bundle")?;
    let gating_bytes = serde_json::to_vec(&projected_gating)
        .context("failed serializing projected gating bundle")?;

    assets.insert("detect/bundle.json".to_string(), detect_bytes);
    assets.insert("gating/bundle.json".to_string(), gating_bytes);
    assets.insert("registry/raw_bundle.json".to_string(), raw_registry_bundle);

    let mut asset_entries = assets
        .iter()
        .map(|(path, bytes)| {
            serde_json::json!({
                "path": path,
                "sha256": sha256_hex(bytes),
                "size_bytes": bytes.len() as u64
            })
        })
        .collect::<Vec<_>>();
    asset_entries.sort_by(|left, right| {
        left.get("path")
            .and_then(Value::as_str)
            .cmp(&right.get("path").and_then(Value::as_str))
    });

    let projected_version = normalize_optional(Some(metadata.version.as_str()))
        .or_else(|| bundle_version_from_payload(normalized_bundle))
        .unwrap_or_else(|| "registry-projected".to_string());
    manifest_obj.insert("version".to_string(), Value::String(projected_version));
    manifest_obj.insert(
        "created_at".to_string(),
        Value::Number(serde_json::Number::from(Utc::now().timestamp())),
    );
    manifest_obj.insert("vendor_sig".to_string(), Value::String(String::new()));
    manifest_obj.insert("assets".to_string(), Value::Array(asset_entries));
    ensure_manifest_scope(manifest_obj);

    let projected_manifest_bytes =
        serde_json::to_vec(&manifest).context("failed serializing projected manifest")?;
    Ok((projected_manifest_bytes, assets))
}

fn bundle_version_from_payload(bundle: &Value) -> Option<String> {
    bundle
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("bundle_version"))
        .and_then(Value::as_str)
        .and_then(|value| normalize_optional(Some(value)))
}

fn manifest_asset_paths(manifest: &Map<String, Value>) -> anyhow::Result<Vec<String>> {
    let entries = manifest
        .get("assets")
        .and_then(Value::as_array)
        .context("runtime manifest missing assets array")?;
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry
            .get("path")
            .and_then(Value::as_str)
            .and_then(|value| normalize_optional(Some(value)))
            .context("runtime manifest asset entry missing path")?;
        paths.push(path);
    }
    Ok(paths)
}

fn ensure_manifest_scope(manifest: &mut Map<String, Value>) {
    if manifest.get("scope").and_then(Value::as_object).is_some() {
        return;
    }
    manifest.insert(
        "scope".to_string(),
        serde_json::json!({
            "intercept_https": true,
            "intercept_http": true,
            "process_filter": null,
            "capture_modes": ["metadata_only", "sensitive_artifacts", "full"]
        }),
    );
}

fn extract_passthrough_domains(detect_bundle: &Value) -> Vec<String> {
    unique_strings(string_array(detect_bundle.get("passthrough_domains")))
}

fn project_detect_bundle(bundle: &Value, passthrough_domains: &[String]) -> Value {
    let llm_providers = bundle
        .get("llm_providers")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let applications = bundle
        .get("applications")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let formats = bundle
        .get("formats")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let filters = bundle
        .get("filters")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let interception = bundle
        .get("interception")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let app_policies = interception
        .get("app_policies")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let browser_policies = interception
        .get("browser_policies")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let mut rest_formats = Map::new();
    for (format_id, format_value) in formats {
        let request = format_value
            .get("request")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let response = format_value
            .get("response")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        rest_formats.insert(
            format_id,
            serde_json::json!({
                "tier": null,
                "request": {
                    "model": normalize_string(request.get("model")),
                    "messages": normalize_string(request.get("messages")),
                    "message": normalize_string(request.get("message")),
                    "chat_history": normalize_string(request.get("chat_history")),
                    "contents": normalize_string(request.get("contents")),
                    "system": normalize_string(request.get("system")),
                    "system_instruction": normalize_string(request.get("system_instruction")),
                    "tools": normalize_string(request.get("tools")),
                    "tool_choice": normalize_string(request.get("tool_choice")),
                    "max_tokens": normalize_string(request.get("max_tokens"))
                        .or_else(|| normalize_string(value_at_path(&format_value, &["request", "generation_config", "max_output_tokens"]))),
                    "temperature": normalize_string(request.get("temperature"))
                        .or_else(|| normalize_string(value_at_path(&format_value, &["request", "generation_config", "temperature"]))),
                    "top_p": normalize_string(request.get("top_p"))
                        .or_else(|| normalize_string(value_at_path(&format_value, &["request", "generation_config", "top_p"]))),
                    "stream": normalize_string(request.get("stream")),
                    "stop": normalize_string(request.get("stop"))
                },
                "response": {
                    "content": normalize_string(value_at_path(&Value::Object(response.clone()), &["json", "extract", "content"])),
                    "model": normalize_string(value_at_path(&Value::Object(response.clone()), &["json", "extract", "model"])),
                    "finish_reason": normalize_string(value_at_path(&Value::Object(response.clone()), &["json", "extract", "finish_reason"])),
                    "input_tokens": normalize_string(value_at_path(&Value::Object(response.clone()), &["json", "extract_usage", "input_tokens"]))
                        .or_else(|| normalize_string(value_at_path(&Value::Object(response.clone()), &["json", "extract_usage", "prompt_tokens"]))),
                    "output_tokens": normalize_string(value_at_path(&Value::Object(response.clone()), &["json", "extract_usage", "output_tokens"]))
                        .or_else(|| normalize_string(value_at_path(&Value::Object(response.clone()), &["json", "extract_usage", "completion_tokens"]))),
                    "stop_reason": normalize_string(value_at_path(&Value::Object(response.clone()), &["json", "extract", "stop_reason"]))
                },
                "system_in_messages": value_at_path(&format_value, &["request", "system"]).is_none(),
                "content_blocks": false,
                "chat_history_mode": value_at_path(&format_value, &["request", "chat_history"]).is_some(),
                "model_from_url_segment": match normalize_string(request.get("model")).as_deref() {
                    Some("{url_path}") => Some("/models/".to_string()),
                    _ => None,
                },
                "role_map": {},
                "model_id_parse": matches!(normalize_string(request.get("model")).as_deref(), Some("{url_path}")),
                "ephemeral_request_fields": [],
                "provider_hint": normalize_string(format_value.get("provider_hint")),
                "model_default": normalize_string(format_value.get("model_default")),
                "encoding": normalize_string(request.get("encoding")).unwrap_or_else(|| "json".to_string()),
                "form_field": normalize_string(request.get("form_field")),
                "preprocess": request.get("preprocess").and_then(Value::as_array).cloned().unwrap_or_default(),
                "stream_format": normalize_string(value_at_path(&Value::Object(response.clone()), &["stream", "format"])),
                "stream_options": value_at_path(&Value::Object(response.clone()), &["stream", "format_options"]).cloned()
            }),
        );
    }

    let full_capture_providers = llm_providers
        .iter()
        .filter_map(|(provider_id, provider_value)| {
            let mode = normalize_string(value_at_path(provider_value, &["capture", "mode"]))
                .unwrap_or_else(|| "metadata_only".to_string());
            if mode != "metadata_only" {
                Some(provider_id.clone())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let mut detect_providers = Map::new();
    for (provider_id, provider_value) in &llm_providers {
        detect_providers.insert(
            provider_id.clone(),
            serde_json::json!({
                "provider_id": normalize_string(provider_value.get("id")).unwrap_or_else(|| provider_id.clone()),
                "name": normalize_string(provider_value.get("name")).unwrap_or_else(|| provider_id.clone()),
                "api_format": normalize_string(provider_value.get("api_format")),
                "provider_type": normalize_string(provider_value.get("type")),
                "pricing": provider_value.get("pricing").cloned(),
                "capture": value_at_path(provider_value, &["capture"]).cloned(),
                "detection": value_at_path(provider_value, &["detection"]).cloned()
            }),
        );
    }

    let mut detect_apps = Map::new();
    for (app_id, app_value) in &applications {
        let process_rules = value_at_path(app_value, &["detection", "process_rules"])
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let bundle_ids = unique_strings(
            process_rules
                .iter()
                .filter_map(|rule| normalize_string(rule.get("bundle_id")))
                .collect(),
        );
        let process_names = unique_strings(
            process_rules
                .iter()
                .filter_map(|rule| normalize_string(rule.get("process_name")))
                .collect(),
        );
        detect_apps.insert(
            app_id.clone(),
            serde_json::json!({
                "app_id": normalize_string(app_value.get("id")).unwrap_or_else(|| app_id.clone()),
                "name": normalize_string(app_value.get("name")).unwrap_or_else(|| app_id.clone()),
                "bundle_ids": bundle_ids,
                "process_names": process_names,
                "app_type": normalize_string(app_value.get("type")),
                "pricing": app_value.get("pricing").cloned(),
                "capture": value_at_path(app_value, &["capture"]).cloned(),
                "detection": value_at_path(app_value, &["detection"]).cloned(),
                "api_format": normalize_string(app_value.get("api_format"))
            }),
        );
    }

    let filter_keywords = unique_strings(
        string_array(filters.get("keywords"))
            .into_iter()
            .chain(string_array(filters.get("path_patterns")))
            .chain(string_array(filters.get("domain_patterns")))
            .collect(),
    );
    let mut projected_policies = Map::new();
    for (app_id, policy_value) in &app_policies {
        let display_name = applications
            .get(app_id)
            .and_then(|value| value.get("name"))
            .and_then(Value::as_str);
        projected_policies.insert(
            app_id.clone(),
            serde_json::json!({
                "app_id": app_id,
                "display_name": display_name,
                "app_kind": map_app_kind(normalize_string(policy_value.get("app_type")).as_deref()),
                "action": normalize_string(policy_value.get("action")),
                "capture_mode": normalize_string(policy_value.get("capture_mode")),
                "enabled": policy_value.get("enabled").and_then(Value::as_bool),
                "host_filter": normalize_string(policy_value.get("host_filter")),
                "host_list_ref": normalize_string(policy_value.get("host_list_ref"))
            }),
        );
    }

    let allowed_apps = unique_strings(string_array(browser_policies.get("allowed_apps")));
    let allowed_browsers = unique_strings(string_array(browser_policies.get("allowed_browsers")));
    let collectors = bundle
        .get("collectors")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    serde_json::json!({
        "rest_formats": Value::Object(rest_formats),
        "graphql_operations": {
            "version": null,
            "operations": [],
            "heuristic_patterns": []
        },
        "grpc_services": {
            "version": null,
            "services": []
        },
        "capture_rules": {
            "default_mode": "metadata_only",
            "full_capture_providers": full_capture_providers,
            "org_overrides": {
                "full_capture_providers": [],
                "metadata_only_providers": []
            }
        },
        "domain_index": bundle.get("domain_index").cloned().unwrap_or_else(|| Value::Object(Map::new())),
        "detection_index": bundle.get("detection_index").cloned().unwrap_or_else(|| Value::Object(Map::new())),
        "llm_providers": Value::Object(detect_providers),
        "applications": Value::Object(detect_apps),
        "filters": {
            "path_keywords": filter_keywords,
            "header_keywords": [],
            "domain_patterns": string_array(filters.get("domain_patterns")),
            "path_patterns": string_array(filters.get("path_patterns")),
            "keywords": string_array(filters.get("keywords"))
        },
        "app_policies": Value::Object(projected_policies),
        "browser_policies": {
            "allowed_apps": allowed_apps,
            "allowed_browsers": allowed_browsers,
            "default_action": normalize_string(browser_policies.get("default_action"))
        },
        "passthrough_domains": passthrough_domains,
        "collectors": Value::Object(collectors),
        "source_metadata": bundle.get("metadata").cloned()
    })
}

fn project_gating_bundle(bundle: &Value, detect_bundle: &Value) -> Value {
    let llm_providers = bundle
        .get("llm_providers")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let applications = bundle
        .get("applications")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let interception = bundle
        .get("interception")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let app_policies = interception
        .get("app_policies")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let browser_policies = interception
        .get("browser_policies")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let defaults = interception
        .get("defaults")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let mut identity_hosts = Map::new();
    let mut identity_non_hosts = Map::new();
    for (entity_id, policy_value) in &app_policies {
        let app_type = normalize_string(policy_value.get("app_type"))
            .unwrap_or_else(|| "non_host".to_string());
        let target = if app_type == "host" {
            &mut identity_hosts
        } else {
            &mut identity_non_hosts
        };
        target.insert(
            entity_id.clone(),
            serde_json::json!({
                "entity_id": entity_id,
                "app_type": if app_type == "host" { "host" } else { "non_host" },
                "capture_mode": map_capture_mode(normalize_string(policy_value.get("capture_mode")).as_deref()),
                "action": map_process_action(normalize_string(policy_value.get("action")).as_deref()),
                "enabled": policy_value.get("enabled").and_then(Value::as_bool),
                "host_filter": normalize_string(policy_value.get("host_filter")),
                "host_list_ref": normalize_string(policy_value.get("host_list_ref"))
            }),
        );
    }
    for browser_id in unique_strings(
        string_array(browser_policies.get("allowed_apps"))
            .into_iter()
            .chain(string_array(browser_policies.get("allowed_browsers")))
            .collect(),
    ) {
        identity_hosts.insert(
            browser_id.clone(),
            serde_json::json!({
                "entity_id": browser_id,
                "app_type": "host",
                "capture_mode": "metadata_only",
                "action": "intercept",
                "enabled": true,
                "host_filter": null,
                "host_list_ref": null
            }),
        );
    }

    let tls_intercept_hosts = unique_strings(
        llm_providers
            .values()
            .chain(applications.values())
            .flat_map(extract_detection_host_patterns)
            .collect(),
    );
    let passthrough_domains = unique_strings(
        string_array(detect_bundle.get("passthrough_domains"))
            .into_iter()
            .filter_map(|value| normalize_bundle_host_pattern(value.as_str()))
            .collect(),
    );

    let catalogs = bundle
        .get("catalogs")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let filters = bundle
        .get("filters")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let blacklisted_keywords = unique_strings(
        string_array(catalogs.get("analytics_blocklist"))
            .into_iter()
            .chain(string_array(filters.get("keywords")))
            .chain(string_array(filters.get("path_patterns")))
            .collect(),
    );
    let allowed_host_origins = unique_strings(
        string_array(catalogs.get("ai_catalog"))
            .into_iter()
            .filter_map(|value| normalize_bundle_host_pattern(value.as_str()))
            .collect(),
    );

    let providers = llm_providers
        .iter()
        .map(|(entity_id, entry)| project_entity_rule(entity_id, entry))
        .collect::<Vec<_>>();
    let web_apps = applications
        .iter()
        .map(|(entity_id, entry)| project_entity_rule(entity_id, entry))
        .collect::<Vec<_>>();

    serde_json::json!({
        "schema_version": 2,
        "identity_index": {
            "hosts": Value::Object(identity_hosts),
            "non_hosts": Value::Object(identity_non_hosts)
        },
        "gates": {
            "order": [
                "stage0_tls",
                "stage1_app_origin",
                "stage2_whitelist",
                "stage3_blacklist",
                "stage4_app_type",
                "stage5_host_origin",
                "intercept"
            ],
            "defaults": {
                "sensor_enabled": true,
                "fail_open_on_config_error": true,
                "unknown_app_action": map_unknown_app_action(
                    normalize_string(defaults.get("whitelisted_unknown_app_action")).as_deref()
                ),
                "non_cataloged_host_action": map_non_cataloged_action(
                    normalize_string(defaults.get("non_whitelisted_host_action")).as_deref()
                ),
                "source_unknown_app_action": normalize_string(defaults.get("unknown_app_action")),
                "source_whitelisted_unknown_app_action": normalize_string(defaults.get("whitelisted_unknown_app_action")),
                "source_non_whitelisted_host_action": normalize_string(defaults.get("non_whitelisted_host_action")),
                "source_browser_default_action": normalize_string(browser_policies.get("default_action")),
                "discovery": {
                    "unknown_app_daily_limit": 1,
                    "unknown_domain_daily_limit": 1
                }
            },
            "stage0_tls": {
                "tls_intercept_hosts": tls_intercept_hosts,
                "passthrough_domains": passthrough_domains,
                "enable_discovery": true
            },
            "stage1_app_origin": {
                "skip_if_unresolved_process": true
            },
            "stage2_whitelist": {
                "allow_empty_means_allow_all_except_denied": true
            },
            "stage3_blacklist": {
                "blacklisted_keywords": blacklisted_keywords,
                "blacklisted_path_substrings": string_array(catalogs.get("analytics_blocklist")),
                "blacklisted_host_substrings": string_array(filters.get("domain_patterns")),
                "graphql_operation_blacklist": [],
                "graphql_operation_blacklist_enabled": false,
                "match_type": "case_insensitive_substring"
            },
            "stage4_app_type": {
                "derive_from_identity_index": true
            },
            "stage5_host_origin": {
                "allowed_host_origins": allowed_host_origins,
                "skip_for_discovery_capture": true
            }
        },
        "entities": {
            "providers": providers,
            "web_apps": web_apps,
            "native_apps": []
        }
    })
}

fn extract_detection_host_patterns(entry: &Value) -> Vec<String> {
    value_at_path(entry, &["detection", "hosts"])
        .and_then(Value::as_array)
        .map(|hosts| {
            hosts
                .iter()
                .filter_map(|host| normalize_string(host.get("pattern")))
                .filter_map(|pattern| normalize_bundle_host_pattern(pattern.as_str()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn project_entity_rule(entity_key: &str, entry: &Value) -> Value {
    let entity_id = normalize_string(entry.get("id")).unwrap_or_else(|| entity_key.to_string());
    let capture_mode =
        map_capture_mode(normalize_string(value_at_path(entry, &["capture", "mode"])).as_deref());
    let methods = string_array(value_at_path(entry, &["capture", "methods"]));

    let hosts = value_at_path(entry, &["detection", "hosts"])
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|host| {
                    let pattern = normalize_string(host.get("pattern"))
                        .and_then(|value| normalize_bundle_host_pattern(value.as_str()))?;
                    Some(serde_json::json!({
                        "pattern": pattern,
                        "methods": methods.clone(),
                        "paths": {
                            "deny_exact": string_array(value_at_path(host, &["paths", "deny_exact"])),
                            "deny_glob": string_array(value_at_path(host, &["paths", "deny_glob"])),
                            "allow": string_array(value_at_path(host, &["paths", "allow"]))
                        },
                        "priority": host.get("priority").and_then(Value::as_u64).map(|value| value as u32)
                    }))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    serde_json::json!({
        "entity_id": entity_id,
        "capture_mode": capture_mode,
        "hosts": hosts,
        "api_format": normalize_string(entry.get("api_format")),
        "entity_type": normalize_string(entry.get("type")),
        "pricing": entry.get("pricing").cloned(),
        "capture": value_at_path(entry, &["capture"]).cloned(),
        "detection": value_at_path(entry, &["detection"]).cloned()
    })
}

fn value_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(value, |current, segment| {
        current.as_object().and_then(|object| object.get(*segment))
    })
}

fn normalize_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .and_then(|raw| normalize_optional(Some(raw)))
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|raw| normalize_optional(Some(raw)))
                .collect()
        })
        .unwrap_or_default()
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn map_app_kind(value: Option<&str>) -> &'static str {
    match value.unwrap_or("unknown") {
        "host" => "browser",
        "non_host" => "agent_app",
        "ide" => "ide",
        "cli" => "cli",
        _ => "unknown",
    }
}

fn map_capture_mode(value: Option<&str>) -> &'static str {
    match value.unwrap_or("metadata_only") {
        "full" => "full",
        "sensitive_artifacts" => "sensitive_artifacts",
        "full_content" => "full_content",
        _ => "metadata_only",
    }
}

fn map_process_action(value: Option<&str>) -> &'static str {
    match value.unwrap_or("intercept") {
        "block" => "block",
        "skip" | "passthrough" => "skip",
        _ => "intercept",
    }
}

fn map_unknown_app_action(value: Option<&str>) -> &'static str {
    match value.unwrap_or("skip") {
        "block" => "block",
        "intercept" | "host_only" => "intercept",
        _ => "skip",
    }
}

fn map_non_cataloged_action(value: Option<&str>) -> &'static str {
    match value.unwrap_or("skip") {
        "tunnel" | "passthrough" => "passthrough",
        _ => "skip",
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

enum BundleFetchResultWithMetadata {
    NotModified {
        version: Option<String>,
    },
    Downloaded {
        bytes: Vec<u8>,
        etag: String,
        metadata: RegistryVersionResponse,
    },
}

#[derive(Debug, Serialize)]
struct RegistryBundleAckRequest {
    device_id_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bundle_type: Option<String>,
    bundle_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bundle_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    install_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    installed_at: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    metadata: HashMap<String, String>,
}

fn normalize_optional(value: Option<&str>) -> Option<String> {
    let raw = value?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalize_etag(value: &str) -> String {
    let trimmed = value.trim();
    let without_weak = trimmed
        .strip_prefix("W/")
        .or_else(|| trimmed.strip_prefix("w/"))
        .unwrap_or(trimmed)
        .trim();
    without_weak.trim_matches('"').to_string()
}

fn extract_required_etag(headers: &HeaderMap) -> anyhow::Result<String> {
    headers
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .map(normalize_etag)
        .filter(|value| !value.is_empty())
        .context("cloud registry bundle response missing ETag header")
}

fn should_skip_pull(expected_bundle_version: Option<&str>, cached_version: Option<&str>) -> bool {
    match (expected_bundle_version, cached_version) {
        (Some(expected), Some(cached)) => expected == cached,
        (None, Some(_)) => true,
        _ => false,
    }
}

fn build_bundle_query_pairs(fetch_query: &RegistryBundleFetchQuery) -> Vec<(&'static str, String)> {
    match fetch_query {
        RegistryBundleFetchQuery::Full => Vec::new(),
        RegistryBundleFetchQuery::Section { section } => {
            let section = section.trim();
            if section.is_empty() {
                Vec::new()
            } else {
                vec![("query", format!("section:{section}"))]
            }
        }
        RegistryBundleFetchQuery::Diff { from_hash, section } => {
            let from_hash = from_hash.trim();
            if from_hash.is_empty() {
                Vec::new()
            } else if let Some(section) = section.as_deref().and_then(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            }) {
                vec![
                    ("query", "diff".to_string()),
                    ("from_hash", from_hash.to_string()),
                    ("section", section.to_string()),
                ]
            } else {
                vec![
                    ("query", "diff".to_string()),
                    ("from_hash", from_hash.to_string()),
                ]
            }
        }
    }
}

fn verify_bundle_integrity(
    metadata: &RegistryVersionResponse,
    bundle_bytes: &[u8],
    bundle_etag: Option<&str>,
) -> anyhow::Result<RegistryVersionResponse> {
    let mut verified = metadata.clone();
    let size_mismatch =
        metadata.size_bytes > 0 && metadata.size_bytes as usize != bundle_bytes.len();
    let actual_hash = format!("{:x}", Sha256::digest(bundle_bytes));

    let expected_hash = metadata
        .bundle_hash
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| metadata.sha256.trim())
        .to_ascii_lowercase();
    let etag_hash = normalize_hash_candidate(bundle_etag);
    if !expected_hash.is_empty() {
        if actual_hash != expected_hash {
            if etag_hash.as_deref() == Some(actual_hash.as_str()) {
                tracing::warn!(
                    metadata_hash = expected_hash,
                    actual_hash = actual_hash,
                    etag_hash = etag_hash.as_deref().unwrap_or_default(),
                    "registry bundle metadata hash drift detected; accepting bundle because ETag hash matches payload"
                );
                verified.sha256 = actual_hash;
                verified.size_bytes = bundle_bytes.len() as u64;
                return Ok(verified);
            }
            anyhow::bail!(
                "registry bundle sha256 mismatch: metadata={} actual={}",
                expected_hash,
                actual_hash
            );
        }
        if size_mismatch {
            tracing::warn!(
                metadata_size = metadata.size_bytes,
                actual_size = bundle_bytes.len(),
                "registry bundle metadata size drift detected; accepting bundle because sha256 matched"
            );
            verified.size_bytes = bundle_bytes.len() as u64;
        }
        return Ok(verified);
    }

    if size_mismatch {
        if etag_hash.as_deref() == Some(actual_hash.as_str()) {
            tracing::warn!(
                metadata_size = metadata.size_bytes,
                actual_size = bundle_bytes.len(),
                actual_hash = actual_hash,
                "registry bundle metadata missing sha256 and has size drift; accepting bundle because ETag hash matches payload"
            );
            verified.sha256 = actual_hash;
            verified.size_bytes = bundle_bytes.len() as u64;
            return Ok(verified);
        }
        anyhow::bail!(
            "registry bundle size mismatch: metadata={} actual={}",
            metadata.size_bytes,
            bundle_bytes.len()
        );
    }

    Ok(verified)
}

fn normalize_hash_candidate(value: Option<&str>) -> Option<String> {
    let candidate = normalize_optional(value).map(|raw| normalize_etag(&raw))?;
    let normalized = candidate.trim().to_ascii_lowercase();
    if normalized.len() == 64 && normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        Some(normalized)
    } else {
        None
    }
}

fn build_current_bundle_metadata(
    headers: HeaderMap,
    bytes: &[u8],
    bundle_type: &str,
) -> RegistryVersionResponse {
    let actual_hash = format!("{:x}", Sha256::digest(bytes));
    let sha256 = normalize_optional(
        headers
            .get("x-soth-bundle-sha256")
            .and_then(|value| value.to_str().ok()),
    )
    .or_else(|| {
        normalize_optional(
            headers
                .get("x-soth-bundle-hash")
                .and_then(|value| value.to_str().ok()),
        )
    })
    .or_else(|| normalize_hash_candidate(headers.get(ETAG).and_then(|value| value.to_str().ok())))
    .unwrap_or_else(|| actual_hash.clone());

    let compiled_at = normalize_optional(
        headers
            .get("x-soth-bundle-compiled-at")
            .and_then(|value| value.to_str().ok()),
    )
    .unwrap_or_else(|| Utc::now().to_rfc3339());

    let version = normalize_optional(
        headers
            .get("x-soth-bundle-version")
            .and_then(|value| value.to_str().ok()),
    )
    .or_else(|| infer_bundle_version_from_payload(bytes))
    .unwrap_or_else(|| "unknown".to_string());

    let channel = normalize_optional(
        headers
            .get("x-soth-bundle-channel")
            .and_then(|value| value.to_str().ok()),
    );

    RegistryVersionResponse {
        bundle_type: bundle_type.to_string(),
        version,
        sha256: sha256.clone(),
        bundle_hash: Some(sha256),
        compiled_at,
        provider_count: 0,
        domain_count: 0,
        format_count: 0,
        size_bytes: bytes.len() as u64,
        manifest: None,
        channel,
    }
}

fn infer_bundle_version_from_payload(bytes: &[u8]) -> Option<String> {
    let parsed: Value = serde_json::from_slice(bytes).ok()?;
    let object = parsed.as_object()?;
    normalize_optional(
        object
            .get("metadata")
            .and_then(Value::as_object)
            .and_then(|metadata| metadata.get("bundle_version"))
            .and_then(Value::as_str),
    )
    .or_else(|| normalize_optional(object.get("version").and_then(Value::as_str)))
    .or_else(|| {
        normalize_optional(
            object
                .get("manifest")
                .and_then(Value::as_object)
                .and_then(|manifest| manifest.get("version"))
                .and_then(Value::as_str),
        )
    })
}

fn parse_channel2_bundle_payload(bytes: &[u8]) -> Option<(Vec<u8>, HashMap<String, Vec<u8>>)> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let object = value.as_object()?;

    let manifest_bytes = if let Some(manifest_value) = object.get("manifest") {
        if manifest_value.is_object() {
            serde_json::to_vec(manifest_value).ok()?
        } else if let Some(manifest_raw) = manifest_value.as_str() {
            decode_bytes_like(manifest_raw.as_bytes(), manifest_raw)?
        } else {
            return None;
        }
    } else if let Some(manifest_b64) = object.get("manifest_bytes").and_then(|v| v.as_str()) {
        decode_bytes_like(manifest_b64.as_bytes(), manifest_b64)?
    } else {
        return None;
    };

    let assets_value = object.get("assets")?.as_object()?;
    let mut assets = HashMap::with_capacity(assets_value.len());
    for (path, raw) in assets_value {
        let bytes = decode_asset_value(raw)?;
        assets.insert(path.clone(), bytes);
    }

    Some((manifest_bytes, assets))
}

fn decode_asset_value(value: &Value) -> Option<Vec<u8>> {
    if let Some(raw) = value.as_str() {
        return decode_bytes_like(raw.as_bytes(), raw);
    }
    if let Some(object) = value.as_object() {
        if let Some(raw) = object.get("base64").and_then(|v| v.as_str()) {
            return decode_bytes_like(raw.as_bytes(), raw);
        }
        if let Some(raw) = object.get("bytes").and_then(|v| v.as_str()) {
            return decode_bytes_like(raw.as_bytes(), raw);
        }
        if let Some(json_payload) = object.get("json") {
            return serde_json::to_vec(json_payload).ok();
        }
    }
    if let Some(array) = value.as_array() {
        let mut bytes = Vec::with_capacity(array.len());
        for item in array {
            let value = item.as_u64()?;
            bytes.push(value as u8);
        }
        return Some(bytes);
    }
    None
}

fn decode_bytes_like(raw_bytes: &[u8], raw: &str) -> Option<Vec<u8>> {
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(raw_bytes) {
        return Some(decoded);
    }
    if raw.trim_start().starts_with('{') || raw.trim_start().starts_with('[') {
        return Some(raw.as_bytes().to_vec());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{
        build_bundle_query_pairs, extract_required_etag, normalize_etag,
        parse_channel2_bundle_payload, project_detect_bundle, should_skip_pull,
        verify_bundle_integrity, BundleWatcher, RegistryPuller,
    };
    use crate::api_types::{RegistryBundleFetchQuery, RegistryVersionResponse};
    use base64::Engine;
    use reqwest::header::HeaderMap;
    use reqwest::header::{HeaderValue, ETAG};
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    fn sample_metadata(sha256: &str, size_bytes: u64) -> RegistryVersionResponse {
        RegistryVersionResponse {
            bundle_type: "local".to_string(),
            version: "bundle-v1".to_string(),
            sha256: sha256.to_string(),
            bundle_hash: None,
            compiled_at: "2026-02-13T00:00:00Z".to_string(),
            provider_count: 1,
            domain_count: 1,
            format_count: 1,
            size_bytes,
            manifest: None,
            channel: None,
        }
    }

    #[test]
    fn normalize_etag_trims_quotes_and_whitespace() {
        assert_eq!(normalize_etag("  \"abc\" "), "abc");
        assert_eq!(normalize_etag("W/\"abc\""), "abc");
    }

    #[test]
    fn stale_expected_bundle_version_does_not_skip_pull() {
        assert!(!should_skip_pull(Some("v2"), Some("v1")));
        assert!(should_skip_pull(Some("v2"), Some("v2")));
    }

    #[test]
    fn missing_etag_header_is_rejected() {
        let headers = HeaderMap::new();
        let err = extract_required_etag(&headers).unwrap_err();
        assert!(err
            .to_string()
            .contains("cloud registry bundle response missing ETag header"));

        let mut headers = HeaderMap::new();
        headers.insert(ETAG, HeaderValue::from_static("\"etag-123\""));
        assert_eq!(extract_required_etag(&headers).unwrap(), "etag-123");
    }

    #[test]
    fn verify_bundle_integrity_accepts_matching_sha_and_size() {
        let payload = br#"{"ok":true}"#;
        let digest = Sha256::digest(payload);
        let metadata = sample_metadata(&format!("{:x}", digest), payload.len() as u64);
        let verified = verify_bundle_integrity(&metadata, payload, None).unwrap();
        assert_eq!(verified.sha256, metadata.sha256);
    }

    #[test]
    fn verify_bundle_integrity_accepts_size_mismatch_when_sha_matches() {
        let payload = br#"{"ok":true}"#;
        let digest = Sha256::digest(payload);
        let metadata = sample_metadata(&format!("{:x}", digest), payload.len() as u64 + 1);
        let verified = verify_bundle_integrity(&metadata, payload, None).unwrap();
        assert_eq!(verified.size_bytes as usize, payload.len());
    }

    #[test]
    fn verify_bundle_integrity_rejects_size_mismatch_without_sha() {
        let payload = br#"{"ok":true}"#;
        let metadata = sample_metadata("", payload.len() as u64 + 1);
        let err = verify_bundle_integrity(&metadata, payload, None).unwrap_err();
        assert!(err.to_string().contains("size mismatch"));
    }

    #[test]
    fn verify_bundle_integrity_rejects_sha_mismatch() {
        let payload = br#"{"ok":true}"#;
        let metadata = sample_metadata("deadbeef", payload.len() as u64);
        let err = verify_bundle_integrity(&metadata, payload, None).unwrap_err();
        assert!(err.to_string().contains("sha256 mismatch"));
    }

    #[test]
    fn verify_bundle_integrity_accepts_sha_mismatch_when_etag_matches_payload_hash() {
        let payload = br#"{"ok":true}"#;
        let digest = Sha256::digest(payload);
        let metadata = sample_metadata("deadbeef", payload.len() as u64);
        let etag = format!("\"{:x}\"", digest);
        let verified = verify_bundle_integrity(&metadata, payload, Some(&etag)).unwrap();
        assert_eq!(verified.sha256, format!("{:x}", digest));
        assert_eq!(verified.size_bytes as usize, payload.len());
    }

    #[test]
    fn build_bundle_query_pairs_full_is_empty() {
        let pairs = build_bundle_query_pairs(&RegistryBundleFetchQuery::Full);
        assert!(pairs.is_empty());
    }

    #[test]
    fn build_bundle_query_pairs_section_sets_section_query() {
        let pairs = build_bundle_query_pairs(&RegistryBundleFetchQuery::Section {
            section: "rules".to_string(),
        });
        assert_eq!(pairs, vec![("query", "section:rules".to_string())]);
    }

    #[test]
    fn build_bundle_query_pairs_diff_sets_from_hash_and_optional_section() {
        let pairs = build_bundle_query_pairs(&RegistryBundleFetchQuery::Diff {
            from_hash: "abc123".to_string(),
            section: Some("tools".to_string()),
        });
        assert_eq!(
            pairs,
            vec![
                ("query", "diff".to_string()),
                ("from_hash", "abc123".to_string()),
                ("section", "tools".to_string())
            ]
        );
    }

    #[test]
    fn parse_channel2_bundle_payload_accepts_manifest_object_and_base64_assets() {
        let manifest = serde_json::json!({
            "version": "bundle-v1",
            "created_at": 1,
            "vendor_sig": "deadbeef",
            "org_approval_sig": null,
            "assets": [],
            "scope": {
                "intercept_https": false,
                "intercept_http": false,
                "process_filter": null,
                "capture_modes": []
            }
        });
        let payload = serde_json::json!({
            "manifest": manifest,
            "assets": {
                "policy/policy_bundle.json": base64::engine::general_purpose::STANDARD.encode(br#"{"ok":true}"#)
            }
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let parsed = parse_channel2_bundle_payload(bytes.as_slice()).expect("payload should parse");
        assert!(!parsed.0.is_empty());
        assert_eq!(
            parsed.1.get("policy/policy_bundle.json").unwrap(),
            br#"{"ok":true}"#
        );
    }

    #[derive(Default)]
    struct MockHookState {
        install_calls: usize,
        last_manifest_version: Option<String>,
        last_asset_paths: Vec<String>,
    }

    struct MockInstallHook {
        state: Arc<Mutex<MockHookState>>,
        allow_projection: bool,
    }

    impl BundleWatcher for MockInstallHook {
        fn install_bundle(
            &self,
            manifest_bytes: &[u8],
            assets: HashMap<String, Vec<u8>>,
        ) -> anyhow::Result<String> {
            let manifest: Value = serde_json::from_slice(manifest_bytes)?;
            let version = manifest
                .get("version")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("manifest.version missing"))?
                .to_string();
            let mut guard = self.state.lock().unwrap();
            guard.install_calls = guard.install_calls.saturating_add(1);
            guard.last_manifest_version = Some(version.clone());
            let mut paths = assets.keys().cloned().collect::<Vec<_>>();
            paths.sort();
            guard.last_asset_paths = paths;
            Ok(version)
        }

        fn allow_registry_projection_install(&self) -> bool {
            self.allow_projection
        }
    }

    #[test]
    fn maybe_install_channel2_bundle_invokes_hook_when_payload_matches_shape() {
        let state = Arc::new(Mutex::new(MockHookState::default()));
        let hook = Arc::new(MockInstallHook {
            state: state.clone(),
            allow_projection: false,
        });
        let puller = RegistryPuller::new("https://example.com", "key", PathBuf::from("/tmp/cache"))
            .with_bundle_watcher(hook);

        let payload = serde_json::json!({
            "manifest": {
                "version": "bundle-v1",
                "created_at": 1,
                "vendor_sig": "deadbeef",
                "org_approval_sig": null,
                "assets": [],
                "scope": {
                    "intercept_https": false,
                    "intercept_http": false,
                    "process_filter": null,
                    "capture_modes": []
                }
            },
            "assets": {
                "policy/policy_bundle.json": base64::engine::general_purpose::STANDARD.encode(br#"{"ok":true}"#)
            }
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        let installed = puller
            .maybe_install_channel2_bundle(bytes.as_slice())
            .expect("install invocation should succeed");
        assert_eq!(installed.as_deref(), Some("bundle-v1"));
        assert_eq!(state.lock().unwrap().install_calls, 1);
    }

    #[test]
    fn projected_registry_bundle_install_uses_existing_bundle_assets_when_allowed() {
        let temp = tempfile::tempdir().expect("temp dir");
        let bundle_dir = temp.path();
        std::fs::create_dir_all(bundle_dir.join("detect")).expect("create detect dir");
        std::fs::create_dir_all(bundle_dir.join("gating")).expect("create gating dir");

        std::fs::write(
            bundle_dir.join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({
                "version": "local-v1",
                "created_at": 1,
                "vendor_sig": "",
                "org_approval_sig": null,
                "assets": [
                    {"path":"detect/bundle.json","sha256":"", "size_bytes":2},
                    {"path":"gating/bundle.json","sha256":"", "size_bytes":2}
                ],
                "scope": {
                    "intercept_https": true,
                    "intercept_http": true,
                    "process_filter": null,
                    "capture_modes": ["metadata_only"]
                }
            }))
            .expect("manifest bytes"),
        )
        .expect("write manifest");
        std::fs::write(
            bundle_dir.join("detect/bundle.json"),
            br#"{"passthrough_domains":["example.com"]}"#,
        )
        .expect("write detect");
        std::fs::write(bundle_dir.join("gating/bundle.json"), br#"{}"#).expect("write gating");

        let state = Arc::new(Mutex::new(MockHookState::default()));
        let hook = Arc::new(MockInstallHook {
            state: state.clone(),
            allow_projection: true,
        });
        let cache_path = bundle_dir.join("registry_bundle_cache.json");
        let puller =
            RegistryPuller::new("https://example.com", "key", cache_path).with_bundle_watcher(hook);

        let payload = serde_json::to_vec(&serde_json::json!({
            "bundle": {
                "schema_version": 4,
                "metadata": {
                    "bundle_version": "bundle-v3",
                    "compiled_at": "2026-03-03T00:00:00Z"
                },
                "llm_providers": {},
                "applications": {},
                "catalogs": {"ai_catalog": [], "analytics_blocklist": []},
                "interception": {
                    "app_policies": {},
                    "browser_policies": {
                        "allowed_apps": [],
                        "allowed_browsers": [],
                        "default_action": "intercept"
                    },
                    "defaults": {
                        "non_whitelisted_host_action": "tunnel",
                        "unknown_app_action": "host_only",
                        "whitelisted_unknown_app_action": "intercept"
                    }
                },
                "detection_index": {},
                "domain_index": {},
                "formats": {},
                "filters": {"domain_patterns": [], "path_patterns": [], "keywords": []},
                "collectors": {}
            }
        }))
        .expect("payload bytes");
        let metadata = RegistryVersionResponse {
            bundle_type: "local".to_string(),
            version: "bundle-v3".to_string(),
            sha256: format!("{:x}", Sha256::digest(payload.as_slice())),
            bundle_hash: None,
            compiled_at: "2026-03-03T00:00:00Z".to_string(),
            provider_count: 0,
            domain_count: 0,
            format_count: 0,
            size_bytes: payload.len() as u64,
            manifest: None,
            channel: Some("stable".to_string()),
        };

        let installed = puller
            .maybe_install_registry_projection_bundle(&metadata, payload.as_slice())
            .expect("projection install should succeed");
        assert_eq!(installed.as_deref(), Some("bundle-v3"));

        let guard = state.lock().expect("mock state");
        assert_eq!(guard.install_calls, 1);
        assert_eq!(guard.last_manifest_version.as_deref(), Some("bundle-v3"));
        assert!(guard
            .last_asset_paths
            .contains(&"detect/bundle.json".to_string()));
        assert!(guard
            .last_asset_paths
            .contains(&"gating/bundle.json".to_string()));
        assert!(guard
            .last_asset_paths
            .contains(&"registry/raw_bundle.json".to_string()));
    }

    #[test]
    fn project_detect_bundle_preserves_rich_provider_and_policy_fields() {
        let bundle = serde_json::json!({
            "llm_providers": {
                "openai": {
                    "id": "openai",
                    "name": "OpenAI",
                    "type": "ai-inference",
                    "api_format": "openai",
                    "pricing": {"default": {"input_per_million_usd": 5.0}},
                    "capture": {"mode": "full", "methods": ["POST"]},
                    "detection": {
                        "hosts": [{"pattern": "api.openai.com", "paths": {"allow": ["/v1/*"], "deny_exact": [], "deny_glob": []}}],
                        "path_patterns": ["**/v1/**"],
                        "header_hints": {"x-openai-client": "openai"}
                    }
                }
            },
            "applications": {
                "chrome": {
                    "id": "chrome",
                    "name": "Google Chrome",
                    "type": "browser",
                    "pricing": {},
                    "capture": {"mode": "metadata_only"},
                    "detection": {
                        "process_rules": [{"bundle_id": "com.google.Chrome", "process_name": "chrome"}],
                        "hosts": [{"pattern": "chatgpt.com", "paths": {"allow": [], "deny_exact": [], "deny_glob": []}}]
                    }
                }
            },
            "formats": {},
            "filters": {
                "domain_patterns": ["*.openai.com"],
                "path_patterns": ["/v1/**"],
                "keywords": ["telemetry"]
            },
            "interception": {
                "app_policies": {
                    "chrome": {
                        "app_type": "host",
                        "action": "intercept",
                        "capture_mode": "metadata_only",
                        "enabled": true,
                        "host_filter": "*.openai.com",
                        "host_list_ref": "ai_catalog"
                    }
                },
                "browser_policies": {
                    "allowed_apps": ["chrome"],
                    "allowed_browsers": [],
                    "default_action": "intercept"
                }
            },
            "domain_index": {"api.openai.com": "openai"},
            "detection_index": {},
            "collectors": {"collector_a": {"enabled": true}},
            "metadata": {"bundle_version": "bundle-v-rich"}
        });

        let projected = project_detect_bundle(&bundle, &[]);

        assert_eq!(
            projected["llm_providers"]["openai"]["provider_type"],
            serde_json::json!("ai-inference")
        );
        assert_eq!(
            projected["llm_providers"]["openai"]["pricing"],
            serde_json::json!({"default": {"input_per_million_usd": 5.0}})
        );
        assert_eq!(
            projected["llm_providers"]["openai"]["capture"]["mode"],
            serde_json::json!("full")
        );
        assert_eq!(
            projected["llm_providers"]["openai"]["detection"]["hosts"][0]["pattern"],
            serde_json::json!("api.openai.com")
        );
        assert_eq!(
            projected["applications"]["chrome"]["app_type"],
            serde_json::json!("browser")
        );
        assert_eq!(
            projected["applications"]["chrome"]["capture"]["mode"],
            serde_json::json!("metadata_only")
        );
        assert_eq!(
            projected["app_policies"]["chrome"]["host_filter"],
            serde_json::json!("*.openai.com")
        );
        assert_eq!(
            projected["collectors"]["collector_a"]["enabled"],
            serde_json::json!(true)
        );
        assert_eq!(
            projected["source_metadata"]["bundle_version"],
            serde_json::json!("bundle-v-rich")
        );
    }

    #[test]
    fn projected_registry_bundle_install_skips_when_not_allowed() {
        let temp = tempfile::tempdir().expect("temp dir");
        let bundle_dir = temp.path();
        std::fs::create_dir_all(bundle_dir.join("detect")).expect("create detect dir");
        std::fs::create_dir_all(bundle_dir.join("gating")).expect("create gating dir");
        std::fs::write(
            bundle_dir.join("manifest.json"),
            serde_json::to_vec(&serde_json::json!({
                "version": "local-v1",
                "created_at": 1,
                "vendor_sig": "",
                "org_approval_sig": null,
                "assets": [
                    {"path":"detect/bundle.json","sha256":"", "size_bytes":2},
                    {"path":"gating/bundle.json","sha256":"", "size_bytes":2}
                ],
                "scope": {
                    "intercept_https": true,
                    "intercept_http": true,
                    "process_filter": null,
                    "capture_modes": ["metadata_only"]
                }
            }))
            .expect("manifest bytes"),
        )
        .expect("write manifest");
        std::fs::write(bundle_dir.join("detect/bundle.json"), br#"{}"#).expect("write detect");
        std::fs::write(bundle_dir.join("gating/bundle.json"), br#"{}"#).expect("write gating");

        let state = Arc::new(Mutex::new(MockHookState::default()));
        let hook = Arc::new(MockInstallHook {
            state: state.clone(),
            allow_projection: false,
        });
        let cache_path = bundle_dir.join("registry_bundle_cache.json");
        let puller =
            RegistryPuller::new("https://example.com", "key", cache_path).with_bundle_watcher(hook);

        let payload = serde_json::to_vec(&serde_json::json!({
            "bundle": {
                "schema_version": 4,
                "metadata": {"bundle_version": "bundle-v3", "compiled_at": "2026-03-03T00:00:00Z"},
                "llm_providers": {},
                "applications": {},
                "catalogs": {"ai_catalog": [], "analytics_blocklist": []},
                "interception": {"app_policies": {}, "browser_policies": {"allowed_apps": [], "allowed_browsers": [], "default_action": "intercept"}, "defaults": {"non_whitelisted_host_action": "tunnel", "unknown_app_action": "host_only", "whitelisted_unknown_app_action": "intercept"}},
                "detection_index": {},
                "domain_index": {},
                "formats": {},
                "filters": {"domain_patterns": [], "path_patterns": [], "keywords": []},
                "collectors": {}
            }
        }))
        .expect("payload bytes");
        let metadata = RegistryVersionResponse {
            bundle_type: "local".to_string(),
            version: "bundle-v3".to_string(),
            sha256: format!("{:x}", Sha256::digest(payload.as_slice())),
            bundle_hash: None,
            compiled_at: "2026-03-03T00:00:00Z".to_string(),
            provider_count: 0,
            domain_count: 0,
            format_count: 0,
            size_bytes: payload.len() as u64,
            manifest: None,
            channel: Some("stable".to_string()),
        };

        let installed = puller
            .maybe_install_registry_projection_bundle(&metadata, payload.as_slice())
            .expect("projection decision should succeed");
        assert!(installed.is_none());
        assert_eq!(state.lock().expect("mock state").install_calls, 0);
    }
}
