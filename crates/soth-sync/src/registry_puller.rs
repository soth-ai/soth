use anyhow::Context;
use reqwest::header::{HeaderMap, ETAG, IF_NONE_MATCH};
use sha2::{Digest, Sha256};
use soth_core::api::{version::API_VERSION_HEADER, RegistryVersionResponse, API_VERSION};
use std::path::PathBuf;

use crate::cache;
use crate::http_client::build_cloud_client;

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
    cache_path: PathBuf,
    bundle_type: String,
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
            cache_path,
            bundle_type: "local".to_string(),
        }
    }

    pub fn with_bundle_type(mut self, bundle_type: impl Into<String>) -> Self {
        self.bundle_type = bundle_type.into();
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
        self.pull_with_fallbacks(if_none_match)
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
    /// Unlike `sync_from_hint`, this always checks cloud version/bundle endpoints
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
        self.pull_with_fallbacks(if_none_match).await
    }

    async fn pull_with_fallbacks(
        &self,
        if_none_match: Option<&str>,
    ) -> anyhow::Result<RegistryPullOutcome> {
        let mut last_error: Option<anyhow::Error> = None;
        for endpoint in self.endpoint_candidates() {
            match self.pull_once(endpoint, if_none_match).await {
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
    ) -> anyhow::Result<Option<RegistryPullOutcome>> {
        let Some(version) = self.fetch_version(endpoint).await? else {
            return Ok(None);
        };
        match self.fetch_bundle(endpoint, if_none_match).await? {
            BundleFetchResult::NotModified => Ok(Some(RegistryPullOutcome {
                checked: true,
                downloaded: false,
                version: Some(version.version),
            })),
            BundleFetchResult::Downloaded { bytes, etag } => {
                let verified_metadata = verify_bundle_integrity(&version, &bytes, Some(&etag))?;
                cache::save_registry_bundle_cache(
                    &self.cache_path,
                    &verified_metadata,
                    &etag,
                    &bytes,
                )?;
                if endpoint != self.endpoint {
                    tracing::warn!(
                        endpoint = endpoint,
                        bundle_version = verified_metadata.version.as_str(),
                        "Registry bundle refresh succeeded via fallback endpoint"
                    );
                }
                Ok(Some(RegistryPullOutcome {
                    checked: true,
                    downloaded: true,
                    version: Some(verified_metadata.version),
                }))
            }
        }
    }

    async fn fetch_version(
        &self,
        endpoint: &str,
    ) -> anyhow::Result<Option<RegistryVersionResponse>> {
        let url = format!("{endpoint}/api/v1/registry/version");
        let response = build_cloud_client(endpoint)
            .get(&url)
            .query(&[("type", self.bundle_type.as_str())])
            .header(API_VERSION_HEADER, API_VERSION)
            .bearer_auth(&self.api_key)
            .send()
            .await
            .with_context(|| format!("cloud registry version pull failed for {url}"))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND
            || response.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED
        {
            return Ok(None);
        }

        if !response.status().is_success() {
            anyhow::bail!(
                "cloud registry version pull failed for {url} with status {}",
                response.status()
            );
        }

        let parsed = response
            .json::<RegistryVersionResponse>()
            .await
            .context("failed decoding cloud registry version response")?;
        Ok(Some(parsed))
    }

    async fn fetch_bundle(
        &self,
        endpoint: &str,
        if_none_match: Option<&str>,
    ) -> anyhow::Result<BundleFetchResult> {
        let url = format!("{endpoint}/api/v1/registry/bundle");
        let mut request = build_cloud_client(endpoint)
            .get(&url)
            .query(&[("type", self.bundle_type.as_str())])
            .header(API_VERSION_HEADER, API_VERSION)
            .bearer_auth(&self.api_key);

        if let Some(if_none_match) = if_none_match {
            request = request.header(IF_NONE_MATCH, if_none_match);
        }

        let response = request
            .send()
            .await
            .with_context(|| format!("cloud registry bundle pull failed for {url}"))?;

        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(BundleFetchResult::NotModified);
        }

        if !response.status().is_success() {
            anyhow::bail!(
                "cloud registry bundle pull failed for {url} with status {}",
                response.status()
            );
        }

        let etag = extract_required_etag(response.headers())?;

        let bytes = response
            .bytes()
            .await
            .context("failed reading cloud registry bundle bytes")?;

        Ok(BundleFetchResult::Downloaded {
            bytes: bytes.to_vec(),
            etag,
        })
    }
}

enum BundleFetchResult {
    NotModified,
    Downloaded { bytes: Vec<u8>, etag: String },
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

fn verify_bundle_integrity(
    metadata: &RegistryVersionResponse,
    bundle_bytes: &[u8],
    bundle_etag: Option<&str>,
) -> anyhow::Result<RegistryVersionResponse> {
    let mut verified = metadata.clone();
    let size_mismatch =
        metadata.size_bytes > 0 && metadata.size_bytes as usize != bundle_bytes.len();
    let actual_hash = format!("{:x}", Sha256::digest(bundle_bytes));

    let expected_hash = metadata.sha256.trim().to_ascii_lowercase();
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

#[cfg(test)]
mod tests {
    use super::{extract_required_etag, normalize_etag, should_skip_pull, verify_bundle_integrity};
    use reqwest::header::HeaderMap;
    use reqwest::header::{HeaderValue, ETAG};
    use sha2::{Digest, Sha256};
    use soth_core::api::RegistryVersionResponse;

    fn sample_metadata(sha256: &str, size_bytes: u64) -> RegistryVersionResponse {
        RegistryVersionResponse {
            bundle_type: "local".to_string(),
            version: "bundle-v1".to_string(),
            sha256: sha256.to_string(),
            compiled_at: "2026-02-13T00:00:00Z".to_string(),
            provider_count: 1,
            domain_count: 1,
            format_count: 1,
            size_bytes,
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
}
