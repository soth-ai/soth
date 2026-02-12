use anyhow::Context;
use reqwest::header::{ETAG, IF_NONE_MATCH};
use soth_core::api::{version::API_VERSION_HEADER, RegistryVersionResponse, API_VERSION};
use std::path::PathBuf;

use crate::cache;

#[derive(Debug, Clone)]
pub struct RegistryPullOutcome {
    pub checked: bool,
    pub downloaded: bool,
    pub version: Option<String>,
}

#[derive(Clone)]
pub struct RegistryPuller {
    endpoint: String,
    api_key: String,
    cache_path: PathBuf,
    bundle_type: String,
    client: reqwest::Client,
}

impl RegistryPuller {
    pub fn new(
        endpoint: impl Into<String>,
        api_key: impl Into<String>,
        cache_path: PathBuf,
    ) -> Self {
        Self {
            endpoint: endpoint.into().trim_end_matches('/').to_string(),
            api_key: api_key.into(),
            cache_path,
            bundle_type: "local".to_string(),
            client: reqwest::Client::new(),
        }
    }

    pub fn with_bundle_type(mut self, bundle_type: impl Into<String>) -> Self {
        self.bundle_type = bundle_type.into();
        self
    }

    pub fn cache_path(&self) -> &PathBuf {
        &self.cache_path
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

        match expected_bundle_version.as_deref() {
            Some(expected_bundle_version)
                if cached
                    .as_ref()
                    .map(|cached| cached.metadata.version.as_str())
                    == Some(expected_bundle_version) =>
            {
                return Ok(RegistryPullOutcome {
                    checked: false,
                    downloaded: false,
                    version: Some(expected_bundle_version.to_string()),
                });
            }
            None if cached.is_some() => {
                return Ok(RegistryPullOutcome {
                    checked: false,
                    downloaded: false,
                    version: cached.map(|cached| cached.metadata.version),
                });
            }
            _ => {}
        }

        let Some(version) = self.fetch_version().await? else {
            return Ok(RegistryPullOutcome {
                checked: false,
                downloaded: false,
                version: expected_bundle_version,
            });
        };
        let if_none_match = cached.as_ref().map(|value| value.etag.as_str());
        let bundle_result = self.fetch_bundle(if_none_match).await?;

        match bundle_result {
            BundleFetchResult::NotModified => Ok(RegistryPullOutcome {
                checked: true,
                downloaded: false,
                version: Some(version.version),
            }),
            BundleFetchResult::Downloaded { bytes, etag } => {
                cache::save_registry_bundle_cache(&self.cache_path, &version, &etag, &bytes)?;
                Ok(RegistryPullOutcome {
                    checked: true,
                    downloaded: true,
                    version: Some(version.version),
                })
            }
        }
    }

    async fn fetch_version(&self) -> anyhow::Result<Option<RegistryVersionResponse>> {
        let url = format!("{}/api/v1/registry/version", self.endpoint);
        let response = self
            .client
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

    async fn fetch_bundle(&self, if_none_match: Option<&str>) -> anyhow::Result<BundleFetchResult> {
        let url = format!("{}/api/v1/registry/bundle", self.endpoint);
        let mut request = self
            .client
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

        let etag = response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .map(normalize_etag)
            .filter(|value| !value.is_empty())
            .context("cloud registry bundle response missing ETag header")?;

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
    value.trim().trim_matches('"').to_string()
}

#[cfg(test)]
mod tests {
    use super::normalize_etag;

    #[test]
    fn normalize_etag_trims_quotes_and_whitespace() {
        assert_eq!(normalize_etag("  \"abc\" "), "abc");
    }
}
