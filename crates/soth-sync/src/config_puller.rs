use anyhow::Context;
use soth_core::api::{version::API_VERSION_HEADER, ConfigResponse, API_VERSION};
use std::path::PathBuf;

use crate::cache;

#[derive(Clone)]
pub struct ConfigPuller {
    endpoint: String,
    api_key: String,
    cache_path: PathBuf,
    client: reqwest::Client,
}

impl ConfigPuller {
    pub fn new(
        endpoint: impl Into<String>,
        api_key: impl Into<String>,
        cache_path: PathBuf,
    ) -> Self {
        Self {
            endpoint: endpoint.into().trim_end_matches('/').to_string(),
            api_key: api_key.into(),
            cache_path,
            client: reqwest::Client::new(),
        }
    }

    pub async fn pull_once(&self) -> anyhow::Result<Option<ConfigResponse>> {
        let url = format!("{}/api/v1/config", self.endpoint);
        let response = self
            .client
            .get(&url)
            .header(API_VERSION_HEADER, API_VERSION)
            .bearer_auth(&self.api_key)
            .send()
            .await
            .with_context(|| format!("cloud config pull failed for {url}"))?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let config = response
            .json::<ConfigResponse>()
            .await
            .context("failed decoding cloud config response")?;
        cache::save_config_cache(&self.cache_path, &config)?;
        Ok(Some(config))
    }

    pub fn cache_path(&self) -> &PathBuf {
        &self.cache_path
    }
}
