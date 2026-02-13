use crate::http_client::build_cloud_client;
use anyhow::Context;
use soth_core::api::{
    version::API_VERSION_HEADER, EventBatchRequest, EventBatchResponse, API_VERSION,
};

#[derive(Clone)]
pub struct MetadataPusher {
    endpoint: String,
    api_key: String,
    client: reqwest::Client,
}

impl MetadataPusher {
    pub fn new(endpoint: impl Into<String>, api_key: impl Into<String>) -> Self {
        let endpoint = endpoint.into().trim_end_matches('/').to_string();
        Self {
            client: build_cloud_client(&endpoint),
            endpoint,
            api_key: api_key.into(),
        }
    }

    pub async fn push_batch(
        &self,
        request: &EventBatchRequest,
    ) -> anyhow::Result<Option<EventBatchResponse>> {
        let url = format!("{}/api/v1/events/batch", self.endpoint);
        let response = self
            .client
            .post(&url)
            .header(API_VERSION_HEADER, API_VERSION)
            .bearer_auth(&self.api_key)
            .json(request)
            .send()
            .await
            .with_context(|| format!("metadata push failed for {url}"))?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let decoded = response
            .json::<EventBatchResponse>()
            .await
            .context("failed decoding event batch response")?;
        Ok(Some(decoded))
    }
}
