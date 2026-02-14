use crate::http_client::build_cloud_client;
use anyhow::Context;
use soth_core::api::{
    version::API_VERSION_HEADER, BlobUploadRequest, BlobUploadResponse, API_VERSION,
};

#[derive(Clone)]
pub struct BodyUploader {
    endpoint: String,
    api_key: String,
    client: reqwest::Client,
}

impl BodyUploader {
    pub fn new(endpoint: impl Into<String>, api_key: impl Into<String>) -> Self {
        let endpoint = endpoint.into().trim_end_matches('/').to_string();
        Self {
            client: build_cloud_client(&endpoint),
            endpoint,
            api_key: api_key.into(),
        }
    }

    pub async fn upload_blob(
        &self,
        request: &BlobUploadRequest,
    ) -> anyhow::Result<Option<BlobUploadResponse>> {
        let url = format!("{}/api/v1/blobs", self.endpoint);
        let response = self
            .client
            .post(&url)
            .header(API_VERSION_HEADER, API_VERSION)
            .header("content-type", "application/json")
            .bearer_auth(&self.api_key)
            .json(request)
            .send()
            .await
            .with_context(|| format!("blob upload failed for {url}"))?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let decoded = response
            .json::<BlobUploadResponse>()
            .await
            .context("failed decoding blob upload response")?;
        Ok(Some(decoded))
    }
}
