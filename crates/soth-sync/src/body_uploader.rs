use crate::api_types::{BlobUploadRequest, BlobUploadResponse};
use crate::http_client::SothHttpClient;
use anyhow::Context;

#[derive(Clone)]
pub struct BodyUploader {
    cloud: SothHttpClient,
}

impl BodyUploader {
    pub fn new(endpoint: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            cloud: SothHttpClient::new(endpoint, api_key),
        }
    }

    pub async fn upload_blob(
        &self,
        request: &BlobUploadRequest,
    ) -> anyhow::Result<Option<BlobUploadResponse>> {
        let url = self.cloud.url("/api/v1/blobs");
        let response = self
            .cloud
            .post("/api/v1/blobs")
            .header("content-type", "application/json")
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
