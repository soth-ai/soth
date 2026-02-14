use crate::http_client::build_cloud_client;
use anyhow::Context;
use reqwest::multipart::{Form, Part};
use soth_core::api::{
    version::API_VERSION_HEADER, BlobUploadRequest, BlobUploadResponse, BodyUploadResponse,
    API_VERSION,
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

    pub async fn upload(
        &self,
        event_id: &str,
        request_body: Option<Vec<u8>>,
        response_body: Option<Vec<u8>>,
    ) -> anyhow::Result<Option<BodyUploadResponse>> {
        let url = format!("{}/api/v1/events/{event_id}/body", self.endpoint);
        let mut form = Form::new();
        if let Some(payload) = request_body {
            form = form.part(
                "request_body",
                Part::bytes(payload)
                    .mime_str("application/json")
                    .context("invalid request_body mime type")?,
            );
        }
        if let Some(payload) = response_body {
            form = form.part(
                "response_body",
                Part::bytes(payload)
                    .mime_str("application/json")
                    .context("invalid response_body mime type")?,
            );
        }

        let response = self
            .client
            .post(&url)
            .header(API_VERSION_HEADER, API_VERSION)
            .bearer_auth(&self.api_key)
            .multipart(form)
            .send()
            .await
            .with_context(|| format!("body upload failed for {url}"))?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let decoded = response
            .json::<BodyUploadResponse>()
            .await
            .context("failed decoding body upload response")?;
        Ok(Some(decoded))
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
