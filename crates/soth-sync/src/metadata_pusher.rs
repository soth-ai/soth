use crate::http_client::build_cloud_client;
use anyhow::Context;
use flate2::{write::GzEncoder, Compression};
use soth_core::api::{
    version::API_VERSION_HEADER, EventBatchRequest, EventBatchResponse, API_VERSION,
};
use std::io::Write;

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
        let request_json =
            serde_json::to_vec(request).context("failed encoding metadata push request")?;
        let request_gzip = gzip_bytes(request_json.as_slice())
            .context("failed compressing metadata push request")?;

        let gzip_response = self
            .client
            .post(&url)
            .header(API_VERSION_HEADER, API_VERSION)
            .header("content-type", "application/json")
            .header("content-encoding", "gzip")
            .bearer_auth(&self.api_key)
            .body(request_gzip)
            .send()
            .await
            .with_context(|| format!("metadata push failed for {url}"))?;

        if gzip_response.status().is_success() {
            let decoded = gzip_response
                .json::<EventBatchResponse>()
                .await
                .context("failed decoding event batch response")?;
            return Ok(Some(decoded));
        }

        if !should_fallback_to_plain(gzip_response.status()) {
            return Ok(None);
        }

        let plain_response = self
            .client
            .post(&url)
            .header(API_VERSION_HEADER, API_VERSION)
            .header("content-type", "application/json")
            .bearer_auth(&self.api_key)
            .body(request_json)
            .send()
            .await
            .with_context(|| format!("metadata push fallback failed for {url}"))?;
        if !plain_response.status().is_success() {
            return Ok(None);
        }

        let decoded = plain_response
            .json::<EventBatchResponse>()
            .await
            .context("failed decoding fallback event batch response")?;
        Ok(Some(decoded))
    }
}

pub fn estimate_gzip_batch_size(request: &EventBatchRequest) -> anyhow::Result<usize> {
    let request_json =
        serde_json::to_vec(request).context("failed encoding metadata batch for sizing")?;
    let request_gzip =
        gzip_bytes(request_json.as_slice()).context("failed compressing metadata batch for sizing")?;
    Ok(request_gzip.len())
}

fn gzip_bytes(input: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(input)
        .context("failed writing gzip encoder input")?;
    encoder.finish().context("failed finalizing gzip payload")
}

fn should_fallback_to_plain(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::BAD_REQUEST
        || status == reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE
        || status == reqwest::StatusCode::NOT_IMPLEMENTED
}
