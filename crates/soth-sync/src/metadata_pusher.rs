use crate::http_client::build_cloud_client;
use anyhow::Context;
use flate2::{write::GzEncoder, Compression};
use soth_core::api::{
    version::API_VERSION_HEADER, ExchangeBatchRequest, ExchangeBatchResponse, API_VERSION,
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

    pub async fn push_exchange_batch(
        &self,
        request: &ExchangeBatchRequest,
    ) -> anyhow::Result<Option<ExchangeBatchResponse>> {
        let url = format!("{}/api/v1/exchanges/batch", self.endpoint);
        let request_json =
            serde_json::to_vec(request).context("failed encoding exchange push request")?;
        let request_gzip = gzip_bytes(request_json.as_slice())
            .context("failed compressing exchange push request")?;

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
            .with_context(|| format!("exchange push failed for {url}"))?;

        if gzip_response.status().is_success() {
            let decoded = gzip_response
                .json::<ExchangeBatchResponse>()
                .await
                .context("failed decoding exchange batch response")?;
            return Ok(Some(decoded));
        }
        Ok(None)
    }
}

pub fn estimate_gzip_exchange_batch_size(request: &ExchangeBatchRequest) -> anyhow::Result<usize> {
    let request_json =
        serde_json::to_vec(request).context("failed encoding exchange batch for sizing")?;
    let request_gzip = gzip_bytes(request_json.as_slice())
        .context("failed compressing exchange batch for sizing")?;
    Ok(request_gzip.len())
}

fn gzip_bytes(input: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(input)
        .context("failed writing gzip encoder input")?;
    encoder.finish().context("failed finalizing gzip payload")
}
