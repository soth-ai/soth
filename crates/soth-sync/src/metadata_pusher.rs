use crate::api_types::{ExchangeBatchRequest, ExchangeBatchResponse};
use crate::http_client::SothHttpClient;
use anyhow::Context;
use flate2::{write::GzEncoder, Compression};
use std::io::Write;

const EDGE_EXCHANGE_UPLOAD_PATH: &str = "/v1/edge/enroll/exchange";

#[derive(Debug, Clone)]
pub enum ExchangePushResult {
    Success(ExchangeBatchResponse),
    NonSuccessStatus(reqwest::StatusCode),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeBatchRoute {
    Live,
    Frontload,
}

#[derive(Clone)]
pub struct MetadataPusher {
    cloud: SothHttpClient,
}

impl MetadataPusher {
    pub fn new(
        endpoint: impl Into<String>,
        api_key: impl Into<String>,
        _frontload_upload_path: Option<String>,
    ) -> Self {
        Self {
            cloud: SothHttpClient::new(endpoint, api_key),
        }
    }

    pub async fn push_exchange_batch(
        &self,
        request: &ExchangeBatchRequest,
        _route: ExchangeBatchRoute,
    ) -> anyhow::Result<ExchangePushResult> {
        let request_json =
            serde_json::to_vec(request).context("failed encoding exchange push request")?;
        let request_gzip = gzip_bytes(request_json.as_slice())
            .context("failed compressing exchange push request")?;
        let url = self.cloud.url(EDGE_EXCHANGE_UPLOAD_PATH);
        self.push_exchange_batch_to_url(url.as_str(), request_gzip.as_slice())
            .await
    }

    async fn push_exchange_batch_to_url(
        &self,
        url: &str,
        request_gzip: &[u8],
    ) -> anyhow::Result<ExchangePushResult> {
        let response = self
            .cloud
            .post(url)
            .header("content-type", "application/json")
            .header("content-encoding", "gzip")
            .body(request_gzip.to_vec())
            .send()
            .await
            .with_context(|| format!("exchange push failed for {url}"))?;

        if response.status().is_success() {
            let decoded = response
                .json::<ExchangeBatchResponse>()
                .await
                .context("failed decoding exchange batch response")?;
            return Ok(ExchangePushResult::Success(decoded));
        }
        Ok(ExchangePushResult::NonSuccessStatus(response.status()))
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
