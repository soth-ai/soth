use crate::http_client::build_cloud_client;
use anyhow::Context;
use flate2::{write::GzEncoder, Compression};
use soth_core::api::{
    version::API_VERSION_HEADER, ExchangeBatchRequest, ExchangeBatchResponse, API_VERSION,
};
use std::io::Write;
use tracing::warn;

const EXCHANGE_BATCH_UPLOAD_PATH: &str = "/api/v1/exchanges/batch";

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
    endpoint: String,
    api_key: String,
    client: reqwest::Client,
    frontload_upload_path: Option<String>,
}

impl MetadataPusher {
    pub fn new(
        endpoint: impl Into<String>,
        api_key: impl Into<String>,
        frontload_upload_path: Option<String>,
    ) -> Self {
        let endpoint = endpoint.into().trim_end_matches('/').to_string();
        Self {
            client: build_cloud_client(&endpoint),
            endpoint,
            api_key: api_key.into(),
            frontload_upload_path: frontload_upload_path
                .as_deref()
                .and_then(normalize_upload_path),
        }
    }

    pub async fn push_exchange_batch(
        &self,
        request: &ExchangeBatchRequest,
        route: ExchangeBatchRoute,
    ) -> anyhow::Result<ExchangePushResult> {
        let request_json =
            serde_json::to_vec(request).context("failed encoding exchange push request")?;
        let request_gzip = gzip_bytes(request_json.as_slice())
            .context("failed compressing exchange push request")?;
        let primary_url = self.exchange_upload_url(route);
        let primary = self
            .push_exchange_batch_to_url(primary_url.as_str(), request_gzip.as_slice())
            .await;

        if !matches!(route, ExchangeBatchRoute::Frontload) {
            return primary;
        }

        let Some(fallback_url) = self.frontload_fallback_url(primary_url.as_str()) else {
            return primary;
        };

        match primary {
            Ok(ExchangePushResult::NonSuccessStatus(status))
                if should_fallback_frontload_route(status) =>
            {
                warn!(
                    primary_url = %primary_url,
                    fallback_url = %fallback_url,
                    status = %status.as_u16(),
                    "Frontload exchange upload route unavailable; retrying against default exchange batch endpoint"
                );
                self.push_exchange_batch_to_url(fallback_url.as_str(), request_gzip.as_slice())
                    .await
            }
            Err(error) => {
                warn!(
                    primary_url = %primary_url,
                    fallback_url = %fallback_url,
                    error = %error,
                    "Frontload exchange upload failed; retrying against default exchange batch endpoint"
                );
                self.push_exchange_batch_to_url(fallback_url.as_str(), request_gzip.as_slice())
                    .await
                    .with_context(|| {
                        format!(
                            "frontload exchange upload failed for {primary_url}; fallback also failed ({fallback_url})"
                        )
                    })
            }
            other => other,
        }
    }

    fn exchange_upload_url(&self, route: ExchangeBatchRoute) -> String {
        match route {
            ExchangeBatchRoute::Live => {
                compose_upload_url(self.endpoint.as_str(), EXCHANGE_BATCH_UPLOAD_PATH)
            }
            ExchangeBatchRoute::Frontload => {
                if let Some(path) = self.frontload_upload_path.as_deref() {
                    compose_upload_url(self.endpoint.as_str(), path)
                } else {
                    compose_upload_url(self.endpoint.as_str(), EXCHANGE_BATCH_UPLOAD_PATH)
                }
            }
        }
    }

    fn frontload_fallback_url(&self, primary_url: &str) -> Option<String> {
        let live_url = compose_upload_url(self.endpoint.as_str(), EXCHANGE_BATCH_UPLOAD_PATH);
        if live_url.eq_ignore_ascii_case(primary_url) {
            None
        } else {
            Some(live_url)
        }
    }

    async fn push_exchange_batch_to_url(
        &self,
        url: &str,
        request_gzip: &[u8],
    ) -> anyhow::Result<ExchangePushResult> {
        let response = self
            .client
            .post(url)
            .header(API_VERSION_HEADER, API_VERSION)
            .header("content-type", "application/json")
            .header("content-encoding", "gzip")
            .bearer_auth(&self.api_key)
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

fn normalize_upload_path(path: &str) -> Option<String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Some(trimmed.trim_end_matches('/').to_string());
    }
    let normalized = if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };
    let normalized = normalized.trim_end_matches('/').to_string();
    if normalized.is_empty() {
        Some("/".to_string())
    } else {
        Some(normalized)
    }
}

fn compose_upload_url(endpoint: &str, path_or_url: &str) -> String {
    if path_or_url.starts_with("http://") || path_or_url.starts_with("https://") {
        return path_or_url.to_string();
    }
    format!("{endpoint}{path_or_url}")
}

fn should_fallback_frontload_route(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::NOT_FOUND
        || status == reqwest::StatusCode::METHOD_NOT_ALLOWED
        || status == reqwest::StatusCode::GONE
        || status == reqwest::StatusCode::NOT_IMPLEMENTED
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
