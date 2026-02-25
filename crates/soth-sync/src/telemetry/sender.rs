use anyhow::Result;
use soth_telemetry::TransmittedBatch;

use crate::http_client::SothHttpClient;

#[derive(Debug, Clone)]
pub enum TelemetrySendOutcome {
    Sent,
    Retryable { reason: String },
    NonRetryable { reason: String },
}

#[derive(Clone)]
pub struct TelemetrySender {
    cloud: SothHttpClient,
    endpoint_path: String,
}

impl TelemetrySender {
    pub fn new(
        endpoint: impl Into<String>,
        api_key: impl Into<String>,
        endpoint_path: impl Into<String>,
    ) -> Result<Self> {
        let endpoint_path = normalize_endpoint_path(endpoint_path.into());
        Ok(Self {
            cloud: SothHttpClient::new(endpoint, api_key),
            endpoint_path,
        })
    }

    pub async fn send_batch(&self, batch: &TransmittedBatch) -> TelemetrySendOutcome {
        let response = self
            .cloud
            .post(self.endpoint_path.as_str())
            .header("content-type", "application/json")
            .json(batch)
            .send()
            .await;

        match response {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    TelemetrySendOutcome::Sent
                } else if is_retryable_status(status) {
                    TelemetrySendOutcome::Retryable {
                        reason: format!("telemetry batch rejected with status {}", status.as_u16()),
                    }
                } else {
                    TelemetrySendOutcome::NonRetryable {
                        reason: format!("telemetry batch rejected with status {}", status.as_u16()),
                    }
                }
            }
            Err(error) => {
                if error.is_timeout() || error.is_connect() || error.is_request() || error.is_body()
                {
                    TelemetrySendOutcome::Retryable {
                        reason: error.to_string(),
                    }
                } else {
                    TelemetrySendOutcome::NonRetryable {
                        reason: error.to_string(),
                    }
                }
            }
        }
    }
}

fn normalize_endpoint_path(raw: String) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "/api/v1/telemetry/batch".to_string();
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_string();
    }
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    status.is_server_error()
        || status == reqwest::StatusCode::REQUEST_TIMEOUT
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status == reqwest::StatusCode::CONFLICT
        || status == reqwest::StatusCode::TOO_EARLY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_endpoint_path_defaults_for_empty() {
        assert_eq!(
            normalize_endpoint_path(String::new()),
            "/api/v1/telemetry/batch"
        );
    }

    #[test]
    fn normalize_endpoint_path_adds_leading_slash() {
        assert_eq!(
            normalize_endpoint_path("api/v1/telemetry/batch".to_string()),
            "/api/v1/telemetry/batch"
        );
    }

    #[test]
    fn retryable_status_detection_matches_expected_set() {
        assert!(is_retryable_status(reqwest::StatusCode::TOO_MANY_REQUESTS));
        assert!(is_retryable_status(reqwest::StatusCode::BAD_GATEWAY));
        assert!(!is_retryable_status(reqwest::StatusCode::BAD_REQUEST));
        assert!(!is_retryable_status(reqwest::StatusCode::UNAUTHORIZED));
    }
}
