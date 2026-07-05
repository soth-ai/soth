use crate::api_types::{HeartbeatRequest, HeartbeatResponse};
use crate::heartbeat_rejection::{self, HeartbeatRejection};
use crate::http_client::SothHttpClient;
use anyhow::Context;
use tracing::warn;

#[derive(Clone)]
pub struct HeartbeatSender {
    cloud: SothHttpClient,
}

impl HeartbeatSender {
    pub fn new(endpoint: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            cloud: SothHttpClient::new(endpoint, api_key),
        }
    }

    pub async fn send(
        &self,
        request: &HeartbeatRequest,
    ) -> anyhow::Result<Option<HeartbeatResponse>> {
        let url = self.cloud.url("/v1/edge/heartbeat");
        let response = self
            .cloud
            .post("/v1/edge/heartbeat")
            .json(request)
            .send()
            .await
            .with_context(|| format!("heartbeat push failed for {url}"))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = match response.text().await {
                Ok(body) => body,
                Err(error) => format!("<failed to read response body: {error}>"),
            };
            let message = truncate_heartbeat_error_body(body.as_str());
            warn!(
                status = status.as_u16(),
                endpoint = %url,
                body = %message,
                "heartbeat push rejected by server"
            );
            // Persist the rejection so `soth status` / `soth doctor` can
            // explain *why* heartbeats stopped (e.g. a 403 org/identity
            // mismatch) and point at the re-enroll escape hatch. Best-effort:
            // a disk failure must not abort the heartbeat loop.
            let entry = HeartbeatRejection {
                rejected_at: heartbeat_rejection::now_epoch_secs(),
                status: status.as_u16(),
                message,
                endpoint: url,
            };
            if let Err(error) = heartbeat_rejection::write(&entry) {
                warn!(error = %error, "failed to persist heartbeat rejection sidecar");
            }
            return Ok(None);
        }

        // Accepted — clear any stale rejection sidecar from a prior failure so
        // recovered devices don't keep alarming `soth status`. Best-effort.
        if let Err(error) = heartbeat_rejection::clear() {
            warn!(error = %error, "failed to clear heartbeat rejection sidecar");
        }

        let decoded = response
            .json::<HeartbeatResponse>()
            .await
            .context("failed decoding heartbeat response")?;
        Ok(Some(decoded))
    }
}

fn truncate_heartbeat_error_body(raw: &str) -> String {
    const MAX_BYTES: usize = 512;
    if raw.len() <= MAX_BYTES {
        return raw.to_string();
    }
    let mut out = raw
        .char_indices()
        .take_while(|(idx, _)| *idx < MAX_BYTES)
        .map(|(_, ch)| ch)
        .collect::<String>();
    out.push_str("...(truncated)");
    out
}
