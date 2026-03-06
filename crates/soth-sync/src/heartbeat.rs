use crate::api_types::{HeartbeatRequest, HeartbeatResponse};
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
            warn!(
                status = status.as_u16(),
                endpoint = %url,
                body = %truncate_heartbeat_error_body(body.as_str()),
                "heartbeat push rejected by server"
            );
            return Ok(None);
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
