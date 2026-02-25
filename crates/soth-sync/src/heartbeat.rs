use crate::api_types::{HeartbeatRequest, HeartbeatResponse};
use crate::http_client::SothHttpClient;
use anyhow::Context;

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
        let url = self.cloud.url("/api/v1/heartbeat");
        let response = self
            .cloud
            .post("/api/v1/heartbeat")
            .json(request)
            .send()
            .await
            .with_context(|| format!("heartbeat push failed for {url}"))?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let decoded = response
            .json::<HeartbeatResponse>()
            .await
            .context("failed decoding heartbeat response")?;
        Ok(Some(decoded))
    }
}
