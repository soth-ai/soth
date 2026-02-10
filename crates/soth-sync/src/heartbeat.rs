use anyhow::Context;
use soth_core::api::{
    version::API_VERSION_HEADER, HeartbeatRequest, HeartbeatResponse, API_VERSION,
};

#[derive(Clone)]
pub struct HeartbeatSender {
    endpoint: String,
    api_key: String,
    client: reqwest::Client,
}

impl HeartbeatSender {
    pub fn new(endpoint: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into().trim_end_matches('/').to_string(),
            api_key: api_key.into(),
            client: reqwest::Client::new(),
        }
    }

    pub async fn send(
        &self,
        request: &HeartbeatRequest,
    ) -> anyhow::Result<Option<HeartbeatResponse>> {
        let url = format!("{}/api/v1/heartbeat", self.endpoint);
        let response = self
            .client
            .post(&url)
            .header(API_VERSION_HEADER, API_VERSION)
            .bearer_auth(&self.api_key)
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
