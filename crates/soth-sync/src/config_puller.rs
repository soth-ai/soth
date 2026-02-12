use anyhow::Context;
use soth_core::api::{version::API_VERSION_HEADER, ConfigResponse, API_VERSION};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::warn;

use crate::cache;
use crate::registry_puller::RegistryPuller;

#[derive(Clone)]
pub struct ConfigPuller {
    endpoint: String,
    api_key: String,
    cache_path: PathBuf,
    client: reqwest::Client,
    debounce_window: Duration,
    debounce_state: Arc<Mutex<DebounceState>>,
    registry_puller: Option<RegistryPuller>,
}

#[derive(Debug, Default)]
struct DebounceState {
    applied_version: Option<String>,
    pending_version: Option<String>,
    pending_since: Option<Instant>,
}

impl ConfigPuller {
    pub fn new(
        endpoint: impl Into<String>,
        api_key: impl Into<String>,
        cache_path: PathBuf,
    ) -> Self {
        Self {
            endpoint: endpoint.into().trim_end_matches('/').to_string(),
            api_key: api_key.into(),
            cache_path,
            client: reqwest::Client::new(),
            debounce_window: Duration::from_secs(6),
            debounce_state: Arc::new(Mutex::new(DebounceState::default())),
            registry_puller: None,
        }
    }

    pub fn with_debounce(mut self, debounce_window: Duration) -> Self {
        self.debounce_window = debounce_window;
        self
    }

    pub fn with_registry_puller(mut self, registry_puller: RegistryPuller) -> Self {
        self.registry_puller = Some(registry_puller);
        self
    }

    pub async fn pull_once(&self) -> anyhow::Result<Option<ConfigResponse>> {
        let url = format!("{}/api/v1/config", self.endpoint);
        let response = self
            .client
            .get(&url)
            .header(API_VERSION_HEADER, API_VERSION)
            .bearer_auth(&self.api_key)
            .send()
            .await
            .with_context(|| format!("cloud config pull failed for {url}"))?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let config = response
            .json::<ConfigResponse>()
            .await
            .context("failed decoding cloud config response")?;

        if let Some(registry_puller) = self.registry_puller.as_ref() {
            if let Err(error) = registry_puller
                .sync_from_hint(config.bundle_version.as_deref())
                .await
            {
                warn!("Cloud registry bundle refresh failed: {}", error);
            }
        }

        if self.should_apply_version(&config.config_version) {
            cache::save_config_cache(&self.cache_path, &config)?;
        }

        Ok(Some(config))
    }

    pub fn cache_path(&self) -> &PathBuf {
        &self.cache_path
    }

    fn should_apply_version(&self, version: &str) -> bool {
        let mut state = self
            .debounce_state
            .lock()
            .expect("config pull debounce state lock poisoned");
        evaluate_debounce(&mut state, version, self.debounce_window, Instant::now())
    }
}

fn evaluate_debounce(
    state: &mut DebounceState,
    version: &str,
    debounce_window: Duration,
    now: Instant,
) -> bool {
    if state.applied_version.as_deref() == Some(version) {
        state.pending_version = None;
        state.pending_since = None;
        return false;
    }

    if debounce_window.is_zero() {
        state.applied_version = Some(version.to_string());
        state.pending_version = None;
        state.pending_since = None;
        return true;
    }

    if state.pending_version.as_deref() != Some(version) {
        state.pending_version = Some(version.to_string());
        state.pending_since = Some(now);
        return false;
    }

    let Some(since) = state.pending_since else {
        state.pending_since = Some(now);
        return false;
    };

    if now.duration_since(since) < debounce_window {
        return false;
    }

    state.applied_version = Some(version.to_string());
    state.pending_version = None;
    state.pending_since = None;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debounce_holds_initial_new_version() {
        let now = Instant::now();
        let mut state = DebounceState::default();
        assert!(!evaluate_debounce(
            &mut state,
            "v1",
            Duration::from_secs(5),
            now
        ));
    }

    #[test]
    fn debounce_applies_stable_version_after_window() {
        let now = Instant::now();
        let mut state = DebounceState::default();
        assert!(!evaluate_debounce(
            &mut state,
            "v1",
            Duration::from_secs(5),
            now
        ));
        assert!(!evaluate_debounce(
            &mut state,
            "v1",
            Duration::from_secs(5),
            now + Duration::from_secs(4)
        ));
        assert!(evaluate_debounce(
            &mut state,
            "v1",
            Duration::from_secs(5),
            now + Duration::from_secs(5)
        ));
    }

    #[test]
    fn debounce_resets_pending_when_version_changes() {
        let now = Instant::now();
        let mut state = DebounceState::default();
        assert!(!evaluate_debounce(
            &mut state,
            "v1",
            Duration::from_secs(5),
            now
        ));
        assert!(!evaluate_debounce(
            &mut state,
            "v2",
            Duration::from_secs(5),
            now + Duration::from_secs(2)
        ));
        assert!(!evaluate_debounce(
            &mut state,
            "v2",
            Duration::from_secs(5),
            now + Duration::from_secs(6)
        ));
        assert!(evaluate_debounce(
            &mut state,
            "v2",
            Duration::from_secs(5),
            now + Duration::from_secs(7)
        ));
    }

    #[test]
    fn debounce_ignores_repeated_applied_version() {
        let now = Instant::now();
        let mut state = DebounceState::default();
        assert!(evaluate_debounce(&mut state, "v1", Duration::ZERO, now));
        assert!(!evaluate_debounce(
            &mut state,
            "v1",
            Duration::from_secs(5),
            now + Duration::from_secs(10)
        ));
    }
}
