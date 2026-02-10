use crate::body_uploader::BodyUploader;
use crate::config_puller::ConfigPuller;
use crate::metadata_pusher::MetadataPusher;
use crate::retry_queue::BodyRetryQueue;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone)]
pub struct SyncAgentConfig {
    pub endpoint: String,
    pub api_key: String,
    pub retry_queue_dir: PathBuf,
    pub retry_queue_max_bytes: u64,
    pub sync_interval: Duration,
}

#[derive(Clone)]
pub struct SyncAgent {
    pub config: SyncAgentConfig,
    pub metadata_pusher: MetadataPusher,
    pub body_uploader: BodyUploader,
    pub retry_queue: BodyRetryQueue,
    pub config_puller: Option<ConfigPuller>,
}

impl SyncAgent {
    pub fn new(
        config: SyncAgentConfig,
        config_puller: Option<ConfigPuller>,
    ) -> anyhow::Result<Self> {
        let metadata_pusher = MetadataPusher::new(&config.endpoint, &config.api_key);
        let body_uploader = BodyUploader::new(&config.endpoint, &config.api_key);
        let retry_queue =
            BodyRetryQueue::new(&config.retry_queue_dir, config.retry_queue_max_bytes)?;
        Ok(Self {
            config,
            metadata_pusher,
            body_uploader,
            retry_queue,
            config_puller,
        })
    }

    /// Placeholder run tick used by the local-side scaffold. Full sync orchestration
    /// is intentionally deferred until cloud service rollout.
    pub async fn tick(&self) -> anyhow::Result<()> {
        if let Some(puller) = &self.config_puller {
            let _ = puller.pull_once().await?;
        }
        Ok(())
    }
}
