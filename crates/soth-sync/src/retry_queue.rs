use anyhow::Context;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryQueueEntry {
    pub event_id: String,
    pub created_at: String,
    pub request_body_path: Option<PathBuf>,
    pub response_body_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_body_b64: Option<String>,
    pub attempts: u32,
    pub last_error: Option<String>,
}

#[derive(Clone)]
pub struct BodyRetryQueue {
    dir: PathBuf,
    max_bytes: u64,
}

impl BodyRetryQueue {
    pub fn new(dir: impl AsRef<Path>, max_bytes: u64) -> anyhow::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed creating retry queue dir {}", dir.display()))?;
        Ok(Self { dir, max_bytes })
    }

    pub fn enqueue(&self, entry: &RetryQueueEntry) -> anyhow::Result<()> {
        self.enforce_size_limit()?;
        let path = self.entry_path(&entry.event_id);
        let payload =
            serde_json::to_string_pretty(entry).context("failed serializing queue entry")?;
        std::fs::write(&path, payload)
            .with_context(|| format!("failed writing retry entry {}", path.display()))?;
        Ok(())
    }

    pub fn mark_error(&self, event_id: &str, error: impl Into<String>) -> anyhow::Result<()> {
        let path = self.entry_path(event_id);
        if !path.exists() {
            return Ok(());
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("failed reading retry entry {}", path.display()))?;
        let mut entry: RetryQueueEntry =
            serde_json::from_str(&content).context("failed parsing retry entry")?;
        entry.attempts = entry.attempts.saturating_add(1);
        entry.last_error = Some(error.into());
        self.enqueue(&entry)
    }

    pub fn remove(&self, event_id: &str) -> anyhow::Result<()> {
        let path = self.entry_path(event_id);
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("failed removing retry entry {}", path.display()))?;
        }
        Ok(())
    }

    pub fn list(&self) -> anyhow::Result<Vec<RetryQueueEntry>> {
        let mut entries = Vec::new();
        for item in std::fs::read_dir(&self.dir)
            .with_context(|| format!("failed listing retry queue {}", self.dir.display()))?
        {
            let item = item?;
            let path = item.path();
            if path.extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("failed reading retry entry {}", path.display()))?;
            let parsed: RetryQueueEntry =
                serde_json::from_str(&content).context("failed parsing retry entry")?;
            entries.push(parsed);
        }
        entries.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(entries)
    }

    pub fn build_entry(
        event_id: impl Into<String>,
        request_body_path: Option<PathBuf>,
        response_body_path: Option<PathBuf>,
    ) -> RetryQueueEntry {
        RetryQueueEntry {
            event_id: event_id.into(),
            created_at: Utc::now().to_rfc3339(),
            request_body_path,
            response_body_path,
            request_body_b64: None,
            response_body_b64: None,
            attempts: 0,
            last_error: None,
        }
    }

    pub fn build_entry_with_payloads(
        event_id: impl Into<String>,
        request_body: Option<Vec<u8>>,
        response_body: Option<Vec<u8>>,
    ) -> RetryQueueEntry {
        use base64::Engine as _;
        RetryQueueEntry {
            event_id: event_id.into(),
            created_at: Utc::now().to_rfc3339(),
            request_body_path: None,
            response_body_path: None,
            request_body_b64: request_body
                .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes)),
            response_body_b64: response_body
                .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes)),
            attempts: 0,
            last_error: None,
        }
    }

    fn entry_path(&self, event_id: &str) -> PathBuf {
        self.dir.join(format!("{event_id}.json"))
    }

    fn enforce_size_limit(&self) -> anyhow::Result<()> {
        let mut files = Vec::new();
        let mut total_bytes: u64 = 0;
        for item in std::fs::read_dir(&self.dir)
            .with_context(|| format!("failed scanning retry queue {}", self.dir.display()))?
        {
            let item = item?;
            let metadata = item.metadata()?;
            let modified = metadata
                .modified()
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            total_bytes = total_bytes.saturating_add(metadata.len());
            files.push((modified, item.path(), metadata.len()));
        }

        if total_bytes <= self.max_bytes {
            return Ok(());
        }

        files.sort_by_key(|(modified, _, _)| *modified);
        for (_, path, size) in files {
            if total_bytes <= self.max_bytes {
                break;
            }
            if path.is_file() {
                std::fs::remove_file(&path).with_context(|| {
                    format!("failed pruning retry queue file {}", path.display())
                })?;
                total_bytes = total_bytes.saturating_sub(size);
            }
        }
        Ok(())
    }
}

impl RetryQueueEntry {
    pub fn from_payloads(
        event_id: impl Into<String>,
        request_body: Option<Vec<u8>>,
        response_body: Option<Vec<u8>>,
    ) -> Self {
        BodyRetryQueue::build_entry_with_payloads(event_id, request_body, response_body)
    }
}
