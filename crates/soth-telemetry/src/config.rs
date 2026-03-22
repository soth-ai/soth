use std::path::PathBuf;
use std::time::Duration;

use ed25519_dalek::SigningKey;

#[derive(Debug, Clone)]
pub enum EncryptionMode {
    None,
    Ecies { vendor_pubkey: [u8; 32] },
}

#[derive(Clone)]
pub struct TelemetryConfig {
    pub batch_window: Duration,
    pub max_batch_size: usize,
    pub anomaly_threshold: f32,
    pub signing_key: SigningKey,
    pub encryption: EncryptionMode,
    pub proxy_version: String,
    pub bundle_version: String,
    pub org_id: String,
    /// Directory containing extension observation queue files (*.obs.queue).
    /// When set, the batcher drains these files at flush time.
    pub observation_queue_dir: Option<PathBuf>,
    /// Directory containing governance queue files (*.queue) written by
    /// extensions like historian. Drained at flush time and converted to
    /// TelemetryEvents via `TelemetryEvent::from_governable`.
    pub governance_queue_dir: Option<PathBuf>,
}

impl TelemetryConfig {
    pub(crate) fn sanitize(mut self) -> Self {
        if self.max_batch_size == 0 {
            self.max_batch_size = 1;
        }
        self.anomaly_threshold = self.anomaly_threshold.clamp(0.0, 1.0);
        if self.batch_window.is_zero() {
            self.batch_window = Duration::from_secs(30);
        }
        self
    }
}
