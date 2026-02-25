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
