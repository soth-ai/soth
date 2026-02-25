use std::time::Duration;

pub const DEFAULT_TELEMETRY_ENDPOINT_PATH: &str = "/api/v1/telemetry/batch";
pub const DEFAULT_TELEMETRY_MAX_RETRY_ATTEMPTS: u8 = 5;
pub const DEFAULT_TELEMETRY_BACKOFF_BASE_MS: u64 = 2_000;
pub const DEFAULT_TELEMETRY_BACKOFF_MAX_MS: u64 = 300_000;
pub const DEFAULT_TELEMETRY_DEAD_LETTER_AFTER_HOURS: u32 = 72;

#[derive(Debug, Clone)]
pub struct TelemetrySyncConfig {
    pub enabled: bool,
    pub endpoint_path: String,
    pub max_retry_attempts: u8,
    pub backoff_base_ms: u64,
    pub backoff_max_ms: u64,
    pub dead_letter_after_hours: u32,
}

impl Default for TelemetrySyncConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint_path: DEFAULT_TELEMETRY_ENDPOINT_PATH.to_string(),
            max_retry_attempts: DEFAULT_TELEMETRY_MAX_RETRY_ATTEMPTS,
            backoff_base_ms: DEFAULT_TELEMETRY_BACKOFF_BASE_MS,
            backoff_max_ms: DEFAULT_TELEMETRY_BACKOFF_MAX_MS,
            dead_letter_after_hours: DEFAULT_TELEMETRY_DEAD_LETTER_AFTER_HOURS,
        }
    }
}

impl TelemetrySyncConfig {
    pub fn sanitize(mut self) -> Self {
        if self.endpoint_path.trim().is_empty() {
            self.endpoint_path = DEFAULT_TELEMETRY_ENDPOINT_PATH.to_string();
        } else if !self.endpoint_path.starts_with('/') {
            self.endpoint_path = format!("/{}", self.endpoint_path.trim());
        } else {
            self.endpoint_path = self.endpoint_path.trim().to_string();
        }

        if self.max_retry_attempts == 0 {
            self.max_retry_attempts = DEFAULT_TELEMETRY_MAX_RETRY_ATTEMPTS;
        }
        if self.backoff_base_ms == 0 {
            self.backoff_base_ms = DEFAULT_TELEMETRY_BACKOFF_BASE_MS;
        }
        if self.backoff_max_ms == 0 {
            self.backoff_max_ms = DEFAULT_TELEMETRY_BACKOFF_MAX_MS;
        }
        if self.backoff_max_ms < self.backoff_base_ms {
            self.backoff_max_ms = self.backoff_base_ms;
        }
        if self.dead_letter_after_hours == 0 {
            self.dead_letter_after_hours = DEFAULT_TELEMETRY_DEAD_LETTER_AFTER_HOURS;
        }
        self
    }

    pub fn base_backoff(&self) -> Duration {
        Duration::from_millis(self.backoff_base_ms)
    }

    pub fn max_backoff(&self) -> Duration {
        Duration::from_millis(self.backoff_max_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_applies_defaults_for_zero_values() {
        let cfg = TelemetrySyncConfig {
            enabled: true,
            endpoint_path: String::new(),
            max_retry_attempts: 0,
            backoff_base_ms: 0,
            backoff_max_ms: 0,
            dead_letter_after_hours: 0,
        }
        .sanitize();

        assert_eq!(cfg.endpoint_path, DEFAULT_TELEMETRY_ENDPOINT_PATH);
        assert_eq!(cfg.max_retry_attempts, DEFAULT_TELEMETRY_MAX_RETRY_ATTEMPTS);
        assert_eq!(cfg.backoff_base_ms, DEFAULT_TELEMETRY_BACKOFF_BASE_MS);
        assert_eq!(cfg.backoff_max_ms, DEFAULT_TELEMETRY_BACKOFF_MAX_MS);
        assert_eq!(
            cfg.dead_letter_after_hours,
            DEFAULT_TELEMETRY_DEAD_LETTER_AFTER_HOURS
        );
    }

    #[test]
    fn sanitize_normalizes_endpoint_path_and_backoff_bounds() {
        let cfg = TelemetrySyncConfig {
            enabled: true,
            endpoint_path: "api/v1/telemetry/custom".to_string(),
            max_retry_attempts: 5,
            backoff_base_ms: 5000,
            backoff_max_ms: 1000,
            dead_letter_after_hours: 48,
        }
        .sanitize();

        assert_eq!(cfg.endpoint_path, "/api/v1/telemetry/custom");
        assert_eq!(cfg.backoff_max_ms, cfg.backoff_base_ms);
    }
}
