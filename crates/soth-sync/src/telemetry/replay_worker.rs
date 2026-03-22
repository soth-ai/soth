use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use rand::Rng;
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

use crate::config::TelemetrySyncConfig;

use super::outbox::TelemetryOutbox;
use super::sender::{TelemetrySendOutcome, TelemetrySender};

/// Retention period for completed (SENT/DEAD) outbox rows. Rows older than
/// this are purged during the periodic scan to prevent unbounded growth.
const COMPLETED_ROW_RETENTION_SECS: i64 = 7 * 24 * 3600; // 7 days

pub struct TelemetryReplayWorker {
    outbox: Arc<TelemetryOutbox>,
    sender: TelemetrySender,
    config: TelemetrySyncConfig,
    rx: mpsc::UnboundedReceiver<String>,
    tx: mpsc::UnboundedSender<String>,
    shutdown: watch::Receiver<bool>,
}

impl TelemetryReplayWorker {
    pub fn new(
        outbox: Arc<TelemetryOutbox>,
        sender: TelemetrySender,
        config: TelemetrySyncConfig,
        rx: mpsc::UnboundedReceiver<String>,
        tx: mpsc::UnboundedSender<String>,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            outbox,
            sender,
            config,
            rx,
            tx,
            shutdown,
        }
    }

    pub async fn run(mut self) {
        let mut scan_interval = tokio::time::interval(Duration::from_secs(15));
        scan_interval.tick().await;
        loop {
            tokio::select! {
                changed = self.shutdown.changed() => {
                    if changed.is_ok() && *self.shutdown.borrow() {
                        break;
                    }
                }
                _ = scan_interval.tick() => {
                    if let Err(error) = self.outbox.drain_on_startup() {
                        tracing::warn!(error = %error, "telemetry replay worker periodic due-scan failed");
                    }
                    if let Err(error) = self.outbox.purge_completed(COMPLETED_ROW_RETENTION_SECS) {
                        tracing::warn!(error = %error, "telemetry outbox purge failed");
                    }
                }
                maybe_batch_id = self.rx.recv() => {
                    let Some(batch_id) = maybe_batch_id else { break; };
                    if let Err(error) = self.process_batch_id(batch_id).await {
                        tracing::warn!(error = %error, "telemetry replay worker failed to process batch");
                    }
                }
            }
        }
    }

    async fn process_batch_id(&self, batch_id: String) -> Result<()> {
        let now = Utc::now().timestamp();
        let Some(record) = self.outbox.claim_for_send(batch_id.as_str(), now)? else {
            return Ok(());
        };

        match self.sender.send_batch(&record.batch).await {
            TelemetrySendOutcome::Sent => {
                self.outbox.mark_sent(record.batch_id)?;
            }
            TelemetrySendOutcome::NonRetryable { reason } => {
                let attempts = record.attempts.saturating_add(1);
                self.outbox
                    .mark_dead(record.batch_id, attempts, reason.as_str())?;
                tracing::warn!(
                    batch_id = %record.batch_id,
                    attempts = attempts,
                    reason = %reason,
                    "telemetry batch marked dead due to non-retryable failure"
                );
            }
            TelemetrySendOutcome::Retryable { reason } => {
                let attempts = record.attempts.saturating_add(1);
                if should_dead_letter(
                    attempts,
                    record.first_queued_at,
                    now,
                    self.config.max_retry_attempts,
                    self.config.dead_letter_after_hours,
                ) {
                    self.outbox
                        .mark_dead(record.batch_id, attempts, reason.as_str())?;
                    tracing::warn!(
                        batch_id = %record.batch_id,
                        attempts = attempts,
                        reason = %reason,
                        "telemetry batch reached dead-letter threshold"
                    );
                    return Ok(());
                }

                let delay = compute_backoff_delay(
                    attempts,
                    self.config.backoff_base_ms,
                    self.config.backoff_max_ms,
                );
                let next_attempt_at = now.saturating_add(delay.as_secs() as i64);
                self.outbox.mark_failed(
                    record.batch_id,
                    attempts,
                    next_attempt_at,
                    reason.as_str(),
                )?;
                self.schedule_retry(record.batch_id, delay)
                    .context("schedule telemetry retry")?;
            }
        }

        Ok(())
    }

    fn schedule_retry(&self, batch_id: Uuid, delay: Duration) -> Result<()> {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = tx.send(batch_id.to_string());
        });
        Ok(())
    }
}

fn should_dead_letter(
    attempts: u8,
    first_queued_at: i64,
    now_ts: i64,
    max_attempts: u8,
    dead_letter_after_hours: u32,
) -> bool {
    if attempts >= max_attempts {
        return true;
    }
    let age_secs = now_ts.saturating_sub(first_queued_at);
    let max_age_secs = i64::from(dead_letter_after_hours).saturating_mul(3600);
    age_secs >= max_age_secs
}

fn compute_backoff_delay(attempts: u8, base_ms: u64, max_ms: u64) -> Duration {
    let shift = u32::from(attempts.saturating_sub(1)).min(16);
    let raw_ms = base_ms.saturating_mul(1u64 << shift).min(max_ms);
    let jitter_span = ((raw_ms as f64) * 0.25) as i64;
    let mut rng = rand::thread_rng();
    let jitter = if jitter_span > 0 {
        rng.gen_range(-jitter_span..=jitter_span)
    } else {
        0
    };
    let jittered_ms = (raw_ms as i64).saturating_add(jitter).max(0) as u64;
    Duration::from_millis(jittered_ms.min(max_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dead_letter_when_attempts_reach_cap() {
        assert!(should_dead_letter(5, 0, 0, 5, 72));
        assert!(!should_dead_letter(4, 0, 0, 5, 72));
    }

    #[test]
    fn dead_letter_when_row_exceeds_age_cap() {
        assert!(should_dead_letter(1, 0, 73_i64 * 3600, 5, 72));
        assert!(!should_dead_letter(1, 0, 71_i64 * 3600, 5, 72));
    }

    #[test]
    fn backoff_delay_stays_within_bounds() {
        for attempt in 1..=6 {
            let delay = compute_backoff_delay(attempt, 2_000, 300_000);
            assert!(delay <= Duration::from_millis(300_000));
        }
    }
}
