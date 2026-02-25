use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use soth_telemetry::{SinkError, TelemetrySink, TransmittedBatch};

use super::outbox::TelemetryOutbox;

#[derive(Clone)]
pub struct SyncTelemetrySink {
    outbox: Option<Arc<TelemetryOutbox>>,
}

impl SyncTelemetrySink {
    pub fn new(outbox: Arc<TelemetryOutbox>) -> Self {
        Self {
            outbox: Some(outbox),
        }
    }

    pub fn disabled() -> Self {
        Self { outbox: None }
    }

    pub fn enqueue_batch(&self, batch: TransmittedBatch) -> Result<()> {
        match &self.outbox {
            Some(outbox) => outbox.enqueue(batch),
            None => Ok(()),
        }
    }
}

#[async_trait]
impl TelemetrySink for SyncTelemetrySink {
    async fn send(&self, batch: TransmittedBatch) -> std::result::Result<(), SinkError> {
        self.enqueue_batch(batch)
            .map_err(|error| SinkError::rejected(error.to_string()))
    }
}
