use tokio::sync::mpsc;

use crate::error::ExtensionError;

/// Handle given to each extension for submitting events into the pipeline.
#[derive(Clone)]
pub struct ExtensionHandle {
    event_tx: mpsc::Sender<soth_core::GovernableEvent>,
}

impl ExtensionHandle {
    pub(crate) fn new(event_tx: mpsc::Sender<soth_core::GovernableEvent>) -> Self {
        Self { event_tx }
    }

    /// Submit a governable event for processing through the pipeline.
    pub async fn submit(&self, event: soth_core::GovernableEvent) -> Result<(), ExtensionError> {
        self.event_tx
            .send(event)
            .await
            .map_err(|_| ExtensionError::ChannelClosed)
    }
}
