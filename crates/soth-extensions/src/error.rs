use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExtensionError {
    #[error("queue write failed: {0}")]
    QueueWrite(String),

    #[error("migration failed: {0}")]
    Migration(String),

    #[error("install failed: {0}")]
    Install(String),

    #[error("extension error: {0}")]
    Other(String),
}
