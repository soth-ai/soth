use thiserror::Error;

#[derive(Debug, Error)]
pub enum HistorianError {
    #[error("discovery error: {0}")]
    Discovery(String),

    #[error("reader error ({tool}): {message}")]
    Reader { tool: String, message: String },

    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parse error: {0}")]
    Json(String),

    #[error("JSON serde error: {0}")]
    JsonSerde(#[from] serde_json::Error),

    #[error("extension error: {0}")]
    Extension(#[from] soth_extensions::ExtensionError),

    #[error("dedup error: {0}")]
    Dedup(String),

    #[error("backfill error: {0}")]
    Backfill(String),

    #[error("watch error: {0}")]
    Watch(String),

    #[error("already running")]
    AlreadyRunning,

    #[error("not running")]
    NotRunning,
}

/// Alias used in reader trait signatures.
pub type ReaderError = HistorianError;
