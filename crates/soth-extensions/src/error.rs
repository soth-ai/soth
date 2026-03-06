use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExtensionError {
    #[error("extension channel closed")]
    ChannelClosed,

    #[error("extension not started")]
    NotStarted,

    #[error("extension already started")]
    AlreadyStarted,

    #[error("no extensions registered")]
    NoExtensions,

    #[error("extension error: {0}")]
    Other(String),
}
