use thiserror::Error;

pub type Result<T> = std::result::Result<T, SothError>;

#[derive(Debug, Error)]
pub enum SothError {
    #[error("{0}")]
    Message(String),
}
