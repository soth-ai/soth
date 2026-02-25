use thiserror::Error;

pub type Result<T> = std::result::Result<T, SothError>;

#[derive(Debug, Error)]
pub enum SothError {
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("policy error: {0}")]
    Policy(String),
    #[error("policy compilation error: {0}")]
    PolicyCompilation(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Message(String),
}
