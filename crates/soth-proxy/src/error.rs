use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("database error: {0}")]
    Database(String),
    #[error("bundle error: {0}")]
    Bundle(String),
    #[error("mitm error: {0}")]
    Mitm(String),
}
