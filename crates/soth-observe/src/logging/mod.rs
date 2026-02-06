//! Async logging module

mod writer;

pub use writer::{AsyncWriter, LoggerConfig, ObservationLogger};
