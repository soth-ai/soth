//! Storage backends for observation logs

pub mod jsonl;

#[cfg(feature = "sqlite")]
pub mod sqlite;
