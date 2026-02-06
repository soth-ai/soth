//! SOTH Observe - Observability, PII detection, and Merkle audit
//!
//! This crate provides:
//! - PII detection with regex patterns (SSN, email, credit card, phone)
//! - Merkle tree for tamper-proof audit logging
//! - Async logging with channel-based buffering
//! - JSONL and optional SQLite storage backends

pub mod logging;
pub mod merkle;
pub mod pii;
pub mod storage;

pub use logging::{AsyncWriter, LoggerConfig, ObservationLogger};
pub use merkle::{MerkleProof, MerkleTree, TransparencyLog};
pub use pii::{PiiDetector, PiiMatch, PiiRedactor};
pub use storage::jsonl::JsonlStorage;

#[cfg(feature = "sqlite")]
pub use storage::sqlite::SqliteStorage;

pub use soth_core::error::{Result, SothError};
pub use soth_core::types::observation::*;
