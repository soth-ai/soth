//! SOTH Test Utilities
//!
//! This crate provides testing utilities for SOTH:
//! - Mock MCP server for fast, in-process testing
//! - Pre-built test scenarios (policy blocked, PII detection, etc.)
//! - Overhead measurement utilities
//! - Test fixtures and helpers

pub mod mock_mcp;
pub mod overhead;
pub mod scenarios;

pub use mock_mcp::{LatencyConfig, MockMcpServer, MockTool};
pub use overhead::{measure_overhead, LatencyStats, OverheadMeasurement};
pub use scenarios::*;
