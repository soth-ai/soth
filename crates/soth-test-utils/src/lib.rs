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

pub use mock_mcp::{MockMcpServer, MockTool, LatencyConfig};
pub use overhead::{measure_overhead, OverheadMeasurement, LatencyStats};
pub use scenarios::*;
