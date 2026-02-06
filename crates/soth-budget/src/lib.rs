//! SOTH Budget - Token counting, cost calculation, and budget tracking
//!
//! This crate provides:
//! - Token estimation (~4 chars/token heuristic)
//! - Model-specific cost calculation
//! - Spend tracking with persistence
//! - Alert thresholds and notifications
//! - SQLite storage for budget data
//! - LiteLLM-compatible pricing catalog
//! - MCP cost attribution
//! - Cost analytics (trends, anomalies, recommendations)

pub mod alerts;
pub mod analytics;
pub mod cost;
pub mod counter;
pub mod mcp_cost;
pub mod pricing;
pub mod storage;
pub mod tracking;

pub use alerts::{AlertEvaluator, AlertNotifier};
pub use analytics::CostAnalytics;
pub use cost::{CostCalculator, ModelPricing};
pub use counter::TokenCounter;
pub use mcp_cost::McpCostAttributor;
pub use pricing::PricingCatalog;
pub use storage::BudgetStorage;
pub use tracking::{BudgetTracker, SpendTracker};

pub use soth_core::error::{Result, SothError};
pub use soth_core::types::budget::*;
