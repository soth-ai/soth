//! Pipeline middleware for MCP message processing
//!
//! Implements Tower-style middleware layers for:
//! - Identity verification
//! - Policy enforcement
//! - Request forwarding
//! - Observation/logging
//! - Budget tracking

pub mod budget;
pub mod identity;
pub mod middleware;
pub mod observe;
pub mod policy;

pub use budget::BudgetLayer;
pub use identity::IdentityLayer;
pub use middleware::{Pipeline, PipelineBuilder};
pub use observe::ObserveLayer;
pub use policy::PolicyLayer;
