//! Pipeline middleware for MCP message processing
//!
//! Implements Tower-style middleware layers for:
//! - Identity verification
//! - Policy enforcement
//! - Request forwarding
//! - Observation/logging
//! - Budget tracking

pub mod middleware;
pub mod identity;
pub mod policy;
pub mod forward;
pub mod observe;
pub mod budget;

pub use middleware::{Pipeline, PipelineBuilder};
pub use identity::IdentityLayer;
pub use policy::PolicyLayer;
pub use forward::ForwardLayer;
pub use observe::ObserveLayer;
pub use budget::BudgetLayer;
