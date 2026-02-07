//! SOTH Proxy - Transport handling and request pipeline
//!
//! This crate provides:
//! - Forward proxy transport/runtime
//! - Tower-style middleware pipeline for message processing
//! - Session management
//! - MCP method routing
//!
//! # Architecture
//!
//! ```text
//! Request → Proxy Transport → Enforcement/Observation
//! ```

pub mod circuit_breaker;
pub mod enforcement;
pub mod error;
pub mod metrics;
pub mod pipeline;
pub mod protocol;
pub mod providers;
pub mod rate_limit;
pub mod router;
pub mod session;
pub mod shutdown;
pub mod transport;

pub use circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitBreakerResult};
pub use error::{ProxyError, Result};
pub use pipeline::{
    BudgetLayer, IdentityLayer, ObserveLayer, Pipeline, PipelineBuilder, PolicyLayer,
};
pub use protocol::{JsonRpcError, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId};
pub use rate_limit::{RateLimitConfig, RateLimitResult, RateLimiter};
pub use router::Router;
pub use session::{Session, SessionManager, SessionStats};
pub use shutdown::{ConnectionGuard, ShutdownCoordinator, ShutdownResult};
