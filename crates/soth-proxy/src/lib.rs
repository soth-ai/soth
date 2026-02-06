//! SOTH Proxy - Transport handling and request pipeline
//!
//! This crate provides:
//! - Multiple transport implementations (stdio, SSE, HTTP)
//! - Tower-style middleware pipeline for message processing
//! - Session management
//! - MCP method routing
//!
//! # Architecture
//!
//! ```text
//! Request → Transport → Pipeline → Forward → Upstream
//!                         ↓
//!                    [Identity]
//!                    [Policy]
//!                    [Observe]
//!                    [Budget]
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use soth_proxy::pipeline::{Pipeline, PipelineBuilder, ObserveLayer, PolicyLayer, BudgetLayer};
//! use soth_proxy::transport::{TransportBuilder, TransportType};
//!
//! // Build the pipeline
//! let pipeline = PipelineBuilder::new()
//!     .layer(ObserveLayer::new(Default::default()))
//!     .layer(PolicyLayer::new(Default::default()))
//!     .layer(BudgetLayer::new(Default::default()))
//!     .build();
//!
//! // Create transport
//! let mut transport = TransportBuilder::new(TransportType::Stdio)
//!     .buffer_size(1000)
//!     .build();
//! ```

pub mod circuit_breaker;
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
    BudgetLayer, ForwardLayer, IdentityLayer, ObserveLayer, Pipeline, PipelineBuilder, PolicyLayer,
};
pub use protocol::{JsonRpcError, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId};
pub use rate_limit::{RateLimitConfig, RateLimitResult, RateLimiter};
pub use router::Router;
pub use session::{Session, SessionManager, SessionStats};
pub use shutdown::{ConnectionGuard, ShutdownCoordinator, ShutdownResult};
pub use transport::{Transport, TransportBuilder, TransportConfig, TransportType};
