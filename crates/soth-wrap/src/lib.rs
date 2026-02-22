//! Standalone MCP wrap runtime.

mod agent_detect;
mod config;
mod enforcement;
mod runtime;

pub use runtime::{run, WrapArgs};
