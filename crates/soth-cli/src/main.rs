//! SOTH ops CLI entry point.

mod cli_config;
mod command_graph;
mod commands;
mod logging;
pub mod style;

pub use command_graph::{
    AuditCommands, BudgetCommands, ConfigCommands, ConfigRegistryCommands, IdentityCommands,
    PolicyCommands,
};

fn main() -> anyhow::Result<()> {
    command_graph::run_ops()
}
