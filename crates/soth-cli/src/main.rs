//! SOTH CLI entry point.

mod cli_config;
mod command_graph;
mod commands;
mod logging;
mod style;
mod update;

fn main() -> anyhow::Result<()> {
    command_graph::run()
}
