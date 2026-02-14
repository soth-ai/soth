//! Proxy API command

use crate::cli_config;
use crate::style;
use soth_core::event_logger::default_event_log_write_path;
use soth_dashboard::server::DashboardServer;
use soth_dashboard::DashboardState;
use std::path::PathBuf;

/// Run `soth proxy api start`.
pub async fn run_start(
    port: Option<u16>,
    config_path: Option<PathBuf>,
    quiet: bool,
) -> anyhow::Result<()> {
    let config = cli_config::load_effective_config(config_path.as_ref(), None)?;
    let api_port = port.unwrap_or(config.dashboard.port);
    let event_db_path = default_event_log_write_path().ok();

    let state = if let Some(path) = event_db_path.as_deref() {
        DashboardState::new_with_rollup_warm_start(path)
    } else {
        DashboardState::new()
    };

    let server = if let Some(path) = event_db_path {
        DashboardServer::new(state, api_port).with_event_store_path(path)
    } else {
        DashboardServer::new(state, api_port).with_event_store()
    };

    if !quiet {
        style::header("SOTH API");
        style::kv("HTTP", &format!("http://127.0.0.1:{api_port}"));
        style::kv(
            "WebSocket",
            &format!("ws://127.0.0.1:{api_port}/api/events/stream"),
        );
        style::info("Press Ctrl+C to stop.");
        println!();
    }

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let _ = shutdown_tx.send(());
    });

    server
        .run_with_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .await?;

    if !quiet {
        style::success("API stopped.");
    }

    Ok(())
}
