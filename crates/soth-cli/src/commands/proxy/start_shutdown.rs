//! Shutdown helpers for proxy start command.

use crate::commands::proxy::system;
use crate::style;
use soth_core::config::SothConfig;
use soth_core::EventLogger;
use std::time::Duration;
use tokio::task::JoinHandle;

pub(crate) async fn shutdown_retention_runtime(
    shutdown_tx: &mut Option<tokio::sync::oneshot::Sender<()>>,
    task: &mut Option<JoinHandle<()>>,
    timeout_budget: Duration,
) {
    if let Some(tx) = shutdown_tx.take() {
        let _ = tx.send(());
    }

    if let Some(mut handle) = task.take() {
        match tokio::time::timeout(timeout_budget, &mut handle).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!("Retention task join error: {}", error);
            }
            Err(_) => {
                handle.abort();
                tracing::warn!("Retention task shutdown timed out; aborted task.");
            }
        }
    }
}

pub(crate) async fn shutdown_fd_monitor_runtime(
    shutdown_tx: &mut Option<tokio::sync::oneshot::Sender<()>>,
    task: &mut Option<JoinHandle<()>>,
    timeout_budget: Duration,
) {
    if let Some(tx) = shutdown_tx.take() {
        let _ = tx.send(());
    }

    if let Some(mut handle) = task.take() {
        match tokio::time::timeout(timeout_budget, &mut handle).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!("FD monitor task join error: {}", error);
            }
            Err(_) => {
                handle.abort();
                tracing::warn!("FD monitor task shutdown timed out; aborted task.");
            }
        }
    }
}

pub(crate) async fn shutdown_cloud_runtime(
    shutdown_tx: &mut Option<tokio::sync::oneshot::Sender<()>>,
    task: &mut Option<JoinHandle<()>>,
    timeout_budget: Duration,
) {
    if let Some(tx) = shutdown_tx.take() {
        let _ = tx.send(());
    }

    if let Some(mut handle) = task.take() {
        match tokio::time::timeout(timeout_budget, &mut handle).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!("Cloud pull task join error: {}", error);
            }
            Err(_) => {
                handle.abort();
                tracing::warn!("Cloud pull task shutdown timed out; aborted task.");
            }
        }
    }
}

pub(crate) async fn shutdown_collector_runtime(
    shutdown_tx: &mut Option<tokio::sync::oneshot::Sender<()>>,
    task: &mut Option<JoinHandle<()>>,
    timeout_budget: Duration,
) {
    if let Some(tx) = shutdown_tx.take() {
        let _ = tx.send(());
    }

    if let Some(mut handle) = task.take() {
        match tokio::time::timeout(timeout_budget, &mut handle).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!("Collector task join error: {}", error);
            }
            Err(_) => {
                handle.abort();
                tracing::warn!("Collector task shutdown timed out; aborted task.");
            }
        }
    }
}

pub(crate) fn runtime_shutdown_timeout(config: &SothConfig) -> Duration {
    config
        .server
        .graceful_shutdown
        .max(Duration::from_secs(2))
        .min(Duration::from_secs(20))
}

pub(crate) async fn flush_local_event_buffers(
    event_logger: &mut Option<EventLogger>,
    timeout_budget: Duration,
    quiet: bool,
) {
    let Some(logger) = event_logger.take() else {
        return;
    };

    let flush_logger = logger.clone();
    match tokio::time::timeout(
        timeout_budget,
        tokio::task::spawn_blocking(move || flush_logger.flush()),
    )
    .await
    {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => {
            if !quiet {
                style::warning(&format!("Failed to flush local event logger: {}", error));
            }
        }
        Ok(Err(error)) => {
            if !quiet {
                style::warning(&format!("Event logger flush task join error: {}", error));
            }
        }
        Err(_) => {
            if !quiet {
                style::warning("Timed out flushing local event logger before shutdown.");
            }
        }
    }

    let close_logger = logger.clone();
    match tokio::time::timeout(
        timeout_budget,
        tokio::task::spawn_blocking(move || close_logger.close()),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            if !quiet {
                style::warning(&format!("Event logger close task join error: {}", error));
            }
        }
        Err(_) => {
            if !quiet {
                style::warning("Timed out closing local event logger; continuing shutdown.");
            }
        }
    }
}

pub(crate) async fn disable_system_proxy_after_run(quiet: bool) {
    if let Err(error) = system::disable_quiet().await {
        if !quiet {
            style::warning(&format!(
                "Failed to disable system proxy automatically: {}",
                error
            ));
        }
    }
}

pub(crate) fn is_expected_shutdown_transport_error(error: &anyhow::Error) -> bool {
    let text = error.to_string().to_ascii_lowercase();
    (text.contains("transport error") && text.contains("io error"))
        || text.contains("operation canceled")
        || text.contains("broken pipe")
        || text.contains("connection closed")
}
