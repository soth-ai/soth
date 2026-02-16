//! TUI Dashboard - Terminal UI backed by the SOTH API service
//!
//! Provides real-time monitoring of proxy traffic, policy decisions,
//! PII detections, and budget tracking in the terminal.

mod api;
mod app;
mod event;
mod theme;
mod ui;
mod widgets;

use anyhow::Result;
use clap::Args;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;
use std::io::{self, stdout};
use std::panic;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

pub use app::App;
pub use event::EventHandler;

/// Arguments for the TUI command
#[derive(Args, Debug)]
pub struct TuiArgs {
    /// SOTH API URL
    #[arg(long, default_value = "http://127.0.0.1:3001")]
    pub api_url: String,

    /// Refresh interval in seconds
    #[arg(long, default_value = "2")]
    pub refresh: u64,
}

/// Run the TUI dashboard
pub async fn run(args: TuiArgs) -> Result<()> {
    // Set up panic hook to restore terminal
    let original_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        let _ = restore_terminal();
        original_hook(panic_info);
    }));

    // Initialize terminal
    let terminal = setup_terminal()?;

    // Run the app
    let result = run_app(terminal, args).await;

    // Restore terminal
    restore_terminal()?;

    result
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

fn restore_terminal() -> Result<()> {
    disable_raw_mode()?;
    execute!(stdout(), LeaveAlternateScreen, DisableMouseCapture)?;
    Ok(())
}

async fn run_app(
    mut terminal: Terminal<CrosstermBackend<io::Stdout>>,
    args: TuiArgs,
) -> Result<()> {
    let mut app = App::new(args.api_url.clone());
    let mut event_handler = EventHandler::new(args.refresh);
    let refresh_secs = args.refresh.max(1);
    let hot_interval = Duration::from_secs(refresh_secs);
    let cold_interval = Duration::from_secs((refresh_secs * 2).max(3));
    let mut next_hot_due = Instant::now() + hot_interval;
    let mut next_cold_due = Instant::now() + cold_interval;

    let mut hot_task: Option<JoinHandle<anyhow::Result<api::HotData>>> = Some(spawn_hot_task(
        args.api_url.clone(),
        app.event_seq_cursor(),
        app.cluster_seq_cursor(),
    ));
    let mut cold_task: Option<JoinHandle<anyhow::Result<api::ColdData>>> =
        Some(spawn_cold_task(args.api_url.clone()));
    let mut payload_task: Option<(app::PayloadPart, JoinHandle<Result<String, String>>)> = None;

    loop {
        poll_background_tasks(&mut app, &mut hot_task, &mut cold_task, &mut payload_task).await;

        // Draw UI
        terminal.draw(|frame| ui::render(frame, &mut app))?;

        let maybe_event = tokio::select! {
            event_result = event_handler.next() => Some(event_result?),
            _ = tokio::signal::ctrl_c() => {
                app.should_quit = true;
                None
            }
        };

        if let Some(event) = maybe_event {
            match event {
                event::AppEvent::Tick => {
                    app.on_tick();
                    maybe_schedule_refreshes(
                        &mut app,
                        &args.api_url,
                        &mut hot_task,
                        &mut cold_task,
                        &mut next_hot_due,
                        &mut next_cold_due,
                        hot_interval,
                        cold_interval,
                    );
                }
                event::AppEvent::Key(key) => {
                    app.on_key(key);
                    if let Some((event_id, part)) = app.take_payload_request() {
                        if payload_task.is_none() {
                            payload_task = Some((
                                part,
                                spawn_payload_task(args.api_url.clone(), event_id, part),
                            ));
                        }
                    }
                    if app.take_refresh_request() {
                        if hot_task.is_none() {
                            hot_task = Some(spawn_hot_task(
                                args.api_url.clone(),
                                app.event_seq_cursor(),
                                app.cluster_seq_cursor(),
                            ));
                            next_hot_due = Instant::now() + hot_interval;
                        }
                        if cold_task.is_none() {
                            cold_task = Some(spawn_cold_task(args.api_url.clone()));
                            next_cold_due = Instant::now() + cold_interval;
                        }
                    }
                }
                event::AppEvent::Resize(_, _) => {
                    // Terminal handles resize automatically
                }
                event::AppEvent::FetchData => {
                    maybe_schedule_refreshes(
                        &mut app,
                        &args.api_url,
                        &mut hot_task,
                        &mut cold_task,
                        &mut next_hot_due,
                        &mut next_cold_due,
                        hot_interval,
                        cold_interval,
                    );
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    if let Some(task) = hot_task {
        task.abort();
    }
    if let Some(task) = cold_task {
        task.abort();
    }
    if let Some((_, task)) = payload_task {
        task.abort();
    }

    Ok(())
}

fn maybe_schedule_refreshes(
    app: &mut App,
    api_url: &str,
    hot_task: &mut Option<JoinHandle<anyhow::Result<api::HotData>>>,
    cold_task: &mut Option<JoinHandle<anyhow::Result<api::ColdData>>>,
    next_hot_due: &mut Instant,
    next_cold_due: &mut Instant,
    hot_interval: Duration,
    cold_interval: Duration,
) {
    if !app.auto_refresh_enabled() {
        return;
    }

    let now = Instant::now();
    if hot_task.is_none() && now >= *next_hot_due {
        *hot_task = Some(spawn_hot_task(
            api_url.to_string(),
            app.event_seq_cursor(),
            app.cluster_seq_cursor(),
        ));
        *next_hot_due = now + hot_interval;
    }
    if cold_task.is_none() && now >= *next_cold_due {
        *cold_task = Some(spawn_cold_task(api_url.to_string()));
        *next_cold_due = now + cold_interval;
    }
}

fn spawn_hot_task(
    api_url: String,
    since_event_seq: Option<i64>,
    since_cluster_seq: Option<i64>,
) -> JoinHandle<anyhow::Result<api::HotData>> {
    tokio::spawn(async move { api::fetch_hot(&api_url, since_event_seq, since_cluster_seq).await })
}

fn spawn_cold_task(api_url: String) -> JoinHandle<anyhow::Result<api::ColdData>> {
    tokio::spawn(async move { api::fetch_cold(&api_url).await })
}

fn spawn_payload_task(
    api_url: String,
    event_id: String,
    part: app::PayloadPart,
) -> JoinHandle<Result<String, String>> {
    tokio::spawn(async move {
        api::fetch_event_payload(&api_url, &event_id, part.as_api_part())
            .await
            .map_err(|error| error.to_string())
    })
}

async fn poll_background_tasks(
    app: &mut App,
    hot_task: &mut Option<JoinHandle<anyhow::Result<api::HotData>>>,
    cold_task: &mut Option<JoinHandle<anyhow::Result<api::ColdData>>>,
    payload_task: &mut Option<(app::PayloadPart, JoinHandle<Result<String, String>>)>,
) {
    if hot_task.as_ref().is_some_and(|handle| handle.is_finished()) {
        if let Some(handle) = hot_task.take() {
            match handle.await {
                Ok(Ok(data)) => app.apply_hot_success(data),
                Ok(Err(error)) => app.apply_fetch_error(error.to_string()),
                Err(error) => app.apply_fetch_error(format!("hot fetch task failed: {error}")),
            }
        }
    }

    if cold_task
        .as_ref()
        .is_some_and(|handle| handle.is_finished())
    {
        if let Some(handle) = cold_task.take() {
            match handle.await {
                Ok(Ok(data)) => app.apply_cold_success(data),
                Ok(Err(error)) => app.apply_cold_error(error.to_string()),
                Err(error) => app.apply_cold_error(format!("cold fetch task failed: {error}")),
            }
        }
    }

    if payload_task
        .as_ref()
        .is_some_and(|(_, handle)| handle.is_finished())
    {
        if let Some((part, handle)) = payload_task.take() {
            let result = match handle.await {
                Ok(result) => result,
                Err(error) => Err(format!("payload task failed: {error}")),
            };
            app.apply_payload_result(part, result);
        }
    }
}
