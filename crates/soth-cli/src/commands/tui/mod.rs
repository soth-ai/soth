//! TUI Dashboard - Terminal user interface for SOTH monitoring
//!
//! Provides real-time monitoring of proxy traffic, policy decisions,
//! PII detections, and budget tracking in the terminal.

mod app;
mod api;
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

pub use app::App;
pub use event::EventHandler;

/// Arguments for the TUI command
#[derive(Args, Debug)]
pub struct TuiArgs {
    /// Dashboard API URL
    #[arg(long, default_value = "http://localhost:3001")]
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

    // Initial fetch
    app.fetch_all(&args.api_url).await;

    loop {
        // Draw UI
        terminal.draw(|frame| ui::render(frame, &mut app))?;

        // Handle events
        match event_handler.next().await? {
            event::AppEvent::Tick => {
                app.on_tick();
            }
            event::AppEvent::Key(key) => {
                app.on_key(key);
            }
            event::AppEvent::Resize(_, _) => {
                // Terminal handles resize automatically
            }
            event::AppEvent::FetchData => {
                app.fetch_all(&args.api_url).await;
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}
