//! Main UI layout rendering

use crate::commands::tui::app::{App, Tab};
use crate::commands::tui::theme::Theme;
use crate::commands::tui::widgets;
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};

/// Render the entire UI
pub fn render(frame: &mut Frame, app: &mut App) {
    let theme = Theme::get();

    // Main layout: header, content, status bar
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header with tabs
            Constraint::Min(10),   // Content
            Constraint::Length(1), // Status bar
        ])
        .split(frame.area());

    // Render header
    widgets::header::render(frame, chunks[0], app);

    // Render content based on active tab
    match app.active_tab {
        Tab::Dashboard => render_dashboard(frame, chunks[1], app),
        Tab::Events => widgets::events::render(frame, chunks[1], app),
        Tab::Agents => widgets::agents::render(frame, chunks[1], app),
        Tab::Help => widgets::help::render(frame, chunks[1]),
    }

    // Render status bar
    widgets::status_bar::render(frame, chunks[2], app);

    // Show error popup if there's an error
    if let Some(ref error) = app.error_message {
        render_error_popup(frame, error, theme);
    }
}

/// Render the dashboard tab with all panels
fn render_dashboard(frame: &mut Frame, area: Rect, app: &App) {
    // Two rows of panels
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Top row: Identity, Policy, Proxy
    let top_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(34),
            Constraint::Percentage(33),
        ])
        .split(rows[0]);

    // Bottom row: Observe, Budget, Summary
    let bottom_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(34),
            Constraint::Percentage(33),
        ])
        .split(rows[1]);

    // Render panels
    widgets::identity::render(frame, top_cols[0], app);
    widgets::policy::render(frame, top_cols[1], app);
    widgets::proxy::render(frame, top_cols[2], app);
    widgets::observe::render(frame, bottom_cols[0], app);
    widgets::budget::render(frame, bottom_cols[1], app);
    widgets::summary::render(frame, bottom_cols[2], app);
}

/// Render an error popup
fn render_error_popup(frame: &mut Frame, error: &str, theme: &Theme) {
    let area = frame.area();

    // Center the popup
    let popup_width = 60.min(area.width.saturating_sub(4));
    let popup_height = 5;
    let popup_area = Rect {
        x: (area.width - popup_width) / 2,
        y: (area.height - popup_height) / 2,
        width: popup_width,
        height: popup_height,
    };

    // Clear the background
    frame.render_widget(
        Block::default().style(Style::default().bg(Color::Black)),
        popup_area,
    );

    let truncated_error = if error.len() > (popup_width as usize - 4) {
        format!("{}...", &error[..(popup_width as usize - 7)])
    } else {
        error.to_string()
    };

    let popup = Paragraph::new(truncated_error)
        .style(theme.error_style())
        .block(
            Block::default()
                .title(" Error ")
                .title_style(theme.error_style().add_modifier(Modifier::BOLD))
                .borders(Borders::ALL)
                .border_style(theme.error_style()),
        )
        .alignment(Alignment::Center);

    frame.render_widget(popup, popup_area);
}
