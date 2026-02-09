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

    // Show event inspector popup when open.
    if app.event_inspector_open() {
        render_event_inspector_popup(frame, app, theme);
    }

    // Show error popup if there's an error
    if let Some(ref error) = app.error_message {
        render_error_popup(frame, error, theme);
    }
}

/// Render the dashboard tab with all panels
fn render_dashboard(frame: &mut Frame, area: Rect, app: &App) {
    widgets::dashboard::render(frame, area, app);
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

fn render_event_inspector_popup(frame: &mut Frame, app: &App, theme: &Theme) {
    let area = frame.area();
    let popup_width = area.width.saturating_sub(6).min(130);
    let popup_height = area.height.saturating_sub(4).min(34);
    let popup_area = Rect {
        x: (area.width.saturating_sub(popup_width)) / 2,
        y: (area.height.saturating_sub(popup_height)) / 2,
        width: popup_width,
        height: popup_height,
    };

    frame.render_widget(
        Block::default().style(Style::default().bg(Color::Black)),
        popup_area,
    );

    let inspector = app.event_inspector();
    let event = match inspector.event.as_ref() {
        Some(event) => event,
        None => return,
    };

    let block = Block::default()
        .title(format!(
            " Event Inspector [{}] ",
            inspector.active_part.label()
        ))
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(theme.border_style(true));
    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(4),
            Constraint::Length(1),
        ])
        .split(inner);

    let header_lines = vec![
        Line::from(vec![
            Span::styled("id ", theme.muted_style()),
            Span::raw(truncate_to_width(&event.id, layout[0].width as usize - 4)),
        ]),
        Line::from(vec![
            Span::styled("agent ", theme.muted_style()),
            Span::raw(event.agent.name.as_str()),
            Span::raw("  "),
            Span::styled("src ", theme.muted_style()),
            Span::raw(format!("{:?}", event.source)),
            Span::raw("  "),
            Span::styled("status ", theme.muted_style()),
            Span::raw(
                event
                    .status_code
                    .map(|status| status.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            Span::raw("  "),
            Span::styled("lat ", theme.muted_style()),
            Span::raw(
                event
                    .latency_ms
                    .map(|ms| format!("{ms}ms"))
                    .unwrap_or_else(|| "-".to_string()),
            ),
        ]),
        Line::from(vec![
            Span::styled("model ", theme.muted_style()),
            Span::raw(event.model.as_deref().unwrap_or("-")),
            Span::raw("  "),
            Span::styled("tok ", theme.muted_style()),
            Span::raw(
                event
                    .token_count
                    .map(|tokens| tokens.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            Span::raw("  "),
            Span::styled("cost ", theme.muted_style()),
            Span::raw(
                event
                    .cost_usd
                    .map(|cost| format!("${cost:.4}"))
                    .unwrap_or_else(|| "-".to_string()),
            ),
        ]),
    ];
    frame.render_widget(Paragraph::new(header_lines), layout[0]);

    let (payload_text, payload_meta) =
        if let Some(payload) = inspector.payload_for_part(inspector.active_part) {
            let mut text = payload.text.clone();
            if payload.truncated {
                text.push_str("\n\n[truncated for TUI performance]");
            }
            let meta = if payload.truncated {
                format!(
                    "{} chars (showing {})",
                    payload.total_chars,
                    payload.text.chars().count()
                )
            } else {
                format!("{} chars", payload.total_chars)
            };
            (text, meta)
        } else if inspector.loading {
            ("Loading payload...".to_string(), "loading".to_string())
        } else if let Some(error) = inspector.error.as_ref() {
            (format!("Payload load failed: {error}"), "error".to_string())
        } else {
            (
                "Payload not loaded. Press 'p' to fetch full payload for current part.".to_string(),
                "not loaded".to_string(),
            )
        };
    let clipped = clip_text_to_area(&payload_text, layout[1]);
    frame.render_widget(
        Paragraph::new(clipped).style(Style::default().fg(theme.fg)),
        layout[1],
    );

    let footer = Line::from(vec![
        Span::styled("[/]", theme.info_style()),
        Span::styled(": part  ", theme.muted_style()),
        Span::styled("p", theme.info_style()),
        Span::styled(": load payload  ", theme.muted_style()),
        Span::styled("Enter/Esc", theme.info_style()),
        Span::styled(": close  ", theme.muted_style()),
        Span::styled(payload_meta, theme.muted_style()),
    ]);
    frame.render_widget(Paragraph::new(footer), layout[2]);
}

fn truncate_to_width(input: &str, width: usize) -> String {
    if input.chars().count() <= width {
        return input.to_string();
    }
    if width <= 1 {
        return "…".to_string();
    }
    let mut out = input
        .chars()
        .take(width.saturating_sub(1))
        .collect::<String>();
    out.push('…');
    out
}

fn clip_text_to_area(text: &str, area: Rect) -> String {
    let max_lines = area.height as usize;
    if max_lines == 0 {
        return String::new();
    }
    let max_width = area.width.saturating_sub(1) as usize;
    if max_width == 0 {
        return String::new();
    }

    let mut out_lines = Vec::with_capacity(max_lines);
    for line in text.lines() {
        if out_lines.len() >= max_lines {
            break;
        }
        if line.chars().count() <= max_width {
            out_lines.push(line.to_string());
            continue;
        }
        let clipped = line
            .chars()
            .take(max_width.saturating_sub(1))
            .collect::<String>()
            + "…";
        out_lines.push(clipped);
    }

    if out_lines.is_empty() {
        String::new()
    } else {
        out_lines.join("\n")
    }
}
