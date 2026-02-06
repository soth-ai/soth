//! Events feed widget

use crate::commands::tui::app::App;
use crate::commands::tui::theme::{truncate, Theme, ARROW_LEFT, ARROW_RIGHT, CHECK, CROSS};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};
use soth_core::types::WrapDirection;

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let theme = Theme::get();

    let block = Block::default()
        .title(format!(" Events ({}) ", app.events.len()))
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(theme.border_style(false));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.events.is_empty() {
        let empty = ratatui::widgets::Paragraph::new("No events yet")
            .style(theme.muted_style())
            .alignment(Alignment::Center);
        frame.render_widget(empty, inner);
        return;
    }

    // Calculate visible range
    let visible_height = inner.height as usize;
    let total = app.events.len();
    let offset = app.events_scroll.offset.min(total.saturating_sub(1));

    // Build list items
    let items: Vec<ListItem> = app
        .events
        .iter()
        .skip(offset)
        .take(visible_height)
        .map(|event| {
            // Time (HH:MM:SS)
            let time = event.timestamp.format("%H:%M:%S").to_string();

            // Direction arrow
            let (arrow, arrow_style) = match event.direction {
                WrapDirection::In => (ARROW_RIGHT, theme.info_style()),
                WrapDirection::Out => (ARROW_LEFT, theme.success_style()),
            };

            // Agent (truncated)
            let agent = truncate(&event.agent.name, 12);

            // Method/Tool
            let method_tool = if let Some(ref tool) = event.tool_name {
                format!("{}/{}", event.server_name, tool)
            } else if let Some(ref method) = event.method {
                method.clone()
            } else {
                "-".to_string()
            };
            let method_tool = truncate(&method_tool, 20);

            // Status
            let (status_icon, status_style) = match event.policy_allowed {
                Some(true) => (CHECK, theme.success_style()),
                Some(false) => (CROSS, theme.error_style()),
                None => ("-", theme.muted_style()),
            };

            // Latency
            let latency = event
                .latency_ms
                .map(|ms| format!("{}ms", ms))
                .unwrap_or_else(|| "-".to_string());

            // Build the line
            let line = Line::from(vec![
                Span::styled(time, theme.muted_style()),
                Span::raw(" "),
                Span::styled(arrow, arrow_style),
                Span::raw(" "),
                Span::styled(format!("{:<12}", agent), Style::default()),
                Span::raw(" "),
                Span::styled(format!("{:<20}", method_tool), theme.muted_style()),
                Span::raw(" "),
                Span::styled(status_icon, status_style),
                Span::raw(" "),
                Span::styled(format!("{:>6}", latency), theme.muted_style()),
            ]);

            ListItem::new(line)
        })
        .collect();

    // Create list with selection
    let list = List::new(items).highlight_style(theme.highlight_style());

    // Calculate selection within visible range
    let selected = if app.events_scroll.selected >= offset {
        Some(app.events_scroll.selected - offset)
    } else {
        None
    };

    let mut state = ListState::default().with_selected(selected);
    frame.render_stateful_widget(list, inner, &mut state);

    // Render scroll indicator if needed
    if total > visible_height {
        render_scroll_indicator(frame, inner, offset, total, visible_height, theme);
    }
}

fn render_scroll_indicator(
    frame: &mut Frame,
    area: Rect,
    offset: usize,
    total: usize,
    visible: usize,
    theme: &Theme,
) {
    if area.width < 3 {
        return;
    }

    let scrollbar_height = area.height.saturating_sub(2) as usize;
    if scrollbar_height == 0 {
        return;
    }

    // Calculate thumb position and size
    let thumb_size = ((visible as f64 / total as f64) * scrollbar_height as f64)
        .max(1.0)
        .min(scrollbar_height as f64) as usize;
    let thumb_pos = ((offset as f64 / total as f64) * scrollbar_height as f64) as usize;

    // Draw scrollbar on the right edge
    for i in 0..scrollbar_height {
        let char = if i >= thumb_pos && i < thumb_pos + thumb_size {
            "\u{2588}" // █
        } else {
            "\u{2591}" // ░
        };

        let scroll_area = Rect {
            x: area.x + area.width - 1,
            y: area.y + 1 + i as u16,
            width: 1,
            height: 1,
        };

        frame.render_widget(
            ratatui::widgets::Paragraph::new(char).style(theme.muted_style()),
            scroll_area,
        );
    }
}
