//! Events feed widget

use crate::commands::tui::app::App;
use crate::commands::tui::theme::{
    format_currency, format_number, truncate, Theme, ARROW_LEFT, ARROW_RIGHT, CHECK, CROSS,
};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use soth_core::types::WrapDirection;

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let theme = Theme::get();

    let block = Block::default()
        .title(format!(
            " Events ({}) [filter:{}] ",
            app.filtered_events_len(),
            app.event_filter_label()
        ))
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(theme.border_style(false));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let total = app.filtered_events_len();
    if total == 0 {
        let empty = Paragraph::new("No events for current filter")
            .style(theme.muted_style())
            .alignment(Alignment::Center);
        frame.render_widget(empty, inner);
        return;
    }

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(4), Constraint::Length(4)])
        .split(inner);
    let list_area = layout[0];
    let detail_area = layout[1];

    // Calculate visible range
    let visible_height = list_area.height as usize;
    let offset = app.events_scroll.offset.min(total.saturating_sub(1));
    let selected_abs = app.events_scroll.selected.min(total.saturating_sub(1));
    let visible_event_indices = app.filtered_event_indices_window(offset, visible_height);

    // Build list items
    let items: Vec<ListItem> = visible_event_indices
        .iter()
        .filter_map(|event_idx| app.events.get(*event_idx))
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
    let selected = if selected_abs >= offset {
        Some(selected_abs - offset)
    } else {
        None
    };

    let mut state = ListState::default().with_selected(selected);
    frame.render_stateful_widget(list, list_area, &mut state);

    // Render scroll indicator if needed
    if total > visible_height {
        render_scroll_indicator(frame, list_area, offset, total, visible_height, theme);
    }

    // Detail panel for selected event
    if let Some(event) = app.cloned_filtered_event(selected_abs) {
        let method_tool = if let Some(ref tool) = event.tool_name {
            format!("{}/{}", event.server_name, tool)
        } else if let Some(ref method) = event.method {
            method.clone()
        } else {
            "-".to_string()
        };
        let status = event
            .status_code
            .map(|status| status.to_string())
            .unwrap_or_else(|| "-".to_string());
        let tokens = event
            .token_count
            .map(format_number)
            .unwrap_or_else(|| "-".to_string());
        let latency = event
            .latency_ms
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "-".to_string());
        let cost = event
            .cost_usd
            .map(format_currency)
            .unwrap_or_else(|| "-".to_string());
        let provider = event.provider.as_deref().unwrap_or("-");
        let model = event.model.as_deref().unwrap_or("-");

        let detail = vec![
            Line::from(vec![
                Span::styled("src ", theme.muted_style()),
                Span::raw(format!("{:?}", event.source)),
                Span::raw("  "),
                Span::styled("provider ", theme.muted_style()),
                Span::raw(provider),
                Span::raw("  "),
                Span::styled("status ", theme.muted_style()),
                Span::raw(status),
                Span::raw("  "),
                Span::styled("lat ", theme.muted_style()),
                Span::raw(latency),
            ]),
            Line::from(vec![
                Span::styled("op ", theme.muted_style()),
                Span::raw(truncate(&method_tool, 28)),
                Span::raw("  "),
                Span::styled("model ", theme.muted_style()),
                Span::raw(truncate(model, 18)),
                Span::raw("  "),
                Span::styled("tok ", theme.muted_style()),
                Span::raw(tokens),
                Span::raw("  "),
                Span::styled("cost ", theme.muted_style()),
                Span::raw(cost),
            ]),
            Line::from(vec![
                Span::styled("hint ", theme.muted_style()),
                Span::raw(truncate(
                    event
                        .request_preview
                        .as_deref()
                        .or(event.response_preview.as_deref())
                        .or(event.content_preview.as_deref())
                        .unwrap_or("no preview"),
                    detail_area.width.saturating_sub(6) as usize,
                )),
            ]),
        ];

        frame.render_widget(Paragraph::new(detail), detail_area);
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
