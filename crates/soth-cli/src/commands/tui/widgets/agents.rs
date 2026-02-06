//! Agents list widget

use crate::commands::tui::app::App;
use crate::commands::tui::theme::{format_number, truncate, Theme, CIRCLE_FILLED};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let theme = Theme::get();

    let block = Block::default()
        .title(format!(" Agents ({}) ", app.agents.len()))
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(theme.border_style(false));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.agents.is_empty() {
        let empty = Paragraph::new("No agents detected yet")
            .style(theme.muted_style())
            .alignment(Alignment::Center);
        frame.render_widget(empty, inner);
        return;
    }

    // Calculate visible range
    let visible_height = inner.height as usize;
    let total = app.agents.len();
    let offset = app.agents_scroll.offset.min(total.saturating_sub(1));

    // Build list items
    let items: Vec<ListItem> = app
        .agents
        .iter()
        .skip(offset)
        .take(visible_height)
        .map(|agent| {
            // Agent name with version
            let name_version = if let Some(ref version) = agent.version {
                format!("{} v{}", agent.name, version)
            } else {
                agent.name.clone()
            };
            let name_display = truncate(&name_version, 25);

            // Event count
            let count = format_number(agent.event_count);

            // Last seen (time only)
            let last_seen = agent
                .last_seen
                .split('T')
                .nth(1)
                .and_then(|t| t.split('.').next())
                .unwrap_or(&agent.last_seen);

            // Servers
            let servers = if agent.servers.len() <= 2 {
                agent.servers.join(", ")
            } else {
                format!(
                    "{}, {} +{}",
                    agent.servers[0],
                    agent.servers[1],
                    agent.servers.len() - 2
                )
            };
            let servers = truncate(&servers, 20);

            // Build the line
            let line = Line::from(vec![
                Span::styled(format!("{} ", CIRCLE_FILLED), theme.success_style()),
                Span::styled(format!("{:<25}", name_display), theme.bold_style()),
                Span::raw(" "),
                Span::styled(format!("{:>8} events", count), theme.muted_style()),
                Span::raw("  "),
                Span::styled(format!("last: {}", last_seen), theme.muted_style()),
                Span::raw("  "),
                Span::styled(servers, theme.muted_style()),
            ]);

            ListItem::new(line)
        })
        .collect();

    // Create list with selection
    let list = List::new(items).highlight_style(theme.highlight_style());

    // Calculate selection within visible range
    let selected = if app.agents_scroll.selected >= offset {
        Some(app.agents_scroll.selected - offset)
    } else {
        None
    };

    let mut state = ListState::default().with_selected(selected);
    frame.render_stateful_widget(list, inner, &mut state);
}
