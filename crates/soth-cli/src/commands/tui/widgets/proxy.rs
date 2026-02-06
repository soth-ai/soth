//! Proxy panel widget

use crate::commands::tui::app::{App, PanelFocus};
use crate::commands::tui::theme::{format_currency, format_number, Theme};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let theme = Theme::get();
    let focused = app.focused_panel == PanelFocus::Proxy;

    let block = Block::default()
        .title(" Proxy ")
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(theme.border_style(focused));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let metrics = match &app.metrics.proxy {
        Some(m) => m,
        None => {
            let loading = Paragraph::new("Loading...")
                .style(theme.muted_style())
                .alignment(Alignment::Center);
            frame.render_widget(loading, inner);
            return;
        }
    };

    // Build content lines
    let mut lines = vec![
        Line::from(vec![
            Span::raw("Requests       "),
            Span::styled(format_number(metrics.total_requests), theme.bold_style()),
        ]),
        Line::from(vec![
            Span::raw("Active Conn.   "),
            Span::styled(
                format_number(metrics.active_connections),
                theme.info_style(),
            ),
        ]),
    ];

    // Add separator
    if inner.width > 10 {
        lines.push(Line::from(Span::styled(
            "\u{2500}".repeat((inner.width as usize).saturating_sub(2)),
            theme.muted_style(),
        )));
    }

    // Provider breakdown
    let mut providers: Vec<_> = metrics.requests_by_provider.iter().collect();
    providers.sort_by(|a, b| b.1.cmp(a.1));

    let max_providers = (inner.height as usize).saturating_sub(6).min(4);
    for (provider, count) in providers.iter().take(max_providers) {
        // Capitalize provider name
        let name = capitalize_first(provider);
        lines.push(Line::from(vec![
            Span::styled(format!("{:<14} ", name), theme.muted_style()),
            Span::styled(format_number(**count), Style::default()),
        ]));
    }

    // Total cost
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::raw("Cost: "),
        Span::styled(
            format_currency(metrics.total_cost_usd),
            theme.success_style(),
        ),
    ]));

    let content = Paragraph::new(lines);
    frame.render_widget(content, inner);
}

fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
    }
}
