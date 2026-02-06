//! Budget panel widget

use crate::commands::tui::app::{App, PanelFocus};
use crate::commands::tui::theme::{format_currency, format_number, format_percent, Theme};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Gauge, Paragraph};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let theme = Theme::get();
    let focused = app.focused_panel == PanelFocus::Budget;

    let block = Block::default()
        .title(" Budget ")
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(theme.border_style(focused));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let metrics = match &app.metrics.budget {
        Some(m) => m,
        None => {
            let loading = Paragraph::new("Loading...")
                .style(theme.muted_style())
                .alignment(Alignment::Center);
            frame.render_widget(loading, inner);
            return;
        }
    };

    // Split inner area for content and progress bar
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // Main stats
            Constraint::Length(2), // Progress bar
            Constraint::Min(1),    // Model breakdown
        ])
        .split(inner);

    // Main stats
    let stats_lines = vec![
        Line::from(vec![
            Span::raw("Tokens         "),
            Span::styled(format_number(metrics.total_tokens), theme.bold_style()),
        ]),
        Line::from(vec![
            Span::raw("Cost           "),
            Span::styled(format_currency(metrics.total_cost_usd), theme.success_style()),
        ]),
        Line::from(vec![
            Span::raw("Daily Limit    "),
            Span::styled(
                metrics
                    .daily_limit_usd
                    .map(|l| format_currency(l))
                    .unwrap_or_else(|| "None".to_string()),
                theme.muted_style(),
            ),
        ]),
    ];

    frame.render_widget(Paragraph::new(stats_lines), chunks[0]);

    // Progress bar (if daily limit is set)
    if let Some(limit) = metrics.daily_limit_usd {
        if limit > 0.0 {
            let ratio = (metrics.total_cost_usd / limit).min(1.0);
            let percent = ratio * 100.0;

            let gauge_style = if percent >= 90.0 {
                Style::default().fg(theme.error)
            } else if percent >= 75.0 {
                Style::default().fg(theme.warning)
            } else {
                Style::default().fg(theme.success)
            };

            let gauge = Gauge::default()
                .gauge_style(gauge_style)
                .ratio(ratio)
                .label(format_percent(percent));

            frame.render_widget(gauge, chunks[1]);
        }
    }

    // Model breakdown
    if !metrics.cost_by_model.is_empty() && chunks[2].height > 1 {
        let mut lines = vec![Line::from(Span::styled(
            "By Model:",
            theme.muted_style(),
        ))];

        let mut models: Vec<_> = metrics.cost_by_model.iter().collect();
        models.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));

        let max_models = (chunks[2].height as usize).saturating_sub(1).min(4);
        for (model, cost) in models.iter().take(max_models) {
            let name = truncate_model_name(model, 12);
            lines.push(Line::from(vec![
                Span::styled(format!("  {:<12} ", name), theme.muted_style()),
                Span::styled(format_currency(**cost), Style::default()),
            ]));
        }

        frame.render_widget(Paragraph::new(lines), chunks[2]);
    }
}

fn truncate_model_name(name: &str, max_len: usize) -> String {
    if name.len() <= max_len {
        name.to_string()
    } else {
        format!("{}\u{2026}", &name[..max_len - 1])
    }
}
