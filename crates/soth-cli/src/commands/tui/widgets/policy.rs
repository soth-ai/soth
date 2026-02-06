//! Policy panel widget

use crate::commands::tui::app::{App, PanelFocus};
use crate::commands::tui::theme::{format_number, format_percent, truncate, Theme, CHECK, CROSS};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let theme = Theme::get();
    let focused = app.focused_panel == PanelFocus::Policy;

    let block = Block::default()
        .title(" Policy ")
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(theme.border_style(focused));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let metrics = match &app.metrics.policy {
        Some(m) => m,
        None => {
            let loading = Paragraph::new("Loading...")
                .style(theme.muted_style())
                .alignment(Alignment::Center);
            frame.render_widget(loading, inner);
            return;
        }
    };

    // Calculate cache hit rate
    let total_cache = metrics.cache_hits + metrics.cache_misses;
    let cache_rate = if total_cache > 0 {
        (metrics.cache_hits as f64 / total_cache as f64) * 100.0
    } else {
        0.0
    };

    // Build content lines
    let mut lines = vec![
        Line::from(vec![
            Span::raw("Evaluations    "),
            Span::styled(format_number(metrics.evaluations), theme.bold_style()),
        ]),
        Line::from(vec![
            Span::styled(format!("{} ", CHECK), theme.success_style()),
            Span::raw("Allowed      "),
            Span::styled(format_number(metrics.allowed), theme.success_style()),
        ]),
        Line::from(vec![
            Span::styled(format!("{} ", CROSS), theme.error_style()),
            Span::raw("Denied       "),
            Span::styled(format_number(metrics.denied), theme.error_style()),
        ]),
        Line::from(vec![
            Span::raw("Cache Hit      "),
            Span::styled(format_percent(cache_rate), theme.info_style()),
        ]),
    ];

    // Add recent denials if space allows
    if inner.height > 6 && !metrics.recent_denials.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Recent Denials:",
            theme.muted_style(),
        )));

        let max_denials = (inner.height as usize).saturating_sub(7).min(5);
        for entry in metrics.recent_denials.iter().take(max_denials) {
            let display = if let Some(ref tool) = entry.tool {
                format!("{}/{}", entry.method, tool)
            } else {
                entry.method.clone()
            };
            let display = truncate(&display, (inner.width as usize).saturating_sub(4));

            lines.push(Line::from(vec![
                Span::styled(format!(" {} ", CROSS), theme.error_style()),
                Span::styled(display, theme.muted_style()),
            ]));
        }
    }

    let content = Paragraph::new(lines);
    frame.render_widget(content, inner);
}
