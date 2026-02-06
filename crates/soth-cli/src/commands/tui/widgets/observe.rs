//! Observe panel widget

use crate::commands::tui::app::{App, PanelFocus};
use crate::commands::tui::theme::{format_number, Theme, WARNING};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let theme = Theme::get();
    let focused = app.focused_panel == PanelFocus::Observe;

    let block = Block::default()
        .title(" Observe ")
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(theme.border_style(focused));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let metrics = match &app.metrics.observe {
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
            Span::styled(format_number(metrics.requests), theme.bold_style()),
        ]),
        Line::from(vec![
            Span::raw("Responses      "),
            Span::styled(format_number(metrics.responses), Style::default()),
        ]),
        Line::from(vec![
            Span::styled(format!("{} ", WARNING), theme.warning_style()),
            Span::raw("PII Found    "),
            Span::styled(format_number(metrics.pii_detections), theme.warning_style()),
        ]),
    ];

    // Add separator and PII breakdown
    if !metrics.pii_by_type.is_empty() && inner.height > 5 {
        lines.push(Line::from(Span::styled(
            "\u{2500}".repeat((inner.width as usize).saturating_sub(2)),
            theme.muted_style(),
        )));
        lines.push(Line::from(Span::styled("By Type:", theme.muted_style())));

        let mut pii_types: Vec<_> = metrics.pii_by_type.iter().collect();
        pii_types.sort_by(|a, b| b.1.cmp(a.1));

        let max_types = (inner.height as usize).saturating_sub(7).min(5);
        for (pii_type, count) in pii_types.iter().take(max_types) {
            // Capitalize type name
            let name = capitalize_first(pii_type);
            lines.push(Line::from(vec![
                Span::styled(format!("  {:<12}", name), theme.muted_style()),
                Span::styled(format_number(**count), theme.warning_style()),
            ]));
        }
    }

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
