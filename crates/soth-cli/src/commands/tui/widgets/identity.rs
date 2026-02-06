//! Identity panel widget

use crate::commands::tui::app::{App, PanelFocus};
use crate::commands::tui::theme::{format_number, truncate, Theme, CHECK, CROSS};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let theme = Theme::get();
    let focused = app.focused_panel == PanelFocus::Identity;

    let block = Block::default()
        .title(" Identity ")
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(theme.border_style(focused));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let metrics = match &app.metrics.identity {
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
            Span::raw("Verifications  "),
            Span::styled(
                format_number(metrics.total_verifications),
                theme.bold_style(),
            ),
        ]),
        Line::from(vec![
            Span::styled(format!("{} ", CHECK), theme.success_style()),
            Span::raw("Successful   "),
            Span::styled(format_number(metrics.successful), theme.success_style()),
        ]),
        Line::from(vec![
            Span::styled(format!("{} ", CROSS), theme.error_style()),
            Span::raw("Failed       "),
            Span::styled(format_number(metrics.failed), theme.error_style()),
        ]),
        Line::from(vec![
            Span::raw("Unique DIDs    "),
            Span::styled(
                format_number(metrics.unique_dids as u64),
                theme.info_style(),
            ),
        ]),
    ];

    // Add recent DIDs if space allows
    if inner.height > 6 && !metrics.recent_dids.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Recent DIDs:",
            theme.muted_style(),
        )));

        let max_dids = (inner.height as usize).saturating_sub(7).min(5);
        for entry in metrics.recent_dids.iter().take(max_dids) {
            let icon = if entry.verified { CHECK } else { CROSS };
            let style = if entry.verified {
                theme.success_style()
            } else {
                theme.error_style()
            };

            // Truncate DID to fit
            let did_display = truncate(&entry.did, (inner.width as usize).saturating_sub(4));

            lines.push(Line::from(vec![
                Span::styled(format!(" {} ", icon), style),
                Span::styled(did_display, theme.muted_style()),
            ]));
        }
    }

    let content = Paragraph::new(lines);
    frame.render_widget(content, inner);
}
