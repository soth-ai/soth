//! Status bar widget with keyboard hints and timestamps

use crate::commands::tui::app::{App, Tab};
use crate::commands::tui::theme::Theme;
use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let theme = Theme::get();

    let mut hints = vec![
        Span::styled("Tab", theme.info_style()),
        Span::styled(": next tab  ", theme.muted_style()),
        Span::styled("1-4", theme.info_style()),
        Span::styled(": tabs  ", theme.muted_style()),
    ];

    match app.active_tab {
        Tab::Dashboard => {
            hints.extend([
                Span::styled("h/l", theme.info_style()),
                Span::styled(": focus  ", theme.muted_style()),
                Span::styled("w/-/=", theme.info_style()),
                Span::styled(": window  ", theme.muted_style()),
            ]);
        }
        Tab::Events => {
            if app.event_inspector_open() {
                hints.extend([
                    Span::styled("[/]", theme.info_style()),
                    Span::styled(": part  ", theme.muted_style()),
                    Span::styled("p", theme.info_style()),
                    Span::styled(": load  ", theme.muted_style()),
                    Span::styled("Enter/Esc", theme.info_style()),
                    Span::styled(": close  ", theme.muted_style()),
                ]);
            } else {
                hints.extend([
                    Span::styled("[/]", theme.info_style()),
                    Span::styled(": filter  ", theme.muted_style()),
                    Span::styled("Enter", theme.info_style()),
                    Span::styled(": inspect  ", theme.muted_style()),
                    Span::styled("j/k", theme.info_style()),
                    Span::styled(": scroll  ", theme.muted_style()),
                ]);
            }
        }
        _ => {}
    }
    hints.extend([
        Span::styled("f", theme.info_style()),
        Span::styled(": live/pause  ", theme.muted_style()),
        Span::styled("r", theme.info_style()),
        Span::styled(": refresh  ", theme.muted_style()),
        Span::styled("q", theme.info_style()),
        Span::styled(": quit", theme.muted_style()),
    ]);

    let mode = if app.auto_refresh_enabled() {
        "live"
    } else {
        "paused"
    };
    let context = match app.active_tab {
        Tab::Dashboard => {
            let mut base = format!("{} {}", mode, app.rollup_window_label());
            if let Some(stats) = app.metrics.stream_stats.as_ref() {
                base.push_str(&format!(
                    " | lag:{} send_fail:{}",
                    stats.lagged_events, stats.broadcast_send_failures
                ));
            }
            base
        }
        Tab::Events => format!("{} {}", mode, app.event_filter_label()),
        _ => mode.to_string(),
    };
    let updated = format!("{context} | updated {}", app.last_updated_string());

    // Calculate positions
    let hints_line = Line::from(hints);
    let updated_span = Span::styled(updated, theme.muted_style());

    // Render hints on the left
    frame.render_widget(Paragraph::new(hints_line), area);

    // Render updated time on the right
    let updated_width = updated_span.content.len() as u16;
    if area.width > updated_width + 2 {
        let updated_area = Rect {
            x: area.x + area.width - updated_width - 1,
            y: area.y,
            width: updated_width,
            height: 1,
        };
        frame.render_widget(Paragraph::new(updated_span), updated_area);
    }
}
