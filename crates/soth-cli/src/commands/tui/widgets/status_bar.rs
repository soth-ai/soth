//! Status bar widget with keyboard hints and timestamps

use crate::commands::tui::app::App;
use crate::commands::tui::theme::Theme;
use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let theme = Theme::get();

    // Left side: keyboard hints
    let hints = vec![
        Span::styled("Tab", theme.info_style()),
        Span::styled(": panels  ", theme.muted_style()),
        Span::styled("1-4", theme.info_style()),
        Span::styled(": tabs  ", theme.muted_style()),
        Span::styled("r", theme.info_style()),
        Span::styled(": refresh  ", theme.muted_style()),
        Span::styled("q", theme.info_style()),
        Span::styled(": quit", theme.muted_style()),
    ];

    // Right side: last updated
    let updated = format!("Updated {}", app.last_updated_string());

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
