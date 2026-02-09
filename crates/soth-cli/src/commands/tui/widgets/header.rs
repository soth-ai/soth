//! Header widget with tabs and connection status

use crate::commands::tui::app::{App, ConnectionState, Tab};
use crate::commands::tui::theme::{Theme, CIRCLE_FILLED};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Tabs};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let theme = Theme::get();

    // Tab titles
    let titles: Vec<Line> = [Tab::Dashboard, Tab::Events, Tab::Agents, Tab::Help]
        .iter()
        .enumerate()
        .map(|(i, tab)| {
            let num = format!("{}:", i + 1);
            Line::from(vec![
                Span::styled(num, theme.muted_style()),
                Span::raw(tab.title()),
            ])
        })
        .collect();

    // Connection status
    let (status_icon, status_style) = match app.connection {
        ConnectionState::Connected => (CIRCLE_FILLED, theme.success_style()),
        ConnectionState::Connecting => (CIRCLE_FILLED, theme.warning_style()),
        ConnectionState::Disconnected => (CIRCLE_FILLED, theme.error_style()),
    };

    let connection_text = match app.connection {
        ConnectionState::Connected => "Connected",
        ConnectionState::Connecting => "Connecting...",
        ConnectionState::Disconnected => "Disconnected",
    };
    let refresh_text = if app.auto_refresh_enabled() {
        "Live"
    } else {
        "Paused"
    };
    let status_text = format!("{connection_text} | {refresh_text}");

    // Create tabs widget
    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .title(" SOTH TUI ")
                .title_style(theme.header_style())
                .borders(Borders::ALL)
                .border_style(theme.border_style(false)),
        )
        .select(app.active_tab as usize)
        .style(theme.muted_style())
        .highlight_style(theme.highlight_style())
        .divider(Span::raw(" │ "));

    frame.render_widget(tabs, area);

    // Render connection status on the right side of the header
    let status_width = status_text.len() + 4; // icon + space + text + padding
    if area.width > status_width as u16 + 10 {
        let status_area = Rect {
            x: area.x + area.width - status_width as u16 - 2,
            y: area.y + 1,
            width: status_width as u16,
            height: 1,
        };

        let status = Line::from(vec![
            Span::styled(format!("{} ", status_icon), status_style),
            Span::styled(status_text, status_style),
        ]);

        frame.render_widget(status, status_area);
    }
}
