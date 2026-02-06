//! Help screen widget

use crate::commands::tui::theme::Theme;
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};

pub fn render(frame: &mut Frame, area: Rect) {
    let theme = Theme::get();

    let block = Block::default()
        .title(" Help ")
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(theme.border_style(false));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let help_text = vec![
        Line::from(""),
        Line::from(Span::styled("SOTH TUI Dashboard", theme.header_style())),
        Line::from(""),
        Line::from(Span::styled("Navigation", theme.bold_style())),
        Line::from(""),
        key_line("1-4", "Switch to tab (Dashboard/Events/Agents/Help)", theme),
        key_line("Tab", "Next tab", theme),
        key_line("Shift+Tab", "Previous tab", theme),
        key_line("h/j/k/l", "Navigate panels / scroll (vim-style)", theme),
        key_line("Arrow keys", "Navigate panels / scroll", theme),
        Line::from(""),
        Line::from(Span::styled(
            "Scrolling (Events/Agents tabs)",
            theme.bold_style(),
        )),
        Line::from(""),
        key_line("j / Down", "Scroll down", theme),
        key_line("k / Up", "Scroll up", theme),
        key_line("PgDn", "Page down", theme),
        key_line("PgUp", "Page up", theme),
        key_line("Home", "Jump to top", theme),
        key_line("End", "Jump to bottom", theme),
        Line::from(""),
        Line::from(Span::styled("Actions", theme.bold_style())),
        Line::from(""),
        key_line("r", "Force refresh data", theme),
        key_line("?", "Show this help", theme),
        key_line("q / Esc", "Quit", theme),
        Line::from(""),
        Line::from(Span::styled("Connection", theme.bold_style())),
        Line::from(""),
        Line::from(vec![
            Span::styled("  API URL: ", theme.muted_style()),
            Span::raw("Set with --api-url (default: http://localhost:3001)"),
        ]),
        Line::from(vec![
            Span::styled("  Refresh: ", theme.muted_style()),
            Span::raw("Set with --refresh (default: 2 seconds)"),
        ]),
    ];

    let help = Paragraph::new(help_text);
    frame.render_widget(help, inner);
}

fn key_line<'a>(key: &'a str, desc: &'a str, theme: &Theme) -> Line<'a> {
    Line::from(vec![
        Span::raw("  "),
        Span::styled(format!("{:<12}", key), theme.info_style()),
        Span::styled(desc, theme.muted_style()),
    ])
}
