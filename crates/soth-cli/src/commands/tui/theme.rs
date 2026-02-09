//! Theme and color definitions for the TUI

use ratatui::style::{Color, Modifier, Style};

/// Status indicators (matching style.rs)
pub const CHECK: &str = "\u{2713}"; // ✓
pub const CROSS: &str = "\u{2717}"; // ✗
pub const WARNING: &str = "\u{26A0}"; // ⚠
pub const CIRCLE_FILLED: &str = "\u{25CF}"; // ●
#[allow(dead_code)]
pub const CIRCLE_EMPTY: &str = "\u{25CB}"; // ○
pub const ARROW_RIGHT: &str = "\u{2192}"; // →
pub const ARROW_LEFT: &str = "\u{2190}"; // ←

/// Theme colors
#[allow(dead_code)]
pub struct Theme {
    pub success: Color,
    pub error: Color,
    pub warning: Color,
    pub info: Color,
    pub muted: Color,
    pub border: Color,
    pub border_focused: Color,
    pub bg: Color,
    pub fg: Color,
    pub highlight_bg: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            success: Color::Rgb(87, 201, 140),
            error: Color::Rgb(232, 93, 93),
            warning: Color::Rgb(217, 119, 87),
            info: Color::Rgb(89, 179, 223),
            muted: Color::Rgb(159, 159, 159),
            border: Color::Rgb(101, 54, 38),
            border_focused: Color::Rgb(217, 119, 87),
            bg: Color::Reset,
            fg: Color::Rgb(245, 245, 245),
            highlight_bg: Color::Rgb(33, 33, 33),
        }
    }
}

impl Theme {
    /// Get the global theme instance
    pub fn get() -> &'static Theme {
        static THEME: std::sync::OnceLock<Theme> = std::sync::OnceLock::new();
        THEME.get_or_init(Theme::default)
    }

    // --- Style helpers ---

    pub fn success_style(&self) -> Style {
        Style::default().fg(self.success)
    }

    pub fn error_style(&self) -> Style {
        Style::default().fg(self.error)
    }

    pub fn warning_style(&self) -> Style {
        Style::default().fg(self.warning)
    }

    pub fn info_style(&self) -> Style {
        Style::default().fg(self.info)
    }

    pub fn muted_style(&self) -> Style {
        Style::default().fg(self.muted)
    }

    pub fn bold_style(&self) -> Style {
        Style::default().add_modifier(Modifier::BOLD)
    }

    pub fn title_style(&self) -> Style {
        Style::default().fg(self.fg).add_modifier(Modifier::BOLD)
    }

    pub fn header_style(&self) -> Style {
        Style::default()
            .fg(self.warning)
            .add_modifier(Modifier::BOLD)
    }

    pub fn highlight_style(&self) -> Style {
        Style::default()
            .bg(self.highlight_bg)
            .add_modifier(Modifier::BOLD)
    }

    pub fn border_style(&self, focused: bool) -> Style {
        if focused {
            Style::default().fg(self.border_focused)
        } else {
            Style::default().fg(self.border)
        }
    }

    #[allow(dead_code)]
    pub fn status_style(&self, ok: bool) -> Style {
        if ok {
            self.success_style()
        } else {
            self.error_style()
        }
    }
}

/// Format a number with thousands separators
pub fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.insert(0, ',');
        }
        result.insert(0, c);
    }
    result
}

/// Format a percentage
pub fn format_percent(value: f64) -> String {
    format!("{:.1}%", value)
}

/// Format currency (USD)
pub fn format_currency(value: f64) -> String {
    format!("${:.2}", value)
}

/// Truncate a string with ellipsis
pub fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len <= 1 {
        "\u{2026}".to_string() // …
    } else {
        format!("{}\u{2026}", &s[..max_len - 1])
    }
}

/// Format duration from seconds
#[allow(dead_code)]
pub fn format_duration(secs: u64) -> String {
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let secs = secs % 60;

    if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else if mins > 0 {
        format!("{}m {}s", mins, secs)
    } else {
        format!("{}s", secs)
    }
}
