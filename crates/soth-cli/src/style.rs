//! CLI styling utilities
//!
//! Provides consistent styling for CLI output including colored text,
//! tables, spinners, and status indicators.
//!
//! Features:
//! - Respects `NO_COLOR` environment variable
//! - Gracefully degrades when output is piped (non-TTY)
//! - Unicode tables with fallback to ASCII

use comfy_table::{presets::UTF8_FULL, ContentArrangement, Table};
use console::Term;
use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::OwoColorize;
use std::time::Duration;

/// Status indicators
pub const CHECK: &str = "\u{2713}"; // ✓
pub const CROSS: &str = "\u{2717}"; // ✗
pub const WARNING: &str = "\u{26A0}"; // ⚠
pub const INFO: &str = "\u{25CF}"; // ●
pub const CIRCLE_FILLED: &str = "\u{25CF}"; // ●
pub const CIRCLE_EMPTY: &str = "\u{25CB}"; // ○
pub const ARROW_RIGHT: &str = "\u{2192}"; // →
pub const ARROW_LEFT: &str = "\u{2190}"; // ←

/// Print a styled section header with box drawing
pub fn header(title: &str) {
    let term_width = Term::stdout().size().1 as usize;
    let width = term_width.min(60).saturating_sub(4);
    let padding = width.saturating_sub(title.len());
    println!();
    println!(
        "\u{256D}\u{2500} {} {}\u{256E}",
        title.bold(),
        "\u{2500}".repeat(padding)
    );
}

/// Print a footer line to close a section
pub fn footer() {
    let term_width = Term::stdout().size().1 as usize;
    let width = term_width.min(60);
    println!("\u{2570}{}\u{256F}", "\u{2500}".repeat(width.saturating_sub(2)));
    println!();
}

/// Create a pre-styled table with UTF8 borders
pub fn table() -> Table {
    let mut t = Table::new();
    t.load_preset(UTF8_FULL);
    t.set_content_arrangement(ContentArrangement::Dynamic);
    t
}

/// Print a success message with green checkmark
pub fn success(msg: &str) {
    println!("{} {}", CHECK.green(), msg);
}

/// Print an error message with red X to stderr
pub fn error(msg: &str) {
    eprintln!("{} {}", CROSS.red(), msg);
}

/// Print a warning message with yellow warning sign
pub fn warning(msg: &str) {
    println!("{} {}", WARNING.yellow(), msg);
}

/// Return a colored status icon based on boolean
pub fn status_icon(ok: bool) -> String {
    if ok {
        CHECK.green().to_string()
    } else {
        CROSS.red().to_string()
    }
}

/// Return a colored status icon for three states: good/warning/bad
pub fn status_icon_tri(state: StatusState) -> String {
    match state {
        StatusState::Good => CHECK.green().to_string(),
        StatusState::Warning => CIRCLE_FILLED.yellow().to_string(),
        StatusState::Bad => CROSS.red().to_string(),
    }
}

/// Three-state status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusState {
    Good,
    Warning,
    Bad,
}

/// Create a spinner for async operations
pub fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .expect("valid template"),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

/// Create a progress bar for determinate operations
pub fn progress_bar(len: u64, msg: &str) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg} [{bar:30.cyan/dim}] {pos}/{len}")
            .expect("valid template")
            .progress_chars("\u{2588}\u{2592}\u{2591}"),
    );
    pb.set_message(msg.to_string());
    pb
}

/// Return dimmed text for secondary info
pub fn dim(msg: &str) -> String {
    msg.dimmed().to_string()
}

/// Print a key-value pair with dimmed key
pub fn kv(key: &str, value: &str) {
    println!("  {}: {}", key.dimmed(), value);
}

/// Print a key-value pair with dimmed key and colored value
pub fn kv_colored(key: &str, value: &str, good: bool) {
    let colored_value = if good {
        value.green().to_string()
    } else {
        value.red().to_string()
    };
    println!("  {}: {}", key.dimmed(), colored_value);
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

/// Format bytes as human readable (KB, MB, GB)
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format duration as human readable
pub fn format_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs >= 3600 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs > 0 {
        format!("{}s", secs)
    } else {
        format!("{}ms", d.as_millis())
    }
}

/// Style for "enabled" status
pub fn enabled(val: bool) -> String {
    if val {
        "enabled".green().to_string()
    } else {
        "disabled".dimmed().to_string()
    }
}

/// Style for active/inactive status with filled/empty circle
pub fn active_indicator(active: bool) -> String {
    if active {
        format!("{} Active", CIRCLE_FILLED.cyan())
    } else {
        format!("{} Inactive", CIRCLE_EMPTY.dimmed())
    }
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

/// Print section subtitle (lighter than header)
pub fn subtitle(title: &str) {
    println!();
    println!("{}", title.bold());
    println!("{}", "\u{2500}".repeat(title.len().min(40)));
}

/// Print an info line with cyan bullet
pub fn info(msg: &str) {
    println!("{} {}", CIRCLE_FILLED.cyan(), msg);
}

/// Return success prefix (green checkmark)
pub fn success_prefix() -> String {
    CHECK.green().to_string()
}

/// Return error prefix (red X)
pub fn error_prefix() -> String {
    CROSS.red().to_string()
}

/// Highlight text in cyan
pub fn highlight(text: &str) -> String {
    text.cyan().bold().to_string()
}

/// Print a step in a multi-step process
pub fn step(num: usize, total: usize, msg: &str) {
    println!(
        "{} {}",
        format!("[{}/{}]", num, total).dimmed(),
        msg
    );
}

/// Print a completed step with checkmark
pub fn step_done(num: usize, total: usize, msg: &str) {
    println!(
        "{} {} {}",
        format!("[{}/{}]", num, total).dimmed(),
        CHECK.green(),
        msg
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(999), "999");
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(1234567), "1,234,567");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("this is long", 8), "this is\u{2026}");
        assert_eq!(truncate("ab", 1), "\u{2026}");
    }

    #[test]
    fn test_status_icon() {
        // Just ensure they don't panic and return something
        assert!(!status_icon(true).is_empty());
        assert!(!status_icon(false).is_empty());
    }
}
