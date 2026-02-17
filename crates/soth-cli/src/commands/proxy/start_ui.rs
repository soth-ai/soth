//! Startup UI rendering helpers for proxy start command.

use console::Term;
use owo_colors::OwoColorize;

const SOTH_PROXY_ASCII: &[&str] = &[
    "  █████████     ███████    ███████████ █████   █████",
    " ███░░░░░███  ███░░░░░███ ░█░░░███░░░█░░███   ░░███ ",
    "░███    ░░░  ███     ░░███░   ░███  ░  ░███    ░███ ",
    "░░█████████ ░███      ░███    ░███     ░███████████ ",
    " ░░░░░░░░███░███      ░███    ░███     ░███░░░░░███ ",
    " ███    ░███░░███     ███     ░███     ░███    ░███ ",
    "░░█████████  ░░░███████░      █████    █████   █████",
    " ░░░░░░░░░     ░░░░░░░       ░░░░░    ░░░░░   ░░░░░ ",
];
const SOTH_ACCENT: (u8, u8, u8) = (0xD9, 0x77, 0x57);
const SOTH_MUTED: (u8, u8, u8) = (0x9F, 0x9F, 0x9F);
const SOTH_TEXT: (u8, u8, u8) = (0xFF, 0xFF, 0xFF);

pub(crate) fn render_startup_panel(
    runtime: &str,
    rules: &str,
    intercept: &str,
    env_line: &str,
    ca_path: &str,
    api_line: &str,
    ui_line: &str,
    events_line: &str,
    system_proxy_line: &str,
) {
    let term_width = Term::stdout().size().1 as usize;
    let total_width = term_width.saturating_sub(2).clamp(78, 110);
    let inner_width = total_width.saturating_sub(2);

    print_panel_top(inner_width, &format!("SOTH Proxy ─ {runtime}"));
    print_panel_kv_row(inner_width, "Rules", rules);
    print_panel_kv_row(inner_width, "Intercept", intercept);
    print_panel_kv_row(inner_width, "Env", env_line);
    print_panel_kv_row(inner_width, "CA", ca_path);
    print_panel_kv_row(inner_width, "API", api_line);
    print_panel_kv_row(inner_width, "UI", ui_line);
    print_panel_kv_row(inner_width, "Events", events_line);
    print_panel_kv_row(inner_width, "System", system_proxy_line);

    print_panel_bottom(inner_width);
    println!();
}

pub(crate) fn print_logo_banner() {
    println!();
    for icon in SOTH_PROXY_ASCII {
        let icon_colored = icon
            .truecolor(SOTH_ACCENT.0, SOTH_ACCENT.1, SOTH_ACCENT.2)
            .bold()
            .to_string();
        println!("  {}", icon_colored);
    }
}

fn print_panel_top(inner_width: usize, title: &str) {
    let middle_width = inner_width;
    let prefix = "─ ";
    let mut title_text = format!("{prefix}{title} ");
    if display_width(&title_text) > middle_width {
        title_text = truncate_display(&title_text, middle_width);
    }
    let fill = middle_width.saturating_sub(display_width(&title_text));
    println!("╭{}{}╮", title_text, "─".repeat(fill));
}

fn print_panel_bottom(inner_width: usize) {
    println!("╰{}╯", "─".repeat(inner_width));
}

fn print_panel_kv_row(inner_width: usize, label: &str, value: &str) {
    let label_field = format!("{label:<10}");
    let label_width = display_width(&label_field);
    let value_width = inner_width.saturating_sub(label_width);
    let value = truncate_display(value, value_width);
    let pad = inner_width
        .saturating_sub(label_width)
        .saturating_sub(display_width(&value));

    println!(
        "│{}{}{}│",
        label_field
            .truecolor(SOTH_MUTED.0, SOTH_MUTED.1, SOTH_MUTED.2)
            .bold(),
        value.truecolor(SOTH_TEXT.0, SOTH_TEXT.1, SOTH_TEXT.2),
        " ".repeat(pad)
    );
}

fn truncate_display(value: &str, max_width: usize) -> String {
    if max_width == 0 {
        return String::new();
    }

    if display_width(value) <= max_width {
        return value.to_string();
    }

    if max_width == 1 {
        return "…".to_string();
    }

    let mut out = String::new();
    for ch in value.chars() {
        if out.chars().count() + 1 >= max_width {
            break;
        }
        out.push(ch);
    }
    out.push('…');
    out
}

fn display_width(value: &str) -> usize {
    value.chars().count()
}

pub(crate) fn compact_path(path: &std::path::Path) -> String {
    let full = path.display().to_string();
    if let Some(home) = dirs::home_dir() {
        let home = home.display().to_string();
        if full.starts_with(&home) {
            return format!("~{}", &full[home.len()..]);
        }
    }
    full
}
