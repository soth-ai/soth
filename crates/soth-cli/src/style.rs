//! Minimal CLI styling utilities for the current production command surface.

use owo_colors::OwoColorize;

pub const CHECK: &str = "\u{2713}";
pub const WARNING: &str = "\u{26A0}";
pub const INFO: &str = "\u{25CF}";
pub const ARROW_RIGHT: &str = "\u{2192}";

const CIRCLE_FILLED: &str = "\u{25CF}";

pub fn success(msg: &str) {
    println!("{} {}", CHECK.green(), msg);
}

pub fn warning(msg: &str) {
    println!("{} {}", WARNING.yellow(), msg);
}

pub fn info(msg: &str) {
    println!("{} {}", CIRCLE_FILLED.cyan(), msg);
}

pub fn kv(key: &str, value: &str) {
    println!("  {}: {}", key.dimmed(), value);
}

pub fn success_prefix() -> String {
    CHECK.green().to_string()
}

pub fn highlight(text: &str) -> String {
    text.cyan().bold().to_string()
}
