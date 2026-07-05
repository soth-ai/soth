//! Minimal CLI styling utilities for the current production command surface.

use crate::logging::use_ansi_colors;
use owo_colors::OwoColorize;

pub const CHECK: &str = "\u{2713}";
pub const WARNING: &str = "\u{26A0}";
pub const INFO: &str = "\u{25CF}";
pub const ARROW_RIGHT: &str = "\u{2192}";

const CIRCLE_FILLED: &str = "\u{25CF}";

pub fn success(msg: &str) {
    if use_ansi_colors() {
        println!("{} {}", CHECK.green(), msg);
    } else {
        println!("{CHECK} {msg}");
    }
}

pub fn warning(msg: &str) {
    if use_ansi_colors() {
        println!("{} {}", WARNING.yellow(), msg);
    } else {
        println!("{WARNING} {msg}");
    }
}

pub fn info(msg: &str) {
    if use_ansi_colors() {
        println!("{} {}", CIRCLE_FILLED.cyan(), msg);
    } else {
        println!("{CIRCLE_FILLED} {msg}");
    }
}

pub fn kv(key: &str, value: &str) {
    if use_ansi_colors() {
        println!("  {}: {}", key.dimmed(), value);
    } else {
        println!("  {key}: {value}");
    }
}

pub fn success_prefix() -> String {
    if use_ansi_colors() {
        CHECK.green().to_string()
    } else {
        CHECK.to_string()
    }
}

pub fn highlight(text: &str) -> String {
    if use_ansi_colors() {
        text.cyan().bold().to_string()
    } else {
        text.to_string()
    }
}
