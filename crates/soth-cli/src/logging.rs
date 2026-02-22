//! Compact SOTH-themed tracing formatter for CLI logs.

use chrono::Local;
use owo_colors::OwoColorize;
use std::fmt;
use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::EnvFilter;

const SOTH_ACCENT: (u8, u8, u8) = (0x65, 0x36, 0x26); // #653626
const SOTH_HIGHLIGHT: (u8, u8, u8) = (0xD9, 0x77, 0x57); // #D97757
const SOTH_MUTED: (u8, u8, u8) = (0x9F, 0x9F, 0x9F); // #9F9F9F
const SOTH_TEXT: (u8, u8, u8) = (0xFF, 0xFF, 0xFF); // #FFFFFF
const SOTH_OK: (u8, u8, u8) = (0x4A, 0xD6, 0x8D);
const SOTH_WARN: (u8, u8, u8) = (0xF5, 0xB5, 0x41);
const SOTH_ERROR: (u8, u8, u8) = (0xEF, 0x44, 0x44);
static LOG_OUTPUT_PAUSED: AtomicBool = AtomicBool::new(false);

/// Build the default log filter when `RUST_LOG` is not explicitly provided.
pub fn default_log_filter(verbose: bool) -> EnvFilter {
    let fallback = if verbose {
        "debug,hudsucker::proxy::internal=warn,soth_dashboard::websocket=debug"
    } else {
        "warn,soth_cli=info,soth_proxy=info,soth_dashboard=info,soth_dashboard::websocket=warn,hudsucker::proxy::internal=off"
    };
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(fallback))
}

/// Use ANSI only when stdout is a TTY and colors are not disabled.
pub fn use_ansi_colors() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

/// Pause/resume formatted stdout log emission (used while TUI owns the screen).
#[allow(dead_code)]
pub fn set_log_output_paused(paused: bool) {
    LOG_OUTPUT_PAUSED.store(paused, Ordering::Relaxed);
}

#[derive(Debug, Clone, Copy)]
pub struct SothLogFormatter {
    ansi: bool,
}

impl SothLogFormatter {
    pub fn new(ansi: bool) -> Self {
        Self { ansi }
    }

    fn paint(&self, input: &str, color: (u8, u8, u8), bold: bool, dim: bool) -> String {
        if !self.ansi {
            return input.to_string();
        }

        match (bold, dim) {
            (true, true) => format!(
                "{}",
                input.truecolor(color.0, color.1, color.2).bold().dimmed()
            ),
            (true, false) => format!("{}", input.truecolor(color.0, color.1, color.2).bold()),
            (false, true) => format!("{}", input.truecolor(color.0, color.1, color.2).dimmed()),
            (false, false) => format!("{}", input.truecolor(color.0, color.1, color.2)),
        }
    }

    fn level_label(&self, level: &Level) -> String {
        match *level {
            Level::ERROR => self.paint("ERR", SOTH_ERROR, true, false),
            Level::WARN => self.paint("WRN", SOTH_WARN, true, false),
            Level::INFO => self.paint("INF", SOTH_HIGHLIGHT, true, false),
            Level::DEBUG => self.paint("DBG", SOTH_ACCENT, true, false),
            Level::TRACE => self.paint("TRC", SOTH_MUTED, true, true),
        }
    }

    fn message_style(&self, level: &Level, message: &str) -> String {
        match *level {
            Level::ERROR => self.paint(message, SOTH_ERROR, false, false),
            Level::WARN => self.paint(message, SOTH_WARN, false, false),
            Level::INFO => self.paint(message, SOTH_TEXT, false, false),
            Level::DEBUG => self.paint(message, SOTH_MUTED, false, false),
            Level::TRACE => self.paint(message, SOTH_MUTED, false, true),
        }
    }

    fn field_value_style(&self, key: &str, value: &str) -> String {
        let mut color = SOTH_TEXT;
        let mut bold = false;
        let mut dim = false;

        if matches!(key, "provider" | "agent" | "model" | "mcp_method") {
            color = SOTH_HIGHLIGHT;
        } else if matches!(key, "method" | "path" | "host") {
            color = SOTH_ACCENT;
        } else if key == "latency_ms" {
            let latency = value.parse::<u64>().unwrap_or_default();
            color = if latency > 2_000 {
                SOTH_ERROR
            } else if latency > 750 {
                SOTH_WARN
            } else {
                SOTH_OK
            };
            bold = latency > 750;
        } else if key == "status" {
            let status = value.parse::<u16>().unwrap_or_default();
            color = if status >= 500 {
                SOTH_ERROR
            } else if status >= 400 {
                SOTH_WARN
            } else {
                SOTH_OK
            };
            bold = status >= 400;
        } else if key == "reason" {
            color = SOTH_WARN;
        } else {
            dim = key == "client_addr";
        }

        self.paint(value, color, bold, dim)
    }
}

impl<S, N> FormatEvent<S, N> for SothLogFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        if LOG_OUTPUT_PAUSED.load(Ordering::Relaxed) {
            return Ok(());
        }

        let mut fields = FieldCollector::default();
        event.record(&mut fields);

        let metadata = event.metadata();
        let timestamp = Local::now().format("%H:%M:%S%.3f").to_string();
        let level = self.level_label(metadata.level());
        let message = fields
            .message
            .unwrap_or_else(|| metadata.target().to_string());
        if should_suppress_noisy_proxy_error(metadata.target(), metadata.level(), &message) {
            return Ok(());
        }

        write!(
            writer,
            "{} {} {}",
            self.paint(&timestamp, SOTH_MUTED, false, true),
            level,
            self.message_style(metadata.level(), &message)
        )?;

        for (key, value) in fields.fields {
            if skip_field(&key) {
                continue;
            }
            write!(
                writer,
                " {}={}",
                self.paint(&key, SOTH_MUTED, false, true),
                self.field_value_style(&key, &value)
            )?;
        }

        writeln!(writer)
    }
}

fn should_suppress_noisy_proxy_error(target: &str, level: &Level, message: &str) -> bool {
    if std::env::var_os("SOTH_LOG_TRANSIENT_PROXY_ERRORS").is_some() {
        return false;
    }
    if *level != Level::ERROR || !target.starts_with("hudsucker") {
        return false;
    }

    let normalized = message.to_ascii_lowercase();
    normalized.contains("failed to forward request: client error (sendrequest)")
        || normalized
            .contains("error serving connection: connection closed before message completed")
        || normalized.contains("error serving connection: error writing a body to connection")
}

#[derive(Default)]
struct FieldCollector {
    message: Option<String>,
    fields: Vec<(String, String)>,
}

impl FieldCollector {
    fn push(&mut self, key: &str, value: String) {
        if key == "message" {
            self.message = Some(value);
        } else {
            self.fields.push((key.to_string(), value));
        }
    }
}

impl Visit for FieldCollector {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field.name(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push(field.name(), value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push(field.name(), value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push(field.name(), value.to_string());
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.push(field.name(), value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let rendered = format!("{value:?}");
        self.push(field.name(), normalize_debug_value(&rendered));
    }
}

fn normalize_debug_value(raw: &str) -> String {
    if let Some(inner) = raw
        .strip_prefix("Some(\"")
        .and_then(|value| value.strip_suffix("\")"))
    {
        return inner.to_string();
    }
    if raw == "None" {
        return "-".to_string();
    }
    if raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2 {
        return raw[1..raw.len() - 1].to_string();
    }
    raw.to_string()
}

fn skip_field(key: &str) -> bool {
    matches!(
        key,
        "log.target" | "log.module_path" | "log.file" | "log.line"
    )
}
