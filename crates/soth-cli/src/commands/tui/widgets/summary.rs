//! Summary panel widget

use crate::commands::tui::app::{App, ConnectionState, PanelFocus};
use crate::commands::tui::theme::{format_duration, format_number, format_percent, Theme, CHECK, CROSS, WARNING};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let theme = Theme::get();
    let focused = app.focused_panel == PanelFocus::Summary;

    let block = Block::default()
        .title(" Summary ")
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(theme.border_style(focused));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Calculate aggregate stats
    let uptime = format_duration(app.metrics.uptime_secs);

    let events_per_min = if app.metrics.uptime_secs > 0 {
        let total_events = app
            .metrics
            .observe
            .as_ref()
            .map(|o| o.requests)
            .unwrap_or(0);
        (total_events as f64 / (app.metrics.uptime_secs as f64 / 60.0)) as u64
    } else {
        0
    };

    // Calculate average latency from recent proxy requests
    let avg_latency = app
        .metrics
        .proxy
        .as_ref()
        .and_then(|p| {
            let latencies: Vec<u64> = p
                .recent_requests
                .iter()
                .filter_map(|r| r.latency_ms)
                .collect();
            if latencies.is_empty() {
                None
            } else {
                Some(latencies.iter().sum::<u64>() / latencies.len() as u64)
            }
        });

    // Calculate error rate
    let error_rate = app.metrics.policy.as_ref().map(|p| {
        if p.evaluations > 0 {
            (p.denied as f64 / p.evaluations as f64) * 100.0
        } else {
            0.0
        }
    });

    // Build content lines
    let mut lines = vec![
        Line::from(vec![
            Span::raw("Uptime         "),
            Span::styled(uptime, theme.info_style()),
        ]),
        Line::from(vec![
            Span::raw("Events/min     "),
            Span::styled(format_number(events_per_min), Style::default()),
        ]),
        Line::from(vec![
            Span::raw("Avg Latency    "),
            Span::styled(
                avg_latency
                    .map(|l| format!("{}ms", l))
                    .unwrap_or_else(|| "-".to_string()),
                Style::default(),
            ),
        ]),
        Line::from(vec![
            Span::raw("Error Rate     "),
            Span::styled(
                error_rate
                    .map(|r| format_percent(r))
                    .unwrap_or_else(|| "-".to_string()),
                if error_rate.unwrap_or(0.0) > 5.0 {
                    theme.warning_style()
                } else {
                    Style::default()
                },
            ),
        ]),
    ];

    // Add spacing
    lines.push(Line::from(""));

    // Status summary
    let (status_icon, status_text, status_style) = match app.connection {
        ConnectionState::Connected => {
            // Check for any alerts
            let has_pii_alerts = app
                .metrics
                .observe
                .as_ref()
                .map(|o| o.pii_detections > 0)
                .unwrap_or(false);
            let has_denials = app
                .metrics
                .policy
                .as_ref()
                .map(|p| p.denied > 0)
                .unwrap_or(false);

            if has_pii_alerts {
                (WARNING, "PII Detected", theme.warning_style())
            } else if has_denials {
                (WARNING, "Denials Present", theme.warning_style())
            } else {
                (CHECK, "All Systems OK", theme.success_style())
            }
        }
        ConnectionState::Connecting => (WARNING, "Connecting...", theme.warning_style()),
        ConnectionState::Disconnected => (CROSS, "Disconnected", theme.error_style()),
    };

    lines.push(Line::from(vec![
        Span::raw("Status: "),
        Span::styled(format!("{} {}", status_icon, status_text), status_style),
    ]));

    let content = Paragraph::new(lines);
    frame.render_widget(content, inner);
}
