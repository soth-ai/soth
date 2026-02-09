//! Dashboard tab (v2): signal-dense operational overview.

use crate::commands::tui::api::ClusterRow;
use crate::commands::tui::app::{App, PanelFocus};
use crate::commands::tui::theme::{
    format_currency, format_number, format_percent, truncate, Theme, CIRCLE_FILLED, WARNING,
};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use soth_core::types::{EventSource, WrapEvent};
use std::collections::HashMap;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7), // Global signal strip
            Constraint::Length(8), // Activity + timeline
            Constraint::Min(8),    // Ranked tables + risks
        ])
        .split(area);

    render_signal_strip(frame, rows[0], app);
    render_middle_row(frame, rows[1], app);
    render_bottom_row(frame, rows[2], app);
}

fn render_signal_strip(frame: &mut Frame, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);

    let focused = app.focused_panel == PanelFocus::Signals;

    let policy = app.metrics.policy.as_ref();
    let proxy = app.metrics.proxy.as_ref();
    let observe = app.metrics.observe.as_ref();
    let budget = app.metrics.budget_primitives.as_ref();
    let clusters = &app.metrics.clusters;

    let (policy_value, policy_sub, policy_style) = if let Some(p) = policy {
        let allow_pct = if p.evaluations > 0 {
            (p.allowed as f64 / p.evaluations as f64) * 100.0
        } else {
            100.0
        };
        let style = if p.denied > 0 {
            Theme::get().warning_style()
        } else {
            Theme::get().success_style()
        };
        (
            format!("{} allow", format_percent(allow_pct)),
            format!("{} denied / {} eval", p.denied, p.evaluations),
            style,
        )
    } else {
        (
            "Loading...".to_string(),
            "policy data pending".to_string(),
            Theme::get().muted_style(),
        )
    };

    let recent_req = proxy.map(|p| p.recent_requests.len() as u64).unwrap_or(0);
    let recent_res = proxy
        .map(|p| {
            p.recent_requests
                .iter()
                .filter(|row| row.status_code.is_some())
                .count() as u64
        })
        .unwrap_or(0);
    let p95_recent = proxy.and_then(p95_recent_latency_ms);
    let p95 = p95_recent
        .or_else(|| p95_latency_ms(clusters))
        .map(|v| format!("{v}ms"))
        .unwrap_or_else(|| "-".to_string());

    let (traffic_value, traffic_sub, traffic_style) = if let Some(p) = proxy {
        let recent_hint = if recent_req > 0 {
            format!(
                "recent {}/{}",
                format_number(recent_req),
                format_number(recent_res)
            )
        } else {
            "recent -/-".to_string()
        };
        (
            format!("{} req", format_number(p.total_requests)),
            format!(
                "{} res | {} | p95 {}",
                format_number(p.total_responses),
                recent_hint,
                p95
            ),
            Theme::get().info_style(),
        )
    } else {
        (
            "Loading...".to_string(),
            "traffic data pending".to_string(),
            Theme::get().muted_style(),
        )
    };

    let (error_value, error_sub, error_style) = if let Some(p) = proxy {
        let (errors_5xx, responses) = if recent_req > 0 {
            let errors = p
                .recent_requests
                .iter()
                .filter(|row| row.status_code.is_some_and(|code| code >= 500))
                .count() as u64;
            (errors, recent_res.max(1))
        } else {
            let errors = clusters
                .iter()
                .filter(|row| row.status_code.unwrap_or(0) >= 500)
                .count() as u64;
            (errors, p.total_responses.max(1))
        };
        let rate = (errors_5xx as f64 / responses as f64) * 100.0;
        let style = if rate >= 2.0 {
            Theme::get().error_style()
        } else if rate >= 0.5 {
            Theme::get().warning_style()
        } else {
            Theme::get().success_style()
        };
        (
            format!("{} 5xx", errors_5xx),
            format!("rate {}", format_percent(rate)),
            style,
        )
    } else {
        (
            "Loading...".to_string(),
            "error data pending".to_string(),
            Theme::get().muted_style(),
        )
    };

    let (spend_value, spend_sub, spend_style) = if let Some(b) = budget {
        let util = b.utilization_pct.unwrap_or(0.0);
        let style = if util >= 95.0 {
            Theme::get().error_style()
        } else if util >= 85.0 {
            Theme::get().warning_style()
        } else {
            Theme::get().success_style()
        };
        (
            format_currency(b.total_cost_usd),
            format!(
                "in {} out {} | {}",
                short_number(b.total_input_tokens),
                short_number(b.total_output_tokens),
                if b.daily_limit_usd.is_some() {
                    format!("{} util", format_percent(util))
                } else {
                    "no limit".to_string()
                }
            ),
            style,
        )
    } else {
        let fallback_cost = proxy.map(|p| p.total_cost_usd).unwrap_or(0.0);
        (
            format_currency(fallback_cost),
            "budget primitives pending".to_string(),
            Theme::get().muted_style(),
        )
    };

    render_signal_card(
        frame,
        cols[0],
        "Policy",
        &policy_value,
        &policy_sub,
        policy_style,
        focused,
    );
    render_signal_card(
        frame,
        cols[1],
        "Traffic",
        &traffic_value,
        &traffic_sub,
        traffic_style,
        focused,
    );
    render_signal_card(
        frame,
        cols[2],
        "Errors",
        &error_value,
        &error_sub,
        error_style,
        focused,
    );
    render_signal_card(
        frame,
        cols[3],
        "Spend",
        &spend_value,
        &spend_sub,
        spend_style,
        focused,
    );

    let _ = observe;
}

fn render_signal_card(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    value: &str,
    subtitle: &str,
    value_style: Style,
    focused: bool,
) {
    let theme = Theme::get();
    let block = Block::default()
        .title(format!(" {title} "))
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(theme.border_style(focused));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines = vec![
        Line::from(Span::styled(
            truncate(value, inner.width as usize),
            value_style,
        )),
        Line::from(Span::styled(
            truncate(subtitle, inner.width as usize),
            theme.muted_style(),
        )),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_middle_row(frame: &mut Frame, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(area);

    render_throughput_chart(
        frame,
        cols[0],
        app,
        app.focused_panel == PanelFocus::Activity,
    );
    render_latency_and_cost_pack(
        frame,
        cols[1],
        app,
        app.focused_panel == PanelFocus::Timeline,
    );
}

fn render_throughput_chart(frame: &mut Frame, area: Rect, app: &App, focused: bool) {
    let theme = Theme::get();
    let block = Block::default()
        .title(" Throughput + Errors ")
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(theme.border_style(focused));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.metrics.rollups.is_empty() {
        frame.render_widget(
            Paragraph::new("No rollup data yet").style(theme.muted_style()),
            inner,
        );
        return;
    }

    let window_points = app.rollup_points();
    let mut throughput_points: Vec<u64> = app
        .metrics
        .rollups
        .iter()
        .take(window_points)
        .map(|row| row.total_events)
        .collect();
    let mut error_points: Vec<u64> = app
        .metrics
        .rollups
        .iter()
        .take(window_points)
        .map(|row| row.error_events)
        .collect();
    throughput_points.reverse();
    error_points.reverse();

    let width = inner.width.saturating_sub(18) as usize;
    let throughput_spark = sparkline(&throughput_points, width);
    let error_spark = sparkline(&error_points, width);

    let latest_total = throughput_points.last().copied().unwrap_or(0);
    let latest_errors = error_points.last().copied().unwrap_or(0);
    let previous_total = throughput_points
        .iter()
        .rev()
        .nth(1)
        .copied()
        .unwrap_or(latest_total);
    let err_rate = if latest_total > 0 {
        (latest_errors as f64 / latest_total as f64) * 100.0
    } else {
        0.0
    };
    let avg_total = if throughput_points.is_empty() {
        0.0
    } else {
        throughput_points.iter().sum::<u64>() as f64 / throughput_points.len() as f64
    };
    let peak_total = throughput_points.iter().copied().max().unwrap_or(0);
    let req_delta = percent_delta(latest_total, previous_total);
    let latest_rollup = app.metrics.rollups.first();

    let mut mcp = 0u64;
    let mut ai = 0u64;
    let mut agent = 0u64;
    for event in app.events.iter().take(300) {
        match event.source {
            EventSource::Mcp => mcp += 1,
            EventSource::AiProxy => ai += 1,
            EventSource::AgentApp => agent += 1,
        }
    }
    let source_total = (mcp + ai + agent).max(1);
    let error_style = if err_rate > 2.0 {
        theme.error_style()
    } else if err_rate > 0.5 {
        theme.warning_style()
    } else {
        theme.success_style()
    };
    let trend_style = if req_delta >= 10.0 {
        theme.warning_style()
    } else if req_delta <= -10.0 {
        theme.info_style()
    } else {
        theme.muted_style()
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("req ", theme.muted_style()),
            Span::styled(throughput_spark, theme.info_style()),
            Span::raw(" "),
            Span::styled(
                format!("max {}", format_number(peak_total)),
                theme.muted_style(),
            ),
        ]),
        Line::from(vec![
            Span::styled("err ", theme.muted_style()),
            Span::styled(error_spark, error_style),
            Span::raw(" "),
            Span::styled(format!("rate {}", format_percent(err_rate)), error_style),
        ]),
        Line::from(vec![
            Span::styled(
                format!(
                    "now {} req/m  avg {:.1}",
                    format_number(latest_total),
                    avg_total
                ),
                theme.muted_style(),
            ),
            Span::raw("  "),
            Span::styled(
                format!(
                    "{}{:.0}%  r{} s{}",
                    if req_delta >= 0.0 { "+" } else { "" },
                    req_delta,
                    latest_rollup.map(|r| r.requests).unwrap_or(0),
                    latest_rollup.map(|r| r.responses).unwrap_or(0),
                ),
                trend_style,
            ),
        ]),
        Line::from(vec![
            Span::styled("mix ", theme.muted_style()),
            Span::styled(
                format!(
                    "mcp:{} ai:{} agent:{}",
                    format_percent((mcp as f64 / source_total as f64) * 100.0),
                    format_percent((ai as f64 / source_total as f64) * 100.0),
                    format_percent((agent as f64 / source_total as f64) * 100.0)
                ),
                theme.muted_style(),
            ),
        ]),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_latency_and_cost_pack(frame: &mut Frame, area: Rect, app: &App, focused: bool) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
        .split(area);

    render_latency_bands(frame, rows[0], app, focused);
    render_provider_cost_bars(frame, rows[1], app, focused);
}

fn render_latency_bands(frame: &mut Frame, area: Rect, app: &App, focused: bool) {
    let theme = Theme::get();
    let window_points = app.rollup_points();
    let block = Block::default()
        .title(format!(" Latency Bands ({}) ", app.rollup_window_label()))
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(theme.border_style(focused));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.metrics.clusters.is_empty() {
        frame.render_widget(
            Paragraph::new("No cluster latency yet").style(theme.muted_style()),
            inner,
        );
        return;
    }

    let (p50, p95, p99) = latency_band_series(&app.metrics.clusters, window_points.max(20));
    let spark_width = inner.width.saturating_sub(18) as usize;
    let p50_spark = sparkline(&p50, spark_width);
    let p95_spark = sparkline(&p95, spark_width);
    let p99_spark = sparkline(&p99, spark_width);
    let recent_latencies: Vec<u64> = app
        .metrics
        .clusters
        .iter()
        .filter_map(|row| row.latency_ms)
        .filter(|latency| *latency > 0)
        .take(window_points.max(40))
        .collect();
    let sample_count = recent_latencies.len().max(1) as f64;
    let under_250ms = recent_latencies.iter().filter(|lat| **lat < 250).count() as f64;
    let over_1000ms = recent_latencies.iter().filter(|lat| **lat >= 1000).count() as f64;

    let mut lines = vec![
        Line::from(vec![
            Span::styled("p50 ", theme.muted_style()),
            Span::styled(p50_spark, theme.success_style()),
            Span::raw(" "),
            Span::styled(
                format!("{:>4}ms", p50.last().copied().unwrap_or(0)),
                theme.success_style(),
            ),
        ]),
        Line::from(vec![
            Span::styled("p95 ", theme.muted_style()),
            Span::styled(p95_spark, theme.warning_style()),
            Span::raw(" "),
            Span::styled(
                format!("{:>4}ms", p95.last().copied().unwrap_or(0)),
                theme.warning_style(),
            ),
        ]),
        Line::from(vec![
            Span::styled("p99 ", theme.muted_style()),
            Span::styled(p99_spark, theme.error_style()),
            Span::raw(" "),
            Span::styled(
                format!("{:>4}ms", p99.last().copied().unwrap_or(0)),
                theme.error_style(),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                format!(
                    "<250ms {}  >1s {}",
                    format_percent((under_250ms / sample_count) * 100.0),
                    format_percent((over_1000ms / sample_count) * 100.0)
                ),
                theme.muted_style(),
            ),
            Span::raw("  "),
            Span::styled("w/-/=", theme.info_style()),
        ]),
    ];
    if inner.height >= 6 {
        lines.push(Line::from(Span::styled(
            "latency distribution over recent clusters",
            theme.muted_style(),
        )));
    }

    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_provider_cost_bars(frame: &mut Frame, area: Rect, app: &App, focused: bool) {
    let theme = Theme::get();
    let block = Block::default()
        .title(" Provider Cost Bars ")
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(theme.border_style(focused));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some(primitives) = app.metrics.budget_primitives.as_ref() else {
        frame.render_widget(
            Paragraph::new("Budget primitives pending").style(theme.muted_style()),
            inner,
        );
        return;
    };

    if primitives.provider_breakdown.is_empty() {
        frame.render_widget(
            Paragraph::new("No provider spend yet").style(theme.muted_style()),
            inner,
        );
        return;
    }

    let available_rows = inner.height.max(1) as usize;
    let top = primitives
        .provider_breakdown
        .iter()
        .take(available_rows.min(4))
        .collect::<Vec<_>>();
    let total_cost = top
        .iter()
        .map(|provider| provider.total_cost_usd)
        .sum::<f64>()
        .max(0.00001);
    let max_cost = top
        .iter()
        .map(|provider| provider.total_cost_usd)
        .fold(0.0_f64, f64::max)
        .max(0.00001);
    let bar_width = inner.width.saturating_sub(34).max(8) as usize;

    let mut lines = Vec::new();
    for provider in top {
        let name = truncate(&provider.provider, 9);
        let share_pct = (provider.total_cost_usd / total_cost) * 100.0;
        let ratio = provider.total_cost_usd / max_cost;
        let filled = ((ratio * bar_width as f64).round() as usize).min(bar_width);
        let bar = format!("{}{}", "█".repeat(filled), "░".repeat(bar_width - filled));
        let bar_style = if share_pct >= 60.0 {
            theme.warning_style()
        } else {
            theme.success_style()
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{:<9}", name), theme.info_style()),
            Span::raw(" "),
            Span::styled(bar, bar_style),
            Span::raw(" "),
            Span::styled(
                format!("{:>5}", format_percent(share_pct)),
                theme.muted_style(),
            ),
            Span::raw(" "),
            Span::styled(
                format!("{:>7}", short_currency(provider.total_cost_usd)),
                theme.warning_style(),
            ),
            Span::raw(" "),
            Span::styled(
                format!("t{}", short_number(provider.total_tokens)),
                theme.muted_style(),
            ),
        ]));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

fn sparkline(values: &[u64], width: usize) -> String {
    const BINS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    if values.is_empty() || width == 0 {
        return String::new();
    }

    let mut sampled = Vec::with_capacity(width);
    for i in 0..width {
        let start = i * values.len() / width;
        let end = ((i + 1) * values.len() / width).max(start + 1);
        let max = values[start..end.min(values.len())]
            .iter()
            .copied()
            .max()
            .unwrap_or(0);
        sampled.push(max);
    }

    let max_value = sampled.iter().copied().max().unwrap_or(1).max(1);
    sampled
        .into_iter()
        .map(|value| {
            let idx = ((value as f64 / max_value as f64) * 7.0).round() as usize;
            BINS[idx.min(7)]
        })
        .collect()
}

fn render_bottom_row(frame: &mut Frame, area: Rect, app: &App) {
    render_engineering_focus(
        frame,
        area,
        app,
        app.focused_panel == PanelFocus::Engineering,
    );
}

fn render_engineering_focus(frame: &mut Frame, area: Rect, app: &App, focused: bool) {
    let theme = Theme::get();
    let block = Block::default()
        .title(" Engineering Focus ")
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(theme.border_style(focused));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(4)])
        .split(inner);
    render_actionables_banner(frame, rows[0], app);

    let content_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(rows[1]);

    let top_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(content_rows[0]);
    render_hot_ops(frame, top_cols[0], app);
    render_slow_paths(frame, top_cols[1], app);

    let bottom_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(36), Constraint::Percentage(64)])
        .split(content_rows[1]);
    render_latency_histogram(frame, bottom_cols[0], app);
    render_observed_signals(frame, bottom_cols[1], app);
}

fn render_hot_ops(frame: &mut Frame, area: Rect, app: &App) {
    let theme = Theme::get();
    let mut op_counts: HashMap<String, (u64, u64)> = HashMap::new(); // op -> (total, errors)

    if let Some(proxy) = app.metrics.proxy.as_ref() {
        if !proxy.recent_requests.is_empty() {
            for row in &proxy.recent_requests {
                let path = compact_path(&row.path);
                let op = format!("{} {}", row.method, path);
                let entry = op_counts.entry(op).or_insert((0, 0));
                entry.0 += 1;
                if row.status_code.is_some_and(|status| status >= 400) {
                    entry.1 += 1;
                }
            }
        }
    }

    if op_counts.is_empty() {
        for event in app.events.iter().take(320) {
            let op = event_operation_label(event);
            let entry = op_counts.entry(op).or_insert((0, 0));
            entry.0 += 1;
            if event.status_code.is_some_and(|status| status >= 400)
                || event.policy_allowed == Some(false)
            {
                entry.1 += 1;
            }
        }
    }

    let mut rows: Vec<(String, (u64, u64))> = op_counts.into_iter().collect();
    rows.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then_with(|| b.1 .1.cmp(&a.1 .1)));

    let max_rows = area.height.saturating_sub(1) as usize;
    let mut lines = Vec::with_capacity(max_rows.max(1));
    lines.push(Line::from(Span::styled("HOT OPS", theme.bold_style())));
    let max_count = rows
        .first()
        .map(|(_, (count, _))| *count)
        .unwrap_or(1)
        .max(1);

    if rows.is_empty() {
        lines.push(Line::from(Span::styled(
            "No recent operations",
            theme.muted_style(),
        )));
    } else {
        let label_width = area.width.saturating_sub(15).max(12) as usize;
        for (op, (count, errors)) in rows.into_iter().take(max_rows.saturating_sub(1)) {
            let bar = ratio_bar(count, max_count, 6);
            let marker = if errors > 0 {
                Span::styled(format!(" !{errors}"), theme.warning_style())
            } else {
                Span::styled(String::new(), theme.muted_style())
            };
            lines.push(Line::from(vec![
                Span::styled(
                    format!(
                        "{:<width$}",
                        truncate(&op, label_width),
                        width = label_width
                    ),
                    if errors > 0 {
                        theme.warning_style()
                    } else {
                        theme.info_style()
                    },
                ),
                Span::raw(" "),
                Span::styled(bar, theme.muted_style()),
                Span::styled(format!(" {:>4}", count), theme.muted_style()),
                marker,
            ]));
        }
    }

    frame.render_widget(Paragraph::new(lines), area);
}

fn render_slow_paths(frame: &mut Frame, area: Rect, app: &App) {
    let theme = Theme::get();
    let mut request_context: HashMap<String, (String, String)> = HashMap::new();
    for event in app.events.iter().take(450) {
        let method = event
            .method
            .clone()
            .or_else(|| {
                event
                    .traffic_envelope
                    .as_ref()
                    .map(|env| env.method.clone())
            })
            .unwrap_or_else(|| "op".to_string());
        let path = event
            .traffic_envelope
            .as_ref()
            .and_then(|env| env.path.as_deref())
            .map(compact_path)
            .unwrap_or_else(|| "-".to_string());
        request_context.insert(event.id.clone(), (method, path));
    }

    let mut aggregates: HashMap<String, SlowPathAggregate> = HashMap::new();
    for row in app.metrics.clusters.iter().take(420) {
        let latency = row.latency_ms.unwrap_or(0);
        if latency == 0 {
            continue;
        }
        let provider = row
            .provider
            .as_deref()
            .or(row.agent.as_deref())
            .unwrap_or("-");
        let context = row
            .request_event_id
            .as_ref()
            .and_then(|id| request_context.get(id));
        let method = row
            .method
            .clone()
            .or_else(|| context.map(|(method, _)| method.clone()))
            .unwrap_or_else(|| "op".to_string());
        let path = context
            .map(|(_, path)| path.clone())
            .unwrap_or_else(|| source_hint(row));
        let key = format!("{provider} {method} {path}");

        let entry = aggregates.entry(key).or_default();
        entry.max_latency = entry.max_latency.max(latency);
        entry.samples += 1;
        entry.worst_status = match (entry.worst_status, row.status_code) {
            (Some(current), Some(next)) => Some(current.max(next)),
            (None, next) => next,
            (current, None) => current,
        };
    }

    let mut rows: Vec<(String, SlowPathAggregate)> = aggregates.into_iter().collect();
    rows.sort_by(|a, b| {
        slow_path_severity_score(&b.1)
            .cmp(&slow_path_severity_score(&a.1))
            .then_with(|| b.1.max_latency.cmp(&a.1.max_latency))
            .then_with(|| b.1.samples.cmp(&a.1.samples))
    });

    let max_rows = area.height.saturating_sub(1) as usize;
    let mut lines = Vec::with_capacity(max_rows.max(1));
    lines.push(Line::from(Span::styled("SLOW PATHS", theme.bold_style())));

    if rows.is_empty() {
        lines.push(Line::from(Span::styled(
            "No latency samples",
            theme.muted_style(),
        )));
    } else {
        let label_width = area.width.saturating_sub(18).max(12) as usize;
        for (op, row) in rows.into_iter().take(max_rows.saturating_sub(1)) {
            let (sev_label, sev_style) = slow_path_severity(row.max_latency, row.worst_status);
            let status_style = if row.worst_status.is_some_and(|code| code >= 500) {
                theme.error_style()
            } else if row.worst_status.is_some_and(|code| code >= 400) {
                theme.warning_style()
            } else {
                theme.muted_style()
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{sev_label} "), sev_style),
                Span::styled(format!("{:>4}ms ", row.max_latency), sev_style),
                Span::styled(
                    format!(
                        "{:<width$}",
                        truncate(&op, label_width),
                        width = label_width
                    ),
                    theme.info_style(),
                ),
                Span::styled(format!(" x{:>2} ", row.samples), theme.muted_style()),
                Span::styled(
                    row.worst_status
                        .map(|code| code.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    status_style,
                ),
            ]));
        }
    }

    frame.render_widget(Paragraph::new(lines), area);
}

fn render_latency_histogram(frame: &mut Frame, area: Rect, app: &App) {
    let theme = Theme::get();
    let block = Block::default()
        .title(" Latency Distribution ")
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(theme.border_style(false));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let latencies = latency_samples(app, 500);
    if latencies.is_empty() {
        frame.render_widget(
            Paragraph::new("No latency samples").style(theme.muted_style()),
            inner,
        );
        return;
    }

    let total = latencies.len() as u64;
    let fast = latencies.iter().filter(|latency| **latency < 250).count() as u64;
    let mid = latencies
        .iter()
        .filter(|latency| (250..1000).contains(&(**latency)))
        .count() as u64;
    let slow = latencies.iter().filter(|latency| **latency >= 1000).count() as u64;
    let tail = latencies.iter().filter(|latency| **latency >= 2000).count() as u64;
    let fast_pct = (fast as f64 / total as f64) * 100.0;
    let mid_pct = (mid as f64 / total as f64) * 100.0;
    let slow_pct = (slow as f64 / total as f64) * 100.0;
    let tail_pct = (tail as f64 / total as f64) * 100.0;
    let width = inner.width.saturating_sub(20).max(4) as usize;
    let lines = vec![
        distribution_line("<250", fast, total, width, theme.success_style()),
        distribution_line("250-1s", mid, total, width, theme.info_style()),
        distribution_line(">1s", slow, total, width, theme.warning_style()),
        Line::from(vec![
            Span::styled(
                format!(
                    "mix f:{} m:{} s:{}",
                    format_percent(fast_pct),
                    format_percent(mid_pct),
                    format_percent(slow_pct),
                ),
                theme.muted_style(),
            ),
            Span::raw("  "),
            Span::styled(
                format!("tail>2s {}", format_percent(tail_pct)),
                theme.error_style(),
            ),
        ]),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_actionables_banner(frame: &mut Frame, area: Rect, app: &App) {
    let theme = Theme::get();
    let priorities = collect_actionables(app);
    let info_line = if priorities.is_empty() {
        Line::from(vec![
            Span::styled(format!("{CIRCLE_FILLED} "), theme.success_style()),
            Span::styled("No material alerts", theme.success_style()),
        ])
    } else {
        let max_items = 2usize;
        let mut joined = String::new();
        for (idx, (score, message)) in priorities.iter().take(max_items).enumerate() {
            if idx > 0 {
                joined.push_str(" | ");
            }
            let _ = std::fmt::write(&mut joined, format_args!("[{score}] {message}"));
        }
        let style = if priorities.first().is_some_and(|(score, _)| *score >= 90) {
            theme.error_style()
        } else {
            theme.warning_style()
        };
        Line::from(vec![
            Span::styled(format!("{WARNING} "), style),
            Span::styled(
                truncate(&joined, area.width.saturating_sub(4) as usize),
                style,
            ),
        ])
    };

    let lines = vec![
        Line::from(Span::styled("ACTIONABLES", theme.bold_style())),
        info_line,
    ];
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_observed_signals(frame: &mut Frame, area: Rect, app: &App) {
    let theme = Theme::get();
    let block = Block::default()
        .title(" Observed Signals ")
        .title_style(theme.title_style())
        .borders(Borders::ALL)
        .border_style(theme.border_style(false));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.height == 0 {
        return;
    }

    const EVENT_WINDOW: usize = 500;
    const CLUSTER_WINDOW: usize = 500;
    let top_n = if inner.width < 46 { 1 } else { 2 };

    let mut ai_events = 0u64;
    let mut mcp_events = 0u64;
    let mut agent_events = 0u64;
    let mut ai_calls = 0u64;
    let mut mcp_calls = 0u64;
    let mut agent_calls = 0u64;
    let mut model_counts: HashMap<String, u64> = HashMap::new();
    let mut model_recency: HashMap<String, usize> = HashMap::new();
    let mut provider_model_counts: HashMap<String, u64> = HashMap::new();
    let mut provider_model_recency: HashMap<String, usize> = HashMap::new();
    let mut mcp_method_counts: HashMap<String, u64> = HashMap::new();
    let mut event_agent_counts: HashMap<String, u64> = HashMap::new();
    let mut event_provider_counts: HashMap<String, u64> = HashMap::new();
    let mut cluster_agent_counts: HashMap<String, u64> = HashMap::new();
    let mut cluster_provider_counts: HashMap<String, u64> = HashMap::new();
    let mut sampled_events = 0u64;
    let mut sampled_clusters = 0u64;
    let mut latest_ai_model: Option<String> = None;

    for (idx, event) in app.events.iter().take(EVENT_WINDOW).enumerate() {
        sampled_events += 1;
        match event.source {
            EventSource::AiProxy => ai_events += 1,
            EventSource::Mcp => mcp_events += 1,
            EventSource::AgentApp => agent_events += 1,
        }

        if let Some(model) = event
            .model
            .as_deref()
            .or_else(|| {
                event
                    .traffic_envelope
                    .as_ref()
                    .and_then(|envelope| envelope.model.as_deref())
            })
            .map(str::trim)
            .filter(|model| !model.is_empty())
        {
            *model_counts.entry(model.to_string()).or_insert(0) += 1;
            model_recency.entry(model.to_string()).or_insert(idx);
            if event.source == EventSource::AiProxy {
                let provider = event
                    .provider
                    .as_deref()
                    .map(str::trim)
                    .filter(|provider| !provider.is_empty())
                    .unwrap_or("unknown");
                let key = format!("{provider}/{model}");
                *provider_model_counts.entry(key.clone()).or_insert(0) += 1;
                provider_model_recency.entry(key.clone()).or_insert(idx);
                if latest_ai_model.is_none() {
                    latest_ai_model = Some(key);
                }
            }
        }

        if event.source == EventSource::Mcp {
            if let Some(method) = event
                .method
                .as_deref()
                .map(str::trim)
                .filter(|m| !m.is_empty())
            {
                *mcp_method_counts.entry(method.to_string()).or_insert(0) += 1;
            }
        }

        if let Some(provider) = event
            .provider
            .as_deref()
            .map(str::trim)
            .filter(|provider| !provider.is_empty())
        {
            *event_provider_counts
                .entry(provider.to_string())
                .or_insert(0) += 1;
        }

        let detected_agent = event.agent.name.trim();
        if !detected_agent.is_empty() && !detected_agent.eq_ignore_ascii_case("unknown") {
            *event_agent_counts
                .entry(detected_agent.to_string())
                .or_insert(0) += 1;
        }
        if let Some(agent) = event
            .traffic_envelope
            .as_ref()
            .and_then(|envelope| envelope.agent.as_deref())
            .map(str::trim)
            .filter(|agent| !agent.is_empty())
        {
            *event_agent_counts.entry(agent.to_string()).or_insert(0) += 1;
        }
    }

    for row in app.metrics.clusters.iter().take(CLUSTER_WINDOW) {
        sampled_clusters += 1;
        let source = row
            .source
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if source.contains("mcp") {
            mcp_calls += 1;
        } else if source.contains("agent") {
            agent_calls += 1;
        } else {
            ai_calls += 1;
        }

        if let Some(provider) = row
            .provider
            .as_deref()
            .map(str::trim)
            .filter(|provider| !provider.is_empty())
        {
            *cluster_provider_counts
                .entry(provider.to_string())
                .or_insert(0) += 1;
        }
        if let Some(agent) = row
            .agent
            .as_deref()
            .map(str::trim)
            .filter(|agent| !agent.is_empty())
        {
            *cluster_agent_counts.entry(agent.to_string()).or_insert(0) += 1;
        }
    }

    let provider_counts = if cluster_provider_counts.is_empty() {
        event_provider_counts
    } else {
        cluster_provider_counts
    };
    let agent_counts = if cluster_agent_counts.is_empty() {
        event_agent_counts
    } else {
        cluster_agent_counts
    };

    let provider_total = provider_counts.values().sum::<u64>().max(1);
    let agent_total = agent_counts.values().sum::<u64>().max(1);
    let model_total = if provider_model_counts.is_empty() {
        model_counts.values().sum::<u64>().max(1)
    } else {
        provider_model_counts.values().sum::<u64>().max(1)
    };
    let mcp_method_total = mcp_method_counts.values().sum::<u64>().max(1);
    let all_models = if provider_model_counts.is_empty() {
        sort_counts_by_recency(model_counts, model_recency)
    } else {
        sort_counts_by_recency(provider_model_counts, provider_model_recency)
    };
    let top_agents = top_counts(agent_counts, top_n);
    let top_providers = top_counts(provider_counts, top_n);
    let top_mcp_methods = top_counts(mcp_method_counts, top_n);
    let mut lines = Vec::new();
    lines.push(Line::from(vec![
        Span::styled("window ", theme.muted_style()),
        Span::styled(
            format!(
                "ev:{} cl:{}",
                short_number(sampled_events),
                short_number(sampled_clusters)
            ),
            theme.info_style(),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("events ", theme.muted_style()),
        Span::styled(
            format!(
                "ai:{} mcp:{} ag:{}",
                short_number(ai_events),
                short_number(mcp_events),
                short_number(agent_events)
            ),
            theme.info_style(),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("calls ", theme.muted_style()),
        Span::styled(
            format!(
                "ai:{} mcp:{} ag:{}",
                short_number(ai_calls),
                short_number(mcp_calls),
                short_number(agent_calls)
            ),
            theme.info_style(),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("latest ", theme.muted_style()),
        Span::styled(
            truncate(
                latest_ai_model.as_deref().unwrap_or("none"),
                inner.width.saturating_sub(8) as usize,
            ),
            theme.info_style(),
        ),
    ]));

    push_ranked_group(
        &mut lines,
        "provider",
        &top_providers,
        provider_total,
        inner.width as usize,
        theme,
    );
    push_ranked_group(
        &mut lines,
        "mcp",
        &top_mcp_methods,
        mcp_method_total,
        inner.width as usize,
        theme,
    );
    push_models_window(&mut lines, &all_models, model_total, inner.width as usize, theme);
    push_ranked_group(
        &mut lines,
        "agent",
        &top_agents,
        agent_total,
        inner.width as usize,
        theme,
    );

    if lines.len() > inner.height as usize {
        lines.truncate(inner.height as usize);
    }

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

fn collect_actionables(app: &App) -> Vec<(u8, String)> {
    let mut priorities: Vec<(u8, String)> = Vec::new();
    if let Some(policy) = app.metrics.policy.as_ref() {
        if policy.denied > 0 {
            let score = if policy.denied >= 50 { 95 } else { 70 };
            priorities.push((score, format!("{} denied requests", policy.denied)));
        }
    }

    if let Some(observe) = app.metrics.observe.as_ref() {
        if observe.pii_detections > 0 {
            let score = if observe.pii_detections >= 10 {
                100
            } else {
                85
            };
            priorities.push((score, format!("{} PII detections", observe.pii_detections)));
        }
    }

    let pending_clusters = app
        .metrics
        .clusters
        .iter()
        .filter(|row| row.response_event_id.is_none())
        .count();
    if pending_clusters > 0 {
        let score = if pending_clusters >= 25 { 75 } else { 55 };
        priorities.push((
            score,
            format!("{pending_clusters} pending req/resp clusters"),
        ));
    }

    if let Some(stats) = app.metrics.stream_stats.as_ref() {
        if stats.lagged_receivers > 0 || stats.lagged_events > 0 {
            let score = if stats.lagged_events >= 500 { 90 } else { 60 };
            priorities.push((
                score,
                format!(
                    "stream lag {} recv / {} events",
                    stats.lagged_receivers, stats.lagged_events
                ),
            ));
        }
    }

    if let Some(budget) = app.metrics.budget_primitives.as_ref() {
        if let Some(util) = budget.utilization_pct {
            if util >= 85.0 {
                let score = if util >= 95.0 { 98 } else { 72 };
                priorities.push((
                    score,
                    format!("budget utilization {}", format_percent(util)),
                ));
            }
        }
    }

    let error_5xx = app
        .metrics
        .clusters
        .iter()
        .filter(|row| row.status_code.is_some_and(|status| status >= 500))
        .count();
    if error_5xx > 0 {
        let score = if error_5xx >= 20 { 92 } else { 64 };
        priorities.push((score, format!("{} server errors (5xx)", error_5xx)));
    }

    priorities.sort_by(|a, b| b.0.cmp(&a.0));
    priorities
}

#[derive(Debug, Default, Clone, Copy)]
struct SlowPathAggregate {
    max_latency: u64,
    samples: u64,
    worst_status: Option<u16>,
}

fn event_operation_label(event: &WrapEvent) -> String {
    if let Some(tool) = event.tool_name.as_deref() {
        return format!("tool/{tool}");
    }

    let method = event
        .method
        .as_deref()
        .or_else(|| {
            event
                .traffic_envelope
                .as_ref()
                .map(|env| env.method.as_str())
        })
        .unwrap_or("op");

    let path = event
        .traffic_envelope
        .as_ref()
        .and_then(|env| env.path.as_deref())
        .map(compact_path);
    if let Some(path) = path {
        return format!("{method} {path}");
    }

    match event.source {
        EventSource::Mcp => format!("mcp/{method}"),
        EventSource::AiProxy => format!("{method} ai"),
        EventSource::AgentApp => format!("{method} agent"),
    }
}

fn compact_path(path: &str) -> String {
    if path.len() <= 32 {
        return path.to_string();
    }
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    if parts.len() < 3 {
        return truncate(path, 32);
    }
    format!("/{}/…/{}", parts[0], parts.last().copied().unwrap_or("-"))
}

fn source_hint(row: &ClusterRow) -> String {
    let source = row.source.as_deref().unwrap_or("-");
    let method = row.method.as_deref().unwrap_or("op");
    if source.contains("mcp") {
        format!("mcp/{method}")
    } else if source.contains("agent") {
        "agent".to_string()
    } else {
        "-".to_string()
    }
}

fn ratio_bar(value: u64, max: u64, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let max = max.max(1);
    let filled = ((value as f64 / max as f64) * width as f64).round() as usize;
    format!(
        "{}{}",
        "█".repeat(filled.min(width)),
        "░".repeat(width.saturating_sub(filled.min(width)))
    )
}

fn percent_delta(current: u64, previous: u64) -> f64 {
    if previous == 0 {
        return if current == 0 { 0.0 } else { 100.0 };
    }
    ((current as f64 - previous as f64) / previous as f64) * 100.0
}

fn distribution_line(
    label: &str,
    count: u64,
    total: u64,
    width: usize,
    style: Style,
) -> Line<'static> {
    let pct = if total > 0 {
        (count as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    let filled = if total > 0 {
        (((count as f64 / total as f64) * width as f64).round() as usize).min(width)
    } else {
        0
    };
    let bar = format!(
        "{}{}",
        "█".repeat(filled),
        "░".repeat(width.saturating_sub(filled))
    );
    Line::from(vec![
        Span::styled(format!("{label:<6} "), Theme::get().muted_style()),
        Span::styled(bar, style),
        Span::raw(" "),
        Span::styled(
            format!("{:>5}", format_percent(pct)),
            Theme::get().muted_style(),
        ),
    ])
}

fn latency_samples(app: &App, limit: usize) -> Vec<u64> {
    if let Some(proxy) = app.metrics.proxy.as_ref() {
        let from_proxy: Vec<u64> = proxy
            .recent_requests
            .iter()
            .filter_map(|row| row.latency_ms)
            .filter(|latency| *latency > 0)
            .take(limit)
            .collect();
        if !from_proxy.is_empty() {
            return from_proxy;
        }
    }
    app.metrics
        .clusters
        .iter()
        .filter_map(|row| row.latency_ms)
        .filter(|latency| *latency > 0)
        .take(limit)
        .collect()
}

fn slow_path_severity_score(row: &SlowPathAggregate) -> u8 {
    let mut score = if row.max_latency >= 3_000 {
        4
    } else if row.max_latency >= 1_500 {
        3
    } else if row.max_latency >= 700 {
        2
    } else {
        1
    };
    score += if row.worst_status.is_some_and(|code| code >= 500) {
        2
    } else if row.worst_status.is_some_and(|code| code >= 400) {
        1
    } else {
        0
    };
    if row.samples >= 8 {
        score += 1;
    }
    score
}

fn slow_path_severity(max_latency: u64, worst_status: Option<u16>) -> (&'static str, Style) {
    let theme = Theme::get();
    if worst_status.is_some_and(|code| code >= 500) || max_latency >= 3_000 {
        ("C", theme.error_style())
    } else if worst_status.is_some_and(|code| code >= 400) || max_latency >= 1_500 {
        ("H", theme.warning_style())
    } else if max_latency >= 700 {
        ("M", theme.info_style())
    } else {
        ("L", theme.muted_style())
    }
}

fn p95_latency_ms(clusters: &[ClusterRow]) -> Option<u64> {
    let mut latencies: Vec<u64> = clusters.iter().filter_map(|row| row.latency_ms).collect();
    if latencies.is_empty() {
        return None;
    }
    latencies.sort_unstable();
    let idx = (((latencies.len() - 1) as f64) * 0.95).round() as usize;
    latencies.get(idx).copied()
}

fn p95_recent_latency_ms(proxy: &soth_dashboard::state::ProxyMetrics) -> Option<u64> {
    let mut latencies: Vec<u64> = proxy
        .recent_requests
        .iter()
        .filter_map(|row| row.latency_ms)
        .collect();
    if latencies.is_empty() {
        return None;
    }
    latencies.sort_unstable();
    let idx = (((latencies.len() - 1) as f64) * 0.95).round() as usize;
    latencies.get(idx).copied()
}

fn short_number(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}m", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn short_currency(v: f64) -> String {
    if v >= 1_000_000.0 {
        format!("${:.1}m", v / 1_000_000.0)
    } else if v >= 1_000.0 {
        format!("${:.1}k", v / 1_000.0)
    } else {
        format_currency(v)
    }
}

fn top_counts(mut values: HashMap<String, u64>, take: usize) -> Vec<(String, u64)> {
    let mut rows: Vec<(String, u64)> = values.drain().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows.into_iter().take(take).collect()
}

fn push_ranked_group(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    items: &[(String, u64)],
    total: u64,
    width: usize,
    theme: &Theme,
) {
    let label_text = format!("{label:>7}");
    let compact = width < 50;
    if items.is_empty() {
        lines.push(Line::from(vec![
            Span::styled(format!("{label_text} "), theme.muted_style()),
            Span::styled("none", theme.muted_style()),
        ]));
        return;
    }

    for (idx, (name, count)) in items.iter().enumerate().take(2) {
        let left = if idx == 0 {
            format!("{label_text} ")
        } else {
            "        ".to_string()
        };
        let pct = (*count as f64 / total.max(1) as f64) * 100.0;
        let trailer = if compact {
            format!(" {}", short_number(*count))
        } else {
            format!(" {} ({})", short_number(*count), format_percent(pct))
        };
        let max_name = width.saturating_sub(left.len() + trailer.len()).max(6);
        lines.push(Line::from(vec![
            Span::styled(left, theme.muted_style()),
            Span::styled(truncate(name, max_name), theme.info_style()),
            Span::styled(trailer, theme.muted_style()),
        ]));
    }
}

fn push_models_window(
    lines: &mut Vec<Line<'static>>,
    items: &[(String, u64)],
    total: u64,
    width: usize,
    theme: &Theme,
) {
    if items.is_empty() {
        lines.push(Line::from(vec![
            Span::styled(" models ", theme.muted_style()),
            Span::styled("none", theme.muted_style()),
        ]));
        return;
    }

    lines.push(Line::from(vec![
        Span::styled(" models ", theme.muted_style()),
        Span::styled(format!("{}", items.len()), theme.info_style()),
        Span::styled(" (window)", theme.muted_style()),
    ]));

    let mut shown = 0usize;
    let label_width = width.saturating_sub(14).max(10);
    for (name, count) in items {
        let pct = (*count as f64 / total.max(1) as f64) * 100.0;
        let right = format!(" {} ({})", short_number(*count), format_percent(pct));
        let max_name = label_width.saturating_sub(right.len()).max(6);
        lines.push(Line::from(vec![
            Span::styled("        ", theme.muted_style()),
            Span::styled(truncate(name, max_name), theme.info_style()),
            Span::styled(right, theme.muted_style()),
        ]));
        shown += 1;
    }

    if shown < items.len() {
        lines.push(Line::from(vec![
            Span::styled("        ", theme.muted_style()),
            Span::styled(format!("+{} more", items.len() - shown), theme.muted_style()),
        ]));
    }
}

fn sort_counts_by_recency(
    mut values: HashMap<String, u64>,
    recency: HashMap<String, usize>,
) -> Vec<(String, u64)> {
    let mut rows: Vec<(String, u64)> = values.drain().collect();
    rows.sort_by(|a, b| {
        let ia = recency.get(&a.0).copied().unwrap_or(usize::MAX);
        let ib = recency.get(&b.0).copied().unwrap_or(usize::MAX);
        ia.cmp(&ib).then_with(|| b.1.cmp(&a.1))
    });
    rows
}

fn latency_band_series(clusters: &[ClusterRow], points: usize) -> (Vec<u64>, Vec<u64>, Vec<u64>) {
    if clusters.is_empty() || points == 0 {
        return (Vec::new(), Vec::new(), Vec::new());
    }

    let mut latencies: Vec<u64> = clusters.iter().filter_map(|row| row.latency_ms).collect();
    if latencies.is_empty() {
        return (Vec::new(), Vec::new(), Vec::new());
    }
    latencies.reverse(); // oldest -> newest

    let sample_points = points.min(latencies.len()).max(1);
    let mut p50 = Vec::with_capacity(sample_points);
    let mut p95 = Vec::with_capacity(sample_points);
    let mut p99 = Vec::with_capacity(sample_points);

    for i in 0..sample_points {
        let start = i * latencies.len() / sample_points;
        let end = ((i + 1) * latencies.len() / sample_points).max(start + 1);
        let mut chunk = latencies[start..end.min(latencies.len())].to_vec();
        chunk.sort_unstable();
        p50.push(percentile_latency(&chunk, 0.50));
        p95.push(percentile_latency(&chunk, 0.95));
        p99.push(percentile_latency(&chunk, 0.99));
    }

    (p50, p95, p99)
}

fn percentile_latency(sorted: &[u64], percentile: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len().saturating_sub(1) as f64) * percentile).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}
