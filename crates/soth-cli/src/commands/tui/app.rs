//! Application state for the TUI dashboard

use crate::commands::tui::api;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use soth_core::types::{EventSource, WrapEvent};
use soth_dashboard::event_store::AgentStats;
use soth_dashboard::state::{
    BudgetPrimitives, IdentityMetrics, ObserveMetrics, PolicyMetrics, ProxyMetrics,
};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Maximum number of events to keep in memory
const MAX_EVENTS: usize = 1200;
const MAX_CLUSTERS: usize = 800;
const MAX_INSPECTOR_PAYLOAD_CHARS: usize = 12_000;
const STARTUP_CONNECT_GRACE_SECS: u64 = 30;

/// Active tab in the TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Dashboard,
    Events,
    Agents,
    Help,
}

impl Tab {
    pub fn next(self) -> Self {
        match self {
            Tab::Dashboard => Tab::Events,
            Tab::Events => Tab::Agents,
            Tab::Agents => Tab::Help,
            Tab::Help => Tab::Dashboard,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Tab::Dashboard => Tab::Help,
            Tab::Events => Tab::Dashboard,
            Tab::Agents => Tab::Events,
            Tab::Help => Tab::Agents,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Tab::Dashboard => "Monitor",
            Tab::Events => "Events",
            Tab::Agents => "Agents",
            Tab::Help => "Help",
        }
    }
}

/// Panel focus for keyboard navigation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PanelFocus {
    #[default]
    Signals,
    Activity,
    Timeline,
    Engineering,
}

impl PanelFocus {
    pub fn next(self) -> Self {
        match self {
            PanelFocus::Signals => PanelFocus::Activity,
            PanelFocus::Activity => PanelFocus::Timeline,
            PanelFocus::Timeline => PanelFocus::Engineering,
            PanelFocus::Engineering => PanelFocus::Signals,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            PanelFocus::Signals => PanelFocus::Engineering,
            PanelFocus::Activity => PanelFocus::Signals,
            PanelFocus::Timeline => PanelFocus::Activity,
            PanelFocus::Engineering => PanelFocus::Timeline,
        }
    }
}

/// Event filter for the Events tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EventFilter {
    #[default]
    All,
    Ai,
    Mcp,
    Agent,
    Denied,
    Errors,
}

impl EventFilter {
    pub fn next(self) -> Self {
        match self {
            EventFilter::All => EventFilter::Ai,
            EventFilter::Ai => EventFilter::Mcp,
            EventFilter::Mcp => EventFilter::Agent,
            EventFilter::Agent => EventFilter::Denied,
            EventFilter::Denied => EventFilter::Errors,
            EventFilter::Errors => EventFilter::All,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            EventFilter::All => EventFilter::Errors,
            EventFilter::Ai => EventFilter::All,
            EventFilter::Mcp => EventFilter::Ai,
            EventFilter::Agent => EventFilter::Mcp,
            EventFilter::Denied => EventFilter::Agent,
            EventFilter::Errors => EventFilter::Denied,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            EventFilter::All => "all",
            EventFilter::Ai => "ai",
            EventFilter::Mcp => "mcp",
            EventFilter::Agent => "agent",
            EventFilter::Denied => "denied",
            EventFilter::Errors => "errors",
        }
    }
}

/// Time window selector for timeline rollups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RollupWindow {
    M30,
    #[default]
    H1,
    H3,
}

impl RollupWindow {
    pub fn next(self) -> Self {
        match self {
            RollupWindow::M30 => RollupWindow::H1,
            RollupWindow::H1 => RollupWindow::H3,
            RollupWindow::H3 => RollupWindow::M30,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            RollupWindow::M30 => RollupWindow::H3,
            RollupWindow::H1 => RollupWindow::M30,
            RollupWindow::H3 => RollupWindow::H1,
        }
    }

    pub fn points(self) -> usize {
        match self {
            RollupWindow::M30 => 30,
            RollupWindow::H1 => 60,
            RollupWindow::H3 => 180,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            RollupWindow::M30 => "30m",
            RollupWindow::H1 => "1h",
            RollupWindow::H3 => "3h",
        }
    }
}

/// Payload section currently shown inside the event inspector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PayloadPart {
    #[default]
    Request,
    Response,
    Content,
}

impl PayloadPart {
    pub fn next(self) -> Self {
        match self {
            PayloadPart::Request => PayloadPart::Response,
            PayloadPart::Response => PayloadPart::Content,
            PayloadPart::Content => PayloadPart::Request,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            PayloadPart::Request => PayloadPart::Content,
            PayloadPart::Response => PayloadPart::Request,
            PayloadPart::Content => PayloadPart::Response,
        }
    }

    pub fn as_api_part(self) -> &'static str {
        match self {
            PayloadPart::Request => "request",
            PayloadPart::Response => "response",
            PayloadPart::Content => "content",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            PayloadPart::Request => "request",
            PayloadPart::Response => "response",
            PayloadPart::Content => "content",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PayloadPreview {
    pub text: String,
    pub truncated: bool,
    pub total_chars: usize,
}

#[derive(Debug, Default)]
pub struct EventInspector {
    pub open: bool,
    pub event: Option<WrapEvent>,
    pub active_part: PayloadPart,
    pub request_payload: Option<PayloadPreview>,
    pub response_payload: Option<PayloadPreview>,
    pub content_payload: Option<PayloadPreview>,
    pub loading: bool,
    pub error: Option<String>,
    pending_request: Option<PayloadPart>,
}

impl EventInspector {
    pub fn payload_for_part(&self, part: PayloadPart) -> Option<&PayloadPreview> {
        match part {
            PayloadPart::Request => self.request_payload.as_ref(),
            PayloadPart::Response => self.response_payload.as_ref(),
            PayloadPart::Content => self.content_payload.as_ref(),
        }
    }

    fn set_payload_for_part(&mut self, part: PayloadPart, payload: PayloadPreview) {
        match part {
            PayloadPart::Request => self.request_payload = Some(payload),
            PayloadPart::Response => self.response_payload = Some(payload),
            PayloadPart::Content => self.content_payload = Some(payload),
        }
    }
}

/// Connection state to the dashboard API
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionState {
    #[default]
    Connecting,
    Connected,
    Disconnected,
}

/// Scroll state for lists
#[derive(Debug, Default)]
pub struct ScrollState {
    pub offset: usize,
    pub selected: usize,
}

impl ScrollState {
    pub fn scroll_up(&mut self, amount: usize) {
        self.offset = self.offset.saturating_sub(amount);
        self.selected = self.selected.saturating_sub(amount);
    }

    pub fn scroll_down(&mut self, amount: usize, max: usize) {
        if max > 0 {
            self.offset = (self.offset + amount).min(max.saturating_sub(1));
            self.selected = (self.selected + amount).min(max.saturating_sub(1));
        }
    }

    pub fn home(&mut self) {
        self.offset = 0;
        self.selected = 0;
    }

    pub fn end(&mut self, max: usize) {
        if max > 0 {
            self.selected = max - 1;
            self.offset = max.saturating_sub(20); // Show last ~20 items
        }
    }
}

/// Dashboard metrics container
#[derive(Debug, Default)]
pub struct DashboardMetrics {
    pub identity: Option<IdentityMetrics>,
    pub policy: Option<PolicyMetrics>,
    pub observe: Option<ObserveMetrics>,
    pub budget_primitives: Option<BudgetPrimitives>,
    pub proxy: Option<ProxyMetrics>,
    pub rollups: Vec<api::RollupRow>,
    pub clusters: Vec<api::ClusterRow>,
    pub stream_stats: Option<api::StreamStats>,
    pub uptime_secs: u64,
    pub last_updated: Option<Instant>,
}

/// Main application state
#[allow(dead_code)]
pub struct App {
    pub active_tab: Tab,
    pub focused_panel: PanelFocus,
    pub metrics: DashboardMetrics,
    pub events: VecDeque<WrapEvent>,
    pub agents: Vec<AgentStats>,
    pub connection: ConnectionState,
    pub events_scroll: ScrollState,
    pub agents_scroll: ScrollState,
    pub should_quit: bool,
    pub api_url: String,
    pub started_at: Instant,
    pub error_message: Option<String>,
    pub consecutive_failures: u32,
    pub auto_refresh: bool,
    pub refresh_requested: bool,
    pub event_filter: EventFilter,
    pub rollup_window: RollupWindow,
    pub inspector: EventInspector,
    event_seq_cursor: Option<i64>,
    cluster_seq_cursor: Option<i64>,
    filtered_event_indices: Vec<usize>,
    filtered_event_indices_dirty: bool,
}

impl App {
    pub fn new(api_url: String) -> Self {
        Self {
            active_tab: Tab::Dashboard,
            focused_panel: PanelFocus::Signals,
            metrics: DashboardMetrics::default(),
            events: VecDeque::with_capacity(MAX_EVENTS),
            agents: Vec::new(),
            connection: ConnectionState::Connecting,
            events_scroll: ScrollState::default(),
            agents_scroll: ScrollState::default(),
            should_quit: false,
            api_url,
            started_at: Instant::now(),
            error_message: None,
            consecutive_failures: 0,
            auto_refresh: true,
            refresh_requested: false,
            event_filter: EventFilter::All,
            rollup_window: RollupWindow::H1,
            inspector: EventInspector::default(),
            event_seq_cursor: None,
            cluster_seq_cursor: None,
            filtered_event_indices: Vec::with_capacity(MAX_EVENTS),
            filtered_event_indices_dirty: true,
        }
    }

    /// Handle key events
    pub fn on_key(&mut self, key: KeyEvent) {
        if self.inspector.open && self.active_tab == Tab::Events {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    self.close_event_inspector();
                    return;
                }
                KeyCode::Char('p') => {
                    self.request_active_payload();
                    return;
                }
                KeyCode::Char(']') => {
                    self.inspector.active_part = self.inspector.active_part.next();
                    self.inspector.error = None;
                    return;
                }
                KeyCode::Char('[') => {
                    self.inspector.active_part = self.inspector.active_part.prev();
                    self.inspector.error = None;
                    return;
                }
                KeyCode::Char('q') => {
                    self.should_quit = true;
                    return;
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.should_quit = true;
                    return;
                }
                _ => return,
            }
        }

        match key.code {
            // Quit
            KeyCode::Char('q') | KeyCode::Esc => {
                self.should_quit = true;
            }
            // Quit with Ctrl+C
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
            }

            // Tab navigation with numbers
            KeyCode::Char('1') => self.active_tab = Tab::Dashboard,
            KeyCode::Char('2') => self.active_tab = Tab::Events,
            KeyCode::Char('3') => self.active_tab = Tab::Agents,
            KeyCode::Char('4') | KeyCode::Char('?') => self.active_tab = Tab::Help,

            // Tab cycling
            KeyCode::Tab => {
                if key.modifiers.contains(KeyModifiers::SHIFT) {
                    self.active_tab = self.active_tab.prev();
                } else {
                    self.active_tab = self.active_tab.next();
                }
            }

            // Panel navigation (Dashboard tab)
            KeyCode::Left | KeyCode::Char('h') if self.active_tab == Tab::Dashboard => {
                self.focused_panel = self.focused_panel.prev();
            }
            KeyCode::Right | KeyCode::Char('l') if self.active_tab == Tab::Dashboard => {
                self.focused_panel = self.focused_panel.next();
            }

            // Scrolling (Events/Agents tabs)
            KeyCode::Up | KeyCode::Char('k') => self.scroll_up(1),
            KeyCode::Down | KeyCode::Char('j') => self.scroll_down(1),
            KeyCode::PageUp => self.scroll_up(10),
            KeyCode::PageDown => self.scroll_down(10),
            KeyCode::Home => self.scroll_home(),
            KeyCode::End => self.scroll_end(),

            // Open event inspector
            KeyCode::Enter if self.active_tab == Tab::Events => {
                self.open_event_inspector();
            }

            // Toggle auto-refresh (freeze/live)
            KeyCode::Char('f') => {
                self.auto_refresh = !self.auto_refresh;
            }

            // Timeline window controls
            KeyCode::Char('w') if self.active_tab == Tab::Dashboard => {
                self.rollup_window = self.rollup_window.next();
            }
            KeyCode::Char('-') if self.active_tab == Tab::Dashboard => {
                self.rollup_window = self.rollup_window.prev();
            }
            KeyCode::Char('=') if self.active_tab == Tab::Dashboard => {
                self.rollup_window = self.rollup_window.next();
            }

            // Event filter controls
            KeyCode::Char('[') if self.active_tab == Tab::Events => {
                self.event_filter = self.event_filter.prev();
                self.invalidate_filtered_events();
                self.events_scroll.home();
            }
            KeyCode::Char(']') if self.active_tab == Tab::Events => {
                self.event_filter = self.event_filter.next();
                self.invalidate_filtered_events();
                self.events_scroll.home();
            }

            // Force refresh
            KeyCode::Char('r') => {
                self.refresh_requested = true;
                self.error_message = None;
            }

            _ => {}
        }
    }

    fn scroll_up(&mut self, amount: usize) {
        match self.active_tab {
            Tab::Events => self.events_scroll.scroll_up(amount),
            Tab::Agents => self.agents_scroll.scroll_up(amount),
            _ => {}
        }
    }

    fn scroll_down(&mut self, amount: usize) {
        match self.active_tab {
            Tab::Events => {
                let max = self.filtered_events_len();
                self.events_scroll.scroll_down(amount, max);
            }
            Tab::Agents => {
                self.agents_scroll.scroll_down(amount, self.agents.len());
            }
            _ => {}
        }
    }

    fn scroll_home(&mut self) {
        match self.active_tab {
            Tab::Events => self.events_scroll.home(),
            Tab::Agents => self.agents_scroll.home(),
            _ => {}
        }
    }

    fn scroll_end(&mut self) {
        match self.active_tab {
            Tab::Events => {
                let max = self.filtered_events_len();
                self.events_scroll.end(max);
            }
            Tab::Agents => self.agents_scroll.end(self.agents.len()),
            _ => {}
        }
    }

    /// Handle tick events
    pub fn on_tick(&mut self) {
        // Update any animations or time-based state here
    }

    /// Apply hot-lane fetch results (events/clusters/stream stats).
    pub fn apply_hot_success(&mut self, data: api::HotData) {
        self.merge_events(data.events);
        self.merge_clusters(data.clusters);
        self.metrics.stream_stats = Some(data.stream_stats);
        self.metrics.last_updated = Some(Instant::now());
        self.connection = ConnectionState::Connected;
        self.error_message = None;
        self.consecutive_failures = 0;
    }

    /// Apply cold-lane fetch results (snapshot/budget/rollups/agents).
    pub fn apply_cold_success(&mut self, data: api::ColdData) {
        self.metrics.identity = Some(data.identity);
        self.metrics.policy = Some(data.policy);
        self.metrics.observe = Some(data.observe);
        self.metrics.budget_primitives = Some(data.budget_primitives);
        self.metrics.proxy = Some(data.proxy);
        self.metrics.rollups = data.rollups;
        self.metrics.uptime_secs = data.uptime_secs;
        self.metrics.last_updated = Some(Instant::now());
        self.agents = data.agents;
        self.connection = ConnectionState::Connected;
        self.error_message = None;
        self.consecutive_failures = 0;
    }

    /// Apply a failed dashboard fetch result to state.
    pub fn apply_fetch_error(&mut self, error: String) {
        self.consecutive_failures += 1;
        let in_startup_grace = self.metrics.last_updated.is_none()
            && self.started_at.elapsed() < Duration::from_secs(STARTUP_CONNECT_GRACE_SECS);
        if in_startup_grace {
            self.connection = ConnectionState::Connecting;
            self.error_message = None;
            return;
        }

        // Avoid popup flicker for transient blips; show full error only after repeated failures.
        if self.consecutive_failures < 3 {
            if self.metrics.last_updated.is_none() {
                self.connection = ConnectionState::Connecting;
            }
            self.error_message = None;
            return;
        }

        let hint = if error.contains("Connection refused")
            || error.contains("failed to connect")
            || error.contains("error sending request")
            || error.contains("operation timed out")
        {
            format!(
                "{error} | hint: ensure `soth start` is running and API is reachable at http://127.0.0.1:3001"
            )
        } else {
            error
        };
        self.error_message = Some(hint);

        self.connection = ConnectionState::Disconnected;
    }

    /// Cold-lane failures should not flap connectivity once hot lane is healthy.
    pub fn apply_cold_error(&mut self, error: String) {
        if self.metrics.last_updated.is_none() {
            self.apply_fetch_error(error);
        }
    }

    /// Cursor for incremental `/api/events?...&since_seq=...`.
    pub fn event_seq_cursor(&self) -> Option<i64> {
        self.event_seq_cursor
    }

    /// Cursor for incremental `/api/clusters?...&since_seq=...`.
    pub fn cluster_seq_cursor(&self) -> Option<i64> {
        self.cluster_seq_cursor
    }

    /// Consume the explicit refresh request flag.
    pub fn take_refresh_request(&mut self) -> bool {
        let requested = self.refresh_requested;
        self.refresh_requested = false;
        requested
    }

    /// Whether periodic fetch ticks should fetch new data.
    pub fn auto_refresh_enabled(&self) -> bool {
        self.auto_refresh
    }

    /// Current event filter label.
    pub fn event_filter_label(&self) -> &'static str {
        self.event_filter.label()
    }

    /// Current rollup window label.
    pub fn rollup_window_label(&self) -> &'static str {
        self.rollup_window.label()
    }

    /// Number of rollup points to use for timeline.
    pub fn rollup_points(&self) -> usize {
        self.rollup_window.points()
    }

    /// Current filtered event count using cached indices.
    pub fn filtered_events_len(&mut self) -> usize {
        self.filtered_event_indices().len()
    }

    /// Visible filtered event indices window (maps to `self.events`).
    pub fn filtered_event_indices_window(&mut self, offset: usize, limit: usize) -> Vec<usize> {
        self.filtered_event_indices()
            .iter()
            .skip(offset)
            .take(limit)
            .copied()
            .collect()
    }

    /// Cloned event for selected filtered index.
    pub fn cloned_filtered_event(&mut self, filtered_idx: usize) -> Option<WrapEvent> {
        let event_idx = *self.filtered_event_indices().get(filtered_idx)?;
        self.events.get(event_idx).cloned()
    }

    /// Whether event inspector modal is open.
    pub fn event_inspector_open(&self) -> bool {
        self.inspector.open
    }

    /// Immutable accessor for event inspector state.
    pub fn event_inspector(&self) -> &EventInspector {
        &self.inspector
    }

    /// Open event inspector for selected row in current filtered event list.
    pub fn open_event_inspector(&mut self) {
        let idx = self.events_scroll.selected;
        let selected = self.cloned_filtered_event(idx);
        if let Some(event) = selected {
            self.inspector.open = true;
            self.inspector.event = Some(event);
            self.inspector.active_part = PayloadPart::Request;
            self.inspector.request_payload = None;
            self.inspector.response_payload = None;
            self.inspector.content_payload = None;
            self.inspector.loading = false;
            self.inspector.error = None;
            self.inspector.pending_request = None;
        }
    }

    /// Close event inspector and clear transient state.
    pub fn close_event_inspector(&mut self) {
        self.inspector.open = false;
        self.inspector.event = None;
        self.inspector.request_payload = None;
        self.inspector.response_payload = None;
        self.inspector.content_payload = None;
        self.inspector.loading = false;
        self.inspector.pending_request = None;
        self.inspector.error = None;
    }

    /// Mark active payload part for lazy fetching.
    pub fn request_active_payload(&mut self) {
        if !self.inspector.open {
            return;
        }
        let part = self.inspector.active_part;
        if self.inspector.payload_for_part(part).is_some() {
            return;
        }
        if self.inspector.event.as_ref().is_none() {
            return;
        }
        self.inspector.loading = true;
        self.inspector.error = None;
        self.inspector.pending_request = Some(part);
    }

    /// Consume pending payload request (event_id, part).
    pub fn take_payload_request(&mut self) -> Option<(String, PayloadPart)> {
        let Some(part) = self.inspector.pending_request.take() else {
            return None;
        };
        let event_id = self.inspector.event.as_ref()?.id.clone();
        Some((event_id, part))
    }

    /// Apply payload fetch result back into inspector.
    pub fn apply_payload_result(&mut self, part: PayloadPart, result: Result<String, String>) {
        self.inspector.loading = false;
        match result {
            Ok(content) => {
                let total_chars = content.chars().count();
                let truncated = total_chars > MAX_INSPECTOR_PAYLOAD_CHARS;
                let text = if truncated {
                    content
                        .chars()
                        .take(MAX_INSPECTOR_PAYLOAD_CHARS)
                        .collect::<String>()
                } else {
                    content
                };
                self.inspector.set_payload_for_part(
                    part,
                    PayloadPreview {
                        text,
                        truncated,
                        total_chars,
                    },
                );
                self.inspector.error = None;
            }
            Err(error) => {
                self.inspector.error = Some(error);
            }
        }
    }

    fn merge_events(&mut self, mut incoming: Vec<WrapEvent>) {
        if incoming.is_empty() {
            return;
        }

        // Normalize ordering to oldest->newest before push_front merge.
        let should_reverse = match (
            incoming.first().and_then(|event| event.seq),
            incoming.last().and_then(|event| event.seq),
        ) {
            (Some(first), Some(last)) => first > last,
            _ => false,
        };
        if should_reverse {
            incoming.reverse();
        }

        for event in incoming {
            if let Some(seq) = event.seq {
                self.event_seq_cursor =
                    Some(self.event_seq_cursor.map_or(seq, |curr| curr.max(seq)));
            }
            if !self.events.iter().any(|existing| existing.id == event.id) {
                self.events.push_front(event);
            }
        }

        while self.events.len() > MAX_EVENTS {
            self.events.pop_back();
        }

        self.invalidate_filtered_events();
    }

    fn merge_clusters(&mut self, incoming: Vec<api::ClusterRow>) {
        if incoming.is_empty() {
            return;
        }

        let mut merged = incoming;
        merged.extend(self.metrics.clusters.iter().cloned());
        merged.sort_by(|a, b| b.request_seq.cmp(&a.request_seq));
        merged.dedup_by_key(|row| row.request_seq);
        merged.truncate(MAX_CLUSTERS);

        self.cluster_seq_cursor = merged
            .iter()
            .map(|row| row.request_seq)
            .max()
            .or(self.cluster_seq_cursor);

        self.metrics.clusters = merged;
    }

    fn invalidate_filtered_events(&mut self) {
        self.filtered_event_indices_dirty = true;
    }

    fn filtered_event_indices(&mut self) -> &[usize] {
        if self.filtered_event_indices_dirty {
            let filter = self.event_filter;
            self.filtered_event_indices.clear();
            for (idx, event) in self.events.iter().enumerate() {
                if event_matches_filter(event, filter) {
                    self.filtered_event_indices.push(idx);
                }
            }
            self.filtered_event_indices_dirty = false;
        }
        &self.filtered_event_indices
    }

    /// Get uptime as a formatted string
    #[allow(dead_code)]
    pub fn uptime_string(&self) -> String {
        let secs = self.started_at.elapsed().as_secs();
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        if hours > 0 {
            format!("{}h {}m", hours, mins)
        } else {
            format!("{}m {}s", mins, secs % 60)
        }
    }

    /// Get time since last update
    pub fn last_updated_string(&self) -> String {
        match self.metrics.last_updated {
            Some(instant) => {
                let secs = instant.elapsed().as_secs();
                if secs < 60 {
                    format!("{}s ago", secs)
                } else {
                    format!("{}m ago", secs / 60)
                }
            }
            None => "never".to_string(),
        }
    }
}

fn event_matches_filter(event: &WrapEvent, filter: EventFilter) -> bool {
    match filter {
        EventFilter::All => true,
        EventFilter::Ai => event.source == EventSource::AiProxy,
        EventFilter::Mcp => event.source == EventSource::Mcp,
        EventFilter::Agent => event.source == EventSource::AgentApp,
        EventFilter::Denied => event.policy_allowed == Some(false),
        EventFilter::Errors => {
            event.status_code.is_some_and(|status| status >= 400)
                || event.policy_allowed == Some(false)
        }
    }
}
