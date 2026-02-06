//! Application state for the TUI dashboard

use crate::commands::tui::api;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use soth_core::types::WrapEvent;
use soth_dashboard::state::{
    BudgetMetrics, IdentityMetrics, ObserveMetrics, PolicyMetrics, ProxyMetrics,
};
use soth_dashboard::event_store::AgentStats;
use std::collections::VecDeque;
use std::time::Instant;

/// Maximum number of events to keep in memory
const MAX_EVENTS: usize = 500;

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
            Tab::Dashboard => "Dashboard",
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
    None,
    Identity,
    Policy,
    Observe,
    Budget,
    Proxy,
    Summary,
}

impl PanelFocus {
    pub fn next(self) -> Self {
        match self {
            PanelFocus::None => PanelFocus::Identity,
            PanelFocus::Identity => PanelFocus::Policy,
            PanelFocus::Policy => PanelFocus::Proxy,
            PanelFocus::Proxy => PanelFocus::Observe,
            PanelFocus::Observe => PanelFocus::Budget,
            PanelFocus::Budget => PanelFocus::Summary,
            PanelFocus::Summary => PanelFocus::Identity,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            PanelFocus::None => PanelFocus::Summary,
            PanelFocus::Identity => PanelFocus::Summary,
            PanelFocus::Policy => PanelFocus::Identity,
            PanelFocus::Proxy => PanelFocus::Policy,
            PanelFocus::Observe => PanelFocus::Proxy,
            PanelFocus::Budget => PanelFocus::Observe,
            PanelFocus::Summary => PanelFocus::Budget,
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
    pub budget: Option<BudgetMetrics>,
    pub proxy: Option<ProxyMetrics>,
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
}

impl App {
    pub fn new(api_url: String) -> Self {
        Self {
            active_tab: Tab::Dashboard,
            focused_panel: PanelFocus::None,
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
        }
    }

    /// Handle key events
    pub fn on_key(&mut self, key: KeyEvent) {
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

            // Force refresh
            KeyCode::Char('r') => {
                // Will be handled by next tick
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
                self.events_scroll.scroll_down(amount, self.events.len());
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
            Tab::Events => self.events_scroll.end(self.events.len()),
            Tab::Agents => self.agents_scroll.end(self.agents.len()),
            _ => {}
        }
    }

    /// Handle tick events
    pub fn on_tick(&mut self) {
        // Update any animations or time-based state here
    }

    /// Fetch all data from the dashboard API
    pub async fn fetch_all(&mut self, api_url: &str) {
        match api::fetch_all(api_url).await {
            Ok(data) => {
                self.metrics.identity = Some(data.identity);
                self.metrics.policy = Some(data.policy);
                self.metrics.observe = Some(data.observe);
                self.metrics.budget = Some(data.budget);
                self.metrics.proxy = Some(data.proxy);
                self.metrics.uptime_secs = data.uptime_secs;
                self.metrics.last_updated = Some(Instant::now());

                // Update events (merge new ones)
                for event in data.events.into_iter().rev() {
                    if !self.events.iter().any(|e| e.timestamp == event.timestamp && e.session_id == event.session_id) {
                        self.events.push_front(event);
                    }
                }
                while self.events.len() > MAX_EVENTS {
                    self.events.pop_back();
                }

                self.agents = data.agents;
                self.connection = ConnectionState::Connected;
                self.error_message = None;
                self.consecutive_failures = 0;
            }
            Err(e) => {
                self.consecutive_failures += 1;
                self.error_message = Some(e.to_string());

                if self.consecutive_failures >= 3 {
                    self.connection = ConnectionState::Disconnected;
                }
            }
        }
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
