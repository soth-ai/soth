use crate::extension::ExtensionArchetype;

// ---------------------------------------------------------------------------
// LifecycleState — tracks where an extension is in its runtime lifecycle
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    /// Extension registered but not yet started.
    Idle,
    /// Running initial bulk data import (historian backfill, etc.).
    Backfilling,
    /// Bulk import done, now watching for incremental changes.
    Watching,
    /// Shutdown signal sent, waiting for clean exit.
    ShuttingDown,
    /// Fully stopped.
    Stopped,
}

impl Default for LifecycleState {
    fn default() -> Self {
        Self::Idle
    }
}

// ---------------------------------------------------------------------------
// BackfillProgressSnapshot — progress report for bulk data import
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct BackfillProgressSnapshot {
    pub tools: Vec<ToolBackfillProgress>,
    pub total_sessions_done: u64,
    pub total_sessions_estimated: u64,
}

#[derive(Debug, Clone)]
pub struct ToolBackfillProgress {
    pub tool_name: String,
    pub sessions_total: u64,
    pub sessions_done: u64,
    pub completed: bool,
}

// ---------------------------------------------------------------------------
// ExtensionStatus — reported by `soth status`
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ExtensionStatus {
    pub name: String,
    pub version: String,
    pub archetype: ExtensionArchetype,
    pub installed: bool,
    pub enabled: bool,
    pub healthy: bool,
    // Lifecycle
    pub lifecycle_state: LifecycleState,
    pub backfill_progress: Option<BackfillProgressSnapshot>,
    // Governance extension fields (zeroed for passive observers)
    pub last_event: Option<i64>,
    pub event_count: u64,
    pub governance_queue_depth: usize,
    // Passive observer fields (zeroed for governance extensions)
    pub last_observation: Option<i64>,
    pub observation_count: u64,
    pub observation_queue_depth: usize,
    // Shared
    pub warnings: Vec<String>,
}

impl Default for ExtensionStatus {
    fn default() -> Self {
        Self {
            name: String::new(),
            version: String::new(),
            archetype: ExtensionArchetype::Governance,
            installed: false,
            enabled: false,
            healthy: false,
            lifecycle_state: LifecycleState::default(),
            backfill_progress: None,
            last_event: None,
            event_count: 0,
            governance_queue_depth: 0,
            last_observation: None,
            observation_count: 0,
            observation_queue_depth: 0,
            warnings: Vec::new(),
        }
    }
}
