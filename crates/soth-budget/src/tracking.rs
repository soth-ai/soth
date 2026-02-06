//! Spend tracking module

use crate::cost::CostCalculator;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use soth_core::types::budget::{BudgetScope, BudgetState, SpendRecord, TokenUsage};
use std::collections::HashMap;
use std::sync::Arc;

/// Spend tracker for recording costs
pub struct SpendTracker {
    /// Records by session
    records: RwLock<Vec<SpendRecord>>,
    /// Cost calculator
    calculator: CostCalculator,
}

impl SpendTracker {
    /// Create a new spend tracker
    pub fn new() -> Self {
        Self {
            records: RwLock::new(Vec::new()),
            calculator: CostCalculator::new(),
        }
    }

    /// Record a spend event
    pub fn record(
        &self,
        session_id: &str,
        agent_id: Option<&str>,
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
        method: Option<&str>,
    ) -> SpendRecord {
        let usage = TokenUsage::new(input_tokens, output_tokens);
        let cost = self.calculator.calculate_cost(model, &usage);

        let record = SpendRecord {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            agent_id: agent_id.map(|s| s.to_string()),
            timestamp: Utc::now(),
            model: model.to_string(),
            token_usage: usage,
            cost,
            method: method.map(|s| s.to_string()),
        };

        self.records.write().push(record.clone());
        record
    }

    /// Get total spend
    pub fn total_spend(&self) -> f64 {
        self.records.read().iter().map(|r| r.cost).sum()
    }

    /// Get spend for a session
    pub fn session_spend(&self, session_id: &str) -> f64 {
        self.records
            .read()
            .iter()
            .filter(|r| r.session_id == session_id)
            .map(|r| r.cost)
            .sum()
    }

    /// Get spend for an agent
    pub fn agent_spend(&self, agent_id: &str) -> f64 {
        self.records
            .read()
            .iter()
            .filter(|r| r.agent_id.as_deref() == Some(agent_id))
            .map(|r| r.cost)
            .sum()
    }

    /// Get all records
    pub fn records(&self) -> Vec<SpendRecord> {
        self.records.read().clone()
    }

    /// Get records for a time period
    pub fn records_since(&self, since: DateTime<Utc>) -> Vec<SpendRecord> {
        self.records
            .read()
            .iter()
            .filter(|r| r.timestamp >= since)
            .cloned()
            .collect()
    }

    /// Clear all records
    pub fn clear(&self) {
        self.records.write().clear();
    }
}

impl Default for SpendTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Budget tracker with limits
pub struct BudgetTracker {
    /// Spend tracker
    spend_tracker: Arc<SpendTracker>,
    /// Budget states by ID
    budgets: RwLock<HashMap<String, BudgetState>>,
    /// Global budget
    global_budget: RwLock<Option<BudgetState>>,
}

impl BudgetTracker {
    /// Create a new budget tracker
    pub fn new() -> Self {
        Self {
            spend_tracker: Arc::new(SpendTracker::new()),
            budgets: RwLock::new(HashMap::new()),
            global_budget: RwLock::new(None),
        }
    }

    /// Set a global budget
    pub fn set_global_budget(&self, daily: Option<f64>, weekly: Option<f64>, monthly: Option<f64>) {
        let mut budget = BudgetState::new("global", BudgetScope::Global);
        budget.daily_limit = daily;
        budget.weekly_limit = weekly;
        budget.monthly_limit = monthly;
        *self.global_budget.write() = Some(budget);
    }

    /// Set an agent budget
    pub fn set_agent_budget(
        &self,
        agent_id: &str,
        daily: Option<f64>,
        weekly: Option<f64>,
        monthly: Option<f64>,
    ) {
        let mut budget = BudgetState::new(agent_id, BudgetScope::PerAgent);
        budget.daily_limit = daily;
        budget.weekly_limit = weekly;
        budget.monthly_limit = monthly;
        self.budgets.write().insert(agent_id.to_string(), budget);
    }

    /// Record spend and update budgets
    pub fn record_spend(
        &self,
        session_id: &str,
        agent_id: Option<&str>,
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
    ) -> SpendRecord {
        let record = self.spend_tracker.record(
            session_id,
            agent_id,
            model,
            input_tokens,
            output_tokens,
            None,
        );

        // Update global budget
        if let Some(ref mut budget) = *self.global_budget.write() {
            budget.current_spend += record.cost;
            budget.total_tokens += record.token_usage.total_tokens;
            budget.total_requests += 1;
            budget.updated_at = Utc::now();
        }

        // Update agent budget
        if let Some(agent_id) = agent_id {
            if let Some(budget) = self.budgets.write().get_mut(agent_id) {
                budget.current_spend += record.cost;
                budget.total_tokens += record.token_usage.total_tokens;
                budget.total_requests += 1;
                budget.updated_at = Utc::now();
            }
        }

        record
    }

    /// Check if a budget is exceeded
    pub fn is_budget_exceeded(&self, agent_id: Option<&str>) -> bool {
        // Check global budget
        if let Some(ref budget) = *self.global_budget.read() {
            if budget.is_exceeded() {
                return true;
            }
        }

        // Check agent budget
        if let Some(agent_id) = agent_id {
            if let Some(budget) = self.budgets.read().get(agent_id) {
                if budget.is_exceeded() {
                    return true;
                }
            }
        }

        false
    }

    /// Get budget status for an agent
    pub fn get_budget_status(&self, agent_id: &str) -> Option<BudgetState> {
        self.budgets.read().get(agent_id).cloned()
    }

    /// Get global budget status
    pub fn get_global_status(&self) -> Option<BudgetState> {
        self.global_budget.read().clone()
    }

    /// Get the spend tracker
    pub fn spend_tracker(&self) -> Arc<SpendTracker> {
        Arc::clone(&self.spend_tracker)
    }

    /// Reset budgets for a new period
    pub fn reset_budgets(&self) {
        if let Some(ref mut budget) = *self.global_budget.write() {
            budget.current_spend = 0.0;
            budget.period_start = Utc::now();
        }

        for budget in self.budgets.write().values_mut() {
            budget.current_spend = 0.0;
            budget.period_start = Utc::now();
        }

        self.spend_tracker.clear();
    }
}

impl Default for BudgetTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spend_tracker() {
        let tracker = SpendTracker::new();

        tracker.record(
            "session-1",
            Some("agent-1"),
            "gpt-4o",
            1000,
            500,
            Some("tools/call"),
        );
        tracker.record("session-1", Some("agent-1"), "gpt-4o", 2000, 1000, None);

        let total = tracker.total_spend();
        assert!(total > 0.0);

        let records = tracker.records();
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn test_session_spend() {
        let tracker = SpendTracker::new();

        tracker.record("session-1", None, "gpt-4o", 1000, 500, None);
        tracker.record("session-2", None, "gpt-4o", 2000, 1000, None);

        let s1_spend = tracker.session_spend("session-1");
        let s2_spend = tracker.session_spend("session-2");

        assert!(s2_spend > s1_spend);
    }

    #[test]
    fn test_budget_tracker() {
        let tracker = BudgetTracker::new();

        tracker.set_global_budget(Some(10.0), None, None);

        assert!(!tracker.is_budget_exceeded(None));

        // Record a lot of spend
        for _ in 0..100 {
            tracker.record_spend("session-1", None, "gpt-4o", 1_000_000, 500_000);
        }

        // Should exceed budget now
        assert!(tracker.is_budget_exceeded(None));
    }

    #[test]
    fn test_agent_budget() {
        let tracker = BudgetTracker::new();

        tracker.set_agent_budget("agent-1", Some(1.0), None, None);

        tracker.record_spend("session-1", Some("agent-1"), "gpt-4o", 1_000_000, 500_000);

        let status = tracker.get_budget_status("agent-1").unwrap();
        assert!(status.current_spend > 0.0);
    }
}
