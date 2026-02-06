//! Alert evaluation and notification

use chrono::Utc;
use soth_core::types::budget::{AlertAction, AlertThreshold, BudgetAlert, BudgetState};

/// Alert evaluator
pub struct AlertEvaluator {
    /// Alert thresholds
    thresholds: Vec<AlertThreshold>,
    /// Fired alerts (to avoid duplicates)
    fired: std::collections::HashSet<(String, u8)>,
}

impl AlertEvaluator {
    /// Create a new alert evaluator
    pub fn new(thresholds: Vec<AlertThreshold>) -> Self {
        Self {
            thresholds,
            fired: std::collections::HashSet::new(),
        }
    }

    /// Add an alert threshold
    pub fn add_threshold(&mut self, threshold_percent: u8, action: AlertAction) {
        self.thresholds.push(AlertThreshold {
            threshold_percent,
            action,
            webhook_url: None,
        });
    }

    /// Add a threshold with webhook
    pub fn add_threshold_with_webhook(
        &mut self,
        threshold_percent: u8,
        action: AlertAction,
        webhook_url: &str,
    ) {
        self.thresholds.push(AlertThreshold {
            threshold_percent,
            action,
            webhook_url: Some(webhook_url.to_string()),
        });
    }

    /// Evaluate budget and return any new alerts
    pub fn evaluate(&mut self, budget: &BudgetState) -> Vec<BudgetAlert> {
        let mut alerts = Vec::new();

        let usage_percent = match budget.usage_percent() {
            Some(p) => p,
            None => return alerts,
        };

        let limit = budget
            .daily_limit
            .or(budget.weekly_limit)
            .or(budget.monthly_limit)
            .unwrap_or(0.0);

        for threshold in &self.thresholds {
            if usage_percent >= threshold.threshold_percent as f64 {
                let key = (budget.id.clone(), threshold.threshold_percent);

                // Check if already fired
                if !self.fired.contains(&key) {
                    self.fired.insert(key);

                    alerts.push(BudgetAlert {
                        id: uuid::Uuid::new_v4().to_string(),
                        budget_id: budget.id.clone(),
                        threshold_percent: threshold.threshold_percent,
                        current_spend: budget.current_spend,
                        limit,
                        action: threshold.action,
                        timestamp: Utc::now(),
                    });
                }
            }
        }

        alerts
    }

    /// Reset fired alerts for a budget
    pub fn reset(&mut self, budget_id: &str) {
        self.fired.retain(|(id, _)| id != budget_id);
    }

    /// Reset all fired alerts
    pub fn reset_all(&mut self) {
        self.fired.clear();
    }
}

impl Default for AlertEvaluator {
    fn default() -> Self {
        Self::new(vec![
            AlertThreshold {
                threshold_percent: 50,
                action: AlertAction::Notify,
                webhook_url: None,
            },
            AlertThreshold {
                threshold_percent: 80,
                action: AlertAction::Warn,
                webhook_url: None,
            },
            AlertThreshold {
                threshold_percent: 100,
                action: AlertAction::Block,
                webhook_url: None,
            },
        ])
    }
}

/// Alert notifier
pub struct AlertNotifier {
    /// HTTP client
    client: Option<reqwest::Client>,
}

impl AlertNotifier {
    /// Create a new alert notifier
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .ok(),
        }
    }

    /// Send alert notification
    pub async fn notify(&self, alert: &BudgetAlert, webhook_url: Option<&str>) {
        // Log the alert
        match alert.action {
            AlertAction::Notify => {
                tracing::info!(
                    "Budget alert: {} at {}% (${:.2} / ${:.2})",
                    alert.budget_id,
                    alert.threshold_percent,
                    alert.current_spend,
                    alert.limit
                );
            }
            AlertAction::Warn => {
                tracing::warn!(
                    "Budget warning: {} at {}% (${:.2} / ${:.2})",
                    alert.budget_id,
                    alert.threshold_percent,
                    alert.current_spend,
                    alert.limit
                );
            }
            AlertAction::Block => {
                tracing::error!(
                    "Budget exceeded: {} at {}% (${:.2} / ${:.2}) - blocking",
                    alert.budget_id,
                    alert.threshold_percent,
                    alert.current_spend,
                    alert.limit
                );
            }
        }

        // Send webhook if configured
        if let (Some(client), Some(url)) = (&self.client, webhook_url) {
            let payload = serde_json::json!({
                "type": "budget_alert",
                "alert": {
                    "id": alert.id,
                    "budget_id": alert.budget_id,
                    "threshold_percent": alert.threshold_percent,
                    "current_spend": alert.current_spend,
                    "limit": alert.limit,
                    "action": format!("{:?}", alert.action),
                    "timestamp": alert.timestamp.to_rfc3339()
                }
            });

            if let Err(e) = client.post(url).json(&payload).send().await {
                tracing::error!("Failed to send webhook: {}", e);
            }
        }
    }
}

impl Default for AlertNotifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soth_core::types::budget::BudgetScope;

    #[test]
    fn test_alert_evaluator() {
        let mut evaluator = AlertEvaluator::default();

        let mut budget = BudgetState::new("test", BudgetScope::Global);
        budget.daily_limit = Some(100.0);
        budget.current_spend = 50.0;

        let alerts = evaluator.evaluate(&budget);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].threshold_percent, 50);

        // Shouldn't fire again
        let alerts = evaluator.evaluate(&budget);
        assert_eq!(alerts.len(), 0);
    }

    #[test]
    fn test_multiple_thresholds() {
        let mut evaluator = AlertEvaluator::default();

        let mut budget = BudgetState::new("test", BudgetScope::Global);
        budget.daily_limit = Some(100.0);
        budget.current_spend = 85.0;

        let alerts = evaluator.evaluate(&budget);
        // Should fire 50% and 80%
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn test_reset() {
        let mut evaluator = AlertEvaluator::default();

        let mut budget = BudgetState::new("test", BudgetScope::Global);
        budget.daily_limit = Some(100.0);
        budget.current_spend = 50.0;

        evaluator.evaluate(&budget);
        evaluator.reset("test");

        // Should fire again after reset
        let alerts = evaluator.evaluate(&budget);
        assert_eq!(alerts.len(), 1);
    }
}
