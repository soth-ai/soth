//! MCP Cost Attribution - correlate AI costs with MCP tool calls
//!
//! Tracks MCP sessions and tool calls to attribute AI inference costs
//! to the tools that triggered them.

use chrono::{DateTime, Duration, Utc};
use parking_lot::RwLock;
use soth_core::types::budget::ToolCostEntry;
use std::collections::HashMap;
use uuid::Uuid;

/// Tracks MCP sessions and correlates with AI inference costs
pub struct McpCostAttributor {
    /// Active MCP sessions: session_id -> McpSessionContext
    sessions: RwLock<HashMap<String, McpSessionContext>>,

    /// Pending tool calls: correlation_id -> PendingToolCall
    pending_calls: RwLock<HashMap<String, PendingToolCall>>,

    /// Completed attributions for reporting
    attributions: RwLock<Vec<McpAttributedCost>>,

    /// Maximum age for pending calls before cleanup (5 minutes)
    max_pending_age: Duration,

    /// Maximum attributions to keep
    max_attributions: usize,
}

/// Context for an active MCP session
#[derive(Debug, Clone)]
pub struct McpSessionContext {
    /// Session ID
    pub session_id: String,

    /// MCP server name
    pub server_name: String,

    /// Agent ID (if known)
    pub agent_id: Option<String>,

    /// When session started
    pub started_at: DateTime<Utc>,

    /// Total cost attributed to this session
    pub total_cost: f64,

    /// Cost by tool within this session
    pub tool_costs: HashMap<String, f64>,

    /// Call count by tool
    pub tool_call_counts: HashMap<String, u64>,

    /// Last activity timestamp
    pub last_activity: DateTime<Utc>,
}

/// A pending tool call waiting for attribution
#[derive(Debug, Clone)]
pub struct PendingToolCall {
    /// Correlation ID
    pub correlation_id: String,

    /// Session ID
    pub session_id: String,

    /// Tool name
    pub tool_name: String,

    /// MCP server name
    pub server_name: String,

    /// When the tool call started
    pub started_at: DateTime<Utc>,

    /// Accumulated cost so far
    pub accumulated_cost: f64,

    /// Accumulated input tokens
    pub accumulated_input_tokens: u64,

    /// Accumulated output tokens
    pub accumulated_output_tokens: u64,
}

/// Attributed cost record
#[derive(Debug, Clone)]
pub struct McpAttributedCost {
    /// Tool name
    pub tool_name: String,

    /// MCP server name
    pub server_name: String,

    /// Session ID
    pub session_id: String,

    /// AI inference cost attributed
    pub inference_cost: f64,

    /// Input tokens used
    pub input_tokens: u64,

    /// Output tokens used
    pub output_tokens: u64,

    /// Model used
    pub model: String,

    /// When this attribution was recorded
    pub timestamp: DateTime<Utc>,
}

impl McpCostAttributor {
    /// Create a new MCP cost attributor
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            pending_calls: RwLock::new(HashMap::new()),
            attributions: RwLock::new(Vec::new()),
            max_pending_age: Duration::minutes(5),
            max_attributions: 10_000,
        }
    }

    /// Start tracking an MCP session
    pub fn start_session(&self, session_id: &str, server_name: &str, agent_id: Option<&str>) {
        let mut sessions = self.sessions.write();
        sessions.insert(
            session_id.to_string(),
            McpSessionContext {
                session_id: session_id.to_string(),
                server_name: server_name.to_string(),
                agent_id: agent_id.map(|s| s.to_string()),
                started_at: Utc::now(),
                total_cost: 0.0,
                tool_costs: HashMap::new(),
                tool_call_counts: HashMap::new(),
                last_activity: Utc::now(),
            },
        );
    }

    /// End an MCP session and return its context
    pub fn end_session(&self, session_id: &str) -> Option<McpSessionContext> {
        self.sessions.write().remove(session_id)
    }

    /// Record a tool call starting (from MCP tools/call request)
    /// Returns a correlation_id for attributing subsequent AI calls
    pub fn start_tool_call(&self, session_id: &str, tool_name: &str) -> String {
        let correlation_id = Uuid::new_v4().to_string();

        // Get server name from session
        let server_name = {
            let sessions = self.sessions.read();
            sessions
                .get(session_id)
                .map(|s| s.server_name.clone())
                .unwrap_or_else(|| "unknown".to_string())
        };

        let pending = PendingToolCall {
            correlation_id: correlation_id.clone(),
            session_id: session_id.to_string(),
            tool_name: tool_name.to_string(),
            server_name,
            started_at: Utc::now(),
            accumulated_cost: 0.0,
            accumulated_input_tokens: 0,
            accumulated_output_tokens: 0,
        };

        self.pending_calls
            .write()
            .insert(correlation_id.clone(), pending);

        // Update session activity
        if let Some(session) = self.sessions.write().get_mut(session_id) {
            session.last_activity = Utc::now();
        }

        correlation_id
    }

    /// Attribute an AI inference cost to an active tool call
    pub fn attribute_inference(
        &self,
        correlation_id: &str,
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
        cost: f64,
    ) -> Option<McpAttributedCost> {
        let mut pending = self.pending_calls.write();

        if let Some(call) = pending.get_mut(correlation_id) {
            // Accumulate costs
            call.accumulated_cost += cost;
            call.accumulated_input_tokens += input_tokens;
            call.accumulated_output_tokens += output_tokens;

            let attribution = McpAttributedCost {
                tool_name: call.tool_name.clone(),
                server_name: call.server_name.clone(),
                session_id: call.session_id.clone(),
                inference_cost: cost,
                input_tokens,
                output_tokens,
                model: model.to_string(),
                timestamp: Utc::now(),
            };

            // Update session totals
            drop(pending); // Release pending lock before acquiring sessions lock
            if let Some(session) = self.sessions.write().get_mut(&attribution.session_id) {
                session.total_cost += cost;
                *session
                    .tool_costs
                    .entry(attribution.tool_name.clone())
                    .or_default() += cost;
                session.last_activity = Utc::now();
            }

            // Store attribution
            let mut attributions = self.attributions.write();
            attributions.push(attribution.clone());

            // Trim if too many
            if attributions.len() > self.max_attributions {
                attributions.drain(0..1000);
            }

            return Some(attribution);
        }

        None
    }

    /// Try to attribute inference based on session correlation (temporal)
    /// Use when no explicit correlation ID is available
    pub fn attribute_by_session(
        &self,
        session_id: &str,
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
        cost: f64,
    ) -> Option<McpAttributedCost> {
        // Find the most recent pending call for this session
        let pending = self.pending_calls.read();
        let recent_call = pending
            .values()
            .filter(|c| c.session_id == session_id)
            .max_by_key(|c| c.started_at);

        if let Some(call) = recent_call {
            let correlation_id = call.correlation_id.clone();
            drop(pending);
            return self.attribute_inference(
                &correlation_id,
                model,
                input_tokens,
                output_tokens,
                cost,
            );
        }

        None
    }

    /// End a tool call and get total attributed cost
    pub fn end_tool_call(&self, correlation_id: &str) -> Option<f64> {
        let call = self.pending_calls.write().remove(correlation_id)?;

        // Update session tool call count
        if let Some(session) = self.sessions.write().get_mut(&call.session_id) {
            *session
                .tool_call_counts
                .entry(call.tool_name.clone())
                .or_default() += 1;
        }

        Some(call.accumulated_cost)
    }

    /// Get cost breakdown for a session
    pub fn get_session_costs(&self, session_id: &str) -> Option<HashMap<String, f64>> {
        self.sessions
            .read()
            .get(session_id)
            .map(|s| s.tool_costs.clone())
    }

    /// Get aggregate cost by tool across all sessions
    pub fn get_cost_by_tool(&self) -> Vec<ToolCostEntry> {
        let mut tool_totals: HashMap<(String, String), (f64, u64)> = HashMap::new();

        for session in self.sessions.read().values() {
            for (tool, cost) in &session.tool_costs {
                let count = session.tool_call_counts.get(tool).copied().unwrap_or(1);
                let key = (tool.clone(), session.server_name.clone());
                let entry = tool_totals.entry(key).or_default();
                entry.0 += cost;
                entry.1 += count;
            }
        }

        let mut entries: Vec<ToolCostEntry> = tool_totals
            .into_iter()
            .map(
                |((tool_name, server_name), (total_cost, call_count))| ToolCostEntry {
                    tool_name,
                    server_name,
                    total_cost,
                    call_count,
                    avg_cost_per_call: if call_count > 0 {
                        total_cost / call_count as f64
                    } else {
                        0.0
                    },
                },
            )
            .collect();

        // Sort by total cost descending
        entries.sort_by(|a, b| {
            b.total_cost
                .partial_cmp(&a.total_cost)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        entries
    }

    /// Get recent attributions
    pub fn get_recent_attributions(&self, limit: usize) -> Vec<McpAttributedCost> {
        let attributions = self.attributions.read();
        attributions.iter().rev().take(limit).cloned().collect()
    }

    /// Cleanup old pending calls
    pub fn cleanup_stale(&self) {
        let cutoff = Utc::now() - self.max_pending_age;
        self.pending_calls
            .write()
            .retain(|_, call| call.started_at > cutoff);
    }

    /// Get total attributed cost across all sessions
    pub fn get_total_attributed_cost(&self) -> f64 {
        self.sessions.read().values().map(|s| s.total_cost).sum()
    }

    /// Check if a session exists
    pub fn has_session(&self, session_id: &str) -> bool {
        self.sessions.read().contains_key(session_id)
    }

    /// Get active session count
    pub fn active_session_count(&self) -> usize {
        self.sessions.read().len()
    }

    /// Get pending call count
    pub fn pending_call_count(&self) -> usize {
        self.pending_calls.read().len()
    }
}

impl Default for McpCostAttributor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_lifecycle() {
        let attributor = McpCostAttributor::new();

        // Start session
        attributor.start_session("session-1", "test-server", Some("agent-1"));
        assert!(attributor.has_session("session-1"));
        assert_eq!(attributor.active_session_count(), 1);

        // End session
        let session = attributor.end_session("session-1").unwrap();
        assert_eq!(session.server_name, "test-server");
        assert!(!attributor.has_session("session-1"));
    }

    #[test]
    fn test_tool_call_attribution() {
        let attributor = McpCostAttributor::new();

        // Start session
        attributor.start_session("session-1", "test-server", None);

        // Start tool call
        let corr_id = attributor.start_tool_call("session-1", "read_file");
        assert_eq!(attributor.pending_call_count(), 1);

        // Attribute some inference cost
        let attr = attributor
            .attribute_inference(&corr_id, "gpt-4o", 1000, 500, 0.05)
            .unwrap();
        assert_eq!(attr.tool_name, "read_file");
        assert_eq!(attr.inference_cost, 0.05);

        // End tool call
        let total = attributor.end_tool_call(&corr_id).unwrap();
        assert!((total - 0.05).abs() < 0.001);
        assert_eq!(attributor.pending_call_count(), 0);

        // Check session totals
        let costs = attributor.get_session_costs("session-1").unwrap();
        assert!((costs.get("read_file").unwrap() - 0.05).abs() < 0.001);
    }

    #[test]
    fn test_multiple_attributions() {
        let attributor = McpCostAttributor::new();

        attributor.start_session("session-1", "server-1", None);

        let corr_id = attributor.start_tool_call("session-1", "expensive_tool");

        // Multiple AI calls for one tool
        attributor.attribute_inference(&corr_id, "gpt-4o", 1000, 500, 0.05);
        attributor.attribute_inference(&corr_id, "gpt-4o", 2000, 1000, 0.10);
        attributor.attribute_inference(&corr_id, "gpt-4o", 500, 200, 0.02);

        let total = attributor.end_tool_call(&corr_id).unwrap();
        assert!((total - 0.17).abs() < 0.001);
    }

    #[test]
    fn test_cost_by_tool() {
        let attributor = McpCostAttributor::new();

        attributor.start_session("session-1", "server-1", None);

        // Tool A - 2 calls
        let corr1 = attributor.start_tool_call("session-1", "tool_a");
        attributor.attribute_inference(&corr1, "gpt-4o", 1000, 500, 0.10);
        attributor.end_tool_call(&corr1);

        let corr2 = attributor.start_tool_call("session-1", "tool_a");
        attributor.attribute_inference(&corr2, "gpt-4o", 1000, 500, 0.10);
        attributor.end_tool_call(&corr2);

        // Tool B - 1 call
        let corr3 = attributor.start_tool_call("session-1", "tool_b");
        attributor.attribute_inference(&corr3, "gpt-4o", 5000, 2000, 0.50);
        attributor.end_tool_call(&corr3);

        let tools = attributor.get_cost_by_tool();
        assert_eq!(tools.len(), 2);

        // Should be sorted by cost descending
        assert_eq!(tools[0].tool_name, "tool_b");
        assert!((tools[0].total_cost - 0.50).abs() < 0.001);
        assert_eq!(tools[0].call_count, 1);

        assert_eq!(tools[1].tool_name, "tool_a");
        assert!((tools[1].total_cost - 0.20).abs() < 0.001);
        assert_eq!(tools[1].call_count, 2);
        assert!((tools[1].avg_cost_per_call - 0.10).abs() < 0.001);
    }

    #[test]
    fn test_session_correlation() {
        let attributor = McpCostAttributor::new();

        attributor.start_session("session-1", "server-1", None);
        let _corr_id = attributor.start_tool_call("session-1", "active_tool");

        // Attribute by session (no explicit correlation ID)
        let attr = attributor
            .attribute_by_session("session-1", "gpt-4o", 1000, 500, 0.05)
            .unwrap();

        assert_eq!(attr.tool_name, "active_tool");
    }
}
