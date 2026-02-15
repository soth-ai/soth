// API Response wrapper
export interface ApiResponse<T> {
  timestamp: string;
  uptime_secs: number;
  data: T;
}

// Identity Panel
export interface DidEntry {
  did: string;
  verified: boolean;
  last_seen: string;
}

export interface IdentityMetrics {
  total_verifications: number;
  successful: number;
  failed: number;
  unique_dids: number;
  recent_dids: DidEntry[];
}

// Policy Panel
export interface DenialEntry {
  timestamp: string;
  method: string;
  tool: string | null;
  reason: string;
}

export interface PolicyMetrics {
  evaluations: number;
  allowed: number;
  denied: number;
  cache_hits: number;
  cache_misses: number;
  active_version: string | null;
  recent_denials: DenialEntry[];
}

// Observe Panel
export interface ObserveMetrics {
  requests: number;
  responses: number;
  pii_detections: number;
  pii_by_type: Record<string, number>;
}

// Budget Panel
export interface BudgetAlert {
  level: "info" | "warning" | "error";
  message: string;
}

export interface BudgetMetrics {
  total_tokens: number;
  total_cost_usd: number;
  daily_limit_usd: number | null;
  cost_by_model: Record<string, number>;
  alerts: BudgetAlert[];
}

export interface ProviderBudgetPrimitive {
  provider: string;
  request_count: number;
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  total_cost_usd: number;
  avg_cost_per_request: number;
}

export interface BudgetRequestPrimitive {
  request_id: string | null;
  timestamp: string;
  provider: string;
  host: string;
  method: string;
  path: string;
  model: string | null;
  status_code: number | null;
  latency_ms: number | null;
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  cost_usd: number;
}

export interface BudgetPrimitives {
  total_requests: number;
  total_responses: number;
  total_input_tokens: number;
  total_output_tokens: number;
  total_tokens: number;
  total_cost_usd: number;
  daily_limit_usd: number | null;
  utilization_pct: number | null;
  alerts: BudgetAlert[];
  provider_breakdown: ProviderBudgetPrimitive[];
  recent_requests: BudgetRequestPrimitive[];
}

// ============================================================================
// Advanced Budget Analytics Types
// ============================================================================

export interface AdvancedBudgetMetrics {
  // Basic metrics
  total_tokens: number;
  total_cost_usd: number;
  daily_limit_usd: number | null;
  cost_by_model: Record<string, number>;
  alerts: BudgetAlert[];

  // Provider breakdown
  cost_by_provider: Record<string, ProviderCostBreakdown>;

  // MCP tool costs
  cost_by_tool: ToolCostEntry[];

  // Team/project allocation
  cost_by_tag: Record<string, Record<string, number>>;

  // Daily trend (last 30 days)
  daily_trend: DailyTrendPoint[];

  // Cost anomalies
  anomalies: CostAnomalyEntry[];

  // Recommendations
  recommendations: RecommendationEntry[];

  // Request type breakdown
  cost_by_request_type: Record<string, number>;
}

export interface ProviderCostBreakdown {
  total_cost: number;
  total_tokens: number;
  input_tokens: number;
  output_tokens: number;
  request_count: number;
  model_breakdown: Record<string, ModelCostEntry>;
}

export interface ModelCostEntry {
  model_name: string;
  cost: number;
  input_tokens: number;
  output_tokens: number;
  request_count: number;
  avg_cost_per_request: number;
}

export interface ToolCostEntry {
  tool_name: string;
  server_name: string;
  total_cost: number;
  call_count: number;
  avg_cost_per_call: number;
}

export interface DailyTrendPoint {
  date: string;
  cost: number;
  tokens: number;
  requests: number;
  by_provider: Record<string, number>;
}

export interface CostAnomalyEntry {
  id: string;
  anomaly_type: "cost_spike" | "usage_spike" | "new_model" | "unusual_time" | "budget_approaching";
  severity: "info" | "warning" | "critical";
  description: string;
  detected_at: string;
  current_value: number;
  expected_value: number;
}

export interface RecommendationEntry {
  id: string;
  recommendation_type: "model_downgrade" | "prompt_caching" | "batch_requests" | "reduce_output_tokens";
  title: string;
  description: string;
  estimated_savings: number;
  effort: "low" | "medium" | "high";
}

export interface CryptoStatusSummary {
  total_events: number;
  signed_events: number;
  signature_coverage_pct: number;
  verification_failures: number;
  active_key_id: string | null;
  merkle_batches: number;
  latest_batch_id: string | null;
  latest_root_hash: string | null;
  latest_signer_did: string | null;
  latest_sealed_at: string | null;
}

export interface CryptoMerkleSealRow {
  batch_id: string;
  seq_start: number;
  seq_end: number;
  expected_events: number;
  observed_events: number;
  root_hash: string;
  signer_did: string;
  prev_root: string | null;
  sealed_at: string;
  chain_link_valid: boolean;
  verification_status: string;
}

export interface CryptoMerkleSummary {
  total_batches: number;
  seals: CryptoMerkleSealRow[];
}

export interface ModelPricingEntry {
  model_id: string;
  model_name: string;
  provider: string;
  input_cost_per_million: number;
  output_cost_per_million: number;
  cache_read_cost_per_million: number | null;
  cache_write_cost_per_million: number | null;
  supports_vision: boolean;
  supports_tools: boolean;
  context_window: number;
  max_output_tokens: number | null;
}

// Health
export interface HealthResponse {
  status: string;
  uptime_secs: number;
  event_store_enabled?: boolean;
  filter_decisions?: FilterDecisionMetrics;
}

// Wrap Events (from soth wrap)
export interface WrapEvent {
  seq?: number;
  id: string;
  timestamp: string;
  session_id: string;
  server_name: string;
  direction: "in" | "out";
  source?: "mcp" | "ai_proxy" | "agent_app";
  provider?: string;
  model?: string;
  method?: string;
  tool_name?: string;
  content?: string;
  content_ref?: string;
  content_preview?: string;
  request_content?: string;
  request_content_ref?: string;
  request_preview?: string;
  response_content?: string;
  response_content_ref?: string;
  response_preview?: string;
  status_code?: number;
  agent: AgentInfo;
  policy_allowed?: boolean;
  policy_reason?: string;
  pii_detected: boolean;
  pii_types: string[];
  token_count?: number;
  input_tokens?: number;
  output_tokens?: number;
  cache_read_tokens?: number;
  cache_write_tokens?: number;
  reasoning_tokens?: number;
  request_size_bytes?: number;
  response_size_bytes?: number;
  headers?: Record<string, string>;
  tags?: Record<string, string>;
  cost_usd?: number;
  latency_ms?: number;
}

export interface AgentInfo {
  name: string;
  version?: string;
  detected_from: string;
}

// Agent statistics
export interface AgentStats {
  name: string;
  version?: string;
  detected_from: string;
  event_count: number;
  last_seen: string;
  servers: string[];
}

export interface AgentsSummary {
  total_agents: number;
  agents: AgentStats[];
}

export interface EventsSummary {
  total_events: number;
  events: WrapEvent[];
}

// Proxy Panel
export interface ProviderTokens {
  input_tokens: number;
  output_tokens: number;
}

export interface ProxyRequestEntry {
  request_id: string | null;
  timestamp: string;
  provider: string;
  host: string;
  method: string;
  path: string;
  status_code: number | null;
  latency_ms: number | null;
  input_tokens: number | null;
  output_tokens: number | null;
  cost_usd: number | null;
  model: string | null;
}

export interface ProxyStatus {
  enabled: boolean;
  listen_address: string | null;
  ca_installed: boolean;
}

export interface FilterDecisionMetrics {
  total: number;
  by_phase: Record<string, number>;
  by_decision: Record<string, number>;
}

export interface ProxyMetrics {
  total_requests: number;
  total_responses: number;
  active_connections: number;
  requests_by_provider: Record<string, number>;
  tokens_by_provider: Record<string, ProviderTokens>;
  cost_by_provider: Record<string, number>;
  total_tokens: number;
  total_cost_usd: number;
  recent_requests: ProxyRequestEntry[];
  status: ProxyStatus;
  filter_decisions?: FilterDecisionMetrics;
}

export interface DashboardSnapshot {
  identity: IdentityMetrics;
  policy: PolicyMetrics;
  observe: ObserveMetrics;
  budget: BudgetMetrics;
  proxy: ProxyMetrics;
}
