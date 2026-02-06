import { useQuery } from "@tanstack/react-query";
import type {
  ApiResponse,
  IdentityMetrics,
  PolicyMetrics,
  ObserveMetrics,
  BudgetMetrics,
  AdvancedBudgetMetrics,
  ProxyMetrics,
  HealthResponse,
  AgentsSummary,
} from "@/types";

const API_BASE = "/api";

async function fetchJson<T>(endpoint: string): Promise<T> {
  const response = await fetch(`${API_BASE}${endpoint}`);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

export function useHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: () => fetchJson<HealthResponse>("/health"),
    refetchInterval: 5000,
  });
}

export function useIdentityMetrics() {
  return useQuery({
    queryKey: ["identity"],
    queryFn: () => fetchJson<ApiResponse<IdentityMetrics>>("/identity"),
  });
}

export function usePolicyMetrics() {
  return useQuery({
    queryKey: ["policy"],
    queryFn: () => fetchJson<ApiResponse<PolicyMetrics>>("/policy"),
  });
}

export function useObserveMetrics() {
  return useQuery({
    queryKey: ["observe"],
    queryFn: () => fetchJson<ApiResponse<ObserveMetrics>>("/observe"),
  });
}

export function useBudgetMetrics() {
  return useQuery({
    queryKey: ["budget"],
    queryFn: () => fetchJson<ApiResponse<BudgetMetrics>>("/budget"),
  });
}

export function useProxyMetrics() {
  return useQuery({
    queryKey: ["proxy"],
    queryFn: () => fetchJson<ApiResponse<ProxyMetrics>>("/proxy"),
    refetchInterval: 2000,
  });
}

export function useAdvancedBudgetMetrics() {
  return useQuery({
    queryKey: ["budget", "advanced"],
    queryFn: () => fetchJson<ApiResponse<AdvancedBudgetMetrics>>("/budget/advanced"),
    refetchInterval: 5000,
  });
}

export function useAgentsData() {
  return useQuery({
    queryKey: ["agents"],
    queryFn: () => fetchJson<ApiResponse<AgentsSummary>>("/agents"),
    refetchInterval: 5000,
  });
}

// Combined hook for all metrics
export function useDashboardMetrics() {
  const health = useHealth();
  const identity = useIdentityMetrics();
  const policy = usePolicyMetrics();
  const observe = useObserveMetrics();
  const budget = useBudgetMetrics();
  const proxy = useProxyMetrics();

  const isLoading =
    identity.isLoading ||
    policy.isLoading ||
    observe.isLoading ||
    budget.isLoading ||
    proxy.isLoading;

  const isError =
    identity.isError ||
    policy.isError ||
    observe.isError ||
    budget.isError ||
    proxy.isError;

  const isConnected = health.isSuccess && health.data?.status === "ok";

  return {
    isLoading,
    isError,
    isConnected,
    uptime: health.data?.uptime_secs ?? 0,
    identity: identity.data?.data,
    policy: policy.data?.data,
    observe: observe.data?.data,
    budget: budget.data?.data,
    proxy: proxy.data?.data,
  };
}
