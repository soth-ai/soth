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
  DashboardSnapshot,
  AgentsSummary,
} from "@/types";
import { buildApiUrl } from "@/lib/endpoints";

async function fetchJson<T>(endpoint: string): Promise<T> {
  const response = await fetch(buildApiUrl(endpoint));
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

export function useDashboardSnapshot() {
  return useQuery({
    queryKey: ["snapshot"],
    queryFn: () => fetchJson<ApiResponse<DashboardSnapshot>>("/snapshot"),
    refetchInterval: 2000,
  });
}

// Combined hook for all metrics
export function useDashboardMetrics() {
  const health = useHealth();
  const snapshot = useDashboardSnapshot();

  const isLoading = snapshot.isLoading;
  const isError = snapshot.isError;

  const isConnected = health.isSuccess && health.data?.status === "ok";

  return {
    isLoading,
    isError,
    isConnected,
    uptime: health.data?.uptime_secs ?? 0,
    identity: snapshot.data?.data.identity,
    policy: snapshot.data?.data.policy,
    observe: snapshot.data?.data.observe,
    budget: snapshot.data?.data.budget,
    proxy: snapshot.data?.data.proxy,
  };
}
