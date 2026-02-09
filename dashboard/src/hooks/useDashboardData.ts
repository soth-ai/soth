import { useQuery } from "@tanstack/react-query";
import type {
  ApiResponse,
  IdentityMetrics,
  PolicyMetrics,
  ObserveMetrics,
  BudgetMetrics,
  BudgetPrimitives,
  AdvancedBudgetMetrics,
  ProxyMetrics,
  HealthResponse,
  DashboardSnapshot,
  AgentsSummary,
} from "@/types";
import { buildApiUrl } from "@/lib/endpoints";
import { useSettingsStore } from "@/store/settings";

async function fetchJson<T>(endpoint: string): Promise<T> {
  const response = await fetch(buildApiUrl(endpoint));
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

export function useHealth() {
  const refreshInterval = useSettingsStore((state) => state.refreshInterval);
  return useQuery({
    queryKey: ["health"],
    queryFn: () => fetchJson<HealthResponse>("/health"),
    refetchInterval: Math.max(1000, refreshInterval),
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
  const refreshInterval = useSettingsStore((state) => state.refreshInterval);
  return useQuery({
    queryKey: ["proxy"],
    queryFn: () => fetchJson<ApiResponse<ProxyMetrics>>("/proxy"),
    refetchInterval: Math.max(1000, refreshInterval),
  });
}

export function useAdvancedBudgetMetrics() {
  const refreshInterval = useSettingsStore((state) => state.refreshInterval);
  return useQuery({
    queryKey: ["budget", "advanced"],
    queryFn: () => fetchJson<ApiResponse<AdvancedBudgetMetrics>>("/budget/advanced"),
    refetchInterval: Math.max(1000, refreshInterval),
  });
}

export function useBudgetPrimitives() {
  const refreshInterval = useSettingsStore((state) => state.refreshInterval);
  return useQuery({
    queryKey: ["budget", "primitives"],
    queryFn: () => fetchJson<ApiResponse<BudgetPrimitives>>("/budget/primitives"),
    refetchInterval: Math.max(1000, refreshInterval),
  });
}

export function useAgentsData() {
  const refreshInterval = useSettingsStore((state) => state.refreshInterval);
  return useQuery({
    queryKey: ["agents"],
    queryFn: () => fetchJson<ApiResponse<AgentsSummary>>("/agents"),
    refetchInterval: Math.max(1000, refreshInterval),
  });
}

export function useDashboardSnapshot() {
  const refreshInterval = useSettingsStore((state) => state.refreshInterval);
  return useQuery({
    queryKey: ["snapshot"],
    queryFn: () => fetchJson<ApiResponse<DashboardSnapshot>>("/snapshot"),
    refetchInterval: Math.max(1000, refreshInterval),
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
