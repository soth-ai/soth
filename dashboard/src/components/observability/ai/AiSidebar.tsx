"use client";

import { useMemo, useState } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import {
  Coins,
  CaretDown,
  CaretRight,
  CircleNotch,
  Plugs,
  FunnelSimple,
  Trash,
  CloudArrowUp,
  CurrencyDollar,
} from "@phosphor-icons/react";
import { format } from "date-fns";
import { useObservabilityStore, type LogEntry } from "@/store/observability";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";

// Compute AI-specific metrics
function computeAiMetrics(logs: LogEntry[]) {
  const aiLogs = logs.filter((log) => log.source === "ai_proxy");
  const now = Date.now();
  const oneSecondAgo = now - 1000;
  const recentLogs = aiLogs.filter(
    (log) => new Date(log.timestamp).getTime() > oneSecondAgo
  );

  // Provider counts
  const providerCounts = new Map<string, number>();
  aiLogs.forEach((log) => {
    if (log.provider) {
      providerCounts.set(log.provider, (providerCounts.get(log.provider) || 0) + 1);
    }
  });

  // Model counts
  const modelCounts = new Map<string, number>();
  aiLogs.forEach((log) => {
    if (log.model) {
      modelCounts.set(log.model, (modelCounts.get(log.model) || 0) + 1);
    }
  });

  // Direction counts
  const incomingCount = aiLogs.filter((l) => l.direction === "in").length;
  const outgoingCount = aiLogs.filter((l) => l.direction === "out").length;

  // Token stats by provider
  let totalTokens = 0;
  let totalCost = 0;
  const tokensByProvider: Record<string, number> = {};
  const costByProvider: Record<string, number> = {};

  aiLogs.forEach((log) => {
    const tokens = log.token_count || 0;
    const cost = log.cost_usd || 0;
    totalTokens += tokens;
    totalCost += cost;
    if (log.provider) {
      tokensByProvider[log.provider] = (tokensByProvider[log.provider] || 0) + tokens;
      costByProvider[log.provider] = (costByProvider[log.provider] || 0) + cost;
    }
  });

  const topProvidersByTokens = Object.entries(tokensByProvider)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const topProvidersByCost = Object.entries(costByProvider)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  return {
    totalMessages: aiLogs.length,
    messagesPerSecond: recentLogs.length,
    providerCounts: Array.from(providerCounts.entries()).map(([provider, count]) => ({
      provider,
      count,
    })),
    modelCounts: Array.from(modelCounts.entries()).map(([model, count]) => ({
      model,
      count,
    })),
    incomingCount,
    outgoingCount,
    totalTokens,
    totalCost,
    topProvidersByTokens,
    topProvidersByCost,
  };
}

export function AiSidebar() {
  const isConnected = useObservabilityStore((state) => state.isConnected);
  const logs = useObservabilityStore((state) => state.logs);
  const filters = useObservabilityStore((state) => state.filters);
  const setFilters = useObservabilityStore((state) => state.setFilters);
  const clearFilters = useObservabilityStore((state) => state.clearFilters);
  const clearLogs = useObservabilityStore((state) => state.clearLogs);

  // Filter for AI logs only
  const aiLogs = useMemo(() => logs.filter((log) => log.source === "ai_proxy"), [logs]);

  // Memoize metrics
  const metrics = useMemo(() => computeAiMetrics(logs), [logs]);
  const [isTokenUsageExpanded, setIsTokenUsageExpanded] = useState(false);
  const [isCostExpanded, setIsCostExpanded] = useState(false);

  // Activity chart data (last 10 seconds)
  const activityData = useMemo(() => {
    const now = Date.now();
    return Array.from({ length: 10 }, (_, i) => {
      const windowStart = now - (10 - i) * 1000;
      const windowEnd = windowStart + 1000;
      const count = aiLogs.filter((log) => {
        const logTime = new Date(log.timestamp).getTime();
        return logTime >= windowStart && logTime < windowEnd;
      }).length;
      return {
        time: format(new Date(windowStart), "HH:mm:ss"),
        rps: count,
      };
    });
  }, [aiLogs]);

  // Unique providers
  const uniqueProviders = useMemo(() => {
    const providers = new Set<string>();
    aiLogs.forEach((log) => {
      if (log.provider) providers.add(log.provider);
    });
    return Array.from(providers);
  }, [aiLogs]);

  // Check if filters are active
  const hasActiveFilters = !!(
    filters.method ||
    filters.direction ||
    filters.serverName ||
    filters.minLatencyMs
  );

  return (
    <div className="flex flex-col h-full bg-background border-r border-border overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-border bg-card">
        <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <CloudArrowUp className="w-4 h-4" weight="duotone" />
          AI Inference
        </h2>
      </div>

      <ScrollArea className="flex-1 overflow-y-auto">
        <div className="p-4 space-y-6">
          {/* Connection Status */}
          <div>
            <h3 className="text-[10px] font-semibold mb-2 text-muted-foreground uppercase tracking-wider">
              Status
            </h3>
            <div
              className={cn(
                "px-3 py-2 rounded-md border text-[11px] font-mono font-medium",
                isConnected
                  ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-500"
                  : "bg-red-500/10 border-red-500/30 text-red-500"
              )}
            >
              <div className="flex items-center gap-2">
                {isConnected ? (
                  <Plugs className="w-3.5 h-3.5" weight="fill" />
                ) : (
                  <CircleNotch className="w-3.5 h-3.5 animate-spin" />
                )}
                {isConnected ? "Connected" : "Connecting..."}
              </div>
            </div>
          </div>

          {/* Metrics */}
          <div>
            <h3 className="text-[10px] font-semibold mb-2 text-muted-foreground uppercase tracking-wider">
              Metrics
            </h3>
            <div className="space-y-2">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-muted-foreground">Total Requests</span>
                <span className="font-mono font-bold text-accent tabular-nums">
                  {metrics.totalMessages}
                </span>
              </div>
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-muted-foreground">RPS (1s)</span>
                <span className="font-mono font-bold text-emerald-500 tabular-nums">
                  {metrics.messagesPerSecond}
                </span>
              </div>
            </div>
          </div>

          {/* Cost Tracking */}
          {metrics.totalCost > 0 && (
            <div>
              <button
                onClick={() => setIsCostExpanded(!isCostExpanded)}
                className="w-full flex items-center justify-between text-[10px] font-semibold mb-2 text-muted-foreground uppercase tracking-wider hover:text-foreground transition-colors"
              >
                <span className="flex items-center gap-1.5">
                  <CurrencyDollar className="w-3 h-3" weight="fill" />
                  Cost
                </span>
                <span className="flex items-center gap-2">
                  <span className="font-mono font-bold text-emerald-500 normal-case">
                    ${metrics.totalCost.toFixed(4)}
                  </span>
                  {isCostExpanded ? (
                    <CaretDown className="w-3 h-3" />
                  ) : (
                    <CaretRight className="w-3 h-3" />
                  )}
                </span>
              </button>

              {isCostExpanded && metrics.topProvidersByCost.length > 0 && (
                <div className="space-y-2 pl-4 border-l-2 border-emerald-500/30">
                  {metrics.topProvidersByCost.map(([provider, cost]) => (
                    <div
                      key={provider}
                      className="flex items-center justify-between text-[10px]"
                    >
                      <span className="font-mono text-muted-foreground truncate max-w-[120px]">
                        {provider}
                      </span>
                      <span className="font-mono text-emerald-500 tabular-nums">
                        ${cost.toFixed(4)}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Token Profiling */}
          {metrics.totalTokens > 0 && (
            <div>
              <button
                onClick={() => setIsTokenUsageExpanded(!isTokenUsageExpanded)}
                className="w-full flex items-center justify-between text-[10px] font-semibold mb-2 text-muted-foreground uppercase tracking-wider hover:text-foreground transition-colors"
              >
                <span className="flex items-center gap-1.5">
                  <Coins className="w-3 h-3" weight="fill" />
                  Token Usage
                </span>
                <span className="flex items-center gap-2">
                  <span className="font-mono font-bold text-amber-500 normal-case">
                    {metrics.totalTokens.toLocaleString()}
                  </span>
                  {isTokenUsageExpanded ? (
                    <CaretDown className="w-3 h-3" />
                  ) : (
                    <CaretRight className="w-3 h-3" />
                  )}
                </span>
              </button>

              {isTokenUsageExpanded && metrics.topProvidersByTokens.length > 0 && (
                <div className="space-y-2 pl-4 border-l-2 border-amber-500/30">
                  {metrics.topProvidersByTokens.map(([provider, tokens]) => (
                    <div
                      key={provider}
                      className="flex items-center justify-between text-[10px]"
                    >
                      <span className="font-mono text-muted-foreground truncate max-w-[120px]">
                        {provider}
                      </span>
                      <span className="font-mono text-amber-500 tabular-nums">
                        {tokens.toLocaleString()}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Activity Chart */}
          <div>
            <h3 className="text-[10px] font-semibold mb-3 text-muted-foreground uppercase tracking-wider">
              Activity (10s)
            </h3>
            <div className="h-24 bg-muted/40 border border-border rounded-md p-2">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={activityData}>
                  <defs>
                    <linearGradient id="colorRps" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="hsl(var(--accent))" stopOpacity={0.8} />
                      <stop offset="95%" stopColor="hsl(var(--accent))" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis
                    dataKey="time"
                    tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 9 }}
                    tickLine={false}
                    axisLine={false}
                    interval="preserveStartEnd"
                  />
                  <YAxis
                    tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 9 }}
                    tickLine={false}
                    axisLine={false}
                    width={20}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(var(--popover))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "6px",
                      fontSize: "11px",
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="rps"
                    stroke="hsl(var(--accent))"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorRps)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Filters */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                <FunnelSimple className="w-3 h-3" />
                Filters
              </h3>
              {hasActiveFilters && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={clearFilters}
                  className="h-6 px-2 text-xs"
                >
                  Clear
                </Button>
              )}
            </div>

            {/* Provider Filter */}
            {uniqueProviders.length > 0 && (
              <div className="space-y-1.5 mb-3">
                <p className="text-[10px] text-muted-foreground">Provider</p>
                <div className="flex flex-wrap gap-1">
                  {uniqueProviders.map((provider) => (
                    <button
                      key={provider}
                      onClick={() =>
                        setFilters({
                          serverName: filters.serverName === provider ? undefined : provider,
                        })
                      }
                      className={cn(
                        "px-2 py-1 rounded text-[10px] font-mono transition-colors",
                        filters.serverName === provider
                          ? "bg-accent text-accent-foreground"
                          : "bg-muted hover:bg-muted/80 text-muted-foreground"
                      )}
                    >
                      {provider}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Direction Filter */}
            <div className="space-y-1.5 mb-3">
              <p className="text-[10px] text-muted-foreground">Direction</p>
              <div className="flex gap-2">
                <Button
                  variant={filters.direction === "in" ? "default" : "outline"}
                  size="sm"
                  onClick={() =>
                    setFilters({
                      direction: filters.direction === "in" ? undefined : "in",
                    })
                  }
                  className="flex-1 h-8 text-xs flex items-center justify-between"
                >
                  <span>Request</span>
                  <span className="ml-1.5 px-1.5 py-0.5 rounded bg-muted/50 text-[10px] font-mono tabular-nums">
                    {metrics.incomingCount}
                  </span>
                </Button>
                <Button
                  variant={filters.direction === "out" ? "default" : "outline"}
                  size="sm"
                  onClick={() =>
                    setFilters({
                      direction: filters.direction === "out" ? undefined : "out",
                    })
                  }
                  className="flex-1 h-8 text-xs flex items-center justify-between"
                >
                  <span>Response</span>
                  <span className="ml-1.5 px-1.5 py-0.5 rounded bg-muted/50 text-[10px] font-mono tabular-nums">
                    {metrics.outgoingCount}
                  </span>
                </Button>
              </div>
            </div>

            {/* Latency Filter */}
            <div className="space-y-1.5 mb-3">
              <p className="text-[10px] text-muted-foreground">Min Latency</p>
              <div className="flex gap-1.5">
                {[
                  { label: ">100ms", value: 100 },
                  { label: ">500ms", value: 500 },
                  { label: ">2s", value: 2000 },
                ].map(({ label, value }) => (
                  <Button
                    key={value}
                    variant={filters.minLatencyMs === value ? "default" : "outline"}
                    size="sm"
                    onClick={() =>
                      setFilters({
                        minLatencyMs: filters.minLatencyMs === value ? undefined : value,
                      })
                    }
                    className={cn(
                      "flex-1 h-7 text-xs px-2",
                      filters.minLatencyMs === value &&
                        value >= 2000 &&
                        "bg-red-500 hover:bg-red-500/90",
                      filters.minLatencyMs === value &&
                        value >= 500 &&
                        value < 2000 &&
                        "bg-amber-500 hover:bg-amber-500/90 text-black"
                    )}
                  >
                    {label}
                  </Button>
                ))}
              </div>
            </div>

            {/* Models Filter */}
            {metrics.modelCounts.length > 0 && (
              <div className="space-y-1.5">
                <p className="text-[10px] text-muted-foreground">Models</p>
                <div className="max-h-32 overflow-y-auto space-y-1">
                  {metrics.modelCounts.slice(0, 10).map(({ model, count }) => (
                    <button
                      key={model}
                      onClick={() =>
                        setFilters({
                          method: filters.method === model ? undefined : model,
                        })
                      }
                      className={cn(
                        "w-full flex items-center justify-between px-2 py-1 rounded text-xs font-mono transition-colors",
                        filters.method === model
                          ? "bg-accent/20 text-accent border border-accent/50"
                          : "hover:bg-muted/50 text-muted-foreground"
                      )}
                    >
                      <span className="truncate">{model}</span>
                      <span
                        className={cn(
                          "ml-2 px-1.5 py-0.5 rounded text-[10px] font-mono tabular-nums flex-shrink-0",
                          filters.method === model
                            ? "bg-accent/30 text-accent"
                            : "bg-muted text-muted-foreground"
                        )}
                      >
                        {count}
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Clear Logs */}
          {aiLogs.length > 0 && (
            <div className="pt-4 border-t border-border">
              <Button
                variant="outline"
                size="sm"
                onClick={clearLogs}
                className="w-full h-8 text-xs text-muted-foreground hover:text-destructive"
              >
                <Trash className="w-3.5 h-3.5 mr-2" />
                Clear all logs
              </Button>
            </div>
          )}
        </div>
      </ScrollArea>
    </div>
  );
}
