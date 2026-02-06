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
  Database,
} from "@phosphor-icons/react";
import { format } from "date-fns";
import { useObservabilityStore, computeLogMetrics } from "@/store/observability";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
export function Sidebar() {
  const sessions = useObservabilityStore((state) => state.sessions);
  const currentSessionId = useObservabilityStore((state) => state.currentSessionId);
  const setCurrentSession = useObservabilityStore((state) => state.setCurrentSession);
  const isConnected = useObservabilityStore((state) => state.isConnected);
  const logs = useObservabilityStore((state) => state.logs);
  const filters = useObservabilityStore((state) => state.filters);
  const setFilters = useObservabilityStore((state) => state.setFilters);
  const clearFilters = useObservabilityStore((state) => state.clearFilters);
  const clearLogs = useObservabilityStore((state) => state.clearLogs);

  // Apply source filter from store if set
  const filteredBySourceLogs = useMemo(() => {
    if (!filters.source) return logs;
    return logs.filter((log) => log.source === filters.source);
  }, [logs, filters.source]);

  // Memoize metrics to avoid infinite loop
  const metrics = useMemo(() => computeLogMetrics(filteredBySourceLogs), [filteredBySourceLogs]);
  const [isTokenUsageExpanded, setIsTokenUsageExpanded] = useState(false);

  // Activity chart data (last 10 seconds)
  const activityData = useMemo(() => {
    const now = Date.now();
    return Array.from({ length: 10 }, (_, i) => {
      const windowStart = now - (10 - i) * 1000;
      const windowEnd = windowStart + 1000;
      const count = filteredBySourceLogs.filter((log) => {
        const logTime = new Date(log.timestamp).getTime();
        return logTime >= windowStart && logTime < windowEnd;
      }).length;
      return {
        time: format(new Date(windowStart), "HH:mm:ss"),
        mps: count,
      };
    });
  }, [filteredBySourceLogs]);

  // Unique servers
  const uniqueServers = useMemo(() => {
    const servers = new Set<string>();
    filteredBySourceLogs.forEach((log) => servers.add(log.server_name));
    return Array.from(servers);
  }, [filteredBySourceLogs]);

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
        <h2 className="text-sm font-semibold text-foreground">Observability</h2>
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
                <span className="text-muted-foreground">Total Messages</span>
                <span className="font-mono font-bold text-accent tabular-nums">
                  {metrics.totalMessages}
                </span>
              </div>
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-muted-foreground">MPS (1s)</span>
                <span className="font-mono font-bold text-emerald-500 tabular-nums">
                  {metrics.messagesPerSecond}
                </span>
              </div>
            </div>
          </div>

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

              {isTokenUsageExpanded && (
                <div className="space-y-2 pl-4 border-l-2 border-amber-500/30">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-muted-foreground">To Server</span>
                    <span className="font-mono font-medium text-cyan-500 tabular-nums">
                      {metrics.tokensToServer.toLocaleString()}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-muted-foreground">From Server</span>
                    <span className="font-mono font-medium text-emerald-500 tabular-nums">
                      {metrics.tokensFromServer.toLocaleString()}
                    </span>
                  </div>

                  {metrics.topMethodsByTokens.length > 0 && (
                    <div className="pt-2 border-t border-border/50">
                      <p className="text-[10px] text-muted-foreground mb-1.5">
                        Top by tokens
                      </p>
                      <div className="space-y-1">
                        {metrics.topMethodsByTokens.map(([method, tokens]) => (
                          <div
                            key={method}
                            className="flex items-center justify-between text-[10px]"
                          >
                            <span className="font-mono text-muted-foreground truncate max-w-[120px]">
                              {method}
                            </span>
                            <span className="font-mono text-amber-500 tabular-nums">
                              {tokens.toLocaleString()}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
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
                    <linearGradient id="colorMps" x1="0" y1="0" x2="0" y2="1">
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
                    dataKey="mps"
                    stroke="hsl(var(--accent))"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorMps)"
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

            {/* Server Filter */}
            {uniqueServers.length > 1 && (
              <div className="space-y-1.5 mb-3">
                <p className="text-[10px] text-muted-foreground">Server</p>
                <div className="flex flex-wrap gap-1">
                  {uniqueServers.map((server) => (
                    <button
                      key={server}
                      onClick={() =>
                        setFilters({
                          serverName: filters.serverName === server ? undefined : server,
                        })
                      }
                      className={cn(
                        "px-2 py-1 rounded text-[10px] font-mono transition-colors",
                        filters.serverName === server
                          ? "bg-accent text-accent-foreground"
                          : "bg-muted hover:bg-muted/80 text-muted-foreground"
                      )}
                    >
                      {server}
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
                  <span>Incoming</span>
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
                  <span>Outgoing</span>
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
                  { label: ">50ms", value: 50 },
                  { label: ">200ms", value: 200 },
                  { label: ">1s", value: 1000 },
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
                        value >= 1000 &&
                        "bg-red-500 hover:bg-red-500/90",
                      filters.minLatencyMs === value &&
                        value >= 200 &&
                        value < 1000 &&
                        "bg-amber-500 hover:bg-amber-500/90 text-black"
                    )}
                  >
                    {label}
                  </Button>
                ))}
              </div>
            </div>

            {/* Method Filter */}
            {metrics.methodCounts.length > 0 && (
              <div className="space-y-1.5">
                <p className="text-[10px] text-muted-foreground">Methods</p>
                <div className="max-h-32 overflow-y-auto space-y-1">
                  {metrics.methodCounts.slice(0, 10).map(({ method, count }) => (
                    <button
                      key={method}
                      onClick={() =>
                        setFilters({
                          method: filters.method === method ? undefined : method,
                        })
                      }
                      className={cn(
                        "w-full flex items-center justify-between px-2 py-1 rounded text-xs font-mono transition-colors",
                        filters.method === method
                          ? "bg-accent/20 text-accent border border-accent/50"
                          : "hover:bg-muted/50 text-muted-foreground"
                      )}
                    >
                      <span className="truncate">{method}</span>
                      <span
                        className={cn(
                          "ml-2 px-1.5 py-0.5 rounded text-[10px] font-mono tabular-nums flex-shrink-0",
                          filters.method === method
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

          {/* Sessions */}
          {sessions.length > 0 && (
            <div>
              <h3 className="text-[10px] font-semibold mb-2 text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                <Database className="w-3 h-3" />
                Sessions
              </h3>
              <div className="max-h-40 overflow-y-auto space-y-1">
                {sessions.map((session) => (
                  <button
                    key={session.id}
                    onClick={() => setCurrentSession(session.id)}
                    className={cn(
                      "w-full text-left px-2 py-2 rounded text-xs transition-colors",
                      currentSessionId === session.id
                        ? "bg-accent/20 text-accent border border-accent/50"
                        : "hover:bg-muted/50 text-muted-foreground"
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-foreground truncate">
                        {session.name || `Session ${session.id.slice(-8)}`}
                      </span>
                      <span className="text-[10px] font-mono tabular-nums">
                        {session.message_count}
                      </span>
                    </div>
                    {session.server_name && (
                      <span className="text-[9px] font-mono px-1 py-0.5 rounded bg-accent/20 text-accent mt-1 inline-block">
                        {session.server_name}
                      </span>
                    )}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Clear Logs */}
          {filteredBySourceLogs.length > 0 && (
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
