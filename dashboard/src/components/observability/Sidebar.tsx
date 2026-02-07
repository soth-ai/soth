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
  FunnelSimple,
  Trash,
  Database,
} from "@phosphor-icons/react";
import { format } from "date-fns";
import { useObservabilityStore, computeLogMetrics } from "@/store/observability";
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

  // Check if filters are active
  const hasActiveFilters = !!(
    filters.method ||
    filters.path ||
    filters.direction ||
    filters.serverName ||
    filters.minLatencyMs
  );

  return (
    <div className="flex flex-col h-full bg-background border-r border-border/50 overflow-hidden font-sans">
      <div className="px-3 py-1.5 border-b border-border/50 bg-secondary/30 backdrop-blur-md">
        <div className="flex items-center justify-between">
          <h2 className="text-[10px] font-semibold text-foreground tracking-tight flex items-center gap-1.5">
            <Database className="w-3.5 h-3.5 text-primary" weight="duotone" />
            Observability
          </h2>
          <div
            className={cn(
              "inline-flex items-center gap-1.5 rounded-md border px-1.5 py-0.5 text-[9px] font-medium",
              isConnected
                ? "border-success/35 bg-success/10 text-success"
                : "border-destructive/35 bg-destructive/10 text-destructive"
            )}
          >
            <span
              className={cn(
                "h-1.5 w-1.5 rounded-full",
                isConnected ? "bg-success animate-pulse" : "bg-destructive"
              )}
            />
            {isConnected ? "live" : "offline"}
          </div>
        </div>
      </div>

      <ScrollArea className="flex-1 overflow-y-auto">
        <div className="p-3 space-y-3">
          <section className="space-y-1.5">
            <div className="flex items-center justify-between text-[8px] font-semibold text-muted-foreground uppercase tracking-[0.08em]">
              <span className="inline-flex items-center gap-1">
                <CircleNotch className="w-3 h-3 text-primary/80" weight="duotone" />
                Metrics
              </span>
              <span className="font-mono text-[9px] text-success">{metrics.messagesPerSecond} mps</span>
            </div>
            <div className="rounded-md border border-border/50 bg-secondary/20 divide-y divide-border/40">
              <div className="flex items-center justify-between px-2 py-1 text-[10px]">
                <span className="text-muted-foreground">Events</span>
                <span className="font-mono font-semibold text-foreground tabular-nums">
                  {metrics.totalMessages.toLocaleString()}
                </span>
              </div>
              <div className="flex items-center justify-between px-2 py-1 text-[10px]">
                <span className="text-muted-foreground">In / Out</span>
                <span className="font-mono font-semibold tabular-nums">
                  <span className="text-cyan-400">{metrics.incomingCount}</span>
                  <span className="text-muted-foreground/60 mx-1">/</span>
                  <span className="text-success">{metrics.outgoingCount}</span>
                </span>
              </div>
            </div>
          </section>

          {metrics.totalTokens > 0 && (
            <section className="rounded-md border border-warning/25 bg-warning/5">
              <button
                onClick={() => setIsTokenUsageExpanded(!isTokenUsageExpanded)}
                className="w-full flex items-center justify-between px-2 py-1 text-[9px] font-semibold text-muted-foreground tracking-[0.05em] hover:text-foreground transition-colors"
              >
                <span className="flex items-center gap-2">
                  <Coins className="w-3 h-3 text-warning" weight="fill" />
                  Token Profiling
                </span>
                <span className="flex items-center gap-2">
                  <span className="font-mono font-semibold text-warning text-[10px]">
                    {metrics.totalTokens.toLocaleString()}
                  </span>
                  {isTokenUsageExpanded ? (
                    <CaretDown className="w-2.5 h-2.5" />
                  ) : (
                    <CaretRight className="w-2.5 h-2.5" />
                  )}
                </span>
              </button>

              {isTokenUsageExpanded && (
                <div className="border-t border-warning/20 px-2 py-1.5 space-y-1 animate-in fade-in slide-in-from-top-1">
                  <div className="flex items-center justify-between text-[10px]">
                    <span className="text-muted-foreground">Inbound tokens</span>
                    <span className="font-mono font-semibold text-accent tabular-nums">
                      {metrics.tokensToServer.toLocaleString()}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-[10px]">
                    <span className="text-muted-foreground">Outbound tokens</span>
                    <span className="font-mono font-semibold text-success tabular-nums">
                      {metrics.tokensFromServer.toLocaleString()}
                    </span>
                  </div>

                  {metrics.topMethodsByTokens.length > 0 && (
                    <div className="pt-1 border-t border-warning/15 space-y-0.5">
                      <p className="text-[8px] text-muted-foreground uppercase font-semibold tracking-[0.08em]">
                        Top token methods
                      </p>
                      <div className="space-y-0.5">
                        {metrics.topMethodsByTokens.map(([method, tokens]) => (
                          <div
                            key={method}
                            className="flex items-center justify-between text-[9px]"
                          >
                            <span className="font-mono text-muted-foreground truncate max-w-[135px]">
                              {method}
                            </span>
                            <span className="font-mono text-warning font-semibold tabular-nums">
                              {tokens.toLocaleString()}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </section>
          )}

          <section>
            <h3 className="text-[8px] font-semibold mb-1.5 text-muted-foreground tracking-[0.08em] uppercase">
              Event velocity
            </h3>
            <div className="h-[72px] rounded-md bg-card border border-border/50 overflow-hidden">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={activityData} margin={{ top: 10, right: 0, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorMps" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--primary)" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="var(--primary)" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" hide={true} />
                  <YAxis hide={true} domain={[0, 'auto']} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "var(--secondary)",
                      border: "1px solid var(--border)",
                      borderRadius: "8px",
                      fontSize: "10px",
                      padding: "4px 8px",
                      boxShadow: "0 4px 12px rgba(0,0,0,0.5)",
                    }}
                    itemStyle={{ color: "var(--foreground)" }}
                    labelStyle={{ display: "none" }}
                  />
                  <Area
                    type="monotone"
                    dataKey="mps"
                    stroke="var(--primary)"
                    strokeWidth={2.5}
                    fillOpacity={1}
                    fill="url(#colorMps)"
                    animationDuration={600}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </section>

          <section className="space-y-1.5">
            <div className="flex items-center justify-between">
              <h3 className="text-[8px] font-semibold text-muted-foreground tracking-[0.08em] uppercase flex items-center gap-1.5">
                <FunnelSimple className="w-3 h-3 text-accent" />
                Filters
              </h3>
              {hasActiveFilters && (
                <button
                  onClick={clearFilters}
                  className="text-[9px] font-semibold text-destructive hover:text-destructive/80 transition-colors"
                >
                  Clear
                </button>
              )}
            </div>

            <div className="flex flex-wrap gap-1">
              <button
                onClick={() => setFilters({ direction: filters.direction === "in" ? undefined : "in" })}
                className={cn(
                  "inline-flex h-6 items-center gap-1.5 rounded-md border px-2 text-[9px] font-medium transition-colors",
                  filters.direction === "in"
                    ? "bg-accent/15 border-accent/35 text-accent"
                    : "bg-secondary/25 border-border/50 text-muted-foreground hover:text-foreground"
                )}
              >
                In
                <span className="font-mono text-[9px] opacity-80 tabular-nums">{metrics.incomingCount}</span>
              </button>
              <button
                onClick={() => setFilters({ direction: filters.direction === "out" ? undefined : "out" })}
                className={cn(
                  "inline-flex h-6 items-center gap-1.5 rounded-md border px-2 text-[9px] font-medium transition-colors",
                  filters.direction === "out"
                    ? "bg-success/15 border-success/35 text-success"
                    : "bg-secondary/25 border-border/50 text-muted-foreground hover:text-foreground"
                )}
              >
                Out
                <span className="font-mono text-[9px] opacity-80 tabular-nums">{metrics.outgoingCount}</span>
              </button>
            </div>

            <div className="flex flex-wrap gap-1">
                {[
                  { label: "50+", value: 50 },
                  { label: "200+", value: 200 },
                  { label: "1s+", value: 1000 },
                ].map(({ label, value }) => (
                  <button
                    key={value}
                    onClick={() => setFilters({ minLatencyMs: filters.minLatencyMs === value ? undefined : value })}
                    className={cn(
                      "inline-flex h-6 items-center rounded-md border px-2 text-[9px] font-semibold transition-colors",
                      filters.minLatencyMs === value
                        ? value >= 1000
                          ? "bg-destructive/15 border-destructive/35 text-destructive"
                          : "bg-warning/15 border-warning/35 text-warning"
                        : "bg-secondary/25 border-border/50 text-muted-foreground hover:text-foreground"
                    )}
                  >
                    {label} ms
                  </button>
                ))}
            </div>

            {metrics.methodCounts.length > 0 && (
              <div className="space-y-1">
                <p className="text-[8px] text-muted-foreground font-semibold uppercase tracking-[0.08em] pl-0.5">
                  Methods
                </p>
                <div className="max-h-28 overflow-y-auto pr-0.5 custom-scrollbar rounded-md border border-border/40 bg-secondary/20 divide-y divide-border/30">
                  {metrics.methodCounts.slice(0, 10).map(({ method, count }) => (
                    <button
                      key={method}
                      onClick={() => setFilters({ method: filters.method === method ? undefined : method })}
                      className={cn(
                        "w-full flex items-center justify-between px-2 py-1 text-[9px] font-mono transition-colors",
                        filters.method === method
                          ? "bg-primary/15 text-primary"
                          : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"
                      )}
                    >
                      <span className="truncate">{method}</span>
                      <span
                        className={cn(
                          "ml-2 rounded px-1.5 py-0.5 text-[9px] font-semibold tabular-nums",
                          filters.method === method
                            ? "bg-primary/20 text-primary"
                            : "bg-muted/70 text-muted-foreground"
                        )}
                      >
                        {count}
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {metrics.hostCounts?.length > 0 && (
              <div className="space-y-1">
                <p className="text-[8px] text-muted-foreground font-semibold uppercase tracking-[0.08em] pl-0.5">
                  Hot hosts
                </p>
                <div className="max-h-28 overflow-y-auto pr-0.5 custom-scrollbar rounded-md border border-border/40 bg-secondary/20 divide-y divide-border/30">
                  {metrics.hostCounts.slice(0, 10).map(({ host, count }) => (
                    <button
                      key={host}
                      onClick={() => setFilters({ serverName: filters.serverName === host ? undefined : host })}
                      className={cn(
                        "w-full flex items-center justify-between px-2 py-1 text-[9px] font-mono transition-colors",
                        filters.serverName === host
                          ? "bg-primary/15 text-primary"
                          : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"
                      )}
                    >
                      <span className="truncate">{host}</span>
                      <span
                        className={cn(
                          "ml-2 rounded px-1.5 py-0.5 text-[9px] font-semibold tabular-nums",
                          filters.serverName === host
                            ? "bg-primary/20 text-primary"
                            : "bg-muted/70 text-muted-foreground"
                        )}
                      >
                        {count}
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {metrics.pathCounts?.length > 0 && (
              <div className="space-y-1">
                <p className="text-[8px] text-muted-foreground font-semibold uppercase tracking-[0.08em] pl-0.5">
                  Hot paths
                </p>
                <div className="max-h-28 overflow-y-auto pr-0.5 custom-scrollbar rounded-md border border-border/40 bg-secondary/20 divide-y divide-border/30">
                  {metrics.pathCounts.slice(0, 10).map(({ path, count }) => (
                    <button
                      key={path}
                      onClick={() => setFilters({ path: filters.path === path ? undefined : path })}
                      className={cn(
                        "w-full flex items-center justify-between px-2 py-1 text-[9px] font-mono transition-colors",
                        filters.path === path
                          ? "bg-primary/15 text-primary"
                          : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"
                      )}
                    >
                      <span className="truncate">{path}</span>
                      <span
                        className={cn(
                          "ml-2 rounded px-1.5 py-0.5 text-[9px] font-semibold tabular-nums",
                          filters.path === path
                            ? "bg-primary/20 text-primary"
                            : "bg-muted/70 text-muted-foreground"
                        )}
                      >
                        {count}
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </section>

          {sessions.length > 0 && (
            <section className="space-y-1">
              <h3 className="text-[8px] font-semibold text-muted-foreground tracking-[0.08em] uppercase flex items-center gap-1.5">
                <Database className="w-3 h-3 text-primary" weight="duotone" />
                Sessions
              </h3>
              <div className="max-h-44 overflow-y-auto pr-0.5 custom-scrollbar rounded-md border border-border/40 bg-secondary/20 divide-y divide-border/30">
                {sessions.map((session) => (
                  <button
                    key={session.id}
                    onClick={() => setCurrentSession(session.id)}
                    className={cn(
                      "w-full text-left px-2 py-1.5 transition-colors group",
                      currentSessionId === session.id
                        ? "bg-primary/15"
                        : "hover:bg-secondary/50"
                    )}
                  >
                    <div className="flex items-center justify-between gap-1.5">
                      <span className={cn(
                        "text-[10px] font-medium truncate transition-colors",
                        currentSessionId === session.id ? "text-primary" : "text-foreground"
                      )}>
                        {session.name || `Session ${session.id.slice(-8)}`}
                      </span>
                      <span className="text-[9px] font-mono text-muted-foreground rounded bg-muted/70 px-1.5 py-0.5 tabular-nums">
                        {session.message_count}
                      </span>
                    </div>
                    <div className="text-[9px] text-muted-foreground/90 font-mono truncate mt-0.5">
                      {session.server_name || "unknown-server"}
                    </div>
                  </button>
                ))}
              </div>
            </section>
          )}

          {filteredBySourceLogs.length > 0 && (
            <div className="pt-1">
              <button
                onClick={clearLogs}
                className="inline-flex h-6 items-center gap-1.5 rounded-md border border-border/50 bg-secondary/25 px-2 text-[9px] font-semibold text-muted-foreground hover:text-destructive hover:border-destructive/30 hover:bg-destructive/5 transition-colors"
              >
                <Trash className="w-3 h-3" />
                Clear events
              </button>
            </div>
          )}
        </div>
      </ScrollArea>
    </div>
  );
}
