"use client";

import { useMemo, useState } from "react";
import {
  WifiHigh,
  WifiSlash,
  ChartLine,
  Waveform,
  Warning,
  Info,
  CurrencyDollar,
  ShieldCheck,
  Pulse,
  Clock,
  ShieldWarning,
  ArrowsOutSimple,
} from "@phosphor-icons/react";
import {
  useAdvancedBudgetMetrics,
  useBudgetPrimitives,
  useDashboardMetrics,
  useAgentsData,
} from "@/hooks/useDashboardData";
import { useEventStream } from "@/hooks/useEventStream";
import { LiveFeedPanel } from "@/components/panels/live-feed-panel";
import { AgentsPanel } from "@/components/panels/agents-panel";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { cn, formatCurrency, formatDuration, formatNumber } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";

type Tab = "metrics" | "live";
type RangeKey = "1h" | "24h" | "7d";

type PrioritySeverity = "critical" | "warning" | "info" | "ok";

interface PriorityEvent {
  severity: PrioritySeverity;
  title: string;
  description: string;
  href: string;
}

function percentile(values: number[], p: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(p * sorted.length) - 1));
  return sorted[index] ?? 0;
}

function signedPercent(value: number): string {
  const sign = value > 0 ? "+" : "";
  return `${sign}${value.toFixed(1)}%`;
}

function formatLatency(ms: number): string {
  if (ms >= 1000) {
    return `${(ms / 1000).toFixed(2)}s`;
  }
  return `${Math.round(ms)}ms`;
}

function modeButtonClass(active: boolean): string {
  return cn(
    "relative inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-[11px] font-medium transition-all duration-200 ease-out",
    active
      ? "bg-foreground text-background border-foreground shadow-[0_2px_10px_rgba(0,0,0,0.1)]"
      : "bg-transparent text-muted-foreground border-border hover:text-foreground hover:bg-muted/50"
  );
}

function signalToneClass(level: "normal" | "warning" | "critical"): string {
  if (level === "critical") return "border-destructive/35 bg-destructive/8";
  if (level === "warning") return "border-warning/35 bg-warning/8";
  return "border-border bg-card";
}

function priorityToneClass(severity: PrioritySeverity): string {
  if (severity === "critical") return "border-destructive/30 bg-destructive/10 text-destructive";
  if (severity === "warning") return "border-warning/30 bg-warning/10 text-warning";
  if (severity === "info") return "border-accent/30 bg-accent/10 text-accent";
  return "border-success/30 bg-success/10 text-success";
}

function ConnectionStatus({ isConnected }: { isConnected: boolean }) {
  return (
    <div className="flex items-center gap-2">
      {isConnected ? (
        <>
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-success"></span>
          </span>
          <WifiHigh className="h-4 w-4 text-success" weight="bold" />
          <span className="text-xs text-success">Connected</span>
        </>
      ) : (
        <>
          <span className="h-2 w-2 rounded-full bg-destructive"></span>
          <WifiSlash className="h-4 w-4 text-destructive" weight="bold" />
          <span className="text-xs text-destructive">Disconnected</span>
        </>
      )}
    </div>
  );
}

function SignalCard({
  title,
  value,
  line1,
  line2,
  level,
}: {
  title: string;
  value: string;
  line1: string;
  line2: string;
  level: "normal" | "warning" | "critical";
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={cn(
        "rounded-xl border p-4 glass-panel transition-all duration-300",
        level === "critical" && "border-destructive/20 bg-destructive/5",
        level === "warning" && "border-warning/20 bg-warning/5"
      )}
    >
      <p className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground font-medium">{title}</p>
      <p className="text-xl md:text-2xl font-semibold mt-2 tabular-nums tracking-tight">{value}</p>
      <div className="mt-3 space-y-0.5">
        <p className="text-[12px] text-muted-foreground font-medium">{line1}</p>
        <p className="text-[11px] opacity-60">{line2}</p>
      </div>
    </motion.div>
  );
}

function OverviewSummaryCard({
  title,
  icon,
  children,
  delay = 0,
}: {
  title: string;
  icon: React.ElementType;
  children: React.ReactNode;
  delay?: number;
}) {
  const Icon = icon;
  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay }}
    >
      <Card className="glass-panel border-white/[0.04]">
        <CardHeader className="pb-3">
          <CardTitle className="text-[13px] font-semibold tracking-tight text-foreground/90">
            <Icon className="h-4 w-4 text-accent" weight="duotone" />
            {title}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-[12px] leading-relaxed text-muted-foreground">
          {children}
        </CardContent>
      </Card>
    </motion.div>
  );
}

export default function OverviewPage() {
  const [activeTab, setActiveTab] = useState<Tab>("metrics");
  const [range, setRange] = useState<RangeKey>("24h");

  const { isLoading, isConnected, uptime, policy, observe, proxy } = useDashboardMetrics();
  const { data: budgetPrimitivesResponse } = useBudgetPrimitives();
  const { data: advancedBudgetResponse } = useAdvancedBudgetMetrics();
  const agents = useAgentsData();

  const primitives = budgetPrimitivesResponse?.data;
  const advanced = advancedBudgetResponse?.data;

  const { events, isConnected: wsConnected, clearEvents } = useEventStream({
    enabled: activeTab === "live",
  });

  const rangeMs = useMemo(() => {
    if (range === "1h") return 60 * 60 * 1000;
    if (range === "7d") return 7 * 24 * 60 * 60 * 1000;
    return 24 * 60 * 60 * 1000;
  }, [range]);
  const rangeMinutes = Math.max(1, Math.floor(rangeMs / 60000));
  const rangeDays = rangeMs / (24 * 60 * 60 * 1000);
  const rangeLabel = range === "1h" ? "1h" : range === "7d" ? "7d" : "24h";

  const rangedRequests = useMemo(() => {
    const requests = primitives?.recent_requests ?? [];
    const now = Date.now();
    return requests.filter((request) => now - new Date(request.timestamp).getTime() <= rangeMs);
  }, [primitives?.recent_requests, rangeMs]);

  const rangedProxyRequests = useMemo(() => {
    const requests = proxy?.recent_requests ?? [];
    const now = Date.now();
    return requests.filter((request) => now - new Date(request.timestamp).getTime() <= rangeMs);
  }, [proxy?.recent_requests, rangeMs]);

  const rangedProxyResponses = useMemo(
    () => rangedProxyRequests.filter((entry) => typeof entry.status_code === "number"),
    [rangedProxyRequests]
  );

  const rangedLatencyValues = useMemo(
    () => rangedProxyResponses
      .map((entry) => entry.latency_ms)
      .filter((value): value is number => typeof value === "number"),
    [rangedProxyResponses]
  );

  const fallbackLatencyValues = useMemo(
    () => (proxy?.recent_requests ?? [])
      .map((entry) => entry.latency_ms)
      .filter((value): value is number => typeof value === "number"),
    [proxy?.recent_requests]
  );

  const latencyValues = rangedLatencyValues.length > 0 ? rangedLatencyValues : fallbackLatencyValues;
  const p95Latency = useMemo(() => percentile(latencyValues, 0.95), [latencyValues]);

  const requestCount = proxy?.total_requests ?? 0;
  const rangedRequestCount = rangedRequests.length > 0 ? rangedRequests.length : rangedProxyRequests.length;
  const requestsPerMinute = rangedRequestCount / rangeMinutes;
  const trafficPresentInRange = rangedRequestCount > 0 || (proxy?.active_connections ?? 0) > 0;

  const responseWindow = useMemo(
    () => (rangedProxyResponses.length > 0
      ? rangedProxyResponses
      : (proxy?.recent_requests ?? []).filter((entry) => typeof entry.status_code === "number")),
    [rangedProxyResponses, proxy?.recent_requests]
  );
  const errors5xx = useMemo(
    () => responseWindow.filter((entry) => (entry.status_code ?? 0) >= 500).length,
    [responseWindow]
  );
  const errorRate = responseWindow.length > 0 ? (errors5xx / responseWindow.length) * 100 : 0;

  const allowRate = policy?.evaluations
    ? (policy.allowed / policy.evaluations) * 100
    : 100;

  const sortedDailyTrend = useMemo(() => {
    const trend = advanced?.daily_trend ?? [];
    return [...trend].sort((a, b) => a.date.localeCompare(b.date));
  }, [advanced?.daily_trend]);

  const rangeSpend = useMemo(
    () => rangedRequests.reduce((sum, request) => sum + request.cost_usd, 0),
    [rangedRequests]
  );

  const spendToday = rangeSpend > 0
    ? rangeSpend
    : sortedDailyTrend.at(-1)?.cost ?? primitives?.total_cost_usd ?? 0;
  const prior7d = sortedDailyTrend.slice(Math.max(0, sortedDailyTrend.length - 8), -1);
  const avg7dSpend =
    prior7d.length > 0
      ? prior7d.reduce((sum, point) => sum + point.cost, 0) / prior7d.length
      : spendToday;
  const spendDeltaPct = avg7dSpend > 0 ? ((spendToday - avg7dSpend) / avg7dSpend) * 100 : 0;
  const monthForecast =
    rangeSpend > 0 ? (rangeSpend / Math.max(0.042, rangeDays)) * 30 : avg7dSpend * 30;
  const burnRatePerMin =
    rangeSpend > 0
      ? rangeSpend / rangeMinutes
      : uptime > 0
        ? (primitives?.total_cost_usd ?? 0) / Math.max(1, uptime / 60)
        : 0;

  const budgetLimit = primitives?.daily_limit_usd ?? advanced?.daily_limit_usd ?? null;
  const utilization = primitives?.utilization_pct ?? 0;

  const newModelFromAnomaly = advanced?.anomalies.find(
    (anomaly) => anomaly.anomaly_type === "new_model"
  );
  const latestModelObserved = useMemo(
    () => (proxy?.recent_requests ?? []).find((entry) => Boolean(entry.model))?.model ?? null,
    [proxy?.recent_requests]
  );

  const costSpikeAnomaly = advanced?.anomalies.find(
    (anomaly) => anomaly.anomaly_type === "cost_spike"
  );

  const riskNotes = useMemo(() => {
    const notes: string[] = [];
    notes.push(`PII detections: ${observe?.pii_detections ?? 0}`);
    if (newModelFromAnomaly) {
      notes.push(`New model observed: ${newModelFromAnomaly.description}`);
    } else if (latestModelObserved) {
      notes.push(`Latest model observed: ${latestModelObserved}`);
    }
    if (costSpikeAnomaly) {
      notes.push(`Cost anomaly: ${costSpikeAnomaly.description}`);
    }
    if (utilization >= 85) {
      notes.push(`Budget threshold approaching: ${utilization.toFixed(1)}%`);
    }
    return notes.slice(0, 4);
  }, [
    observe?.pii_detections,
    newModelFromAnomaly,
    latestModelObserved,
    costSpikeAnomaly,
    utilization,
  ]);

  const changeSummary = useMemo(() => {
    const changes: string[] = [];

    if (Math.abs(spendDeltaPct) >= 5) {
      changes.push(`Spend changed ${signedPercent(spendDeltaPct)} vs 7d baseline.`);
    }

    if (newModelFromAnomaly) {
      changes.push(`New model detected: ${newModelFromAnomaly.description}`);
    } else if (latestModelObserved) {
      changes.push(`Latest model in production traffic: ${latestModelObserved}`);
    }

    if ((policy?.denied ?? 0) === 0) {
      changes.push("No policy denies observed (unchanged).");
    } else {
      changes.push(`Policy denies observed: ${policy?.denied ?? 0}.`);
    }

    if (p95Latency > 800) {
      changes.push(`Latency elevated (p95 ${formatLatency(p95Latency)}).`);
    } else {
      changes.push("Latency remains within normal operating range.");
    }

    return changes.length > 0 ? changes : ["No material changes in selected range."];
  }, [
    spendDeltaPct,
    newModelFromAnomaly,
    latestModelObserved,
    policy?.denied,
    p95Latency,
  ]);

  const priorityEvents = useMemo(() => {
    const items: PriorityEvent[] = [];

    if (costSpikeAnomaly) {
      items.push({
        severity: "warning",
        title: "Cost spike detected",
        description: costSpikeAnomaly.description,
        href: "/budget",
      });
    } else if (spendDeltaPct >= 15) {
      items.push({
        severity: "warning",
        title: "Spend velocity increased",
        description: `Spend is ${signedPercent(spendDeltaPct)} vs 7d baseline in current range.`,
        href: "/budget",
      });
    }

    if (proxy && !proxy.status.enabled && trafficPresentInRange) {
      items.push({
        severity: "critical",
        title: "Proxy runtime disabled with traffic present",
        description: "Traffic is active while proxy status reports not running.",
        href: "/observability",
      });
    }

    if (utilization >= 85) {
      items.push({
        severity: "warning",
        title: "Budget threshold approaching",
        description: `${utilization.toFixed(1)}% used against configured daily limit.`,
        href: "/budget",
      });
    }

    if (newModelFromAnomaly || latestModelObserved) {
      items.push({
        severity: "info",
        title: "Model surface changed",
        description:
          newModelFromAnomaly?.description ??
          `Recent production model: ${latestModelObserved ?? "unknown"}`,
        href: "/observability",
      });
    }

    if ((policy?.denied ?? 0) === 0 && (observe?.pii_detections ?? 0) === 0) {
      items.push({
        severity: "ok",
        title: "No enforcement or PII incidents",
        description: "Policy denies and PII detections are both zero in current state.",
        href: "/policies",
      });
    }

    const rank: Record<PrioritySeverity, number> = {
      critical: 0,
      warning: 1,
      info: 2,
      ok: 3,
    };

    return items.sort((a, b) => rank[a.severity] - rank[b.severity]).slice(0, 5);
  }, [
    costSpikeAnomaly,
    spendDeltaPct,
    proxy,
    trafficPresentInRange,
    utilization,
    newModelFromAnomaly,
    latestModelObserved,
    policy?.denied,
    observe?.pii_detections,
  ]);

  const flowSnapshots = useMemo(() => {
    const map = new Map<string, { provider: string; path: string; model: string; totalCost: number; count: number }>();

    for (const request of rangedRequests) {
      const path = (request.path || "-").split("?")[0] || request.path || "-";
      const model = request.model || request.provider || "unknown";
      const provider = request.provider || "unknown";
      const key = `${provider}|${path}|${model}`;

      const current = map.get(key) || {
        provider,
        path,
        model,
        totalCost: 0,
        count: 0,
      };
      current.totalCost += request.cost_usd;
      current.count += 1;
      map.set(key, current);
    }

    return Array.from(map.values())
      .map((row) => ({
        provider: row.provider,
        path: row.path,
        model: row.model,
        avgCost: row.count > 0 ? row.totalCost / row.count : 0,
      }))
      .sort((a, b) => b.avgCost - a.avgCost)
      .slice(0, 2);
  }, [rangedRequests]);

  const alertsCount = (primitives?.alerts.length ?? 0) +
    (advanced?.anomalies.filter((anomaly) => anomaly.severity !== "info").length ?? 0) +
    ((proxy && !proxy.status.enabled && trafficPresentInRange) ? 1 : 0);

  const isBusy = isLoading || agents.isLoading;
  const envLabel = process.env.NEXT_PUBLIC_SOTH_ENV || "Prod";

  return (
    <div className="min-h-screen bg-background selection:bg-accent/30">
      <header className="border-b border-white/[0.04] bg-background/60 backdrop-blur-xl sticky top-0 z-20">
        <div className="px-6 py-4 flex items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <h1 className="text-xl font-bold tracking-tight bg-gradient-to-br from-foreground to-foreground/60 bg-clip-text text-transparent">
              Overview
            </h1>
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-muted/50 border border-border text-[10px] font-bold uppercase tracking-widest text-muted-foreground">
                <span className={cn("h-1.5 w-1.5 rounded-full", isConnected ? "bg-success shadow-[0_0_8px_rgba(16,185,129,0.5)]" : "bg-destructive")} />
                {envLabel}
              </span>
              <select
                value={range}
                onChange={(event) => setRange(event.target.value as RangeKey)}
                className="h-8 rounded-full border border-border bg-card/50 px-3 text-[11px] font-medium text-foreground/80 hover:bg-card hover:border-border-hover transition-all focus:outline-none focus:ring-2 focus:ring-accent/20 cursor-pointer"
              >
                <option value="1h">Last 1 hour</option>
                <option value="24h">Last 24 hours</option>
                <option value="7d">Last 7 days</option>
              </select>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="bg-muted/40 p-1 rounded-full flex gap-1">
              <button
                onClick={() => setActiveTab("metrics")}
                className={modeButtonClass(activeTab === "metrics")}
              >
                <ChartLine className="h-3.5 w-3.5" weight={activeTab === "metrics" ? "fill" : "regular"} />
                Metrics
              </button>
              <button
                onClick={() => setActiveTab("live")}
                className={modeButtonClass(activeTab === "live")}
              >
                <Waveform className="h-3.5 w-3.5" weight={activeTab === "live" ? "fill" : "regular"} />
                Live
              </button>
            </div>

            <span className={cn(
              "hidden sm:inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-[10px] font-bold uppercase tracking-widest transition-all",
              alertsCount > 0
                ? "border-warning/20 bg-warning/10 text-warning animate-pulse"
                : "border-border bg-muted/30 text-muted-foreground"
            )}>
              Alerts ({alertsCount})
            </span>

            <div className="h-4 w-px bg-border mx-1 hidden sm:block" />

            <ConnectionStatus isConnected={isConnected} />

            {isConnected && (
              <span className="hidden lg:inline text-[11px] text-muted-foreground/60 font-mono tracking-tighter tabular-nums bg-muted/30 px-2 py-1 rounded-md">
                UPTIME: {formatDuration(uptime)}
              </span>
            )}
          </div>
        </div>
      </header>

      <div className="px-4 md:px-6 py-4 md:py-5 space-y-4 md:space-y-5">
        {!isConnected && !isBusy && (
          <div className="p-3 rounded-lg border border-destructive/25 bg-destructive/10">
            <div className="flex items-start gap-2 text-xs text-destructive">
              <WifiSlash className="h-4 w-4 mt-0.5 shrink-0" weight="bold" />
              <span>
                Unable to connect to SOTH backend. Start proxy with dashboard enabled to restore overview telemetry.
              </span>
            </div>
          </div>
        )}

        {activeTab === "metrics" && (
          <>
            <div className="hidden md:grid md:grid-cols-4 gap-4">
              <SignalCard
                title="Policy"
                value={`Allow ${allowRate.toFixed(1)}%`}
                line1={`${policy?.denied ?? 0} denies`}
                line2={(policy?.denied ?? 0) > 0 ? "investigate deny policy" : "unchanged"}
                level={(policy?.denied ?? 0) > 0 ? "warning" : "normal"}
              />
              <SignalCard
                title="Traffic"
                value={`${formatNumber(Math.round(requestsPerMinute))} bpm`}
                line1={`p95 ${formatLatency(p95Latency)}`}
                line2={`window: last ${rangeLabel}`}
                level={p95Latency > 800 ? "warning" : "normal"}
              />
              <SignalCard
                title="Errors"
                value={`${errorRate.toFixed(1)}%`}
                line1={`5xx: ${errors5xx}`}
                line2={`window: last ${rangeLabel}`}
                level={errorRate > 2 ? "warning" : "normal"}
              />
              <SignalCard
                title="Spend"
                value={`${formatCurrency(spendToday)}`}
                line1={`vs 7d: ${signedPercent(spendDeltaPct)}`}
                line2={budgetLimit ? `budget @ ${utilization.toFixed(1)}%` : `forecast ${formatCurrency(monthForecast)}`}
                level={utilization >= 85 || spendDeltaPct >= 15 ? "warning" : "normal"}
              />
            </div>

            <div className="hidden md:grid grid-cols-2 gap-6">
              <div className="space-y-6">
                <OverviewSummaryCard title="Traffic & Proxy" icon={Pulse} delay={0.1}>
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-foreground">Proxy Status</span>
                    <span className={cn("px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider border", proxy?.status.enabled ? "text-success border-success/20 bg-success/5" : "text-warning border-warning/20 bg-warning/5")}>
                      {proxy?.status.enabled ? "Active" : "Disabled"}
                    </span>
                  </div>
                  <p className="text-muted-foreground">Active connections: <span className="text-foreground font-medium">{proxy?.active_connections ?? 0}</span></p>
                  <p className="text-muted-foreground">Total requests: <span className="text-foreground font-medium">{formatNumber(requestCount)}</span></p>
                </OverviewSummaryCard>

                <OverviewSummaryCard title="Policy Enforcement" icon={ShieldCheck} delay={0.2}>
                  <div className="space-y-1.5 pt-1">
                    <div className="flex justify-between">
                      <span>Evaluations</span>
                      <span className="text-foreground font-medium">{formatNumber(policy?.evaluations ?? 0)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Allowed</span>
                      <span className="text-success font-medium">{formatNumber(policy?.allowed ?? 0)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Denied</span>
                      <span className="text-destructive font-medium">{formatNumber(policy?.denied ?? 0)}</span>
                    </div>
                  </div>
                  <div className="mt-3 pt-3 border-t border-border/50">
                    <p className="text-[10px] uppercase font-bold tracking-widest text-muted-foreground/50">Top Deny Reason</p>
                    <p className="text-foreground font-medium truncate mt-1" title={policy?.recent_denials?.[0]?.reason ?? "-"}>
                      {policy?.recent_denials?.[0]?.reason ?? "None observed"}
                    </p>
                  </div>
                </OverviewSummaryCard>
              </div>

              <div className="space-y-6">
                <OverviewSummaryCard title="Spend Velocity" icon={CurrencyDollar} delay={0.15}>
                  <div className="space-y-1.5 pt-1">
                    <div className="flex justify-between">
                      <span>Range vs 7d</span>
                      <span className={cn("font-medium", spendDeltaPct > 0 ? "text-warning" : "text-success")}>{signedPercent(spendDeltaPct)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Burn Rate</span>
                      <span className="text-foreground font-medium">{formatCurrency(burnRatePerMin)} / min</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Month Forecast</span>
                      <span className="text-foreground font-medium">{formatCurrency(monthForecast)}</span>
                    </div>
                  </div>
                  <div className="mt-3 pt-3 border-t border-border/50">
                    <p className="text-[10px] uppercase font-bold tracking-widest text-muted-foreground/50">Limit Status</p>
                    <p className="text-foreground font-medium mt-1">
                      {budgetLimit
                        ? `Utilizing ${utilization.toFixed(1)}% of daily limit`
                        : "No budget limit defined"}
                    </p>
                  </div>
                </OverviewSummaryCard>

                <OverviewSummaryCard title="Risk & Compliance" icon={ShieldWarning} delay={0.25}>
                  {riskNotes.length === 0 ? (
                    <p className="text-muted-foreground py-2 italic text-center">No active risk indicators.</p>
                  ) : (
                    <div className="space-y-2 pt-1">
                      {riskNotes.map((note) => (
                        <div key={note} className="flex items-center gap-2">
                          <div className="h-1.5 w-1.5 rounded-full bg-accent/40" />
                          <p className="text-foreground/80">{note}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </OverviewSummaryCard>
              </div>
            </div>

            <OverviewSummaryCard title={`What Changed Since ${range === "1h" ? "Last Hour" : range === "7d" ? "Last 7 Days" : "Last 24 Hours"}`} icon={Clock} delay={0.3}>
              <div className="space-y-2 pt-1 font-medium italic">
                {changeSummary.map((item, i) => (
                  <p key={item} className="text-foreground/70">• {item}</p>
                ))}
              </div>
            </OverviewSummaryCard>

            <OverviewSummaryCard title="Priority Events" icon={Warning} delay={0.35}>
              <div className="space-y-3 pt-1">
                {priorityEvents.length === 0 ? (
                  <div className="rounded-xl border border-success/10 bg-success/5 px-4 py-3 text-xs text-success/80 font-medium text-center">
                    System nominal. No priority events observed.
                  </div>
                ) : (
                  priorityEvents.map((event, index) => (
                    <motion.a
                      key={`${event.title}-${index}`}
                      href={event.href}
                      whileHover={{ scale: 1.01, x: 2 }}
                      className={cn(
                        "flex items-start justify-between gap-3 rounded-xl border px-4 py-3 transition-all",
                        priorityToneClass(event.severity),
                        "hover:brightness-110 shadow-sm"
                      )}
                    >
                      <div className="space-y-1">
                        <p className="text-[13px] font-bold tracking-tight">{event.title}</p>
                        <p className="text-[11px] font-medium opacity-70 leading-relaxed">{event.description}</p>
                      </div>
                      <ArrowsOutSimple className="h-3.5 w-3.5 shrink-0 mt-0.5 opacity-40" />
                    </motion.a>
                  ))
                )}

                <div className="flex items-center gap-2 pt-2">
                  <Button asChild variant="outline" size="sm" className="h-8 rounded-full px-4 border-white/[0.04] bg-white/[0.02]">
                    <a href="/observability">Observability</a>
                  </Button>
                  <Button asChild variant="outline" size="sm" className="h-8 rounded-full px-4 border-white/[0.04] bg-white/[0.02]">
                    <a href="/budget">Budget Control</a>
                  </Button>
                  <Button asChild variant="outline" size="sm" className="h-8 rounded-full px-4 border-white/[0.04] bg-white/[0.02]">
                    <a href="/policies">Policy Engine</a>
                  </Button>
                </div>
              </div>
            </OverviewSummaryCard>

            <OverviewSummaryCard title="Request Flow Architecture" icon={Info} delay={0.4}>
              <div className="space-y-3 pt-1">
                {flowSnapshots.length === 0 ? (
                  <p className="text-muted-foreground py-2 italic">Architecture telemetry unavailable for this range.</p>
                ) : (
                  flowSnapshots.map((flow, index) => (
                    <div key={`${flow.provider}-${flow.path}-${index}`} className="group p-3 rounded-xl border border-white/[0.04] bg-white/[0.02] hover:bg-white/[0.04] transition-colors">
                      <div className="flex items-center gap-2 font-mono text-[11px] tracking-tight">
                        <span className="text-accent/60">APP</span>
                        <span className="text-muted-foreground/30">→</span>
                        <span className="text-success/60">POLICY</span>
                        <span className="text-muted-foreground/30">→</span>
                        <span className="text-foreground/80 truncate">{flow.path}</span>
                        <span className="text-muted-foreground/30">→</span>
                        <span className="text-accent/80 font-bold">{flow.model}</span>
                      </div>
                      <div className="flex justify-between mt-2 items-center">
                        <span className="text-[10px] uppercase font-bold tracking-widest text-muted-foreground/40">{flow.provider}</span>
                        <span className="text-[11px] font-bold text-foreground/60">{formatCurrency(flow.avgCost)} <span className="text-[9px] font-normal opacity-40">avg/req</span></span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </OverviewSummaryCard>

            <div className="md:hidden space-y-3">
              <Card>
                <CardContent className="p-3 space-y-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Policy</span>
                    <span className="font-semibold text-success">OK</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Traffic</span>
                    <span className="font-semibold">{formatNumber(Math.round(requestsPerMinute))} / min</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Latency</span>
                    <span className="font-semibold">p95 {formatLatency(p95Latency)}</span>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-3 space-y-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Spend</span>
                    <span className={cn("font-semibold", spendDeltaPct >= 15 ? "text-warning" : "text-foreground")}>
                      {formatCurrency(spendToday)} {signedPercent(spendDeltaPct)}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Forecast</span>
                    <span className="font-semibold">{formatCurrency(monthForecast)}</span>
                  </div>
                  {budgetLimit && (
                    <div className="flex items-center justify-between">
                      <span className="text-muted-foreground">Budget</span>
                      <span className={cn("font-semibold", utilization >= 85 ? "text-warning" : "text-foreground")}>
                        {utilization.toFixed(1)}%
                      </span>
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-semibold tracking-[0.02em]">
                    <Clock className="h-3.5 w-3.5 text-accent" weight="duotone" />
                    What Changed
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-1 text-[11px] text-muted-foreground">
                  {changeSummary.slice(0, 3).map((item) => (
                    <p key={item}>• {item}</p>
                  ))}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm font-semibold tracking-[0.02em]">
                    <Warning className="h-3.5 w-3.5 text-warning" weight="duotone" />
                    Priority Events ({priorityEvents.length})
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-1.5 text-[11px]">
                  {priorityEvents.slice(0, 2).map((event, index) => (
                    <a
                      key={`${event.title}-${index}`}
                      href={event.href}
                      className={cn(
                        "block rounded-md border px-2.5 py-2",
                        priorityToneClass(event.severity)
                      )}
                    >
                      <p className="font-medium">{event.title}</p>
                      <p className="opacity-90">{event.description}</p>
                    </a>
                  ))}
                </CardContent>
              </Card>

              <div className="grid grid-cols-3 gap-2">
                <Button asChild variant="outline" size="sm" className="h-7 text-[11px]">
                  <a href="/observability">Observe</a>
                </Button>
                <Button asChild variant="outline" size="sm" className="h-7 text-[11px]">
                  <a href="/budget">Budget</a>
                </Button>
                <Button asChild variant="outline" size="sm" className="h-7 text-[11px]">
                  <a href="/policies">Policy</a>
                </Button>
              </div>
            </div>
          </>
        )}

        {activeTab === "live" && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 md:gap-6">
            <div className="lg:col-span-2 order-1">
              <LiveFeedPanel events={events} isConnected={wsConnected} onClear={clearEvents} />
            </div>
            <div className="order-2">
              <AgentsPanel data={agents.data?.data} isLoading={agents.isLoading} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
