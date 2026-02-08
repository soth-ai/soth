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
    "inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md border text-[11px] font-medium transition-colors",
    active
      ? "bg-accent/12 text-accent border-accent/40"
      : "bg-transparent text-muted-foreground border-border hover:text-foreground hover:bg-muted/40"
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
    <div className={cn("rounded-lg border p-3", signalToneClass(level))}>
      <p className="text-[10px] uppercase tracking-[0.08em] text-muted-foreground">{title}</p>
      <p className="text-sm md:text-base font-semibold mt-1 tabular-nums">{value}</p>
      <p className="text-[11px] text-muted-foreground mt-1">{line1}</p>
      <p className="text-[11px] text-muted-foreground">{line2}</p>
    </div>
  );
}

function OverviewSummaryCard({
  title,
  icon,
  children,
}: {
  title: string;
  icon: React.ElementType;
  children: React.ReactNode;
}) {
  const Icon = icon;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-semibold tracking-[0.02em]">
          <Icon className="h-3.5 w-3.5 text-accent" weight="duotone" />
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-1.5 text-xs">{children}</CardContent>
    </Card>
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
    <div className="min-h-screen">
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-20">
        <div className="px-4 md:px-6 py-2.5 md:py-3 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 md:gap-3">
            <h1 className="text-base md:text-lg font-semibold">Overview</h1>
            <span className="inline-flex items-center gap-1 px-2 py-1 rounded-md border border-border text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
              Env: {envLabel}
              <span className={cn("h-1.5 w-1.5 rounded-full", isConnected ? "bg-success" : "bg-destructive")} />
            </span>
            <select
              value={range}
              onChange={(event) => setRange(event.target.value as RangeKey)}
              className="h-7 rounded-md border border-border bg-transparent px-2 text-[11px] text-muted-foreground focus:outline-none focus:ring-1 focus:ring-accent"
            >
              <option value="1h">Last 1h</option>
              <option value="24h">Last 24h</option>
              <option value="7d">Last 7d</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
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
            <span className={cn(
              "inline-flex items-center gap-1 rounded-md border px-2 py-1 text-[10px] uppercase tracking-[0.08em]",
              alertsCount > 0
                ? "border-warning/35 bg-warning/10 text-warning"
                : "border-border text-muted-foreground"
            )}>
              Alerts ({alertsCount})
            </span>
            <ConnectionStatus isConnected={isConnected} />
            {isConnected && (
              <span className="hidden sm:inline text-[11px] text-muted-foreground font-mono tabular-nums">
                {formatDuration(uptime)}
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
            <div className="hidden md:grid md:grid-cols-4 gap-3">
              <SignalCard
                title="Policy"
                value={`Allow ${allowRate.toFixed(1)}%`}
                line1={`${policy?.denied ?? 0} denies`}
                line2={(policy?.denied ?? 0) > 0 ? "investigate deny policy" : "unchanged"}
                level={(policy?.denied ?? 0) > 0 ? "warning" : "normal"}
              />
              <SignalCard
                title="Traffic"
                value={`${formatNumber(Math.round(requestsPerMinute))} / min`}
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

            <div className="hidden md:grid grid-cols-2 gap-4">
              <div className="space-y-4">
                <OverviewSummaryCard title="Traffic & Proxy" icon={Pulse}>
                  <p className={cn("font-medium", proxy?.status.enabled ? "text-success" : "text-warning")}>
                    Proxy: {proxy?.status.enabled ? "Running" : "Not running"}
                  </p>
                  <p className="text-muted-foreground">Active connections: {proxy?.active_connections ?? 0}</p>
                  <p className="text-muted-foreground">Total requests: {formatNumber(requestCount)}</p>
                </OverviewSummaryCard>

                <OverviewSummaryCard title="Policy Enforcement" icon={ShieldCheck}>
                  <p className="text-muted-foreground">Evaluations: {formatNumber(policy?.evaluations ?? 0)}</p>
                  <p className="text-muted-foreground">Allowed: {formatNumber(policy?.allowed ?? 0)}</p>
                  <p className="text-muted-foreground">Denied: {formatNumber(policy?.denied ?? 0)}</p>
                  <p className="text-muted-foreground truncate" title={policy?.recent_denials?.[0]?.reason ?? "-"}>
                    Top deny reason: {policy?.recent_denials?.[0]?.reason ?? "-"}
                  </p>
                </OverviewSummaryCard>
              </div>

              <div className="space-y-4">
                <OverviewSummaryCard title="Spend Velocity" icon={CurrencyDollar}>
                  <p className="text-muted-foreground">{rangeLabel} vs 7d avg: {signedPercent(spendDeltaPct)}</p>
                  <p className="text-muted-foreground">Burn rate: {formatCurrency(burnRatePerMin)} / min</p>
                  <p className="text-muted-foreground">
                    Forecast: {formatCurrency(monthForecast)}
                  </p>
                  <p className="text-muted-foreground">
                    {budgetLimit
                      ? `Daily budget utilization: ${utilization.toFixed(1)}%`
                      : "No budget limit configured"}
                  </p>
                </OverviewSummaryCard>

                <OverviewSummaryCard title="Risk & Compliance" icon={ShieldWarning}>
                  {riskNotes.length === 0 ? (
                    <p className="text-muted-foreground">No active risk indicators.</p>
                  ) : (
                    riskNotes.map((note) => (
                      <p key={note} className="text-muted-foreground">{note}</p>
                    ))
                  )}
                </OverviewSummaryCard>
              </div>
            </div>

            <Card className="hidden md:block">
              <CardHeader>
                <CardTitle className="text-sm font-semibold tracking-[0.02em]">
                  <Clock className="h-3.5 w-3.5 text-accent" weight="duotone" />
                  What Changed Since {range === "1h" ? "Last 1h" : range === "7d" ? "Last 7d" : "Last 24h"}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-1.5 text-xs text-muted-foreground">
                {changeSummary.map((item) => (
                  <p key={item}>• {item}</p>
                ))}
              </CardContent>
            </Card>

            <Card className="hidden md:block">
              <CardHeader>
                <CardTitle className="text-sm font-semibold tracking-[0.02em]">
                  <Warning className="h-3.5 w-3.5 text-warning" weight="duotone" />
                  Priority Events
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {priorityEvents.length === 0 ? (
                  <div className="rounded-md border border-success/30 bg-success/10 px-3 py-2 text-xs text-success">
                    No priority events in current range.
                  </div>
                ) : (
                  priorityEvents.map((event, index) => (
                    <a
                      key={`${event.title}-${index}`}
                      href={event.href}
                      className={cn(
                        "flex items-start justify-between gap-2 rounded-md border px-3 py-2 transition-colors",
                        priorityToneClass(event.severity),
                        "hover:brightness-110"
                      )}
                    >
                      <div>
                        <p className="text-xs font-medium">{event.title}</p>
                        <p className="text-[11px] opacity-90 mt-0.5">{event.description}</p>
                      </div>
                      <ArrowsOutSimple className="h-3.5 w-3.5 shrink-0 mt-0.5" />
                    </a>
                  ))
                )}

                <div className="flex items-center gap-2 pt-2">
                  <Button asChild variant="outline" size="sm" className="h-7 px-2.5 text-[11px]">
                    <a href="/observability">View Observability</a>
                  </Button>
                  <Button asChild variant="outline" size="sm" className="h-7 px-2.5 text-[11px]">
                    <a href="/budget">View Budget</a>
                  </Button>
                  <Button asChild variant="outline" size="sm" className="h-7 px-2.5 text-[11px]">
                    <a href="/policies">View Policies</a>
                  </Button>
                </div>
              </CardContent>
            </Card>

            <Card className="hidden md:block">
              <CardHeader>
                <CardTitle className="text-sm font-semibold tracking-[0.02em]">
                  <Info className="h-3.5 w-3.5 text-accent" weight="duotone" />
                  Request Flow Snapshot
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-1.5 text-xs">
                {flowSnapshots.length === 0 ? (
                  <p className="text-muted-foreground">No request flow snapshots available for this range.</p>
                ) : (
                  flowSnapshots.map((flow, index) => (
                    <p key={`${flow.provider}-${flow.path}-${index}`} className="font-mono text-muted-foreground">
                      Agent App -&gt; Policy Allowed -&gt; {flow.path} -&gt; {flow.model} ({flow.provider}) -&gt; {formatCurrency(flow.avgCost)} / req
                    </p>
                  ))
                )}
              </CardContent>
            </Card>

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
