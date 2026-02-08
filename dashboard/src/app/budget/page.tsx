"use client";

import { useMemo, useState } from "react";
import {
  CurrencyDollar,
  Coin,
  Target,
  TrendUp,
  Warning,
  Info,
  CheckCircle,
  WifiSlash,
  DownloadSimple,
  ChartPie,
  Lightning,
  Funnel,
} from "@phosphor-icons/react";
import {
  useAdvancedBudgetMetrics,
  useBudgetPrimitives,
  useDashboardMetrics,
} from "@/hooks/useDashboardData";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { cn, formatCurrency, formatNumber } from "@/lib/utils";
import type { AdvancedBudgetMetrics, BudgetPrimitives, BudgetRequestPrimitive } from "@/types";

type BreakdownMode = "provider" | "model" | "endpoint";

interface TrendPoint {
  label: string;
  cost: number;
}

interface BreakdownRow {
  key: string;
  requests: number;
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  totalCost: number;
  avgCost: number;
  avgLatencyMs: number | null;
}

interface BudgetAnomaly {
  level: "info" | "warning" | "error";
  title: string;
  description: string;
}

interface BudgetRecommendation {
  title: string;
  description: string;
  effort: "low" | "medium" | "high";
}

function normalizePath(path: string): string {
  const trimmed = path.trim();
  if (!trimmed) return "-";
  const withoutQuery = trimmed.split("?")[0] || trimmed;
  return withoutQuery;
}

function buildTrend(requests: BudgetRequestPrimitive[]): TrendPoint[] {
  if (requests.length === 0) {
    return [];
  }

  const sorted = [...requests].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  const minuteCost = new Map<string, number>();
  for (const request of sorted) {
    const date = new Date(request.timestamp);
    const label = `${String(date.getHours()).padStart(2, "0")}:${String(
      date.getMinutes()
    ).padStart(2, "0")}`;
    minuteCost.set(label, (minuteCost.get(label) || 0) + request.cost_usd);
  }

  return Array.from(minuteCost.entries())
    .map(([label, cost]) => ({ label, cost }))
    .slice(-24);
}

function buildBreakdownRows(
  requests: BudgetRequestPrimitive[],
  mode: BreakdownMode
): BreakdownRow[] {
  const grouped = new Map<
    string,
    {
      requests: number;
      inputTokens: number;
      outputTokens: number;
      totalTokens: number;
      totalCost: number;
      latencySum: number;
      latencyCount: number;
    }
  >();

  for (const request of requests) {
    const key =
      mode === "provider"
        ? request.provider || "unknown"
        : mode === "model"
          ? request.model || "unknown"
          : `${request.method} ${normalizePath(request.path)}`;

    const current = grouped.get(key) || {
      requests: 0,
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 0,
      totalCost: 0,
      latencySum: 0,
      latencyCount: 0,
    };

    current.requests += 1;
    current.inputTokens += request.input_tokens;
    current.outputTokens += request.output_tokens;
    current.totalTokens += request.total_tokens;
    current.totalCost += request.cost_usd;

    if (typeof request.latency_ms === "number") {
      current.latencySum += request.latency_ms;
      current.latencyCount += 1;
    }

    grouped.set(key, current);
  }

  return Array.from(grouped.entries())
    .map(([key, value]) => ({
      key,
      requests: value.requests,
      inputTokens: value.inputTokens,
      outputTokens: value.outputTokens,
      totalTokens: value.totalTokens,
      totalCost: value.totalCost,
      avgCost: value.requests > 0 ? value.totalCost / value.requests : 0,
      avgLatencyMs:
        value.latencyCount > 0 ? value.latencySum / value.latencyCount : null,
    }))
    .sort((a, b) => b.totalCost - a.totalCost || b.totalTokens - a.totalTokens)
    .slice(0, 50);
}

function buildAnomalies(
  primitives: BudgetPrimitives | undefined,
  advanced: AdvancedBudgetMetrics | undefined
): BudgetAnomaly[] {
  const anomalies: BudgetAnomaly[] = [];

  if (primitives?.alerts?.length) {
    anomalies.push(
      ...primitives.alerts.map((alert) => ({
        level: alert.level,
        title:
          alert.level === "error"
            ? "Budget Alert"
            : alert.level === "warning"
              ? "Budget Warning"
              : "Budget Info",
        description: alert.message,
      }))
    );
  }

  if (advanced?.anomalies?.length) {
    anomalies.push(
      ...advanced.anomalies.slice(0, 3).map((anomaly) => ({
        level:
          anomaly.severity === "critical"
            ? "error"
            : anomaly.severity === "warning"
              ? "warning"
              : "info",
        title: anomaly.anomaly_type.replace(/_/g, " "),
        description: anomaly.description,
      }))
    );
  }

  if ((primitives?.utilization_pct || 0) >= 90) {
    anomalies.unshift({
      level: "error",
      title: "Daily Budget Near Limit",
      description: `${(primitives?.utilization_pct || 0).toFixed(1)}% of daily limit is already used.`,
    });
  }

  return anomalies.slice(0, 5);
}

function buildRecommendations(
  primitives: BudgetPrimitives | undefined,
  advanced: AdvancedBudgetMetrics | undefined
): BudgetRecommendation[] {
  if (advanced?.recommendations?.length) {
    return advanced.recommendations.slice(0, 3).map((item) => ({
      title: item.title,
      description: item.description,
      effort: item.effort,
    }));
  }

  if (!primitives) {
    return [];
  }

  const recommendations: BudgetRecommendation[] = [];
  const providerBreakdown = primitives.provider_breakdown;
  const topProvider = providerBreakdown[0];

  if (topProvider && primitives.total_cost_usd > 0) {
    const share = (topProvider.total_cost_usd / primitives.total_cost_usd) * 100;
    if (share >= 70) {
      recommendations.push({
        title: `Diversify from ${topProvider.provider}`,
        description: `${topProvider.provider} is ${share.toFixed(1)}% of current spend. Validate lower-cost routing for non-critical calls.`,
        effort: "medium",
      });
    }
  }

  if (primitives.total_output_tokens > primitives.total_input_tokens * 2) {
    recommendations.push({
      title: "Cap output token budgets",
      description:
        "Output tokens are disproportionately high. Add tighter max output tokens or shorter completion constraints.",
      effort: "low",
    });
  }

  if (providerBreakdown.some((provider) => provider.avg_cost_per_request > 0.01)) {
    recommendations.push({
      title: "Review high-cost request classes",
      description:
        "Some request classes show high average cost. Consider model tier downgrades for deterministic or tooling-heavy paths.",
      effort: "medium",
    });
  }

  return recommendations.slice(0, 3);
}

function toCsv(rows: BreakdownRow[], mode: BreakdownMode): string {
  const header = [
    mode,
    "requests",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "avg_cost_usd",
    "total_cost_usd",
    "avg_latency_ms",
  ];

  const escape = (value: string) => {
    if (value.includes(",") || value.includes("\"") || value.includes("\n")) {
      return `"${value.replace(/\"/g, '""')}"`;
    }
    return value;
  };

  const body = rows.map((row) =>
    [
      escape(row.key),
      row.requests.toString(),
      row.inputTokens.toString(),
      row.outputTokens.toString(),
      row.totalTokens.toString(),
      row.avgCost.toFixed(6),
      row.totalCost.toFixed(6),
      row.avgLatencyMs === null ? "" : row.avgLatencyMs.toFixed(2),
    ].join(",")
  );

  return [header.join(","), ...body].join("\n");
}

function downloadBlob(fileName: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  anchor.click();
  URL.revokeObjectURL(url);
}

function StatCard({
  label,
  value,
  subtitle,
  icon: Icon,
  tone = "default",
}: {
  label: string;
  value: string;
  subtitle?: string;
  icon: React.ElementType;
  tone?: "default" | "warning" | "error" | "success";
}) {
  const toneClasses = {
    default: "bg-accent/10 text-accent",
    warning: "bg-warning/10 text-warning",
    error: "bg-destructive/10 text-destructive",
    success: "bg-success/10 text-success",
  };

  return (
    <Card>
      <CardContent className="p-3.5 md:p-4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <p className="text-[10px] text-muted-foreground uppercase tracking-[0.08em]">{label}</p>
            <p className="text-xl md:text-2xl font-semibold tabular-nums mt-1">{value}</p>
            {subtitle ? <p className="text-[11px] text-muted-foreground mt-1">{subtitle}</p> : null}
          </div>
          <div className={cn("p-1.5 rounded-lg", toneClasses[tone])}>
            <Icon className="h-3.5 w-3.5" weight="duotone" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default function BudgetPage() {
  const { isConnected } = useDashboardMetrics();
  const { data: primitivesResponse, isLoading, isError, refetch } = useBudgetPrimitives();
  const { data: advancedResponse } = useAdvancedBudgetMetrics();
  const [breakdown, setBreakdown] = useState<BreakdownMode>("provider");

  const primitives = primitivesResponse?.data;
  const advanced = advancedResponse?.data;

  const trend = useMemo(
    () => buildTrend(primitives?.recent_requests || []),
    [primitives?.recent_requests]
  );
  const anomalies = useMemo(
    () => buildAnomalies(primitives, advanced),
    [primitives, advanced]
  );
  const recommendations = useMemo(
    () => buildRecommendations(primitives, advanced),
    [primitives, advanced]
  );
  const breakdownRows = useMemo(
    () => buildBreakdownRows(primitives?.recent_requests || [], breakdown),
    [primitives?.recent_requests, breakdown]
  );

  const utilization = primitives?.utilization_pct || 0;
  const maxTrendCost = Math.max(1, ...trend.map((point) => point.cost));

  const handleExportJson = () => {
    if (!primitives) return;
    const payload = {
      generated_at: new Date().toISOString(),
      breakdown,
      primitives,
      breakdown_rows: breakdownRows,
    };
    downloadBlob(
      `soth-budget-primitives-${Date.now()}.json`,
      JSON.stringify(payload, null, 2),
      "application/json"
    );
  };

  const handleExportCsv = () => {
    if (!breakdownRows.length) return;
    downloadBlob(
      `soth-budget-breakdown-${breakdown}-${Date.now()}.csv`,
      toCsv(breakdownRows, breakdown),
      "text/csv;charset=utf-8"
    );
  };

  return (
    <div className="min-h-screen">
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-10">
        <div className="px-4 md:px-6 py-2.5 md:py-3 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 md:gap-3">
            <div className="h-7 w-7 rounded-lg bg-accent/10 flex items-center justify-center">
              <CurrencyDollar className="h-4 w-4 text-accent" weight="duotone" />
            </div>
            <div>
              <h1 className="text-base md:text-lg font-semibold">Budget & Spend</h1>
              <p className="text-[11px] text-muted-foreground hidden sm:block">
                Unified budget primitives for finance, security, and engineering.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={() => refetch()}
              className="h-7 px-2.5 text-[11px] font-medium"
            >
              Refresh
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={handleExportCsv}
              disabled={!breakdownRows.length}
              className="h-7 px-2.5 text-[11px] font-medium"
            >
              <DownloadSimple className="h-3 w-3 mr-1" />
              CSV
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={handleExportJson}
              disabled={!primitives}
              className="h-7 px-2.5 text-[11px] font-medium"
            >
              <DownloadSimple className="h-3 w-3 mr-1" />
              JSON
            </Button>
          </div>
        </div>
      </header>

      <div className="px-4 md:px-6 py-4 md:py-5 space-y-4 md:space-y-5">
        {!isConnected && (
          <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/20">
            <div className="flex items-center gap-2 text-xs text-destructive">
              <WifiSlash className="h-4 w-4" weight="bold" />
              <span>Unable to connect to SOTH backend. Start the proxy and dashboard API.</span>
            </div>
          </div>
        )}

        {isError && !isLoading && (
          <div className="p-3 rounded-lg bg-warning/10 border border-warning/20">
            <div className="flex items-center gap-2 text-xs text-warning">
              <Warning className="h-4 w-4" weight="fill" />
              <span>Failed to load budget primitives. Retry after the proxy starts receiving traffic.</span>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3 md:gap-4">
          {isLoading ? (
            Array.from({ length: 4 }).map((_, idx) => (
              <Card key={idx}>
                <CardContent className="p-3.5">
                  <Skeleton className="h-20 w-full" />
                </CardContent>
              </Card>
            ))
          ) : (
            <>
              <StatCard
                label="Total Spend"
                value={formatCurrency(primitives?.total_cost_usd || 0)}
                subtitle={`${formatNumber(primitives?.total_requests || 0)} requests`}
                icon={CurrencyDollar}
              />
              <StatCard
                label="Total Tokens"
                value={formatNumber(primitives?.total_tokens || 0)}
                subtitle={`In ${formatNumber(primitives?.total_input_tokens || 0)} / Out ${formatNumber(primitives?.total_output_tokens || 0)}`}
                icon={Coin}
              />
              <StatCard
                label="Budget Utilization"
                value={
                  primitives?.daily_limit_usd
                    ? `${utilization.toFixed(1)}%`
                    : "No limit"
                }
                subtitle={
                  primitives?.daily_limit_usd
                    ? `${formatCurrency(primitives?.daily_limit_usd || 0)} daily limit`
                    : "Set daily_limit_usd in config"
                }
                icon={Target}
                tone={utilization >= 90 ? "error" : utilization >= 75 ? "warning" : "success"}
              />
              <StatCard
                label="Providers Active"
                value={formatNumber(primitives?.provider_breakdown.length || 0)}
                subtitle={`${formatNumber(primitives?.total_responses || 0)} responses captured`}
                icon={ChartPie}
              />
            </>
          )}
        </div>

        {primitives?.daily_limit_usd ? (
          <Card>
            <CardContent className="p-3.5">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-muted-foreground uppercase tracking-[0.08em]">Daily budget usage</span>
                <span
                  className={cn(
                    "text-xs font-semibold tabular-nums",
                    utilization >= 90
                      ? "text-destructive"
                      : utilization >= 75
                        ? "text-warning"
                        : "text-success"
                  )}
                >
                  {utilization.toFixed(1)}%
                </span>
              </div>
              <Progress value={Math.min(utilization, 100)} className="h-1.5" indicatorClassName={cn(
                utilization >= 90
                  ? "bg-destructive"
                  : utilization >= 75
                    ? "bg-warning"
                    : "bg-success"
              )} />
            </CardContent>
          </Card>
        ) : null}

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 md:gap-5">
          <Card className="xl:col-span-2">
            <CardHeader>
              <CardTitle className="text-sm font-semibold tracking-[0.02em]">
                <TrendUp className="h-3.5 w-3.5 text-accent" weight="duotone" />
                Spend Trend (recent)
              </CardTitle>
            </CardHeader>
            <CardContent>
              {trend.length === 0 ? (
                <div className="py-8 text-xs text-muted-foreground text-center">
                  No recent request-cost points available yet.
                </div>
              ) : (
                <>
                  <div className="h-32 flex items-end gap-1">
                    {trend.map((point) => {
                      const height = Math.max(4, (point.cost / maxTrendCost) * 100);
                      return (
                        <div key={`${point.label}-${point.cost}`} className="flex-1 min-w-0 group">
                          <div
                            className="w-full rounded-sm bg-accent/80 group-hover:bg-accent transition-colors"
                            style={{ height: `${height}%` }}
                            title={`${point.label} - ${formatCurrency(point.cost)}`}
                          />
                        </div>
                      );
                    })}
                  </div>
                  <div className="mt-2 flex items-center justify-between text-[10px] text-muted-foreground font-mono">
                    <span>{trend[0]?.label}</span>
                    <span>{trend[trend.length - 1]?.label}</span>
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-semibold tracking-[0.02em]">
                <Lightning className="h-3.5 w-3.5 text-warning" weight="duotone" />
                Cost Drivers
              </CardTitle>
            </CardHeader>
            <CardContent>
              {!primitives?.provider_breakdown?.length ? (
                <div className="py-8 text-xs text-muted-foreground text-center">
                  No provider cost data yet.
                </div>
              ) : (
                <div className="space-y-2.5">
                  {primitives.provider_breakdown.slice(0, 6).map((provider) => {
                    const share =
                      primitives.total_cost_usd > 0
                        ? (provider.total_cost_usd / primitives.total_cost_usd) * 100
                        : 0;
                    return (
                      <div key={provider.provider}>
                        <div className="flex items-center justify-between text-xs mb-1">
                          <span className="font-medium capitalize truncate">{provider.provider}</span>
                          <span className="font-mono tabular-nums">{formatCurrency(provider.total_cost_usd)}</span>
                        </div>
                        <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                          <span>{provider.request_count} req</span>
                          <span>{share.toFixed(1)}%</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-semibold tracking-[0.02em]">
              <Info className="h-3.5 w-3.5 text-accent" weight="duotone" />
              Alerts & Anomalies
            </CardTitle>
          </CardHeader>
          <CardContent>
            {anomalies.length === 0 ? (
              <div className="flex items-center gap-2 text-xs text-success">
                <CheckCircle className="h-3.5 w-3.5" weight="fill" />
                <span>No active budget anomalies detected.</span>
              </div>
            ) : (
              <div className="space-y-2">
                {anomalies.map((anomaly, index) => (
                  <div
                    key={`${anomaly.title}-${index}`}
                    className={cn(
                      "rounded-md border px-3 py-2",
                      anomaly.level === "error" && "bg-destructive/10 border-destructive/25",
                      anomaly.level === "warning" && "bg-warning/10 border-warning/25",
                      anomaly.level === "info" && "bg-accent/10 border-accent/25"
                    )}
                  >
                    <p className="text-xs font-medium capitalize">{anomaly.title}</p>
                    <p className="text-[11px] text-muted-foreground mt-0.5">{anomaly.description}</p>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-semibold tracking-[0.02em]">
              <Funnel className="h-3.5 w-3.5 text-accent" weight="duotone" />
              Breakdown
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="inline-flex items-center gap-1 p-1 rounded-lg border border-border bg-muted/40">
              {([
                ["provider", "Provider"],
                ["model", "Model"],
                ["endpoint", "Endpoint"],
              ] as const).map(([id, label]) => (
                <button
                  key={id}
                  onClick={() => setBreakdown(id)}
                  className={cn(
                    "px-2.5 py-1.5 rounded-md text-[11px] uppercase tracking-[0.08em] font-medium transition-colors",
                    breakdown === id
                      ? "bg-background text-foreground border border-border"
                      : "text-muted-foreground hover:text-foreground"
                  )}
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="rounded-lg border border-border overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead className="bg-muted/40 text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                    <tr>
                      <th className="text-left px-3 py-2">{breakdown}</th>
                      <th className="text-right px-3 py-2">Req</th>
                      <th className="text-right px-3 py-2">In / Out</th>
                      <th className="text-right px-3 py-2">Avg Cost</th>
                      <th className="text-right px-3 py-2">Total Cost</th>
                      <th className="text-right px-3 py-2">Avg Lat</th>
                    </tr>
                  </thead>
                  <tbody>
                    {isLoading ? (
                      <tr>
                        <td colSpan={6} className="px-3 py-4">
                          <Skeleton className="h-6 w-full" />
                        </td>
                      </tr>
                    ) : breakdownRows.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="px-3 py-6 text-center text-xs text-muted-foreground">
                          No rows available for this breakdown.
                        </td>
                      </tr>
                    ) : (
                      breakdownRows.map((row) => (
                        <tr key={row.key} className="border-t border-border/50">
                          <td className="px-3 py-1.5 font-mono text-[11px] truncate max-w-[380px]" title={row.key}>
                            {row.key}
                          </td>
                          <td className="px-3 py-1.5 text-right font-mono tabular-nums">{formatNumber(row.requests)}</td>
                          <td className="px-3 py-1.5 text-right font-mono tabular-nums">
                            {formatNumber(row.inputTokens)} / {formatNumber(row.outputTokens)}
                          </td>
                          <td className="px-3 py-1.5 text-right font-mono tabular-nums">{formatCurrency(row.avgCost)}</td>
                          <td className="px-3 py-1.5 text-right font-mono tabular-nums">{formatCurrency(row.totalCost)}</td>
                          <td className="px-3 py-1.5 text-right font-mono tabular-nums text-muted-foreground">
                            {row.avgLatencyMs === null ? "-" : `${Math.round(row.avgLatencyMs)}ms`}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-semibold tracking-[0.02em]">
              <Target className="h-3.5 w-3.5 text-success" weight="duotone" />
              Optimization Opportunities
            </CardTitle>
          </CardHeader>
          <CardContent>
            {recommendations.length === 0 ? (
              <p className="text-xs text-muted-foreground">
                Recommendations will appear after more traffic and model/tool diversity is observed.
              </p>
            ) : (
              <div className="space-y-2">
                {recommendations.map((recommendation, idx) => (
                  <div key={`${recommendation.title}-${idx}`} className="rounded-md border border-border px-3 py-2">
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-xs font-medium">{recommendation.title}</p>
                      <span
                        className={cn(
                          "text-[10px] uppercase tracking-[0.08em] px-2 py-0.5 rounded",
                          recommendation.effort === "low" && "bg-success/15 text-success",
                          recommendation.effort === "medium" && "bg-warning/15 text-warning",
                          recommendation.effort === "high" && "bg-destructive/15 text-destructive"
                        )}
                      >
                        {recommendation.effort}
                      </span>
                    </div>
                    <p className="text-[11px] text-muted-foreground mt-1">{recommendation.description}</p>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
