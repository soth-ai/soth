"use client";

import {
  TrendUp,
  TrendDown,
  CurrencyDollar,
  ChartLineUp,
  Warning,
  ShieldWarning,
  Users,
  CalendarBlank,
  ArrowUp,
  ArrowDown,
  Minus,
  Info,
  Lightning,
  Target,
} from "@phosphor-icons/react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, formatNumber, formatCurrency } from "@/lib/utils";
import type { AdvancedBudgetMetrics, DailyTrendPoint, CostAnomalyEntry } from "@/types";

interface CFOViewProps {
  metrics: AdvancedBudgetMetrics | undefined;
  isLoading: boolean;
}

export function CFOView({ metrics, isLoading }: CFOViewProps) {
  if (isLoading) {
    return <CFOViewSkeleton />;
  }

  if (!metrics) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <div className="h-16 w-16 rounded-2xl bg-muted/50 flex items-center justify-center mb-4">
          <ChartLineUp className="h-8 w-8 text-muted-foreground" weight="duotone" />
        </div>
        <h3 className="text-lg font-semibold mb-1">No Analytics Data</h3>
        <p className="text-sm text-muted-foreground max-w-sm">
          Cost analytics will appear once there is sufficient usage data.
        </p>
      </div>
    );
  }

  // Calculate trend metrics
  const dailyTrend = metrics.daily_trend || [];
  const todayCost = dailyTrend.length > 0 ? dailyTrend[dailyTrend.length - 1]?.cost || 0 : 0;
  const yesterdayCost = dailyTrend.length > 1 ? dailyTrend[dailyTrend.length - 2]?.cost || 0 : 0;
  const weekAgoCost = dailyTrend.length > 7 ? dailyTrend[dailyTrend.length - 8]?.cost || 0 : 0;

  const dailyChange = yesterdayCost > 0 ? ((todayCost - yesterdayCost) / yesterdayCost) * 100 : 0;
  const weeklyChange = weekAgoCost > 0 ? ((todayCost - weekAgoCost) / weekAgoCost) * 100 : 0;

  const weekTotal = dailyTrend.slice(-7).reduce((sum, d) => sum + d.cost, 0);
  const monthTotal = dailyTrend.slice(-30).reduce((sum, d) => sum + d.cost, 0);

  const budgetUtilization = metrics.daily_limit_usd
    ? (todayCost / metrics.daily_limit_usd) * 100
    : null;

  return (
    <div className="space-y-6">
      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <KPICard
          label="Today's Spend"
          value={formatCurrency(todayCost)}
          change={dailyChange}
          changeLabel="vs yesterday"
          icon={CurrencyDollar}
        />
        <KPICard
          label="7-Day Total"
          value={formatCurrency(weekTotal)}
          change={weeklyChange}
          changeLabel="vs last week"
          icon={CalendarBlank}
        />
        <KPICard
          label="30-Day Total"
          value={formatCurrency(monthTotal)}
          icon={ChartLineUp}
          trend={`${formatNumber(metrics.total_tokens)} tokens`}
        />
        {budgetUtilization !== null ? (
          <KPICard
            label="Budget Utilization"
            value={`${budgetUtilization.toFixed(1)}%`}
            icon={Target}
            status={budgetUtilization >= 90 ? "critical" : budgetUtilization >= 70 ? "warning" : "success"}
            trend={`${formatCurrency(metrics.daily_limit_usd! - todayCost)} remaining`}
          />
        ) : (
          <KPICard
            label="Avg Cost/Request"
            value={formatCurrency(metrics.total_cost_usd / Math.max(1, Object.values(metrics.cost_by_provider).reduce((sum, p) => sum + p.request_count, 0)))}
            icon={Lightning}
          />
        )}
      </div>

      {/* Anomalies Alert Banner */}
      {metrics.anomalies.length > 0 && (
        <AnomaliesAlert anomalies={metrics.anomalies} />
      )}

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Trend Chart */}
        <div className="xl:col-span-2">
          <TrendChart data={dailyTrend} />
        </div>

        {/* Team/Project Allocation */}
        <div className="xl:col-span-1">
          <TeamAllocationCard costByTag={metrics.cost_by_tag} totalCost={monthTotal} />
        </div>
      </div>

      {/* Detailed Anomalies */}
      {metrics.anomalies.length > 0 && (
        <AnomaliesDetailCard anomalies={metrics.anomalies} />
      )}

      {/* Provider Summary Table */}
      <ProviderSummaryTable providers={metrics.cost_by_provider} />
    </div>
  );
}

function CFOViewSkeleton() {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        {[...Array(4)].map((_, i) => (
          <Card key={i}>
            <CardContent className="p-4">
              <Skeleton className="h-20 w-full" />
            </CardContent>
          </Card>
        ))}
      </div>
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <Card className="xl:col-span-2">
          <CardContent className="p-6">
            <Skeleton className="h-64 w-full" />
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-6">
            <Skeleton className="h-64 w-full" />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

interface KPICardProps {
  label: string;
  value: string;
  change?: number;
  changeLabel?: string;
  icon: React.ElementType;
  trend?: string;
  status?: "success" | "warning" | "critical";
}

function KPICard({ label, value, change, changeLabel, icon: Icon, trend, status }: KPICardProps) {
  const statusColors = {
    success: "text-success",
    warning: "text-warning",
    critical: "text-destructive",
  };

  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-start justify-between mb-2">
          <span className="text-sm text-muted-foreground">{label}</span>
          <div className={cn(
            "p-2 rounded-lg",
            status ? `${statusColors[status]}/10` : "bg-accent/10"
          )}>
            <Icon className={cn("h-4 w-4", status ? statusColors[status] : "text-accent")} weight="duotone" />
          </div>
        </div>
        <p className={cn("text-2xl font-bold tabular-nums", status && statusColors[status])}>
          {value}
        </p>
        {change !== undefined && (
          <div className="flex items-center gap-1 mt-1">
            {change > 0 ? (
              <ArrowUp className="h-3 w-3 text-destructive" weight="bold" />
            ) : change < 0 ? (
              <ArrowDown className="h-3 w-3 text-success" weight="bold" />
            ) : (
              <Minus className="h-3 w-3 text-muted-foreground" weight="bold" />
            )}
            <span className={cn(
              "text-xs font-medium",
              change > 0 ? "text-destructive" : change < 0 ? "text-success" : "text-muted-foreground"
            )}>
              {Math.abs(change).toFixed(1)}%
            </span>
            {changeLabel && (
              <span className="text-xs text-muted-foreground">{changeLabel}</span>
            )}
          </div>
        )}
        {trend && (
          <p className="text-xs text-muted-foreground mt-1">{trend}</p>
        )}
      </CardContent>
    </Card>
  );
}

interface AnomaliesAlertProps {
  anomalies: CostAnomalyEntry[];
}

function AnomaliesAlert({ anomalies }: AnomaliesAlertProps) {
  const criticalCount = anomalies.filter(a => a.severity === "critical").length;
  const warningCount = anomalies.filter(a => a.severity === "warning").length;

  if (criticalCount === 0 && warningCount === 0) return null;

  return (
    <div className={cn(
      "flex items-center gap-4 p-4 rounded-lg border",
      criticalCount > 0
        ? "bg-destructive/10 border-destructive/20"
        : "bg-warning/10 border-warning/20"
    )}>
      <ShieldWarning
        className={cn(
          "h-6 w-6 shrink-0",
          criticalCount > 0 ? "text-destructive" : "text-warning"
        )}
        weight="fill"
      />
      <div className="flex-1">
        <h4 className={cn(
          "font-semibold text-sm",
          criticalCount > 0 ? "text-destructive" : "text-warning"
        )}>
          {criticalCount > 0 ? "Critical Cost Anomalies Detected" : "Cost Anomalies Detected"}
        </h4>
        <p className="text-sm text-muted-foreground">
          {criticalCount > 0 && `${criticalCount} critical`}
          {criticalCount > 0 && warningCount > 0 && ", "}
          {warningCount > 0 && `${warningCount} warning`}
          {" "}anomal{(criticalCount + warningCount) === 1 ? "y" : "ies"} require attention
        </p>
      </div>
    </div>
  );
}

interface TrendChartProps {
  data: DailyTrendPoint[];
}

function TrendChart({ data }: TrendChartProps) {
  const maxCost = Math.max(...data.map(d => d.cost), 1);
  const minCost = Math.min(...data.map(d => d.cost));
  const range = maxCost - minCost || 1;

  // Show last 14 days for better visualization
  const displayData = data.slice(-14);

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <ChartLineUp className="h-4 w-4 text-accent" weight="duotone" />
          Daily Cost Trend
        </CardTitle>
      </CardHeader>
      <CardContent>
        {displayData.length < 2 ? (
          <div className="flex flex-col items-center justify-center py-12 text-center">
            <div className="h-12 w-12 rounded-xl bg-muted/50 flex items-center justify-center mb-3">
              <ChartLineUp className="h-6 w-6 text-muted-foreground" weight="duotone" />
            </div>
            <p className="text-sm text-muted-foreground">
              Need more data to show trend chart
            </p>
          </div>
        ) : (
          <>
            {/* Simple bar chart */}
            <div className="flex items-end gap-1 h-48">
              {displayData.map((point, idx) => {
                const height = ((point.cost - minCost) / range) * 100;
                const isToday = idx === displayData.length - 1;
                const date = new Date(point.date);

                return (
                  <div
                    key={point.date}
                    className="flex-1 flex flex-col items-center gap-1 group"
                  >
                    <div className="relative w-full flex flex-col items-center">
                      <div
                        className={cn(
                          "w-full rounded-t transition-all",
                          isToday ? "bg-accent" : "bg-accent/40 group-hover:bg-accent/60"
                        )}
                        style={{ height: `${Math.max(height, 4)}%` }}
                      />
                      <div className="absolute -top-6 opacity-0 group-hover:opacity-100 transition-opacity bg-popover border border-border rounded px-2 py-1 text-xs whitespace-nowrap z-10">
                        {formatCurrency(point.cost)}
                      </div>
                    </div>
                    <span className="text-[10px] text-muted-foreground">
                      {date.getDate()}
                    </span>
                  </div>
                );
              })}
            </div>

            {/* Legend */}
            <div className="flex items-center justify-between mt-4 pt-4 border-t border-border text-xs text-muted-foreground">
              <span>
                {new Date(displayData[0]?.date || "").toLocaleDateString("en-US", { month: "short", day: "numeric" })}
              </span>
              <span>Last 14 days</span>
              <span>
                {new Date(displayData[displayData.length - 1]?.date || "").toLocaleDateString("en-US", { month: "short", day: "numeric" })}
              </span>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

interface TeamAllocationCardProps {
  costByTag: Record<string, Record<string, number>>;
  totalCost: number;
}

function TeamAllocationCard({ costByTag, totalCost }: TeamAllocationCardProps) {
  // Get team/project breakdown
  const teams = costByTag.team || {};
  const projects = costByTag.project || {};

  const teamEntries = Object.entries(teams).sort(([, a], [, b]) => b - a);
  const projectEntries = Object.entries(projects).sort(([, a], [, b]) => b - a);
  const maxTeamCost = teamEntries.length > 0 ? teamEntries[0][1] : 0;

  const hasData = teamEntries.length > 0 || projectEntries.length > 0;

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>
          <Users className="h-4 w-4 text-accent" weight="duotone" />
          Cost Allocation
        </CardTitle>
      </CardHeader>
      <CardContent>
        {!hasData ? (
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <div className="h-12 w-12 rounded-xl bg-muted/50 flex items-center justify-center mb-3">
              <Users className="h-6 w-6 text-muted-foreground" weight="duotone" />
            </div>
            <p className="text-sm text-muted-foreground mb-2">No cost tags configured</p>
            <p className="text-xs text-muted-foreground">
              Add team/project tags in config to track allocation
            </p>
          </div>
        ) : (
          <div className="space-y-6">
            {teamEntries.length > 0 && (
              <div>
                <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-3">
                  By Team
                </h4>
                <div className="space-y-2">
                  {teamEntries.slice(0, 5).map(([team, cost]) => {
                    const percentage = totalCost > 0 ? (cost / totalCost) * 100 : 0;
                    const barWidth = maxTeamCost > 0 ? (cost / maxTeamCost) * 100 : 0;

                    return (
                      <div key={team}>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-sm font-medium truncate max-w-[120px]">{team}</span>
                          <div className="flex items-center gap-2">
                            <span className="text-xs text-muted-foreground">{percentage.toFixed(1)}%</span>
                            <span className="text-sm font-bold tabular-nums">{formatCurrency(cost)}</span>
                          </div>
                        </div>
                        <Progress value={barWidth} className="h-1.5" indicatorClassName="bg-violet-500" />
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {projectEntries.length > 0 && (
              <div>
                <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-3">
                  By Project
                </h4>
                <div className="space-y-2">
                  {projectEntries.slice(0, 5).map(([project, cost]) => {
                    const percentage = totalCost > 0 ? (cost / totalCost) * 100 : 0;

                    return (
                      <div key={project} className="flex items-center justify-between">
                        <span className="text-sm truncate max-w-[150px]">{project}</span>
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-muted-foreground">{percentage.toFixed(1)}%</span>
                          <span className="text-sm font-medium tabular-nums">{formatCurrency(cost)}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

interface AnomaliesDetailCardProps {
  anomalies: CostAnomalyEntry[];
}

function AnomaliesDetailCard({ anomalies }: AnomaliesDetailCardProps) {
  const sortedAnomalies = [...anomalies].sort((a, b) => {
    const severityOrder = { critical: 0, warning: 1, info: 2 };
    return severityOrder[a.severity] - severityOrder[b.severity];
  });

  const severityIcons = {
    critical: <ShieldWarning className="h-4 w-4 text-destructive" weight="fill" />,
    warning: <Warning className="h-4 w-4 text-warning" weight="fill" />,
    info: <Info className="h-4 w-4 text-accent" weight="fill" />,
  };

  const severityColors = {
    critical: "border-destructive/30 bg-destructive/5",
    warning: "border-warning/30 bg-warning/5",
    info: "border-accent/30 bg-accent/5",
  };

  const typeLabels: Record<string, string> = {
    cost_spike: "Cost Spike",
    usage_spike: "Usage Spike",
    new_model: "New Model",
    unusual_time: "Unusual Activity",
    budget_approaching: "Budget Alert",
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <Warning className="h-4 w-4 text-warning" weight="duotone" />
          Anomaly Details
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {sortedAnomalies.map((anomaly) => (
            <div
              key={anomaly.id}
              className={cn(
                "p-4 rounded-lg border",
                severityColors[anomaly.severity]
              )}
            >
              <div className="flex items-start gap-3">
                <div className="shrink-0 mt-0.5">
                  {severityIcons[anomaly.severity]}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-semibold text-sm">
                      {typeLabels[anomaly.anomaly_type] || anomaly.anomaly_type}
                    </span>
                    <span className="text-[10px] text-muted-foreground bg-muted px-1.5 py-0.5 rounded">
                      {new Date(anomaly.detected_at).toLocaleTimeString()}
                    </span>
                  </div>
                  <p className="text-sm text-muted-foreground">{anomaly.description}</p>
                  <div className="flex items-center gap-4 mt-2 text-xs">
                    <span className="text-muted-foreground">
                      Expected: <span className="font-medium text-foreground">{formatCurrency(anomaly.expected_value)}</span>
                    </span>
                    <span className="text-muted-foreground">
                      Actual: <span className={cn(
                        "font-medium",
                        anomaly.current_value > anomaly.expected_value ? "text-destructive" : "text-success"
                      )}>
                        {formatCurrency(anomaly.current_value)}
                      </span>
                    </span>
                    <span className={cn(
                      "font-medium",
                      anomaly.current_value > anomaly.expected_value ? "text-destructive" : "text-success"
                    )}>
                      {anomaly.current_value > anomaly.expected_value ? "+" : ""}
                      {(((anomaly.current_value - anomaly.expected_value) / anomaly.expected_value) * 100).toFixed(0)}%
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

interface ProviderSummaryTableProps {
  providers: Record<string, {
    total_cost: number;
    total_tokens: number;
    input_tokens: number;
    output_tokens: number;
    request_count: number;
  }>;
}

function ProviderSummaryTable({ providers }: ProviderSummaryTableProps) {
  const providerEntries = Object.entries(providers).sort(([, a], [, b]) => b.total_cost - a.total_cost);
  const totals = providerEntries.reduce(
    (acc, [, p]) => ({
      cost: acc.cost + p.total_cost,
      tokens: acc.tokens + p.total_tokens,
      input: acc.input + p.input_tokens,
      output: acc.output + p.output_tokens,
      requests: acc.requests + p.request_count,
    }),
    { cost: 0, tokens: 0, input: 0, output: 0, requests: 0 }
  );

  if (providerEntries.length === 0) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <TrendUp className="h-4 w-4 text-accent" weight="duotone" />
          Provider Summary
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-2 font-medium text-muted-foreground">Provider</th>
                <th className="text-right py-3 px-2 font-medium text-muted-foreground">Requests</th>
                <th className="text-right py-3 px-2 font-medium text-muted-foreground">Input Tokens</th>
                <th className="text-right py-3 px-2 font-medium text-muted-foreground">Output Tokens</th>
                <th className="text-right py-3 px-2 font-medium text-muted-foreground">Total Cost</th>
                <th className="text-right py-3 px-2 font-medium text-muted-foreground">Share</th>
              </tr>
            </thead>
            <tbody>
              {providerEntries.map(([provider, data]) => {
                const share = totals.cost > 0 ? (data.total_cost / totals.cost) * 100 : 0;

                return (
                  <tr key={provider} className="border-b border-border/50 hover:bg-muted/30">
                    <td className="py-3 px-2">
                      <span className="font-medium capitalize">{provider}</span>
                    </td>
                    <td className="text-right py-3 px-2 tabular-nums">{formatNumber(data.request_count)}</td>
                    <td className="text-right py-3 px-2 tabular-nums text-cyan-500">{formatNumber(data.input_tokens)}</td>
                    <td className="text-right py-3 px-2 tabular-nums text-emerald-500">{formatNumber(data.output_tokens)}</td>
                    <td className="text-right py-3 px-2 font-bold tabular-nums">{formatCurrency(data.total_cost)}</td>
                    <td className="text-right py-3 px-2">
                      <div className="flex items-center justify-end gap-2">
                        <Progress value={share} className="w-16 h-1.5" />
                        <span className="text-xs text-muted-foreground w-10">{share.toFixed(1)}%</span>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
            <tfoot>
              <tr className="bg-muted/30 font-medium">
                <td className="py-3 px-2">Total</td>
                <td className="text-right py-3 px-2 tabular-nums">{formatNumber(totals.requests)}</td>
                <td className="text-right py-3 px-2 tabular-nums text-cyan-500">{formatNumber(totals.input)}</td>
                <td className="text-right py-3 px-2 tabular-nums text-emerald-500">{formatNumber(totals.output)}</td>
                <td className="text-right py-3 px-2 font-bold tabular-nums">{formatCurrency(totals.cost)}</td>
                <td className="text-right py-3 px-2 text-xs text-muted-foreground">100%</td>
              </tr>
            </tfoot>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}
