"use client";

import { useState } from "react";
import {
  CurrencyDollar,
  Coin,
  Warning,
  Info,
  XCircle,
  TrendUp,
  ChartPie,
  Target,
  Clock,
  WifiSlash,
  CheckCircle,
  Code,
  ChartLineUp,
  CaretDown,
} from "@phosphor-icons/react";
import { useDashboardMetrics, useAdvancedBudgetMetrics } from "@/hooks/useDashboardData";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { cn, formatNumber, formatCurrency } from "@/lib/utils";
import { DeveloperView, CFOView } from "@/components/budget";

type PersonaView = "overview" | "developer" | "cfo";

// Stat card component
function StatCard({
  label,
  value,
  icon: Icon,
  trend,
  color = "default",
}: {
  label: string;
  value: string | number;
  icon: React.ElementType;
  trend?: string;
  color?: "default" | "success" | "destructive" | "warning";
}) {
  const colorClasses = {
    default: "bg-accent/10 text-accent",
    success: "bg-success/10 text-success",
    destructive: "bg-destructive/10 text-destructive",
    warning: "bg-warning/10 text-warning",
  };

  return (
    <Card>
      <CardContent className="p-6">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-sm text-muted-foreground font-medium">{label}</p>
            <p className="text-3xl font-bold mt-1 tabular-nums">{value}</p>
            {trend && (
              <p className="text-xs text-muted-foreground mt-1">{trend}</p>
            )}
          </div>
          <div className={cn("p-3 rounded-xl", colorClasses[color])}>
            <Icon className="h-6 w-6" weight="duotone" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default function BudgetPage() {
  const [activeView, setActiveView] = useState<PersonaView>("overview");
  const { isLoading, isConnected, budget, proxy } = useDashboardMetrics();
  const { data: advancedData, isLoading: advancedLoading } = useAdvancedBudgetMetrics();

  const advancedMetrics = advancedData?.data;

  // Combine budget and proxy cost data
  const totalCost = (budget?.total_cost_usd ?? 0) + (proxy?.total_cost_usd ?? 0);
  const totalTokens = (budget?.total_tokens ?? 0) + (proxy?.total_tokens ?? 0);

  const usagePercent = budget?.daily_limit_usd
    ? (totalCost / budget.daily_limit_usd) * 100
    : 0;

  // Combine cost by model from both sources
  const costByModel = { ...budget?.cost_by_model };
  if (proxy?.cost_by_provider) {
    Object.entries(proxy.cost_by_provider).forEach(([provider, cost]) => {
      costByModel[provider] = (costByModel[provider] ?? 0) + cost;
    });
  }

  // Sort models by cost
  const modelCosts = Object.entries(costByModel)
    .sort(([, a], [, b]) => b - a);

  const topModelCost = modelCosts.length > 0 ? modelCosts[0][1] : 0;

  const viewOptions: { id: PersonaView; label: string; icon: React.ElementType; description: string }[] = [
    { id: "overview", label: "Overview", icon: CurrencyDollar, description: "Summary view" },
    { id: "developer", label: "Developer", icon: Code, description: "Cost optimization" },
    { id: "cfo", label: "CFO/CISO", icon: ChartLineUp, description: "Trends & compliance" },
  ];

  return (
    <div className="min-h-screen">
      {/* Page Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 md:top-14 z-10">
        <div className="px-4 md:px-6 py-3 md:py-4 flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 md:gap-3">
            <div className="h-7 w-7 md:h-8 md:w-8 rounded-lg bg-accent/10 flex items-center justify-center">
              <CurrencyDollar className="h-4 w-4 md:h-5 md:w-5 text-accent" weight="duotone" />
            </div>
            <div>
              <h1 className="text-base md:text-lg font-semibold">Budget</h1>
              <p className="text-[10px] md:text-xs text-muted-foreground hidden sm:block">
                Cost tracking & usage limits
              </p>
            </div>
          </div>

          {/* Persona Toggle */}
          <div className="flex items-center gap-0.5 md:gap-1 p-0.5 md:p-1 bg-muted/50 rounded-lg">
            {viewOptions.map((option) => {
              const Icon = option.icon;
              const isActive = activeView === option.id;

              return (
                <button
                  key={option.id}
                  onClick={() => setActiveView(option.id)}
                  className={cn(
                    "flex items-center gap-1.5 md:gap-2 px-2 md:px-3 py-1.5 rounded-md text-xs md:text-sm font-medium transition-all",
                    isActive
                      ? "bg-background text-foreground shadow-sm"
                      : "text-muted-foreground hover:text-foreground hover:bg-muted"
                  )}
                  title={option.description}
                >
                  <Icon className="h-4 w-4" weight={isActive ? "duotone" : "regular"} />
                  <span className="hidden sm:inline">{option.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      </header>

      <div className="px-4 md:px-6 py-4 md:py-6">
        {!isConnected && !isLoading && (
          <div className="mb-6 p-4 rounded-lg bg-destructive/10 border border-destructive/20">
            <div className="flex items-center gap-2 text-sm text-destructive">
              <WifiSlash className="h-4 w-4" weight="bold" />
              <span>
                Unable to connect to SOTH backend. Make sure the proxy is running.
              </span>
            </div>
          </div>
        )}

        {/* Render active view */}
        {activeView === "developer" ? (
          <DeveloperView metrics={advancedMetrics} isLoading={advancedLoading} />
        ) : activeView === "cfo" ? (
          <CFOView metrics={advancedMetrics} isLoading={advancedLoading} />
        ) : (
          /* Overview (default) view */
          <>
            {/* Stats Grid */}
            <div className="grid grid-cols-2 md:grid-cols-2 xl:grid-cols-4 gap-3 md:gap-6 mb-4 md:mb-6">
              {isLoading ? (
                <>
                  {[...Array(4)].map((_, i) => (
                    <Card key={i}>
                      <CardContent className="p-6">
                        <Skeleton className="h-20 w-full" />
                      </CardContent>
                    </Card>
                  ))}
                </>
              ) : (
                <>
                  <StatCard
                    label="Total Cost"
                    value={formatCurrency(totalCost)}
                    icon={CurrencyDollar}
                    color="default"
                  />
                  <StatCard
                    label="Total Tokens"
                    value={formatNumber(totalTokens)}
                    icon={Coin}
                    trend={`${((totalTokens / 1000000) || 0).toFixed(2)}M tokens`}
                    color="default"
                  />
                  <StatCard
                    label="Daily Limit"
                    value={budget?.daily_limit_usd ? formatCurrency(budget.daily_limit_usd) : "No limit"}
                    icon={Target}
                    trend={budget?.daily_limit_usd ? `${usagePercent.toFixed(1)}% used` : undefined}
                    color={usagePercent >= 90 ? "destructive" : usagePercent >= 70 ? "warning" : "success"}
                  />
                  <StatCard
                    label="Models Used"
                    value={modelCosts.length}
                    icon={ChartPie}
                    color="default"
                  />
                </>
              )}
            </div>

            {/* Alerts */}
            {(budget?.alerts?.length ?? 0) > 0 && (
              <div className="mb-6 space-y-3">
                {budget?.alerts.map((alert, i) => (
                  <div
                    key={i}
                    className={cn(
                      "flex items-start gap-3 p-4 rounded-lg",
                      alert.level === "error" && "bg-destructive/10 border border-destructive/20",
                      alert.level === "warning" && "bg-warning/10 border border-warning/20",
                      alert.level === "info" && "bg-accent/10 border border-accent/20"
                    )}
                  >
                    {alert.level === "error" && <XCircle className="h-5 w-5 text-destructive shrink-0" weight="fill" />}
                    {alert.level === "warning" && <Warning className="h-5 w-5 text-warning shrink-0" weight="fill" />}
                    {alert.level === "info" && <Info className="h-5 w-5 text-accent shrink-0" weight="fill" />}
                    <div>
                      <p className={cn(
                        "font-medium text-sm",
                        alert.level === "error" && "text-destructive",
                        alert.level === "warning" && "text-warning",
                        alert.level === "info" && "text-accent"
                      )}>
                        {alert.level === "error" && "Budget Alert"}
                        {alert.level === "warning" && "Budget Warning"}
                        {alert.level === "info" && "Budget Info"}
                      </p>
                      <p className="text-sm text-muted-foreground mt-0.5">{alert.message}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Main Content Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 md:gap-6">
              {/* Daily Usage */}
              {budget?.daily_limit_usd && (
                <Card className="xl:col-span-1">
                  <CardHeader>
                    <CardTitle>
                      <Target className="h-4 w-4 text-accent" weight="duotone" />
                      Daily Budget
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {isLoading ? (
                      <Skeleton className="h-32 w-full" />
                    ) : (
                      <>
                        <div className="text-center mb-6">
                          <p className="text-4xl font-bold tabular-nums">
                            {formatCurrency(totalCost)}
                          </p>
                          <p className="text-sm text-muted-foreground mt-1">
                            of {formatCurrency(budget.daily_limit_usd)} daily limit
                          </p>
                        </div>

                        <div className="mb-4">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-sm text-muted-foreground">Usage</span>
                            <span className={cn(
                              "text-lg font-bold tabular-nums",
                              usagePercent >= 90 ? "text-destructive" :
                              usagePercent >= 70 ? "text-warning" : "text-success"
                            )}>
                              {usagePercent.toFixed(1)}%
                            </span>
                          </div>
                          <Progress
                            value={Math.min(usagePercent, 100)}
                            className="h-4"
                            indicatorClassName={cn(
                              usagePercent >= 90 ? "bg-destructive" :
                              usagePercent >= 70 ? "bg-warning" : "bg-success"
                            )}
                          />
                        </div>

                        <div className="grid grid-cols-2 gap-4 mt-6">
                          <div className="p-3 bg-muted/30 rounded-lg text-center">
                            <p className="text-xl font-bold tabular-nums">
                              {formatCurrency(budget.daily_limit_usd - totalCost)}
                            </p>
                            <p className="text-xs text-muted-foreground">Remaining</p>
                          </div>
                          <div className="p-3 bg-muted/30 rounded-lg text-center">
                            <p className="text-xl font-bold tabular-nums">
                              {formatCurrency(totalCost / 24)}
                            </p>
                            <p className="text-xs text-muted-foreground">Avg/Hour</p>
                          </div>
                        </div>
                      </>
                    )}
                  </CardContent>
                </Card>
              )}

              {/* Cost by Model */}
              <Card className={budget?.daily_limit_usd ? "lg:col-span-2" : "lg:col-span-3"}>
                <CardHeader>
                  <CardTitle>
                    <ChartPie className="h-4 w-4 text-accent" weight="duotone" />
                    Cost by Model / Provider
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {isLoading ? (
                    <div className="space-y-3">
                      {[...Array(5)].map((_, i) => (
                        <Skeleton key={i} className="h-12 w-full" />
                      ))}
                    </div>
                  ) : modelCosts.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-12 text-center">
                      <div className="h-16 w-16 rounded-2xl bg-muted/50 flex items-center justify-center mb-4">
                        <Coin className="h-8 w-8 text-muted-foreground" weight="duotone" />
                      </div>
                      <h3 className="text-lg font-semibold mb-1">No Cost Data</h3>
                      <p className="text-sm text-muted-foreground max-w-sm">
                        Start making AI API requests to see cost breakdown by model.
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {modelCosts.map(([model, cost], index) => {
                        const percentage = topModelCost > 0 ? (cost / topModelCost) * 100 : 0;
                        const totalPercentage = totalCost > 0 ? (cost / totalCost) * 100 : 0;

                        return (
                          <div key={model} className="group">
                            <div className="flex items-center justify-between mb-1.5">
                              <div className="flex items-center gap-2">
                                <span className={cn(
                                  "w-6 h-6 rounded-lg flex items-center justify-center text-xs font-bold",
                                  index === 0 ? "bg-accent text-accent-foreground" : "bg-muted text-muted-foreground"
                                )}>
                                  {index + 1}
                                </span>
                                <span className="font-mono text-sm font-medium truncate max-w-[200px]">
                                  {model}
                                </span>
                              </div>
                              <div className="flex items-center gap-3">
                                <span className="text-xs text-muted-foreground tabular-nums">
                                  {totalPercentage.toFixed(1)}%
                                </span>
                                <span className="font-bold tabular-nums min-w-[80px] text-right">
                                  {formatCurrency(cost)}
                                </span>
                              </div>
                            </div>
                            <Progress
                              value={percentage}
                              className="h-2"
                              indicatorClassName={cn(
                                index === 0 ? "bg-accent" :
                                index === 1 ? "bg-accent/80" :
                                index === 2 ? "bg-accent/60" : "bg-accent/40"
                              )}
                            />
                          </div>
                        );
                      })}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* Token Usage by Provider */}
            {proxy?.tokens_by_provider && Object.keys(proxy.tokens_by_provider).length > 0 && (
              <div className="mt-6">
                <Card>
                  <CardHeader>
                    <CardTitle>
                      <Coin className="h-4 w-4 text-accent" weight="duotone" />
                      Token Usage by Provider
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                      {Object.entries(proxy.tokens_by_provider).map(([provider, tokens]) => (
                        <div
                          key={provider}
                          className="p-4 bg-muted/30 border border-border rounded-lg"
                        >
                          <div className="flex items-center justify-between mb-3">
                            <span className="font-semibold capitalize">{provider}</span>
                            <span className="text-xs text-muted-foreground bg-muted px-2 py-0.5 rounded">
                              {formatNumber(tokens.input_tokens + tokens.output_tokens)} total
                            </span>
                          </div>
                          <div className="grid grid-cols-2 gap-3">
                            <div className="text-center p-2 bg-cyan-500/10 border border-cyan-500/20 rounded">
                              <p className="text-lg font-bold text-cyan-500 tabular-nums">
                                {formatNumber(tokens.input_tokens)}
                              </p>
                              <p className="text-[10px] text-muted-foreground uppercase">Input</p>
                            </div>
                            <div className="text-center p-2 bg-emerald-500/10 border border-emerald-500/20 rounded">
                              <p className="text-lg font-bold text-emerald-500 tabular-nums">
                                {formatNumber(tokens.output_tokens)}
                              </p>
                              <p className="text-[10px] text-muted-foreground uppercase">Output</p>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </div>
            )}

            {/* Budget Info */}
            <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>
                    <TrendUp className="h-4 w-4 text-accent" weight="duotone" />
                    Cost Tracking
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="p-4 bg-muted/30 rounded-lg">
                      <h4 className="text-sm font-medium mb-2">Real-time Cost Monitoring</h4>
                      <p className="text-xs text-muted-foreground">
                        SOTH tracks token usage and costs for all AI API requests passing through the proxy.
                        Costs are calculated based on each provider&apos;s pricing model.
                      </p>
                    </div>
                    <div className="flex items-center gap-2 text-sm">
                      <CheckCircle className="h-4 w-4 text-success" weight="fill" />
                      <span>Per-request cost tracking</span>
                    </div>
                    <div className="flex items-center gap-2 text-sm">
                      <CheckCircle className="h-4 w-4 text-success" weight="fill" />
                      <span>Input/output token breakdown</span>
                    </div>
                    <div className="flex items-center gap-2 text-sm">
                      <CheckCircle className="h-4 w-4 text-success" weight="fill" />
                      <span>Multi-provider aggregation</span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>
                    <Clock className="h-4 w-4 text-warning" weight="duotone" />
                    Budget Controls
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="p-4 bg-muted/30 rounded-lg">
                      <h4 className="text-sm font-medium mb-2">Daily Limits</h4>
                      <p className="text-xs text-muted-foreground">
                        Set daily spending limits in your SOTH configuration to prevent unexpected costs.
                        Alerts are triggered when usage approaches the limit.
                      </p>
                    </div>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-muted-foreground">Limit Status</span>
                        <span className={cn(
                          "font-medium",
                          budget?.daily_limit_usd ? "text-success" : "text-warning"
                        )}>
                          {budget?.daily_limit_usd ? "Configured" : "Not Set"}
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-muted-foreground">Alert Threshold</span>
                        <span className="font-medium">80% / 90%</span>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
