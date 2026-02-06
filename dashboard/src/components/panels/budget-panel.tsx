"use client";

import { CurrencyDollar, Coin, Warning, Info, XCircle } from "@phosphor-icons/react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { cn, formatNumber, formatCurrency } from "@/lib/utils";
import type { BudgetMetrics } from "@/types";

interface MetricRowProps {
  label: string;
  value: string | number;
  valueClassName?: string;
}

function MetricRow({ label, value, valueClassName }: MetricRowProps) {
  return (
    <div className="flex items-center justify-between py-2.5 border-b border-border last:border-0">
      <span className="text-muted-foreground text-sm">{label}</span>
      <span className={cn("font-semibold tabular-nums", valueClassName)}>
        {value}
      </span>
    </div>
  );
}

interface BudgetPanelProps {
  data: BudgetMetrics | undefined;
  isLoading: boolean;
}

export function BudgetPanel({ data, isLoading }: BudgetPanelProps) {
  if (isLoading) {
    return (
      <Card className="animate-fade-in">
        <CardHeader>
          <CardTitle>
            <CurrencyDollar className="h-4 w-4 text-accent" weight="duotone" />
            Budget
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {[...Array(4)].map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!data) return null;

  const usagePercent = data.daily_limit_usd
    ? (data.total_cost_usd / data.daily_limit_usd) * 100
    : 0;

  // Sort models by cost
  const modelCosts = Object.entries(data.cost_by_model)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5);

  return (
    <Card className="animate-slide-up stagger-4">
      <CardHeader>
        <CardTitle>
          <CurrencyDollar className="h-4 w-4 text-accent" weight="duotone" />
          Budget
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-0">
          <MetricRow
            label="Total Tokens"
            value={formatNumber(data.total_tokens)}
          />
          <MetricRow
            label="Total Cost"
            value={formatCurrency(data.total_cost_usd)}
            valueClassName="text-accent"
          />
          {data.daily_limit_usd && (
            <MetricRow
              label="Daily Limit"
              value={formatCurrency(data.daily_limit_usd)}
            />
          )}
        </div>

        {/* Usage progress */}
        {data.daily_limit_usd && (
          <div className="mt-4 pt-4 border-t border-border">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-muted-foreground">Daily Usage</span>
              <span className={cn(
                "font-semibold tabular-nums",
                usagePercent >= 90 ? "text-destructive" :
                usagePercent >= 70 ? "text-warning" : "text-success"
              )}>
                {usagePercent.toFixed(1)}%
              </span>
            </div>
            <Progress
              value={Math.min(usagePercent, 100)}
              className="h-2"
              indicatorClassName={cn(
                usagePercent >= 90 ? "bg-destructive" :
                usagePercent >= 70 ? "bg-warning" : "bg-success"
              )}
            />
          </div>
        )}

        {/* Cost by model */}
        {modelCosts.length > 0 && (
          <div className="mt-4 pt-4 border-t border-border">
            <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">
              Cost by Model
            </h4>
            <div className="space-y-1.5">
              {modelCosts.map(([model, cost]) => (
                <div
                  key={model}
                  className="flex items-center justify-between text-sm"
                >
                  <span className="text-muted-foreground font-mono text-xs truncate max-w-[60%]">
                    {model}
                  </span>
                  <span className="font-medium tabular-nums">
                    {formatCurrency(cost)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Alerts */}
        {data.alerts.length > 0 && (
          <div className="mt-4 space-y-2">
            {data.alerts.map((alert, i) => (
              <div
                key={i}
                className={cn(
                  "flex items-start gap-2 text-xs rounded px-3 py-2",
                  alert.level === "error" && "bg-destructive/10 border border-destructive/20 text-destructive",
                  alert.level === "warning" && "bg-warning/10 border border-warning/20 text-warning",
                  alert.level === "info" && "bg-accent/10 border border-accent/20 text-accent"
                )}
              >
                {alert.level === "error" && <XCircle className="h-3.5 w-3.5 shrink-0 mt-0.5" weight="fill" />}
                {alert.level === "warning" && <Warning className="h-3.5 w-3.5 shrink-0 mt-0.5" weight="fill" />}
                {alert.level === "info" && <Info className="h-3.5 w-3.5 shrink-0 mt-0.5" weight="fill" />}
                <span>{alert.message}</span>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
