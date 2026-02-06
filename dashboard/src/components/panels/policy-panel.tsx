"use client";

import { Shield, CheckCircle, XCircle, Lightning } from "@phosphor-icons/react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { cn, formatNumber } from "@/lib/utils";
import type { PolicyMetrics } from "@/types";

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

interface PolicyPanelProps {
  data: PolicyMetrics | undefined;
  isLoading: boolean;
}

export function PolicyPanel({ data, isLoading }: PolicyPanelProps) {
  if (isLoading) {
    return (
      <Card className="animate-fade-in">
        <CardHeader>
          <CardTitle>
            <Shield className="h-4 w-4 text-accent" weight="duotone" />
            Policy
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

  const total = data.cache_hits + data.cache_misses;
  const cacheHitRate = total > 0 ? (data.cache_hits / total) * 100 : 0;

  return (
    <Card className="animate-slide-up stagger-2">
      <CardHeader>
        <CardTitle>
          <Shield className="h-4 w-4 text-accent" weight="duotone" />
          Policy
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-0">
          <MetricRow
            label="Total Evaluations"
            value={formatNumber(data.evaluations)}
          />
          <MetricRow
            label="Allowed"
            value={formatNumber(data.allowed)}
            valueClassName="text-success"
          />
          <MetricRow
            label="Denied"
            value={formatNumber(data.denied)}
            valueClassName={data.denied > 0 ? "text-destructive" : undefined}
          />
        </div>

        {/* Cache performance */}
        <div className="mt-4 pt-4 border-t border-border">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-muted-foreground flex items-center gap-1.5">
              <Lightning className="h-3.5 w-3.5" weight="fill" />
              Cache Hit Rate
            </span>
            <span className="font-semibold tabular-nums text-accent">
              {cacheHitRate.toFixed(1)}%
            </span>
          </div>
          <Progress
            value={cacheHitRate}
            className="h-1.5"
            indicatorClassName={cn(
              cacheHitRate >= 80 ? "bg-success" :
              cacheHitRate >= 50 ? "bg-warning" : "bg-destructive"
            )}
          />
          <div className="flex justify-between mt-1.5 text-xs text-muted-foreground">
            <span>{formatNumber(data.cache_hits)} hits</span>
            <span>{formatNumber(data.cache_misses)} misses</span>
          </div>
        </div>

        {data.recent_denials.length > 0 && (
          <div className="mt-4 pt-4 border-t border-border">
            <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">
              Recent Denials
            </h4>
            <div className="space-y-2">
              {data.recent_denials.slice(0, 3).map((denial, i) => (
                <div
                  key={i}
                  className="text-xs bg-destructive/10 border border-destructive/20 rounded px-2 py-1.5"
                >
                  <div className="flex items-center gap-1.5 font-medium text-destructive">
                    <XCircle className="h-3 w-3" weight="fill" />
                    {denial.method}
                    {denial.tool && (
                      <span className="text-muted-foreground">({denial.tool})</span>
                    )}
                  </div>
                  <div className="text-muted-foreground mt-0.5 truncate">
                    {denial.reason}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
