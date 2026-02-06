"use client";

import { Key, CheckCircle, XCircle, Users } from "@phosphor-icons/react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, formatNumber } from "@/lib/utils";
import type { IdentityMetrics } from "@/types";

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

interface IdentityPanelProps {
  data: IdentityMetrics | undefined;
  isLoading: boolean;
}

export function IdentityPanel({ data, isLoading }: IdentityPanelProps) {
  if (isLoading) {
    return (
      <Card className="animate-fade-in">
        <CardHeader>
          <CardTitle>
            <Key className="h-4 w-4 text-accent" weight="duotone" />
            Identity
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

  const successRate = data.total_verifications > 0
    ? ((data.successful / data.total_verifications) * 100).toFixed(1)
    : "0.0";

  return (
    <Card className="animate-slide-up stagger-1">
      <CardHeader>
        <CardTitle>
          <Key className="h-4 w-4 text-accent" weight="duotone" />
          Identity
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-0">
          <MetricRow
            label="Total Verifications"
            value={formatNumber(data.total_verifications)}
          />
          <MetricRow
            label="Successful"
            value={formatNumber(data.successful)}
            valueClassName="text-success"
          />
          <MetricRow
            label="Failed"
            value={formatNumber(data.failed)}
            valueClassName={data.failed > 0 ? "text-destructive" : undefined}
          />
          <MetricRow
            label="Unique DIDs"
            value={formatNumber(data.unique_dids)}
          />
          <MetricRow
            label="Success Rate"
            value={`${successRate}%`}
            valueClassName="text-accent"
          />
        </div>

        {data.recent_dids.length > 0 && (
          <div className="mt-4 pt-4 border-t border-border">
            <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">
              Recent DIDs
            </h4>
            <div className="space-y-2">
              {data.recent_dids.slice(0, 3).map((entry, i) => (
                <div
                  key={i}
                  className="flex items-center gap-2 text-xs font-mono bg-muted rounded px-2 py-1.5"
                >
                  {entry.verified ? (
                    <CheckCircle className="h-3.5 w-3.5 text-success shrink-0" weight="fill" />
                  ) : (
                    <XCircle className="h-3.5 w-3.5 text-destructive shrink-0" weight="fill" />
                  )}
                  <span className="truncate">{entry.did.slice(0, 32)}...</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
