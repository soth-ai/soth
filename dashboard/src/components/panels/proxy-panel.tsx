"use client";

import {
  Globe,
  ArrowsClockwise,
  Plugs,
  CheckCircle,
  Warning,
  Lightning,
} from "@phosphor-icons/react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, formatNumber, formatCurrency } from "@/lib/utils";
import type { ProxyMetrics } from "@/types";

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

interface ProxyPanelProps {
  data: ProxyMetrics | undefined;
  isLoading: boolean;
}

export function ProxyPanel({ data, isLoading }: ProxyPanelProps) {
  if (isLoading) {
    return (
      <Card className="animate-fade-in">
        <CardHeader>
          <CardTitle>
            <Globe className="h-4 w-4 text-accent" weight="duotone" />
            Forward Proxy
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {[...Array(5)].map((_, i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!data) return null;

  // Provider stats
  const providerStats = Object.entries(data.requests_by_provider)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5);

  // Cost breakdown
  const costBreakdown = Object.entries(data.cost_by_provider)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5);

  // Recent requests (last 5)
  const recentRequests = data.recent_requests.slice(0, 5);

  const isRunning = data.status.enabled && data.status.listen_address;

  return (
    <Card className="animate-slide-up stagger-5">
      <CardHeader>
        <CardTitle>
          <Globe className="h-4 w-4 text-accent" weight="duotone" />
          Forward Proxy
        </CardTitle>
      </CardHeader>
      <CardContent>
        {/* Status */}
        <div className="flex items-center gap-2 mb-4 pb-4 border-b border-border">
          {isRunning ? (
            <>
              <CheckCircle className="h-4 w-4 text-success" weight="fill" />
              <span className="text-sm text-success font-medium">Running</span>
              <span className="text-xs text-muted-foreground font-mono ml-auto">
                {data.status.listen_address}
              </span>
            </>
          ) : (
            <>
              <Warning className="h-4 w-4 text-muted-foreground" weight="fill" />
              <span className="text-sm text-muted-foreground font-medium">Not running</span>
            </>
          )}
        </div>

        {/* Overview metrics */}
        <div className="space-y-0">
          <MetricRow
            label="Total Requests"
            value={formatNumber(data.total_requests)}
          />
          <MetricRow
            label="Active Connections"
            value={data.active_connections}
            valueClassName={data.active_connections > 0 ? "text-accent" : ""}
          />
          <MetricRow
            label="Total Tokens"
            value={formatNumber(data.total_tokens)}
          />
          <MetricRow
            label="Total Cost"
            value={formatCurrency(data.total_cost_usd)}
            valueClassName="text-accent"
          />
        </div>

        {/* Provider breakdown */}
        {providerStats.length > 0 && (
          <div className="mt-4 pt-4 border-t border-border">
            <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <ArrowsClockwise className="h-3 w-3" weight="bold" />
              Requests by Provider
            </h4>
            <div className="space-y-1.5">
              {providerStats.map(([provider, count]) => (
                <div
                  key={provider}
                  className="flex items-center justify-between text-sm"
                >
                  <span className="text-muted-foreground capitalize">
                    {provider}
                  </span>
                  <span className="font-medium tabular-nums">
                    {formatNumber(count)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Cost by provider */}
        {costBreakdown.length > 0 && (
          <div className="mt-4 pt-4 border-t border-border">
            <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <Plugs className="h-3 w-3" weight="bold" />
              Cost by Provider
            </h4>
            <div className="space-y-1.5">
              {costBreakdown.map(([provider, cost]) => (
                <div
                  key={provider}
                  className="flex items-center justify-between text-sm"
                >
                  <span className="text-muted-foreground capitalize">
                    {provider}
                  </span>
                  <span className="font-medium tabular-nums">
                    {formatCurrency(cost)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recent requests */}
        {recentRequests.length > 0 && (
          <div className="mt-4 pt-4 border-t border-border">
            <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <Lightning className="h-3 w-3" weight="bold" />
              Recent Requests
            </h4>
            <div className="space-y-2">
              {recentRequests.map((req, i) => (
                <div
                  key={i}
                  className="flex items-start gap-2 text-xs bg-muted/30 rounded px-2 py-1.5"
                >
                  <span
                    className={cn(
                      "font-mono shrink-0",
                      req.status_code && req.status_code >= 200 && req.status_code < 300
                        ? "text-success"
                        : req.status_code && req.status_code >= 400
                        ? "text-destructive"
                        : "text-muted-foreground"
                    )}
                  >
                    {req.status_code ?? "..."}
                  </span>
                  <span className="text-muted-foreground truncate flex-1">
                    {req.method} {req.path.split("?")[0]}
                  </span>
                  {req.latency_ms && (
                    <span className="text-muted-foreground tabular-nums shrink-0">
                      {req.latency_ms}ms
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
