"use client";

import { Eye, ArrowUp, ArrowDown, Warning } from "@phosphor-icons/react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, formatNumber } from "@/lib/utils";
import type { ObserveMetrics } from "@/types";

interface MetricRowProps {
  label: string;
  value: string | number;
  valueClassName?: string;
  icon?: React.ReactNode;
}

function MetricRow({ label, value, valueClassName, icon }: MetricRowProps) {
  return (
    <div className="flex items-center justify-between py-2.5 border-b border-border last:border-0">
      <span className="text-muted-foreground text-sm flex items-center gap-1.5">
        {icon}
        {label}
      </span>
      <span className={cn("font-semibold tabular-nums", valueClassName)}>
        {value}
      </span>
    </div>
  );
}

interface ObservePanelProps {
  data: ObserveMetrics | undefined;
  isLoading: boolean;
}

export function ObservePanel({ data, isLoading }: ObservePanelProps) {
  if (isLoading) {
    return (
      <Card className="animate-fade-in">
        <CardHeader>
          <CardTitle>
            <Eye className="h-4 w-4 text-accent" weight="duotone" />
            Observe
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

  // Sort PII types by count
  const piiTypes = Object.entries(data.pii_by_type)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5);

  return (
    <Card className="animate-slide-up stagger-3">
      <CardHeader>
        <CardTitle>
          <Eye className="h-4 w-4 text-accent" weight="duotone" />
          Observe
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-0">
          <MetricRow
            label="Requests"
            value={formatNumber(data.requests)}
            icon={<ArrowDown className="h-3.5 w-3.5 text-success" weight="bold" />}
          />
          <MetricRow
            label="Responses"
            value={formatNumber(data.responses)}
            icon={<ArrowUp className="h-3.5 w-3.5 text-accent" weight="bold" />}
          />
          <MetricRow
            label="PII Detections"
            value={formatNumber(data.pii_detections)}
            valueClassName={data.pii_detections > 0 ? "text-warning" : undefined}
            icon={<Warning className="h-3.5 w-3.5 text-warning" weight="fill" />}
          />
        </div>

        {piiTypes.length > 0 && (
          <div className="mt-4 pt-4 border-t border-border">
            <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">
              PII by Type
            </h4>
            <div className="space-y-1.5">
              {piiTypes.map(([type, count]) => (
                <div
                  key={type}
                  className="flex items-center justify-between text-sm"
                >
                  <span className="text-muted-foreground capitalize">
                    {type.replace(/_/g, " ")}
                  </span>
                  <span className="font-medium tabular-nums text-warning">
                    {formatNumber(count)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Throughput indicator */}
        <div className="mt-4 pt-4 border-t border-border">
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted-foreground">Total Messages</span>
            <span className="font-semibold tabular-nums">
              {formatNumber(data.requests + data.responses)}
            </span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
