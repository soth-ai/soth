"use client";

import { useMemo } from "react";
import {
  ShieldSlash,
  Eye,
  Timer,
  XCircle,
  Funnel,
  ArrowsClockwise,
  CurrencyDollar,
  Lightning,
} from "@phosphor-icons/react";
import {
  useObservabilityStore,
  computeLogMetrics,
  getLogTokenCount,
  type EventSource,
} from "@/store/observability";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface QuickFilter {
  id: string;
  label: string;
  icon: React.ElementType;
  color: "red" | "orange" | "amber" | "cyan" | "purple" | "green";
  count: number;
  isActive: boolean;
  onClick: () => void;
}

interface AiCommandBarProps {
  sourceFilter: EventSource;
}

export function AiCommandBar({ sourceFilter }: AiCommandBarProps) {
  const logs = useObservabilityStore((state) => state.logs);
  const filters = useObservabilityStore((state) => state.filters);
  const setFilters = useObservabilityStore((state) => state.setFilters);
  const clearFilters = useObservabilityStore((state) => state.clearFilters);
  const clearLogs = useObservabilityStore((state) => state.clearLogs);

  // Filter logs by source
  const filteredLogs = useMemo(() => {
    return logs.filter((log) => log.source === sourceFilter);
  }, [logs, sourceFilter]);

  // Compute counts and stats for quick filters
  const stats = useMemo(() => {
    let policyDenied = 0;
    let piiDetected = 0;
    let slowRequests = 0;
    let errors = 0;
    let totalCost = 0;
    let totalTokens = 0;
    const providers = new Map<string, number>();
    const models = new Map<string, number>();

    filteredLogs.forEach((log) => {
      if (log.policy_allowed === false) policyDenied++;
      if (log.pii_detected) piiDetected++;
      if ((log.latency_ms ?? 0) >= 2000) slowRequests++;
      if (log.status_code && log.status_code >= 400) errors++;
      if (log.cost_usd) totalCost += log.cost_usd;
      totalTokens += getLogTokenCount(log);
      if (log.provider) {
        providers.set(log.provider, (providers.get(log.provider) || 0) + 1);
      }
      if (log.model) {
        models.set(log.model, (models.get(log.model) || 0) + 1);
      }
    });

    return {
      policyDenied,
      piiDetected,
      slowRequests,
      errors,
      totalCost,
      totalTokens,
      providerCount: providers.size,
      modelCount: models.size,
    };
  }, [filteredLogs]);

  const metrics = useMemo(() => computeLogMetrics(filteredLogs), [filteredLogs]);

  // Check which filters are active
  const hasActiveFilters = !!(
    filters.method ||
    filters.path ||
    filters.direction ||
    filters.serverName ||
    filters.minLatencyMs ||
    filters.policyDenied ||
    filters.piiDetected ||
    filters.hasError
  );

  const colorClasses = {
    red: {
      active: "bg-red-500/20 text-red-500 border-red-500/50",
      inactive: "hover:bg-red-500/10 hover:text-red-500 hover:border-red-500/30",
    },
    orange: {
      active: "bg-orange-500/20 text-orange-500 border-orange-500/50",
      inactive: "hover:bg-orange-500/10 hover:text-orange-500 hover:border-orange-500/30",
    },
    amber: {
      active: "bg-amber-500/20 text-amber-500 border-amber-500/50",
      inactive: "hover:bg-amber-500/10 hover:text-amber-500 hover:border-amber-500/30",
    },
    cyan: {
      active: "bg-cyan-500/20 text-cyan-500 border-cyan-500/50",
      inactive: "hover:bg-cyan-500/10 hover:text-cyan-500 hover:border-cyan-500/30",
    },
    purple: {
      active: "bg-purple-500/20 text-purple-500 border-purple-500/50",
      inactive: "hover:bg-purple-500/10 hover:text-purple-500 hover:border-purple-500/30",
    },
    green: {
      active: "bg-emerald-500/20 text-emerald-500 border-emerald-500/50",
      inactive: "hover:bg-emerald-500/10 hover:text-emerald-500 hover:border-emerald-500/30",
    },
  };

  const quickFilters: QuickFilter[] = [
    {
      id: "policy-denied",
      label: "Blocked",
      icon: ShieldSlash,
      color: "red",
      count: stats.policyDenied,
      isActive: filters.policyDenied === true,
      onClick: () =>
        setFilters({
          policyDenied: filters.policyDenied ? undefined : true,
        }),
    },
    {
      id: "pii-detected",
      label: "PII",
      icon: Eye,
      color: "orange",
      count: stats.piiDetected,
      isActive: filters.piiDetected === true,
      onClick: () =>
        setFilters({
          piiDetected: filters.piiDetected ? undefined : true,
        }),
    },
    {
      id: "slow",
      label: "Slow (>2s)",
      icon: Timer,
      color: "amber",
      count: stats.slowRequests,
      isActive: filters.minLatencyMs === 2000,
      onClick: () =>
        setFilters({
          minLatencyMs: filters.minLatencyMs === 2000 ? undefined : 2000,
        }),
    },
    {
      id: "errors",
      label: "Errors",
      icon: XCircle,
      color: "red",
      count: stats.errors,
      isActive: filters.hasError === true,
      onClick: () =>
        setFilters({
          hasError: filters.hasError ? undefined : true,
        }),
    },
  ];

  return (
    <div className="flex items-center gap-3 px-4 py-2.5 bg-card/50 border border-dashed border-border rounded-t-[12px]">
      {/* Quick Filters */}
      <div className="flex items-center gap-1.5">
        <Funnel className="w-3.5 h-3.5 text-muted-foreground mr-1" weight="duotone" />
        {quickFilters.map((filter) => (
          <button
            key={filter.id}
            onClick={filter.onClick}
            disabled={filter.count === 0}
            className={cn(
              "inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-all",
              "disabled:opacity-30 disabled:cursor-not-allowed",
              filter.isActive
                ? colorClasses[filter.color].active
                : cn(
                    "bg-transparent text-muted-foreground border-border",
                    colorClasses[filter.color].inactive
                  )
            )}
          >
            <filter.icon className="w-3.5 h-3.5" weight={filter.isActive ? "fill" : "regular"} />
            <span>{filter.label}</span>
            {filter.count > 0 && (
              <span
                className={cn(
                  "px-1.5 py-0.5 rounded text-[10px] font-mono tabular-nums",
                  filter.isActive ? "bg-current/20" : "bg-muted"
                )}
              >
                {filter.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Divider */}
      <div className="h-6 w-px bg-border" />

      {/* Stats */}
      <div className="flex items-center gap-4 text-xs">
        <div className="flex items-center gap-1.5 text-muted-foreground">
          <span className="font-medium">{metrics.totalMessages}</span>
          <span>requests</span>
        </div>
        <div className="flex items-center gap-1.5">
          <Lightning className="w-3.5 h-3.5 text-purple-500" weight="duotone" />
          <span className="font-mono font-medium text-foreground tabular-nums">
            {stats.totalTokens.toLocaleString()}
          </span>
          <span className="text-muted-foreground">tokens</span>
        </div>
        <div className="flex items-center gap-1.5">
          <CurrencyDollar className="w-3.5 h-3.5 text-emerald-500" weight="duotone" />
          <span className="font-mono font-bold text-emerald-500 tabular-nums">
            ${stats.totalCost.toFixed(4)}
          </span>
        </div>
      </div>

      {/* Spacer */}
      <div className="flex-1" />

      {/* Actions */}
      <div className="flex items-center gap-2">
        {hasActiveFilters && (
          <Button
            variant="ghost"
            size="sm"
            onClick={clearFilters}
            className="h-7 px-2.5 text-xs text-muted-foreground hover:text-foreground"
          >
            Clear filters
          </Button>
        )}
        <Button
          variant="ghost"
          size="sm"
          onClick={clearLogs}
          className="h-7 px-2.5 text-xs text-muted-foreground hover:text-destructive"
        >
          <ArrowsClockwise className="w-3.5 h-3.5 mr-1.5" />
          Clear
        </Button>
      </div>
    </div>
  );
}
