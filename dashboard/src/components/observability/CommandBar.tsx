"use client";

import { useMemo } from "react";
import {
  ShieldSlash,
  Eye,
  Timer,
  XCircle,
  Funnel,
  ArrowsClockwise,
  Robot,
  Cpu,
  CloudArrowUp,
  CurrencyDollar,
} from "@phosphor-icons/react";
import { useObservabilityStore, computeLogMetrics, type EventSource } from "@/store/observability";
import { Button } from "@/components/ui/button";
import { PresetDropdown } from "./PresetDropdown";
import { cn } from "@/lib/utils";

interface QuickFilter {
  id: string;
  label: string;
  icon: React.ElementType;
  color: "red" | "orange" | "amber" | "cyan" | "purple" | "gray";
  count: number;
  isActive: boolean;
  onClick: () => void;
}

interface SourceToggle {
  id: EventSource;
  label: string;
  icon: React.ElementType;
  color: string;
  count: number;
}

export function CommandBar() {
  const logs = useObservabilityStore((state) => state.logs);
  const filters = useObservabilityStore((state) => state.filters);
  const setFilters = useObservabilityStore((state) => state.setFilters);
  const clearFilters = useObservabilityStore((state) => state.clearFilters);
  const clearLogs = useObservabilityStore((state) => state.clearLogs);

  // Apply source filter for counting
  const filteredBySource = useMemo(() => {
    if (!filters.source) return logs;
    return logs.filter((log) => log.source === filters.source);
  }, [logs, filters.source]);

  // Compute counts for source toggles
  const sourceCounts = useMemo(() => {
    const counts = { mcp: 0, ai_proxy: 0, agent_app: 0 };
    logs.forEach((log) => {
      if (log.source in counts) {
        counts[log.source as keyof typeof counts]++;
      }
    });
    return counts;
  }, [logs]);

  // Compute counts for quick filters
  const counts = useMemo(() => {
    let policyDenied = 0;
    let piiDetected = 0;
    let slowRequests = 0;
    let errors = 0;
    let totalCost = 0;
    let totalTokens = 0;
    const agents = new Set<string>();

    filteredBySource.forEach((log) => {
      if (log.policy_allowed === false) policyDenied++;
      if (log.pii_detected) piiDetected++;
      if ((log.latency_ms ?? 0) >= 1000) slowRequests++;
      if (log.cost_usd) totalCost += log.cost_usd;
      if (log.token_count) totalTokens += log.token_count;
      try {
        const parsed = JSON.parse(log.content);
        if (parsed.error) errors++;
      } catch {
        // Not JSON
      }
      if (log.status_code && log.status_code >= 400) errors++;
      if (log.agent?.name) agents.add(log.agent.name);
    });

    return { policyDenied, piiDetected, slowRequests, errors, agentCount: agents.size, totalCost, totalTokens };
  }, [filteredBySource]);

  const metrics = useMemo(() => computeLogMetrics(filteredBySource), [filteredBySource]);

  // Check which filters are active
  const hasActiveFilters = !!(
    filters.method ||
    filters.path ||
    filters.direction ||
    filters.serverName ||
    filters.minLatencyMs ||
    filters.policyDenied ||
    filters.piiDetected ||
    filters.hasError ||
    filters.source
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
    gray: {
      active: "bg-muted text-foreground border-border",
      inactive: "hover:bg-muted/50 hover:text-muted-foreground",
    },
  };

  const sourceToggles: SourceToggle[] = [
    { id: "mcp", label: "MCP", icon: Cpu, color: "cyan", count: sourceCounts.mcp },
    { id: "ai_proxy", label: "AI", icon: CloudArrowUp, color: "purple", count: sourceCounts.ai_proxy },
    { id: "agent_app", label: "Agent", icon: Robot, color: "amber", count: sourceCounts.agent_app },
  ];

  const quickFilters: QuickFilter[] = [
    {
      id: "policy-denied",
      label: "Blocked",
      icon: ShieldSlash,
      color: "red",
      count: counts.policyDenied,
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
      count: counts.piiDetected,
      isActive: filters.piiDetected === true,
      onClick: () =>
        setFilters({
          piiDetected: filters.piiDetected ? undefined : true,
        }),
    },
    {
      id: "slow",
      label: "Slow",
      icon: Timer,
      color: "amber",
      count: counts.slowRequests,
      isActive: filters.minLatencyMs === 1000,
      onClick: () =>
        setFilters({
          minLatencyMs: filters.minLatencyMs === 1000 ? undefined : 1000,
        }),
    },
    {
      id: "errors",
      label: "Errors",
      icon: XCircle,
      color: "red",
      count: counts.errors,
      isActive: filters.hasError === true,
      onClick: () =>
        setFilters({
          hasError: filters.hasError ? undefined : true,
        }),
    },
  ];

  const handleSourceToggle = (source: EventSource) => {
    setFilters({
      source: filters.source === source ? undefined : source,
    });
  };

  return (
    <div className="flex items-center gap-2.5 px-3 py-2 bg-card/50 border border-dashed border-border rounded-t-[12px]">
      {/* Source Toggles */}
      <div className="flex items-center gap-1">
        {sourceToggles.map((source) => {
          const isActive = filters.source === source.id;
          const colorKey = source.color as keyof typeof colorClasses;
          return (
            <button
              key={source.id}
              onClick={() => handleSourceToggle(source.id)}
              className={cn(
                "inline-flex items-center gap-1 px-2 py-1 rounded-lg text-[11px] font-medium border transition-all",
                isActive
                  ? colorClasses[colorKey].active
                  : cn("bg-transparent text-muted-foreground border-border", colorClasses[colorKey].inactive)
              )}
            >
              <source.icon className="w-3 h-3" weight={isActive ? "fill" : "duotone"} />
              <span>{source.label}</span>
              <span
                className={cn(
                  "px-1.5 py-0.5 rounded text-[10px] font-mono tabular-nums",
                  isActive ? "bg-current/20" : "bg-muted"
                )}
              >
                {source.count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Divider */}
      <div className="h-5 w-px bg-border" />

      {/* Presets */}
      <PresetDropdown />

      {/* Divider */}
      <div className="h-5 w-px bg-border" />

      {/* Quick Filters */}
      <div className="flex items-center gap-1">
        <Funnel className="w-3 h-3 text-muted-foreground mr-1" weight="duotone" />
        {quickFilters.map((filter) => (
          <button
            key={filter.id}
            onClick={filter.onClick}
            disabled={filter.count === 0}
            className={cn(
              "inline-flex items-center gap-1 px-1.5 py-1 rounded-lg text-[11px] font-medium border transition-all",
              "disabled:opacity-30 disabled:cursor-not-allowed",
              filter.isActive
                ? colorClasses[filter.color].active
                : cn("bg-transparent text-muted-foreground border-border", colorClasses[filter.color].inactive)
            )}
          >
            <filter.icon className="w-3 h-3" weight={filter.isActive ? "fill" : "regular"} />
            <span>{filter.label}</span>
            {filter.count > 0 && (
              <span
                className={cn(
                  "px-1 py-0.5 rounded text-[10px] font-mono tabular-nums",
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
      <div className="h-5 w-px bg-border" />

      {/* Stats */}
      <div className="flex items-center gap-2.5 text-[11px]">
        <div className="flex items-center gap-1.5 text-muted-foreground">
          <span className="font-mono font-bold tabular-nums text-foreground">{metrics.totalMessages}</span>
          <span>events</span>
        </div>
        {counts.totalTokens > 0 && (
          <div className="flex items-center gap-1.5 text-purple-500">
            <span className="font-mono font-medium tabular-nums">{(counts.totalTokens / 1000).toFixed(1)}k</span>
            <span className="text-muted-foreground">tokens</span>
          </div>
        )}
        {counts.totalCost > 0 && (
          <div className="flex items-center gap-1.5">
            <CurrencyDollar className="w-3 h-3 text-emerald-500" weight="duotone" />
            <span className="font-mono font-bold text-emerald-500 tabular-nums">${counts.totalCost.toFixed(4)}</span>
          </div>
        )}
        <div className="flex items-center gap-1.5">
          <Robot className="w-3 h-3 text-muted-foreground" weight="duotone" />
          <span className="font-medium text-foreground tabular-nums">{counts.agentCount}</span>
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
            className="h-6 px-2 text-[11px] text-muted-foreground hover:text-foreground"
          >
            Clear filters
          </Button>
        )}
        <Button
          variant="ghost"
          size="sm"
          onClick={clearLogs}
          className="h-6 px-2 text-[11px] text-muted-foreground hover:text-destructive"
        >
          <ArrowsClockwise className="w-3 h-3 mr-1.5" />
          Clear
        </Button>
      </div>
    </div>
  );
}
