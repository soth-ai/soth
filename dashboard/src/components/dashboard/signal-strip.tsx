"use client";

import { useMemo } from "react";
import {
  ShieldCheck,
  Shield,
  Pulse,
  CurrencyDollar,
  TrendUp,
  TrendDown,
  Minus,
} from "@phosphor-icons/react";
import { cn, formatNumber, formatCurrency, formatPercent } from "@/lib/utils";

interface SignalCardProps {
  label: string;
  value: string;
  sublabel?: string;
  trend?: number; // percentage change
  status?: "healthy" | "warning" | "critical" | "neutral";
  icon: React.ElementType;
  sparkline?: number[];
}

function SignalCard({
  label,
  value,
  sublabel,
  trend,
  status = "neutral",
  icon: Icon,
  sparkline,
}: SignalCardProps) {
  const statusColors = {
    healthy: "text-success",
    warning: "text-warning",
    critical: "text-destructive",
    neutral: "text-foreground",
  };

  const statusBg = {
    healthy: "bg-success/5 border-success/20",
    warning: "bg-warning/5 border-warning/20",
    critical: "bg-destructive/5 border-destructive/20",
    neutral: "bg-card border-border",
  };

  return (
    <div
      className={cn(
        "flex flex-col p-4 rounded-xl border transition-all hover:border-border-hover",
        statusBg[status]
      )}
    >
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Icon
            className={cn("h-4 w-4", statusColors[status])}
            weight="duotone"
          />
          <span className="text-xs text-muted-foreground font-medium uppercase tracking-wider">
            {label}
          </span>
        </div>
        {trend !== undefined && (
          <div
            className={cn(
              "flex items-center gap-0.5 text-xs font-medium",
              trend > 0 ? "text-destructive" : trend < 0 ? "text-success" : "text-muted-foreground"
            )}
          >
            {trend > 0 ? (
              <TrendUp className="h-3 w-3" weight="bold" />
            ) : trend < 0 ? (
              <TrendDown className="h-3 w-3" weight="bold" />
            ) : (
              <Minus className="h-3 w-3" weight="bold" />
            )}
            <span>{Math.abs(trend).toFixed(1)}%</span>
          </div>
        )}
      </div>

      <div className="flex items-end justify-between gap-4">
        <div>
          <p className={cn("text-2xl font-bold tabular-nums", statusColors[status])}>
            {value}
          </p>
          {sublabel && (
            <p className="text-xs text-muted-foreground mt-0.5">{sublabel}</p>
          )}
        </div>

        {sparkline && sparkline.length > 0 && (
          <Sparkline data={sparkline} status={status} />
        )}
      </div>
    </div>
  );
}

function Sparkline({
  data,
  status,
}: {
  data: number[];
  status: "healthy" | "warning" | "critical" | "neutral";
}) {
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;

  const points = data
    .map((value, i) => {
      const x = (i / (data.length - 1)) * 60;
      const y = 20 - ((value - min) / range) * 16;
      return `${x},${y}`;
    })
    .join(" ");

  const strokeColor = {
    healthy: "stroke-success",
    warning: "stroke-warning",
    critical: "stroke-destructive",
    neutral: "stroke-accent",
  };

  return (
    <svg
      className="w-[60px] h-[20px] shrink-0"
      viewBox="0 0 60 20"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <polyline
        points={points}
        className={cn("fill-none", strokeColor[status])}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

interface SignalStripProps {
  identity: {
    successRate: number;
    total: number;
    trend?: number;
  };
  policy: {
    allowRate: number;
    total: number;
    denials: number;
    trend?: number;
  };
  traffic: {
    requestsPerMinute: number;
    trend?: number;
    sparkline?: number[];
  };
  spend: {
    todayUsd: number;
    trend?: number;
    dailyLimit?: number | null;
  };
}

export function SignalStrip({
  identity,
  policy,
  traffic,
  spend,
}: SignalStripProps) {
  // Determine statuses
  const identityStatus = useMemo(() => {
    if (identity.successRate >= 98) return "healthy";
    if (identity.successRate >= 90) return "warning";
    return "critical";
  }, [identity.successRate]);

  const policyStatus = useMemo(() => {
    if (policy.allowRate >= 99) return "healthy";
    if (policy.allowRate >= 95) return "warning";
    return "critical";
  }, [policy.allowRate]);

  const trafficStatus = useMemo((): "healthy" | "warning" | "critical" | "neutral" => {
    // Could be enhanced with baseline comparison
    return "neutral";
  }, []);

  const spendStatus = useMemo(() => {
    if (!spend.dailyLimit) return "neutral";
    const usage = (spend.todayUsd / spend.dailyLimit) * 100;
    if (usage >= 90) return "critical";
    if (usage >= 70) return "warning";
    return "healthy";
  }, [spend.todayUsd, spend.dailyLimit]);

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <SignalCard
        label="Identity"
        value={formatPercent(identity.successRate)}
        sublabel="Trust Score"
        trend={identity.trend}
        status={identityStatus}
        icon={ShieldCheck}
      />
      <SignalCard
        label="Policy"
        value={formatPercent(policy.allowRate)}
        sublabel={`${formatNumber(policy.denials)} denials`}
        trend={policy.trend}
        status={policyStatus}
        icon={Shield}
      />
      <SignalCard
        label="Traffic"
        value={`${formatNumber(traffic.requestsPerMinute)}/min`}
        sublabel="Requests"
        trend={traffic.trend}
        status={trafficStatus}
        icon={Pulse}
        sparkline={traffic.sparkline}
      />
      <SignalCard
        label="Spend"
        value={formatCurrency(spend.todayUsd)}
        sublabel={spend.dailyLimit ? `of ${formatCurrency(spend.dailyLimit)} limit` : "today"}
        trend={spend.trend}
        status={spendStatus}
        icon={CurrencyDollar}
      />
    </div>
  );
}

// Export individual card for reuse
export { SignalCard };
