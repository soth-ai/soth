"use client";

import { useState, useMemo } from "react";
import { WifiHigh, WifiSlash, ChartLine, Waveform } from "@phosphor-icons/react";
import { useDashboardMetrics, useAgentsData } from "@/hooks/useDashboardData";
import { useEventStream } from "@/hooks/useEventStream";
import { SignalStrip } from "@/components/dashboard";
import { IdentityPanel } from "@/components/panels/identity-panel";
import { PolicyPanel } from "@/components/panels/policy-panel";
import { ObservePanel } from "@/components/panels/observe-panel";
import { BudgetPanel } from "@/components/panels/budget-panel";
import { ProxyPanel } from "@/components/panels/proxy-panel";
import { LiveFeedPanel } from "@/components/panels/live-feed-panel";
import { AgentsPanel } from "@/components/panels/agents-panel";
import { cn, formatDuration } from "@/lib/utils";

type Tab = "metrics" | "live";

function ConnectionStatus({ isConnected }: { isConnected: boolean }) {
  return (
    <div className="flex items-center gap-2">
      {isConnected ? (
        <>
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-success"></span>
          </span>
          <WifiHigh className="h-4 w-4 text-success" weight="bold" />
          <span className="text-sm text-success">Connected</span>
        </>
      ) : (
        <>
          <span className="h-2 w-2 rounded-full bg-destructive"></span>
          <WifiSlash className="h-4 w-4 text-destructive" weight="bold" />
          <span className="text-sm text-destructive">Disconnected</span>
        </>
      )}
    </div>
  );
}

function TabButton({
  active,
  onClick,
  icon: Icon,
  label,
}: {
  active: boolean;
  onClick: () => void;
  icon: React.ElementType;
  label: string;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg transition-colors",
        active
          ? "bg-accent text-accent-foreground"
          : "text-muted-foreground hover:text-foreground hover:bg-muted"
      )}
    >
      <Icon className="h-4 w-4" weight={active ? "fill" : "regular"} />
      {label}
    </button>
  );
}

export default function OverviewPage() {
  const [activeTab, setActiveTab] = useState<Tab>("metrics");

  const { isLoading, isConnected, uptime, identity, policy, observe, budget, proxy } =
    useDashboardMetrics();

  const agents = useAgentsData();

  const {
    events,
    isConnected: wsConnected,
    clearEvents,
  } = useEventStream({ enabled: activeTab === "live" });

  // Compute signal strip data
  const signalData = useMemo(() => {
    const identitySuccessRate = identity?.total_verifications
      ? (identity.successful / identity.total_verifications) * 100
      : 100;

    const policyAllowRate = policy?.evaluations
      ? (policy.allowed / policy.evaluations) * 100
      : 100;

    // Estimate requests per minute from observe data
    const totalRequests = (observe?.requests ?? 0) + (observe?.responses ?? 0);
    const requestsPerMinute = uptime > 0 ? Math.round((totalRequests / uptime) * 60) : 0;

    const todaySpend = (budget?.total_cost_usd ?? 0) + (proxy?.total_cost_usd ?? 0);

    return {
      identity: {
        successRate: identitySuccessRate,
        total: identity?.total_verifications ?? 0,
      },
      policy: {
        allowRate: policyAllowRate,
        total: policy?.evaluations ?? 0,
        denials: policy?.denied ?? 0,
      },
      traffic: {
        requestsPerMinute,
        sparkline: [], // Could be populated from historical data
      },
      spend: {
        todayUsd: todaySpend,
        dailyLimit: budget?.daily_limit_usd ?? null,
      },
    };
  }, [identity, policy, observe, budget, proxy, uptime]);

  return (
    <div className="min-h-screen">
      {/* Page Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-20">
        <div className="px-4 md:px-6 py-3 md:py-4 flex items-center justify-between">
          <div className="flex items-center gap-4 md:gap-6">
            <div className="flex items-center gap-1 md:gap-2">
              <TabButton
                active={activeTab === "metrics"}
                onClick={() => setActiveTab("metrics")}
                icon={ChartLine}
                label="Metrics"
              />
              <TabButton
                active={activeTab === "live"}
                onClick={() => setActiveTab("live")}
                icon={Waveform}
                label="Live"
              />
            </div>
          </div>

          <div className="flex items-center gap-3 md:gap-6">
            <ConnectionStatus isConnected={isConnected} />
            {isConnected && (
              <div className="hidden sm:block text-sm text-muted-foreground">
                <span className="font-mono tabular-nums">{formatDuration(uptime)}</span>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Main content */}
      <div className="px-4 md:px-6 py-4 md:py-6">
        {!isConnected && !isLoading && (
          <div className="mb-4 md:mb-6 p-3 md:p-4 rounded-lg bg-destructive/10 border border-destructive/20">
            <div className="flex items-start gap-2 text-sm text-destructive">
              <WifiSlash className="h-4 w-4 shrink-0 mt-0.5" weight="bold" />
              <span className="text-xs md:text-sm">
                Unable to connect to SOTH backend.
                <span className="hidden sm:inline">
                  {" "}Make sure the proxy is running with <code className="font-mono">dashboard.enabled: true</code>.
                </span>
              </span>
            </div>
          </div>
        )}

        {activeTab === "metrics" && (
          <>
            {/* Signal Strip */}
            <div className="mb-4 md:mb-6 overflow-x-auto -mx-4 px-4 md:mx-0 md:px-0">
              <div className="min-w-[600px] md:min-w-0">
                <SignalStrip {...signalData} />
              </div>
            </div>

            {/* Dual-Lane Layout */}
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 md:gap-6 mb-4 md:mb-6">
              {/* Left Lane: Runtime & Security */}
              <div className="space-y-4 md:space-y-6">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 md:gap-6">
                  <IdentityPanel data={identity} isLoading={isLoading} />
                  <PolicyPanel data={policy} isLoading={isLoading} />
                </div>
                <ProxyPanel data={proxy} isLoading={isLoading} />
              </div>

              {/* Right Lane: Cost & Risk */}
              <div className="space-y-4 md:space-y-6">
                <BudgetPanel data={budget} isLoading={isLoading} />
                <ObservePanel data={observe} isLoading={isLoading} />
              </div>
            </div>
          </>
        )}

        {activeTab === "live" && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 md:gap-6">
            {/* Live Feed - takes 2 columns on large screens */}
            <div className="lg:col-span-2 order-1">
              <LiveFeedPanel
                events={events}
                isConnected={wsConnected}
                onClear={clearEvents}
              />
            </div>

            {/* Agents panel */}
            <div className="order-2">
              <AgentsPanel
                data={agents.data?.data}
                isLoading={agents.isLoading}
              />
            </div>
          </div>
        )}

        {/* Footer - hidden on mobile */}
        <footer className="hidden md:block mt-12 pt-6 border-t border-border text-center text-xs text-muted-foreground">
          <p>
            {activeTab === "metrics" && "Auto-refreshing every 2 seconds"}
            {activeTab === "live" && (wsConnected ? "Streaming events in real-time" : "Connecting to event stream...")}
            {isConnected && " • "}
            {isConnected && (
              <span className="font-mono">
                {(identity?.total_verifications ?? 0) +
                  (policy?.evaluations ?? 0) +
                  (observe?.requests ?? 0) +
                  (observe?.responses ?? 0)}{" "}
                total events
              </span>
            )}
          </p>
        </footer>
      </div>
    </div>
  );
}
