"use client";

import { useMemo } from "react";
import {
  BugBeetle,
  CheckCircle,
  CloudArrowUp,
  Cpu,
  Robot,
  WarningCircle,
  WifiHigh,
  WifiSlash,
} from "@phosphor-icons/react";
import {
  useAgentsData,
  useEventStreamStats,
  useHealth,
  useProxyMetrics,
} from "@/hooks/useDashboardData";
import { useEventStream } from "@/hooks/useEventStream";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn, formatLatency, formatNumber, formatTimestamp } from "@/lib/utils";
import type { WrapEvent } from "@/types";

type SourceKey = "ai_proxy" | "mcp" | "agent_app";

interface SourceSummary {
  source: SourceKey;
  total: number;
  errors: number;
  denied: number;
  pii: number;
  topSignal: string;
  lastSeen: string;
}

function normalizeSource(value: WrapEvent["source"]): SourceKey | null {
  if (value === "ai_proxy" || value === "mcp" || value === "agent_app") {
    return value;
  }
  return null;
}

function statusTone(ok: boolean): string {
  return ok ? "text-emerald-500" : "text-rose-500";
}

function sourceTitle(source: SourceKey): string {
  if (source === "ai_proxy") return "AI Inference";
  if (source === "mcp") return "MCP";
  return "Agent Apps";
}

function sourceIcon(source: SourceKey) {
  if (source === "ai_proxy") return CloudArrowUp;
  if (source === "mcp") return Cpu;
  return Robot;
}

export default function DebugPage() {
  const { data: health, isLoading: healthLoading } = useHealth();
  const { data: proxyResponse, isLoading: proxyLoading } = useProxyMetrics();
  const { data: agentsResponse } = useAgentsData();
  const { data: streamStatsResponse } = useEventStreamStats();
  const {
    events: liveEvents,
    isConnected: streamConnected,
    error: streamError,
    lastSeq,
  } = useEventStream({
    enabled: true,
    maxEvents: 400,
  });

  const proxy = proxyResponse?.data;
  const streamStats = streamStatsResponse?.data;
  const agents = agentsResponse?.data?.agents ?? [];
  const topProviders = useMemo(
    () =>
      Object.entries(proxy?.requests_by_provider ?? {})
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8),
    [proxy?.requests_by_provider]
  );

  const modelSignals = useMemo(() => {
    const counts = new Map<string, number>();
    for (const event of liveEvents) {
      const model = event.model?.trim();
      if (!model || model === "-") continue;
      counts.set(model, (counts.get(model) ?? 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  }, [liveEvents]);

  const sourceSummaries = useMemo<SourceSummary[]>(() => {
    const rows = new Map<SourceKey, SourceSummary>();
    const defaults: SourceSummary[] = [
      {
        source: "ai_proxy",
        total: 0,
        errors: 0,
        denied: 0,
        pii: 0,
        topSignal: "-",
        lastSeen: "-",
      },
      {
        source: "mcp",
        total: 0,
        errors: 0,
        denied: 0,
        pii: 0,
        topSignal: "-",
        lastSeen: "-",
      },
      {
        source: "agent_app",
        total: 0,
        errors: 0,
        denied: 0,
        pii: 0,
        topSignal: "-",
        lastSeen: "-",
      },
    ];
    for (const row of defaults) rows.set(row.source, { ...row });

    const signalCounts = new Map<SourceKey, Map<string, number>>();
    for (const source of ["ai_proxy", "mcp", "agent_app"] as const) {
      signalCounts.set(source, new Map());
    }

    for (const event of liveEvents) {
      const source = normalizeSource(event.source);
      if (!source) continue;
      const row = rows.get(source)!;
      row.total += 1;
      if ((event.status_code ?? 0) >= 500) row.errors += 1;
      if (event.policy_allowed === false) row.denied += 1;
      if (event.pii_detected) row.pii += 1;

      const candidateSignal =
        event.method || event.tool_name || event.model || event.provider || event.server_name || "-";
      const map = signalCounts.get(source)!;
      map.set(candidateSignal, (map.get(candidateSignal) ?? 0) + 1);

      if (
        row.lastSeen === "-" ||
        new Date(event.timestamp).getTime() > new Date(row.lastSeen).getTime()
      ) {
        row.lastSeen = event.timestamp;
      }
    }

    for (const [source, row] of rows.entries()) {
      const map = signalCounts.get(source)!;
      const top = [...map.entries()].sort((a, b) => b[1] - a[1])[0];
      if (top) {
        row.topSignal = `${top[0]} (${top[1]})`;
      }
    }

    return [...rows.values()];
  }, [liveEvents]);

  const recentFailures = useMemo(() => {
    const failures = (proxy?.recent_requests ?? [])
      .filter(
        (request) =>
          (request.status_code ?? 0) >= 500 ||
          (request.latency_ms ?? 0) >= 3000
      )
      .slice(0, 12);
    return failures;
  }, [proxy?.recent_requests]);

  const healthOk = health?.status === "ok";
  const proxyEnabled = proxy?.status.enabled ?? false;
  const caInstalled = proxy?.status.ca_installed ?? false;
  const laggedEvents = streamStats?.lagged_events ?? 0;
  const laggedReceivers = streamStats?.lagged_receivers ?? 0;
  const sendFailures = streamStats?.broadcast_send_failures ?? 0;
  const backfills = streamStats?.backfill_batches ?? 0;
  const syncHealthy = laggedEvents === 0 && sendFailures === 0;

  return (
    <div className="mx-auto w-full max-w-[1400px] px-2 py-4 md:px-0 md:py-6 space-y-4">
      <div className="rounded-xl border border-border bg-card/60 p-4">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
              <BugBeetle className="h-6 w-6 text-accent" weight="duotone" />
              Debug
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              Live diagnostics for custom MCP, agent apps, and AI inference flows.
            </p>
          </div>
          <div className="text-xs text-muted-foreground text-right">
            <p>Live events: {formatNumber(liveEvents.length)}</p>
            <p>Latest seq: {lastSeq ?? 0}</p>
          </div>
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-3">
        <Card className="border-border/80">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Connectivity</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <p className="flex items-center justify-between">
              <span>Dashboard API</span>
              <span className={cn("font-medium", statusTone(healthOk))}>
                {healthLoading ? "Checking..." : healthOk ? "Connected" : "Disconnected"}
              </span>
            </p>
            <p className="flex items-center justify-between">
              <span>Event Stream</span>
              <span className={cn("font-medium", statusTone(streamConnected))}>
                {streamConnected ? "Connected" : "Disconnected"}
              </span>
            </p>
            <p className="flex items-center justify-between">
              <span>Proxy Runtime</span>
              <span className={cn("font-medium", statusTone(proxyEnabled))}>
                {proxyLoading ? "Checking..." : proxyEnabled ? "Enabled" : "Disabled"}
              </span>
            </p>
            <p className="flex items-center justify-between">
              <span>CA Trust</span>
              <span className={cn("font-medium", statusTone(caInstalled))}>
                {caInstalled ? "Installed" : "Missing"}
              </span>
            </p>
            {streamError ? (
              <p className="text-xs text-rose-500">Stream error: {streamError}</p>
            ) : null}
          </CardContent>
        </Card>

        <Card className="border-border/80">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Sync Health</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <p className="flex items-center justify-between">
              <span>Status</span>
              <span className={cn("font-medium", statusTone(syncHealthy))}>
                {syncHealthy ? "Healthy" : "Backpressure"}
              </span>
            </p>
            <p className="flex items-center justify-between">
              <span>Lagged Receivers</span>
              <span className="font-medium">{formatNumber(laggedReceivers)}</span>
            </p>
            <p className="flex items-center justify-between">
              <span>Lagged Events</span>
              <span className={cn("font-medium", laggedEvents > 0 && "text-amber-500")}>
                {formatNumber(laggedEvents)}
              </span>
            </p>
            <p className="flex items-center justify-between">
              <span>Broadcast Failures</span>
              <span className={cn("font-medium", sendFailures > 0 && "text-rose-500")}>
                {formatNumber(sendFailures)}
              </span>
            </p>
            <p className="flex items-center justify-between">
              <span>Backfill Batches</span>
              <span className="font-medium">{formatNumber(backfills)}</span>
            </p>
          </CardContent>
        </Card>

        <Card className="border-border/80">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Failures</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <p className="flex items-center justify-between">
              <span>Recent request failures</span>
              <span className={cn("font-medium", recentFailures.length > 0 ? "text-rose-500" : "text-emerald-500")}>
                {formatNumber(recentFailures.length)}
              </span>
            </p>
            <p className="flex items-center justify-between">
              <span>Policy denials (live)</span>
              <span className="font-medium">
                {formatNumber(
                  liveEvents.filter((event) => event.policy_allowed === false).length
                )}
              </span>
            </p>
            <p className="flex items-center justify-between">
              <span>PII flags (live)</span>
              <span className="font-medium">
                {formatNumber(liveEvents.filter((event) => event.pii_detected).length)}
              </span>
            </p>
            <div className="pt-1 text-xs text-muted-foreground">
              {recentFailures.length === 0
                ? "No high-latency/5xx failures in recent proxy requests."
                : "Inspect the failure table below for endpoints and latency."}
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-3 md:grid-cols-3">
        {sourceSummaries.map((row) => {
          const Icon = sourceIcon(row.source);
          return (
            <Card key={row.source} className="border-border/80">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Icon className="h-4 w-4 text-accent" weight="duotone" />
                  {sourceTitle(row.source)}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <p className="flex items-center justify-between">
                  <span>Events</span>
                  <span className="font-medium">{formatNumber(row.total)}</span>
                </p>
                <p className="flex items-center justify-between">
                  <span>Errors</span>
                  <span className={cn("font-medium", row.errors > 0 && "text-rose-500")}>
                    {formatNumber(row.errors)}
                  </span>
                </p>
                <p className="flex items-center justify-between">
                  <span>Denied</span>
                  <span className={cn("font-medium", row.denied > 0 && "text-amber-500")}>
                    {formatNumber(row.denied)}
                  </span>
                </p>
                <p className="flex items-center justify-between">
                  <span>PII</span>
                  <span className={cn("font-medium", row.pii > 0 && "text-amber-500")}>
                    {formatNumber(row.pii)}
                  </span>
                </p>
                <p className="text-xs text-muted-foreground truncate">
                  Top signal: {row.topSignal}
                </p>
                <p className="text-xs text-muted-foreground">
                  Last seen: {row.lastSeen === "-" ? "-" : formatTimestamp(row.lastSeen)}
                </p>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <div className="grid gap-3 lg:grid-cols-2">
        <Card className="border-border/80">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Detection Summary</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <div>
              <p className="text-xs uppercase tracking-wide text-muted-foreground mb-1">Top Providers</p>
              {topProviders.length === 0 ? (
                <p className="text-xs text-muted-foreground">No provider traffic yet.</p>
              ) : (
                <div className="space-y-1">
                  {topProviders.map(([provider, count]) => (
                    <p key={provider} className="flex items-center justify-between">
                      <span className="truncate pr-3">{provider}</span>
                      <span className="font-medium">{formatNumber(count)}</span>
                    </p>
                  ))}
                </div>
              )}
            </div>

            <div>
              <p className="text-xs uppercase tracking-wide text-muted-foreground mb-1">Top Agents</p>
              {agents.length === 0 ? (
                <p className="text-xs text-muted-foreground">No agents detected yet.</p>
              ) : (
                <div className="space-y-1">
                  {agents.slice(0, 6).map((agent) => (
                    <p key={agent.name} className="flex items-center justify-between">
                      <span className="truncate pr-3">{agent.name}</span>
                      <span className="font-medium">{formatNumber(agent.event_count)}</span>
                    </p>
                  ))}
                </div>
              )}
            </div>

            <div>
              <p className="text-xs uppercase tracking-wide text-muted-foreground mb-1">Observed Models</p>
              {modelSignals.length === 0 ? (
                <p className="text-xs text-muted-foreground">No model metadata in current window.</p>
              ) : (
                <div className="space-y-1">
                  {modelSignals.map(([model, count]) => (
                    <p key={model} className="flex items-center justify-between">
                      <span className="truncate pr-3">{model}</span>
                      <span className="font-medium">{formatNumber(count)}</span>
                    </p>
                  ))}
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        <Card className="border-border/80">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Recent Failure Requests</CardTitle>
          </CardHeader>
          <CardContent>
            {recentFailures.length === 0 ? (
              <div className="flex items-center gap-2 text-sm text-emerald-500">
                <CheckCircle className="h-4 w-4" weight="fill" />
                No recent high-latency or 5xx requests.
              </div>
            ) : (
              <div className="space-y-2">
                {recentFailures.map((request, idx) => (
                  <div
                    key={`${request.timestamp}-${request.host}-${idx}`}
                    className="rounded-md border border-border/70 px-3 py-2 text-xs"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-medium truncate">
                        {request.method} {request.path}
                      </span>
                      <span className="text-muted-foreground">
                        {formatTimestamp(request.timestamp)}
                      </span>
                    </div>
                    <div className="mt-1 flex items-center justify-between gap-2 text-muted-foreground">
                      <span className="truncate">{request.host}</span>
                      <span className="flex items-center gap-3">
                        <span className="inline-flex items-center gap-1">
                          <WarningCircle className="h-3 w-3 text-rose-500" weight="fill" />
                          {request.status_code ?? "-"}
                        </span>
                        <span>
                          {typeof request.latency_ms === "number"
                            ? formatLatency(request.latency_ms)
                            : "-"}
                        </span>
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="rounded-xl border border-border bg-card/40 px-3 py-2 text-xs text-muted-foreground flex items-center justify-between">
        <span className="inline-flex items-center gap-1">
          {streamConnected ? (
            <>
              <WifiHigh className="h-4 w-4 text-emerald-500" weight="fill" />
              Live stream active
            </>
          ) : (
            <>
              <WifiSlash className="h-4 w-4 text-rose-500" weight="fill" />
              Live stream disconnected
            </>
          )}
        </span>
        <span>
          Providers: {formatNumber(topProviders.length)} | Agents: {formatNumber(agents.length)} | Events in window:{" "}
          {formatNumber(liveEvents.length)}
        </span>
      </div>
    </div>
  );
}
