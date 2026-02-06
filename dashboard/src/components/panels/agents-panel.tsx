"use client";

import { Robot, HardDrive, Clock } from "@phosphor-icons/react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, formatNumber } from "@/lib/utils";
import type { AgentsSummary, AgentStats } from "@/types";

interface AgentsPanelProps {
  data: AgentsSummary | undefined;
  isLoading: boolean;
}

function formatLastSeen(timestamp: string): string {
  try {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffSecs = Math.floor(diffMs / 1000);

    if (diffSecs < 60) return "just now";
    if (diffSecs < 3600) return `${Math.floor(diffSecs / 60)}m ago`;
    if (diffSecs < 86400) return `${Math.floor(diffSecs / 3600)}h ago`;
    return `${Math.floor(diffSecs / 86400)}d ago`;
  } catch {
    return "-";
  }
}

function AgentRow({ agent }: { agent: AgentStats }) {
  return (
    <div className="py-3 border-b border-border last:border-0">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Robot className="h-4 w-4 text-accent" weight="duotone" />
          <span className="font-medium">{agent.name}</span>
          {agent.version && (
            <span className="text-xs text-muted-foreground">v{agent.version}</span>
          )}
        </div>
        <span className="font-semibold tabular-nums">{formatNumber(agent.event_count)}</span>
      </div>

      <div className="mt-1.5 flex items-center gap-4 text-xs text-muted-foreground">
        <span className="flex items-center gap-1">
          <Clock className="h-3 w-3" />
          {formatLastSeen(agent.last_seen)}
        </span>
        <span className="flex items-center gap-1">
          <HardDrive className="h-3 w-3" />
          {agent.servers.length} server{agent.servers.length !== 1 ? "s" : ""}
        </span>
        <span className="capitalize">{agent.detected_from.replace(/_/g, " ")}</span>
      </div>

      {agent.servers.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {agent.servers.slice(0, 5).map((server) => (
            <span
              key={server}
              className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-muted text-muted-foreground"
            >
              {server}
            </span>
          ))}
          {agent.servers.length > 5 && (
            <span className="text-xs text-muted-foreground">
              +{agent.servers.length - 5} more
            </span>
          )}
        </div>
      )}
    </div>
  );
}

export function AgentsPanel({ data, isLoading }: AgentsPanelProps) {
  if (isLoading) {
    return (
      <Card className="animate-fade-in">
        <CardHeader>
          <CardTitle>
            <Robot className="h-4 w-4 text-accent" weight="duotone" />
            Agents
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {[...Array(3)].map((_, i) => (
              <Skeleton key={i} className="h-16 w-full" />
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!data) {
    return null;
  }

  return (
    <Card className="animate-slide-up">
      <CardHeader>
        <CardTitle>
          <Robot className="h-4 w-4 text-accent" weight="duotone" />
          Agents
          <span className="ml-auto text-xs font-normal text-muted-foreground">
            {data.total_agents} detected
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {data.agents.length === 0 ? (
          <div className="py-8 text-center text-muted-foreground text-sm">
            <Robot className="h-8 w-8 mx-auto mb-2 opacity-50" />
            <p>No agents detected yet</p>
            <p className="text-xs mt-1">
              Agents are detected from MCP initialize messages
            </p>
          </div>
        ) : (
          <div className="space-y-0">
            {data.agents.map((agent) => (
              <AgentRow key={agent.name} agent={agent} />
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
