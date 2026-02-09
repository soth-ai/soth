"use client";

import { Robot, HardDrive, Clock } from "@phosphor-icons/react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, formatNumber } from "@/lib/utils";
import { motion } from "framer-motion";
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
    <motion.div
      initial={{ opacity: 0, x: 10 }}
      animate={{ opacity: 1, x: 0 }}
      className="py-4 border-b border-white/[0.04] last:border-0 group"
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-accent/5 border border-accent/10">
            <Robot className="h-4 w-4 text-accent" weight="duotone" />
          </div>
          <div className="flex flex-col">
            <span className="font-bold tracking-tight text-foreground/90">{agent.name}</span>
            {agent.version && (
              <span className="text-[10px] font-bold text-muted-foreground/40 uppercase tracking-widest">v{agent.version}</span>
            )}
          </div>
        </div>
        <div className="text-right">
          <span className="text-[14px] font-bold tabular-nums text-foreground/80">{formatNumber(agent.event_count)}</span>
          <p className="text-[9px] font-bold text-muted-foreground/30 uppercase tracking-[0.1em]">events</p>
        </div>
      </div>

      <div className="mt-3 flex items-center gap-4 text-[11px] font-medium text-muted-foreground/60">
        <span className="flex items-center gap-1.5">
          <Clock className="h-3.5 w-3.5 opacity-40" />
          {formatLastSeen(agent.last_seen)}
        </span>
        <span className="flex items-center gap-1.5">
          <HardDrive className="h-3.5 w-3.5 opacity-40" />
          {agent.servers.length} NODE{agent.servers.length !== 1 ? "S" : ""}
        </span>
      </div>

      {agent.servers.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {agent.servers.slice(0, 3).map((server) => (
            <span
              key={server}
              className="inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-bold tracking-wider bg-white/[0.03] border border-white/[0.04] text-muted-foreground/60"
            >
              {server.toUpperCase()}
            </span>
          ))}
          {agent.servers.length > 3 && (
            <span className="text-[10px] font-bold text-muted-foreground/30 px-1">
              +{agent.servers.length - 3} MORE
            </span>
          )}
        </div>
      )}
    </motion.div>
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
    <Card className="glass-panel border-white/[0.04] overflow-hidden">
      <CardHeader className="px-6 py-4 border-b border-white/[0.04] bg-white/[0.01]">
        <CardTitle className="text-[14px] font-bold tracking-tight">
          <Robot className="h-4 w-4 text-accent" weight="duotone" />
          Agents
          <span className="ml-auto text-[10px] font-bold text-muted-foreground/40 uppercase tracking-widest bg-muted/30 px-2 py-0.5 rounded">
            {data.total_agents} DETECTED
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="px-6">
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
