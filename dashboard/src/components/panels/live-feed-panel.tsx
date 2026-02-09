"use client";

import {
  Waveform,
  ArrowRight,
  ArrowLeft,
  Warning,
  Check,
  X,
  Trash,
} from "@phosphor-icons/react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { WrapEvent } from "@/types";
import { motion, AnimatePresence } from "framer-motion";

interface LiveFeedPanelProps {
  events: WrapEvent[];
  isConnected: boolean;
  onClear: () => void;
}

function formatTime(timestamp: string): string {
  try {
    const date = new Date(timestamp);
    return date.toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch {
    return "-";
  }
}

function EventRow({ event }: { event: WrapEvent }) {
  const isInbound = event.direction === "in";

  const methodDisplay = event.tool_name
    ? `${event.server_name}/${event.tool_name}`
    : event.method || "-";

  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      className={cn(
        "flex items-center gap-4 py-2.5 px-4 text-sm border-b border-white/[0.04] last:border-0",
        "hover:bg-white/[0.02] transition-colors group"
      )}
    >
      {/* Time */}
      <span className="text-muted-foreground font-mono text-xs w-16 shrink-0">
        {formatTime(event.timestamp)}
      </span>

      {/* Direction */}
      <div className="w-5 shrink-0">
        {isInbound ? (
          <ArrowRight className="h-4 w-4 text-success" weight="bold" />
        ) : (
          <ArrowLeft className="h-4 w-4 text-accent" weight="bold" />
        )}
      </div>

      {/* Agent */}
      <span className="text-muted-foreground w-28 truncate shrink-0" title={event.agent?.name || "Unknown"}>
        {event.agent?.name || "Unknown"}
      </span>

      {/* Method/Tool */}
      <span className="font-medium truncate flex-1 min-w-0" title={methodDisplay}>
        {methodDisplay}
      </span>

      {/* Policy Status */}
      <div className="w-6 shrink-0 flex justify-center">
        {event.policy_allowed === true && (
          <Check className="h-4 w-4 text-success" weight="bold" />
        )}
        {event.policy_allowed === false && (
          <X className="h-4 w-4 text-destructive" weight="bold" />
        )}
      </div>

      {/* PII Warning */}
      <div className="w-6 shrink-0 flex justify-center">
        {event.pii_detected && (
          <span title={event.pii_types.join(", ")}>
            <Warning className="h-4 w-4 text-warning" weight="fill" />
          </span>
        )}
      </div>

      {/* Latency */}
      <span className="text-muted-foreground/60 font-mono text-[11px] w-14 text-right shrink-0 tabular-nums">
        {event.latency_ms ? `${event.latency_ms}ms` : "-"}
      </span>
    </motion.div>
  );
}

export function LiveFeedPanel({ events, isConnected, onClear }: LiveFeedPanelProps) {
  return (
    <Card className="col-span-2 glass-panel border-white/[0.04] overflow-hidden">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 px-6 py-4">
        <CardTitle className="text-[14px] font-bold tracking-tight">
          <Waveform className="h-4 w-4 text-accent" weight="duotone" />
          Live Feed
          <span
            className={cn(
              "ml-2.5 h-1.5 w-1.5 rounded-full inline-block mb-0.5",
              isConnected ? "bg-success shadow-[0_0_8px_rgba(16,185,129,0.5)] animate-pulse" : "bg-destructive"
            )}
          />
        </CardTitle>
        <div className="flex items-center gap-3">
          <span className="text-[11px] font-bold text-muted-foreground/50 uppercase tracking-widest bg-muted/30 px-2 py-0.5 rounded">
            {events.length} EVENTS
          </span>
          <button
            onClick={onClear}
            className="p-1.5 hover:bg-white/[0.05] rounded-full transition-all text-muted-foreground/40 hover:text-muted-foreground"
            title="Clear events"
          >
            <Trash className="h-4 w-4" />
          </button>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        {/* Header */}
        <div className="flex items-center gap-4 py-2 px-4 text-[10px] font-bold tracking-widest text-muted-foreground/40 uppercase border-y border-white/[0.04] bg-white/[0.01]">
          <span className="w-16 shrink-0">TIME</span>
          <span className="w-5 shrink-0 text-center">DIR</span>
          <span className="w-28 shrink-0">AGENT</span>
          <span className="flex-1">TRANSACTION / TOOL</span>
          <span className="w-6 shrink-0 text-center">OK</span>
          <span className="w-6 shrink-0 text-center">PII</span>
          <span className="w-14 shrink-0 text-right">MS</span>
        </div>

        {/* Events list */}
        <div className="max-h-[400px] overflow-y-auto">
          {events.length === 0 ? (
            <div className="py-12 text-center text-muted-foreground text-sm">
              {isConnected ? (
                <>
                  <Waveform className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>Waiting for events...</p>
                  <p className="text-xs mt-1">
                    Use <code className="font-mono">soth wrap</code> to start capturing traffic
                  </p>
                </>
              ) : (
                <>
                  <Waveform className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>Connecting to event stream...</p>
                  <p className="text-xs mt-1">
                    Make sure the dashboard API is running on port 3001
                  </p>
                </>
              )}
            </div>
          ) : (
            events.map((event, index) => (
              <EventRow key={`${event.id}-${event.timestamp}-${index}`} event={event} />
            ))
          )}
        </div>
      </CardContent>
    </Card>
  );
}
