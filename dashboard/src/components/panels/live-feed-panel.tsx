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
    <div
      className={cn(
        "flex items-center gap-3 py-2 px-3 text-sm border-b border-border last:border-0",
        "hover:bg-muted/50 transition-colors"
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
      <span className="text-muted-foreground font-mono text-xs w-14 text-right shrink-0">
        {event.latency_ms ? `${event.latency_ms}ms` : "-"}
      </span>
    </div>
  );
}

export function LiveFeedPanel({ events, isConnected, onClear }: LiveFeedPanelProps) {
  return (
    <Card className="col-span-2 animate-fade-in">
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <CardTitle>
          <Waveform className="h-4 w-4 text-accent" weight="duotone" />
          Live Feed
          <span
            className={cn(
              "ml-2 h-2 w-2 rounded-full",
              isConnected ? "bg-success animate-pulse" : "bg-destructive"
            )}
          />
        </CardTitle>
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">
            {events.length} events
          </span>
          <button
            onClick={onClear}
            className="p-1 hover:bg-muted rounded transition-colors"
            title="Clear events"
          >
            <Trash className="h-4 w-4 text-muted-foreground" />
          </button>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        {/* Header */}
        <div className="flex items-center gap-3 py-2 px-3 text-xs font-medium text-muted-foreground border-b border-border bg-muted/30">
          <span className="w-16 shrink-0">TIME</span>
          <span className="w-5 shrink-0">DIR</span>
          <span className="w-28 shrink-0">AGENT</span>
          <span className="flex-1">METHOD</span>
          <span className="w-6 shrink-0 text-center">OK</span>
          <span className="w-6 shrink-0 text-center">PII</span>
          <span className="w-14 shrink-0 text-right">LATENCY</span>
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
