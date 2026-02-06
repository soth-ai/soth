"use client";

import { useEffect, useState } from "react";
import {
  Panel,
  PanelGroup,
  PanelResizeHandle,
} from "react-resizable-panels";
import { List, X, Funnel, MagnifyingGlass } from "@phosphor-icons/react";
import { MessageStream, Inspector, Sidebar, CommandBar } from "@/components/observability";
import { useObservabilityStore, type LogEntry } from "@/store/observability";
import { useIsMobile } from "@/hooks/useMobile";
import { cn } from "@/lib/utils";

type MobilePanel = "stream" | "inspector" | "filters";

export default function ObservabilityPage() {
  const { addLog, setConnected, addSession, selectedLogId } = useObservabilityStore();
  const isMobile = useIsMobile();
  const [mobilePanel, setMobilePanel] = useState<MobilePanel>("stream");
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  // Auto-switch to inspector when a log is selected on mobile
  useEffect(() => {
    if (isMobile && selectedLogId) {
      setMobilePanel("inspector");
    }
  }, [isMobile, selectedLogId]);

  // Connect to WebSocket event stream
  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimeout: NodeJS.Timeout | null = null;

    const connect = () => {
      const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const wsUrl = `${wsProtocol}//${window.location.host}/api/events/stream`;
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        console.log("WebSocket connected to event stream");
        setConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);

          // Handle different message types
          switch (data.type) {
            case "event": {
              // Transform WrapEvent to LogEntry
              const wrapEvent = data.event;
              const log: LogEntry = {
                id: wrapEvent.id,
                timestamp: wrapEvent.timestamp,
                session_id: wrapEvent.session_id,
                server_name: wrapEvent.server_name,
                direction: wrapEvent.direction,
                source: wrapEvent.source || "mcp",
                provider: wrapEvent.provider,
                model: wrapEvent.model,
                method: wrapEvent.method,
                tool_name: wrapEvent.tool_name,
                // Use full content if available, fallback to content_preview, then full event
                content: wrapEvent.content || wrapEvent.content_preview || JSON.stringify(wrapEvent, null, 2),
                content_preview: wrapEvent.content_preview,
                agent: wrapEvent.agent || { name: "Unknown", detected_from: "unknown" },
                policy_allowed: wrapEvent.policy_allowed,
                policy_reason: wrapEvent.policy_reason,
                pii_detected: wrapEvent.pii_detected || false,
                pii_types: wrapEvent.pii_types || [],
                token_count: wrapEvent.token_count,
                cost_usd: wrapEvent.cost_usd,
                latency_ms: wrapEvent.latency_ms,
                status_code: wrapEvent.status_code,
                message_type: (wrapEvent.source === "ai_proxy" || wrapEvent.source === "agent_app") ? "raw" : "json-rpc",
              };
              addLog(log);
              break;
            }
            case "session": {
              addSession({
                id: data.session.id,
                name: data.session.name || `Session ${data.session.id.slice(-8)}`,
                server_name: data.session.server_name,
                started_at: data.session.started_at,
                message_count: 0,
                last_activity: data.session.started_at,
              });
              break;
            }
            case "connected": {
              console.log("SOTH event stream:", data.message);
              break;
            }
            default:
              console.log("Unknown message type:", data.type);
          }
        } catch (err) {
          console.error("Failed to parse WebSocket message:", err);
        }
      };

      ws.onclose = () => {
        setConnected(false);
        // Silent reconnect - don't spam console
        reconnectTimeout = setTimeout(connect, 3000);
      };

      ws.onerror = () => {
        // Connection failed - this is expected if backend isn't running
        // Don't log as error to avoid Next.js error overlay
        console.warn("WebSocket connection failed. Is the SOTH backend running?");
        ws?.close();
      };
    };

    connect();

    return () => {
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (ws) ws.close();
    };
  }, [addLog, setConnected, addSession]);

  // Prevent hydration mismatch
  if (!mounted) {
    return <div className="h-screen bg-background" />;
  }

  // Mobile Layout
  if (isMobile) {
    return (
      <div className="h-[calc(100vh-3.5rem-4rem)] bg-background text-foreground overflow-hidden flex flex-col">
        {/* Mobile Tab Bar */}
        <div className="flex items-center border-b border-border bg-card">
          <button
            onClick={() => setMobilePanel("stream")}
            className={cn(
              "flex-1 flex items-center justify-center gap-2 py-3 text-sm font-medium transition-colors",
              mobilePanel === "stream"
                ? "text-accent border-b-2 border-accent"
                : "text-muted-foreground"
            )}
          >
            <List className="h-4 w-4" />
            <span>Stream</span>
          </button>
          <button
            onClick={() => setMobilePanel("inspector")}
            className={cn(
              "flex-1 flex items-center justify-center gap-2 py-3 text-sm font-medium transition-colors relative",
              mobilePanel === "inspector"
                ? "text-accent border-b-2 border-accent"
                : "text-muted-foreground"
            )}
          >
            <MagnifyingGlass className="h-4 w-4" />
            <span>Details</span>
            {selectedLogId && mobilePanel !== "inspector" && (
              <span className="absolute top-2 right-1/4 h-2 w-2 rounded-full bg-accent" />
            )}
          </button>
          <button
            onClick={() => setMobilePanel("filters")}
            className={cn(
              "flex-1 flex items-center justify-center gap-2 py-3 text-sm font-medium transition-colors",
              mobilePanel === "filters"
                ? "text-accent border-b-2 border-accent"
                : "text-muted-foreground"
            )}
          >
            <Funnel className="h-4 w-4" />
            <span>Filters</span>
          </button>
        </div>

        {/* Mobile Content */}
        <div className="flex-1 overflow-hidden">
          {mobilePanel === "stream" && (
            <div className="h-full flex flex-col">
              <CommandBar />
              <div className="flex-1 overflow-hidden">
                <MessageStream />
              </div>
            </div>
          )}
          {mobilePanel === "inspector" && (
            <div className="h-full">
              <Inspector />
            </div>
          )}
          {mobilePanel === "filters" && (
            <div className="h-full overflow-y-auto">
              <Sidebar />
            </div>
          )}
        </div>
      </div>
    );
  }

  // Desktop Layout
  return (
    <div className="h-[calc(100vh-3.5rem)] bg-background text-foreground overflow-hidden flex flex-col">
      {/* Unified Layout */}
      <PanelGroup direction="horizontal" className="flex-1">
        {/* Left Sidebar - Metrics & Filters */}
        <Panel
          defaultSize={18}
          minSize={15}
          maxSize={25}
          className="min-w-[220px]"
        >
          <Sidebar />
        </Panel>

        <PanelResizeHandle className="w-1.5 bg-border hover:bg-accent/50 transition-colors data-[resize-handle-active]:bg-accent" />

        {/* Center - Command Bar + Unified Stream */}
        <Panel defaultSize={52} minSize={35}>
          <div className="flex flex-col h-full">
            <CommandBar />
            <div className="flex-1 overflow-hidden">
              <MessageStream />
            </div>
          </div>
        </Panel>

        <PanelResizeHandle className="w-1.5 bg-border hover:bg-accent/50 transition-colors data-[resize-handle-active]:bg-accent" />

        {/* Right - Inspector */}
        <Panel
          defaultSize={30}
          minSize={25}
          maxSize={45}
          className="min-w-[350px]"
        >
          <Inspector />
        </Panel>
      </PanelGroup>
    </div>
  );
}
