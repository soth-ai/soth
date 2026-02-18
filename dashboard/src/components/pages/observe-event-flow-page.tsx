"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  Panel,
  PanelGroup,
  PanelResizeHandle,
} from "react-resizable-panels";
import { List, Funnel, MagnifyingGlass } from "@phosphor-icons/react";
import { MessageStream, Inspector, Sidebar, CommandBar } from "@/components/observability";
import { useObservabilityStore, type LogEntry } from "@/store/observability";
import { useIsMobile } from "@/hooks/useMobile";
import { useEventStream } from "@/hooks/useEventStream";
import { buildApiUrl } from "@/lib/endpoints";
import type { ApiResponse, EventsSummary, WrapEvent } from "@/types";
import { cn } from "@/lib/utils";

type MobilePanel = "stream" | "inspector" | "filters";
const BOOTSTRAP_LIMIT = 250;

function normalizePayload(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (value === null || value === undefined) {
    return "";
  }
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function normalizePreview(value: unknown): string | undefined {
  const normalized = normalizePayload(value);
  return normalized.length > 0 ? normalized : undefined;
}

function shouldHideNoisyAiWebSocket(wrapEvent: WrapEvent): boolean {
  if (wrapEvent.source !== "ai_proxy") {
    return false;
  }
  const method = (wrapEvent.method || "").toLowerCase();
  if (!method.startsWith("websocket")) {
    return false;
  }
  const provider = (wrapEvent.provider || "unknown").toLowerCase();
  return provider === "unknown";
}

function mapWrapEventToLog(wrapEvent: WrapEvent): LogEntry {
  const derivedInputTokens = wrapEvent.input_tokens;
  const derivedOutputTokens = wrapEvent.output_tokens;
  const derivedTokenCount =
    wrapEvent.token_count ??
    ((derivedInputTokens ?? 0) + (derivedOutputTokens ?? 0) || undefined);

  const content =
    normalizePayload(wrapEvent.content) ||
    normalizePreview(wrapEvent.content_preview) ||
    JSON.stringify(wrapEvent, null, 2);

  const normalizedSource =
    wrapEvent.source === "ai_proxy" && wrapEvent.provider === "mcp"
      ? "mcp"
      : (wrapEvent.source || "mcp");
  const normalizedAgent =
    wrapEvent.agent?.name === "websocket" && wrapEvent.provider
      ? { ...wrapEvent.agent, name: wrapEvent.provider }
      : (wrapEvent.agent || { name: "Unknown", detected_from: "unknown" });

  return {
    id: wrapEvent.id,
    timestamp: wrapEvent.timestamp,
    session_id: wrapEvent.session_id,
    server_name: wrapEvent.server_name,
    direction: wrapEvent.direction,
    source: normalizedSource,
    provider: wrapEvent.provider,
    model: wrapEvent.model,
    method: wrapEvent.method,
    tool_name: wrapEvent.tool_name,
    content,
    content_ref: wrapEvent.content_ref,
    content_preview: normalizePreview(wrapEvent.content_preview),
    request_content: normalizePreview(wrapEvent.request_content),
    request_content_ref: wrapEvent.request_content_ref,
    request_preview: normalizePreview(wrapEvent.request_preview),
    response_content: normalizePreview(wrapEvent.response_content),
    response_content_ref: wrapEvent.response_content_ref,
    response_preview: normalizePreview(wrapEvent.response_preview),
    status_code: wrapEvent.status_code,
    agent: normalizedAgent,
    policy_allowed: wrapEvent.policy_allowed,
    policy_reason: wrapEvent.policy_reason,
    pii_detected: wrapEvent.pii_detected || false,
    pii_types: wrapEvent.pii_types || [],
    token_count: derivedTokenCount,
    input_tokens: derivedInputTokens,
    output_tokens: derivedOutputTokens,
    cache_read_tokens: wrapEvent.cache_read_tokens,
    cache_write_tokens: wrapEvent.cache_write_tokens,
    reasoning_tokens: wrapEvent.reasoning_tokens,
    request_size_bytes: wrapEvent.request_size_bytes,
    response_size_bytes: wrapEvent.response_size_bytes,
    headers: wrapEvent.headers,
    tags: wrapEvent.tags,
    cost_usd: wrapEvent.cost_usd,
    latency_ms: wrapEvent.latency_ms,
    message_type:
      wrapEvent.source === "ai_proxy" || wrapEvent.source === "agent_app"
        ? "raw"
        : "json-rpc",
  };
}

export default function ObservabilityPage() {
  const addLogsBatch = useObservabilityStore((state) => state.addLogsBatch);
  const setConnected = useObservabilityStore((state) => state.setConnected);
  const applyPreset = useObservabilityStore((state) => state.applyPreset);
  const selectedLogId = useObservabilityStore((state) => state.selectedLogId);
  const streamCursorSeq = useObservabilityStore((state) => state.streamCursorSeq);
  const advanceStreamCursor = useObservabilityStore((state) => state.advanceStreamCursor);
  const searchParams = useSearchParams();
  const isMobile = useIsMobile();
  const [mobilePanel, setMobilePanel] = useState<MobilePanel>("stream");
  const [mounted, setMounted] = useState(false);
  const appliedPresetFromQueryRef = useRef<string | null>(null);

  useEffect(() => {
    setMounted(true);
  }, []);

  // Auto-switch to inspector when a log is selected on mobile
  useEffect(() => {
    if (isMobile && selectedLogId) {
      setMobilePanel("inspector");
    }
  }, [isMobile, selectedLogId]);

  const handleWrapEvents = useCallback(
    (wrapEvents: WrapEvent[]) => {
      if (!wrapEvents.length) return;
      const visibleEvents = wrapEvents.filter(
        (wrapEvent) => !shouldHideNoisyAiWebSocket(wrapEvent)
      );
      if (visibleEvents.length > 0) {
        addLogsBatch(visibleEvents.map(mapWrapEventToLog));
      }

      let maxSeq: number | null = null;
      for (const wrapEvent of wrapEvents) {
        if (typeof wrapEvent.seq === "number") {
          maxSeq = maxSeq === null ? wrapEvent.seq : Math.max(maxSeq, wrapEvent.seq);
        }
      }
      if (maxSeq !== null) {
        advanceStreamCursor(maxSeq);
      }
    },
    [addLogsBatch, advanceStreamCursor]
  );

  const { isConnected: wsConnected } = useEventStream({
    enabled: mounted,
    sinceSeq: streamCursorSeq,
    captureEvents: false,
    onEvents: handleWrapEvents,
  });

  useEffect(() => {
    setConnected(wsConnected);
  }, [wsConnected, setConnected]);

  useEffect(() => {
    if (!mounted) {
      return;
    }
    const presetParam = searchParams.get("preset");
    if (!presetParam) {
      return;
    }
    const resolvedPreset = presetParam === "pii" ? "builtin-pii-alerts" : presetParam;
    if (appliedPresetFromQueryRef.current === resolvedPreset) {
      return;
    }
    applyPreset(resolvedPreset);
    appliedPresetFromQueryRef.current = resolvedPreset;
  }, [mounted, searchParams, applyPreset]);

  // Bootstrap with recent snapshot before relying on live stream updates.
  useEffect(() => {
    if (!mounted) {
      return;
    }

    let cancelled = false;

    const loadBootstrap = async () => {
      try {
        const response = await fetch(
          buildApiUrl(`/events?limit=${BOOTSTRAP_LIMIT}`),
          { cache: "no-store" }
        );
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }

        const payload = (await response.json()) as ApiResponse<EventsSummary>;
        const bootstrapEvents = [...payload.data.events].reverse();

        if (cancelled || bootstrapEvents.length === 0) {
          return;
        }
        handleWrapEvents(bootstrapEvents);
      } catch (error) {
        console.warn("Failed to load initial event snapshot", error);
      }
    };

    loadBootstrap();

    return () => {
      cancelled = true;
    };
  }, [mounted, handleWrapEvents]);

  // Prevent hydration mismatch
  if (!mounted) {
    return <div className="h-screen bg-background" />;
  }

  // Mobile Layout
  if (isMobile) {
    return (
      <div className="h-[100dvh] bg-background text-foreground overflow-hidden flex flex-col">
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
    <div className="h-[100dvh] bg-background text-foreground overflow-hidden flex flex-col relative">
      {/* Premium Controls Floating Bar (Optional, but let's integrate into unified layout) */}

      <PanelGroup direction="horizontal" className="flex-1">
        {/* Left Sidebar - Metrics & Filters */}
        <Panel
          defaultSize={15}
          minSize={10}
          maxSize={25}
          collapsible={true}
          className="min-w-[180px] transition-all duration-300 ease-in-out"
        >
          <Sidebar />
        </Panel>

        <PanelResizeHandle className="group relative w-px bg-border hover:bg-accent/50 transition-colors data-[resize-handle-active]:bg-primary">
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 flex items-center justify-center">
            <div className="w-1.5 h-8 rounded-full bg-border group-hover:bg-primary/50 transition-colors" />
          </div>
        </PanelResizeHandle>

        {/* Center - Command Bar + Unified Stream */}
        <Panel defaultSize={60} minSize={30}>
          <div className="flex flex-col h-full bg-card/30 backdrop-blur-sm border-x border-border/50">
            <CommandBar />
            <div className="flex-1 overflow-hidden">
              <div className="h-full scrollbar-thin scrollbar-thumb-border scrollbar-track-transparent">
                <MessageStream />
              </div>
            </div>
          </div>
        </Panel>

        <PanelResizeHandle className="group relative w-px bg-border hover:bg-accent/50 transition-colors data-[resize-handle-active]:bg-primary">
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 flex items-center justify-center">
            <div className="w-1.5 h-8 rounded-full bg-border group-hover:bg-primary/50 transition-colors" />
          </div>
        </PanelResizeHandle>

        {/* Right - Inspector */}
        <Panel
          defaultSize={25}
          minSize={20}
          maxSize={45}
          className="min-w-[300px]"
        >
          <Inspector />
        </Panel>
      </PanelGroup>
    </div>
  );
}
