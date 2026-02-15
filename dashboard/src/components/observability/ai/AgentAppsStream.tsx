"use client";

import { useEffect, useRef, memo, useState, useCallback, useMemo } from "react";
import { Virtuoso, VirtuosoHandle } from "react-virtuoso";
import {
  ArrowDown,
  ArrowUp,
  MagnifyingGlass,
  X,
  Pause,
  Play,
  Copy,
  Funnel,
  Robot,
} from "@phosphor-icons/react";
import { toast } from "sonner";
import {
  useObservabilityStore,
  decodeSmartDisplayText,
  hasPairedPayload,
  getLogPath,
  matchesServerFilter,
  normalizeServerName,
  type LogEntry,
  type Filters,
} from "@/store/observability";
import { cn, formatTimestamp, formatLatency } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  OBSERVABILITY_SCROLL_SEEK_CONFIG,
  OBSERVABILITY_VIRTUOSO_COMPONENTS,
} from "@/components/observability/ScrollSeekPlaceholder";

// Helper function to filter agent app logs
function filterAgentLogs(logs: LogEntry[], filters: Filters): LogEntry[] {
  return logs.filter((log) => {
    // Only agent app logs
    if (log.source !== "agent_app") return false;

    if (filters.sessionId && log.session_id !== filters.sessionId) return false;
    if (filters.searchText) {
      const search = filters.searchText.toLowerCase();
      const searchableContent = (
        log.request_preview ||
        log.response_preview ||
        log.content_preview ||
        log.content ||
        ""
      ).slice(0, 2048);
      const matchesContent = searchableContent.toLowerCase().includes(search);
      const matchesProvider = log.provider?.toLowerCase().includes(search);
      const matchesModel = log.model?.toLowerCase().includes(search);
      const matchesMethod = log.method?.toLowerCase().includes(search);
      const matchesServer = log.server_name?.toLowerCase().includes(search);
      const matchesAgent = log.agent?.name?.toLowerCase().includes(search);
      if (
        !matchesContent &&
        !matchesProvider &&
        !matchesModel &&
        !matchesMethod &&
        !matchesServer &&
        !matchesAgent
      ) {
        return false;
      }
    }
    // Accept either provider name (agent filter behavior) or host name (hot-host filters)
    if (filters.serverName) {
      const selected = normalizeServerName(filters.serverName);
      const provider = normalizeServerName(log.provider);
      const providerMatches = provider.length > 0 && provider === selected;
      const hostMatches = matchesServerFilter(log.server_name, filters.serverName);
      if (!providerMatches && !hostMatches) return false;
    }
    if (filters.path && getLogPath(log) !== filters.path) return false;
    if (filters.direction && log.direction !== filters.direction) return false;
    // For agent traffic, filter by model using method filter
    if (filters.method && log.model !== filters.method) return false;
    if (filters.minLatencyMs && log.latency_ms !== undefined) {
      if (log.latency_ms < filters.minLatencyMs) return false;
    }
    return true;
  });
}

interface AgentLogRowProps {
  log: LogEntry;
  index: number;
}

const PREVIEW_DECODE_LIMIT = 4096;

function decodePreviewText(preview?: string, raw?: string): string {
  if (preview && preview.length > 0) {
    return decodeSmartDisplayText(preview);
  }
  if (!raw) {
    return "";
  }
  return decodeSmartDisplayText(raw.slice(0, PREVIEW_DECODE_LIMIT));
}

// Helper functions
const getLatencyColor = (ms: number) => {
  if (ms >= 2000) return "text-red-500";
  if (ms >= 500) return "text-amber-500";
  if (ms >= 100) return "text-muted-foreground";
  return "text-muted-foreground/70";
};

// Get agent app color (purple theme for agents)
const getAgentColor = (agentName: string | undefined, serverName: string, model?: string) => {
  const normalizedAgent = (agentName || "").toLowerCase();
  const normalizedModel = (model || "").toLowerCase();
  const name = serverName.toLowerCase();

  if (normalizedModel.includes("codex") || normalizedAgent.includes("codex")) {
    return "bg-sky-500/20 text-sky-500 border-sky-500/30";
  }
  if (normalizedAgent.includes("chatgpt")) {
    return "bg-emerald-500/20 text-emerald-500 border-emerald-500/30";
  }
  if (normalizedAgent.includes("claude")) {
    return "bg-orange-500/20 text-orange-500 border-orange-500/30";
  }
  // OpenAI/ChatGPT - emerald green
  if (name.includes("chatgpt") || (name.includes("openai.com") && !name.startsWith("api."))) {
    return "bg-emerald-500/20 text-emerald-500 border-emerald-500/30";
  }
  // Anthropic/Claude - orange
  if (name.includes("claude") || (name.includes("anthropic.com") && !name.startsWith("api."))) {
    return "bg-orange-500/20 text-orange-500 border-orange-500/30";
  }
  // Perplexity - cyan
  if (name.includes("perplexity")) {
    return "bg-cyan-500/20 text-cyan-500 border-cyan-500/30";
  }
  // Google - blue
  if (name.includes("google") || name.includes("aistudio") || name.includes("makersuite")) {
    return "bg-blue-500/20 text-blue-500 border-blue-500/30";
  }
  return "bg-purple-500/20 text-purple-500 border-purple-500/30";
};

const getStatusCodeColor = (code: number) => {
  if (code >= 400) return "bg-red-500/20 text-red-500 border-red-500/30";
  if (code >= 300) return "bg-amber-500/20 text-amber-500 border-amber-500/30";
  return "bg-emerald-500/20 text-emerald-500 border-emerald-500/30";
};

// Get friendly agent name. Prefer backend-detected agent, fallback to host heuristics.
const getAgentName = (log: LogEntry): string => {
  const modelLower = log.model?.trim().toLowerCase();
  if (modelLower?.includes("codex")) {
    return "Codex";
  }

  const detected = log.agent?.name?.trim().toLowerCase();
  if (detected) {
    if (detected === "codex") return "Codex";
    if (detected === "chatgpt") return "ChatGPT";
    if (detected === "claude") return "Claude";
    if (detected === "claude-code") return "Claude Code";
    if (detected === "openai") return "OpenAI";
    return log.agent.name;
  }

  const name = log.server_name.toLowerCase();
  // OpenAI/ChatGPT apps
  if (name.includes("chatgpt") || (name.includes("openai.com") && !name.startsWith("api."))) {
    return "ChatGPT";
  }
  // Claude apps
  if (name.includes("claude.ai") || (name.includes("anthropic.com") && !name.startsWith("api."))) {
    return "Claude";
  }
  if (name.includes("perplexity")) return "Perplexity";
  if (name.includes("aistudio") || name.includes("makersuite")) return "AI Studio";
  // Return domain without common prefixes
  return log.server_name.replace(/^(www\.|app\.|chat\.)/i, "");
};

const AgentLogRow = memo(function AgentLogRow({ log, index }: AgentLogRowProps) {
  const selectedLogId = useObservabilityStore((state) => state.selectedLogId);
  const selectedLogPart = useObservabilityStore((state) => state.selectedLogPart);
  const selectLog = useObservabilityStore((state) => state.selectLog);
  const [isHovered, setIsHovered] = useState(false);
  const isSelected = selectedLogId === log.id;
  const rowRef = useRef<HTMLDivElement>(null);

  const isError = log.policy_allowed === false;
  const isPairedEvent = hasPairedPayload(log);

  // Copy JSON to clipboard
  const handleCopyJson = useCallback((e: React.MouseEvent, content: string) => {
    e.stopPropagation();
    navigator.clipboard.writeText(content);
    toast.success("Copied to clipboard", { duration: 2000 });
  }, []);

  // Scroll into view when selected
  useEffect(() => {
    if (isSelected && rowRef.current) {
      rowRef.current.scrollIntoView({ block: "nearest", behavior: "auto" });
    }
  }, [isSelected]);

  // Parse method for display
  const displayMethod = log.method?.split(" ").slice(0, 2).join(" ") || "request";
  const agentName = getAgentName(log);
  const requestPreview = useMemo(
    () => decodePreviewText(log.request_preview, log.request_content),
    [log.request_preview, log.request_content]
  );
  const responsePreview = useMemo(
    () => {
      const raw = log.response_content || log.response_preview || "";
      if (raw) {
        return decodePreviewText(log.response_preview, log.response_content);
      }

      const method = log.method || "request";
      const status = log.status_code ?? "unknown";
      if (method.toLowerCase().includes("/backend-api/codex/responses")) {
        return `[no HTTP response body captured for ${method} (HTTP ${status}) - Codex output may be streamed via WebSocket]`;
      }
      return `[no HTTP response body captured for ${method} (HTTP ${status})]`;
    },
    [log.response_preview, log.response_content, log.method, log.status_code]
  );
  const contentPreview = useMemo(
    () => decodePreviewText(log.content_preview, log.content),
    [log.content_preview, log.content]
  );

  // For paired events, render two connected rows
  if (isPairedEvent) {
    const requestIsSelected = isSelected && selectedLogPart !== "response";
    const responseIsSelected = isSelected && selectedLogPart === "response";

    return (
      <div
        ref={rowRef}
        className={cn(
          "group relative border-l-2 transition-all duration-150",
          isSelected ? "border-l-purple-500 bg-purple-500/5" : "border-l-muted-foreground/30 hover:border-l-purple-500/50 hover:bg-muted/20",
        )}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
      >
        {/* Request Row */}
        <div
          onClick={() => selectLog(log.id, "request")}
          className={cn(
            "flex items-center gap-3 px-4 h-8 cursor-pointer border-b border-border/50",
            requestIsSelected && "bg-cyan-500/5"
          )}
        >
          {/* Status Dot */}
          <div className="flex-shrink-0">
            <div className={cn("w-2 h-2 rounded-full bg-cyan-500", requestIsSelected && "ring-2 ring-purple-500/50")} />
          </div>

          {/* Timestamp */}
          <span className="text-xs text-muted-foreground font-mono w-24 flex-shrink-0 tabular-nums">
            {formatTimestamp(log.timestamp)}
          </span>

          {/* Direction Icon */}
          <ArrowUp className="w-3 h-3 text-cyan-500 flex-shrink-0" weight="bold" />

          {/* Agent Badge */}
          <span
            className={cn(
              "inline-flex items-center gap-1 px-1.5 py-0.5 rounded-md text-[10px] font-mono font-medium flex-shrink-0 min-w-[70px] max-w-[100px] truncate border",
              getAgentColor(log.agent?.name, log.server_name, log.model)
            )}
          >
            <Robot className="w-3 h-3" weight="fill" />
            {agentName}
          </span>

          {/* Model (if available) */}
          {log.model && (
            <span className="text-xs text-muted-foreground font-mono w-32 truncate flex-shrink-0">
              {log.model}
            </span>
          )}

          {/* Method - truncated, full on hover */}
          <span
            className={cn(
              "inline-flex items-center px-1.5 py-0.5 rounded-md text-xs font-mono font-medium bg-secondary text-secondary-foreground border border-border",
              isHovered ? "flex-shrink-0" : "flex-shrink-0 max-w-[140px] truncate"
            )}
            title={log.method || ""}
          >
            {displayMethod}
          </span>

          {/* Request Preview */}
          <span className="text-xs text-cyan-600 dark:text-cyan-400 flex-1 min-w-0 font-mono overflow-hidden whitespace-nowrap">
            {requestPreview}
          </span>

          {/* Copy button */}
          {isHovered && (
            <Button
              variant="ghost"
              size="sm"
              onClick={(e) => handleCopyJson(e, log.request_content || log.request_preview || "")}
              className="h-6 w-6 p-0 bg-secondary border border-border hover:bg-muted"
              title="Copy request"
            >
              <Copy className="w-3 h-3 text-muted-foreground" />
            </Button>
          )}
        </div>

        {/* Response Row */}
        <div
          onClick={() => selectLog(log.id, "response")}
          className={cn(
            "flex items-center gap-3 px-4 h-8 cursor-pointer border-b border-border",
            responseIsSelected && "bg-emerald-500/5"
          )}
        >
          {/* Status Dot */}
          <div className="flex-shrink-0">
            <div className={cn(
              "w-2 h-2 rounded-full",
              log.status_code && log.status_code >= 400 ? "bg-red-500" : "bg-emerald-500",
              responseIsSelected && "ring-2 ring-purple-500/50"
            )} />
          </div>

          {/* Latency as timestamp placeholder */}
          <span className="text-xs text-muted-foreground font-mono w-24 flex-shrink-0 tabular-nums">
            {log.latency_ms !== undefined ? `+${formatLatency(log.latency_ms)}` : ""}
          </span>

          {/* Direction Icon */}
          <ArrowDown className="w-3 h-3 text-emerald-500 flex-shrink-0" weight="bold" />

          {/* Status Code */}
          {log.status_code && (
            <span className={cn(
              "inline-flex items-center px-1.5 py-0.5 rounded-md text-[10px] font-mono font-semibold flex-shrink-0 border",
              getStatusCodeColor(log.status_code)
            )}>
              {log.status_code}
            </span>
          )}

          {/* Spacer to align with request row */}
          {log.model && <span className="w-32 flex-shrink-0" />}

          {/* Response label */}
          <span className="inline-flex items-center px-1.5 py-0.5 rounded-md text-xs font-mono font-medium flex-shrink-0 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
            response
          </span>

          {/* Response Preview */}
          <span className="text-xs text-emerald-600 dark:text-emerald-400 flex-1 min-w-0 font-mono overflow-hidden whitespace-nowrap">
            {responsePreview}
          </span>

          {/* Policy indicator */}
          {log.policy_allowed === false && (
            <span className="text-[10px] font-mono flex-shrink-0 px-1.5 py-0.5 rounded bg-red-500/20 text-red-500">
              DENIED
            </span>
          )}

          {/* PII indicator */}
          {log.pii_detected && (
            <span className="text-[10px] font-mono flex-shrink-0 px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-500">
              PII
            </span>
          )}

          {/* Copy button */}
          {isHovered && (
            <Button
              variant="ghost"
              size="sm"
              onClick={(e) => handleCopyJson(e, log.response_content || log.response_preview || responsePreview || "")}
              className="h-6 w-6 p-0 bg-secondary border border-border hover:bg-muted"
              title="Copy response"
            >
              <Copy className="w-3 h-3 text-muted-foreground" />
            </Button>
          )}
        </div>
      </div>
    );
  }

  // Single row for non-paired events (original behavior)
  const getStatusColor = () => {
    if (isError) return "bg-red-500";
    if (log.status_code && log.status_code >= 400) return "bg-red-500";
    if (log.pii_detected) return "bg-orange-500";
    if (log.latency_ms && log.latency_ms >= 2000) return "bg-amber-500";
    if (log.direction === "in") return "bg-cyan-500";
    return "bg-purple-500";
  };

  return (
    <div
      ref={rowRef}
      tabIndex={isSelected ? 0 : -1}
      role="button"
      onClick={() => selectLog(log.id)}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className={cn(
        "group relative flex items-center gap-3 px-4 h-8 cursor-pointer border-b border-border transition-all duration-150",
        "hover:bg-muted/40",
        isSelected && "border-l-2 border-l-purple-500 bg-purple-500/10",
        isError && !isSelected && "border-l-2 border-l-red-500 bg-red-500/5",
        !isSelected && !isError && "border-l-2 border-l-transparent",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-purple-500 focus-visible:ring-offset-2"
      )}
    >
      {/* Status Dot */}
      <div className="flex-shrink-0">
        <div
          className={cn(
            "w-2 h-2 rounded-full transition-all",
            getStatusColor(),
            isSelected && "ring-2 ring-purple-500/50"
          )}
        />
      </div>

      {/* Timestamp */}
      <span className="text-xs text-muted-foreground font-mono w-24 flex-shrink-0 tabular-nums">
        {formatTimestamp(log.timestamp)}
      </span>

      {/* Direction Icon */}
      <div className="flex-shrink-0">
        {log.direction === "in" ? (
          <ArrowUp className="w-3 h-3 text-cyan-500" weight="bold" />
        ) : (
          <ArrowDown className="w-3 h-3 text-purple-500" weight="bold" />
        )}
      </div>

      {/* Agent Badge */}
      <span
        className={cn(
          "inline-flex items-center gap-1 px-1.5 py-0.5 rounded-md text-[10px] font-mono font-medium flex-shrink-0 min-w-[70px] max-w-[100px] truncate border",
          getAgentColor(log.agent?.name, log.server_name, log.model)
        )}
        title={log.server_name}
      >
        <Robot className="w-3 h-3" weight="fill" />
        {agentName}
      </span>

      {/* Model (if available) */}
      {log.model && (
        <span
          className="text-xs text-muted-foreground font-mono w-32 truncate flex-shrink-0"
          title={log.model}
        >
          {log.model}
        </span>
      )}

      {/* Method - truncated, full on hover */}
      <span
        className={cn(
          "inline-flex items-center px-1.5 py-0.5 rounded-md text-xs font-mono font-medium bg-secondary text-secondary-foreground border border-border",
          isHovered ? "flex-shrink-0" : "flex-shrink-0 max-w-[140px] truncate"
        )}
        title={log.method || ""}
      >
        {displayMethod}
      </span>

      {/* Status Code (for paired events) */}
      {log.status_code && (
        <span
          className={cn(
            "inline-flex items-center px-1.5 py-0.5 rounded-md text-[10px] font-mono font-semibold flex-shrink-0 border",
            log.status_code >= 400
              ? "bg-red-500/20 text-red-500 border-red-500/30"
              : log.status_code >= 300
              ? "bg-amber-500/20 text-amber-500 border-amber-500/30"
              : "bg-emerald-500/20 text-emerald-500 border-emerald-500/30"
          )}
        >
          {log.status_code}
        </span>
      )}

      {/* Content Preview */}
      <span className="text-xs text-muted-foreground flex-1 min-w-0 font-mono overflow-hidden whitespace-nowrap">
        {contentPreview}
      </span>

      {/* Policy indicator */}
      {log.policy_allowed === false && (
        <span
          className="text-[10px] font-mono flex-shrink-0 px-1.5 py-0.5 rounded bg-red-500/20 text-red-500"
          title={log.policy_reason || "Policy denied"}
        >
          DENIED
        </span>
      )}

      {/* PII indicator */}
      {log.pii_detected && (
        <span
          className="text-[10px] font-mono flex-shrink-0 px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-500"
          title={log.pii_types.join(", ")}
        >
          PII
        </span>
      )}

      {/* Latency */}
      {log.latency_ms !== undefined && log.latency_ms !== null && (
        <span
          className={cn(
            "text-xs font-mono flex-shrink-0 w-16 text-right tabular-nums",
            getLatencyColor(log.latency_ms)
          )}
        >
          {formatLatency(log.latency_ms)}
        </span>
      )}

      {/* Copy JSON Button (on hover) */}
      {isHovered && (
        <Button
          variant="ghost"
          size="sm"
          onClick={(e) => handleCopyJson(e, log.content)}
          className="absolute right-2 h-6 w-6 p-0 bg-secondary border border-border hover:bg-muted"
          title="Copy"
        >
          <Copy className="w-3 h-3 text-muted-foreground" />
        </Button>
      )}
    </div>
  );
});

export function AgentAppsStream() {
  const logs = useObservabilityStore((state) => state.logs);
  const filters = useObservabilityStore((state) => state.filters);
  const selectedLogId = useObservabilityStore((state) => state.selectedLogId);
  const isLive = useObservabilityStore((state) => state.isLive);
  const isConnected = useObservabilityStore((state) => state.isConnected);
  const setFilters = useObservabilityStore((state) => state.setFilters);
  const selectLog = useObservabilityStore((state) => state.selectLog);
  const setIsLive = useObservabilityStore((state) => state.setIsLive);

  // Memoize filtered logs
  const filteredLogs = useMemo(() => filterAgentLogs(logs, filters), [logs, filters]);
  const allAgentLogs = useMemo(() => logs.filter((l) => l.source === "agent_app"), [logs]);
  const virtuosoRef = useRef<VirtuosoHandle>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const [searchValue, setSearchValue] = useState(filters.searchText || "");

  // Check if filters are active
  const hasActiveFilters = !!(
    filters.searchText ||
    filters.method ||
    filters.path ||
    filters.direction ||
    filters.serverName ||
    filters.minLatencyMs
  );

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (isLive && filteredLogs.length > 0) {
      virtuosoRef.current?.scrollToIndex({
        index: filteredLogs.length - 1,
        behavior: "auto",
      });
    }
  }, [filteredLogs.length, isLive]);

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (
        document.activeElement instanceof HTMLInputElement ||
        document.activeElement instanceof HTMLTextAreaElement
      ) {
        if ((e.metaKey || e.ctrlKey) && e.key === "k") {
          e.preventDefault();
          searchInputRef.current?.focus();
        }
        return;
      }

      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        searchInputRef.current?.focus();
        return;
      }

      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();

        const currentIndex = selectedLogId
          ? filteredLogs.findIndex((log) => log.id === selectedLogId)
          : -1;

        if (e.key === "ArrowDown") {
          if (currentIndex < filteredLogs.length - 1) {
            const nextLog = filteredLogs[currentIndex + 1];
            if (nextLog) {
              selectLog(nextLog.id);
              virtuosoRef.current?.scrollToIndex({
                index: currentIndex + 1,
                behavior: "auto",
                align: "center",
              });
            }
          }
        } else if (e.key === "ArrowUp") {
          if (currentIndex > 0) {
            const prevLog = filteredLogs[currentIndex - 1];
            if (prevLog) {
              selectLog(prevLog.id);
              virtuosoRef.current?.scrollToIndex({
                index: currentIndex - 1,
                behavior: "auto",
                align: "center",
              });
            }
          } else if (currentIndex === -1 && filteredLogs.length > 0) {
            selectLog(filteredLogs[0].id);
          }
        }
        return;
      }

      if (e.key === "Escape") {
        e.preventDefault();
        selectLog(null);
        return;
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [filteredLogs, selectedLogId, selectLog]);

  // Update search filter with debounce
  useEffect(() => {
    const timer = setTimeout(() => {
      setFilters({ searchText: searchValue || undefined });
    }, 300);
    return () => clearTimeout(timer);
  }, [searchValue, setFilters]);

  const handleClearSearch = () => {
    setSearchValue("");
    setFilters({ searchText: undefined });
  };

  const toggleLive = () => {
    const newState = !isLive;
    setIsLive(newState);

    if (newState && filteredLogs.length > 0) {
      virtuosoRef.current?.scrollToIndex({
        index: filteredLogs.length - 1,
        behavior: "auto",
      });
    }
  };

  return (
    <div className="flex flex-col h-full bg-background rounded-b-[12px] border-x border-b border-dashed border-border overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-card">
        <div className="flex items-center gap-3">
          <h2 className="text-sm font-semibold text-foreground">Agent Apps Stream</h2>
          <span className="text-[10px] font-semibold text-muted-foreground bg-muted px-1.5 py-0.5 rounded-md border border-dashed border-border uppercase tracking-wide">
            {filteredLogs.length}
            {hasActiveFilters && ` / ${allAgentLogs.length}`}
          </span>

          {/* Live Indicator */}
          {isLive && isConnected && (
            <div className="flex items-center gap-1.5 px-2 py-0.5 bg-purple-500/10 border border-purple-500/30 rounded-md">
              <div className="w-1.5 h-1.5 rounded-full bg-purple-500 animate-pulse" />
              <span className="text-[10px] font-semibold text-purple-500 tracking-wide">
                LIVE
              </span>
            </div>
          )}
        </div>

        <div className="flex items-center gap-2">
          {/* Live/Pause Toggle */}
          <Button
            variant="ghost"
            size="sm"
              onClick={toggleLive}
              className={cn(
              "h-7 px-2.5 border border-border",
              isLive
                ? "text-purple-500 hover:bg-purple-500/10"
                : "text-muted-foreground hover:bg-muted"
            )}
            title={isLive ? "Pause auto-scroll" : "Resume auto-scroll"}
          >
            {isLive ? (
              <Pause className="w-4 h-4" weight="fill" />
            ) : (
              <Play className="w-4 h-4" weight="fill" />
            )}
          </Button>

          {/* Search Input */}
          <div className="relative w-64">
            <MagnifyingGlass className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
            <Input
              ref={searchInputRef}
              type="text"
              placeholder="Search... (Cmd+K)"
              value={searchValue}
              onChange={(e) => setSearchValue(e.target.value)}
              className="pl-8 pr-8 h-8 text-xs focus:border-purple-500/50 focus:ring-1 focus:ring-purple-500/30"
            />
            {searchValue && (
              <Button
                variant="ghost"
                size="sm"
                onClick={handleClearSearch}
                className="absolute right-0.5 top-1/2 -translate-y-1/2 h-7 w-7 p-0 hover:bg-muted"
              >
                <X className="w-3.5 h-3.5 text-muted-foreground" />
              </Button>
            )}
          </div>
        </div>
      </div>

      {/* Virtualized List */}
      <div className="flex-1 overflow-hidden">
        {filteredLogs.length === 0 ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center max-w-sm">
              {hasActiveFilters && allAgentLogs.length > 0 ? (
                <>
                  <Funnel className="w-10 h-10 mx-auto mb-3 text-amber-500" weight="duotone" />
                  <p className="text-sm text-foreground font-medium">No matches found</p>
                  <p className="text-xs text-muted-foreground mt-2">
                    {allAgentLogs.length} request{allAgentLogs.length === 1 ? "" : "s"} hidden by
                    filters.
                  </p>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setFilters({
                        searchText: undefined,
                        method: undefined,
                        direction: undefined,
                        minLatencyMs: undefined,
                        serverName: undefined,
                      });
                      setSearchValue("");
                    }}
                    className="mt-4 h-8 text-xs"
                  >
                    Clear all filters
                  </Button>
                </>
              ) : (
                <>
                  <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-purple-500/20 to-purple-500/5 flex items-center justify-center">
                    <Robot className="w-8 h-8 text-purple-500" weight="duotone" />
                  </div>
                  <p className="text-base text-foreground font-semibold mb-2">
                    Ready to monitor agent apps
                  </p>
                  <p className="text-sm text-muted-foreground mb-4 max-w-xs mx-auto">
                    Enable the forward proxy with{" "}
                    <code className="font-mono bg-muted px-1 rounded">soth on</code> to
                    capture traffic from ChatGPT, Claude, and other AI assistants.
                  </p>
                  <p className="text-[11px] text-muted-foreground/60 mt-4">
                    Supports ChatGPT, Claude, Perplexity, and Google AI Studio
                  </p>
                </>
              )}
            </div>
          </div>
        ) : (
          <Virtuoso
            ref={virtuosoRef}
            data={filteredLogs}
            components={OBSERVABILITY_VIRTUOSO_COMPONENTS}
            computeItemKey={(index, log) => log.id}
            itemContent={(index, log) => <AgentLogRow log={log} index={index} />}
            scrollSeekConfiguration={OBSERVABILITY_SCROLL_SEEK_CONFIG}
            followOutput={(isAtBottom) => {
              if (!isAtBottom && isLive) {
                setIsLive(false);
              }
              return isLive && isAtBottom ? true : false;
            }}
            className="scrollbar-thin"
            defaultItemHeight={32}
            increaseViewportBy={120}
            overscan={6}
          />
        )}
      </div>
    </div>
  );
}
