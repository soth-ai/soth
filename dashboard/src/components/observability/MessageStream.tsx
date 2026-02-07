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
  Lightning,
  Funnel,
  Cpu,
  CloudArrowUp,
  Robot,
  Stack,
} from "@phosphor-icons/react";
import { toast } from "sonner";
import {
  useObservabilityStore,
  parseLogMessage,
  findCorrelatedRequest,
  calculateLatency,
  getLogSummary,
  createClusters,
  type LogEntry,
  type Filters,
  type EventCluster,
  type DisplayItem,
} from "@/store/observability";
import { cn, formatTimestamp, formatLatency, truncate } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useSettingsStore } from "@/store/settings";
import {
  OBSERVABILITY_SCROLL_SEEK_CONFIG,
  OBSERVABILITY_VIRTUOSO_COMPONENTS,
} from "@/components/observability/ScrollSeekPlaceholder";

// Helper function to filter logs
function filterLogs(logs: LogEntry[], filters: Filters): LogEntry[] {
  return logs.filter((log) => {
    if (filters.source && log.source !== filters.source) return false;
    if (filters.sessionId && log.session_id !== filters.sessionId) return false;
    if (filters.searchText) {
      const search = filters.searchText.toLowerCase();
      const searchableContent = (log.content_preview || log.content || "").slice(0, 2048);
      const matchesContent = searchableContent.toLowerCase().includes(search);
      const matchesMethod = log.method?.toLowerCase().includes(search);
      const matchesToolName = log.tool_name?.toLowerCase().includes(search);
      const matchesServer = log.server_name.toLowerCase().includes(search);
      const matchesAgent = log.agent.name.toLowerCase().includes(search);
      if (!matchesContent && !matchesMethod && !matchesToolName && !matchesServer && !matchesAgent) {
        return false;
      }
    }
    if (filters.method && log.method !== filters.method) return false;
    if (filters.direction && log.direction !== filters.direction) return false;
    if (filters.serverName && log.server_name !== filters.serverName) return false;
    if (filters.minLatencyMs && log.latency_ms !== undefined) {
      if (log.latency_ms < filters.minLatencyMs) return false;
    }
    if (filters.policyDenied && log.policy_allowed !== false) return false;
    if (filters.piiDetected && !log.pii_detected) return false;
    if (filters.hasError) {
      try {
        const parsed = JSON.parse(log.content);
        if (!parsed.error && !(log.status_code && log.status_code >= 400)) return false;
      } catch {
        if (!(log.status_code && log.status_code >= 400)) return false;
      }
    }
    return true;
  });
}

// Source type config
const sourceConfig = {
  mcp: { icon: Cpu, label: "MCP", color: "text-cyan-500 bg-cyan-500/10 border-cyan-500/30" },
  ai_proxy: { icon: CloudArrowUp, label: "AI", color: "text-purple-500 bg-purple-500/10 border-purple-500/30" },
  agent_app: { icon: Robot, label: "Agent", color: "text-amber-500 bg-amber-500/10 border-amber-500/30" },
};

// Latency color helper
function getLatencyColor(ms: number) {
  if (ms >= 1000) return "text-red-500";
  if (ms >= 200) return "text-amber-500";
  if (ms >= 50) return "text-muted-foreground";
  return "text-muted-foreground/70";
}

interface ClusterRowProps {
  cluster: EventCluster;
  selectedLogId: string | null;
  selectedLogPart: "request" | "response" | null;
  selectLog: (id: string | null, part?: "request" | "response" | null) => void;
}

function isClusterRequestSelected(
  cluster: EventCluster,
  selectedLogId: string | null,
  selectedLogPart: "request" | "response" | null
): boolean {
  const isSameIdPair = !!cluster.response && cluster.request.id === cluster.response.id;
  return isSameIdPair
    ? selectedLogId === cluster.request.id && selectedLogPart !== "response"
    : selectedLogId === cluster.request.id;
}

function isClusterResponseSelected(
  cluster: EventCluster,
  selectedLogId: string | null,
  selectedLogPart: "request" | "response" | null
): boolean {
  const responseTargetId = cluster.response?.id || cluster.request.id;
  const isSameIdPair = !!cluster.response && cluster.request.id === cluster.response.id;
  return isSameIdPair
    ? selectedLogId === cluster.request.id && selectedLogPart === "response"
    : selectedLogId === responseTargetId;
}

function areClusterRowPropsEqual(prev: ClusterRowProps, next: ClusterRowProps): boolean {
  if (prev.cluster !== next.cluster) {
    return false;
  }

  const prevReqSelected = isClusterRequestSelected(
    prev.cluster,
    prev.selectedLogId,
    prev.selectedLogPart
  );
  const nextReqSelected = isClusterRequestSelected(
    next.cluster,
    next.selectedLogId,
    next.selectedLogPart
  );
  if (prevReqSelected !== nextReqSelected) {
    return false;
  }

  const prevRespSelected = isClusterResponseSelected(
    prev.cluster,
    prev.selectedLogId,
    prev.selectedLogPart
  );
  const nextRespSelected = isClusterResponseSelected(
    next.cluster,
    next.selectedLogId,
    next.selectedLogPart
  );
  return prevRespSelected === nextRespSelected;
}

// Cluster Row Component
const ClusterRow = memo(function ClusterRow({
  cluster,
  selectedLogId,
  selectedLogPart,
  selectLog,
}: ClusterRowProps) {
  const highlightPii = useSettingsStore((state) => state.highlightPii);
  const highlightErrors = useSettingsStore((state) => state.highlightErrors);
  const [isHovered, setIsHovered] = useState(false);
  const isSelected = selectedLogId === cluster.request.id || selectedLogId === cluster.response?.id;

  const source = sourceConfig[cluster.source] || sourceConfig.mcp;
  const isPending = !cluster.response;
  const singleLine = useCallback((value: string) => value.replace(/\s+/g, " ").trim(), []);
  const requestSummary = useMemo(
    () => singleLine(getLogSummary(cluster.request)),
    [cluster.request, singleLine]
  );
  const responseSummary = useMemo(
    () => (cluster.response ? singleLine(getLogSummary(cluster.response)) : "pending response"),
    [cluster.response, singleLine]
  );

  // Apply highlight settings
  const showErrorHighlight = highlightErrors && (cluster.hasError || cluster.policyDenied);
  const showPiiHighlight = highlightPii && cluster.hasPii;

  const handleCopy = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    const parseMaybeJson = (raw: string) => {
      try {
        return JSON.parse(raw);
      } catch {
        return raw;
      }
    };
    const content = cluster.response
      ? JSON.stringify(
          {
            request: parseMaybeJson(cluster.request.content),
            response: parseMaybeJson(cluster.response.content),
          },
          null,
          2
        )
      : cluster.request.content;
    navigator.clipboard.writeText(content);
    toast.success("Copied to clipboard", { duration: 2000 });
  }, [cluster]);

  const responseTargetId = cluster.response?.id || cluster.request.id;
  const isSameIdPair = !!cluster.response && cluster.request.id === cluster.response.id;
  const requestIsSelected = isClusterRequestSelected(cluster, selectedLogId, selectedLogPart);
  const responseIsSelected = isClusterResponseSelected(cluster, selectedLogId, selectedLogPart);

  const rowClass = "flex items-center gap-3 px-4 h-8 overflow-hidden";
  const sourceChipClass =
    "inline-flex items-center justify-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium border w-[56px] flex-shrink-0";
  const methodChipClass =
    "inline-flex items-center px-1.5 py-0.5 rounded-md text-xs font-mono font-medium min-w-[120px] max-w-[180px] flex-shrink-0 truncate";
  const badgeSlotClass = "flex items-center justify-end gap-1.5 w-[168px] flex-shrink-0";

  return (
    <div
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className={cn(
        "group border-b border-border border-l-2 transition-colors",
        isSelected && "border-l-accent bg-accent/10",
        showErrorHighlight && !isSelected && "border-l-red-500 bg-red-500/5",
        showPiiHighlight && !showErrorHighlight && !isSelected && "border-l-orange-500 bg-orange-500/5",
        !isSelected && !showErrorHighlight && !showPiiHighlight && "border-l-transparent"
      )}
    >
      {/* Request Row */}
      <div
        onClick={() => selectLog(cluster.request.id, isSameIdPair ? "request" : null)}
        className={cn(
          rowClass,
          "cursor-pointer hover:bg-muted/35",
          requestIsSelected && "bg-accent/20"
        )}
      >
        <div className="w-4 flex items-center justify-center flex-shrink-0">
          <div className="w-2 h-2 rounded-full bg-cyan-500" />
        </div>

        <span className="text-xs text-muted-foreground font-mono w-24 flex-shrink-0 tabular-nums whitespace-nowrap">
          {formatTimestamp(cluster.request.timestamp)}
        </span>

        <ArrowDown className="w-3.5 h-3.5 text-cyan-500 flex-shrink-0" weight="bold" />

        <span className={cn(sourceChipClass, source.color)}>
          <source.icon className="w-3 h-3" weight="duotone" />
          {source.label}
        </span>

        <span
          className="text-xs text-muted-foreground w-24 truncate flex-shrink-0"
          title={cluster.request.agent.name}
        >
          {cluster.request.agent.name}
        </span>

        <span
          className={cn(
            methodChipClass,
            "bg-secondary text-secondary-foreground border border-border",
            cluster.policyDenied && "bg-red-500/20 text-red-500 border-red-500/30"
          )}
          title={cluster.method}
        >
          {truncate(cluster.method, 20)}
        </span>

        <span
          className="text-xs text-cyan-500/90 truncate font-mono flex-1 min-w-0 whitespace-nowrap"
          title={requestSummary}
        >
          {truncate(requestSummary, 90)}
        </span>

        <span className="text-xs font-mono tabular-nums text-right w-16 flex-shrink-0 text-cyan-500/80">
          {cluster.request.token_count ? `${cluster.request.token_count}t` : ""}
        </span>

        <div className={badgeSlotClass}>
          <Button
            variant="ghost"
            size="sm"
            onClick={handleCopy}
            className={cn(
              "h-6 w-6 p-0 bg-secondary border border-border hover:bg-muted transition-opacity",
              isHovered ? "opacity-100" : "opacity-0 pointer-events-none"
            )}
            title="Copy request + response JSON"
          >
            <Copy className="w-3 h-3 text-muted-foreground" />
          </Button>
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-500">
            REQUEST
          </span>
        </div>
      </div>

      {/* Response Row */}
      <div
        onClick={() => selectLog(responseTargetId, isSameIdPair ? "response" : null)}
        className={cn(
          rowClass,
          "cursor-pointer border-t border-border/60 hover:bg-muted/35",
          responseIsSelected && "bg-accent/20"
        )}
      >
        <div className="w-4 flex items-center justify-center flex-shrink-0">
          <div
            className={cn(
              "w-2 h-2 rounded-full",
              isPending
                ? "bg-amber-500 animate-pulse"
                : cluster.hasError
                ? "bg-red-500"
                : "bg-emerald-500"
            )}
          />
        </div>

        <span className="text-xs text-muted-foreground font-mono w-24 flex-shrink-0 tabular-nums whitespace-nowrap">
          {formatTimestamp(cluster.response?.timestamp || cluster.timestamp)}
        </span>

        <ArrowUp
          className={cn(
            "w-3.5 h-3.5 flex-shrink-0",
            isPending
              ? "text-amber-500"
              : cluster.hasError
              ? "text-red-500"
              : "text-emerald-500"
          )}
          weight="bold"
        />

        <span className={cn(sourceChipClass, source.color)}>
          <source.icon className="w-3 h-3" weight="duotone" />
          {source.label}
        </span>

        <span
          className="text-xs text-muted-foreground w-24 truncate flex-shrink-0"
          title={cluster.response?.agent.name || cluster.request.agent.name}
        >
          {cluster.response?.agent.name || cluster.request.agent.name}
        </span>

        <span
          className={cn(
            methodChipClass,
            "border",
            isPending
              ? "bg-amber-500/10 text-amber-500 border-amber-500/30"
              : cluster.hasError
              ? "bg-red-500/20 text-red-500 border-red-500/30"
              : "bg-emerald-500/10 text-emerald-500 border-emerald-500/30"
          )}
          title={cluster.method}
        >
          {truncate(cluster.method, 20)}
        </span>

        <span
          className={cn(
            "text-xs truncate font-mono flex-1 min-w-0 whitespace-nowrap",
            isPending
              ? "text-amber-500"
              : cluster.hasError
              ? "text-red-500/90"
              : "text-emerald-500/90"
          )}
          title={responseSummary}
        >
          {truncate(responseSummary, 90)}
        </span>

        <span
          className={cn(
            "text-xs font-mono tabular-nums text-right w-16 flex-shrink-0",
            cluster.latency !== null ? getLatencyColor(cluster.latency) : "text-amber-500"
          )}
        >
          {cluster.latency !== null ? formatLatency(cluster.latency) : "pending"}
        </span>

        <div className={badgeSlotClass}>
          {cluster.policyDenied && (
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-red-500/20 text-red-500">
              DENIED
            </span>
          )}
          {cluster.hasPii && (
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-500">
              PII
            </span>
          )}
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-500">
            RESPONSE
          </span>
        </div>
      </div>
    </div>
  );
}, areClusterRowPropsEqual);

// Standalone Log Row (for non-clustered items)
const LogRow = memo(function LogRow({ log }: { log: LogEntry }) {
  const selectedLogId = useObservabilityStore((state) => state.selectedLogId);
  const selectLog = useObservabilityStore((state) => state.selectLog);
  const logs = useObservabilityStore((state) => state.logs);
  const highlightPii = useSettingsStore((state) => state.highlightPii);
  const highlightErrors = useSettingsStore((state) => state.highlightErrors);
  const [isHovered, setIsHovered] = useState(false);
  const isSelected = selectedLogId === log.id;
  const rowRef = useRef<HTMLDivElement>(null);

  const isRawMessage = log.message_type === "raw";
  const isStderrMessage = log.message_type === "stderr";
  const isNonJsonRpc = isRawMessage || isStderrMessage;

  const parsed = useMemo(
    () => (isNonJsonRpc ? null : parseLogMessage(log)),
    [isNonJsonRpc, log]
  );
  const isError = parsed?.error !== undefined || isStderrMessage || log.policy_allowed === false;

  // Apply highlight settings
  const showErrorHighlight = highlightErrors && isError;
  const showPiiHighlight = highlightPii && log.pii_detected;
  const isRequest = parsed?.method !== undefined && !parsed.result && !parsed.error;

  const correlatedRequest = useMemo(
    () =>
      (parsed?.result !== undefined || parsed?.error !== undefined) && !parsed?.method
        ? findCorrelatedRequest(log, logs)
        : null,
    [parsed, log, logs]
  );
  const correlatedRequestMethod = useMemo(
    () => (correlatedRequest ? parseLogMessage(correlatedRequest)?.method : undefined),
    [correlatedRequest]
  );
  const actualLatency = useMemo(
    () => (correlatedRequest ? calculateLatency(correlatedRequest, log) : null),
    [correlatedRequest, log]
  );
  const displayLatency = actualLatency ?? log.latency_ms;

  const method = useMemo(() => {
    if (isStderrMessage) return "stderr";
    if (isRawMessage) return "raw";
    if (log.tool_name) return `${log.method}/${log.tool_name}`;
    return parsed?.method || correlatedRequestMethod || "response";
  }, [isStderrMessage, isRawMessage, log.tool_name, log.method, parsed, correlatedRequestMethod]);

  const rpcId = parsed?.id;
  const source = sourceConfig[log.source] || sourceConfig.mcp;
  const summary = useMemo(() => truncate(getLogSummary(log), 60), [log]);

  const handleCopyJson = useCallback((e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(log.content);
    toast.success("JSON copied to clipboard", { duration: 2000 });
  }, [log.content]);

  const getStatusColor = () => {
    if (isStderrMessage) return "bg-red-500";
    if (isRawMessage) return "bg-amber-500";
    if (isError) return "bg-red-500";
    if (log.pii_detected) return "bg-orange-500";
    if (isRequest) return "bg-cyan-500";
    return "bg-emerald-500";
  };

  useEffect(() => {
    if (isSelected && rowRef.current) {
      rowRef.current.scrollIntoView({ block: "nearest", behavior: "auto" });
    }
  }, [isSelected]);

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
        isSelected && "border-l-2 border-l-accent bg-muted/60",
        showErrorHighlight && !isSelected && "border-l-2 border-l-red-500 bg-red-500/5",
        showPiiHighlight && !showErrorHighlight && !isSelected && "border-l-2 border-l-orange-500 bg-orange-500/5",
        !isSelected && !showErrorHighlight && !showPiiHighlight && "border-l-2 border-l-transparent",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2"
      )}
    >
      {/* Status Dot */}
      <div className="flex-shrink-0">
        <div
          className={cn(
            "w-2 h-2 rounded-full transition-all",
            getStatusColor(),
            isSelected && "ring-2 ring-accent/50"
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
          <ArrowDown className="w-3 h-3 text-muted-foreground" weight="bold" />
        ) : (
          <ArrowUp className="w-3 h-3 text-muted-foreground" weight="bold" />
        )}
      </div>

      {/* Source Type Chip */}
      <span
        className={cn(
          "inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium border flex-shrink-0",
          source.color
        )}
        title={`Source: ${log.source}`}
      >
        <source.icon className="w-3 h-3" weight="duotone" />
        {source.label}
      </span>

      {/* Agent */}
      <span
        className="text-xs text-muted-foreground w-24 truncate flex-shrink-0"
        title={log.agent.name}
      >
        {log.agent.name}
      </span>

      {/* Method Badge */}
      <span
        className={cn(
          "inline-flex items-center px-1.5 py-0.5 rounded-md text-xs font-mono font-medium flex-shrink-0 min-w-[120px] max-w-[180px] truncate",
          isStderrMessage
            ? "bg-red-500/20 text-red-500 border border-red-500/30"
            : isRawMessage
            ? "bg-amber-500/20 text-amber-500 border border-amber-500/30"
            : "bg-secondary text-secondary-foreground border border-border"
        )}
        title={method}
      >
        {truncate(method, 20)}
        {rpcId !== undefined && (
          <span className="text-muted-foreground ml-1.5">#{String(rpcId)}</span>
        )}
      </span>

      {/* Summary */}
      <span className="text-xs text-muted-foreground flex-1 truncate font-mono">
        {summary}
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

      {/* Token count */}
      {log.token_count !== undefined && log.token_count > 0 && (
        <span
          className="text-[10px] font-mono flex-shrink-0 px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-500 tabular-nums"
          title={`${log.token_count.toLocaleString()} tokens`}
        >
          {log.token_count >= 1000
            ? `${(log.token_count / 1000).toFixed(1)}k`
            : log.token_count}
        </span>
      )}

      {/* Latency */}
      {displayLatency !== undefined && displayLatency !== null && (
        <span
          className={cn(
            "text-xs font-mono flex-shrink-0 w-16 text-right tabular-nums",
            getLatencyColor(displayLatency)
          )}
          title={actualLatency !== null ? `Round-trip latency from request #${rpcId}` : "Latency"}
        >
          {formatLatency(displayLatency)}
        </span>
      )}

      {/* Copy JSON Button (on hover) */}
      {isHovered && (
        <Button
          variant="ghost"
          size="sm"
          onClick={handleCopyJson}
          className="absolute right-2 h-6 w-6 p-0 bg-secondary border border-border hover:bg-muted"
          title="Copy JSON"
        >
          <Copy className="w-3 h-3 text-muted-foreground" />
        </Button>
      )}
    </div>
  );
});

export function MessageStream() {
  const logs = useObservabilityStore((state) => state.logs);
  const filters = useObservabilityStore((state) => state.filters);
  const selectedLogId = useObservabilityStore((state) => state.selectedLogId);
  const selectedLogPart = useObservabilityStore((state) => state.selectedLogPart);
  const isLive = useObservabilityStore((state) => state.isLive);
  const isConnected = useObservabilityStore((state) => state.isConnected);
  const setFilters = useObservabilityStore((state) => state.setFilters);
  const selectLog = useObservabilityStore((state) => state.selectLog);
  const setIsLive = useObservabilityStore((state) => state.setIsLive);
  const clusteringEnabled = useObservabilityStore((state) => state.clusteringEnabled);
  const setClusteringEnabled = useObservabilityStore((state) => state.setClusteringEnabled);

  const filteredLogs = useMemo(() => filterLogs(logs, filters), [logs, filters]);
  const allLogs = logs;

  // Create display items (clustered or flat)
  const displayItems = useMemo(() => {
    if (!clusteringEnabled) {
      return filteredLogs.map((log) => ({ type: 'log' as const, log }));
    }
    return createClusters(filteredLogs);
  }, [filteredLogs, clusteringEnabled]);

  const virtuosoRef = useRef<VirtuosoHandle>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const [searchValue, setSearchValue] = useState(filters.searchText || "");

  const hasActiveFilters = !!(
    filters.searchText ||
    filters.method ||
    filters.direction ||
    filters.serverName ||
    filters.minLatencyMs ||
    filters.policyDenied ||
    filters.piiDetected ||
    filters.hasError ||
    filters.source
  );

  // Auto-scroll to bottom when new items arrive
  useEffect(() => {
    if (isLive && displayItems.length > 0) {
      virtuosoRef.current?.scrollToIndex({
        index: displayItems.length - 1,
        behavior: "auto",
      });
    }
  }, [displayItems.length, isLive]);

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (
        document.activeElement instanceof HTMLInputElement ||
        document.activeElement instanceof HTMLTextAreaElement
      ) {
        return;
      }

      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        // Navigate through items
        // (simplified - would need more logic for clusters)
      }

      if (e.key === "Escape") {
        e.preventDefault();
        selectLog(null);
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [selectLog]);

  // Search filter debounce
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
    if (newState && displayItems.length > 0) {
      virtuosoRef.current?.scrollToIndex({
        index: displayItems.length - 1,
        behavior: "auto",
      });
    }
  };

  // Render item based on type
  const renderItem = useCallback(
    (index: number, item: DisplayItem) => {
      if (item.type === "cluster") {
        return (
          <ClusterRow
            cluster={item.cluster}
            selectedLogId={selectedLogId}
            selectedLogPart={selectedLogPart}
            selectLog={selectLog}
          />
        );
      }
      return <LogRow log={item.log} />;
    },
    [selectedLogId, selectedLogPart, selectLog]
  );

  return (
    <div className="flex flex-col h-full bg-background rounded-b-[12px] border-x border-b border-dashed border-border overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-border bg-card">
        <div className="flex items-center gap-3">
          <h2 className="text-[24px] font-normal text-foreground">Message Stream</h2>
          <span className="soth-chip-text text-muted-foreground bg-muted px-2 py-0.5 rounded-md border border-dashed border-border">
            {displayItems.length}
            {hasActiveFilters && ` / ${allLogs.length}`}
          </span>

          {/* Live Indicator */}
          {isLive && isConnected && (
            <div className="flex items-center gap-1.5 px-2 py-0.5 bg-emerald-500/10 border border-emerald-500/30 rounded-md">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              <span className="text-xs font-semibold text-emerald-500 tracking-wide">LIVE</span>
            </div>
          )}
        </div>

        <div className="flex items-center gap-2">
          {/* Clustering Toggle */}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setClusteringEnabled(!clusteringEnabled)}
            className={cn(
              "h-8 px-3 border border-border gap-1.5",
              clusteringEnabled
                ? "text-accent bg-accent/10 border-accent/30"
                : "text-muted-foreground hover:bg-muted"
            )}
            title={clusteringEnabled ? "Disable clustering" : "Enable clustering"}
          >
            <Stack className="w-4 h-4" weight={clusteringEnabled ? "fill" : "regular"} />
            <span className="text-xs">Cluster</span>
          </Button>

          {/* Live/Pause Toggle */}
          <Button
            variant="ghost"
            size="sm"
            onClick={toggleLive}
            className={cn(
              "h-8 px-3 border border-border",
              isLive
                ? "text-emerald-500 hover:bg-emerald-500/10"
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
              placeholder="Search... (⌘K)"
              value={searchValue}
              onChange={(e) => setSearchValue(e.target.value)}
              className="pl-8 pr-8 h-8 text-[16px] focus:border-accent/50 focus:ring-1 focus:ring-accent/30"
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
        {displayItems.length === 0 ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center max-w-sm">
              {hasActiveFilters && allLogs.length > 0 ? (
                <>
                  <Funnel className="w-10 h-10 mx-auto mb-3 text-amber-500" weight="duotone" />
                  <p className="text-sm text-foreground font-medium">No matches found</p>
                  <p className="text-xs text-muted-foreground mt-2">
                    {allLogs.length} message{allLogs.length === 1 ? "" : "s"} hidden by filters.
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
                        policyDenied: undefined,
                        piiDetected: undefined,
                        hasError: undefined,
                        source: undefined,
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
                  <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-accent/20 to-accent/5 flex items-center justify-center">
                    <Lightning className="w-8 h-8 text-accent" weight="duotone" />
                  </div>
                  <p className="text-base text-foreground font-semibold mb-2">
                    Ready to inspect AI traffic
                  </p>
                  <p className="text-sm text-muted-foreground mb-4 max-w-xs mx-auto">
                    Use <code className="font-mono bg-muted px-1 rounded">soth wrap</code> for MCP,
                    or <code className="font-mono bg-muted px-1 rounded">soth proxy on</code> for AI API calls.
                  </p>
                  <p className="text-[11px] text-muted-foreground/60 mt-4">
                    Press{" "}
                    <kbd className="px-1.5 py-0.5 bg-muted border border-border rounded text-[10px] font-mono">
                      ?
                    </kbd>{" "}
                    for keyboard shortcuts
                  </p>
                </>
              )}
            </div>
          </div>
        ) : (
          <Virtuoso
            ref={virtuosoRef}
            data={displayItems}
            components={OBSERVABILITY_VIRTUOSO_COMPONENTS}
            computeItemKey={(index, item) =>
              item.type === "cluster" ? item.cluster.id : item.log.id
            }
            itemContent={renderItem}
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
