"use client";

import { useEffect, useRef, memo, useState, useCallback, useMemo } from "react";
import { Virtuoso, VirtuosoHandle } from "react-virtuoso";
import {
  ArrowDown,
  ArrowUp,
  MagnifyingGlass,
  X,
  Copy,
  Lightning,
  Funnel,
  Cpu,
  CloudArrowUp,
  Robot,
  Pulse,
} from "@phosphor-icons/react";
import { toast } from "sonner";
import {
  useObservabilityStore,
  parseLogMessage,
  findCorrelatedRequest,
  calculateLatency,
  getLogSummary,
  getLogTokenCount,
  createClusters,
  filterLogs,
  type LogEntry,
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
  showTimestamps: boolean;
  compactMode: boolean;
}

function isActivateKey(event: React.KeyboardEvent | KeyboardEvent): boolean {
  return event.key === "Enter" || event.key === " ";
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
  if (prev.showTimestamps !== next.showTimestamps) {
    return false;
  }
  if (prev.compactMode !== next.compactMode) {
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
  showTimestamps,
  compactMode,
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
  const requestTokenCount = getLogTokenCount(cluster.request);

  const rowClass = cn(
    "flex items-center gap-3 px-4 overflow-hidden transition-all duration-200 group/row",
    compactMode ? "h-7" : "h-8"
  );
  const sourceChipClass =
    "inline-flex items-center justify-center gap-1 px-1.5 py-0.5 rounded-md text-[10px] font-bold border w-[56px] flex-shrink-0 transition-opacity";
  const methodChipClass =
    "inline-flex items-center px-1.5 py-0.5 rounded-md text-[10px] font-mono font-semibold min-w-[110px] max-w-[160px] flex-shrink-0 truncate transition-all";
  const badgeSlotClass = "flex items-center justify-end gap-1.5 w-[136px] flex-shrink-0";

  return (
    <div
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className={cn(
        "group border-b border-border/50 border-l-2 transition-all duration-300",
        isSelected ? "border-l-primary bg-primary/[0.03]" : "border-l-transparent hover:bg-muted/[0.08]",
        showErrorHighlight && !isSelected && "border-l-destructive bg-destructive/[0.02]",
        showPiiHighlight && !showErrorHighlight && !isSelected && "border-l-warning bg-warning/[0.02]"
      )}
    >
      {/* Request Row */}
      <div
        onClick={() => selectLog(cluster.request.id, isSameIdPair ? "request" : null)}
        onKeyDown={(event) => {
          if (!isActivateKey(event)) {
            return;
          }
          event.preventDefault();
          selectLog(cluster.request.id, isSameIdPair ? "request" : null);
        }}
        tabIndex={requestIsSelected ? 0 : -1}
        role="button"
        aria-label={`Select request event ${cluster.method}`}
        className={cn(
          rowClass,
          "cursor-pointer focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary/50",
          requestIsSelected && "bg-primary/[0.06] shadow-[inset_0_0_12px_-4px_rgba(217,119,87,0.1)]"
        )}
      >
        <div className="w-4 flex items-center justify-center flex-shrink-0">
          <div className={cn(
            "w-1.5 h-1.5 rounded-full transition-all duration-300 shadow-[0_0_8px_rgba(34,211,238,0.4)]",
            requestIsSelected ? "bg-primary scale-125" : "bg-cyan-500"
          )} />
        </div>

        {showTimestamps ? (
          <span className="text-[10px] text-muted-foreground font-mono w-24 flex-shrink-0 tabular-nums whitespace-nowrap opacity-60 group-hover/row:opacity-100 transition-opacity">
            {formatTimestamp(cluster.request.timestamp)}
          </span>
        ) : null}

        <ArrowDown className="w-3.5 h-3.5 text-cyan-500/70 flex-shrink-0" weight="bold" />

        <span
          className={cn(sourceChipClass, source.color, "group-hover/row:opacity-100 opacity-80")}
        >
          <source.icon className="w-3.5 h-3.5" weight="duotone" />
          {source.label}
        </span>

        <span
          className="text-[10px] font-medium text-muted-foreground w-24 truncate flex-shrink-0"
          title={cluster.request.agent.name}
        >
          {cluster.request.agent.name}
        </span>

        <span
          className={cn(
            methodChipClass,
            "bg-secondary/40 text-secondary-foreground border border-border/30",
            cluster.policyDenied && "bg-destructive/10 text-destructive border-destructive/20"
          )}
          title={cluster.method}
        >
          {truncate(cluster.method, 22)}
        </span>

        <span
          className="text-[11px] text-cyan-500/80 truncate font-mono flex-1 min-w-0 tracking-tight"
          title={requestSummary}
        >
          {requestSummary}
        </span>

        <span className="text-[10px] font-mono tabular-nums text-right w-12 flex-shrink-0 text-cyan-500/60 font-bold">
          {requestTokenCount > 0 ? `${requestTokenCount}t` : ""}
        </span>

        <div className={badgeSlotClass}>
          <Button
            variant="ghost"
            size="sm"
            onClick={handleCopy}
            className={cn(
              "h-6 w-6 p-0 bg-background/50 border border-border/50 hover:bg-muted transition-all duration-300",
              isHovered ? "opacity-100 translate-x-0" : "opacity-0 translate-x-1 pointer-events-none"
            )}
            title="Copy Context"
          >
            <Copy className="w-3 h-3 text-muted-foreground" />
          </Button>
          <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full bg-cyan-500/10 text-cyan-500 border border-cyan-500/20 tracking-wider">
            REQ
          </span>
        </div>
      </div>

      {/* Response Row */}
      <div
        onClick={() => selectLog(responseTargetId, isSameIdPair ? "response" : null)}
        onKeyDown={(event) => {
          if (!isActivateKey(event)) {
            return;
          }
          event.preventDefault();
          selectLog(responseTargetId, isSameIdPair ? "response" : null);
        }}
        tabIndex={responseIsSelected ? 0 : -1}
        role="button"
        aria-label={`Select response event ${cluster.method}`}
        className={cn(
          rowClass,
          "cursor-pointer border-t border-border/30 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary/50",
          responseIsSelected && "bg-primary/[0.06] shadow-[inset_0_0_12px_-4px_rgba(217,119,87,0.1)]"
        )}
      >
        <div className="w-4 flex items-center justify-center flex-shrink-0">
          <div
            className={cn(
              "w-1.5 h-1.5 rounded-full transition-all duration-300",
              isPending
                ? "bg-warning animate-pulse shadow-[0_0_8px_rgba(245,158,11,0.5)]"
                : cluster.hasError
                  ? "bg-destructive shadow-[0_0_8px_rgba(239,68,68,0.5)]"
                  : "bg-success shadow-[0_0_8px_rgba(16,185,129,0.5)]",
              responseIsSelected && "scale-125"
            )}
          />
        </div>

        {showTimestamps ? (
          <span className="text-[10px] text-muted-foreground font-mono w-24 flex-shrink-0 tabular-nums whitespace-nowrap opacity-60 group-hover/row:opacity-100 transition-opacity">
            {formatTimestamp(cluster.response?.timestamp || cluster.timestamp)}
          </span>
        ) : null}

        <ArrowUp
          className={cn(
            "w-3.5 h-3.5 flex-shrink-0",
            isPending
              ? "text-warning"
              : cluster.hasError
                ? "text-destructive"
                : "text-success"
          )}
          weight="bold"
        />

        <span
          className={cn(sourceChipClass, source.color, "group-hover/row:opacity-100 opacity-80")}
        >
          <source.icon className="w-3.5 h-3.5" weight="duotone" />
          {source.label}
        </span>

        <span
          className="text-[10px] font-medium text-muted-foreground w-24 truncate flex-shrink-0"
          title={cluster.response?.agent.name || cluster.request.agent.name}
        >
          {cluster.response?.agent.name || cluster.request.agent.name}
        </span>

        <span
          className={cn(
            methodChipClass,
            "border",
            isPending
              ? "bg-warning/10 text-warning border-warning/20"
              : cluster.hasError
                ? "bg-destructive/10 text-destructive border-destructive/20"
                : "bg-success/10 text-success border-success/20"
          )}
          title={cluster.method}
        >
          {truncate(cluster.method, 22)}
        </span>

        <span
          className={cn(
            "text-[11px] truncate font-mono flex-1 min-w-0 tracking-tight",
            isPending
              ? "text-warning"
              : cluster.hasError
                ? "text-destructive/90"
                : "text-success/90"
          )}
          title={responseSummary}
        >
          {responseSummary}
        </span>

        <span
          className={cn(
            "text-[10px] font-mono tabular-nums text-right w-12 flex-shrink-0 font-bold",
            cluster.latency !== null ? getLatencyColor(cluster.latency) : "text-warning"
          )}
        >
          {cluster.latency !== null ? formatLatency(cluster.latency) : "pending"}
        </span>

        <div className={badgeSlotClass}>
          {cluster.policyDenied && (
            <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full bg-destructive/10 text-destructive border border-destructive/20">
              DENIED
            </span>
          )}
          {cluster.hasPii && (
            <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full bg-warning/10 text-warning border border-warning/20">
              PII
            </span>
          )}
          <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 tracking-wider">
            RES
          </span>
        </div>
      </div>
    </div>
  );
}, areClusterRowPropsEqual);

// Standalone Log Row (for non-clustered items)
const LogRow = memo(function LogRow({
  log,
  showTimestamps,
  compactMode,
}: {
  log: LogEntry;
  showTimestamps: boolean;
  compactMode: boolean;
}) {
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
  const logTokenCount = getLogTokenCount(log);

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
      aria-label={`Select event ${method}`}
      onClick={() => selectLog(log.id)}
      onKeyDown={(event) => {
        if (!isActivateKey(event)) {
          return;
        }
        event.preventDefault();
        selectLog(log.id);
      }}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className={cn(
        "group/row relative flex items-center gap-3 px-4 cursor-pointer border-b border-border/50 transition-all duration-300",
        compactMode ? "h-7" : "h-8",
        isSelected ? "border-l-2 border-l-primary bg-primary/[0.03]" : "border-l-2 border-l-transparent hover:bg-muted/[0.08]",
        showErrorHighlight && !isSelected && "border-l-2 border-l-destructive bg-destructive/[0.02]",
        showPiiHighlight && !showErrorHighlight && !isSelected && "border-l-2 border-l-warning bg-warning/[0.02]",
        "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary/50"
      )}
    >
      {/* Status Dot */}
      <div className="w-4 flex items-center justify-center flex-shrink-0">
        <div
          className={cn(
            "w-1.5 h-1.5 rounded-full transition-all duration-300",
            getStatusColor(),
            isSelected && "scale-125 shadow-[0_0_8px_rgba(217,119,87,0.4)]"
          )}
        />
      </div>

      {/* Timestamp */}
      {showTimestamps ? (
        <span className="text-[10px] text-muted-foreground font-mono w-24 flex-shrink-0 tabular-nums opacity-60 group-hover/row:opacity-100 transition-opacity">
          {formatTimestamp(log.timestamp)}
        </span>
      ) : null}

      {/* Direction Icon */}
      <div className="flex-shrink-0">
        {log.direction === "in" ? (
          <ArrowDown className="w-3.5 h-3.5 text-cyan-500/70" weight="bold" />
        ) : (
          <ArrowUp className="w-3.5 h-3.5 text-success/70" weight="bold" />
        )}
      </div>

      {/* Source Type Chip */}
      <span
        className={cn(
          "inline-flex items-center justify-center gap-1 px-1.5 py-0.5 rounded-md text-[10px] font-bold border w-[56px] flex-shrink-0 transition-opacity opacity-80 group-hover/row:opacity-100",
          source.color
        )}
      >
        <source.icon className="w-3.5 h-3.5" weight="duotone" />
        {source.label}
      </span>

      {/* Agent */}
      <span
        className="text-[10px] font-medium text-muted-foreground w-24 truncate flex-shrink-0"
        title={log.agent.name}
      >
        {log.agent.name}
      </span>

      {/* Method Badge */}
      <span
        className={cn(
          "inline-flex items-center px-1.5 py-0.5 rounded-md text-[10px] font-mono font-semibold min-w-[110px] max-w-[160px] flex-shrink-0 truncate transition-all",
          isStderrMessage
            ? "bg-destructive/10 text-destructive border-destructive/20"
            : isRawMessage
              ? "bg-warning/10 text-warning border-warning/20"
              : "bg-secondary/40 text-secondary-foreground border border-border/30"
        )}
        title={method}
      >
        {truncate(method, 22)}
        {rpcId !== undefined && (
          <span className="text-muted-foreground/60 ml-1.5 text-[10px]">#{String(rpcId)}</span>
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
      {logTokenCount > 0 && (
        <span
          className="text-[10px] font-mono flex-shrink-0 px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-500 tabular-nums"
          title={`${logTokenCount.toLocaleString()} tokens`}
        >
          {logTokenCount >= 1000
            ? `${(logTokenCount / 1000).toFixed(1)}k`
            : logTokenCount}
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
  const setFilters = useObservabilityStore((state) => state.setFilters);
  const selectLog = useObservabilityStore((state) => state.selectLog);
  const setIsLive = useObservabilityStore((state) => state.setIsLive);
  const clusteringEnabled = useObservabilityStore((state) => state.clusteringEnabled);
  const setClusteringEnabled = useObservabilityStore((state) => state.setClusteringEnabled);
  const defaultClusteringEnabled = useSettingsStore((state) => state.defaultClusteringEnabled);
  const autoScrollEnabled = useSettingsStore((state) => state.autoScrollEnabled);
  const showTimestamps = useSettingsStore((state) => state.showTimestamps);
  const compactMode = useSettingsStore((state) => state.compactMode);

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
  const settingsAppliedRef = useRef(false);
  const displayItemsRef = useRef<DisplayItem[]>(displayItems);
  const selectedLogIdRef = useRef<string | null>(selectedLogId);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const [searchValue, setSearchValue] = useState(filters.searchText || "");

  const hasActiveFilters = !!(
    filters.searchText ||
    filters.method ||
    filters.path ||
    filters.direction ||
    filters.serverName ||
    filters.minLatencyMs ||
    filters.policyDenied ||
    filters.piiDetected ||
    filters.hasError ||
    filters.source
  );

  useEffect(() => {
    displayItemsRef.current = displayItems;
  }, [displayItems]);

  useEffect(() => {
    selectedLogIdRef.current = selectedLogId;
  }, [selectedLogId]);

  useEffect(() => {
    if (settingsAppliedRef.current) {
      return;
    }
    settingsAppliedRef.current = true;
    setClusteringEnabled(defaultClusteringEnabled);
    setIsLive(autoScrollEnabled);
  }, [defaultClusteringEnabled, autoScrollEnabled, setClusteringEnabled, setIsLive]);

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
        const currentItems = displayItemsRef.current;
        if (currentItems.length === 0) {
          return;
        }

        const currentSelection = selectedLogIdRef.current;
        const currentIndex = currentItems.findIndex((item) =>
          item.type === "cluster"
            ? currentSelection === item.cluster.request.id || currentSelection === item.cluster.response?.id
            : currentSelection === item.log.id
        );
        const delta = e.key === "ArrowDown" ? 1 : -1;
        const nextIndex =
          currentIndex === -1
            ? delta > 0
              ? 0
              : currentItems.length - 1
            : Math.min(currentItems.length - 1, Math.max(0, currentIndex + delta));
        const target = currentItems[nextIndex];
        if (!target) {
          return;
        }

        if (target.type === "cluster") {
          const isSameIdPair =
            !!target.cluster.response && target.cluster.request.id === target.cluster.response.id;
          selectLog(target.cluster.request.id, isSameIdPair ? "request" : null);
        } else {
          selectLog(target.log.id);
        }

        virtuosoRef.current?.scrollToIndex({
          index: nextIndex,
          align: "center",
          behavior: "auto",
        });
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
            showTimestamps={showTimestamps}
            compactMode={compactMode}
          />
        );
      }
      return <LogRow log={item.log} showTimestamps={showTimestamps} compactMode={compactMode} />;
    },
    [selectedLogId, selectedLogPart, selectLog, showTimestamps, compactMode]
  );

  return (
    <div className="flex flex-col h-full bg-background rounded-b-[12px] border-x border-b border-dashed border-border overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-border/50 bg-secondary/30 backdrop-blur-md sticky top-0 z-10">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-primary/10 border border-primary/20">
            <Pulse className="w-3.5 h-3.5 text-primary" weight="duotone" />
            <span className="text-[10px] font-bold text-primary tracking-wider uppercase">Live Stream</span>
          </div>
          <div className="h-4 w-[1px] bg-border/50 mx-1" />
          <div className="flex items-center gap-3 text-[10px] font-bold text-muted-foreground uppercase tracking-wider">
            <span>{displayItems.length} Events</span>
            {hasActiveFilters && (
              <span className="text-primary/70 bg-primary/5 px-1.5 py-0.5 rounded">Filtered</span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center bg-secondary/40 rounded-lg border border-border/50 p-0.5">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setClusteringEnabled(true)}
              className={cn(
                "h-6 px-2.5 text-[9px] font-bold rounded-md transition-all",
                clusteringEnabled ? "bg-primary text-primary-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"
              )}
            >
              CLUSTERED
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setClusteringEnabled(false)}
              className={cn(
                "h-6 px-2.5 text-[9px] font-bold rounded-md transition-all",
                !clusteringEnabled ? "bg-primary text-primary-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"
              )}
            >
              RAW
            </Button>
          </div>

          <Button
            variant="ghost"
            size="sm"
            onClick={toggleLive}
            className={cn(
              "h-7 px-2.5 gap-1.5 border border-border/50 rounded-lg hover:bg-muted transition-all",
              isLive ? "text-success bg-success/5 border-success/20" : "text-muted-foreground focus:ring-0"
            )}
          >
            {isLive ? (
              <>
                <div className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
                <span className="text-[9px] font-bold">PAUSE</span>
              </>
            ) : (
              <>
                <div className="w-1.5 h-1.5 rounded-full bg-muted-foreground" />
                <span className="text-[9px] font-bold text-foreground">RESUME</span>
              </>
            )}
          </Button>

          {/* Search Input */}
          <div className="relative w-64">
            <MagnifyingGlass className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground/60" />
            <Input
              ref={searchInputRef}
              type="text"
              placeholder="Filter logs... (⌘K)"
              value={searchValue}
              onChange={(e) => setSearchValue(e.target.value)}
              className="pl-8 pr-8 h-8 bg-secondary/40 border-border/50 text-xs focus:border-primary/50 focus:ring-primary/20 transition-all rounded-lg"
            />
            {searchValue && (
              <Button
                variant="ghost"
                size="sm"
                onClick={handleClearSearch}
                className="absolute right-1 top-1/2 -translate-y-1/2 h-6 w-6 p-0 hover:bg-muted"
              >
                <X className="w-3 h-3 text-muted-foreground" />
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
                    or <code className="font-mono bg-muted px-1 rounded">soth on</code> for AI API calls.
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
            defaultItemHeight={clusteringEnabled ? (compactMode ? 56 : 64) : (compactMode ? 28 : 32)}
            increaseViewportBy={120}
            overscan={6}
          />
        )}
      </div>
    </div>
  );
}
