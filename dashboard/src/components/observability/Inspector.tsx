"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import Editor from "@monaco-editor/react";
import {
  Copy,
  Check,
  FileJs,
  ArrowRight,
  ArrowUp,
  ArrowDown,
  WarningCircle,
  Terminal,
  ShieldSlash,
  Eye,
  Lightbulb,
  Timer,
  XCircle,
  CurrencyDollar,
} from "@phosphor-icons/react";
import { toast } from "sonner";
import {
  useObservabilityStore,
  decodeEditorContent,
  hasPairedPayload,
  parseLogMessage,
  findCorrelatedRequest,
  calculateLatency,
  type LogEntry,
  type ParsedMessage,
} from "@/store/observability";
import { fetchEventPayload } from "@/lib/event-payload";
import { defineSothMonacoTheme, SOTH_MONACO_THEME } from "@/lib/monaco-theme";
import { Button } from "@/components/ui/button";
import { cn, formatTimestamp, formatLatency } from "@/lib/utils";

interface Insight {
  icon: React.ElementType;
  color: string;
  title: string;
  description: string;
}

function WhyThisMatters({
  log,
  parsed,
  latency,
}: {
  log: LogEntry;
  parsed: ParsedMessage | null;
  latency: number | null;
}) {
  const insights: Insight[] = [];

  if (log.policy_allowed === false) {
    insights.push({
      icon: ShieldSlash,
      color: "text-destructive",
      title: "Policy Violation",
      description: log.policy_reason || "Access to this resource was blocked by security policy.",
    });
  }

  if (log.pii_detected) {
    insights.push({
      icon: Eye,
      color: "text-warning",
      title: "Sensitive Data Found",
      description: `Detected: ${log.pii_types.join(", ")}. Content has been audited.`,
    });
  }

  const effectiveLatency = latency ?? log.latency_ms ?? 0;
  if (effectiveLatency >= 1000) {
    insights.push({
      icon: Timer,
      color: "text-warning",
      title: "Performance Bottleneck",
      description: `Operation latancy (${(effectiveLatency / 1000).toFixed(1)}s) exceeds safety threshold.`,
    });
  }

  if (parsed?.error) {
    insights.push({
      icon: XCircle,
      color: "text-destructive",
      title: "System Error",
      description: `[${parsed.error.code}] ${parsed.error.message}`,
    });
  }

  if (log.token_count && log.token_count > 10000) {
    insights.push({
      icon: CurrencyDollar,
      color: "text-warning",
      title: "High Resource Usage",
      description: `${log.token_count.toLocaleString()} tokens consumed in a single transaction.`,
    });
  }

  if (insights.length === 0) return null;

  return (
    <div className="mx-3 my-1.5 rounded-md border border-primary/20 bg-primary/5">
      <div className="flex items-center gap-1.5 border-b border-primary/15 px-2 py-1">
        <Lightbulb className="w-3.5 h-3.5 text-primary" weight="fill" />
        <h3 className="text-[8px] font-semibold text-foreground tracking-[0.08em] uppercase">
          Insights
        </h3>
      </div>
      <div className="space-y-1 px-2 py-1.5">
        {insights.map((insight, i) => (
          <div key={i} className="flex gap-1.5">
            <div className={cn("mt-0.5", insight.color)}>
              <insight.icon className="w-3 h-3" weight="fill" />
            </div>
            <div className="flex-1 min-w-0">
              <p className={cn("text-[9px] font-semibold leading-tight", insight.color)}>
                {insight.title}
              </p>
              <p className="text-[9px] text-muted-foreground leading-tight mt-0.5">
                {insight.description}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function Inspector() {
  const logs = useObservabilityStore((state) => state.logs);
  const selectedLogId = useObservabilityStore((state) => state.selectedLogId);
  const selectedLogPart = useObservabilityStore((state) => state.selectedLogPart);
  const selectLog = useObservabilityStore((state) => state.selectLog);
  const hydrateLogPayload = useObservabilityStore((state) => state.hydrateLogPayload);
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<"request" | "response">("request");

  // Memoize selected log lookup
  const selectedLog = useMemo(
    () => logs.find((l) => l.id === selectedLogId) || null,
    [logs, selectedLogId]
  );

  const hasPairedContent = useMemo(
    () => (selectedLog ? hasPairedPayload(selectedLog) : false),
    [selectedLog]
  );

  const getEmptyResponsePlaceholder = useCallback(() => {
    if (!selectedLog) return "[no response body captured]";
    const method = selectedLog.method || "request";
    const status = selectedLog.status_code ?? "unknown";
    if (method.toLowerCase().includes("/backend-api/codex/responses")) {
      return `[no HTTP response body captured for ${method} (HTTP ${status}) - Codex output may be streamed via WebSocket]`;
    }
    return `[no HTTP response body captured for ${method} (HTTP ${status})]`;
  }, [selectedLog]);

  const displayContent = useMemo(() => {
    if (!selectedLog) return "";
    if (!hasPairedContent) return selectedLog.content;
    if (activeTab === "request") {
      return selectedLog.request_content || selectedLog.request_preview || "";
    }
    return (
      selectedLog.response_content ||
      selectedLog.response_preview ||
      getEmptyResponsePlaceholder()
    );
  }, [selectedLog, hasPairedContent, activeTab, getEmptyResponsePlaceholder]);

  const editorPayload = useMemo(
    () => decodeEditorContent(displayContent),
    [displayContent]
  );
  const isJsonEditor = editorPayload.language === "json";

  // Check message type
  const isRawMessage = selectedLog?.message_type === "raw";
  const isStderrMessage = selectedLog?.message_type === "stderr";
  const showRawUi = !!isRawMessage && !isJsonEditor;
  const isNonJsonRpc = isStderrMessage || showRawUi;

  // Parse and correlate
  const parsed = selectedLog && !isNonJsonRpc ? parseLogMessage(selectedLog) : null;
  const isResponse =
    parsed && !parsed.method && (parsed.result !== undefined || parsed.error !== undefined);
  const correlatedRequest =
    isResponse && selectedLog ? findCorrelatedRequest(selectedLog, logs) : null;
  const latency =
    correlatedRequest && selectedLog
      ? calculateLatency(correlatedRequest, selectedLog)
      : null;

  // Reset copied state when selection changes
  useEffect(() => {
    setCopied(false);
    if (!selectedLog) return;
    if (!hasPairedContent) {
      setActiveTab("request");
      return;
    }
    if (selectedLogPart === "request") {
      setActiveTab("request");
      return;
    }
    if (selectedLogPart === "response") {
      setActiveTab("response");
      return;
    }
    setActiveTab(
      selectedLog.response_content || selectedLog.response_preview || selectedLog.response_content_ref
        ? "response"
        : "request"
    );
  }, [
    selectedLog,
    selectedLogPart,
    hasPairedContent,
    selectedLog?.response_content,
    selectedLog?.response_preview,
    selectedLog?.response_content_ref,
  ]);

  useEffect(() => {
    if (!selectedLog) return;

    let partToLoad: "request" | "response" | "content" | null = null;
    if (hasPairedContent) {
      if (activeTab === "request" && !selectedLog.request_content && selectedLog.request_content_ref) {
        partToLoad = "request";
      } else if (
        activeTab === "response" &&
        !selectedLog.response_content &&
        selectedLog.response_content_ref
      ) {
        partToLoad = "response";
      }
    } else if (
      selectedLog.content_ref &&
      (selectedLog.content.length === 0 ||
        selectedLog.content === (selectedLog.content_preview || ""))
    ) {
      partToLoad = "content";
    }

    if (!partToLoad) return;

    let cancelled = false;
    const loadPayload = async () => {
      try {
        const fullContent = await fetchEventPayload(selectedLog.id, partToLoad!);
        if (!cancelled && fullContent) {
          hydrateLogPayload(selectedLog.id, partToLoad!, fullContent);
        }
      } catch (error) {
        console.warn("Failed to lazy-load event payload", error);
      }
    };

    loadPayload();
    return () => {
      cancelled = true;
    };
  }, [
    selectedLog,
    activeTab,
    hasPairedContent,
    hydrateLogPayload,
    selectedLog?.id,
    selectedLog?.content,
    selectedLog?.content_ref,
    selectedLog?.request_content,
    selectedLog?.request_content_ref,
    selectedLog?.response_content,
    selectedLog?.response_content_ref,
  ]);

  const handleCopy = useCallback(async () => {
    if (!selectedLog) return;

    try {
      await navigator.clipboard.writeText(displayContent);
      setCopied(true);
      toast.success("JSON copied to clipboard", { duration: 2000 });
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
      toast.error("Failed to copy to clipboard", { duration: 3000 });
    }
  }, [selectedLog, displayContent]);

  const handleJumpToRequest = useCallback(() => {
    if (correlatedRequest) {
      selectLog(correlatedRequest.id);
    }
  }, [correlatedRequest, selectLog]);

  // Get latency color
  const getLatencyColor = (ms: number) => {
    if (ms >= 1000) return "text-red-500";
    if (ms >= 200) return "text-amber-500";
    return "text-emerald-500";
  };

  const handleMonacoBeforeMount = useCallback((monaco: unknown) => {
    defineSothMonacoTheme(monaco as Parameters<typeof defineSothMonacoTheme>[0]);
  }, []);

  const effectiveDirection = hasPairedContent
    ? activeTab === "response"
      ? "out"
      : "in"
    : selectedLog?.direction;

  return (
    <div className="flex flex-col h-full bg-background border-l border-border/50 font-sans">
      <div className="flex items-center justify-between px-2.5 py-1 border-b border-border/50 bg-secondary/30 backdrop-blur-md sticky top-0 z-10">
        <div className="flex items-center gap-1.5 min-w-0">
          <div className="w-5 h-5 rounded border border-primary/20 bg-primary/10 flex items-center justify-center shrink-0">
            {isStderrMessage ? (
              <WarningCircle className="w-3 h-3 text-destructive" weight="fill" />
            ) : showRawUi ? (
              <Terminal className="w-3 h-3 text-warning" weight="duotone" />
            ) : (
              <FileJs className="w-3 h-3 text-primary" weight="duotone" />
            )}
          </div>
          <div className="min-w-0">
            <h2 className="text-[8px] font-semibold text-foreground tracking-[0.08em] uppercase">
              {isStderrMessage ? "Stderr Output" : showRawUi ? "Raw Data" : "Event Inspector"}
            </h2>
            <p className="text-[8px] text-muted-foreground font-medium tracking-[0.02em] truncate">
              {selectedLog?.server_name} • {selectedLog?.agent.name}
            </p>
          </div>
        </div>
        {selectedLog && (
          <div className="flex items-center gap-1 shrink-0">
            {hasPairedContent && (
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setActiveTab("request")}
                  className={cn(
                    "inline-flex h-5 items-center gap-1 rounded-md border px-1.5 text-[8px] font-semibold uppercase tracking-[0.06em] transition-colors",
                    activeTab === "request"
                      ? "border-primary/35 bg-primary/15 text-primary"
                      : "border-border/50 bg-secondary/25 text-muted-foreground hover:text-foreground"
                  )}
                >
                  <ArrowDown className="w-2.5 h-2.5" weight="bold" />
                  Req
                </button>
                <button
                  onClick={() => setActiveTab("response")}
                  className={cn(
                    "inline-flex h-5 items-center gap-1 rounded-md border px-1.5 text-[8px] font-semibold uppercase tracking-[0.06em] transition-colors",
                    activeTab === "response"
                      ? "border-success/35 bg-success/15 text-success"
                      : "border-border/50 bg-secondary/25 text-muted-foreground hover:text-foreground"
                  )}
                >
                  <ArrowUp className="w-2.5 h-2.5" weight="bold" />
                  Res
                </button>
              </div>
            )}
            <Button
              variant="ghost"
              size="sm"
              onClick={handleCopy}
              className="h-5 px-1.5 border border-border/50 bg-secondary/20 hover:bg-muted font-semibold text-[8px] gap-1 rounded-md"
            >
              {copied ? (
                <>
                  <Check className="w-2.5 h-2.5 text-success" weight="bold" />
                  <span className="text-success">Done</span>
                </>
              ) : (
                <>
                  <Copy className="w-2.5 h-2.5 text-muted-foreground" weight="bold" />
                  <span>Copy</span>
                </>
              )}
            </Button>
          </div>
        )}
      </div>

      {/* Content */}
      {selectedLog ? (
        <div className="flex flex-col flex-1 overflow-hidden">
          <div className="flex-shrink-0 overflow-y-auto max-h-[38%] border-b border-border/50 bg-secondary/10">
            <div className="px-3 py-2 space-y-1.5">
              <div className="rounded-md border border-border/50 bg-secondary/20 px-2 py-1.5">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[9px]">
                  <span className="text-muted-foreground uppercase tracking-[0.08em]">Time</span>
                  <span className="font-mono text-foreground tabular-nums">
                    {formatTimestamp(selectedLog.timestamp)}
                  </span>
                  <span className="text-muted-foreground/70">|</span>
                  <span
                    className={cn(
                      "inline-flex items-center rounded border px-1 py-0.5 text-[8px] font-semibold uppercase tracking-[0.06em]",
                      isStderrMessage
                        ? "bg-destructive/10 text-destructive border-destructive/20"
                        : isRawMessage
                          ? "bg-warning/10 text-warning border-warning/20"
                          : "bg-primary/10 text-primary border-primary/20"
                    )}
                  >
                    {isStderrMessage ? "stderr" : isRawMessage ? "raw" : "json-rpc"}
                  </span>
                  <span className="text-muted-foreground/70">|</span>
                  <span className="text-muted-foreground uppercase tracking-[0.08em]">Latency</span>
                  {(latency !== null || selectedLog.latency_ms !== undefined) ? (
                    <span
                      className={cn(
                        "font-mono font-semibold tabular-nums",
                        getLatencyColor(latency ?? selectedLog.latency_ms ?? 0)
                      )}
                    >
                      {formatLatency(latency ?? selectedLog.latency_ms ?? 0)}
                    </span>
                  ) : (
                    <span className="text-muted-foreground">N/A</span>
                  )}
                  <span className="text-muted-foreground/70">|</span>
                  <span className="text-muted-foreground uppercase tracking-[0.08em]">Tokens</span>
                  <span className="font-mono tabular-nums text-warning">
                    {selectedLog.token_count !== undefined && selectedLog.token_count > 0
                      ? selectedLog.token_count.toLocaleString()
                      : "0"}
                  </span>
                </div>
              </div>

              <div className="rounded-md border border-border/50 bg-secondary/20 px-2 py-1.5 space-y-1">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[9px]">
                  <span className="text-muted-foreground uppercase tracking-[0.08em]">Direction</span>
                  <span
                    className={cn(
                      "font-semibold uppercase tracking-[0.08em]",
                      effectiveDirection === "in" ? "text-cyan-500" : "text-success"
                    )}
                  >
                    {effectiveDirection === "in" ? "Inbound" : "Outbound"}
                  </span>
                  <span className="text-muted-foreground/70">|</span>
                  <span className="text-muted-foreground uppercase tracking-[0.08em]">Session</span>
                  <span className="font-mono text-foreground" title={selectedLog.session_id}>
                    {selectedLog.session_id.slice(0, 8)}...{selectedLog.session_id.slice(-8)}
                  </span>
                </div>
                {correlatedRequest && (
                  <div className="flex items-center justify-between gap-2 border-t border-border/40 pt-1 text-[9px]">
                    <div className="flex min-w-0 items-center gap-1.5">
                      <span className="text-muted-foreground uppercase tracking-[0.08em]">Paired</span>
                      <span className="font-mono text-muted-foreground">#{String(parsed?.id)}</span>
                      <span className="font-mono text-primary truncate">
                        {parseLogMessage(correlatedRequest)?.method}
                      </span>
                    </div>
                    <button
                      onClick={handleJumpToRequest}
                      className="inline-flex h-5 items-center gap-1 rounded-md border border-primary/30 bg-primary/10 px-1.5 text-[8px] font-semibold uppercase tracking-[0.06em] text-primary hover:bg-primary/15 transition-colors"
                    >
                      <ArrowRight className="w-2.5 h-2.5" weight="bold" />
                      Jump
                    </button>
                  </div>
                )}
              </div>
            </div>

            <WhyThisMatters log={selectedLog} parsed={parsed} latency={latency} />
          </div>

          <div className="flex-1 overflow-hidden">
            <Editor
              height="100%"
              language={editorPayload.language}
              value={editorPayload.content}
              theme={SOTH_MONACO_THEME}
              beforeMount={handleMonacoBeforeMount}
              options={{
                readOnly: true,
                minimap: { enabled: false },
                fontSize: 12,
                fontFamily: "Geist Mono, JetBrains Mono, monospace",
                lineNumbers: "on",
                scrollBeyondLastLine: false,
                automaticLayout: true,
                wordWrap: "on",
                folding: editorPayload.language === "json",
                renderLineHighlight: "all",
                scrollbar: {
                  vertical: "auto",
                  horizontal: "auto",
                  verticalScrollbarSize: 6,
                  horizontalScrollbarSize: 6,
                },
                padding: {
                  top: 12,
                  bottom: 12,
                },
              }}
            />
          </div>
        </div>
      ) : (
        <div className="flex items-center justify-center h-full">
          <div className="text-center max-w-xs">
            <div className="w-12 h-12 mx-auto mb-3 rounded-xl bg-muted/50 flex items-center justify-center">
              <FileJs className="w-6 h-6 text-muted-foreground/50" weight="duotone" />
            </div>
            <p className="text-xs text-foreground font-medium mb-1">Select a message</p>
            <p className="text-xs text-muted-foreground">
              Click any message in the stream to view its full JSON content, metadata, and
              latency info.
            </p>
            <p className="text-[11px] text-muted-foreground/60 mt-3">
              Use{" "}
              <kbd className="px-1 py-0.5 bg-muted border border-border rounded text-[10px] font-mono">
                ↑
              </kbd>{" "}
              <kbd className="px-1 py-0.5 bg-muted border border-border rounded text-[10px] font-mono">
                ↓
              </kbd>{" "}
              to navigate
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
