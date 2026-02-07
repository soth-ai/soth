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

  // Policy denied
  if (log.policy_allowed === false) {
    insights.push({
      icon: ShieldSlash,
      color: "text-red-500",
      title: "Request blocked by policy",
      description: log.policy_reason
        ? `Reason: ${log.policy_reason}`
        : "This request was denied by your security policy. Check your policy rules to ensure this is expected behavior.",
    });
  }

  // PII detected
  if (log.pii_detected && log.pii_types.length > 0) {
    insights.push({
      icon: Eye,
      color: "text-orange-500",
      title: "Personal data detected",
      description: `Found ${log.pii_types.join(", ")} in this message. Consider masking sensitive data or reviewing your data handling policies.`,
    });
  }

  // Slow response
  const effectiveLatency = latency ?? log.latency_ms ?? 0;
  if (effectiveLatency >= 1000) {
    insights.push({
      icon: Timer,
      color: "text-amber-500",
      title: "Slow response time",
      description: `This operation took ${(effectiveLatency / 1000).toFixed(1)}s. Consider optimizing the tool or checking for upstream issues.`,
    });
  }

  // Error response
  if (parsed?.error) {
    insights.push({
      icon: XCircle,
      color: "text-red-500",
      title: "Error response",
      description: `Error ${parsed.error.code}: ${parsed.error.message}. This may indicate a problem with the MCP server or tool.`,
    });
  }

  // High token count
  if (log.token_count && log.token_count > 10000) {
    insights.push({
      icon: CurrencyDollar,
      color: "text-amber-500",
      title: "High token usage",
      description: `This message used ${log.token_count.toLocaleString()} tokens. Consider optimizing prompts or responses to reduce costs.`,
    });
  }

  // No insights - show success state
  if (insights.length === 0) {
    return null;
  }

  return (
    <div className="px-4 py-3 bg-muted/20 border-b border-border">
      <div className="flex items-center gap-1.5 mb-2 text-xs">
        <Lightbulb className="w-3.5 h-3.5 text-accent" weight="duotone" />
        <span className="font-semibold text-foreground">Why This Matters</span>
      </div>
      <div className="space-y-2">
        {insights.map((insight, i) => (
          <div key={i} className="flex items-start gap-2">
            <insight.icon className={cn("w-4 h-4 mt-0.5 flex-shrink-0", insight.color)} weight="fill" />
            <div className="flex-1 min-w-0">
              <p className={cn("text-xs font-medium", insight.color)}>{insight.title}</p>
              <p className="text-xs text-muted-foreground mt-0.5">{insight.description}</p>
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
    <div className="flex flex-col h-full bg-background border-l border-dashed border-border">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-border bg-card">
        <div className="flex items-center gap-2">
          {isStderrMessage ? (
            <WarningCircle className="w-4 h-4 text-red-500" weight="fill" />
          ) : showRawUi ? (
            <Terminal className="w-4 h-4 text-amber-500" weight="duotone" />
          ) : (
            <FileJs className="w-4 h-4 text-accent" weight="duotone" />
          )}
          <h2 className="text-[24px] font-normal text-foreground">
            {isStderrMessage ? "Stderr Output" : showRawUi ? "Raw Output" : "Inspector"}
          </h2>
        </div>
        {selectedLog && (
          <div className="flex items-center gap-2">
            {hasPairedContent && (
              <div className="flex items-center rounded-md border border-border overflow-hidden">
                <button
                  onClick={() => setActiveTab("request")}
                  className={cn(
                    "flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium transition-colors duration-150 ease-in-out",
                    activeTab === "request"
                      ? "bg-cyan-500/20 text-cyan-500"
                      : "text-muted-foreground hover:bg-muted"
                  )}
                >
                  <ArrowDown className="w-3 h-3" weight="bold" />
                  Request
                </button>
                <button
                  onClick={() => setActiveTab("response")}
                  className={cn(
                    "flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium transition-colors duration-150 ease-in-out border-l border-border",
                    activeTab === "response"
                      ? "bg-emerald-500/20 text-emerald-500"
                      : "text-muted-foreground hover:bg-muted"
                  )}
                >
                  <ArrowUp className="w-3 h-3" weight="bold" />
                  Response
                </button>
              </div>
            )}
            {/* Copy button */}
            <Button
              variant="ghost"
              size="sm"
              onClick={handleCopy}
              className="h-8 px-3 border border-border hover:bg-muted"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 mr-2 text-emerald-500" />
                  <span className="text-xs text-emerald-500">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 mr-2 text-muted-foreground" />
                  <span className="text-xs text-foreground">Copy</span>
                </>
              )}
            </Button>
          </div>
        )}
      </div>

      {/* Content */}
      {selectedLog ? (
        <div className="flex flex-col flex-1 overflow-hidden">
          {/* Metadata */}
          <div className="px-4 py-3 bg-muted/40 border-b border-border space-y-2">
            {/* WarningCircle banners */}
            {isStderrMessage && (
              <div className="flex items-center gap-2 px-3 py-2 bg-red-500/10 border border-red-500/30 rounded-md mb-2">
                <WarningCircle className="w-4 h-4 text-red-500 flex-shrink-0" weight="fill" />
                <span className="text-xs text-red-500">
                  This is stderr output from the MCP server (errors, warnings, tracebacks)
                </span>
              </div>
            )}
            {showRawUi && (
              <div className="flex items-center gap-2 px-3 py-2 bg-amber-500/10 border border-amber-500/30 rounded-md mb-2">
                <Terminal className="w-4 h-4 text-amber-500 flex-shrink-0" weight="duotone" />
                <span className="text-xs text-amber-500">
                  This is raw stdout output (non-JSON-RPC data)
                </span>
              </div>
            )}
            {selectedLog.policy_allowed === false && (
              <div className="flex items-center gap-2 px-3 py-2 bg-red-500/10 border border-red-500/30 rounded-md mb-2">
                <ShieldSlash className="w-4 h-4 text-red-500 flex-shrink-0" weight="fill" />
                <span className="text-xs text-red-500">
                  Policy denied: {selectedLog.policy_reason || "No reason provided"}
                </span>
              </div>
            )}
            {selectedLog.pii_detected && (
              <div className="flex items-center gap-2 px-3 py-2 bg-orange-500/10 border border-orange-500/30 rounded-md mb-2">
                <Eye className="w-4 h-4 text-orange-500 flex-shrink-0" weight="fill" />
                <span className="text-xs text-orange-500">
                  PII detected: {selectedLog.pii_types.join(", ")}
                </span>
              </div>
            )}

            {/* Metadata rows */}
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground font-medium">Timestamp</span>
              <span className="font-mono text-foreground tabular-nums">
                {formatTimestamp(selectedLog.timestamp)}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground font-medium">Type</span>
              <span
                className={cn(
                  "inline-flex items-center px-1.5 py-0.5 rounded-md font-mono font-medium border",
                  isStderrMessage
                    ? "bg-red-500/20 text-red-500 border-red-500/30"
                    : isRawMessage
                    ? "bg-amber-500/20 text-amber-500 border-amber-500/30"
                    : "bg-secondary text-secondary-foreground border-border"
                )}
              >
                {isStderrMessage ? "stderr" : isRawMessage ? "raw" : "json-rpc"}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground font-medium">Direction</span>
              <span
                className={cn(
                  "inline-flex items-center px-1.5 py-0.5 rounded-md font-mono font-medium bg-secondary border border-border",
                  effectiveDirection === "in" ? "text-cyan-500" : "text-emerald-500"
                )}
              >
                {effectiveDirection === "in" ? "Incoming" : "Outgoing"}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground font-medium">Server</span>
              <span className="font-mono text-foreground">{selectedLog.server_name}</span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground font-medium">Agent</span>
              <span className="font-mono text-foreground">{selectedLog.agent.name}</span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground font-medium">Session</span>
              <span
                className="font-mono text-muted-foreground text-[11px] truncate max-w-[180px]"
                title={selectedLog.session_id}
              >
                ...{selectedLog.session_id.slice(-12)}
              </span>
            </div>

            {/* Latency */}
            {(latency !== null || selectedLog.latency_ms !== undefined) && (
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground font-medium">
                  {latency !== null ? "Round-trip Latency" : "Latency"}
                </span>
                <span
                  className={cn(
                    "font-mono font-semibold tabular-nums",
                    getLatencyColor(latency ?? selectedLog.latency_ms ?? 0)
                  )}
                >
                  {formatLatency(latency ?? selectedLog.latency_ms ?? 0)}
                </span>
              </div>
            )}

            {/* Token count */}
            {selectedLog.token_count !== undefined && selectedLog.token_count > 0 && (
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground font-medium">Tokens</span>
                <span className="font-mono text-amber-500 tabular-nums">
                  {selectedLog.token_count.toLocaleString()}
                </span>
              </div>
            )}

            {/* Correlated Request Info */}
            {correlatedRequest && (
              <div className="pt-2 mt-2 border-t border-border">
                <div className="flex items-center justify-between text-xs mb-2">
                  <span className="text-muted-foreground font-medium">Correlated Request</span>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={handleJumpToRequest}
                    className="h-7 px-3 text-xs border border-border hover:bg-muted"
                  >
                    <ArrowRight className="w-3.5 h-3.5 mr-1.5 text-accent" />
                    <span className="text-foreground">Jump</span>
                  </Button>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">Request ID</span>
                  <span className="font-mono text-foreground">#{String(parsed?.id)}</span>
                </div>
                <div className="flex items-center justify-between text-xs mt-1">
                  <span className="text-muted-foreground">Method</span>
                  <span className="inline-flex items-center px-1.5 py-0.5 rounded-md font-mono text-[11px] font-medium bg-secondary text-cyan-500 border border-border">
                    {parseLogMessage(correlatedRequest)?.method}
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* Why This Matters Section */}
          <WhyThisMatters log={selectedLog} parsed={parsed} latency={latency} />

          {/* Monaco Editor */}
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
                fontSize: 16,
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
                  top: 16,
                  bottom: 16,
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
            <p className="text-sm text-foreground font-medium mb-1">Select a message</p>
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
