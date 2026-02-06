"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import Editor from "@monaco-editor/react";
import {
  Copy,
  Check,
  CloudArrowUp,
  ShieldSlash,
  Eye,
  CurrencyDollar,
  Coins,
  Timer,
  ArrowUp,
  ArrowDown,
} from "@phosphor-icons/react";
import { toast } from "sonner";
import { useObservabilityStore } from "@/store/observability";
import { Button } from "@/components/ui/button";
import { cn, formatTimestamp, formatLatency } from "@/lib/utils";

type TabType = "request" | "response";

function formatJSON(jsonStr: string): string {
  try {
    const parsed = JSON.parse(jsonStr);
    return JSON.stringify(parsed, null, 2);
  } catch {
    return jsonStr;
  }
}

export function AiInspector() {
  const logs = useObservabilityStore((state) => state.logs);
  const selectedLogId = useObservabilityStore((state) => state.selectedLogId);
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<TabType>("request");

  // Memoize selected log lookup (AI proxy and agent app logs)
  const selectedLog = useMemo(() => {
    const log = logs.find((l) => l.id === selectedLogId);
    return (log?.source === "ai_proxy" || log?.source === "agent_app") ? log : null;
  }, [logs, selectedLogId]);

  // Check if this is a paired request/response event
  const hasPairedContent = useMemo(() => {
    return !!(selectedLog?.request_content || selectedLog?.response_content);
  }, [selectedLog]);

  // Reset copied state and tab when selection changes
  useEffect(() => {
    setCopied(false);
    // Default to response tab for paired events, request otherwise
    if (selectedLog?.response_content) {
      setActiveTab("response");
    } else {
      setActiveTab("request");
    }
  }, [selectedLog?.id, selectedLog?.response_content]);

  const handleCopy = useCallback(async () => {
    if (!selectedLog) return;

    let contentToCopy: string;
    if (hasPairedContent) {
      contentToCopy = (activeTab === "request" ? selectedLog.request_content : selectedLog.response_content) || "";
    } else {
      contentToCopy = selectedLog.response_content || selectedLog.content;
    }

    try {
      await navigator.clipboard.writeText(contentToCopy);
      setCopied(true);
      toast.success("Copied to clipboard", { duration: 2000 });
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
      toast.error("Failed to copy to clipboard", { duration: 3000 });
    }
  }, [selectedLog, hasPairedContent, activeTab]);

  // Formatted content for display
  const formattedContent = useMemo(() => {
    if (!selectedLog) return "";

    if (hasPairedContent) {
      const content = activeTab === "request"
        ? selectedLog.request_content
        : selectedLog.response_content;
      return content ? formatJSON(content) : "";
    }

    // For non-paired events, prefer response_content if available, then content
    const content = selectedLog.response_content || selectedLog.content;
    return formatJSON(content);
  }, [selectedLog, hasPairedContent, activeTab]);

  // Get latency color
  const getLatencyColor = (ms: number) => {
    if (ms >= 2000) return "text-red-500";
    if (ms >= 500) return "text-amber-500";
    return "text-emerald-500";
  };

  // Get provider color
  const getProviderColor = (provider: string) => {
    switch (provider.toLowerCase()) {
      case "openai":
        return "bg-emerald-500/20 text-emerald-500 border-emerald-500/30";
      case "anthropic":
        return "bg-orange-500/20 text-orange-500 border-orange-500/30";
      case "google":
        return "bg-blue-500/20 text-blue-500 border-blue-500/30";
      default:
        return "bg-secondary text-secondary-foreground border-border";
    }
  };

  return (
    <div className="flex flex-col h-full bg-background border-l border-border">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-border bg-card">
        <div className="flex items-center gap-2">
          <CloudArrowUp className="w-4 h-4 text-accent" weight="duotone" />
          <h2 className="text-sm font-semibold text-foreground">Request Inspector</h2>
        </div>
        {selectedLog && (
          <div className="flex items-center gap-2">
            {/* Request/Response Tabs */}
            {hasPairedContent && (
              <div className="flex items-center rounded-md border border-border overflow-hidden">
                <button
                  onClick={() => setActiveTab("request")}
                  className={cn(
                    "flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium transition-colors",
                    activeTab === "request"
                      ? "bg-cyan-500/20 text-cyan-500"
                      : "text-muted-foreground hover:bg-muted"
                  )}
                >
                  <ArrowUp className="w-3 h-3" weight="bold" />
                  Request
                </button>
                <button
                  onClick={() => setActiveTab("response")}
                  className={cn(
                    "flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium transition-colors border-l border-border",
                    activeTab === "response"
                      ? "bg-emerald-500/20 text-emerald-500"
                      : "text-muted-foreground hover:bg-muted"
                  )}
                >
                  <ArrowDown className="w-3 h-3" weight="bold" />
                  Response
                  {selectedLog.status_code && (
                    <span className={cn(
                      "ml-1 px-1 py-0.5 rounded text-[10px] font-mono",
                      selectedLog.status_code >= 400
                        ? "bg-red-500/20 text-red-500"
                        : "bg-emerald-500/20 text-emerald-500"
                    )}>
                      {selectedLog.status_code}
                    </span>
                  )}
                </button>
              </div>
            )}

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
            {/* Warning banners */}
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
              <span className="text-muted-foreground font-medium">Direction</span>
              <span
                className={cn(
                  "inline-flex items-center px-1.5 py-0.5 rounded-md font-mono font-medium bg-secondary border border-border",
                  selectedLog.direction === "in" ? "text-cyan-500" : "text-emerald-500"
                )}
              >
                {selectedLog.direction === "in" ? "Request" : "Response"}
              </span>
            </div>

            {selectedLog.provider && (
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground font-medium">Provider</span>
                <span
                  className={cn(
                    "inline-flex items-center px-1.5 py-0.5 rounded-md font-mono font-medium border",
                    getProviderColor(selectedLog.provider)
                  )}
                >
                  {selectedLog.provider}
                </span>
              </div>
            )}

            {selectedLog.model && (
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground font-medium">Model</span>
                <span className="font-mono text-foreground">{selectedLog.model}</span>
              </div>
            )}

            {selectedLog.method && (
              <div className="flex flex-col gap-1 text-xs">
                <span className="text-muted-foreground font-medium">Endpoint</span>
                <span
                  className="font-mono text-foreground text-[11px] break-all"
                  title={selectedLog.method}
                >
                  {selectedLog.method}
                </span>
              </div>
            )}

            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground font-medium">Session</span>
              <span
                className="font-mono text-muted-foreground text-[11px] truncate max-w-[180px]"
                title={selectedLog.session_id}
              >
                ...{selectedLog.session_id.slice(-12)}
              </span>
            </div>

            {/* Performance metrics */}
            {(selectedLog.latency_ms !== undefined ||
              selectedLog.token_count !== undefined ||
              selectedLog.cost_usd !== undefined) && (
              <div className="pt-2 mt-2 border-t border-border space-y-2">
                <p className="text-[10px] text-muted-foreground font-semibold uppercase tracking-wider">
                  Performance
                </p>

                {selectedLog.latency_ms !== undefined && (
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground font-medium flex items-center gap-1.5">
                      <Timer className="w-3 h-3" weight="fill" />
                      Latency
                    </span>
                    <span
                      className={cn(
                        "font-mono font-semibold tabular-nums",
                        getLatencyColor(selectedLog.latency_ms)
                      )}
                    >
                      {formatLatency(selectedLog.latency_ms)}
                    </span>
                  </div>
                )}

                {selectedLog.token_count !== undefined && selectedLog.token_count > 0 && (
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground font-medium flex items-center gap-1.5">
                      <Coins className="w-3 h-3" weight="fill" />
                      Tokens
                    </span>
                    <span className="font-mono text-amber-500 tabular-nums">
                      {selectedLog.token_count.toLocaleString()}
                    </span>
                  </div>
                )}

                {selectedLog.cost_usd !== undefined && selectedLog.cost_usd > 0 && (
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground font-medium flex items-center gap-1.5">
                      <CurrencyDollar className="w-3 h-3" weight="fill" />
                      Cost
                    </span>
                    <span className="font-mono text-emerald-500 tabular-nums">
                      ${selectedLog.cost_usd.toFixed(6)}
                    </span>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Monaco Editor */}
          <div className="flex-1 overflow-hidden">
            <Editor
              height="100%"
              defaultLanguage="json"
              value={formattedContent}
              theme="vs-dark"
              options={{
                readOnly: true,
                minimap: { enabled: false },
                fontSize: 12,
                fontFamily: "JetBrains Mono, Geist Mono, monospace",
                lineNumbers: "on",
                scrollBeyondLastLine: false,
                automaticLayout: true,
                wordWrap: "on",
                folding: true,
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
              <CloudArrowUp className="w-6 h-6 text-muted-foreground/50" weight="duotone" />
            </div>
            <p className="text-sm text-foreground font-medium mb-1">Select a request</p>
            <p className="text-xs text-muted-foreground">
              Click any request in the stream to view its full payload, metadata, and cost info.
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
