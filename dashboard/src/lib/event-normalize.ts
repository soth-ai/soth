import type { WrapEvent } from "@/types";

export type NormalizedEventSource = "mcp" | "ai_proxy" | "agent_app";

function isLikelyMcpMethod(method: string): boolean {
  const normalized = method.trim().toLowerCase();
  if (!normalized) {
    return false;
  }
  return (
    normalized === "initialize" ||
    normalized.startsWith("tools/") ||
    normalized.startsWith("resources/") ||
    normalized.startsWith("prompts/") ||
    normalized.startsWith("notifications/") ||
    normalized.startsWith("sampling/") ||
    normalized.startsWith("roots/")
  );
}

export function normalizeEventSource(
  event: Pick<WrapEvent, "source" | "provider" | "method" | "tool_name" | "server_name">
): NormalizedEventSource {
  if (event.source === "mcp") {
    return "mcp";
  }
  if (event.source === "agent_app") {
    return "agent_app";
  }
  if (event.source === "ai_proxy") {
    if ((event.provider || "").toLowerCase() === "mcp") {
      return "mcp";
    }
    if (isLikelyMcpMethod(event.method || "")) {
      return "mcp";
    }
    return "ai_proxy";
  }

  if (isLikelyMcpMethod(event.method || "") || !!event.tool_name) {
    return "mcp";
  }

  if ((event.server_name || "").toLowerCase().includes("mcp")) {
    return "mcp";
  }

  return "ai_proxy";
}
