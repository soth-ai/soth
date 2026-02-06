"use client";

import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { useRouter } from "next/navigation";
import {
  MagnifyingGlass,
  House,
  Shield,
  CurrencyDollar,
  Eye,
  ArrowRight,
  Command,
  Robot,
  Cpu,
  CloudArrowUp,
  Lightning,
  Trash,
  Play,
  Pause,
  BookmarkSimple,
  ShieldWarning,
  Timer,
  XCircle,
  Funnel,
  Gear,
} from "@phosphor-icons/react";
import { useObservabilityStore, usePresets, type FilterPreset } from "@/store/observability";
import { cn } from "@/lib/utils";

type CommandType = "navigation" | "action" | "search" | "agent" | "event" | "preset";

interface CommandItem {
  id: string;
  type: CommandType;
  icon: React.ElementType;
  label: string;
  description?: string;
  shortcut?: string;
  color?: string;
  onSelect: () => void;
}

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
}

// Helper to get color class for preset
function getPresetColorClass(color: FilterPreset["color"]): string {
  const colorMap: Record<NonNullable<FilterPreset["color"]>, string> = {
    red: "text-red-500",
    orange: "text-orange-500",
    amber: "text-amber-500",
    cyan: "text-cyan-500",
    purple: "text-purple-500",
    emerald: "text-emerald-500",
    blue: "text-blue-500",
    gray: "text-muted-foreground",
  };
  return color ? colorMap[color] : "text-muted-foreground";
}

export function CommandPalette({ isOpen, onClose }: CommandPaletteProps) {
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // Store state
  const logs = useObservabilityStore((state) => state.logs);
  const isLive = useObservabilityStore((state) => state.isLive);
  const setIsLive = useObservabilityStore((state) => state.setIsLive);
  const clearLogs = useObservabilityStore((state) => state.clearLogs);
  const setFilters = useObservabilityStore((state) => state.setFilters);
  const applyPreset = useObservabilityStore((state) => state.applyPreset);
  const presets = usePresets();

  // Icon map for preset icons
  const presetIconMap: Record<string, React.ElementType> = {
    ShieldWarning,
    Eye,
    Timer,
    XCircle,
    Cpu,
    CloudArrowUp,
    Robot,
    Funnel,
    BookmarkSimple,
  };

  // Get unique agents from logs
  const agents = useMemo(() => {
    const agentMap = new Map<string, { name: string; count: number; lastSeen: string }>();
    logs.forEach((log) => {
      const name = log.agent?.name || "Unknown";
      const existing = agentMap.get(name);
      if (existing) {
        existing.count++;
        if (log.timestamp > existing.lastSeen) {
          existing.lastSeen = log.timestamp;
        }
      } else {
        agentMap.set(name, { name, count: 1, lastSeen: log.timestamp });
      }
    });
    return Array.from(agentMap.values()).sort((a, b) => b.count - a.count);
  }, [logs]);

  // Navigation commands
  const navigationCommands: CommandItem[] = [
    {
      id: "nav-overview",
      type: "navigation",
      icon: House,
      label: "Go to Overview",
      description: "Dashboard home with metrics",
      shortcut: "G O",
      onSelect: () => {
        router.push("/");
        onClose();
      },
    },
    {
      id: "nav-observability",
      type: "navigation",
      icon: Eye,
      label: "Go to Observability",
      description: "Traffic inspection & events",
      shortcut: "G T",
      onSelect: () => {
        router.push("/observability");
        onClose();
      },
    },
    {
      id: "nav-policies",
      type: "navigation",
      icon: Shield,
      label: "Go to Policies",
      description: "Policy evaluations & rules",
      shortcut: "G P",
      onSelect: () => {
        router.push("/policies");
        onClose();
      },
    },
    {
      id: "nav-budget",
      type: "navigation",
      icon: CurrencyDollar,
      label: "Go to Budget",
      description: "Cost tracking & limits",
      shortcut: "G B",
      onSelect: () => {
        router.push("/budget");
        onClose();
      },
    },
    {
      id: "nav-settings",
      type: "navigation",
      icon: Gear,
      label: "Go to Settings",
      description: "Dashboard configuration",
      shortcut: "G S",
      onSelect: () => {
        router.push("/settings");
        onClose();
      },
    },
  ];

  // Action commands
  const actionCommands: CommandItem[] = [
    {
      id: "action-toggle-live",
      type: "action",
      icon: isLive ? Pause : Play,
      label: isLive ? "Pause Live Updates" : "Resume Live Updates",
      description: "Toggle auto-scroll in observability",
      onSelect: () => {
        setIsLive(!isLive);
        onClose();
      },
    },
    {
      id: "action-clear-logs",
      type: "action",
      icon: Trash,
      label: "Clear All Events",
      description: "Remove all captured events",
      color: "text-destructive",
      onSelect: () => {
        clearLogs();
        onClose();
      },
    },
    {
      id: "action-filter-mcp",
      type: "action",
      icon: Cpu,
      label: "Show MCP Traffic Only",
      description: "Filter to MCP events",
      color: "text-cyan-500",
      onSelect: () => {
        setFilters({ source: "mcp" });
        router.push("/observability");
        onClose();
      },
    },
    {
      id: "action-filter-ai",
      type: "action",
      icon: CloudArrowUp,
      label: "Show AI Traffic Only",
      description: "Filter to AI proxy events",
      color: "text-purple-500",
      onSelect: () => {
        setFilters({ source: "ai_proxy" });
        router.push("/observability");
        onClose();
      },
    },
    {
      id: "action-filter-agent",
      type: "action",
      icon: Robot,
      label: "Show Agent Traffic Only",
      description: "Filter to agent app events",
      color: "text-amber-500",
      onSelect: () => {
        setFilters({ source: "agent_app" });
        router.push("/observability");
        onClose();
      },
    },
  ];

  // Agent commands (dynamic based on captured agents)
  const agentCommands: CommandItem[] = agents.slice(0, 5).map((agent) => ({
    id: `agent-${agent.name}`,
    type: "agent" as CommandType,
    icon: Robot,
    label: `Agent: ${agent.name}`,
    description: `${agent.count} events captured`,
    onSelect: () => {
      setFilters({ searchText: agent.name });
      router.push("/observability");
      onClose();
    },
  }));

  // Preset commands (filter presets)
  const presetCommands: CommandItem[] = presets.map((preset) => ({
    id: `preset-${preset.id}`,
    type: "preset" as CommandType,
    icon: presetIconMap[preset.icon || "BookmarkSimple"] || BookmarkSimple,
    label: preset.name,
    description: preset.description || "Apply filter preset",
    color: preset.color ? getPresetColorClass(preset.color) : undefined,
    onSelect: () => {
      applyPreset(preset.id);
      router.push("/observability");
      onClose();
    },
  }));

  // Recent events (show methods/tools)
  const recentMethods = useMemo(() => {
    const methodMap = new Map<string, number>();
    logs.slice(-100).forEach((log) => {
      const method = log.method || log.tool_name;
      if (method) {
        methodMap.set(method, (methodMap.get(method) || 0) + 1);
      }
    });
    return Array.from(methodMap.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
  }, [logs]);

  const eventCommands: CommandItem[] = recentMethods.map(([method, count]) => ({
    id: `event-${method}`,
    type: "event" as CommandType,
    icon: Lightning,
    label: `Method: ${method}`,
    description: `${count} recent calls`,
    onSelect: () => {
      setFilters({ method });
      router.push("/observability");
      onClose();
    },
  }));

  // Filter commands based on query
  const filteredCommands = useMemo(() => {
    const allCommands = [
      ...navigationCommands,
      ...actionCommands,
      ...presetCommands,
      ...(agents.length > 0 ? agentCommands : []),
      ...(recentMethods.length > 0 ? eventCommands : []),
    ];

    if (!query) return allCommands;

    const lowerQuery = query.toLowerCase();
    return allCommands.filter(
      (cmd) =>
        cmd.label.toLowerCase().includes(lowerQuery) ||
        cmd.description?.toLowerCase().includes(lowerQuery)
    );
  }, [query, navigationCommands, actionCommands, presetCommands, agentCommands, eventCommands, agents.length, recentMethods.length]);

  // Reset selection when query changes
  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  // Focus input when opened
  useEffect(() => {
    if (isOpen) {
      setQuery("");
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [isOpen]);

  // Scroll selected item into view
  useEffect(() => {
    if (listRef.current && filteredCommands.length > 0) {
      const selectedElement = listRef.current.children[selectedIndex] as HTMLElement;
      if (selectedElement) {
        selectedElement.scrollIntoView({ block: "nearest" });
      }
    }
  }, [selectedIndex, filteredCommands.length]);

  // Keyboard navigation
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      switch (e.key) {
        case "ArrowDown":
          e.preventDefault();
          setSelectedIndex((i) => Math.min(i + 1, filteredCommands.length - 1));
          break;
        case "ArrowUp":
          e.preventDefault();
          setSelectedIndex((i) => Math.max(i - 1, 0));
          break;
        case "Enter":
          e.preventDefault();
          if (filteredCommands[selectedIndex]) {
            filteredCommands[selectedIndex].onSelect();
          }
          break;
        case "Escape":
          e.preventDefault();
          onClose();
          break;
      }
    },
    [filteredCommands, selectedIndex, onClose]
  );

  if (!isOpen) return null;

  // Group commands by type for display
  const groupedCommands = filteredCommands.reduce(
    (acc, cmd) => {
      if (!acc[cmd.type]) acc[cmd.type] = [];
      acc[cmd.type].push(cmd);
      return acc;
    },
    {} as Record<CommandType, CommandItem[]>
  );

  const groupLabels: Record<CommandType, string> = {
    navigation: "Navigation",
    action: "Actions",
    preset: "Filter Presets",
    agent: "Agents",
    event: "Recent Methods",
    search: "Search Results",
  };

  let globalIndex = 0;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50"
        onClick={onClose}
      />

      {/* Palette */}
      <div className="fixed left-1/2 top-[20%] -translate-x-1/2 w-full max-w-xl z-50">
        <div className="bg-card border border-border rounded-xl shadow-2xl overflow-hidden">
          {/* Search Input */}
          <div className="flex items-center gap-3 px-4 py-3 border-b border-border">
            <MagnifyingGlass className="w-5 h-5 text-muted-foreground flex-shrink-0" />
            <input
              ref={inputRef}
              type="text"
              placeholder="Type a command or search..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              className="flex-1 bg-transparent text-foreground placeholder:text-muted-foreground outline-none text-sm"
            />
            <div className="flex items-center gap-1 text-xs text-muted-foreground">
              <kbd className="px-1.5 py-0.5 bg-muted border border-border rounded text-[10px] font-mono">
                esc
              </kbd>
              <span>to close</span>
            </div>
          </div>

          {/* Command List */}
          <div ref={listRef} className="max-h-[400px] overflow-y-auto py-2">
            {filteredCommands.length === 0 ? (
              <div className="px-4 py-8 text-center">
                <MagnifyingGlass className="w-8 h-8 mx-auto mb-2 text-muted-foreground/50" />
                <p className="text-sm text-muted-foreground">No commands found</p>
                <p className="text-xs text-muted-foreground/60 mt-1">
                  Try a different search term
                </p>
              </div>
            ) : (
              Object.entries(groupedCommands).map(([type, commands]) => (
                <div key={type}>
                  <div className="px-4 py-1.5">
                    <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">
                      {groupLabels[type as CommandType]}
                    </span>
                  </div>
                  {commands.map((cmd) => {
                    const index = globalIndex++;
                    const isSelected = index === selectedIndex;
                    return (
                      <button
                        key={cmd.id}
                        onClick={cmd.onSelect}
                        onMouseEnter={() => setSelectedIndex(index)}
                        className={cn(
                          "w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors",
                          isSelected ? "bg-accent" : "hover:bg-muted/50"
                        )}
                      >
                        <cmd.icon
                          className={cn(
                            "w-4 h-4 flex-shrink-0",
                            cmd.color || (isSelected ? "text-accent-foreground" : "text-muted-foreground")
                          )}
                          weight={isSelected ? "fill" : "duotone"}
                        />
                        <div className="flex-1 min-w-0">
                          <p
                            className={cn(
                              "text-sm font-medium truncate",
                              isSelected ? "text-accent-foreground" : "text-foreground"
                            )}
                          >
                            {cmd.label}
                          </p>
                          {cmd.description && (
                            <p
                              className={cn(
                                "text-xs truncate",
                                isSelected ? "text-accent-foreground/70" : "text-muted-foreground"
                              )}
                            >
                              {cmd.description}
                            </p>
                          )}
                        </div>
                        {cmd.shortcut && (
                          <div className="flex items-center gap-1 flex-shrink-0">
                            {cmd.shortcut.split(" ").map((key, i) => (
                              <kbd
                                key={i}
                                className={cn(
                                  "px-1.5 py-0.5 rounded text-[10px] font-mono border",
                                  isSelected
                                    ? "bg-accent-foreground/10 border-accent-foreground/20 text-accent-foreground"
                                    : "bg-muted border-border text-muted-foreground"
                                )}
                              >
                                {key}
                              </kbd>
                            ))}
                          </div>
                        )}
                        {isSelected && (
                          <ArrowRight
                            className="w-4 h-4 text-accent-foreground flex-shrink-0"
                            weight="bold"
                          />
                        )}
                      </button>
                    );
                  })}
                </div>
              ))
            )}
          </div>

          {/* Footer */}
          <div className="px-4 py-2 border-t border-border bg-muted/30 flex items-center justify-between text-xs text-muted-foreground">
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1">
                <kbd className="px-1 py-0.5 bg-muted border border-border rounded text-[10px] font-mono">↑</kbd>
                <kbd className="px-1 py-0.5 bg-muted border border-border rounded text-[10px] font-mono">↓</kbd>
                <span>navigate</span>
              </span>
              <span className="flex items-center gap-1">
                <kbd className="px-1 py-0.5 bg-muted border border-border rounded text-[10px] font-mono">↵</kbd>
                <span>select</span>
              </span>
            </div>
            <div className="flex items-center gap-1">
              <Command className="w-3 h-3" />
              <span>K to open</span>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
