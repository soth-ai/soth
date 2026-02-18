"use client";

import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { useRouter } from "next/navigation";
import {
  MagnifyingGlass,
  House,
  BugBeetle,
  Gear,
  ArrowRight,
  Command,
  ArrowsClockwise,
} from "@phosphor-icons/react";
import { cn } from "@/lib/utils";

type CommandType = "navigation" | "action";

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

export function CommandPalette({ isOpen, onClose }: CommandPaletteProps) {
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const navigationCommands = useMemo<CommandItem[]>(
    () => [
      {
        id: "nav-overview",
        type: "navigation",
        icon: House,
        label: "Go to Overview",
        description: "Runtime status and high-level health",
        shortcut: "G O",
        onSelect: () => {
          router.push("/");
          onClose();
        },
      },
      {
        id: "nav-debug",
        type: "navigation",
        icon: BugBeetle,
        label: "Go to Debug",
        description: "MCP, agent, and AI inference diagnostics",
        shortcut: "G D",
        onSelect: () => {
          router.push("/debug");
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
    ],
    [router, onClose]
  );

  const actionCommands = useMemo<CommandItem[]>(
    () => [
      {
        id: "action-refresh",
        type: "action",
        icon: ArrowsClockwise,
        label: "Refresh current view",
        description: "Reload current page and refetch diagnostics",
        shortcut: "R",
        onSelect: () => {
          onClose();
          window.location.reload();
        },
      },
    ],
    [onClose]
  );

  const filteredCommands = useMemo(() => {
    const allCommands = [...navigationCommands, ...actionCommands];

    if (!query) return allCommands;

    const lowerQuery = query.toLowerCase();
    return allCommands.filter(
      (cmd) =>
        cmd.label.toLowerCase().includes(lowerQuery) ||
        cmd.description?.toLowerCase().includes(lowerQuery)
    );
  }, [query, navigationCommands, actionCommands]);

  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  useEffect(() => {
    if (isOpen) {
      setQuery("");
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [isOpen]);

  useEffect(() => {
    if (listRef.current && filteredCommands.length > 0) {
      const selectedElement = listRef.current.children[selectedIndex] as HTMLElement;
      if (selectedElement) {
        selectedElement.scrollIntoView({ block: "nearest" });
      }
    }
  }, [selectedIndex, filteredCommands.length]);

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
  };

  let globalIndex = 0;

  return (
    <>
      <div
        className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50"
        onClick={onClose}
      />

      <div className="fixed left-1/2 top-[20%] -translate-x-1/2 w-full max-w-xl z-50">
        <div className="bg-card border border-border rounded-xl shadow-2xl overflow-hidden">
          <div className="flex items-center gap-3 px-4 py-3 border-b border-border">
            <MagnifyingGlass className="w-5 h-5 text-muted-foreground flex-shrink-0" />
            <input
              ref={inputRef}
              type="text"
              placeholder="Type a command..."
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

          <div ref={listRef} className="max-h-[400px] overflow-y-auto py-2">
            {filteredCommands.length === 0 ? (
              <div className="px-4 py-8 text-center">
                <MagnifyingGlass className="w-8 h-8 mx-auto mb-2 text-muted-foreground/50" />
                <p className="text-sm text-muted-foreground">No commands found</p>
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
