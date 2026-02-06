"use client";

import { useState, useEffect } from "react";
import {
  MagnifyingGlass,
  Bell,
  CaretDown,
  Clock,
  Command,
} from "@phosphor-icons/react";
import { useHealth } from "@/hooks/useDashboardData";
import { useCommandPalette } from "@/store/command-palette";
import { cn } from "@/lib/utils";

interface TimeRange {
  label: string;
  value: string;
  duration: string;
}

const timeRanges: TimeRange[] = [
  { label: "Last 15 minutes", value: "15m", duration: "15m" },
  { label: "Last 1 hour", value: "1h", duration: "1h" },
  { label: "Last 6 hours", value: "6h", duration: "6h" },
  { label: "Last 24 hours", value: "24h", duration: "24h" },
  { label: "Last 7 days", value: "7d", duration: "7d" },
];

export function TopBar() {
  const [selectedRange, setSelectedRange] = useState<TimeRange>(timeRanges[3]); // 24h default
  const [showRangeDropdown, setShowRangeDropdown] = useState(false);
  const [alertCount] = useState(0); // Will be connected to API
  const { data: health } = useHealth();
  const { open: openCommandPalette } = useCommandPalette();

  const isConnected = health?.status === "ok";

  // Close dropdown on outside click
  useEffect(() => {
    const handleClick = () => setShowRangeDropdown(false);
    if (showRangeDropdown) {
      document.addEventListener("click", handleClick);
      return () => document.removeEventListener("click", handleClick);
    }
  }, [showRangeDropdown]);

  return (
    <header className="h-14 border-b border-border bg-card/80 backdrop-blur-sm flex items-center justify-between px-4 sticky top-0 z-30">
      {/* Left: Environment Badge */}
      <div className="flex items-center gap-3">
        <EnvironmentBadge env="production" isConnected={isConnected} />
      </div>

      {/* Center: Time Range Selector */}
      <div className="flex items-center gap-4">
        <div className="relative">
          <button
            onClick={(e) => {
              e.stopPropagation();
              setShowRangeDropdown(!showRangeDropdown);
            }}
            className="flex items-center gap-2 px-3 py-1.5 text-sm rounded-lg border border-border hover:border-border-hover hover:bg-muted/50 transition-colors"
          >
            <Clock className="h-4 w-4 text-muted-foreground" weight="duotone" />
            <span className="text-muted-foreground">{selectedRange.label}</span>
            <CaretDown className="h-3 w-3 text-muted-foreground" />
          </button>

          {showRangeDropdown && (
            <div className="absolute top-full mt-1 left-0 w-48 bg-card border border-border rounded-lg shadow-lg py-1 z-50">
              {timeRanges.map((range) => (
                <button
                  key={range.value}
                  onClick={() => {
                    setSelectedRange(range);
                    setShowRangeDropdown(false);
                  }}
                  className={cn(
                    "w-full text-left px-3 py-2 text-sm hover:bg-muted transition-colors",
                    selectedRange.value === range.value
                      ? "text-accent bg-accent/10"
                      : "text-foreground"
                  )}
                >
                  {range.label}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Right: Search + Alerts */}
      <div className="flex items-center gap-2">
        {/* Global Search */}
        <button
          onClick={openCommandPalette}
          className="flex items-center gap-2 px-3 py-1.5 text-sm rounded-lg border border-border hover:border-border-hover hover:bg-muted/50 transition-colors min-w-[200px]"
        >
          <MagnifyingGlass className="h-4 w-4 text-muted-foreground" />
          <span className="text-muted-foreground flex-1 text-left">Search...</span>
          <kbd className="flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] font-mono bg-muted border border-border rounded">
            <Command className="h-2.5 w-2.5" />K
          </kbd>
        </button>

        {/* Alerts Indicator */}
        <button
          className={cn(
            "relative p-2 rounded-lg border border-border hover:border-border-hover hover:bg-muted/50 transition-colors",
            alertCount > 0 && "border-warning/50"
          )}
        >
          <Bell
            className={cn(
              "h-5 w-5",
              alertCount > 0 ? "text-warning" : "text-muted-foreground"
            )}
            weight={alertCount > 0 ? "fill" : "regular"}
          />
          {alertCount > 0 && (
            <span className="absolute -top-1 -right-1 h-4 w-4 bg-warning text-warning-foreground text-[10px] font-bold rounded-full flex items-center justify-center">
              {alertCount > 9 ? "9+" : alertCount}
            </span>
          )}
        </button>
      </div>
    </header>
  );
}

function EnvironmentBadge({
  env,
  isConnected,
}: {
  env: "production" | "staging" | "development";
  isConnected: boolean;
}) {
  const envConfig = {
    production: { label: "Production", color: "bg-success/10 text-success border-success/30" },
    staging: { label: "Staging", color: "bg-warning/10 text-warning border-warning/30" },
    development: { label: "Development", color: "bg-accent/10 text-accent border-accent/30" },
  };

  const config = envConfig[env];

  return (
    <div className="flex items-center gap-2">
      <div
        className={cn(
          "flex items-center gap-2 px-2.5 py-1 rounded-md border text-xs font-medium",
          config.color
        )}
      >
        <span
          className={cn(
            "h-1.5 w-1.5 rounded-full",
            isConnected ? "bg-current" : "bg-destructive"
          )}
        />
        {config.label}
      </div>
    </div>
  );
}
