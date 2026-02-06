import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { format } from "date-fns";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatTimestamp(timestamp: string): string {
  try {
    const date = new Date(timestamp);
    return format(date, "HH:mm:ss.SSS");
  } catch {
    return "-";
  }
}

export function formatLatency(ms: number): string {
  if (ms >= 1000) {
    return `${(ms / 1000).toFixed(2)}s`;
  }
  return `${ms.toFixed(0)}ms`;
}

export function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength - 3) + "...";
}

export function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

export function formatCurrency(amount: number): string {
  if (amount >= 1) return `$${amount.toFixed(2)}`;
  if (amount >= 0.01) return `$${amount.toFixed(4)}`;
  return `$${amount.toFixed(6)}`;
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${m}m ${s}s`;
  }
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

export function formatPercent(value: number): string {
  return `${value.toFixed(1)}%`;
}
