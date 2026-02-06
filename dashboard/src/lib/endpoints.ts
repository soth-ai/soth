const DEFAULT_API_BASE = "/api";

function trimTrailingSlash(value: string): string {
  return value.endsWith("/") ? value.slice(0, -1) : value;
}

function normalizeWsBase(value: string): string {
  const trimmed = trimTrailingSlash(value.trim());

  if (trimmed.startsWith("ws://") || trimmed.startsWith("wss://")) {
    return trimmed;
  }

  if (trimmed.startsWith("http://")) {
    return `ws://${trimmed.slice("http://".length)}`;
  }

  if (trimmed.startsWith("https://")) {
    return `wss://${trimmed.slice("https://".length)}`;
  }

  return trimmed;
}

export function getApiBaseUrl(): string {
  const configured = process.env.NEXT_PUBLIC_SOTH_API_BASE?.trim();
  if (!configured) {
    return DEFAULT_API_BASE;
  }

  return trimTrailingSlash(configured);
}

export function getWsBaseUrl(): string {
  const configured = process.env.NEXT_PUBLIC_SOTH_WS_BASE?.trim();
  if (configured) {
    return normalizeWsBase(configured);
  }

  if (typeof window !== "undefined") {
    // Local dev default: Next UI runs on :3002 and Rust backend on :3001.
    if (window.location.port === "3002") {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      return `${protocol}//${window.location.hostname}:3001`;
    }

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${protocol}//${window.location.host}`;
  }

  return "ws://localhost:3001";
}

export function buildApiUrl(path: string): string {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return `${getApiBaseUrl()}${normalizedPath}`;
}

export function buildWsUrl(path: string): string {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return `${getWsBaseUrl()}${normalizedPath}`;
}
