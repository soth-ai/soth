import { create } from 'zustand';
import { persist } from 'zustand/middleware';

// Dynamic import to avoid circular dependency
const getMaxLogRetention = () => {
  try {
    const stored = localStorage.getItem('soth-dashboard-settings');
    if (stored) {
      const parsed = JSON.parse(stored);
      return parsed.state?.maxLogRetention ?? 3000;
    }
  } catch {
    // Ignore
  }
  return 3000;
};

// Event source type
export type EventSource = 'mcp' | 'ai_proxy' | 'agent_app';

// Filter preset for saved filter combinations
export interface FilterPreset {
  id: string;
  name: string;
  description?: string;
  icon?: string; // Phosphor icon name
  color?: 'red' | 'orange' | 'amber' | 'cyan' | 'purple' | 'emerald' | 'blue' | 'gray';
  filters: Filters;
  createdAt: string;
  isBuiltIn?: boolean;
}

// Log entry as received from backend (based on WrapEvent)
export interface LogEntry {
  id: string;
  timestamp: string;
  session_id: string;
  server_name: string;
  direction: 'in' | 'out';
  // Event source (MCP or AI Proxy)
  source: EventSource;
  // AI provider (for proxy traffic)
  provider?: string;
  // AI model (for proxy traffic)
  model?: string;
  method?: string;
  tool_name?: string;
  content: string; // Full JSON content
  content_ref?: string;
  content_preview?: string;
  // Paired request/response content (for AI proxy)
  request_content?: string;
  request_content_ref?: string;
  request_preview?: string;
  response_content?: string;
  response_content_ref?: string;
  response_preview?: string;
  // HTTP status code (for AI proxy responses)
  status_code?: number;
  agent: {
    name: string;
    version?: string;
    detected_from: string;
  };
  policy_allowed?: boolean;
  policy_reason?: string;
  pii_detected: boolean;
  pii_types: string[];
  token_count?: number;
  input_tokens?: number;
  output_tokens?: number;
  cost_usd?: number;
  latency_ms?: number;
  // Computed fields
  message_type?: 'json-rpc' | 'raw' | 'stderr';
  search_index?: string;
  path_cache?: string;
  has_error_cache?: boolean;
}

// Parsed JSON-RPC message
export interface ParsedMessage {
  jsonrpc?: string;
  id?: number | string;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

// Session info
export interface Session {
  id: string;
  name: string;
  server_name?: string;
  started_at: string;
  message_count: number;
  last_activity: string;
  tags?: string[];
}

// Filter state
export interface Filters {
  searchText?: string;
  method?: string;
  path?: string;
  direction?: 'in' | 'out';
  minLatencyMs?: number;
  serverName?: string;
  tags?: string[];
  sessionId?: string;
  // Quick filters
  policyDenied?: boolean;
  piiDetected?: boolean;
  hasError?: boolean;
  // Source filter
  source?: EventSource;
}

interface ObservabilityState {
  // Connection
  isConnected: boolean;
  setConnected: (connected: boolean) => void;
  streamCursorSeq: number | null;
  setStreamCursorSeq: (seq: number | null) => void;
  advanceStreamCursor: (seq: number) => void;

  // Logs
  logs: LogEntry[];
  logEntities: Record<string, LogEntry>;
  orderedLogIds: string[];
  logIndexById: Record<string, number>;
  logIds: Set<string>;
  addLog: (log: LogEntry) => void;
  addLogsBatch: (logs: LogEntry[]) => void;
  hydrateLogPayload: (
    id: string,
    part: "request" | "response" | "content",
    content: string
  ) => void;
  clearLogs: () => void;

  // Selection
  selectedLogId: string | null;
  selectedLogPart: 'request' | 'response' | null;
  selectLog: (id: string | null, part?: 'request' | 'response' | null) => void;
  getSelectedLog: () => LogEntry | null;

  // Sessions
  sessions: Session[];
  currentSessionId: string | null;
  addSession: (session: Session) => void;
  setCurrentSession: (id: string | null) => void;

  // Filters
  filters: Filters;
  setFilters: (filters: Partial<Filters>) => void;
  clearFilters: () => void;
  getFilteredLogs: () => LogEntry[];

  // Auto-scroll
  isLive: boolean;
  setIsLive: (live: boolean) => void;

  // View Settings
  isCompactMode: boolean;
  toggleCompactMode: () => void;

  // Clustering
  clusteringEnabled: boolean;
  setClusteringEnabled: (enabled: boolean) => void;
  expandedClusters: Set<string>;
  toggleCluster: (clusterId: string) => void;
  expandAllClusters: () => void;
  collapseAllClusters: () => void;

  // Filter Presets
  savePreset: (name: string, description?: string, icon?: string, color?: FilterPreset['color']) => void;
  deletePreset: (id: string) => void;
  applyPreset: (id: string) => void;
  updatePreset: (id: string, updates: Partial<Omit<FilterPreset, 'id' | 'createdAt' | 'isBuiltIn'>>) => void;
}

// Built-in filter presets
const BUILT_IN_PRESETS: FilterPreset[] = [
  {
    id: 'builtin-security-issues',
    name: 'Security Issues',
    description: 'Policy denials and PII detections',
    icon: 'ShieldWarning',
    color: 'red',
    filters: { policyDenied: true },
    createdAt: '2024-01-01T00:00:00Z',
    isBuiltIn: true,
  },
  {
    id: 'builtin-pii-alerts',
    name: 'PII Alerts',
    description: 'Messages containing personal information',
    icon: 'Eye',
    color: 'orange',
    filters: { piiDetected: true },
    createdAt: '2024-01-01T00:00:00Z',
    isBuiltIn: true,
  },
  {
    id: 'builtin-slow-requests',
    name: 'Slow Requests',
    description: 'Requests taking over 1 second',
    icon: 'Timer',
    color: 'amber',
    filters: { minLatencyMs: 1000 },
    createdAt: '2024-01-01T00:00:00Z',
    isBuiltIn: true,
  },
  {
    id: 'builtin-errors-only',
    name: 'Errors Only',
    description: 'Failed requests and error responses',
    icon: 'XCircle',
    color: 'red',
    filters: { hasError: true },
    createdAt: '2024-01-01T00:00:00Z',
    isBuiltIn: true,
  },
  {
    id: 'builtin-mcp-traffic',
    name: 'MCP Traffic',
    description: 'Only MCP JSON-RPC messages',
    icon: 'Cpu',
    color: 'cyan',
    filters: { source: 'mcp' },
    createdAt: '2024-01-01T00:00:00Z',
    isBuiltIn: true,
  },
  {
    id: 'builtin-ai-calls',
    name: 'AI API Calls',
    description: 'Direct AI provider API requests',
    icon: 'CloudArrowUp',
    color: 'purple',
    filters: { source: 'ai_proxy' },
    createdAt: '2024-01-01T00:00:00Z',
    isBuiltIn: true,
  },
];

const PARSED_MESSAGE_CACHE_LIMIT = 10_000;
const SMART_DECODE_CACHE_LIMIT = 8_000;
const EDITOR_DECODE_CACHE_LIMIT = 4_000;
const LOG_SUMMARY_CACHE_LIMIT = 10_000;

const parsedMessageCache = new Map<
  string,
  { signature: string; parsed: ParsedMessage | null }
>();
const smartDecodeCache = new Map<string, string>();
const editorDecodeCache = new Map<
  string,
  {
    content: string;
    language: 'json' | 'plaintext';
  }
>();
const logSummaryCache = new Map<string, { signature: string; summary: string }>();

function setBoundedCache<T>(cache: Map<string, T>, key: string, value: T, limit: number): void {
  if (cache.size >= limit) {
    const oldestKey = cache.keys().next().value;
    if (oldestKey !== undefined) {
      cache.delete(oldestKey);
    }
  }
  cache.set(key, value);
}

function parseSignature(log: LogEntry): string {
  const content = log.content || '';
  const prefix = content.slice(0, 256);
  const suffix = content.slice(-128);
  return `${log.message_type ?? ''}|${content.length}|${prefix}|${suffix}`;
}

function computeHasErrorCache(log: LogEntry): boolean {
  if (log.status_code !== undefined && log.status_code >= 400) {
    return true;
  }
  if (log.policy_allowed === false) {
    return true;
  }
  if (log.message_type === 'raw' || log.message_type === 'stderr') {
    return false;
  }

  if (!log.content) {
    return false;
  }

  try {
    const parsed = JSON.parse(log.content) as { error?: unknown };
    return parsed.error !== undefined;
  } catch {
    return false;
  }
}

function computeSearchIndex(log: LogEntry): string {
  const searchableContent = (log.content_preview || log.content || '').slice(0, 2048);
  return [
    searchableContent,
    log.method || '',
    log.tool_name || '',
    log.server_name || '',
    log.agent.name || '',
  ]
    .join(' ')
    .toLowerCase();
}

function withDerivedLogFields(log: LogEntry): LogEntry {
  const searchIndex = computeSearchIndex(log);
  const pathCache = getLogPath(log);
  const hasErrorCache = computeHasErrorCache(log);

  if (
    log.search_index === searchIndex &&
    log.path_cache === pathCache &&
    log.has_error_cache === hasErrorCache
  ) {
    return log;
  }

  return {
    ...log,
    search_index: searchIndex,
    path_cache: pathCache,
    has_error_cache: hasErrorCache,
  };
}

export function filterLogs(logs: LogEntry[], filters: Filters): LogEntry[] {
  return logs.filter((log) => {
    if (filters.source && log.source !== filters.source) return false;
    if (filters.sessionId && log.session_id !== filters.sessionId) return false;

    if (filters.searchText) {
      const search = filters.searchText.toLowerCase();
      const indexed = log.search_index ?? computeSearchIndex(log);
      if (!indexed.includes(search)) {
        return false;
      }
    }

    if (filters.method && log.method !== filters.method) return false;
    if (filters.direction && log.direction !== filters.direction) return false;
    if (filters.serverName && !matchesServerFilter(log.server_name, filters.serverName)) return false;
    if (filters.path && (log.path_cache ?? getLogPath(log)) !== filters.path) return false;

    if (filters.minLatencyMs && log.latency_ms !== undefined && log.latency_ms < filters.minLatencyMs) {
      return false;
    }

    if (filters.policyDenied && log.policy_allowed !== false) return false;
    if (filters.piiDetected && !log.pii_detected) return false;
    if (filters.hasError && !(log.has_error_cache ?? computeHasErrorCache(log))) return false;

    return true;
  });
}

// Parse JSON-RPC message from content
export function parseLogMessage(log: LogEntry): ParsedMessage | null {
  if (log.message_type === 'raw' || log.message_type === 'stderr') {
    return null;
  }
  const signature = parseSignature(log);
  const cached = parsedMessageCache.get(log.id);
  if (cached && cached.signature === signature) {
    return cached.parsed;
  }

  try {
    const parsed = JSON.parse(log.content) as ParsedMessage;
    setBoundedCache(
      parsedMessageCache,
      log.id,
      { signature, parsed },
      PARSED_MESSAGE_CACHE_LIMIT
    );
    return parsed;
  } catch {
    setBoundedCache(
      parsedMessageCache,
      log.id,
      { signature, parsed: null },
      PARSED_MESSAGE_CACHE_LIMIT
    );
    return null;
  }
}

// Find correlated request for a response
export function findCorrelatedRequest(
  response: LogEntry,
  logs: LogEntry[]
): LogEntry | null {
  const parsed = parseLogMessage(response);
  if (!parsed || parsed.id === undefined) return null;

  // Response should be outgoing, request should be incoming
  if (response.direction !== 'out') return null;

  const responseIndex = logs.findIndex((l) => l.id === response.id);
  if (responseIndex === -1) return null;

  // Search backwards for matching request
  for (let i = responseIndex - 1; i >= 0; i--) {
    const log = logs[i];
    if (log.direction !== 'in') continue;

    const reqParsed = parseLogMessage(log);
    if (reqParsed && reqParsed.id === parsed.id && reqParsed.method) {
      return log;
    }
  }

  return null;
}

// Calculate latency between request and response
export function calculateLatency(
  request: LogEntry,
  response: LogEntry
): number | null {
  try {
    const reqTime = new Date(request.timestamp).getTime();
    const respTime = new Date(response.timestamp).getTime();
    return respTime - reqTime; // in milliseconds
  } catch {
    return null;
  }
}

export function normalizeServerName(value?: string): string {
  return (value || '').trim().toLowerCase();
}

export function matchesServerFilter(serverName: string | undefined, filterValue: string): boolean {
  const server = normalizeServerName(serverName);
  const selected = normalizeServerName(filterValue);
  if (!server || !selected) {
    return false;
  }
  return server === selected || server.endsWith(`.${selected}`);
}

export function getLogHost(log: LogEntry): string | undefined {
  const host = normalizeServerName(log.server_name);
  return host || undefined;
}

export function getLogPath(log: LogEntry): string | undefined {
  const method = (log.method || '').trim();
  if (!method) {
    return undefined;
  }

  const tokenMatch = method.match(/^(?:[A-Z]+|WebSocket)\s+([^\s|]+)/i);
  const token = tokenMatch?.[1] || method;

  if (token.startsWith('/')) {
    return token.split('?')[0] || undefined;
  }

  if (token.startsWith('http://') || token.startsWith('https://')) {
    try {
      const parsed = new URL(token);
      return parsed.pathname || undefined;
    } catch {
      return undefined;
    }
  }

  return undefined;
}

export function getLogTokenCount(log: Pick<LogEntry, "token_count" | "input_tokens" | "output_tokens">): number {
  if (typeof log.token_count === "number" && Number.isFinite(log.token_count) && log.token_count > 0) {
    return log.token_count;
  }

  const inputTokens =
    typeof log.input_tokens === "number" && Number.isFinite(log.input_tokens)
      ? Math.max(0, log.input_tokens)
      : 0;
  const outputTokens =
    typeof log.output_tokens === "number" && Number.isFinite(log.output_tokens)
      ? Math.max(0, log.output_tokens)
      : 0;

  return inputTokens + outputTokens;
}

function normalizeInline(text: string): string {
  // Remove non-display control chars while keeping normal spacing.
  return text
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function isLikelyBinaryPayload(text: string): boolean {
  if (!text) return false;

  const sample = text.slice(0, 4096);
  let replacementCount = 0;
  let controlCount = 0;

  for (const ch of sample) {
    if (ch === '�') {
      replacementCount += 1;
      continue;
    }

    const code = ch.charCodeAt(0);
    const isControl = (code >= 0x00 && code <= 0x08) || (code >= 0x0e && code <= 0x1f);
    if (isControl) {
      controlCount += 1;
      continue;
    }

  }

  const total = Math.max(1, sample.length);
  const badRatio = (replacementCount + controlCount) / total;

  // Tuned from local DB inspection: compressed payloads contain many replacement chars/control bytes.
  return replacementCount >= 3 || controlCount >= 8 || badRatio >= 0.08;
}

function summarizeBinaryPreview(raw: string): string {
  const normalized = normalizeInline(raw);
  const arrowMatch = normalized.match(/^(.{0,180}?\|\s*←)\s*(.+)$/);
  if (arrowMatch) {
    return `${arrowMatch[1]} [compressed/binary payload]`;
  }
  if (normalized.startsWith('→') && normalized.includes('|')) {
    return `${normalized.slice(0, 160)} [compressed/binary payload]`;
  }
  return '[compressed/binary payload]';
}

function parsePossiblyEncodedJson(raw: string): unknown {
  let current: unknown = raw.trim();
  for (let depth = 0; depth < 3; depth++) {
    if (typeof current !== 'string') {
      break;
    }
    const value = current.trim();
    const looksJson =
      (value.startsWith('{') && value.endsWith('}')) ||
      (value.startsWith('[') && value.endsWith(']')) ||
      (value.startsWith('"') && value.endsWith('"'));
    if (!looksJson) {
      break;
    }
    try {
      current = JSON.parse(value);
    } catch {
      break;
    }
  }
  return current;
}

function parseJsonValueLoose(raw: string): { ok: boolean; value: unknown } {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    return { ok: false, value: raw };
  }

  try {
    let current: unknown = JSON.parse(trimmed);
    for (let depth = 0; depth < 2; depth++) {
      if (typeof current !== 'string') {
        break;
      }
      const nested = current.trim();
      if (nested.length === 0) {
        break;
      }
      try {
        current = JSON.parse(nested);
      } catch {
        break;
      }
    }
    return { ok: true, value: current };
  } catch {
    return { ok: false, value: raw };
  }
}

function formatJsonLikeValue(value: unknown): string {
  if (typeof value === 'string') {
    return value;
  }
  return JSON.stringify(value, null, 2);
}

function looksLikeSsePayload(raw: string): boolean {
  if (!raw.includes('\n')) {
    return false;
  }
  const lines = raw.split(/\r?\n/);
  let taggedLines = 0;

  for (const line of lines.slice(0, 120)) {
    const trimmed = line.trimStart();
    if (
      trimmed.startsWith('data:') ||
      trimmed.startsWith('event:') ||
      trimmed.startsWith('id:') ||
      trimmed.startsWith('retry:')
    ) {
      taggedLines += 1;
    }
  }

  return taggedLines >= 2;
}

function tryFormatSseForEditor(raw: string): { content: string; language: 'plaintext' } | null {
  if (!looksLikeSsePayload(raw)) {
    return null;
  }

  const lines = raw.split(/\r?\n/);
  const out: string[] = [];

  for (const line of lines) {
    const trimmed = line.trimStart();

    if (trimmed.startsWith('data:')) {
      const payload = trimmed.slice(5).trimStart();
      if (payload.length === 0) {
        out.push('data:');
        continue;
      }
      if (payload === '[DONE]') {
        out.push('data: [DONE]');
        continue;
      }

      const parsed = parseJsonValueLoose(payload);
      if (!parsed.ok) {
        out.push(`data: ${payload}`);
        continue;
      }

      const formatted = formatJsonLikeValue(parsed.value);
      if (formatted.includes('\n')) {
        out.push('data:');
        for (const formattedLine of formatted.split('\n')) {
          out.push(`  ${formattedLine}`);
        }
      } else {
        out.push(`data: ${formatted}`);
      }
      continue;
    }

    if (
      trimmed.startsWith('event:') ||
      trimmed.startsWith('id:') ||
      trimmed.startsWith('retry:')
    ) {
      out.push(trimmed);
      continue;
    }

    if (trimmed.length === 0) {
      out.push('');
      continue;
    }

    out.push(line);
  }

  return {
    content: out.join('\n'),
    language: 'plaintext',
  };
}

function tryFormatNdjsonForEditor(raw: string): { content: string; language: 'json' } | null {
  const lines = raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  if (lines.length < 2) {
    return null;
  }

  const parsedValues: unknown[] = [];
  for (const line of lines) {
    const parsed = parseJsonValueLoose(line);
    if (!parsed.ok || typeof parsed.value === 'string') {
      return null;
    }
    parsedValues.push(parsed.value);
  }

  return {
    content: JSON.stringify(parsedValues, null, 2),
    language: 'json',
  };
}

function extractReadableText(value: unknown, depth = 0): string | null {
  if (value === null || value === undefined || depth > 4) {
    return null;
  }

  if (typeof value === 'string') {
    const normalized = normalizeInline(value);
    return normalized.length > 0 ? normalized : null;
  }

  if (Array.isArray(value)) {
    const parts: string[] = [];
    for (const item of value.slice(0, 8)) {
      const text = extractReadableText(item, depth + 1);
      if (text) {
        parts.push(text);
      }
    }
    return parts.length > 0 ? parts.join(' | ') : null;
  }

  if (typeof value !== 'object') {
    return null;
  }

  const obj = value as Record<string, unknown>;

  if (typeof obj.event === 'string') {
    const eventText = normalizeInline(obj.event);
    if (eventText.length > 0) {
      return eventText;
    }
  }

  if (obj.error !== undefined) {
    const errorText = extractReadableText(obj.error, depth + 1);
    if (errorText) return errorText;
  }

  if (Array.isArray(obj.content)) {
    const contentTexts: string[] = [];
    for (const entry of obj.content.slice(0, 8)) {
      if (typeof entry === 'string') {
        const normalized = normalizeInline(entry);
        if (normalized) contentTexts.push(normalized);
        continue;
      }
      if (entry && typeof entry === 'object') {
        const item = entry as Record<string, unknown>;
        if (typeof item.text === 'string') {
          const normalized = normalizeInline(item.text);
          if (normalized) contentTexts.push(normalized);
          continue;
        }
        if (typeof item.content === 'string') {
          const normalized = normalizeInline(item.content);
          if (normalized) contentTexts.push(normalized);
          continue;
        }
      }
    }
    if (contentTexts.length > 0) {
      return contentTexts.join(' | ');
    }
  }

  if (Array.isArray(obj.choices) && obj.choices.length > 0) {
    const firstChoice = obj.choices[0];
    const choiceText = extractReadableText(firstChoice, depth + 1);
    if (choiceText) return choiceText;
  }

  const directKeys = [
    'text',
    'message',
    'content',
    'detail',
    'description',
    'reason',
    'summary',
    'type',
    'method',
    'name',
    'event',
  ];
  for (const key of directKeys) {
    const candidate = obj[key];
    if (typeof candidate === 'string') {
      const normalized = normalizeInline(candidate);
      if (normalized.length > 0) {
        return normalized;
      }
    }
  }

  const nestedKeys = [
    'params',
    'result',
    'data',
    'payload',
    'arguments',
    'delta',
    'command',
    'reply',
    'response',
  ];
  for (const key of nestedKeys) {
    const nested = obj[key];
    const nestedText = extractReadableText(nested, depth + 1);
    if (nestedText) {
      return nestedText;
    }
  }

  // WebSocket style objects: synthesize useful summary from structured fields.
  if (obj.command && typeof obj.command === 'object') {
    const commandObj = obj.command as Record<string, unknown>;
    const commandType =
      typeof commandObj.type === 'string' ? commandObj.type : 'command';
    const topic =
      typeof commandObj.topic_id === 'string' ? ` ${commandObj.topic_id}` : '';
    const idPart = obj.id !== undefined ? `#${String(obj.id)} ` : '';
    return `${idPart}${commandType}${topic}`.trim();
  }
  if (obj.reply && typeof obj.reply === 'object') {
    const replyObj = obj.reply as Record<string, unknown>;
    const replyType =
      typeof replyObj.type === 'string' ? replyObj.type : 'reply';
    const topic =
      typeof replyObj.topic_id === 'string' ? ` ${replyObj.topic_id}` : '';
    const idPart = obj.id !== undefined ? `#${String(obj.id)} ` : '';
    return `${idPart}${replyType}${topic}`.trim();
  }

  return null;
}

// Smart display decode for row previews (handles escaped/double-encoded payloads).
export function decodeSmartDisplayText(raw?: string): string {
  if (!raw) {
    return '';
  }

  const cached = smartDecodeCache.get(raw);
  if (cached !== undefined) {
    return cached;
  }

  if (isLikelyBinaryPayload(raw)) {
    const value = summarizeBinaryPreview(raw);
    setBoundedCache(smartDecodeCache, raw, value, SMART_DECODE_CACHE_LIMIT);
    return value;
  }

  const parsed = parsePossiblyEncodedJson(raw);
  if (typeof parsed === 'string') {
    const normalized = normalizeInline(parsed);
    if (normalized.length === 0) {
      const value = normalizeInline(raw);
      setBoundedCache(smartDecodeCache, raw, value, SMART_DECODE_CACHE_LIMIT);
      return value;
    }
    if (isLikelyBinaryPayload(normalized)) {
      const value = summarizeBinaryPreview(raw);
      setBoundedCache(smartDecodeCache, raw, value, SMART_DECODE_CACHE_LIMIT);
      return value;
    }
    setBoundedCache(smartDecodeCache, raw, normalized, SMART_DECODE_CACHE_LIMIT);
    return normalized;
  }

  const extracted = extractReadableText(parsed);
  if (extracted) {
    setBoundedCache(smartDecodeCache, raw, extracted, SMART_DECODE_CACHE_LIMIT);
    return extracted;
  }

  if (typeof parsed === 'object' && parsed !== null) {
    try {
      const normalized = normalizeInline(JSON.stringify(parsed));
      if (isLikelyBinaryPayload(normalized)) {
        const value = summarizeBinaryPreview(raw);
        setBoundedCache(smartDecodeCache, raw, value, SMART_DECODE_CACHE_LIMIT);
        return value;
      }
      setBoundedCache(smartDecodeCache, raw, normalized, SMART_DECODE_CACHE_LIMIT);
      return normalized;
    } catch {
      const value = normalizeInline(raw);
      setBoundedCache(smartDecodeCache, raw, value, SMART_DECODE_CACHE_LIMIT);
      return value;
    }
  }

  const value = normalizeInline(String(parsed));
  setBoundedCache(smartDecodeCache, raw, value, SMART_DECODE_CACHE_LIMIT);
  return value;
}

// Decode payload for the inspector editor (preserves structure for JSON syntax highlight).
export function decodeEditorContent(raw?: string): {
  content: string;
  language: 'json' | 'plaintext';
} {
  if (!raw) {
    return { content: '', language: 'plaintext' };
  }

  const cached = editorDecodeCache.get(raw);
  if (cached) {
    return cached;
  }

  if (isLikelyBinaryPayload(raw)) {
    const value = { content: summarizeBinaryPreview(raw), language: 'plaintext' as const };
    setBoundedCache(editorDecodeCache, raw, value, EDITOR_DECODE_CACHE_LIMIT);
    return value;
  }

  const sseFormatted = tryFormatSseForEditor(raw);
  if (sseFormatted) {
    return sseFormatted;
  }

  const ndjsonFormatted = tryFormatNdjsonForEditor(raw);
  if (ndjsonFormatted) {
    return ndjsonFormatted;
  }

  const parsed = parsePossiblyEncodedJson(raw);

  if (parsed !== null && typeof parsed === 'object') {
    try {
      const value = {
        content: JSON.stringify(parsed, null, 2),
        language: 'json' as const,
      };
      setBoundedCache(editorDecodeCache, raw, value, EDITOR_DECODE_CACHE_LIMIT);
      return value;
    } catch {
      const value = { content: raw, language: 'plaintext' as const };
      setBoundedCache(editorDecodeCache, raw, value, EDITOR_DECODE_CACHE_LIMIT);
      return value;
    }
  }

  if (parsed === null || typeof parsed === 'number' || typeof parsed === 'boolean') {
    const value = {
      content: JSON.stringify(parsed, null, 2),
      language: 'json' as const,
    };
    setBoundedCache(editorDecodeCache, raw, value, EDITOR_DECODE_CACHE_LIMIT);
    return value;
  }

  const text = typeof parsed === 'string' ? parsed : String(parsed);
  const trimmed = text.trim();
  const looksLikeJsonEnvelope =
    (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
    (trimmed.startsWith('[') && trimmed.endsWith(']'));

  if (looksLikeJsonEnvelope) {
    try {
      const reparsed = JSON.parse(trimmed);
      const value = {
        content: JSON.stringify(reparsed, null, 2),
        language: 'json' as const,
      };
      setBoundedCache(editorDecodeCache, raw, value, EDITOR_DECODE_CACHE_LIMIT);
      return value;
    } catch {
      // Keep plaintext fallback below.
    }
  }

  if (isLikelyBinaryPayload(text)) {
    const value = { content: summarizeBinaryPreview(raw), language: 'plaintext' as const };
    setBoundedCache(editorDecodeCache, raw, value, EDITOR_DECODE_CACHE_LIMIT);
    return value;
  }

  const value = {
    content: text,
    language: 'plaintext' as const,
  };
  setBoundedCache(editorDecodeCache, raw, value, EDITOR_DECODE_CACHE_LIMIT);
  return value;
}

// Get summary of log content
export function getLogSummary(log: LogEntry): string {
  const signature = `${parseSignature(log)}|${log.content_preview ?? ''}`;
  const cached = logSummaryCache.get(log.id);
  if (cached && cached.signature === signature) {
    return cached.summary;
  }

  let summary = '';
  if (log.content_preview) {
    summary = decodeSmartDisplayText(log.content_preview);
    setBoundedCache(
      logSummaryCache,
      log.id,
      { signature, summary },
      LOG_SUMMARY_CACHE_LIMIT
    );
    return summary;
  }

  const parsed = parseLogMessage(log);
  if (!parsed) {
    summary = decodeSmartDisplayText(log.content);
    setBoundedCache(
      logSummaryCache,
      log.id,
      { signature, summary },
      LOG_SUMMARY_CACHE_LIMIT
    );
    return summary;
  }

  if (parsed.error) {
    summary = decodeSmartDisplayText(`Error ${parsed.error.code}: ${parsed.error.message}`);
    setBoundedCache(
      logSummaryCache,
      log.id,
      { signature, summary },
      LOG_SUMMARY_CACHE_LIMIT
    );
    return summary;
  }

  if (parsed.params) {
    summary = decodeSmartDisplayText(JSON.stringify(parsed.params));
    setBoundedCache(
      logSummaryCache,
      log.id,
      { signature, summary },
      LOG_SUMMARY_CACHE_LIMIT
    );
    return summary;
  }

  if (parsed.result) {
    summary = decodeSmartDisplayText(JSON.stringify(parsed.result));
    setBoundedCache(
      logSummaryCache,
      log.id,
      { signature, summary },
      LOG_SUMMARY_CACHE_LIMIT
    );
    return summary;
  }

  summary = decodeSmartDisplayText(JSON.stringify(parsed));
  setBoundedCache(
    logSummaryCache,
    log.id,
    { signature, summary },
    LOG_SUMMARY_CACHE_LIMIT
  );
  return summary;
}

// Separate persisted state for presets
interface PersistedPresetState {
  userPresets: FilterPreset[];
}

const usePresetStore = create<PersistedPresetState>()(
  persist(
    (): PersistedPresetState => ({
      userPresets: [] as FilterPreset[],
    }),
    {
      name: 'soth-filter-presets',
    }
  )
);

export const useObservabilityStore = create<ObservabilityState>((set, get) => ({
  // Connection
  isConnected: false,
  setConnected: (connected) => set({ isConnected: connected }),
  streamCursorSeq: null,
  setStreamCursorSeq: (seq) => set({ streamCursorSeq: seq }),
  advanceStreamCursor: (seq) =>
    set((state) => ({
      streamCursorSeq:
        state.streamCursorSeq === null
          ? seq
          : Math.max(state.streamCursorSeq, seq),
    })),

  // Logs
  logs: [],
  logEntities: {},
  orderedLogIds: [],
  logIndexById: {},
  logIds: new Set<string>(),
  addLog: (log) => get().addLogsBatch([log]),
  addLogsBatch: (incomingLogs) =>
    set((state) => {
      if (!incomingLogs.length) {
        return state;
      }

      let logs = [...state.logs];
      let orderedLogIds = [...state.orderedLogIds];
      let logIndexById = { ...state.logIndexById };
      const logEntities = { ...state.logEntities };
      const logIds = new Set(state.logIds);
      const sessionDelta = new Map<string, { count: number; lastActivity: string }>();
      for (const log of incomingLogs) {
        const normalizedLog = withDerivedLogFields(log);
        const existingIndex = logIndexById[normalizedLog.id];
        if (existingIndex !== undefined) {
          logs[existingIndex] = normalizedLog;
          logEntities[normalizedLog.id] = normalizedLog;
          continue;
        }

        logIndexById[normalizedLog.id] = logs.length;
        logs.push(normalizedLog);
        orderedLogIds.push(normalizedLog.id);
        logIds.add(normalizedLog.id);
        logEntities[normalizedLog.id] = normalizedLog;

        const existing = sessionDelta.get(normalizedLog.session_id);
        if (existing) {
          existing.count += 1;
          if (normalizedLog.timestamp > existing.lastActivity) {
            existing.lastActivity = normalizedLog.timestamp;
          }
        } else {
          sessionDelta.set(normalizedLog.session_id, {
            count: 1,
            lastActivity: normalizedLog.timestamp,
          });
        }
      }

      const maxLogs = getMaxLogRetention();
      const nextLogIds = logIds;

      const overflow = Math.max(0, logs.length - maxLogs);
      if (overflow > 0) {
        for (let i = 0; i < overflow; i++) {
          const removed = logs[i];
          if (removed) {
            nextLogIds.delete(removed.id);
            delete logEntities[removed.id];
          }
        }
        logs = logs.slice(overflow);
        orderedLogIds = orderedLogIds.slice(overflow);
        logIndexById = {};
        for (let i = 0; i < logs.length; i++) {
          logIndexById[logs[i].id] = i;
        }
      }

      const sessions = state.sessions.map((session) => {
        const delta = sessionDelta.get(session.id);
        if (!delta) {
          return session;
        }
        return {
          ...session,
          message_count: session.message_count + delta.count,
          last_activity:
            delta.lastActivity > session.last_activity ? delta.lastActivity : session.last_activity,
        };
      });

      return {
        logs,
        logEntities,
        orderedLogIds,
        logIndexById,
        logIds: nextLogIds,
        sessions,
      };
    }),
  hydrateLogPayload: (id, part, content) =>
    set((state) => {
      const index = state.logIndexById[id];
      if (index === undefined) {
        return state;
      }

      const existing = state.logs[index];
      if (!existing) {
        return state;
      }

      let nextLog: LogEntry;
      if (part === "request") {
        nextLog = withDerivedLogFields({ ...existing, request_content: content });
      } else if (part === "response") {
        nextLog = withDerivedLogFields({ ...existing, response_content: content });
      } else {
        nextLog = withDerivedLogFields({ ...existing, content });
      }

      const logs = [...state.logs];
      logs[index] = nextLog;

      return {
        logs,
        logEntities: {
          ...state.logEntities,
          [id]: nextLog,
        },
      };
    }),
  clearLogs: () => {
    parsedMessageCache.clear();
    logSummaryCache.clear();
    set({
      logs: [],
      logEntities: {},
      orderedLogIds: [],
      logIndexById: {},
      logIds: new Set<string>(),
      streamCursorSeq: null,
      selectedLogId: null,
      selectedLogPart: null,
    });
  },

  // Selection
  selectedLogId: null,
  selectedLogPart: null,
  selectLog: (id, part = null) =>
    set({
      selectedLogId: id,
      selectedLogPart: id === null ? null : part,
    }),
  getSelectedLog: () => {
    const { logEntities, selectedLogId } = get();
    if (!selectedLogId) {
      return null;
    }
    return logEntities[selectedLogId] || null;
  },

  // Sessions
  sessions: [],
  currentSessionId: null,
  addSession: (session) =>
    set((state) => ({
      sessions: [...state.sessions, session],
      currentSessionId: state.currentSessionId || session.id,
    })),
  setCurrentSession: (id) =>
    set({
      currentSessionId: id,
      filters: id ? { ...get().filters, sessionId: id } : get().filters,
    }),

  // Auto-scroll
  isLive: true,
  setIsLive: (live) => set({ isLive: live }),

  // View Settings
  isCompactMode: false,
  toggleCompactMode: () => set((state) => ({ isCompactMode: !state.isCompactMode })),

  // Filters
  filters: {},
  setFilters: (newFilters) =>
    set((state) => ({
      filters: { ...state.filters, ...newFilters },
    })),
  clearFilters: () => set({ filters: {} }),
  getFilteredLogs: () => {
    const { logs, filters } = get();
    return filterLogs(logs, filters);
  },

  // Clustering
  clusteringEnabled: true,
  setClusteringEnabled: (enabled) => set({ clusteringEnabled: enabled }),
  expandedClusters: new Set<string>(),
  toggleCluster: (clusterId) =>
    set((state) => {
      const newExpanded = new Set(state.expandedClusters);
      if (newExpanded.has(clusterId)) {
        newExpanded.delete(clusterId);
      } else {
        newExpanded.add(clusterId);
      }
      return { expandedClusters: newExpanded };
    }),
  expandAllClusters: () =>
    set(() => {
      // This will be populated when clusters are rendered
      return { expandedClusters: new Set<string>() };
    }),
  collapseAllClusters: () => set({ expandedClusters: new Set<string>() }),

  // Filter Presets
  savePreset: (name, description, icon, color) => {
    const { filters } = get();
    const newPreset: FilterPreset = {
      id: `user-${Date.now()}`,
      name,
      description,
      icon,
      color,
      filters: { ...filters },
      createdAt: new Date().toISOString(),
      isBuiltIn: false,
    };
    usePresetStore.setState((state) => ({
      userPresets: [...state.userPresets, newPreset],
    }));
  },

  deletePreset: (id) => {
    usePresetStore.setState((state) => ({
      userPresets: state.userPresets.filter((p) => p.id !== id),
    }));
  },

  applyPreset: (id) => {
    // Get presets from both stores
    const userPresets = usePresetStore.getState().userPresets;
    const allPresets = [...BUILT_IN_PRESETS, ...userPresets];
    const preset = allPresets.find((p) => p.id === id);
    if (preset) {
      set({ filters: { ...preset.filters } });
    }
  },

  updatePreset: (id, updates) => {
    usePresetStore.setState((state) => ({
      userPresets: state.userPresets.map((p) =>
        p.id === id ? { ...p, ...updates } : p
      ),
    }));
  },
}));

// Helper function to compute metrics (pure function for memoization)
export function computeLogMetrics(logs: LogEntry[]) {
  const now = Date.now();
  const oneSecondAgo = now - 1000;
  const recentLogs = logs.filter(
    (log) => new Date(log.timestamp).getTime() > oneSecondAgo
  );

  // Unique methods with counts
  const methodCounts = new Map<string, number>();
  const hostCounts = new Map<string, number>();
  const pathCounts = new Map<string, number>();
  logs.forEach((log) => {
    const isRawOrStderrMessage =
      log.message_type === 'raw' ||
      log.message_type === 'stderr' ||
      log.method === 'raw' ||
      log.method === 'stderr';
    if (log.method && !isRawOrStderrMessage) {
      methodCounts.set(log.method, (methodCounts.get(log.method) || 0) + 1);
    }
    const host = getLogHost(log);
    if (host) {
      hostCounts.set(host, (hostCounts.get(host) || 0) + 1);
    }
    const path = log.path_cache ?? getLogPath(log);
    if (path) {
      pathCounts.set(path, (pathCounts.get(path) || 0) + 1);
    }
  });

  // Direction counts
  const incomingCount = logs.filter((l) => l.direction === 'in').length;
  const outgoingCount = logs.filter((l) => l.direction === 'out').length;

  // Token stats
  let totalTokens = 0;
  let tokensToServer = 0;
  let tokensFromServer = 0;
  const tokensByMethod: Record<string, number> = {};

  logs.forEach((log) => {
    const tokens = getLogTokenCount(log);
    totalTokens += tokens;
    if (log.direction === 'in') {
      tokensToServer += tokens;
    } else {
      tokensFromServer += tokens;
    }
    const isRawOrStderrMessage =
      log.message_type === 'raw' ||
      log.message_type === 'stderr' ||
      log.method === 'raw' ||
      log.method === 'stderr';
    if (log.method && !isRawOrStderrMessage) {
      tokensByMethod[log.method] = (tokensByMethod[log.method] || 0) + tokens;
    }
  });

  const topMethodsByTokens = Object.entries(tokensByMethod)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  return {
    totalMessages: logs.length,
    messagesPerSecond: recentLogs.length,
    methodCounts: Array.from(methodCounts.entries())
      .map(([method, count]) => ({ method, count }))
      .sort((a, b) => b.count - a.count),
    hostCounts: Array.from(hostCounts.entries())
      .map(([host, count]) => ({ host, count }))
      .sort((a, b) => b.count - a.count),
    pathCounts: Array.from(pathCounts.entries())
      .map(([path, count]) => ({ path, count }))
      .sort((a, b) => b.count - a.count),
    incomingCount,
    outgoingCount,
    totalTokens,
    tokensToServer,
    tokensFromServer,
    topMethodsByTokens,
  };
}

// Cluster type for grouping request/response pairs
export interface EventCluster {
  id: string;
  request: LogEntry;
  response: LogEntry | null;
  method: string;
  latency: number | null;
  hasError: boolean;
  hasPii: boolean;
  policyDenied: boolean;
  timestamp: string;
  source: EventSource;
}

// Display item can be either a cluster or a standalone log
export type DisplayItem =
  | { type: 'cluster'; cluster: EventCluster }
  | { type: 'log'; log: LogEntry };

export function hasPairedPayload(log: LogEntry): boolean {
  return !!(
    log.request_content ||
    log.response_content ||
    log.request_preview ||
    log.response_preview ||
    log.request_content_ref ||
    log.response_content_ref
  );
}

function isPrePairedAiEvent(log: LogEntry): boolean {
  return (
    (log.source === 'ai_proxy' || log.source === 'agent_app') &&
    hasPairedPayload(log)
  );
}

function isCodexRequestWithMissingResponse(log: LogEntry): boolean {
  const method = (log.method || '').toLowerCase();
  if (!method.includes('/backend-api/codex/responses')) {
    return false;
  }
  const response = log.response_content || '';
  if (!response.trim()) {
    return true;
  }
  return response.includes('[no HTTP response body captured');
}

function looksLikeCodexWebsocketUpdate(log: LogEntry): boolean {
  if (log.source !== 'agent_app') {
    return false;
  }
  if (log.direction !== 'out') {
    return false;
  }
  const method = log.method || '';
  if (!method.startsWith('WebSocket /c2/ws/')) {
    return false;
  }
  const content = (log.content || '').trim();
  if (content.length < 120) {
    return false;
  }
  const lower = content.toLowerCase();
  return (
    lower.includes('"conversation-update"') ||
    lower.includes('"update_type":"add-messages"') ||
    lower.includes('"conversation_id"') ||
    lower.includes('"messages":[')
  );
}

function isWithinCorrelationWindow(
  requestTimestamp: string,
  candidateTimestamp: string,
  maxMs: number
): boolean {
  const req = Date.parse(requestTimestamp);
  const cand = Date.parse(candidateTimestamp);
  if (Number.isNaN(req) || Number.isNaN(cand)) {
    return true;
  }
  if (cand < req) {
    return false;
  }
  return cand - req <= maxMs;
}

function findCodexWebsocketResponse(
  logs: LogEntry[],
  requestIndex: number,
  request: LogEntry,
  usedResponseIds: Set<string>
): LogEntry | null {
  // Keep this bounded for latency and to avoid cross-turn mispairing.
  const maxLookahead = Math.min(logs.length, requestIndex + 120);
  for (let j = requestIndex + 1; j < maxLookahead; j++) {
    const candidate = logs[j];
    if (usedResponseIds.has(candidate.id)) {
      continue;
    }
    if (candidate.session_id !== request.session_id) {
      continue;
    }
    if (!looksLikeCodexWebsocketUpdate(candidate)) {
      continue;
    }
    if (!isWithinCorrelationWindow(request.timestamp, candidate.timestamp, 120_000)) {
      continue;
    }
    return candidate;
  }

  return null;
}

// Create clusters from logs
export function createClusters(logs: LogEntry[]): DisplayItem[] {
  const items: DisplayItem[] = [];
  const usedResponseIds = new Set<string>();
  const parsedCache = new Map<string, ParsedMessage | null>();
  const pendingByRpc = new Map<string, number[]>();
  const pendingFallback = new Map<string, number[]>();

  const getParsed = (log: LogEntry): ParsedMessage | null => {
    if (parsedCache.has(log.id)) {
      return parsedCache.get(log.id) ?? null;
    }
    const parsed = parseLogMessage(log);
    parsedCache.set(log.id, parsed);
    return parsed;
  };

  const getRpcId = (log: LogEntry): string | null => {
    const parsed = getParsed(log);
    if (parsed?.id === undefined || parsed?.id === null) {
      return null;
    }
    return String(parsed.id);
  };

  const baseKey = (log: LogEntry): string =>
    `${log.source}|${log.session_id}|${log.server_name}`;

  const rpcKey = (log: LogEntry, rpcId: string): string =>
    `${baseKey(log)}|${rpcId}`;

  const enqueuePending = (map: Map<string, number[]>, key: string, index: number): void => {
    const queue = map.get(key);
    if (queue) {
      queue.push(index);
      return;
    }
    map.set(key, [index]);
  };

  const dequeuePending = (map: Map<string, number[]>, key: string): number | undefined => {
    const queue = map.get(key);
    if (!queue || queue.length === 0) {
      return undefined;
    }

    while (queue.length > 0) {
      const index = queue.shift();
      if (index === undefined) {
        continue;
      }
      const item = items[index];
      if (item?.type === 'cluster' && !item.cluster.response) {
        if (queue.length === 0) {
          map.delete(key);
        }
        return index;
      }
    }

    map.delete(key);
    return undefined;
  };

  const removePendingIndex = (map: Map<string, number[]>, key: string, index: number): void => {
    const queue = map.get(key);
    if (!queue || queue.length === 0) {
      return;
    }
    const filtered = queue.filter((entry) => entry !== index);
    if (filtered.length === 0) {
      map.delete(key);
      return;
    }
    map.set(key, filtered);
  };

  const buildEmptyResponsePlaceholder = (log: LogEntry): string => {
    const method = log.method || 'request';
    const status = log.status_code ?? 'unknown';
    const methodLower = method.toLowerCase();

    if (methodLower.includes('/backend-api/codex/responses')) {
      return `[no HTTP response body captured for ${method} (HTTP ${status}) - Codex output may be streamed via WebSocket]`;
    }
    return `[no HTTP response body captured for ${method} (HTTP ${status})]`;
  };

  const buildPairedRequestLog = (log: LogEntry): LogEntry => {
    const requestContent = log.request_content?.trim() ? log.request_content : '';
    const fallbackPreview =
      log.request_preview ||
      `[no request body captured for ${log.method || 'request'}]`;
    const requestDisplay = requestContent || fallbackPreview;

    return {
      ...log,
      direction: 'in',
      content: requestDisplay,
      content_preview: requestDisplay,
      status_code: undefined,
    };
  };

  const buildPairedResponseLog = (log: LogEntry): LogEntry => {
    const responseContent = log.response_content?.trim() ? log.response_content : '';
    const fallbackPreview =
      log.response_preview || buildEmptyResponsePlaceholder(log);
    const responseDisplay = responseContent || fallbackPreview;

    return {
      ...log,
      direction: 'out',
      content: responseDisplay,
      content_preview: responseDisplay,
    };
  };

  const hasResponseError = (content?: string): boolean => {
    if (!content) return false;
    try {
      const parsed = JSON.parse(content) as { error?: unknown };
      return parsed.error !== undefined;
    } catch {
      return false;
    }
  };

  // Process logs in a single pass and pair responses in O(1) average time.
  for (let i = 0; i < logs.length; i++) {
    const log = logs[i];
    if (usedResponseIds.has(log.id)) {
      continue;
    }

    // AI/Agent rows may already contain paired request/response payloads in a single event.
    // Render them as coupled rows to match MCP request/response clustering behavior.
    if (isPrePairedAiEvent(log)) {
      const request = buildPairedRequestLog(log);
      let response = buildPairedResponseLog(log);
      let correlatedWsResponse: LogEntry | null = null;

      // Codex often returns an empty HTTP body and streams the actual output via websocket.
      // Correlate nearby websocket conversation updates so the response row is meaningful.
      if (isCodexRequestWithMissingResponse(log)) {
        correlatedWsResponse = findCodexWebsocketResponse(logs, i, log, usedResponseIds);
        if (correlatedWsResponse) {
          usedResponseIds.add(correlatedWsResponse.id);
          response = {
            ...response,
            timestamp: correlatedWsResponse.timestamp,
            content: correlatedWsResponse.content || response.content,
            content_preview:
              correlatedWsResponse.content || correlatedWsResponse.content_preview || response.content_preview,
          };
        }
      }

      const correlatedLatency = correlatedWsResponse
        ? calculateLatency(request, correlatedWsResponse)
        : null;
      const cluster: EventCluster = {
        id: `cluster-${log.id}`,
        request,
        response,
        method: log.tool_name ? `${log.method}/${log.tool_name}` : log.method || 'request',
        latency: correlatedLatency ?? log.latency_ms ?? null,
        hasError:
          (log.status_code !== undefined && log.status_code >= 400) ||
          log.policy_allowed === false ||
          hasResponseError(response.content),
        hasPii: log.pii_detected,
        policyDenied: log.policy_allowed === false,
        timestamp: log.timestamp,
        source: log.source,
      };

      items.push({ type: 'cluster', cluster });
      continue;
    }

    const parsed = getParsed(log);
    const rpcId = getRpcId(log);
    const base = baseKey(log);

    const requestLike = (() => {
      if (isPrePairedAiEvent(log)) {
        return false;
      }
      if (log.direction !== 'in') {
        return false;
      }
      if (log.method) {
        return true;
      }
      return !!parsed?.method;
    })();

    if (requestLike) {
      const method = log.tool_name
        ? `${log.method || parsed?.method || 'request'}/${log.tool_name}`
        : log.method || parsed?.method || 'request';

      const cluster: EventCluster = {
        id: `cluster-${log.id}`,
        request: log,
        response: null,
        method,
        latency: null,
        hasError:
          (log.status_code !== undefined && log.status_code >= 400) ||
          log.policy_allowed === false,
        hasPii: log.pii_detected,
        policyDenied: log.policy_allowed === false,
        timestamp: log.timestamp,
        source: log.source,
      };

      const itemIndex = items.length;
      items.push({ type: 'cluster', cluster });

      if (rpcId) {
        enqueuePending(pendingByRpc, rpcKey(log, rpcId), itemIndex);
      }
      if (log.source === 'mcp' || !rpcId) {
        enqueuePending(pendingFallback, base, itemIndex);
      }

      continue;
    }

    const responseLike = (() => {
      if (log.direction !== 'out') {
        return false;
      }
      if (isPrePairedAiEvent(log)) {
        return false;
      }
      if (log.source === 'ai_proxy' || log.source === 'agent_app') {
        return false;
      }
      if (!parsed) {
        return true;
      }
      return parsed.result !== undefined || parsed.error !== undefined || !parsed.method;
    })();

    if (responseLike) {
      let matchIndex: number | undefined;
      if (rpcId) {
        matchIndex = dequeuePending(pendingByRpc, rpcKey(log, rpcId));
      }
      if (matchIndex === undefined) {
        matchIndex = dequeuePending(pendingFallback, base);
      }

      if (matchIndex === undefined) {
        items.push({ type: 'log', log });
        continue;
      }

      const matched = items[matchIndex];
      if (!matched || matched.type !== 'cluster') {
        items.push({ type: 'log', log });
        continue;
      }

      const request = matched.cluster.request;
      const requestRpcId = getRpcId(request);
      if (requestRpcId) {
        removePendingIndex(pendingByRpc, rpcKey(request, requestRpcId), matchIndex);
      }
      if (request.source === 'mcp' || !requestRpcId) {
        removePendingIndex(pendingFallback, baseKey(request), matchIndex);
      }

      matched.cluster.response = log;
      matched.cluster.latency = calculateLatency(request, log);
      matched.cluster.hasError =
        matched.cluster.hasError ||
        ((log.status_code !== undefined && log.status_code >= 400) ||
          log.policy_allowed === false ||
          parsed?.error !== undefined);
      matched.cluster.hasPii = matched.cluster.hasPii || log.pii_detected;
      matched.cluster.policyDenied =
        matched.cluster.policyDenied || log.policy_allowed === false;

      continue;
    }

    if (!usedResponseIds.has(log.id)) {
      items.push({ type: 'log', log });
    }
  }

  return items;
}

// Hook to get all presets (combines built-in and user presets)
export function usePresets(): FilterPreset[] {
  const userPresets = usePresetStore((state) => state.userPresets);
  return [...BUILT_IN_PRESETS, ...userPresets];
}

// Get presets without hook (for non-component use)
export function getPresets(): FilterPreset[] {
  const userPresets = usePresetStore.getState().userPresets;
  return [...BUILT_IN_PRESETS, ...userPresets];
}
