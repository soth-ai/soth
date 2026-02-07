import { create } from 'zustand';
import { persist } from 'zustand/middleware';

// Dynamic import to avoid circular dependency
const getMaxLogRetention = () => {
  try {
    const stored = localStorage.getItem('soth-dashboard-settings');
    if (stored) {
      const parsed = JSON.parse(stored);
      return parsed.state?.maxLogRetention ?? 10000;
    }
  } catch {
    // Ignore
  }
  return 10000;
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
  cost_usd?: number;
  latency_ms?: number;
  // Computed fields
  message_type?: 'json-rpc' | 'raw' | 'stderr';
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

  // Logs
  logs: LogEntry[];
  addLog: (log: LogEntry) => void;
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

// Parse JSON-RPC message from content
export function parseLogMessage(log: LogEntry): ParsedMessage | null {
  if (log.message_type === 'raw' || log.message_type === 'stderr') {
    return null;
  }
  try {
    return JSON.parse(log.content) as ParsedMessage;
  } catch {
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

  if (isLikelyBinaryPayload(raw)) {
    return summarizeBinaryPreview(raw);
  }

  const parsed = parsePossiblyEncodedJson(raw);
  if (typeof parsed === 'string') {
    const normalized = normalizeInline(parsed);
    if (normalized.length === 0) {
      return normalizeInline(raw);
    }
    if (isLikelyBinaryPayload(normalized)) {
      return summarizeBinaryPreview(raw);
    }
    return normalized;
  }

  const extracted = extractReadableText(parsed);
  if (extracted) {
    return extracted;
  }

  if (typeof parsed === 'object' && parsed !== null) {
    try {
      const normalized = normalizeInline(JSON.stringify(parsed));
      if (isLikelyBinaryPayload(normalized)) {
        return summarizeBinaryPreview(raw);
      }
      return normalized;
    } catch {
      return normalizeInline(raw);
    }
  }

  return normalizeInline(String(parsed));
}

// Decode payload for the inspector editor (preserves structure for JSON syntax highlight).
export function decodeEditorContent(raw?: string): {
  content: string;
  language: 'json' | 'plaintext';
} {
  if (!raw) {
    return { content: '', language: 'plaintext' };
  }

  if (isLikelyBinaryPayload(raw)) {
    return { content: summarizeBinaryPreview(raw), language: 'plaintext' };
  }

  const parsed = parsePossiblyEncodedJson(raw);

  if (parsed !== null && typeof parsed === 'object') {
    try {
      return {
        content: JSON.stringify(parsed, null, 2),
        language: 'json',
      };
    } catch {
      return { content: raw, language: 'plaintext' };
    }
  }

  if (parsed === null || typeof parsed === 'number' || typeof parsed === 'boolean') {
    return {
      content: JSON.stringify(parsed, null, 2),
      language: 'json',
    };
  }

  const text = typeof parsed === 'string' ? parsed : String(parsed);
  const trimmed = text.trim();
  const looksLikeJsonEnvelope =
    (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
    (trimmed.startsWith('[') && trimmed.endsWith(']'));

  if (looksLikeJsonEnvelope) {
    try {
      const reparsed = JSON.parse(trimmed);
      return {
        content: JSON.stringify(reparsed, null, 2),
        language: 'json',
      };
    } catch {
      // Keep plaintext fallback below.
    }
  }

  if (isLikelyBinaryPayload(text)) {
    return { content: summarizeBinaryPreview(raw), language: 'plaintext' };
  }

  return {
    content: text,
    language: 'plaintext',
  };
}

// Get summary of log content
export function getLogSummary(log: LogEntry): string {
  if (log.content_preview) {
    return decodeSmartDisplayText(log.content_preview);
  }

  const parsed = parseLogMessage(log);
  if (!parsed) {
    return decodeSmartDisplayText(log.content);
  }

  if (parsed.error) {
    return decodeSmartDisplayText(`Error ${parsed.error.code}: ${parsed.error.message}`);
  }

  if (parsed.params) {
    return decodeSmartDisplayText(JSON.stringify(parsed.params));
  }

  if (parsed.result) {
    return decodeSmartDisplayText(JSON.stringify(parsed.result));
  }

  return decodeSmartDisplayText(JSON.stringify(parsed));
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

  // Logs
  logs: [],
  addLog: (log) =>
    set((state) => {
      if (state.logs.some((existing) => existing.id === log.id)) {
        return state;
      }

      // Limit logs based on settings
      const maxLogs = getMaxLogRetention();
      const newLogs = [...state.logs, log];
      while (newLogs.length > maxLogs) {
        newLogs.shift();
      }

      // Update session message count
      const sessions = state.sessions.map((s) =>
        s.id === log.session_id
          ? { ...s, message_count: s.message_count + 1, last_activity: log.timestamp }
          : s
      );

      return { logs: newLogs, sessions };
    }),
  hydrateLogPayload: (id, part, content) =>
    set((state) => {
      let updated = false;
      const logs = state.logs.map((log) => {
        if (log.id !== id) {
          return log;
        }

        updated = true;
        if (part === "request") {
          return { ...log, request_content: content };
        }
        if (part === "response") {
          return { ...log, response_content: content };
        }
        return { ...log, content };
      });

      return updated ? { logs } : state;
    }),
  clearLogs: () => set({ logs: [], selectedLogId: null, selectedLogPart: null }),

  // Selection
  selectedLogId: null,
  selectedLogPart: null,
  selectLog: (id, part = null) =>
    set({
      selectedLogId: id,
      selectedLogPart: id === null ? null : part,
    }),
  getSelectedLog: () => {
    const { logs, selectedLogId } = get();
    return logs.find((l) => l.id === selectedLogId) || null;
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

  // Filters
  filters: {},
  setFilters: (newFilters) =>
    set((state) => ({
      filters: { ...state.filters, ...newFilters },
    })),
  clearFilters: () => set({ filters: {} }),
  getFilteredLogs: () => {
    const { logs, filters } = get();

    return logs.filter((log) => {
      // Session filter
      if (filters.sessionId && log.session_id !== filters.sessionId) {
        return false;
      }

      // Search text
      if (filters.searchText) {
        const search = filters.searchText.toLowerCase();
        const matchesContent = log.content.toLowerCase().includes(search);
        const matchesMethod = log.method?.toLowerCase().includes(search);
        const matchesToolName = log.tool_name?.toLowerCase().includes(search);
        const matchesServer = log.server_name.toLowerCase().includes(search);
        const matchesAgent = log.agent.name.toLowerCase().includes(search);
        if (!matchesContent && !matchesMethod && !matchesToolName && !matchesServer && !matchesAgent) {
          return false;
        }
      }

      // Method filter
      if (filters.method && log.method !== filters.method) {
        return false;
      }

      // Direction filter
      if (filters.direction && log.direction !== filters.direction) {
        return false;
      }

      // Server name filter
      if (filters.serverName) {
        const server = (log.server_name || '').toLowerCase();
        const selected = filters.serverName.toLowerCase();
        const matchesServer = server === selected || server.endsWith(`.${selected}`);
        if (!matchesServer) {
          return false;
        }
      }

      // Latency filter
      if (filters.minLatencyMs && log.latency_ms !== undefined) {
        if (log.latency_ms < filters.minLatencyMs) {
          return false;
        }
      }

      // Policy denied filter
      if (filters.policyDenied && log.policy_allowed !== false) {
        return false;
      }

      // PII detected filter
      if (filters.piiDetected && !log.pii_detected) {
        return false;
      }

      // Has error filter
      if (filters.hasError) {
        try {
          const parsed = JSON.parse(log.content);
          if (!parsed.error) {
            return false;
          }
        } catch {
          return false;
        }
      }

      // Source filter
      if (filters.source && log.source !== filters.source) {
        return false;
      }

      return true;
    });
  },

  // Auto-scroll
  isLive: true,
  setIsLive: (live) => set({ isLive: live }),

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
  logs.forEach((log) => {
    if (log.method) {
      methodCounts.set(log.method, (methodCounts.get(log.method) || 0) + 1);
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
    const tokens = log.token_count || 0;
    totalTokens += tokens;
    if (log.direction === 'in') {
      tokensToServer += tokens;
    } else {
      tokensFromServer += tokens;
    }
    if (log.method) {
      tokensByMethod[log.method] = (tokensByMethod[log.method] || 0) + tokens;
    }
  });

  const topMethodsByTokens = Object.entries(tokensByMethod)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  return {
    totalMessages: logs.length,
    messagesPerSecond: recentLogs.length,
    methodCounts: Array.from(methodCounts.entries()).map(([method, count]) => ({
      method,
      count,
    })),
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

function extractRpcId(log: LogEntry): string | null {
  const parsed = parseLogMessage(log);
  if (parsed?.id === undefined || parsed?.id === null) {
    return null;
  }
  return String(parsed.id);
}

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

function isRequestLike(log: LogEntry): boolean {
  if (isPrePairedAiEvent(log)) {
    return false;
  }
  if (log.direction !== 'in') {
    return false;
  }
  if (log.method) {
    return true;
  }
  const parsed = parseLogMessage(log);
  return !!parsed?.method;
}

function isResponseLike(log: LogEntry): boolean {
  if (log.direction !== 'out') {
    return false;
  }
  if (isPrePairedAiEvent(log)) {
    return false;
  }
  if (log.source === 'ai_proxy' || log.source === 'agent_app') {
    return false;
  }
  const parsed = parseLogMessage(log);
  if (!parsed) {
    return true;
  }
  return parsed.result !== undefined || parsed.error !== undefined || !parsed.method;
}

// Create clusters from logs
export function createClusters(logs: LogEntry[]): DisplayItem[] {
  const items: DisplayItem[] = [];
  const usedResponseIds = new Set<string>();

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

  const findMatchingResponse = (requestIndex: number, request: LogEntry): LogEntry | null => {
    const requestRpcId = extractRpcId(request);
    const isMcp = request.source === 'mcp';

    for (let j = requestIndex + 1; j < logs.length; j++) {
      const candidate = logs[j];
      if (usedResponseIds.has(candidate.id)) {
        continue;
      }
      if (!isResponseLike(candidate)) {
        continue;
      }
      if (candidate.source !== request.source) {
        continue;
      }
      if (candidate.session_id !== request.session_id) {
        continue;
      }
      if (candidate.server_name !== request.server_name) {
        continue;
      }

      const candidateRpcId = extractRpcId(candidate);

      // Strongest pairing: same JSON-RPC id.
      if (requestRpcId && candidateRpcId) {
        if (requestRpcId === candidateRpcId) {
          return candidate;
        }
        continue;
      }

      // MCP fallback: pair to the next outgoing message in same session/server.
      if (isMcp) {
        return candidate;
      }

      // Generic fallback for sparse/legacy events with no ids.
      if (!requestRpcId && !candidateRpcId) {
        return candidate;
      }
    }

    return null;
  };

  // Process logs to find request/response pairs
  for (let i = 0; i < logs.length; i++) {
    const log = logs[i];

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

    const parsed = parseLogMessage(log);
    if (isRequestLike(log)) {
      const matchingResponse = findMatchingResponse(i, log);
      if (matchingResponse) {
        usedResponseIds.add(matchingResponse.id);
      }

      // Create cluster
      const latency = matchingResponse ? calculateLatency(log, matchingResponse) : null;
      const responseParsed = matchingResponse ? parseLogMessage(matchingResponse) : null;
      const method = log.tool_name
        ? `${log.method || parsed?.method || 'request'}/${log.tool_name}`
        : log.method || parsed?.method || 'request';

      const cluster: EventCluster = {
        id: `cluster-${log.id}`,
        request: log,
        response: matchingResponse,
        method,
        latency,
        hasError:
          (matchingResponse?.status_code !== undefined && matchingResponse.status_code >= 400) ||
          (log.status_code !== undefined && log.status_code >= 400) ||
          matchingResponse?.policy_allowed === false ||
          responseParsed?.error !== undefined,
        hasPii: log.pii_detected || (matchingResponse?.pii_detected ?? false),
        policyDenied: log.policy_allowed === false || matchingResponse?.policy_allowed === false,
        timestamp: log.timestamp,
        source: log.source,
      };

      items.push({ type: 'cluster', cluster });
    } else if (!usedResponseIds.has(log.id)) {
      // Standalone log (not part of a cluster)
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
