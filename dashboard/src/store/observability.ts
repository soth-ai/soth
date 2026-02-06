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
  content_preview?: string;
  // Paired request/response content (for AI proxy)
  request_content?: string;
  request_preview?: string;
  response_content?: string;
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
  clearLogs: () => void;

  // Selection
  selectedLogId: string | null;
  selectLog: (id: string | null) => void;
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

// Get summary of log content
export function getLogSummary(log: LogEntry): string {
  if (log.content_preview) {
    return log.content_preview;
  }

  const parsed = parseLogMessage(log);
  if (!parsed) {
    return log.content.slice(0, 80);
  }

  if (parsed.error) {
    return `Error ${parsed.error.code}: ${parsed.error.message.slice(0, 60)}`;
  }

  if (parsed.params) {
    const paramStr = JSON.stringify(parsed.params);
    return paramStr.slice(0, 80);
  }

  if (parsed.result) {
    const resultStr = JSON.stringify(parsed.result);
    return resultStr.slice(0, 80);
  }

  return 'No content';
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
  clearLogs: () => set({ logs: [], selectedLogId: null }),

  // Selection
  selectedLogId: null,
  selectLog: (id) => set({ selectedLogId: id }),
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
      if (filters.serverName && log.server_name !== filters.serverName) {
        return false;
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

// Create clusters from logs
export function createClusters(logs: LogEntry[]): DisplayItem[] {
  const items: DisplayItem[] = [];
  const usedResponseIds = new Set<string>();

  // Process logs to find request/response pairs
  for (let i = 0; i < logs.length; i++) {
    const log = logs[i];
    const parsed = parseLogMessage(log);

    // Check if this is a request (has method, incoming)
    const isRequest = parsed?.method && log.direction === 'in';

    if (isRequest && parsed?.id !== undefined) {
      // Look for matching response
      let matchingResponse: LogEntry | null = null;

      for (let j = i + 1; j < logs.length; j++) {
        const potentialResponse = logs[j];
        if (usedResponseIds.has(potentialResponse.id)) continue;

        const respParsed = parseLogMessage(potentialResponse);
        if (
          potentialResponse.direction === 'out' &&
          respParsed &&
          respParsed.id === parsed.id &&
          (respParsed.result !== undefined || respParsed.error !== undefined)
        ) {
          matchingResponse = potentialResponse;
          usedResponseIds.add(potentialResponse.id);
          break;
        }
      }

      // Create cluster
      const latency = matchingResponse
        ? calculateLatency(log, matchingResponse)
        : null;

      const cluster: EventCluster = {
        id: `cluster-${log.id}`,
        request: log,
        response: matchingResponse,
        method: log.tool_name ? `${parsed.method}/${log.tool_name}` : parsed.method || 'unknown',
        latency,
        hasError: matchingResponse
          ? parseLogMessage(matchingResponse)?.error !== undefined
          : false,
        hasPii: log.pii_detected || (matchingResponse?.pii_detected ?? false),
        policyDenied: log.policy_allowed === false,
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
