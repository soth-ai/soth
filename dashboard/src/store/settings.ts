import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export type Theme = 'system' | 'light' | 'dark';

export interface DashboardSettings {
  // Display
  theme: Theme;
  compactMode: boolean;
  showTimestamps: boolean;
  timestampFormat: '12h' | '24h' | 'relative';

  // Observability
  defaultClusteringEnabled: boolean;
  autoScrollEnabled: boolean;
  maxLogRetention: number; // max logs to keep
  highlightPii: boolean;
  highlightErrors: boolean;

  // Notifications
  notifyOnPolicyDenial: boolean;
  notifyOnPiiDetection: boolean;
  notifyOnBudgetAlert: boolean;
  soundEnabled: boolean;

  // Connection
  apiBaseUrl: string;
  wsReconnectInterval: number; // ms
  refreshInterval: number; // ms

  // Data
  autoExportEnabled: boolean;
  exportFormat: 'json' | 'csv';
}

interface SettingsState extends DashboardSettings {
  updateSettings: (settings: Partial<DashboardSettings>) => void;
  resetSettings: () => void;
}

const defaultSettings: DashboardSettings = {
  // Display
  theme: 'system',
  compactMode: false,
  showTimestamps: true,
  timestampFormat: 'relative',

  // Observability
  defaultClusteringEnabled: true,
  autoScrollEnabled: true,
  maxLogRetention: 10000,
  highlightPii: true,
  highlightErrors: true,

  // Notifications
  notifyOnPolicyDenial: true,
  notifyOnPiiDetection: true,
  notifyOnBudgetAlert: true,
  soundEnabled: false,

  // Connection
  apiBaseUrl: '/api',
  wsReconnectInterval: 3000,
  refreshInterval: 5000,

  // Data
  autoExportEnabled: false,
  exportFormat: 'json',
};

export const useSettingsStore = create<SettingsState>()(
  persist(
    (set) => ({
      ...defaultSettings,

      updateSettings: (newSettings) =>
        set((state) => ({
          ...state,
          ...newSettings,
        })),

      resetSettings: () => set(defaultSettings),
    }),
    {
      name: 'soth-dashboard-settings',
    }
  )
);
