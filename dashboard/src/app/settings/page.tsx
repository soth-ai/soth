"use client";

import { useState } from "react";
import {
  Gear,
  Palette,
  Eye,
  Bell,
  PlugsConnected,
  Database,
  ArrowCounterClockwise,
  Check,
  Moon,
  Sun,
  Desktop,
  Info,
  FloppyDisk,
  Trash,
  Export,
} from "@phosphor-icons/react";
import { useSettingsStore, type Theme, type DashboardSettings } from "@/store/settings";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

// Toggle switch component
function Toggle({
  enabled,
  onChange,
  disabled = false,
}: {
  enabled: boolean;
  onChange: (value: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={enabled}
      disabled={disabled}
      onClick={() => onChange(!enabled)}
      className={cn(
        "relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50",
        enabled ? "bg-accent" : "bg-muted"
      )}
    >
      <span
        className={cn(
          "pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-lg ring-0 transition-transform",
          enabled ? "translate-x-5" : "translate-x-0"
        )}
      />
    </button>
  );
}

// Setting row component
function SettingRow({
  label,
  description,
  children,
}: {
  label: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center justify-between py-3 md:py-4 border-b border-border last:border-0 gap-2 sm:gap-4">
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-foreground">{label}</p>
        {description && (
          <p className="text-[10px] md:text-xs text-muted-foreground mt-0.5">{description}</p>
        )}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

// Select component
function Select<T extends string>({
  value,
  options,
  onChange,
}: {
  value: T;
  options: { value: T; label: string }[];
  onChange: (value: T) => void;
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value as T)}
      className="px-3 py-1.5 text-sm bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-accent/50 focus:border-accent"
    >
      {options.map((option) => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </select>
  );
}

// Number input
function NumberInput({
  value,
  onChange,
  min,
  max,
  step = 1,
  suffix,
}: {
  value: number;
  onChange: (value: number) => void;
  min?: number;
  max?: number;
  step?: number;
  suffix?: string;
}) {
  return (
    <div className="flex items-center gap-2">
      <input
        type="number"
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        min={min}
        max={max}
        step={step}
        className="w-24 px-3 py-1.5 text-sm bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-accent/50 focus:border-accent tabular-nums"
      />
      {suffix && <span className="text-xs text-muted-foreground">{suffix}</span>}
    </div>
  );
}

// Theme selector
function ThemeSelector({
  value,
  onChange,
}: {
  value: Theme;
  onChange: (value: Theme) => void;
}) {
  const themes: { value: Theme; label: string; icon: React.ElementType }[] = [
    { value: "system", label: "System", icon: Desktop },
    { value: "light", label: "Light", icon: Sun },
    { value: "dark", label: "Dark", icon: Moon },
  ];

  return (
    <div className="flex gap-1 md:gap-2">
      {themes.map((theme) => (
        <button
          key={theme.value}
          onClick={() => onChange(theme.value)}
          className={cn(
            "flex items-center gap-1 md:gap-2 px-2 md:px-3 py-1.5 md:py-2 rounded-lg border transition-all",
            value === theme.value
              ? "bg-accent text-accent-foreground border-accent"
              : "bg-background border-border hover:bg-muted hover:border-border-hover"
          )}
        >
          <theme.icon className="h-4 w-4" weight={value === theme.value ? "fill" : "regular"} />
          <span className="text-xs md:text-sm font-medium hidden sm:inline">{theme.label}</span>
        </button>
      ))}
    </div>
  );
}

export default function SettingsPage() {
  const settings = useSettingsStore();
  const [hasChanges, setHasChanges] = useState(false);

  const updateSetting = <K extends keyof DashboardSettings>(
    key: K,
    value: DashboardSettings[K]
  ) => {
    settings.updateSettings({ [key]: value });
    setHasChanges(true);
  };

  const handleReset = () => {
    settings.resetSettings();
    setHasChanges(false);
    toast.success("Settings reset to defaults");
  };

  const handleSave = () => {
    // Settings are already persisted via zustand, this is just for UX
    setHasChanges(false);
    toast.success("Settings saved");
  };

  const handleClearData = () => {
    if (confirm("This will clear all stored data including presets and logs. Continue?")) {
      localStorage.clear();
      toast.success("All data cleared");
      setTimeout(() => window.location.reload(), 500);
    }
  };

  return (
    <div className="min-h-screen">
      {/* Page Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 md:top-14 z-10">
        <div className="px-4 md:px-6 py-3 md:py-4 flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 md:gap-3">
            <div className="h-7 w-7 md:h-8 md:w-8 rounded-lg bg-accent/10 flex items-center justify-center">
              <Gear className="h-4 w-4 md:h-5 md:w-5 text-accent" weight="duotone" />
            </div>
            <div>
              <h1 className="text-base md:text-lg font-semibold">Settings</h1>
              <p className="text-[10px] md:text-xs text-muted-foreground hidden sm:block">
                Dashboard configuration & preferences
              </p>
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-2">
            <button
              onClick={handleReset}
              className="flex items-center gap-1 md:gap-1.5 px-2 md:px-3 py-1.5 text-xs md:text-sm text-muted-foreground hover:text-foreground rounded-lg hover:bg-muted transition-colors"
            >
              <ArrowCounterClockwise className="h-4 w-4" />
              <span className="hidden sm:inline">Reset</span>
            </button>
            {hasChanges && (
              <button
                onClick={handleSave}
                className="flex items-center gap-1 md:gap-1.5 px-3 md:px-4 py-1.5 text-xs md:text-sm font-medium bg-accent text-accent-foreground rounded-lg hover:bg-accent/90 transition-colors"
              >
                <Check className="h-4 w-4" weight="bold" />
                <span className="hidden sm:inline">Save</span>
              </button>
            )}
          </div>
        </div>
      </header>

      <div className="px-4 md:px-6 py-4 md:py-6 max-w-4xl">
        {/* Appearance */}
        <Card className="mb-4 md:mb-6">
          <CardHeader>
            <CardTitle>
              <Palette className="h-4 w-4 text-accent" weight="duotone" />
              Appearance
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <SettingRow label="Theme" description="Choose your preferred color scheme">
              <ThemeSelector
                value={settings.theme}
                onChange={(v) => updateSetting("theme", v)}
              />
            </SettingRow>
            <SettingRow
              label="Compact Mode"
              description="Reduce spacing for denser information display"
            >
              <Toggle
                enabled={settings.compactMode}
                onChange={(v) => updateSetting("compactMode", v)}
              />
            </SettingRow>
            <SettingRow label="Show Timestamps" description="Display timestamps on log entries">
              <Toggle
                enabled={settings.showTimestamps}
                onChange={(v) => updateSetting("showTimestamps", v)}
              />
            </SettingRow>
            <SettingRow label="Timestamp Format" description="How to display timestamps">
              <Select
                value={settings.timestampFormat}
                options={[
                  { value: "relative", label: "Relative (2m ago)" },
                  { value: "12h", label: "12-hour (3:45 PM)" },
                  { value: "24h", label: "24-hour (15:45)" },
                ]}
                onChange={(v) => updateSetting("timestampFormat", v)}
              />
            </SettingRow>
          </CardContent>
        </Card>

        {/* Observability */}
        <Card className="mb-4 md:mb-6">
          <CardHeader>
            <CardTitle>
              <Eye className="h-4 w-4 text-accent" weight="duotone" />
              Observability
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <SettingRow
              label="Event Clustering"
              description="Group request/response pairs by default"
            >
              <Toggle
                enabled={settings.defaultClusteringEnabled}
                onChange={(v) => updateSetting("defaultClusteringEnabled", v)}
              />
            </SettingRow>
            <SettingRow
              label="Auto-Scroll"
              description="Automatically scroll to new events"
            >
              <Toggle
                enabled={settings.autoScrollEnabled}
                onChange={(v) => updateSetting("autoScrollEnabled", v)}
              />
            </SettingRow>
            <SettingRow
              label="Highlight PII"
              description="Visually highlight events with detected PII"
            >
              <Toggle
                enabled={settings.highlightPii}
                onChange={(v) => updateSetting("highlightPii", v)}
              />
            </SettingRow>
            <SettingRow
              label="Highlight Errors"
              description="Visually highlight error responses"
            >
              <Toggle
                enabled={settings.highlightErrors}
                onChange={(v) => updateSetting("highlightErrors", v)}
              />
            </SettingRow>
            <SettingRow
              label="Max Log Retention"
              description="Maximum number of log entries to keep in memory"
            >
              <NumberInput
                value={settings.maxLogRetention}
                onChange={(v) => updateSetting("maxLogRetention", v)}
                min={1000}
                max={100000}
                step={1000}
                suffix="entries"
              />
            </SettingRow>
          </CardContent>
        </Card>

        {/* Notifications */}
        <Card className="mb-4 md:mb-6">
          <CardHeader>
            <CardTitle>
              <Bell className="h-4 w-4 text-accent" weight="duotone" />
              Notifications
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <SettingRow
              label="Policy Denial Alerts"
              description="Notify when a request is blocked by policy"
            >
              <Toggle
                enabled={settings.notifyOnPolicyDenial}
                onChange={(v) => updateSetting("notifyOnPolicyDenial", v)}
              />
            </SettingRow>
            <SettingRow
              label="PII Detection Alerts"
              description="Notify when PII is detected in traffic"
            >
              <Toggle
                enabled={settings.notifyOnPiiDetection}
                onChange={(v) => updateSetting("notifyOnPiiDetection", v)}
              />
            </SettingRow>
            <SettingRow
              label="Budget Alerts"
              description="Notify when budget thresholds are reached"
            >
              <Toggle
                enabled={settings.notifyOnBudgetAlert}
                onChange={(v) => updateSetting("notifyOnBudgetAlert", v)}
              />
            </SettingRow>
            <SettingRow
              label="Sound"
              description="Play sound for notifications"
            >
              <Toggle
                enabled={settings.soundEnabled}
                onChange={(v) => updateSetting("soundEnabled", v)}
              />
            </SettingRow>
          </CardContent>
        </Card>

        {/* Connection */}
        <Card className="mb-4 md:mb-6">
          <CardHeader>
            <CardTitle>
              <PlugsConnected className="h-4 w-4 text-accent" weight="duotone" />
              Connection
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <SettingRow
              label="API Base URL"
              description="Backend API endpoint"
            >
              <input
                type="text"
                value={settings.apiBaseUrl}
                onChange={(e) => updateSetting("apiBaseUrl", e.target.value)}
                className="w-48 px-3 py-1.5 text-sm bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-accent/50 focus:border-accent font-mono"
              />
            </SettingRow>
            <SettingRow
              label="WebSocket Reconnect"
              description="Interval between reconnection attempts"
            >
              <NumberInput
                value={settings.wsReconnectInterval}
                onChange={(v) => updateSetting("wsReconnectInterval", v)}
                min={1000}
                max={30000}
                step={1000}
                suffix="ms"
              />
            </SettingRow>
            <SettingRow
              label="Refresh Interval"
              description="How often to poll for metric updates"
            >
              <NumberInput
                value={settings.refreshInterval}
                onChange={(v) => updateSetting("refreshInterval", v)}
                min={1000}
                max={60000}
                step={1000}
                suffix="ms"
              />
            </SettingRow>
          </CardContent>
        </Card>

        {/* Data & Export */}
        <Card className="mb-4 md:mb-6">
          <CardHeader>
            <CardTitle>
              <Database className="h-4 w-4 text-accent" weight="duotone" />
              Data & Export
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <SettingRow
              label="Auto Export"
              description="Automatically export logs when buffer is full"
            >
              <Toggle
                enabled={settings.autoExportEnabled}
                onChange={(v) => updateSetting("autoExportEnabled", v)}
              />
            </SettingRow>
            <SettingRow
              label="Export Format"
              description="File format for exported data"
            >
              <Select
                value={settings.exportFormat}
                options={[
                  { value: "json", label: "JSON" },
                  { value: "csv", label: "CSV" },
                ]}
                onChange={(v) => updateSetting("exportFormat", v)}
              />
            </SettingRow>
          </CardContent>
        </Card>

        {/* Danger Zone */}
        <Card className="border-destructive/30">
          <CardHeader>
            <CardTitle className="text-destructive">
              <Trash className="h-4 w-4" weight="duotone" />
              Danger Zone
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <SettingRow
              label="Clear All Data"
              description="Remove all stored settings, presets, and cached data"
            >
              <button
                onClick={handleClearData}
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-destructive border border-destructive/30 rounded-lg hover:bg-destructive/10 transition-colors"
              >
                <Trash className="h-4 w-4" />
                Clear Data
              </button>
            </SettingRow>
          </CardContent>
        </Card>

        {/* Info footer */}
        <div className="mt-8 flex items-center gap-2 text-xs text-muted-foreground">
          <Info className="h-3.5 w-3.5" />
          <span>
            Settings are automatically saved to local storage and persist across sessions.
          </span>
        </div>
      </div>
    </div>
  );
}
