"use client";

import { useEffect, useRef } from "react";
import { toast } from "sonner";
import { useObservabilityStore, type LogEntry } from "@/store/observability";
import { useSettingsStore } from "@/store/settings";

// Track which log IDs we've already notified about
const notifiedLogIds = new Set<string>();

// Sound for notifications (optional)
const playNotificationSound = () => {
  try {
    const audio = new Audio("/notification.mp3");
    audio.volume = 0.3;
    audio.play().catch(() => {
      // Ignore errors - sound may not be available
    });
  } catch {
    // Ignore
  }
};

export function NotificationProvider({ children }: { children: React.ReactNode }) {
  const logs = useObservabilityStore((state) => state.logs);
  const prevLogsLengthRef = useRef(0);

  // Settings
  const notifyOnPolicyDenial = useSettingsStore((state) => state.notifyOnPolicyDenial);
  const notifyOnPiiDetection = useSettingsStore((state) => state.notifyOnPiiDetection);
  const notifyOnBudgetAlert = useSettingsStore((state) => state.notifyOnBudgetAlert);
  const soundEnabled = useSettingsStore((state) => state.soundEnabled);

  useEffect(() => {
    // Only check new logs (avoid notifying on initial load)
    if (prevLogsLengthRef.current === 0) {
      prevLogsLengthRef.current = logs.length;
      // Mark all existing logs as already notified
      logs.forEach((log) => notifiedLogIds.add(log.id));
      return;
    }

    // Process new logs
    const newLogs = logs.slice(prevLogsLengthRef.current);
    prevLogsLengthRef.current = logs.length;

    newLogs.forEach((log) => {
      // Skip if already notified
      if (notifiedLogIds.has(log.id)) return;
      notifiedLogIds.add(log.id);

      // Policy denial notification
      if (notifyOnPolicyDenial && log.policy_allowed === false) {
        toast.error(
          <div>
            <p className="font-semibold">Policy Denied</p>
            <p className="text-xs opacity-80">
              {log.method || "Request"} blocked
              {log.policy_reason ? `: ${log.policy_reason}` : ""}
            </p>
          </div>,
          {
            duration: 5000,
            id: `policy-${log.id}`,
          }
        );
        if (soundEnabled) playNotificationSound();
      }

      // PII detection notification
      if (notifyOnPiiDetection && log.pii_detected && log.pii_types.length > 0) {
        toast.warning(
          <div>
            <p className="font-semibold">PII Detected</p>
            <p className="text-xs opacity-80">
              Found: {log.pii_types.join(", ")}
            </p>
          </div>,
          {
            duration: 4000,
            id: `pii-${log.id}`,
          }
        );
        if (soundEnabled) playNotificationSound();
      }

      // Budget alert (check for high cost)
      if (notifyOnBudgetAlert && log.cost_usd && log.cost_usd > 0.10) {
        toast.info(
          <div>
            <p className="font-semibold">High Cost Request</p>
            <p className="text-xs opacity-80">
              ${log.cost_usd.toFixed(4)} - {log.method || log.model || "Request"}
            </p>
          </div>,
          {
            duration: 4000,
            id: `cost-${log.id}`,
          }
        );
      }
    });

    // Cleanup old IDs to prevent memory leak (keep last 1000)
    if (notifiedLogIds.size > 1000) {
      const idsArray = Array.from(notifiedLogIds);
      idsArray.slice(0, idsArray.length - 1000).forEach((id) => notifiedLogIds.delete(id));
    }
  }, [logs, notifyOnPolicyDenial, notifyOnPiiDetection, notifyOnBudgetAlert, soundEnabled]);

  return <>{children}</>;
}
