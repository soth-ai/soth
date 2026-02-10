"use client";

import { useEffect, useRef } from "react";
import { toast } from "sonner";
import { useObservabilityStore } from "@/store/observability";
import { useSettingsStore } from "@/store/settings";

// Track which log IDs we've already notified about
const notifiedLogIds = new Set<string>();
const STARTUP_NOTIFICATION_WARMUP_MS = 4000;
const HISTORICAL_EVENT_GRACE_MS = 1500;
const PII_TOAST_ID = "pii-live";

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
  const warmupUntilRef = useRef(Date.now() + STARTUP_NOTIFICATION_WARMUP_MS);
  const mountedAtRef = useRef(Date.now());

  // Settings
  const notifyOnPolicyDenial = useSettingsStore((state) => state.notifyOnPolicyDenial);
  const notifyOnPiiDetection = useSettingsStore((state) => state.notifyOnPiiDetection);
  const notifyOnBudgetAlert = useSettingsStore((state) => state.notifyOnBudgetAlert);
  const soundEnabled = useSettingsStore((state) => state.soundEnabled);

  useEffect(() => {
    if (logs.length < prevLogsLengthRef.current) {
      prevLogsLengthRef.current = logs.length;
      logs.forEach((log) => notifiedLogIds.add(log.id));
      return;
    }

    // Only check new logs (avoid notifying on initial load)
    if (prevLogsLengthRef.current === 0) {
      prevLogsLengthRef.current = logs.length;
      // Mark all existing logs as already notified
      logs.forEach((log) => notifiedLogIds.add(log.id));
      return;
    }

    // Warm up briefly after mount/reload to absorb bootstrap/backfill batches.
    if (Date.now() < warmupUntilRef.current) {
      prevLogsLengthRef.current = logs.length;
      logs.forEach((log) => notifiedLogIds.add(log.id));
      return;
    }

    // Process new logs
    const newLogs = logs.slice(prevLogsLengthRef.current);
    prevLogsLengthRef.current = logs.length;
    const piiLogsToNotify: Array<{ id: string; pii_types: string[] }> = [];
    let shouldPlaySound = false;

    newLogs.forEach((log) => {
      // Skip if already notified
      if (notifiedLogIds.has(log.id)) return;
      notifiedLogIds.add(log.id);

      const eventTs = Date.parse(log.timestamp);
      const isHistorical =
        Number.isFinite(eventTs) && eventTs < mountedAtRef.current - HISTORICAL_EVENT_GRACE_MS;
      if (isHistorical) {
        return;
      }

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
        shouldPlaySound = true;
      }

      // PII detection notification
      if (notifyOnPiiDetection && log.pii_detected && log.pii_types.length > 0) {
        piiLogsToNotify.push(log);
        shouldPlaySound = true;
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

    if (notifyOnPiiDetection && piiLogsToNotify.length === 1) {
      const log = piiLogsToNotify[0];
      toast.warning(
        <div>
          <p className="font-semibold">PII Detected</p>
          <p className="text-xs opacity-80">Found: {log.pii_types.join(", ")}</p>
        </div>,
        {
          duration: 4000,
          id: PII_TOAST_ID,
        }
      );
    } else if (notifyOnPiiDetection && piiLogsToNotify.length > 1) {
      const types = new Set<string>();
      piiLogsToNotify.forEach((log) => log.pii_types.forEach((type) => types.add(type)));
      const topTypes = Array.from(types).slice(0, 4);
      toast.warning(
        <div>
          <p className="font-semibold">PII Detected ({piiLogsToNotify.length} events)</p>
          <p className="text-xs opacity-80">
            Types: {topTypes.join(", ")}
            {types.size > topTypes.length ? ` +${types.size - topTypes.length} more` : ""}
          </p>
        </div>,
        {
          duration: 4500,
          id: PII_TOAST_ID,
        }
      );
    }

    if (shouldPlaySound && soundEnabled) {
      playNotificationSound();
    }

    // Cleanup old IDs to prevent memory leak (keep last 1000)
    if (notifiedLogIds.size > 1000) {
      const idsArray = Array.from(notifiedLogIds);
      idsArray.slice(0, idsArray.length - 1000).forEach((id) => notifiedLogIds.delete(id));
    }
  }, [logs, notifyOnPolicyDenial, notifyOnPiiDetection, notifyOnBudgetAlert, soundEnabled]);

  return <>{children}</>;
}
