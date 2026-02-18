"use client";

import { useEffect, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";

// Chord timeout in ms
const CHORD_TIMEOUT = 500;

interface ShortcutMap {
  [key: string]: {
    path: string;
    label: string;
  };
}

const navigationShortcuts: ShortcutMap = {
  o: { path: "/", label: "Overview" },
  d: { path: "/debug", label: "Debug" },
  s: { path: "/settings", label: "Settings" },
};

export function KeyboardShortcuts({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const chordStartRef = useRef<number | null>(null);
  const pendingChordRef = useRef<string | null>(null);

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      // Ignore if typing in an input
      const target = e.target as HTMLElement;
      if (
        target.tagName === "INPUT" ||
        target.tagName === "TEXTAREA" ||
        target.contentEditable === "true"
      ) {
        return;
      }

      // Ignore if modifier keys are pressed (except for Cmd+K which is handled elsewhere)
      if (e.metaKey || e.ctrlKey || e.altKey) {
        return;
      }

      const key = e.key.toLowerCase();
      const now = Date.now();

      // Check if we're in a chord sequence
      if (pendingChordRef.current === "g") {
        // Check if still within timeout
        if (chordStartRef.current && now - chordStartRef.current < CHORD_TIMEOUT) {
          const shortcut = navigationShortcuts[key];
          if (shortcut) {
            e.preventDefault();
            router.push(shortcut.path);
            toast.success(`Navigated to ${shortcut.label}`, {
              duration: 1500,
            });
          }
        }
        // Reset chord state
        pendingChordRef.current = null;
        chordStartRef.current = null;
        return;
      }

      // Start a new chord if 'g' is pressed
      if (key === "g") {
        pendingChordRef.current = "g";
        chordStartRef.current = now;

        // Auto-reset after timeout
        setTimeout(() => {
          if (pendingChordRef.current === "g" && chordStartRef.current === now) {
            pendingChordRef.current = null;
            chordStartRef.current = null;
          }
        }, CHORD_TIMEOUT);
      }

      // Single key shortcuts
      if (key === "?") {
        e.preventDefault();
        toast.info(
          <div className="space-y-1">
            <p className="font-semibold">Keyboard Shortcuts</p>
            <p className="text-xs">⌘K - Command Palette</p>
            <p className="text-xs">G O - Go to Overview</p>
            <p className="text-xs">G D - Go to Debug</p>
            <p className="text-xs">G S - Go to Settings</p>
          </div>,
          { duration: 5000 }
        );
      }
    },
    [router]
  );

  useEffect(() => {
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown]);

  return <>{children}</>;
}
