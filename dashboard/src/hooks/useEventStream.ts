import { useEffect, useRef, useState, useCallback } from "react";
import type { WrapEvent } from "@/types";

const MAX_EVENTS = 200;

interface UseEventStreamOptions {
  enabled?: boolean;
  maxEvents?: number;
}

interface UseEventStreamResult {
  events: WrapEvent[];
  isConnected: boolean;
  error: string | null;
  clearEvents: () => void;
}

export function useEventStream(
  options: UseEventStreamOptions = {}
): UseEventStreamResult {
  const { enabled = true, maxEvents = MAX_EVENTS } = options;
  const [events, setEvents] = useState<WrapEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  useEffect(() => {
    if (!enabled) {
      return;
    }

    const connect = () => {
      try {
        // Use the same host but with WebSocket protocol
        const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        // Connect to the Rust API backend (port 3001)
        const wsUrl = `${wsProtocol}//localhost:3001/api/events/stream`;

        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          setIsConnected(true);
          setError(null);
          console.log("WebSocket connected to event stream");
        };

        ws.onmessage = (event) => {
          try {
            const wrapEvent: WrapEvent = JSON.parse(event.data);
            setEvents((prev) => {
              // Add to front, limit size
              const updated = [wrapEvent, ...prev];
              if (updated.length > maxEvents) {
                return updated.slice(0, maxEvents);
              }
              return updated;
            });
          } catch (e) {
            console.error("Failed to parse event:", e);
          }
        };

        ws.onerror = (e) => {
          console.error("WebSocket error:", e);
          setError("Connection error");
        };

        ws.onclose = () => {
          setIsConnected(false);
          wsRef.current = null;

          // Attempt to reconnect after 3 seconds
          reconnectTimeoutRef.current = setTimeout(() => {
            console.log("Attempting to reconnect...");
            connect();
          }, 3000);
        };
      } catch (e) {
        console.error("Failed to connect:", e);
        setError("Failed to connect");
      }
    };

    connect();

    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [enabled, maxEvents]);

  return {
    events,
    isConnected,
    error,
    clearEvents,
  };
}
