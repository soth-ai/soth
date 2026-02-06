import { useEffect, useRef, useState, useCallback } from "react";
import type { WrapEvent } from "@/types";
import { buildWsUrl } from "@/lib/endpoints";

const MAX_EVENTS = 200;

interface UseEventStreamOptions {
  enabled?: boolean;
  maxEvents?: number;
  sinceSeq?: number | null;
  onEvent?: (event: WrapEvent) => void;
}

interface UseEventStreamResult {
  events: WrapEvent[];
  isConnected: boolean;
  error: string | null;
  lastSeq: number | null;
  clearEvents: () => void;
}

export function useEventStream(
  options: UseEventStreamOptions = {}
): UseEventStreamResult {
  const { enabled = true, maxEvents = MAX_EVENTS, sinceSeq = null, onEvent } = options;
  const [events, setEvents] = useState<WrapEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastSeq, setLastSeq] = useState<number | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const sinceSeqRef = useRef<number | null>(sinceSeq);
  const onEventRef = useRef<typeof onEvent>(onEvent);

  useEffect(() => {
    sinceSeqRef.current = sinceSeq;
  }, [sinceSeq]);

  useEffect(() => {
    onEventRef.current = onEvent;
  }, [onEvent]);

  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  useEffect(() => {
    if (!enabled) {
      return;
    }

    const connect = () => {
      try {
        const params = new URLSearchParams();
        if (sinceSeqRef.current !== null) {
          params.set("since_seq", String(sinceSeqRef.current));
        }
        const query = params.toString();
        const wsUrl = `${buildWsUrl("/api/events/stream")}${query ? `?${query}` : ""}`;

        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          setIsConnected(true);
          setError(null);
          console.log("WebSocket connected to event stream");
        };

        ws.onmessage = (event) => {
          try {
            const payload = JSON.parse(event.data) as
              | { type?: string; event?: WrapEvent }
              | WrapEvent;
            const wrapEvent =
              typeof payload === "object" &&
              payload !== null &&
              "type" in payload &&
              payload.type === "event"
                ? payload.event
                : (payload as WrapEvent);

            if (!wrapEvent?.id) {
              return;
            }

            if (typeof wrapEvent.seq === "number") {
              setLastSeq((prev) => {
                const next = prev === null ? wrapEvent.seq! : Math.max(prev, wrapEvent.seq!);
                sinceSeqRef.current = next;
                return next;
              });
            }

            setEvents((prev) => {
              if (prev.some((existing) => existing.id === wrapEvent.id)) {
                return prev;
              }

              // Keep oldest -> newest ordering
              const updated = [...prev, wrapEvent];
              if (updated.length > maxEvents) {
                return updated.slice(updated.length - maxEvents);
              }

              return updated;
            });
            onEventRef.current?.(wrapEvent);
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
    lastSeq,
    clearEvents,
  };
}
