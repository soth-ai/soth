import { buildApiUrl } from "@/lib/endpoints";
import type { ApiResponse } from "@/types";

export type EventPayloadPart = "request" | "response" | "content";

interface EventPayloadData {
  event_id: string;
  part: string;
  content: string;
}

const payloadCache = new Map<string, string>();
const inFlightFetches = new Map<string, Promise<string>>();

function payloadKey(eventId: string, part: EventPayloadPart): string {
  return `${eventId}:${part}`;
}

export async function fetchEventPayload(
  eventId: string,
  part: EventPayloadPart
): Promise<string> {
  const key = payloadKey(eventId, part);

  const cached = payloadCache.get(key);
  if (cached !== undefined) {
    return cached;
  }

  const existingRequest = inFlightFetches.get(key);
  if (existingRequest) {
    return existingRequest;
  }

  const request = (async () => {
    const response = await fetch(
      buildApiUrl(`/events/${encodeURIComponent(eventId)}/payload?part=${part}`),
      { cache: "no-store" }
    );

    if (!response.ok) {
      throw new Error(`Failed to fetch event payload: HTTP ${response.status}`);
    }

    const payload = (await response.json()) as ApiResponse<EventPayloadData>;
    const content = payload.data.content || "";
    payloadCache.set(key, content);
    return content;
  })();

  inFlightFetches.set(key, request);
  try {
    return await request;
  } finally {
    inFlightFetches.delete(key);
  }
}
