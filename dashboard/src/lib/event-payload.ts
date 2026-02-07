import { buildApiUrl } from "@/lib/endpoints";
import type { ApiResponse } from "@/types";

export type EventPayloadPart = "request" | "response" | "content";

interface EventPayloadData {
  event_id: string;
  part: string;
  content: string;
}

export async function fetchEventPayload(
  eventId: string,
  part: EventPayloadPart
): Promise<string> {
  const response = await fetch(
    buildApiUrl(`/events/${encodeURIComponent(eventId)}/payload?part=${part}`),
    { cache: "no-store" }
  );

  if (!response.ok) {
    throw new Error(`Failed to fetch event payload: HTTP ${response.status}`);
  }

  const payload = (await response.json()) as ApiResponse<EventPayloadData>;
  return payload.data.content || "";
}
