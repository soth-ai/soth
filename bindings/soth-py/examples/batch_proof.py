"""Fire 20 cheap Anthropic calls concurrently through the SDK and
print the shipper's POST lines so we can count how many HTTP requests
actually leave the box.

If batching works, 20 events should land in 1–2 POSTs (one if they
all queue inside a single 5s batch window, two if some land after
the first window fires).
"""

from __future__ import annotations

import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import anthropic
import soth

ORG_ID = os.environ["SOTH_ORG_ID"]
SOTH_API_KEY = os.environ["SOTH_API_KEY"]
TELEMETRY_ENDPOINT = os.environ.get(
    "SOTH_TELEMETRY_ENDPOINT", "https://ingest.soth.ai/v1/edge/telemetry/batch"
)
MODEL = "claude-haiku-4-5-20251001"
N_CALLS = 20


def fire(client: anthropic.Anthropic, i: int) -> int:
    msg = client.messages.create(
        model=MODEL,
        max_tokens=8,
        messages=[{"role": "user", "content": f"Reply with the number {i}, nothing else."}],
    )
    return msg.usage.output_tokens


def main() -> int:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ANTHROPIC_API_KEY not set", file=sys.stderr)
        return 1

    soth.init(api_key=SOTH_API_KEY, org_id=ORG_ID, telemetry_endpoint=TELEMETRY_ENDPOINT)
    soth.instrument(providers=["anthropic"])
    client = anthropic.Anthropic()

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=10) as ex:
        outs = list(ex.map(lambda i: fire(client, i), range(N_CALLS)))
    dt = time.time() - t0
    print(f"\n>>> fired {N_CALLS} calls in {dt:.2f}s, total output tokens: {sum(outs)}")
    print(">>> sleeping 12s to let shipper drain (BATCH_WINDOW=5s)…")
    time.sleep(12)
    soth.shutdown()
    print(">>> shutdown complete (forces final-drain POST)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
