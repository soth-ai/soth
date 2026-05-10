"""Run Anthropic agents through the soth-py SDK auto-instrumentation.

Flow:
    soth.init(api_key, org_id, telemetry_endpoint)  # cloud shipper
    soth.instrument()                               # patch anthropic SDK
    # ... normal anthropic.Anthropic() calls now run through SOTH's
    #     pre/post lifecycle and ship telemetry to the configured
    #     ingest endpoint, which is what the dashboard reads from.
"""

from __future__ import annotations

import logging
import os
import sys
import time
import uuid

import anthropic
import soth

# Wire SOTH at the same org/api_key the local edge agent uses so the
# SDK's telemetry lands in the workspace the dashboard renders. The
# easy way is to read them from ~/.soth/soth.yaml; we keep the demo
# config-free by requiring env vars the customer pastes once.
ORG_ID = os.environ["SOTH_ORG_ID"]
SOTH_API_KEY = os.environ["SOTH_API_KEY"]
TELEMETRY_ENDPOINT = os.environ.get(
    "SOTH_TELEMETRY_ENDPOINT", "https://ingest.soth.ai/v1/edge/telemetry/batch"
)

# Unique-per-run tag so we can find these events in the dashboard.
RUN_TAG = f"soth-py-demo/{uuid.uuid4().hex[:8]}"
MODEL = "claude-haiku-4-5-20251001"


def section(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def demo_oneshot(client: anthropic.Anthropic) -> None:
    section("[1/3] one-shot")
    t0 = time.time()
    msg = client.messages.create(
        model=MODEL,
        max_tokens=128,
        metadata={"user_id": RUN_TAG},
        messages=[
            {
                "role": "user",
                "content": "In one sentence: what does an L7 forward proxy do?",
            }
        ],
    )
    dt = time.time() - t0
    text = "".join(b.text for b in msg.content if getattr(b, "type", None) == "text")
    print(f"latency={dt*1000:.0f}ms  in={msg.usage.input_tokens}  out={msg.usage.output_tokens}")
    print(text)


def demo_agent(client: anthropic.Anthropic) -> None:
    section("[2/3] agent loop with tool use")

    def calc(expr: str) -> str:
        allowed = set("0123456789+-*/.() ")
        if not expr or set(expr) - allowed:
            return f"refused: {expr!r}"
        return str(eval(expr, {"__builtins__": {}}))  # noqa: S307

    def weather(city: str) -> str:
        fake = {"sf": "62F foggy", "nyc": "48F clear", "tokyo": "55F rain"}
        return fake.get(city.lower().strip(), f"no data for {city}")

    tools = [
        {
            "name": "calculator",
            "description": "Evaluate a basic arithmetic expression.",
            "input_schema": {
                "type": "object",
                "properties": {"expression": {"type": "string"}},
                "required": ["expression"],
            },
        },
        {
            "name": "weather",
            "description": "Look up weather for sf, nyc, or tokyo.",
            "input_schema": {
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"],
            },
        },
    ]

    messages: list = [
        {
            "role": "user",
            "content": (
                "What's 47 * 19, and what's the weather in Tokyo? "
                "Then say 'done.' on its own line."
            ),
        }
    ]
    for step in range(1, 6):
        resp = client.messages.create(
            model=MODEL,
            max_tokens=512,
            tools=tools,
            metadata={"user_id": RUN_TAG},
            messages=messages,
        )
        messages.append({"role": "assistant", "content": resp.content})
        if resp.stop_reason != "tool_use":
            text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
            print(f"steps={step} stop={resp.stop_reason}")
            print(text)
            return
        tool_results = []
        for block in resp.content:
            if getattr(block, "type", None) != "tool_use":
                continue
            if block.name == "calculator":
                out = calc(block.input.get("expression", ""))
            elif block.name == "weather":
                out = weather(block.input.get("city", ""))
            else:
                out = f"unknown tool {block.name}"
            tool_results.append(
                {"type": "tool_result", "tool_use_id": block.id, "content": str(out)}
            )
        messages.append({"role": "user", "content": tool_results})
    print("hit max_steps")


def demo_stream(client: anthropic.Anthropic) -> None:
    section("[3/3] streaming")
    t0 = time.time()
    chunks = 0
    with client.messages.stream(
        model=MODEL,
        max_tokens=160,
        metadata={"user_id": RUN_TAG},
        messages=[
            {
                "role": "user",
                "content": "List 3 fun facts about TLS in numbered bullets.",
            }
        ],
    ) as stream:
        for text in stream.text_stream:
            chunks += 1
            sys.stdout.write(text)
            sys.stdout.flush()
        final = stream.get_final_message()
    dt = time.time() - t0
    print()
    print(
        f"\nchunks={chunks} latency={dt*1000:.0f}ms "
        f"in={final.usage.input_tokens} out={final.usage.output_tokens}"
    )


def main() -> int:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ANTHROPIC_API_KEY not set", file=sys.stderr)
        return 1

    # Verbose so we can see the telemetry shipper's POST results.
    logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s: %(message)s")

    print(f"run tag: {RUN_TAG}")
    print(f"telemetry endpoint: {TELEMETRY_ENDPOINT}")
    print(f"org_id: {ORG_ID}")

    soth.init(
        api_key=SOTH_API_KEY,
        org_id=ORG_ID,
        telemetry_endpoint=TELEMETRY_ENDPOINT,
    )
    state = soth.instrument(providers=["anthropic"])
    print(f"instrumentation: {state}")
    print(f"is_instrumented(anthropic) = {soth.is_instrumented('anthropic')}")

    client = anthropic.Anthropic()  # vanilla — instrumented in place

    try:
        demo_oneshot(client)
        demo_agent(client)
        demo_stream(client)
    finally:
        section("flushing telemetry…")
        # Sleep > BATCH_WINDOW (5s) so the shipper drains, then shutdown
        # forces a final flush.
        time.sleep(7)
        soth.shutdown()

    section(
        f"done — search dashboard for run tag '{RUN_TAG}' "
        f"or org_id={ORG_ID}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
