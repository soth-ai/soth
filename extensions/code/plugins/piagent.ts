// __SOTH_CODE_MANAGED__
// soth-code plugin for Pi Agent.
//
// Installed by `soth code install --target pi_agent` to
// ~/.pi/agent/extensions/soth-code.ts. Pi Agent loads this file via
// its extensions API and dispatches hook callbacks to the exported
// default function. This plugin synchronously shells out to the
// `soth` binary for each hook event, propagating Block decisions
// (exit code 2) back to Pi Agent so the upcoming action is halted.
//
// Architectural choice (gryph PR #20 / #22 lessons):
//   - spawnSync, not spawn — fire-and-forget would silently bypass
//     policy enforcement.
//   - Hard 30s timeout — anything longer freezes the agent UX.
//   - Block via { block: true, reason } return shape, not via
//     thrown exception — Pi Agent's handler treats throws as
//     plugin errors, not as policy decisions.
//
// `__SOTH_BIN__` is replaced with the absolute soth binary path at
// install time by the soth-code installer (extensions/code/src/
// install.rs::install_pi_agent).

import { spawnSync } from "node:child_process";

const SOTH_BIN = "__SOTH_BIN__";
const TIMEOUT_MS = 30_000;

function callSoth(
  hookType: string,
  payload: Record<string, unknown>,
): { exitCode: number; stderr: string } {
  const result = spawnSync(
    SOTH_BIN,
    ["code", "hook", "--agent", "pi_agent", "--type", hookType],
    {
      input: JSON.stringify(payload),
      encoding: "utf8",
      timeout: TIMEOUT_MS,
    },
  );
  return {
    exitCode: result.status ?? 1,
    stderr: typeof result.stderr === "string" ? result.stderr : "",
  };
}

interface PiCtx {
  sessionManager?: { getSessionFile?: () => string | null };
  cwd?: string;
}

interface PiToolEvent {
  toolName?: string;
  toolCallId?: string;
  input?: unknown;
  output?: unknown;
}

interface PiPromptEvent {
  prompt?: string;
}

function sessionId(ctx: PiCtx): string {
  return ctx.sessionManager?.getSessionFile?.() ?? "ephemeral";
}

// Pi Agent's plugin API. Typed loosely (`any`) since the upstream
// types aren't shipped in a public package — keep the surface
// flexible for protocol evolution.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export default function plugin(pi: any) {
  pi.on("session_start", (_event: unknown, ctx: PiCtx) => {
    callSoth("session_start", { session_id: sessionId(ctx), cwd: ctx.cwd });
  });

  pi.on("session_shutdown", (_event: unknown, ctx: PiCtx) => {
    callSoth("session_end", { session_id: sessionId(ctx), cwd: ctx.cwd });
  });

  pi.on("user_prompt_submit", (event: PiPromptEvent, ctx: PiCtx) => {
    const r = callSoth("user_prompt_submit", {
      session_id: sessionId(ctx),
      cwd: ctx.cwd,
      prompt: event.prompt,
    });
    if (r.exitCode === 2) {
      return {
        block: true,
        reason: r.stderr.trim() || "Blocked by soth-code policy",
      };
    }
  });

  pi.on("tool_call", (event: PiToolEvent, ctx: PiCtx) => {
    const r = callSoth("pre_tool_use", {
      session_id: sessionId(ctx),
      cwd: ctx.cwd,
      tool_name: event.toolName,
      tool_call_id: event.toolCallId,
      input: event.input,
    });
    if (r.exitCode === 2) {
      return {
        block: true,
        reason: r.stderr.trim() || "Blocked by soth-code policy",
      };
    }
  });

  pi.on("tool_result", (event: PiToolEvent, ctx: PiCtx) => {
    callSoth("post_tool_use", {
      session_id: sessionId(ctx),
      cwd: ctx.cwd,
      tool_name: event.toolName,
      tool_call_id: event.toolCallId,
      output: event.output,
    });
  });
}
