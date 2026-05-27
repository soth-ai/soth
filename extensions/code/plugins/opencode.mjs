// __SOTH_CODE_MANAGED__
// soth-code plugin for OpenCode.
//
// Installed by `soth code install --target opencode` to
// ~/.config/opencode/plugins/soth-code.mjs. OpenCode loads this file
// from its plugins/ directory and calls the exported plugin object's
// hook handlers. This plugin synchronously shells out to the `soth`
// binary for each hook event, propagating Block decisions (exit
// code 2) back to OpenCode so the upcoming action is halted.
//
// `__SOTH_BIN__` is replaced with the absolute soth binary path at
// install time by the soth-code installer (extensions/code/src/
// install.rs::install_opencode).

import { execFileSync } from "child_process";

const SOTH_BIN = "__SOTH_BIN__";
const TIMEOUT_MS = 30_000;

function invokeSoth(hookType, payload) {
  try {
    execFileSync(
      SOTH_BIN,
      ["code", "hook", "--agent", "opencode", "--type", hookType],
      {
        input: JSON.stringify(payload),
        stdio: ["pipe", "pipe", "pipe"],
        timeout: TIMEOUT_MS,
      },
    );
  } catch (e) {
    // Exit code 2 → policy Block. Throw so OpenCode halts the action.
    // Other exit codes (1 = tooling error) get logged but don't
    // block — distinguish enforcement from tooling errors so plugin
    // bugs never silently bypass policy.
    if (e && e.status === 2) {
      const reason =
        (e.stderr && e.stderr.toString().trim()) || "Blocked by soth-code policy";
      throw new Error(reason);
    }
    if (e && e.status === 1) {
      console.error(`[soth-code] hook tool error: ${e.stderr?.toString()?.trim() || "unknown"}`);
    }
  }
}

export const SothCodePlugin = async ({ directory }) => ({
  // OpenCode's plugin API splits the tool-execute event into
  // `(input, output)` where `input` carries identity (sessionID,
  // tool, callID) and `output.args` carries the *mutable* tool
  // arguments — plugins can rewrite `output.args` to alter what
  // actually runs. So tool name comes from `input.tool` and tool
  // args come from `output.args`; that's correct per the upstream
  // contract, not a bug.
  //
  // Known gap: OpenCode's plugin SDK has no synchronous pre-prompt
  // hook (only `tool.execute.before/after` + `session.*` + the
  // post-action `chat.message`). Until upstream adds one, we cannot
  // enforce a Block decision on a user prompt before it reaches the
  // model — `OpenCodeAdapter::is_pre_action_hook` reflects that.
  "tool.execute.before": async (input, output) => {
    invokeSoth("tool_execute_before", {
      session_id: input.sessionID,
      tool: input.tool,
      args: output.args,
      cwd: directory,
    });
  },

  "tool.execute.after": async (input, output) => {
    try {
      invokeSoth("tool_execute_after", {
        session_id: input.sessionID,
        tool: input.tool,
        result: output,
        cwd: directory,
      });
    } catch (_) {
      // Post-action hooks never throw; soth-code's enforcement gate
      // downgrades any Block decision to Allow on post-action hooks
      // server-side, but defending in depth here too against any
      // edge case where the gate misfires.
    }
  },

  "session.created": async (input) => {
    invokeSoth("session_created", { session_id: input.sessionID });
  },

  "session.error": async (input) => {
    invokeSoth("session_error", {
      session_id: input.sessionID,
      error: input.error?.toString?.() ?? null,
    });
  },

  "session.idle": async (input) => {
    invokeSoth("session_idle", { session_id: input.sessionID });
  },
});

// OpenCode's plugin loader expects a default export named
// `plugin` or matching the file pattern. Re-export under both names
// so older and newer OpenCode versions both pick it up.
export default SothCodePlugin;
