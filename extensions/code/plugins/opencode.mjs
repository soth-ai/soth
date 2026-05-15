// __SOTH_CODE_MANAGED__
// soth-code plugin for OpenCode.
//
// Installed by `soth code install --target opencode` to
// ~/.config/opencode/plugins/soth-code.js. OpenCode loads this file
// from its plugins/ directory and calls the exported plugin object's
// hook handlers. NOTE: destination must be `.js` (not `.mjs`) — the
// OpenCode plugin loader only auto-discovers `.js` and `.ts` files;
// `.mjs` files in the plugins directory are silently skipped. This plugin synchronously shells out to the `soth`
// binary for each hook event, propagating Block decisions (exit
// code 2) back to OpenCode so the upcoming action is halted.
//
// `__SOTH_BIN__` is replaced with the absolute soth binary path at
// install time by the soth-code installer (extensions/code/src/
// install.rs::install_opencode).

import { execFileSync } from "child_process";

const SOTH_BIN = "__SOTH_BIN__";
const TIMEOUT_MS = 30_000;

// Reduce OpenCode's `input.model` / `input.provider` (which arrive as
// nested objects, not strings) to the string ids the soth pipeline
// expects. Observed shapes across hooks:
//   chat.message → model: { providerID, modelID }
//   chat.params  → model: { id, providerID, name, family, api, ... },
//                  provider: { id, source, name, env, models, ... }
// Always returns a string or null — never an object — so the Rust
// adapter's `.as_str()` succeeds.
function modelId(m) {
  if (m == null) return null;
  if (typeof m === "string") return m;
  return m.id ?? m.modelID ?? m.modelId ?? m.name ?? null;
}
function providerId(p, modelObj) {
  if (p != null) {
    if (typeof p === "string") return p;
    if (p.id) return p.id;
    if (p.name) return p.name;
  }
  if (modelObj && typeof modelObj === "object") {
    return modelObj.providerID ?? modelObj.providerId ?? null;
  }
  return null;
}

// Concatenate text from an OpenCode message/parts shape. OpenCode
// chat events carry the user's typed text as an array of parts, each
// typically `{type:"text", text:"..."}` (with other shapes mixed in
// for tool calls, files, etc.). We pull just the text parts so soth's
// classifier sees natural language, not a JSON blob.
function extractMessageText(maybeMessage, maybeParts) {
  const collected = [];
  const push = (p) => {
    if (!p) return;
    if (typeof p === "string") {
      collected.push(p);
      return;
    }
    if (typeof p.text === "string") {
      collected.push(p.text);
      return;
    }
    if (typeof p.content === "string") {
      collected.push(p.content);
    }
  };
  if (Array.isArray(maybeParts)) maybeParts.forEach(push);
  if (Array.isArray(maybeMessage?.parts)) maybeMessage.parts.forEach(push);
  if (typeof maybeMessage?.content === "string") push(maybeMessage.content);
  if (typeof maybeMessage === "string") push(maybeMessage);
  return collected.join("\n").trim();
}

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
    // block — gryph Issue #20 lesson: distinguish enforcement from
    // tooling errors.
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
      model: modelId(input?.model),
      provider: providerId(input?.provider, input?.model),
      agent: input?.agent ?? null,
      cwd: directory,
    });
  },

  "tool.execute.after": async (input, output) => {
    try {
      invokeSoth("tool_execute_after", {
        session_id: input.sessionID,
        tool: input.tool,
        result: output,
        model: modelId(input?.model),
        provider: providerId(input?.provider, input?.model),
        agent: input?.agent ?? null,
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

  // OpenCode plugin events beyond tool/session: chat turns and
  // permission gates. Shapes vary by OpenCode version; ship input and
  // output through verbatim and let the soth-side adapter pick out
  // what it needs.

  "chat.message": async (input, output) => {
    const role = input?.message?.role ?? output?.message?.role ?? null;
    const content = extractMessageText(output?.message, output?.parts);
    invokeSoth("chat_message", {
      session_id: input?.sessionID ?? null,
      model: modelId(input?.model),
      provider: providerId(input?.provider, input?.model),
      agent: input?.agent ?? null,
      role,
      content,
      input,
      output,
      cwd: directory,
    });
  },

  "chat.params": async (input, output) => {
    const content = extractMessageText(input?.message, input?.message?.parts);
    invokeSoth("chat_params", {
      session_id: input?.sessionID ?? null,
      model: modelId(input?.model),
      provider: providerId(input?.provider, input?.model),
      agent: input?.agent ?? null,
      content,
      input,
      output,
      cwd: directory,
    });
  },

  "permission.ask": async (input, output) => {
    invokeSoth("permission_ask", {
      session_id: input?.sessionID ?? null,
      model: modelId(input?.model),
      provider: providerId(input?.provider, input?.model),
      agent: input?.agent ?? null,
      input,
      output,
      cwd: directory,
    });
  },
});

// OpenCode's plugin loader expects a default export named
// `plugin` or matching the file pattern. Re-export under both names
// so older and newer OpenCode versions both pick it up.
export default SothCodePlugin;
