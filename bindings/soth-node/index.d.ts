// Type declarations for @soth/sdk.

export interface InitOptions {
  apiKey: string;
  orgId: string;
  /**
   * Read the HMAC key from this environment variable. The SDK never
   * sees the plaintext over the wire; soth-cloud never has the key.
   * See SDK_WASM_TRUST_BOUNDARY_SPEC.md §6.6.
   */
  hmacKeyEnv?: string;
  hmacKeyStatic?: Buffer;
}

export interface Message {
  role: string;
  content: string;
}

export interface Tool {
  name: string;
  description?: string;
  parametersJson?: string;
}

export interface LlmCall {
  provider: string;
  model: string;
  messages: Message[];
  system?: string;
  tools?: Tool[];
  stream?: boolean;
}

export interface BlockReason {
  /** "sensitive_artifact" | "budget_exceeded" | "policy_rule" | "use_alternative" */
  kind: string;
  artifact?: string;
  severity?: string;
  budgetKind?: string;
  observed?: number;
  limit?: number;
  ruleId?: string;
  ruleName?: string;
  suggestedProvider?: string;
  suggestedModel?: string;
}

export class SothBlocked extends Error {
  decisionId: string;
  reason: BlockReason;
}

export class SothFlagged {
  severity: string;
}

export interface GuardOptions {
  call: LlmCall;
}

export function init(options: InitOptions): void;
export function guard<T>(callFn: () => Promise<T>, options: GuardOptions): Promise<T>;
export function getSdk(): unknown;
