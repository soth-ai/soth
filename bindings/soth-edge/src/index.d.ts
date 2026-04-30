// Type declarations for @soth/sdk-edge.
//
// Mirrors the shape of @soth/sdk's index.d.ts where APIs overlap;
// edge-specific concerns (the wasmModule init parameter,
// classification mode locked to Reduced) are documented inline.

export interface InitOptions {
  apiKey: string;
  orgId: string;
  hmacKeyEnv?: string;
  hmacKeyStatic?: Uint8Array;
  telemetryEndpoint?: string;
  /**
   * Compiled WebAssembly module containing soth-sdk-core. Customer
   * loads this via their runtime's preferred mechanism:
   *   - Cloudflare Workers: `import wasm from './soth_sdk_core.wasm'`
   *   - Vercel Edge:        same wasm import
   *   - Deno:               `await WebAssembly.compileStreaming(...)`
   */
  wasmModule: WebAssembly.Module | WebAssembly.Instance;
}

export interface Message {
  role: string;
  content: string;
}

export interface LlmCall {
  provider: string;
  model: string;
  messages: Message[];
  system?: string;
  stream?: boolean;
}

export interface BlockReason {
  kind: string;
  artifact?: string;
  severity?: string;
  ruleId?: string;
  ruleName?: string;
  suggestedProvider?: string;
  suggestedModel?: string;
}

export class SothBlocked extends Error {
  decisionId: string;
  reason: BlockReason;
}

export interface GuardOptions {
  call: LlmCall;
}

export interface ChunkExtractorOutput {
  deltaContent: string | null;
  finishReason: string | null;
}

export interface GuardStreamOptions<TChunk = unknown> {
  call: LlmCall;
  chunkExtractor?: (chunk: TChunk) => ChunkExtractorOutput;
}

export function init(options: InitOptions): Promise<void>;
export function guard<T>(callFn: () => Promise<T>, options: GuardOptions): Promise<T>;
export function guardStream<TChunk = unknown>(
  iterFactory: () => AsyncIterable<TChunk> | Promise<AsyncIterable<TChunk>>,
  options: GuardStreamOptions<TChunk>,
): AsyncIterable<TChunk>;
export function shutdown(): Promise<void>;
