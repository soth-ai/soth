package soth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
)

// wasmBridge owns the wazero runtime and the soth-sdk-core module
// exports.
//
// Phase-4 status: scaffold. The wazero `Runtime`, `CompiledModule`, and
// per-function references are placeholders. The extern "C" exports
// on soth-sdk-core itself (the next PR's work) provide:
//
//   __soth_init(api_key_ptr, api_key_len, org_id_ptr, org_id_len,
//               hmac_ptr, hmac_len, classification_mode) -> i32
//   __soth_pre_call(call_json_ptr, call_json_len) -> result_handle
//   __soth_post_call(token_handle) -> i32
//   __soth_stream_begin(call_json_ptr, call_json_len) -> result_handle
//   __soth_stream_chunk(token_handle, sequence, delta_ptr, delta_len, ...)
//   __soth_stream_end(token_handle) -> i32
//   __soth_shutdown() -> i32
//
// Until those land, this struct's methods short-circuit with stubbed
// values that preserve the Go API contract.
type wasmBridge struct {
	wasmBytes []byte
}

func newWasmBridge(ctx context.Context, wasmBytes []byte) (*wasmBridge, error) {
	if len(wasmBytes) == 0 {
		return nil, errors.New("wasm bytes empty")
	}
	// Phase-4 follow-up: wazero.NewRuntime(ctx), CompileModule, etc.
	// Today the runtime is left nil so the stub methods above can run
	// without an actual WASM load.
	return &wasmBridge{wasmBytes: wasmBytes}, nil
}

func (b *wasmBridge) preCall(ctx context.Context, call LlmCall) (*Decision, error) {
	// Stub — Phase-4 follow-up will marshal `call` to JSON, copy into
	// the WASM linear memory, invoke __soth_pre_call, and read the
	// returned Decision back.
	return &Decision{
		Kind:  "allow",
		Token: stubToken("pre"),
	}, nil
}

func (b *wasmBridge) postCall(ctx context.Context, token string) error {
	// Stub — no-op until __soth_post_call is wired.
	_ = token
	return nil
}

func (b *wasmBridge) streamBegin(ctx context.Context, call LlmCall) (*Decision, error) {
	return &Decision{
		Kind:  "allow",
		Token: stubToken("stream"),
	}, nil
}

func (b *wasmBridge) streamChunk(ctx context.Context, token string, sequence uint32, delta string, finish string) error {
	_, _, _, _ = token, sequence, delta, finish
	return nil
}

func (b *wasmBridge) streamEnd(ctx context.Context, token string) error {
	_ = token
	return nil
}

func (b *wasmBridge) shutdown(ctx context.Context) error {
	return nil
}

func stubToken(kind string) string {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return "stub-" + kind + "-" + hex.EncodeToString(buf[:])
}
