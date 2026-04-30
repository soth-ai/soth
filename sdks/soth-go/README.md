# soth-go

Go SDK for SOTH — observability + policy enforcement for LLM API calls.

Loads the same `soth-sdk-core` WASM artifact the edge SDK uses, via
[wazero](https://github.com/tetratelabs/wazero). **No cgo** — Go's
static-binary, alpine-Linux, and cross-compile stories all stay
intact.

## Status

**Phase 4 scaffold.** This commit lands:
- `go.mod` / package skeleton
- Public API surface (`Init`, `Guard`, `Shutdown`, `SothBlocked`)
  matching the Python/Node bindings
- `wazero` dependency and a `wasmBridge` placeholder
- 4 unit tests covering the API contract + error semantics

What's NOT in this commit (next-PR work):
- The extern "C" exports on `soth-sdk-core` that wazero invokes
  (`__soth_init`, `__soth_pre_call`, etc.). Until those land, the
  bridge methods short-circuit with stubbed Allow decisions so the
  Go API contract can stabilize.
- WASM loading via wazero (the runtime/module is constructed, but
  no functions are called)
- Streaming round-trip (the API surface is reserved but not wired)
- Auto-instrumentation for Go SDKs that wrap LLM calls
  (e.g. `go-openai`)

The customer-facing API surface is **frozen** at this scaffold — only
internals will change in subsequent PRs.

## Why Go + wazero, not Go + cgo

cgo breaks three things Go shops care about a lot:

1. **Static binaries** — cgo binaries link against libc, breaking
   distroless / scratch container images
2. **alpine** — cgo + musl is fragile; alpine-based deploys fail
3. **Cross-compile** — `GOOS=linux GOARCH=arm64 go build` works for
   pure Go; cgo requires a target-arch C toolchain

Wazero is a pure-Go WASM runtime. The same `soth_sdk_core.wasm`
artifact `@soth/sdk-edge` loads in V8 isolates, this SDK loads via
wazero. One source of truth in Rust; no toolchain divergence.

Performance: the wazero authors benchmark WASM execution at 5-50%
slower than native, depending on workload. For SOTH's
synchronous block-decision path (≤5 ms p99 budget per the Decision
API spec), this is comfortably within budget.

## Usage (once Phase-4 follow-up lands)

```go
import (
    "context"
    _ "embed"

    "github.com/labterminal/soth/sdks/soth-go/soth"
)

//go:embed soth_sdk_core.wasm
var sothWasm []byte

func main() {
    ctx := context.Background()
    sdk, err := soth.Init(ctx, soth.Config{
        APIKey:            os.Getenv("SOTH_API_KEY"),
        OrgID:             os.Getenv("SOTH_ORG_ID"),
        HmacKeyEnv:        "SOTH_HMAC_KEY",
        TelemetryEndpoint: "https://api.soth.cloud/v1/edge/telemetry/batch",
        WasmBytes:         sothWasm,
    })
    if err != nil {
        log.Fatalf("soth.Init: %v", err)
    }
    defer sdk.Shutdown(ctx)

    err = sdk.Guard(ctx,
        soth.LlmCall{
            Provider: "openai",
            Model:    "gpt-4o-mini",
            Messages: []soth.Message{{Role: "user", Content: "hello"}},
        },
        func() error {
            // Customer's existing OpenAI call here.
            return nil
        },
    )
    var blocked soth.SothBlocked
    if errors.As(err, &blocked) {
        log.Printf("soth blocked: %s", blocked.Reason.Kind)
    } else if err != nil {
        log.Fatalf("Guard: %v", err)
    }
}
```

## Building the WASM artifact

The Go SDK consumes a WASM blob built from `soth-sdk-core`:

```sh
cargo build -p soth-sdk-core --target wasm32-unknown-unknown --release --no-default-features
# binary lands at target/wasm32-unknown-unknown/release/soth_sdk_core.wasm
```

Customers `//go:embed` the WASM into their binary, so cross-compile
still produces a single static binary that includes the SDK.

## Running the tests

```sh
cd sdks/soth-go
go test ./...
```

The tests don't require the WASM artifact to be built — they
exercise the Go API surface against the bridge stubs. Real
end-to-end tests against a built WASM artifact land alongside the
extern "C" exports on `soth-sdk-core`.

## Phase 4 follow-ups

1. **wasm-bindgen / extern "C" exports on soth-sdk-core.** This is the
   single biggest gap. Decide between:
   - `wasm-bindgen` (best for browser/JS hosts; abi is JS-shaped)
   - Plain `extern "C"` with manual marshalling (cleaner for wazero)
   - The Component Model (future-proof but ecosystem still young)
2. **Auto-instrumentation for go-openai / sashabaranov-openai.** The
   net/http middleware pattern works well for monkey-patching the
   transport layer.
3. **Streaming round-trip.** Go's `io.Reader` -based streaming maps
   cleanly onto WASM's host function callbacks.
4. **Bundle CDN signature verification** in pure Go (Ed25519 has a
   stdlib impl; reuse the spec from `soth-bundle::verify`).
5. **Conformance harness Go lane.** Same fixtures, drives through
   `soth.Guard`.
