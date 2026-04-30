// Package soth is the Go SDK for SOTH — observability + policy
// enforcement for LLM API calls.
//
// Status: Phase 4 scaffold. The Go API surface mirrors the native
// Python and Node bindings (Init / Guard / GuardStream / Context /
// Shutdown); the WASM bridge to soth-sdk-core via wazero is the
// next PR's work. Today the package compiles, the API shape is
// stable, and the wazero scaffolding is in place — but the actual
// extern "C" exports on soth-sdk-core haven't been wired yet, so
// Pre-call decisions are all Allow stubs.
//
// See README.md for the full integration model and the current set
// of "what's stubbed" markers.
//
// # Why Go via WASM (not cgo)
//
// Cgo destroys Go's static-binary, alpine-Linux, and cross-compile
// stories — three things Go shops care about a lot. Wazero is a
// pure-Go WASM runtime that loads the same soth-sdk-core.wasm
// artifact the edge SDK loads. One source of truth, no cgo,
// preserved cross-compile.
package soth

import (
	"context"
	"errors"
	"fmt"
	"sync"

	_ "github.com/tetratelabs/wazero"
)

// Config configures a SOTH SDK instance.
type Config struct {
	APIKey            string
	OrgID             string
	HmacKeyEnv        string
	HmacKeyStatic     []byte
	TelemetryEndpoint string
	WasmBytes         []byte
}

// LlmCall describes the customer's LLM request to the SDK. Mirrors the
// `LlmCall` shape from soth-sdk-core / the Python and Node bindings.
type LlmCall struct {
	Provider string    `json:"provider"`
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	System   string    `json:"system,omitempty"`
	Tools    []Tool    `json:"tools,omitempty"`
	Stream   bool      `json:"stream"`
}

// Message is a single conversation turn.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Tool describes a function-call definition exposed to the model.
type Tool struct {
	Name           string `json:"name"`
	Description    string `json:"description,omitempty"`
	ParametersJSON string `json:"parameters_json,omitempty"`
}

// Decision is the SDK's per-call enforcement output.
//
// Customers branch on Kind. Block decisions raise SothBlocked from
// Guard; Allow / Flag / Redact proceed to the wrapped call.
type Decision struct {
	Kind   string       `json:"kind"`
	Token  string       `json:"token"`
	Reason *BlockReason `json:"reason,omitempty"`
}

// BlockReason carries why a Block fired. Mirrors BlockReason from the
// Decision API spec; customer code can branch on Kind for graceful
// degradation (e.g. retry-with-alternative when Kind == "use_alternative").
type BlockReason struct {
	Kind              string `json:"kind"`
	Artifact          string `json:"artifact,omitempty"`
	Severity          string `json:"severity,omitempty"`
	RuleID            string `json:"rule_id,omitempty"`
	RuleName          string `json:"rule_name,omitempty"`
	SuggestedProvider string `json:"suggested_provider,omitempty"`
	SuggestedModel    string `json:"suggested_model,omitempty"`
}

// SothBlocked is returned by Guard when SOTH policy blocks a call.
// It satisfies error so customer retry-on-error logic can branch on
// errors.Is(err, soth.SothBlocked{}). Per the Decision API spec,
// SothBlocked must NOT be considered a provider API error.
type SothBlocked struct {
	DecisionID string
	Reason     BlockReason
}

// Error implements error.
func (e SothBlocked) Error() string {
	return fmt.Sprintf("SOTH policy blocked call: %s", e.Reason.Kind)
}

// SDK is a SOTH SDK instance. Construct via Init.
type SDK struct {
	cfg Config
	mu  sync.Mutex
	// Phase-4 follow-up: hold the wazero runtime + module + exported
	// function references here. Today the field is a placeholder so
	// the rest of the API can have a sensible receiver.
	bridge *wasmBridge
}

// Init constructs a new SDK instance, loading the soth-sdk-core WASM
// from cfg.WasmBytes via wazero.
//
// Phase-4 status: returns a stub SDK that responds Allow to every
// pre-call. The wazero load + extern "C" call wiring is the next PR.
func Init(ctx context.Context, cfg Config) (*SDK, error) {
	if cfg.APIKey == "" {
		return nil, errors.New("soth.Init: Config.APIKey required")
	}
	if cfg.OrgID == "" {
		return nil, errors.New("soth.Init: Config.OrgID required")
	}
	if len(cfg.HmacKeyStatic) == 0 && cfg.HmacKeyEnv == "" {
		return nil, errors.New("soth.Init: Config.HmacKeyStatic or HmacKeyEnv required")
	}
	if len(cfg.WasmBytes) == 0 {
		return nil, errors.New("soth.Init: Config.WasmBytes required (load soth_sdk_core.wasm)")
	}
	bridge, err := newWasmBridge(ctx, cfg.WasmBytes)
	if err != nil {
		return nil, fmt.Errorf("soth.Init: %w", err)
	}
	return &SDK{cfg: cfg, bridge: bridge}, nil
}

// Guard wraps an LLM call with SOTH's pre/post lifecycle. Block
// decisions return a SothBlocked error; Allow / Flag / Redact proceed
// to invoke fn.
//
// Phase-4 status: stubbed Allow. Customer's fn always runs.
func (s *SDK) Guard(ctx context.Context, call LlmCall, fn func() error) error {
	if s == nil || s.bridge == nil {
		return errors.New("soth.Guard: SDK not initialized")
	}
	decision, err := s.bridge.preCall(ctx, call)
	if err != nil {
		return fmt.Errorf("soth.Guard: pre_call: %w", err)
	}
	if decision.Kind == "block" {
		_ = s.bridge.postCall(ctx, decision.Token)
		var reason BlockReason
		if decision.Reason != nil {
			reason = *decision.Reason
		}
		return SothBlocked{DecisionID: decision.Token, Reason: reason}
	}
	defer func() {
		_ = s.bridge.postCall(ctx, decision.Token)
	}()
	return fn()
}

// Shutdown stops the background telemetry shipper (if running) and
// frees the wazero runtime. Idempotent.
func (s *SDK) Shutdown(ctx context.Context) {
	if s == nil || s.bridge == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.bridge.shutdown(ctx)
	s.bridge = nil
}
