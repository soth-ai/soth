package soth

import (
	"context"
	"errors"
	"testing"
)

// minimalConfig — used by every test below to satisfy the required
// fields without spinning up real cloud / HMAC infrastructure.
func minimalConfig() Config {
	return Config{
		APIKey:        "sk-test",
		OrgID:         "org-test",
		HmacKeyStatic: make([]byte, 32),
		WasmBytes:     []byte("placeholder-wasm-not-actually-loaded-in-stub-phase"),
	}
}

func TestInitRequiresAllRequiredFields(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{"missing api_key", func(c *Config) { c.APIKey = "" }},
		{"missing org_id", func(c *Config) { c.OrgID = "" }},
		{"missing hmac key", func(c *Config) { c.HmacKeyStatic = nil; c.HmacKeyEnv = "" }},
		{"missing wasm bytes", func(c *Config) { c.WasmBytes = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := minimalConfig()
			tc.mut(&cfg)
			if _, err := Init(ctx, cfg); err == nil {
				t.Fatalf("Init succeeded but expected error for %q", tc.name)
			}
		})
	}
}

func TestInitSucceedsWithFullConfig(t *testing.T) {
	ctx := context.Background()
	sdk, err := Init(ctx, minimalConfig())
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if sdk == nil {
		t.Fatal("Init returned nil SDK")
	}
	defer sdk.Shutdown(ctx)
}

func TestGuardAllowsAndInvokesCallback(t *testing.T) {
	ctx := context.Background()
	sdk, err := Init(ctx, minimalConfig())
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer sdk.Shutdown(ctx)

	called := false
	err = sdk.Guard(ctx,
		LlmCall{
			Provider: "openai",
			Model:    "gpt-4o-mini",
			Messages: []Message{{Role: "user", Content: "hello"}},
		},
		func() error {
			called = true
			return nil
		},
	)
	if err != nil {
		t.Fatalf("Guard returned error: %v", err)
	}
	if !called {
		t.Fatal("Guard did not invoke the callback (Phase-4 stub returns Allow)")
	}
}

func TestSothBlockedSatisfiesErrorInterface(t *testing.T) {
	// Sanity: SothBlocked must be returnable through the standard
	// error interface so customers' retry logic can branch on it.
	var err error = SothBlocked{
		DecisionID: "test-123",
		Reason:     BlockReason{Kind: "sensitive_artifact"},
	}
	if !errors.Is(err, err) {
		t.Fatal("SothBlocked failed errors.Is identity check")
	}

	var asBlocked SothBlocked
	if !errors.As(err, &asBlocked) {
		t.Fatal("errors.As failed to unwrap SothBlocked")
	}
	if asBlocked.DecisionID != "test-123" {
		t.Fatalf("decision_id round-trip: got %q", asBlocked.DecisionID)
	}
}

func TestShutdownIsIdempotent(t *testing.T) {
	ctx := context.Background()
	sdk, _ := Init(ctx, minimalConfig())
	sdk.Shutdown(ctx)
	sdk.Shutdown(ctx) // must not panic
}
