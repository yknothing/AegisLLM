package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yknothing/AegisLLM/internal/server"
)

func TestResolveKeyIDUsesPoolMapping(t *testing.T) {
	ctx := &server.RequestContext{
		ProviderID: "openai-main",
		KeySource:  KeySourcePool,
	}

	got := resolveKeyID(ctx, map[string]string{"openai-main": "pool-openai-key"})
	if got != "pool-openai-key" {
		t.Fatalf("key ID = %q, want pool-openai-key", got)
	}
}

func TestResolveKeyIDRejectsBYOKSource(t *testing.T) {
	ctx := &server.RequestContext{
		ProviderID: "openai-main",
		KeySource:  keySourceBYOK,
		BYOKKeyID:  "user-456-openai",
	}

	got := resolveKeyID(ctx, map[string]string{"openai-main": "pool-openai-key"})
	if got != "" {
		t.Fatalf("key ID = %q, want empty for reserved BYOK source", got)
	}
}

func TestResolveKeyIDRejectsMissingKeySource(t *testing.T) {
	ctx := &server.RequestContext{ProviderID: "openai-main"}

	got := resolveKeyID(ctx, map[string]string{"openai-main": "pool-openai-key"})
	if got != "" {
		t.Fatalf("key ID = %q, want empty for missing key source", got)
	}
}

func TestKMSInjectorFailsClosedWhenProviderMissing(t *testing.T) {
	ctx := &server.RequestContext{
		Writer:     httptest.NewRecorder(),
		Request:    httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
		ProviderID: "openai-main",
		KeySource:  KeySourcePool,
	}

	calledNext := false
	KMSInjector(KMSMiddlewareConfig{
		PoolKeyMapping: map[string]string{"openai-main": "pool-openai-key"},
	})(ctx, func() {
		calledNext = true
	})

	if calledNext {
		t.Fatal("KMSInjector called next without a KMS provider")
	}
	if !ctx.IsAborted() {
		t.Fatal("KMSInjector did not abort when KMS provider was missing")
	}
	if ctx.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", ctx.StatusCode, http.StatusServiceUnavailable)
	}
}
