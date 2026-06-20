package middleware

import (
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
