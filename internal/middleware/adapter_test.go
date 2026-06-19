package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yknothing/AegisLLM/internal/server"
)

func TestAdapterFailsClosedWhenProviderTypeMissing(t *testing.T) {
	ctx := &server.RequestContext{
		Request:    httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o","messages":[]}`)),
		ProviderID: "openai-main",
		Model:      "gpt-4o",
	}

	calledNext := false
	Adapter(NewAdapterRegistry(), map[string]string{}, 1024)(ctx, func() {
		calledNext = true
	})

	if calledNext {
		t.Fatal("Adapter called next with a missing provider type mapping")
	}
	if !ctx.IsAborted() {
		t.Fatal("Adapter did not fail closed for a missing provider type mapping")
	}
	if ctx.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", ctx.StatusCode, http.StatusInternalServerError)
	}
}

func TestAdapterPassesThroughKnownOpenAIProviderType(t *testing.T) {
	ctx := &server.RequestContext{
		Request:    httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o","messages":[]}`)),
		ProviderID: "openai-main",
		Model:      "gpt-4o",
	}

	calledNext := false
	Adapter(NewAdapterRegistry(), map[string]string{"openai-main": "openai"}, 1024)(ctx, func() {
		calledNext = true
	})

	if !calledNext {
		t.Fatal("Adapter did not call next for a known provider type mapping")
	}
	if ctx.IsAborted() {
		t.Fatal("Adapter aborted a known provider type mapping")
	}
	if ctx.ProviderType != "openai" {
		t.Fatalf("provider type = %q, want openai", ctx.ProviderType)
	}
	if ctx.TargetPath != "/v1/chat/completions" {
		t.Fatalf("target path = %q, want /v1/chat/completions", ctx.TargetPath)
	}
}
