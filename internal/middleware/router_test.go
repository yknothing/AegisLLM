package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yknothing/AegisLLM/internal/server"
)

const (
	routerTestBodyLimit          int64 = 1024
	routerTestOpenAIProviderID         = "openai-primary"
	routerTestFallbackProviderID       = "deepseek-fallback"
	routerTestModel                    = "gpt-4o"
	routerTestFallbackModel            = "deepseek-v3"
	routerTestPoolKeyID                = "openai-key-1"
	routerTestFallbackKeyID            = "deepseek-key-1"
	routerTestPrimaryWeight            = 10
	routerTestFallbackWeight           = 5
	routerTestPrimaryPriority          = 1
	routerTestFallbackPriority         = 2
)

func TestRouterSelectsPermittedProviderAndPreservesBody(t *testing.T) {
	body := `{"model":"gpt-4o","stream":true,"messages":[]}`
	ctx := routerTestContext(body, []string{routerTestModel})

	calledNext := false
	Router(routerTestConfig())(ctx, func() {
		calledNext = true
		if ctx.ProviderID != routerTestOpenAIProviderID {
			t.Fatalf("provider ID = %q, want %s", ctx.ProviderID, routerTestOpenAIProviderID)
		}
		if ctx.ProviderAPIKeyID != routerTestPoolKeyID {
			t.Fatalf("provider API key ID = %q, want %s", ctx.ProviderAPIKeyID, routerTestPoolKeyID)
		}
		if ctx.Model != routerTestModel {
			t.Fatalf("model = %q, want %s", ctx.Model, routerTestModel)
		}
		if !ctx.IsStreaming {
			t.Fatal("streaming flag = false, want true")
		}
		if ctx.Request.ContentLength != int64(len(body)) {
			t.Fatalf("content length = %d, want %d", ctx.Request.ContentLength, len(body))
		}
		preservedBody, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			t.Fatalf("ReadAll returned error: %v", err)
		}
		if string(preservedBody) != body {
			t.Fatalf("body = %q, want %q", preservedBody, body)
		}
	})

	if !calledNext {
		t.Fatal("Router did not call next for a permitted model")
	}
	if ctx.IsAborted() {
		t.Fatalf("Router aborted permitted model with status %d", ctx.StatusCode)
	}
}

func TestRouterRejectsUnpermittedModelBeforeProviderSelection(t *testing.T) {
	ctx := routerTestContext(`{"model":"gpt-4o","messages":[]}`, []string{routerTestFallbackModel})

	calledNext := false
	Router(routerTestConfig())(ctx, func() {
		calledNext = true
	})

	if calledNext {
		t.Fatal("Router called next for an unpermitted model")
	}
	if !ctx.IsAborted() {
		t.Fatal("Router did not abort an unpermitted model")
	}
	if ctx.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", ctx.StatusCode, http.StatusForbidden)
	}
	if ctx.ProviderID != "" || ctx.ProviderAPIKeyID != "" {
		t.Fatalf("provider selected on forbidden request: provider=%q key=%q", ctx.ProviderID, ctx.ProviderAPIKeyID)
	}
}

func TestRouterWildcardPermissionAllowsKnownModel(t *testing.T) {
	ctx := routerTestContext(`{"model":"gpt-4o","messages":[]}`, []string{"*"})

	calledNext := false
	Router(routerTestConfig())(ctx, func() {
		calledNext = true
		if ctx.ProviderID != routerTestOpenAIProviderID {
			t.Fatalf("provider ID = %q, want %s", ctx.ProviderID, routerTestOpenAIProviderID)
		}
		if ctx.ProviderAPIKeyID != routerTestPoolKeyID {
			t.Fatalf("provider API key ID = %q, want %s", ctx.ProviderAPIKeyID, routerTestPoolKeyID)
		}
		if ctx.Model != routerTestModel {
			t.Fatalf("model = %q, want %s", ctx.Model, routerTestModel)
		}
	})

	if !calledNext {
		t.Fatal("Router did not call next for a wildcard-permitted model")
	}
	if ctx.IsAborted() {
		t.Fatalf("Router aborted wildcard-permitted model with status %d", ctx.StatusCode)
	}
}

func TestRouterRejectsMissingModel(t *testing.T) {
	ctx := routerTestContext(`{"messages":[]}`, []string{"*"})

	calledNext := false
	Router(routerTestConfig())(ctx, func() {
		calledNext = true
	})

	if calledNext {
		t.Fatal("Router called next without a model")
	}
	if !ctx.IsAborted() {
		t.Fatal("Router did not abort missing model")
	}
	if ctx.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", ctx.StatusCode, http.StatusBadRequest)
	}
}

func TestRouterReturnsUnavailableWhenNoProviderSupportsPermittedModel(t *testing.T) {
	ctx := routerTestContext(`{"model":"unknown-model","messages":[]}`, []string{"unknown-model"})

	calledNext := false
	Router(routerTestConfig())(ctx, func() {
		calledNext = true
	})

	if calledNext {
		t.Fatal("Router called next without an available provider")
	}
	if !ctx.IsAborted() {
		t.Fatal("Router did not abort unsupported provider model")
	}
	if ctx.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", ctx.StatusCode, http.StatusServiceUnavailable)
	}
}

func TestRouterEnforcesBodyLimit(t *testing.T) {
	ctx := routerTestContext(strings.Repeat("x", int(routerTestBodyLimit)+1), []string{"*"})

	calledNext := false
	Router(routerTestConfig())(ctx, func() {
		calledNext = true
	})

	if calledNext {
		t.Fatal("Router called next for oversized body")
	}
	if !ctx.IsAborted() {
		t.Fatal("Router did not abort oversized body")
	}
	if ctx.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", ctx.StatusCode, http.StatusRequestEntityTooLarge)
	}
}

func routerTestContext(body string, permissions []string) *server.RequestContext {
	return &server.RequestContext{
		Request:     httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body)),
		Permissions: permissions,
	}
}

func routerTestConfig() RouterConfig {
	return RouterConfig{
		MaxRequestBodySize: routerTestBodyLimit,
		Channels: []ProviderChannel{
			{
				ID:       routerTestOpenAIProviderID,
				Name:     "OpenAI Primary",
				Type:     "openai",
				BaseURL:  "https://api.openai.com",
				KeyID:    routerTestPoolKeyID,
				Models:   []string{routerTestModel},
				Weight:   routerTestPrimaryWeight,
				Priority: routerTestPrimaryPriority,
				Enabled:  true,
			},
			{
				ID:       routerTestFallbackProviderID,
				Name:     "DeepSeek Fallback",
				Type:     "deepseek",
				BaseURL:  "https://api.deepseek.com",
				KeyID:    routerTestFallbackKeyID,
				Models:   []string{routerTestFallbackModel},
				Weight:   routerTestFallbackWeight,
				Priority: routerTestFallbackPriority,
				Enabled:  true,
			},
		},
	}
}
