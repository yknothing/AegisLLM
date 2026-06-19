package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yknothing/AegisLLM/internal/server"
)

func TestRateLimiterFailsClosedForTPMClaims(t *testing.T) {
	ctx := &server.RequestContext{
		Request:      httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
		VirtualKeyID: "vk_test",
		MaxTPM:       1000,
	}

	calledNext := false
	RateLimiter(RateLimitConfig{
		Backend:        "memory",
		DefaultRPM:     0,
		DefaultTPM:     0,
		DefaultMaxConc: 0,
	})(ctx, func() {
		calledNext = true
	})

	if calledNext {
		t.Fatal("RateLimiter called next for an unsupported TPM claim")
	}
	if !ctx.IsAborted() {
		t.Fatal("RateLimiter did not fail closed for an unsupported TPM claim")
	}
	if ctx.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", ctx.StatusCode, http.StatusServiceUnavailable)
	}
}

func TestRateLimiterFailsClosedForUnsupportedBackend(t *testing.T) {
	ctx := &server.RequestContext{
		Request:      httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
		VirtualKeyID: "vk_test",
	}

	calledNext := false
	RateLimiter(RateLimitConfig{
		Backend: "memcached",
	})(ctx, func() {
		calledNext = true
	})

	if calledNext {
		t.Fatal("RateLimiter called next for an unsupported backend")
	}
	if !ctx.IsAborted() {
		t.Fatal("RateLimiter did not fail closed for an unsupported backend")
	}
	if ctx.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", ctx.StatusCode, http.StatusServiceUnavailable)
	}
}
