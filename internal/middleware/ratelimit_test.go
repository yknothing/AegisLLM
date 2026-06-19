package middleware

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yknothing/AegisLLM/internal/config"
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
	backend := `bad","leak":"secret`
	ctx := &server.RequestContext{
		Request:      httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
		VirtualKeyID: "vk_test",
	}

	calledNext := false
	RateLimiter(RateLimitConfig{
		Backend: backend,
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

	pipeline, err := server.NewPipeline(&config.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewPipeline error = %v", err)
	}
	pipeline.Use(RateLimiter(RateLimitConfig{Backend: backend}))

	recorder := httptest.NewRecorder()
	pipeline.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("pipeline status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	body := recorder.Body.Bytes()
	var got struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("rate limit body is invalid JSON: %v", err)
	}
	if got.Error.Message != "rate limit service unavailable" {
		t.Fatalf("message = %q, want generic unavailable message", got.Error.Message)
	}
	if strings.Contains(string(body), backend) || strings.Contains(string(body), "secret") {
		t.Fatalf("rate limit body leaked backend details: %s", body)
	}
}
