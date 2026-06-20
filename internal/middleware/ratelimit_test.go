package middleware

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yknothing/AegisLLM/internal/config"
	"github.com/yknothing/AegisLLM/internal/server"
)

type recordingLimiter struct {
	allowDimensions []string
	concurrencyKeys []string
}

const (
	tokenRetentionTestRPM            = 60
	tokenRetentionTestMaxConcurrency = 1
	tokenRetentionTestInputTokens    = 11
	tokenRetentionTestOutputTokens   = 13
	memoryLimiterTestRPM             = 1
	memoryLimiterTestMaxConcurrency  = 1
)

func (r *recordingLimiter) Allow(_ string, dimension string, _ int, _ time.Duration) (bool, error) {
	r.allowDimensions = append(r.allowDimensions, dimension)
	return true, nil
}

func (r *recordingLimiter) AcquireConcurrency(key string, _ int) (bool, func()) {
	r.concurrencyKeys = append(r.concurrencyKeys, key)
	return true, func() {}
}

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

func TestRateLimiterDoesNotRetainTokenUsageWhileTPMReserved(t *testing.T) {
	ctx := &server.RequestContext{
		Request:      httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
		VirtualKeyID: "vk_test",
	}
	limiter := &recordingLimiter{}

	calledNext := false
	rateLimiter(RateLimitConfig{
		DefaultRPM:     tokenRetentionTestRPM,
		DefaultTPM:     0,
		DefaultMaxConc: tokenRetentionTestMaxConcurrency,
	}, limiter, nil)(ctx, func() {
		calledNext = true
		ctx.InputTokens = tokenRetentionTestInputTokens
		ctx.OutputTokens = tokenRetentionTestOutputTokens
	})

	if !calledNext {
		t.Fatal("RateLimiter did not call next for a supported RPM/concurrency request")
	}
	if ctx.IsAborted() {
		t.Fatalf("RateLimiter aborted request with status %d", ctx.StatusCode)
	}
	if len(limiter.allowDimensions) != 1 || limiter.allowDimensions[0] != "rpm" {
		t.Fatalf("allow dimensions = %v, want only rpm", limiter.allowDimensions)
	}
	if len(limiter.concurrencyKeys) != 1 || limiter.concurrencyKeys[0] != "vk_test" {
		t.Fatalf("concurrency keys = %v, want [vk_test]", limiter.concurrencyKeys)
	}
}

func TestRateLimiterEnforcesRPMWithMemoryLimiter(t *testing.T) {
	middleware := RateLimiter(RateLimitConfig{
		Backend:    "memory",
		DefaultRPM: memoryLimiterTestRPM,
	})

	firstCtx := &server.RequestContext{
		Request:      httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
		VirtualKeyID: "vk_test",
	}
	firstCalledNext := false
	middleware(firstCtx, func() {
		firstCalledNext = true
	})
	if !firstCalledNext {
		t.Fatal("RateLimiter did not call next for the first request")
	}
	if firstCtx.IsAborted() {
		t.Fatalf("first request aborted with status %d", firstCtx.StatusCode)
	}

	secondCtx := &server.RequestContext{
		Request:      httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
		VirtualKeyID: "vk_test",
	}
	secondCalledNext := false
	middleware(secondCtx, func() {
		secondCalledNext = true
	})
	if secondCalledNext {
		t.Fatal("RateLimiter called next after the memory RPM limit was exhausted")
	}
	if !secondCtx.IsAborted() {
		t.Fatal("RateLimiter did not abort the request after the memory RPM limit was exhausted")
	}
	if secondCtx.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want %d", secondCtx.StatusCode, http.StatusTooManyRequests)
	}
}

func TestRateLimiterEnforcesDefaultConcurrencyWithMemoryLimiter(t *testing.T) {
	middleware := RateLimiter(RateLimitConfig{
		Backend:        "memory",
		DefaultMaxConc: memoryLimiterTestMaxConcurrency,
	})

	firstCtx := &server.RequestContext{
		Request:      httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
		VirtualKeyID: "vk_test",
	}
	enteredFirst := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan bool, 1)

	go func() {
		middleware(firstCtx, func() {
			close(enteredFirst)
			<-releaseFirst
		})
		firstDone <- firstCtx.IsAborted()
	}()

	select {
	case <-enteredFirst:
	case firstAborted := <-firstDone:
		t.Fatalf("first request finished before holding the concurrency slot; aborted=%v status=%d", firstAborted, firstCtx.StatusCode)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the first request to hold the concurrency slot")
	}

	secondCtx := &server.RequestContext{
		Request:      httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil),
		VirtualKeyID: "vk_test",
	}
	secondCalledNext := false
	middleware(secondCtx, func() {
		secondCalledNext = true
	})
	if secondCalledNext {
		t.Fatal("RateLimiter called next after the memory concurrency limit was exhausted")
	}
	if !secondCtx.IsAborted() {
		t.Fatal("RateLimiter did not abort the request after the memory concurrency limit was exhausted")
	}
	if secondCtx.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want %d", secondCtx.StatusCode, http.StatusTooManyRequests)
	}

	close(releaseFirst)
	select {
	case firstAborted := <-firstDone:
		if firstAborted {
			t.Fatalf("first request aborted with status %d", firstCtx.StatusCode)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the first request to release the concurrency slot")
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
