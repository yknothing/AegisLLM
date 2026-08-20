package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestRouterDoesNotOpenProviderCircuitForLocalGatewayFailures(t *testing.T) {
	router := Router(routerTestConfig())

	for attempt := 1; attempt <= 6; attempt++ {
		ctx := routerTestContext(`{"model":"gpt-4o","messages":[]}`, []string{routerTestModel})
		calledNext := false
		router(ctx, func() {
			calledNext = true
			ctx.StatusCode = http.StatusServiceUnavailable
		})

		if !calledNext {
			t.Fatalf("attempt %d did not reach local downstream middleware; provider circuit was polluted by a gateway-local failure", attempt)
		}
	}
}

func TestRouterOpensProviderCircuitForProviderFailures(t *testing.T) {
	router := Router(routerTestConfig())

	for attempt := 1; attempt <= 5; attempt++ {
		ctx := routerTestContext(`{"model":"gpt-4o","messages":[]}`, []string{routerTestModel})
		calledNext := false
		router(ctx, func() {
			calledNext = true
			ctx.StatusCode = http.StatusServiceUnavailable
			ctx.ProviderResponded = true
			ctx.ProviderFailure = true
		})
		if !calledNext {
			t.Fatalf("attempt %d did not reach provider", attempt)
		}
	}

	ctx := routerTestContext(`{"model":"gpt-4o","messages":[]}`, []string{routerTestModel})
	calledNext := false
	router(ctx, func() { calledNext = true })
	if calledNext {
		t.Fatal("provider request reached downstream after circuit threshold")
	}
	if ctx.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", ctx.StatusCode, http.StatusServiceUnavailable)
	}
}

func TestRouterTreatsAnyNonFailureProviderResponseAsReachable(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{name: "provider 4xx", statusCode: http.StatusBadRequest},
		{name: "client canceled after provider headers", statusCode: http.StatusBadGateway},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := Router(routerTestConfig())

			for attempt := 1; attempt <= 4; attempt++ {
				routerTestProviderFailure(t, router, attempt)
			}

			ctx := routerTestContext(`{"model":"gpt-4o","messages":[]}`, []string{routerTestModel})
			router(ctx, func() {
				ctx.StatusCode = tt.statusCode
				ctx.ProviderResponded = true
			})

			routerTestProviderFailure(t, router, 5)

			ctx = routerTestContext(`{"model":"gpt-4o","messages":[]}`, []string{routerTestModel})
			calledNext := false
			router(ctx, func() { calledNext = true })
			if !calledNext {
				t.Fatal("provider response did not reset prior failures; circuit opened after one later failure")
			}
		})
	}
}

func TestCircuitBreakerAllowsOnlyOneConcurrentHalfOpenProbe(t *testing.T) {
	const (
		trials     = 200
		contenders = 128
	)
	for trial := 1; trial <= trials; trial++ {
		cb := newCircuitBreaker()
		cb.state.Store(stateOpen)
		cb.lastFailure.Store(time.Now().Add(-time.Minute).Unix())

		start := make(chan struct{})
		results := make(chan bool, contenders)
		var ready sync.WaitGroup
		ready.Add(contenders)
		for range contenders {
			go func() {
				ready.Done()
				<-start
				_, allowed := cb.AllowProbe()
				results <- allowed
			}()
		}
		ready.Wait()
		close(start)

		allowed := 0
		for range contenders {
			if <-results {
				allowed++
			}
		}
		if allowed != 1 {
			t.Fatalf("trial %d: allowed probes = %d, want exactly 1", trial, allowed)
		}
	}
}

func TestRouterReleasesHalfOpenProbeWhenProviderWasNotReached(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{name: "local gateway failure", statusCode: http.StatusServiceUnavailable},
		{name: "client canceled before provider response", statusCode: http.StatusBadGateway},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router, cb, lastFailure := routerTestHalfOpenMiddleware(t)
			ctx := routerTestContext(`{"model":"gpt-4o","messages":[]}`, []string{routerTestModel})
			calledNext := false
			router(ctx, func() {
				calledNext = true
				ctx.StatusCode = tt.statusCode
			})

			if !calledNext {
				t.Fatal("half-open probe did not reach downstream")
			}
			routerTestAssertReleasedProbe(t, cb, lastFailure)
			routerTestAssertImmediateProbe(t, router, cb)
		})
	}
}

func TestRouterReleasesHalfOpenProbeDuringPanicUnwind(t *testing.T) {
	router, cb, lastFailure := routerTestHalfOpenMiddleware(t)
	ctx := routerTestContext(`{"model":"gpt-4o","messages":[]}`, []string{routerTestModel})
	panicMarker := &struct{}{}
	var recovered any

	func() {
		defer func() { recovered = recover() }()
		router(ctx, func() { panic(panicMarker) })
	}()

	if recovered != panicMarker {
		t.Fatalf("recovered panic = %v, want original marker", recovered)
	}
	routerTestAssertReleasedProbe(t, cb, lastFailure)
	routerTestAssertImmediateProbe(t, router, cb)
}

func TestRouterRecordsProviderSuccessDuringPanicUnwind(t *testing.T) {
	router, cb, _ := routerTestHalfOpenMiddleware(t)
	ctx := routerTestContext(`{"model":"gpt-4o","messages":[]}`, []string{routerTestModel})
	panicMarker := &struct{}{}
	var recovered any

	func() {
		defer func() { recovered = recover() }()
		router(ctx, func() {
			ctx.StatusCode = http.StatusBadRequest
			ctx.ProviderResponded = true
			panic(panicMarker)
		})
	}()

	if recovered != panicMarker {
		t.Fatalf("recovered panic = %v, want original marker", recovered)
	}
	if state := cb.state.Load(); state != stateClosed {
		t.Fatalf("breaker state = %d, want closed", state)
	}
	if failures := cb.failures.Load(); failures != 0 {
		t.Fatalf("failures = %d, want 0", failures)
	}
}

func TestRouterIgnoresLateSuccessFromEarlierCircuitGeneration(t *testing.T) {
	cfg := routerTestConfig()
	rt := newRouterTable(cfg.Channels)
	router := routerWithTable(cfg, rt)
	cb := rt.breakers[routerTestOpenAIProviderID]

	aCtx := routerTestContext(`{"model":"gpt-4o","messages":[]}`, []string{routerTestModel})
	aEntered, releaseA, aDone := routerTestStartBlockedRequest(router, aCtx, func() {
		aCtx.StatusCode = http.StatusOK
		aCtx.ProviderResponded = true
	})
	routerTestWait(t, aEntered, "request A to acquire a closed-state route")

	for attempt := 1; attempt <= 5; attempt++ {
		routerTestProviderFailure(t, router, attempt)
	}
	cb.lastFailure.Store(time.Now().Add(-2 * cb.recoveryTime).Unix())

	pCtx := routerTestContext(`{"model":"gpt-4o","messages":[]}`, []string{routerTestModel})
	pEntered, releaseP, pDone := routerTestStartBlockedRequest(router, pCtx, func() {
		pCtx.StatusCode = http.StatusServiceUnavailable
		pCtx.ProviderResponded = true
		pCtx.ProviderFailure = true
	})
	routerTestWait(t, pEntered, "request P to claim the half-open probe")

	close(releaseA)
	routerTestWait(t, aDone, "late request A to finish")
	if state := cb.state.Load(); state != stateHalfOpen {
		t.Fatalf("breaker state after stale success = %d, want half-open", state)
	}

	close(releaseP)
	routerTestWait(t, pDone, "half-open probe P to finish")
	if state := cb.state.Load(); state != stateOpen {
		t.Fatalf("breaker state after half-open failure = %d, want open", state)
	}
}

func TestRouterIgnoresLateFailureFromEarlierCircuitGeneration(t *testing.T) {
	cfg := routerTestConfig()
	rt := newRouterTable(cfg.Channels)
	router := routerWithTable(cfg, rt)
	cb := rt.breakers[routerTestOpenAIProviderID]

	aCtx := routerTestContext(`{"model":"gpt-4o","messages":[]}`, []string{routerTestModel})
	aEntered, releaseA, aDone := routerTestStartBlockedRequest(router, aCtx, func() {
		aCtx.StatusCode = http.StatusServiceUnavailable
		aCtx.ProviderResponded = true
		aCtx.ProviderFailure = true
	})
	routerTestWait(t, aEntered, "request A to acquire a closed-state route")

	for attempt := 1; attempt <= 5; attempt++ {
		routerTestProviderFailure(t, router, attempt)
	}
	cb.lastFailure.Store(time.Now().Add(-2 * cb.recoveryTime).Unix())

	pCtx := routerTestContext(`{"model":"gpt-4o","messages":[]}`, []string{routerTestModel})
	pEntered, releaseP, pDone := routerTestStartBlockedRequest(router, pCtx, func() {
		pCtx.StatusCode = http.StatusBadRequest
		pCtx.ProviderResponded = true
	})
	routerTestWait(t, pEntered, "request P to claim the half-open probe")

	close(releaseP)
	routerTestWait(t, pDone, "successful half-open probe P to finish")
	if state := cb.state.Load(); state != stateClosed {
		t.Fatalf("breaker state after half-open success = %d, want closed", state)
	}
	lastFailure := cb.lastFailure.Load()

	close(releaseA)
	routerTestWait(t, aDone, "late request A to finish")
	if state := cb.state.Load(); state != stateClosed {
		t.Fatalf("breaker state after stale failure = %d, want closed", state)
	}
	if failures := cb.failures.Load(); failures != 0 {
		t.Fatalf("failures after stale failure = %d, want 0", failures)
	}
	if got := cb.lastFailure.Load(); got != lastFailure {
		t.Fatalf("last failure after stale failure = %d, want unchanged %d", got, lastFailure)
	}
}

func routerTestStartBlockedRequest(
	router server.Middleware,
	ctx *server.RequestContext,
	outcome func(),
) (entered, release, done chan struct{}) {
	entered = make(chan struct{})
	release = make(chan struct{})
	done = make(chan struct{})
	go func() {
		defer close(done)
		router(ctx, func() {
			close(entered)
			<-release
			outcome()
		})
	}()
	return entered, release, done
}

func routerTestWait(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func routerTestHalfOpenMiddleware(t *testing.T) (server.Middleware, *circuitBreaker, int64) {
	t.Helper()
	cfg := routerTestConfig()
	rt := newRouterTable(cfg.Channels)
	cb := rt.breakers[routerTestOpenAIProviderID]
	cb.failures.Store(cb.threshold)
	lastFailure := time.Now().Add(-2 * cb.recoveryTime).Unix()
	cb.lastFailure.Store(lastFailure)
	cb.state.Store(stateOpen)
	return routerWithTable(cfg, rt), cb, lastFailure
}

func routerTestAssertReleasedProbe(t *testing.T, cb *circuitBreaker, lastFailure int64) {
	t.Helper()
	if state := cb.state.Load(); state != stateOpen {
		t.Fatalf("breaker state = %d, want open", state)
	}
	if failures := cb.failures.Load(); failures != cb.threshold {
		t.Fatalf("failures = %d, want unchanged %d", failures, cb.threshold)
	}
	if got := cb.lastFailure.Load(); got != lastFailure {
		t.Fatalf("last failure = %d, want unchanged %d", got, lastFailure)
	}
}

func routerTestAssertImmediateProbe(t *testing.T, router server.Middleware, cb *circuitBreaker) {
	t.Helper()
	ctx := routerTestContext(`{"model":"gpt-4o","messages":[]}`, []string{routerTestModel})
	calledNext := false
	router(ctx, func() {
		calledNext = true
		ctx.StatusCode = http.StatusBadRequest
		ctx.ProviderResponded = true
	})
	if !calledNext {
		t.Fatal("released half-open probe could not be reclaimed immediately")
	}
	if state := cb.state.Load(); state != stateClosed {
		t.Fatalf("breaker state after successful retry = %d, want closed", state)
	}
}

func routerTestProviderFailure(t *testing.T, router server.Middleware, attempt int) {
	t.Helper()
	ctx := routerTestContext(`{"model":"gpt-4o","messages":[]}`, []string{routerTestModel})
	calledNext := false
	router(ctx, func() {
		calledNext = true
		ctx.StatusCode = http.StatusServiceUnavailable
		ctx.ProviderResponded = true
		ctx.ProviderFailure = true
	})
	if !calledNext {
		t.Fatalf("attempt %d did not reach provider", attempt)
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
