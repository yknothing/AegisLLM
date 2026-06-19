// Package middleware - router.go implements intelligent routing with circuit breaker.
//
// DESIGN:
//   - Routes requests to the optimal provider based on model, priority, and health
//   - Implements Circuit Breaker pattern for fault tolerance
//   - Supports multi-level fallback chains (e.g., gpt-4o → claude-sonnet → deepseek)
//   - Weighted load balancing across multiple keys for the same provider
//
// SECURITY:
//   - Only routes to pre-configured providers (no open redirect)
//   - Validates requested model against virtual key's allowed models
package middleware

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yknothing/AegisLLM/internal/server"
)

// ProviderChannel represents a configured LLM provider endpoint.
type ProviderChannel struct {
	ID       string
	Name     string
	Type     string // "openai" | "anthropic" | "google" | "deepseek"
	BaseURL  string
	KeyID    string // Reference to KMS-stored key
	Models   []string
	Weight   int
	Priority int // Lower = higher priority for fallback
	Enabled  bool
}

// RouterConfig configures the routing middleware.
type RouterConfig struct {
	Channels           []ProviderChannel
	MaxRequestBodySize int64
}

// Router creates the routing middleware.
// It selects the best available provider for the requested model.
func Router(cfg RouterConfig) server.Middleware {
	rt := newRouterTable(cfg.Channels)

	return func(ctx *server.RequestContext, next func()) {
		// Extract requested model from the request
		model, streaming, err := extractModelFromRequest(ctx.Request, cfg.MaxRequestBodySize)
		if errors.Is(err, errRequestBodyTooLarge) {
			ctx.Abort(http.StatusRequestEntityTooLarge, []byte(`{"error":{"message":"request body too large","type":"invalid_request_error"}}`))
			return
		}
		if err != nil {
			ctx.Abort(http.StatusBadRequest, []byte(`{"error":{"message":"invalid request body","type":"invalid_request_error"}}`))
			return
		}
		if model == "" {
			ctx.Abort(http.StatusBadRequest, []byte(`{"error":{"message":"model field is required","type":"invalid_request_error"}}`))
			return
		}

		// SECURITY: Verify the virtual key is allowed to access this model
		if !isModelAllowed(model, ctx.Permissions) {
			ctx.Abort(http.StatusForbidden, []byte(`{"error":{"message":"model not permitted for this virtual key","type":"permission_error"}}`))
			return
		}

		// Find the best available channel for this model
		channel := rt.Route(model)
		if channel == nil {
			ctx.Abort(http.StatusServiceUnavailable, []byte(`{"error":{"message":"no available provider for requested model","type":"service_error"}}`))
			return
		}

		// Populate routing decision in context
		ctx.ProviderID = channel.ID
		ctx.ProviderType = channel.Type
		ctx.ProviderAPIKeyID = channel.KeyID
		ctx.Model = model
		ctx.BaseURL = channel.BaseURL
		ctx.IsStreaming = streaming

		next()

		// After request: update circuit breaker based on response
		if ctx.StatusCode >= 500 || ctx.StatusCode == 429 {
			rt.RecordFailure(channel.ID)
		} else if ctx.StatusCode > 0 && ctx.StatusCode < 400 {
			rt.RecordSuccess(channel.ID)
		}
	}
}

// --- Router Table with Circuit Breaker ---

type routerTable struct {
	mu       sync.RWMutex
	channels []ProviderChannel
	breakers map[string]*circuitBreaker
}

func newRouterTable(channels []ProviderChannel) *routerTable {
	breakers := make(map[string]*circuitBreaker)
	for _, ch := range channels {
		breakers[ch.ID] = newCircuitBreaker()
	}
	return &routerTable{
		channels: channels,
		breakers: breakers,
	}
}

// Route finds the best available channel for the given model.
// Strategy: priority-based with circuit breaker health check.
func (rt *routerTable) Route(model string) *ProviderChannel {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	// Find all channels that support this model, sorted by priority
	var candidates []*ProviderChannel
	for i := range rt.channels {
		ch := &rt.channels[i]
		if !ch.Enabled {
			continue
		}
		if supportsModel(ch, model) {
			candidates = append(candidates, ch)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Priority == candidates[j].Priority {
			return candidates[i].Weight > candidates[j].Weight
		}
		return candidates[i].Priority < candidates[j].Priority
	})

	// Select the first healthy channel (lowest priority number = highest priority)
	for _, ch := range candidates {
		if breaker, ok := rt.breakers[ch.ID]; ok {
			if breaker.IsHealthy() {
				return ch
			}
		}
	}

	// All channels are unhealthy - try half-open ones
	for _, ch := range candidates {
		if breaker, ok := rt.breakers[ch.ID]; ok {
			if breaker.AllowProbe() {
				return ch
			}
		}
	}

	return nil
}

func (rt *routerTable) RecordFailure(channelID string) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	if b, ok := rt.breakers[channelID]; ok {
		b.RecordFailure()
	}
}

func (rt *routerTable) RecordSuccess(channelID string) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	if b, ok := rt.breakers[channelID]; ok {
		b.RecordSuccess()
	}
}

// --- Circuit Breaker ---

// Circuit breaker states
const (
	stateClosed   int32 = iota // Normal operation
	stateOpen                  // All requests fail-fast
	stateHalfOpen              // Allowing probe requests
)

type circuitBreaker struct {
	state        atomic.Int32
	failures     atomic.Int64
	lastFailure  atomic.Int64 // Unix timestamp
	threshold    int64        // Failures before opening
	recoveryTime time.Duration
}

func newCircuitBreaker() *circuitBreaker {
	cb := &circuitBreaker{
		threshold:    5,
		recoveryTime: 30 * time.Second,
	}
	cb.state.Store(stateClosed)
	return cb
}

func (cb *circuitBreaker) IsHealthy() bool {
	return cb.state.Load() == stateClosed
}

func (cb *circuitBreaker) AllowProbe() bool {
	if cb.state.Load() != stateOpen {
		return false
	}
	// Check if recovery time has elapsed
	lastFail := time.Unix(cb.lastFailure.Load(), 0)
	if time.Since(lastFail) > cb.recoveryTime {
		cb.state.Store(stateHalfOpen)
		return true
	}
	return false
}

func (cb *circuitBreaker) RecordFailure() {
	cb.failures.Add(1)
	cb.lastFailure.Store(time.Now().Unix())
	if cb.failures.Load() >= cb.threshold {
		cb.state.Store(stateOpen)
	}
}

func (cb *circuitBreaker) RecordSuccess() {
	cb.failures.Store(0)
	cb.state.Store(stateClosed)
}

// --- Helper Functions ---

func extractModelFromRequest(r *http.Request, limit int64) (string, bool, error) {
	body, err := readAndReplaceBody(r, limit)
	if err != nil {
		return "", false, err
	}

	var req struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	if len(body) == 0 {
		return "", false, nil
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return "", false, err
	}

	return req.Model, req.Stream, nil
}

func isModelAllowed(model string, allowed []string) bool {
	if len(allowed) == 0 {
		return true // No restrictions
	}
	for _, m := range allowed {
		if m == model || m == "*" {
			return true
		}
	}
	return false
}

func supportsModel(ch *ProviderChannel, model string) bool {
	for _, m := range ch.Models {
		if m == model || m == "*" {
			return true
		}
	}
	return false
}
