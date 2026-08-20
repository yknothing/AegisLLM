// Package middleware - router.go implements intelligent routing with circuit breaker.
//
// DESIGN:
//   - Routes requests to a healthy provider that supports the requested model
//   - Uses priority ordering, with weight as a deterministic tie-breaker
//   - Implements Circuit Breaker pattern for fault tolerance
//   - Does not perform cross-model fallback or probabilistic weighted balancing
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
	Priority int // Lower = higher priority for same-model routing
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
	return routerWithTable(cfg, newRouterTable(cfg.Channels))
}

func routerWithTable(cfg RouterConfig, rt *routerTable) server.Middleware {
	return func(ctx *server.RequestContext, next func()) {
		// Extract requested model from the request
		model, streaming, err := extractModelFromRequest(ctx, cfg.MaxRequestBodySize)
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
		channel, lease := rt.Route(model)
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

		// After request: only the proxy boundary may update provider health.
		// Gateway-local KMS, adapter, or policy failures must not poison it.
		defer func() {
			if ctx.ProviderFailure {
				rt.RecordFailure(channel.ID, lease)
			} else if ctx.ProviderResponded {
				rt.RecordSuccess(channel.ID, lease)
			} else if lease.probe {
				rt.ReleaseProbe(channel.ID, lease)
			}
		}()

		next()
	}
}

// --- Router Table with Circuit Breaker ---

type routerTable struct {
	mu       sync.RWMutex
	channels []ProviderChannel
	breakers map[string]*circuitBreaker
}

type circuitLease struct {
	generation uint64
	probe      bool
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
// Strategy: same-model priority routing with weight as a deterministic tie-breaker
// and circuit breaker health checks.
func (rt *routerTable) Route(model string) (*ProviderChannel, circuitLease) {
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
			if lease, acquired := breaker.AcquireClosed(); acquired {
				return ch, lease
			}
		}
	}

	// All channels are unhealthy - try half-open ones
	for _, ch := range candidates {
		if breaker, ok := rt.breakers[ch.ID]; ok {
			if lease, acquired := breaker.AllowProbe(); acquired {
				return ch, lease
			}
		}
	}

	return nil, circuitLease{}
}

func (rt *routerTable) RecordFailure(channelID string, lease circuitLease) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	if b, ok := rt.breakers[channelID]; ok {
		b.RecordFailure(lease)
	}
}

func (rt *routerTable) RecordSuccess(channelID string, lease circuitLease) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	if b, ok := rt.breakers[channelID]; ok {
		b.RecordSuccess(lease)
	}
}

func (rt *routerTable) ReleaseProbe(channelID string, lease circuitLease) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	if b, ok := rt.breakers[channelID]; ok {
		b.ReleaseProbe(lease)
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
	mu           sync.Mutex
	state        atomic.Int32
	failures     atomic.Int64
	lastFailure  atomic.Int64 // Unix timestamp
	generation   uint64
	threshold    int64 // Failures before opening
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

func (cb *circuitBreaker) AcquireClosed() (circuitLease, bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.state.Load() != stateClosed {
		return circuitLease{}, false
	}
	return circuitLease{generation: cb.generation}, true
}

func (cb *circuitBreaker) AllowProbe() (circuitLease, bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.state.Load() != stateOpen {
		return circuitLease{}, false
	}
	// Check if recovery time has elapsed
	lastFail := time.Unix(cb.lastFailure.Load(), 0)
	if time.Since(lastFail) > cb.recoveryTime {
		if cb.state.CompareAndSwap(stateOpen, stateHalfOpen) {
			return circuitLease{generation: cb.generation, probe: true}, true
		}
	}
	return circuitLease{}, false
}

func (cb *circuitBreaker) RecordFailure(lease circuitLease) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.generation != lease.generation {
		return
	}

	if lease.probe {
		if cb.state.Load() != stateHalfOpen {
			return
		}
		cb.failures.Add(1)
		cb.lastFailure.Store(time.Now().Unix())
		if cb.state.CompareAndSwap(stateHalfOpen, stateOpen) {
			cb.generation++
		}
		return
	}

	if cb.state.Load() != stateClosed {
		return
	}
	if cb.failures.Add(1) >= cb.threshold {
		cb.lastFailure.Store(time.Now().Unix())
		if cb.state.CompareAndSwap(stateClosed, stateOpen) {
			cb.generation++
		}
		return
	}
	cb.lastFailure.Store(time.Now().Unix())
}

func (cb *circuitBreaker) RecordSuccess(lease circuitLease) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.generation != lease.generation {
		return
	}

	if lease.probe {
		if cb.state.CompareAndSwap(stateHalfOpen, stateClosed) {
			cb.failures.Store(0)
			cb.generation++
		}
		return
	}

	if cb.state.Load() == stateClosed {
		cb.failures.Store(0)
	}
}

func (cb *circuitBreaker) ReleaseProbe(lease circuitLease) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if !lease.probe || cb.generation != lease.generation {
		return
	}
	cb.state.CompareAndSwap(stateHalfOpen, stateOpen)
}

// --- Helper Functions ---

func extractModelFromRequest(ctx *server.RequestContext, limit int64) (string, bool, error) {
	body, err := readRequestBody(ctx, limit)
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
		return false
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
