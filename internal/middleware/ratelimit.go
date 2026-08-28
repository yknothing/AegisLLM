// Package middleware - ratelimit.go implements the request rate limiter.
//
// DESIGN: Three-dimensional rate limiting:
//  1. RPM (Requests Per Minute) - prevents request flooding
//  2. TPM (Tokens Per Minute) - sliding window with body estimate, then reconcile
//  3. Concurrency - prevents connection pool exhaustion
//
// Backends:
//   - "memory": In-process sliding window (standalone mode)
//   - "redis": Reserved distributed token bucket backend (cluster mode)
//
// SECURITY: Rate limiting is the second middleware in the pipeline,
// applied AFTER authentication but BEFORE any expensive operations.
// This prevents authenticated-but-abusive clients from causing DoS.
package middleware

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/yknothing/AegisLLM/internal/gatewayconst"
	"github.com/yknothing/AegisLLM/internal/server"
)

// RateLimitConfig configures the rate limiter middleware.
type RateLimitConfig struct {
	Backend            string // "memory" | "redis"
	RedisURL           string
	DefaultRPM         int
	DefaultTPM         int
	DefaultMaxConc     int
	MaxRequestBodySize int64
}

// RateLimiter creates the rate limiting middleware.
func RateLimiter(cfg RateLimitConfig) server.Middleware {
	var limiter Limiter
	var initErr error
	switch cfg.Backend {
	case "redis":
		initErr = errors.New("redis rate limiter backend is not implemented")
	case "memory", "":
		limiter = newMemoryLimiter()
	default:
		initErr = errors.New("unsupported rate limiter backend: " + cfg.Backend)
	}

	return rateLimiter(cfg, limiter, initErr)
}

func rateLimiter(cfg RateLimitConfig, limiter Limiter, initErr error) server.Middleware {
	return func(ctx *server.RequestContext, next func()) {
		if initErr != nil {
			ctx.Abort(http.StatusServiceUnavailable, rateLimitUnavailableJSON())
			return
		}

		key := ctx.VirtualKeyID
		if key == "" {
			key = ctx.Request.RemoteAddr
		}

		tpmLimit := cfg.DefaultTPM
		if ctx.MaxTPM > 0 {
			tpmLimit = effectivePolicyLimit(cfg.DefaultTPM, ctx.MaxTPM)
		}

		rpmLimit := cfg.DefaultRPM
		if ctx.MaxRPM > 0 {
			rpmLimit = effectivePolicyLimit(cfg.DefaultRPM, ctx.MaxRPM)
		}
		maxConcurrency := cfg.DefaultMaxConc
		if ctx.MaxConcurrency > 0 {
			maxConcurrency = effectivePolicyLimit(cfg.DefaultMaxConc, ctx.MaxConcurrency)
		}

		allowed, err := limiter.Allow(key, gatewayconst.RateDimensionRPM, rpmLimit, time.Minute)
		if err != nil || !allowed {
			ctx.Abort(http.StatusTooManyRequests, rateLimitErrorJSON("rate limit exceeded (RPM)"))
			return
		}

		estimatedTokens := 0
		if tpmLimit > 0 {
			body, bodyErr := readRequestBody(ctx, cfg.MaxRequestBodySize)
			if errors.Is(bodyErr, errRequestBodyTooLarge) {
				ctx.Abort(http.StatusRequestEntityTooLarge, []byte(`{"error":{"message":"request body too large","type":"invalid_request_error"}}`))
				return
			}
			if bodyErr != nil {
				ctx.Abort(http.StatusBadRequest, []byte(`{"error":{"message":"invalid request body","type":"invalid_request_error"}}`))
				return
			}
			estimatedTokens = estimateTokensFromBody(body)
			allowed, err = limiter.AllowN(key, gatewayconst.RateDimensionTPM, estimatedTokens, tpmLimit, time.Minute)
			if err != nil || !allowed {
				ctx.Abort(http.StatusTooManyRequests, rateLimitErrorJSON("rate limit exceeded (TPM)"))
				return
			}
		}

		acquired, release := limiter.AcquireConcurrency(key, maxConcurrency)
		if !acquired {
			ctx.Abort(http.StatusTooManyRequests, rateLimitErrorJSON("concurrency limit exceeded"))
			return
		}
		defer release()

		next()

		if tpmLimit > 0 {
			actual := ctx.InputTokens + ctx.OutputTokens
			if actual > estimatedTokens {
				limiter.Record(key, gatewayconst.RateDimensionTPM, actual-estimatedTokens, time.Minute)
			}
		}
	}
}

// Limiter is the interface for rate limiting backends.
type Limiter interface {
	Allow(key, dimension string, limit int, window time.Duration) (bool, error)
	AllowN(key, dimension string, n, limit int, window time.Duration) (bool, error)
	Record(key, dimension string, n int, window time.Duration)
	AcquireConcurrency(key string, maxConc int) (acquired bool, release func())
}

// --- In-Memory Limiter (Standalone Mode) ---

type memoryLimiter struct {
	mu         sync.Mutex
	windows    map[string]*slidingWindow
	conc       map[string]*concurrencyTracker
	operations uint64
}

type slidingWindow struct {
	counts []timestampedCount
	window time.Duration
	head   int
	total  int
}

type timestampedCount struct {
	time  time.Time
	count int
}

type concurrencyTracker struct {
	current int
}

const memoryLimiterCleanupEvery = 256

func newMemoryLimiter() *memoryLimiter {
	return &memoryLimiter{
		windows: make(map[string]*slidingWindow),
		conc:    make(map[string]*concurrencyTracker),
	}
}

func (m *memoryLimiter) Allow(key, dimension string, limit int, window time.Duration) (bool, error) {
	return m.AllowN(key, dimension, 1, limit, window)
}

func (m *memoryLimiter) AllowN(key, dimension string, n, limit int, window time.Duration) (bool, error) {
	if n <= 0 {
		return true, nil
	}
	if limit <= 0 {
		return true, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	m.operations++
	if m.operations%memoryLimiterCleanupEvery == 0 {
		m.cleanupExpiredWindows(now)
	}

	sw := m.windowLocked(key, dimension, window, now)
	if sw.total+n > limit {
		return false, nil
	}
	sw.counts = append(sw.counts, timestampedCount{time: now, count: n})
	sw.total += n
	return true, nil
}

func (m *memoryLimiter) Record(key, dimension string, n int, window time.Duration) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	sw := m.windowLocked(key, dimension, window, now)
	sw.counts = append(sw.counts, timestampedCount{time: now, count: n})
	sw.total += n
}

func (m *memoryLimiter) windowLocked(key, dimension string, window time.Duration, now time.Time) *slidingWindow {
	compositeKey := key + ":" + dimension
	sw, ok := m.windows[compositeKey]
	if !ok {
		sw = &slidingWindow{window: window}
		m.windows[compositeKey] = sw
	}
	sw.window = window
	sw.prune(now)
	return sw
}

func estimateTokensFromBody(body []byte) int {
	if len(body) == 0 {
		return gatewayconst.MinEstimatedTokens
	}
	tokens := (len(body) + gatewayconst.CharsPerTokenEstimate - 1) / gatewayconst.CharsPerTokenEstimate
	if tokens < gatewayconst.MinEstimatedTokens {
		return gatewayconst.MinEstimatedTokens
	}
	return tokens
}

func (sw *slidingWindow) prune(now time.Time) {
	cutoff := now.Add(-sw.window)
	for sw.head < len(sw.counts) && !sw.counts[sw.head].time.After(cutoff) {
		sw.total -= sw.counts[sw.head].count
		sw.head++
	}
	if sw.head == len(sw.counts) {
		sw.counts = nil
		sw.head = 0
		sw.total = 0
		return
	}
	// Periodically compact an active window without rescanning its live tail.
	if sw.head >= 1024 && sw.head*2 >= len(sw.counts) {
		remaining := copy(sw.counts, sw.counts[sw.head:])
		sw.counts = sw.counts[:remaining]
		sw.head = 0
	}
}

func (m *memoryLimiter) cleanupExpiredWindows(now time.Time) {
	for key, sw := range m.windows {
		if sw.window <= 0 {
			delete(m.windows, key)
			continue
		}
		sw.prune(now)
		if sw.total == 0 {
			delete(m.windows, key)
		}
	}
}

func (m *memoryLimiter) AcquireConcurrency(key string, maxConc int) (bool, func()) {
	if maxConc <= 0 {
		return true, func() {}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	ct, ok := m.conc[key]
	if !ok {
		ct = &concurrencyTracker{}
		m.conc[key] = ct
	}

	if ct.current >= maxConc {
		return false, nil
	}

	ct.current++
	released := false
	release := func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if released {
			return
		}
		released = true
		ct.current--
		if ct.current == 0 && m.conc[key] == ct {
			delete(m.conc, key)
		}
	}

	return true, release
}

func effectivePolicyLimit(defaultMax, keyMax int) int {
	// A non-zero default is both fallback and a policy ceiling for each key.
	// This limiter does not implement an aggregate process-wide ceiling.
	if keyMax <= 0 {
		return defaultMax
	}
	if defaultMax <= 0 {
		return keyMax
	}
	if keyMax < defaultMax {
		return keyMax
	}
	return defaultMax
}

// rateLimitErrorJSON creates a rate limit error response.
func rateLimitErrorJSON(msg string) []byte {
	return errorResponseJSON(msg, "rate_limit_error")
}

func rateLimitUnavailableJSON() []byte {
	return errorResponseJSON("rate limit service unavailable", "server_error")
}

func errorResponseJSON(msg, typ string) []byte {
	resp := struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}{}
	resp.Error.Message = msg
	resp.Error.Type = typ
	b, _ := json.Marshal(resp)
	return b
}
