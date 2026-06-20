// Package middleware - ratelimit.go implements the request rate limiter.
//
// DESIGN: Three-dimensional rate limiting:
//  1. RPM (Requests Per Minute) - prevents request flooding
//  2. TPM (Tokens Per Minute) - reserved, fails closed until implemented
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

	"github.com/yknothing/AegisLLM/internal/server"
)

// RateLimitConfig configures the rate limiter middleware.
type RateLimitConfig struct {
	Backend        string // "memory" | "redis"
	RedisURL       string
	DefaultRPM     int
	DefaultTPM     int
	DefaultMaxConc int
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
			tpmLimit = ctx.MaxTPM
		}
		if tpmLimit > 0 {
			ctx.Abort(http.StatusServiceUnavailable, rateLimitUnavailableJSON())
			return
		}

		rpmLimit := cfg.DefaultRPM
		if ctx.MaxRPM > 0 {
			rpmLimit = ctx.MaxRPM
		}
		maxConcurrency := cfg.DefaultMaxConc
		if ctx.MaxConcurrency > 0 {
			maxConcurrency = effectiveMaxConcurrency(cfg.DefaultMaxConc, ctx.MaxConcurrency)
		}

		// Check RPM limit
		allowed, err := limiter.Allow(key, "rpm", rpmLimit, time.Minute)
		if err != nil || !allowed {
			ctx.Abort(http.StatusTooManyRequests, rateLimitErrorJSON("rate limit exceeded (RPM)"))
			return
		}

		// Check concurrency limit
		acquired, release := limiter.AcquireConcurrency(key, maxConcurrency)
		if !acquired {
			ctx.Abort(http.StatusTooManyRequests, rateLimitErrorJSON("concurrency limit exceeded"))
			return
		}
		defer release()

		next()
	}
}

// Limiter is the interface for rate limiting backends.
type Limiter interface {
	// Allow checks if a request is within the rate limit.
	Allow(key, dimension string, limit int, window time.Duration) (bool, error)

	// AcquireConcurrency attempts to acquire a concurrency slot.
	// Returns true and a release function if successful.
	AcquireConcurrency(key string, maxConc int) (acquired bool, release func())
}

// --- In-Memory Limiter (Standalone Mode) ---

type memoryLimiter struct {
	mu      sync.Mutex
	windows map[string]*slidingWindow
	conc    map[string]*concurrencyTracker
}

type slidingWindow struct {
	counts []timestampedCount
}

type timestampedCount struct {
	time  time.Time
	count int
}

type concurrencyTracker struct {
	current int
}

func newMemoryLimiter() *memoryLimiter {
	return &memoryLimiter{
		windows: make(map[string]*slidingWindow),
		conc:    make(map[string]*concurrencyTracker),
	}
}

func (m *memoryLimiter) Allow(key, dimension string, limit int, window time.Duration) (bool, error) {
	if limit <= 0 {
		return true, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	compositeKey := key + ":" + dimension
	sw, ok := m.windows[compositeKey]
	if !ok {
		sw = &slidingWindow{}
		m.windows[compositeKey] = sw
	}

	// Evict expired entries
	now := time.Now()
	cutoff := now.Add(-window)
	valid := sw.counts[:0]
	total := 0
	for _, tc := range sw.counts {
		if tc.time.After(cutoff) {
			valid = append(valid, tc)
			total += tc.count
		}
	}
	sw.counts = valid

	if total >= limit {
		return false, nil
	}

	sw.counts = append(sw.counts, timestampedCount{time: now, count: 1})
	return true, nil
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
	release := func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		ct.current--
	}

	return true, release
}

func effectiveMaxConcurrency(defaultMax, keyMax int) int {
	// A non-zero default is both fallback and deployment-wide ceiling.
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
