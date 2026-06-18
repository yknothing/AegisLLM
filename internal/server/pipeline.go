// Package server - pipeline.go implements the middleware pipeline (onion model).
//
// The pipeline is the architectural heart of Aegis. It chains middleware
// functions in a strict order, ensuring every request passes through
// security, rate limiting, and routing layers before reaching the proxy.
//
// Design: Each middleware receives a RequestContext and a next() function.
// Calling next() passes control to the inner layer. Not calling next()
// short-circuits the pipeline (e.g., for auth failures or rate limit hits).
package server

import (
	cryptoRand "crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/yknothing/AegisLLM/internal/config"
)

// Middleware is a function that processes a request and optionally
// delegates to the next middleware in the pipeline.
type Middleware func(ctx *RequestContext, next func())

// RequestContext carries all per-request state through the pipeline.
// SECURITY: This struct is zeroed after the request completes.
type RequestContext struct {
	// Request and response
	Writer  http.ResponseWriter
	Request *http.Request

	// Identity (populated by auth middleware)
	VirtualKeyID string
	Permissions  []string
	Budget       float64

	// Routing decision (populated by router middleware)
	ProviderID string
	Model      string
	BaseURL    string

	// Secrets (populated by KMS middleware, zeroed after use)
	ProviderAPIKey []byte

	// Metrics (populated during processing)
	StartTime    time.Time
	InputTokens  int
	OutputTokens int
	StatusCode   int

	// Internal pipeline state
	logger     *slog.Logger
	aborted    bool
	abortCode  int
	abortBody  []byte
}

// Abort stops the pipeline and returns an error response.
func (rc *RequestContext) Abort(statusCode int, body []byte) {
	rc.aborted = true
	rc.abortCode = statusCode
	rc.abortBody = body
}

// IsAborted returns whether the pipeline has been short-circuited.
func (rc *RequestContext) IsAborted() bool {
	return rc.aborted
}

// Pipeline orchestrates the ordered execution of middleware.
type Pipeline struct {
	middlewares []Middleware
	logger      *slog.Logger
}

// NewPipeline constructs the middleware pipeline based on configuration.
// The order of middleware is critical and security-sensitive:
//   1. Auth (reject unauthorized requests immediately)
//   2. Rate Limiter (prevent abuse before expensive processing)
//   3. PII Redaction (sanitize before routing/logging)
//   4. Router & LB (select provider)
//   5. KMS (inject real API key)
//   6. Protocol Adapter & Proxy (forward to provider)
func NewPipeline(cfg *config.Config, logger *slog.Logger) (*Pipeline, error) {
	p := &Pipeline{
		logger: logger,
	}

	// Register middleware in strict security-first order
	// Each middleware is responsible for its own initialization
	p.Use(RecoveryMiddleware(logger))
	p.Use(RequestIDMiddleware())
	p.Use(AuditMiddleware(logger))

	// TODO: Initialize and register core middleware from config
	// p.Use(middleware.NewAuth(cfg.Auth))
	// p.Use(middleware.NewRateLimiter(cfg.RateLimit))
	// p.Use(middleware.NewPIIRedaction())
	// p.Use(middleware.NewRouter(cfg.Providers))
	// p.Use(middleware.NewKMS(cfg.KMS))
	// p.Use(middleware.NewProxy())

	return p, nil
}

// Use appends a middleware to the pipeline.
func (p *Pipeline) Use(m Middleware) {
	p.middlewares = append(p.middlewares, m)
}

// ServeHTTP implements http.HandlerFunc and dispatches requests through the pipeline.
func (p *Pipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := &RequestContext{
		Writer:    w,
		Request:   r,
		StartTime: time.Now(),
		logger:    p.logger,
	}

	// Execute the middleware chain
	p.execute(ctx, 0)

	// If aborted, write the error response
	if ctx.IsAborted() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(ctx.abortCode)
		_, _ = w.Write(ctx.abortBody)
	}

	// SECURITY: Zero sensitive fields after request completion
	clear(ctx.ProviderAPIKey)
	ctx.ProviderAPIKey = nil
}

// execute recursively runs the middleware chain.
func (p *Pipeline) execute(ctx *RequestContext, index int) {
	if ctx.IsAborted() || index >= len(p.middlewares) {
		return
	}

	p.middlewares[index](ctx, func() {
		p.execute(ctx, index+1)
	})
}

// --- Built-in infrastructure middleware ---

// RecoveryMiddleware catches panics and prevents server crashes.
func RecoveryMiddleware(logger *slog.Logger) Middleware {
	return func(ctx *RequestContext, next func()) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("panic recovered in pipeline",
					"error", fmt.Sprintf("%v", r),
					// SECURITY: Do NOT log request body or headers
				)
				ctx.Abort(http.StatusInternalServerError, []byte(`{"error":"internal server error"}`))
			}
		}()
		next()
	}
}

// RequestIDMiddleware assigns a unique request ID for tracing.
func RequestIDMiddleware() Middleware {
	return func(ctx *RequestContext, next func()) {
		// Use existing X-Request-ID or generate one
		reqID := ctx.Request.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = generateRequestID()
		}
		ctx.Writer.Header().Set("X-Request-ID", reqID)
		next()
	}
}

// AuditMiddleware logs request metadata (never content) for compliance.
func AuditMiddleware(logger *slog.Logger) Middleware {
	return func(ctx *RequestContext, next func()) {
		next()

		// SECURITY: Only log metadata, NEVER log request/response bodies
		duration := time.Since(ctx.StartTime)
		logger.Info("request completed",
			"method", ctx.Request.Method,
			"path", ctx.Request.URL.Path,
			"status", ctx.StatusCode,
			"duration_ms", duration.Milliseconds(),
			"input_tokens", ctx.InputTokens,
			"output_tokens", ctx.OutputTokens,
			"provider", ctx.ProviderID,
			"model", ctx.Model,
			"virtual_key", ctx.VirtualKeyID,
			// NEVER: "body", "prompt", "completion", "headers"
		)
	}
}

// generateRequestID creates a unique identifier for request tracing.
// SECURITY: Uses crypto/rand for unpredictable IDs (prevents enumeration attacks).
func generateRequestID() string {
	b := make([]byte, 16)
	if _, err := cryptoRand.Read(b); err != nil {
		// Fallback should never happen, but don't panic
		return fmt.Sprintf("req_%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("req_%x", b)
}
