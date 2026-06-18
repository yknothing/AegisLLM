// Package middleware - kms.go injects provider API keys into the request context.
//
// SECURITY CRITICAL:
//   - This middleware fetches the real API key from KMS just before proxying
//   - The key is stored in RequestContext.ProviderAPIKey as []byte
//   - The key MUST be zeroed after the proxy completes (handled by pipeline)
//   - Keys are never logged, cached, or written to disk
//   - If KMS is unreachable, the request fails gracefully (no fallback to plaintext)
package middleware

import (
	"net/http"

	"github.com/yknothing/AegisLLM/internal/kms"
	"github.com/yknothing/AegisLLM/internal/server"
)

// KMSMiddlewareConfig configures the KMS key injection middleware.
type KMSMiddlewareConfig struct {
	Provider kms.Provider
	// KeyMapping maps provider IDs to their KMS key IDs.
	// This allows multiple providers to use different stored keys.
	KeyMapping map[string]string
}

// KMSInjector creates the KMS middleware that injects provider API keys.
//
// Position in pipeline: AFTER Router (needs ProviderID), BEFORE Proxy.
//
// SECURITY INVARIANTS:
//   1. Key is fetched on-demand, never pre-cached
//   2. Key is stored only in RequestContext (zeroed after request)
//   3. KMS failure = request failure (no insecure fallback)
//   4. Key retrieval is logged as metadata only (key ID, not key value)
func KMSInjector(cfg KMSMiddlewareConfig) server.Middleware {
	return func(ctx *server.RequestContext, next func()) {
		if ctx.ProviderID == "" {
			// Router middleware should have set this
			ctx.Abort(http.StatusInternalServerError, []byte(`{"error":{"message":"internal routing error","type":"server_error"}}`))
			return
		}

		// Resolve the KMS key ID for this provider
		keyID, ok := cfg.KeyMapping[ctx.ProviderID]
		if !ok {
			ctx.Abort(http.StatusInternalServerError, []byte(`{"error":{"message":"provider key not configured","type":"server_error"}}`))
			return
		}

		// Fetch the decrypted key from KMS
		secureKey, err := cfg.Provider.GetKey(ctx.Request.Context(), keyID)
		if err != nil {
			// SECURITY: Do not reveal KMS details in error response
			ctx.Abort(http.StatusServiceUnavailable, []byte(`{"error":{"message":"key service unavailable","type":"server_error"}}`))
			return
		}

		// Inject key into request context
		// SECURITY: This will be zeroed by the pipeline after request completion
		ctx.ProviderAPIKey = secureKey.Bytes()

		next()

		// Defense in depth: zero the key even though pipeline also does it
		secureKey.Close()
		ctx.ProviderAPIKey = nil
	}
}
