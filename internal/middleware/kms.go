// Package middleware - kms.go injects provider API keys into the request context.
//
// SECURITY CRITICAL:
//   - This middleware fetches the real API key from KMS just before proxying
//   - The key is stored in RequestContext.ProviderAPIKey as []byte
//   - The key MUST be zeroed after the proxy completes (handled by pipeline)
//   - Keys are never logged, cached, or written to disk
//   - If KMS is unreachable, the request fails gracefully (no fallback to plaintext)
//
// KEY SOURCE RESOLUTION (ADR-003):
//   - If the Virtual Key has key_source="pool", resolve from the pool mapping
//   - If the Virtual Key has key_source="byok", use the byok_key_id from JWT claims
//   - This enables the hybrid model where both developer and user keys coexist
package middleware

import (
	"net/http"

	"github.com/yknothing/AegisLLM/internal/kms"
	"github.com/yknothing/AegisLLM/internal/server"
)

// KMSMiddlewareConfig configures the KMS key injection middleware.
type KMSMiddlewareConfig struct {
	Provider kms.Provider
	// PoolKeyMapping maps provider IDs to their KMS key IDs for pool mode.
	// Used when key_source="pool" (server-hosted keys).
	PoolKeyMapping map[string]string
}

// KMSInjector creates the KMS middleware that injects provider API keys.
//
// Position in pipeline: AFTER Router (needs ProviderID), BEFORE Proxy.
//
// SECURITY INVARIANTS:
//  1. Key is fetched on-demand, never pre-cached
//  2. Key is stored only in RequestContext (zeroed after request)
//  3. KMS failure = request failure (no insecure fallback)
//  4. Key retrieval is logged as metadata only (key ID, not key value)
//
// KEY SOURCE RESOLUTION:
//   - Pool mode: keyID = PoolKeyMapping[providerID]
//   - BYOK mode: keyID = claims.BYOKKeyID (from JWT)
func KMSInjector(cfg KMSMiddlewareConfig) server.Middleware {
	return func(ctx *server.RequestContext, next func()) {
		if ctx.ProviderID == "" {
			ctx.Abort(http.StatusInternalServerError, []byte(`{"error":{"message":"internal routing error","type":"server_error"}}`))
			return
		}

		// Resolve the KMS key ID based on key source
		keyID := resolveKeyID(ctx, cfg.PoolKeyMapping)
		if keyID == "" {
			ctx.Abort(http.StatusInternalServerError, []byte(`{"error":{"message":"unable to resolve provider key","type":"server_error"}}`))
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

// resolveKeyID determines which KMS key to fetch based on the Virtual Key's source.
//
// For "pool" mode: Uses the server's pool mapping (developer-owned keys).
// For "byok" mode: Uses the key ID embedded in the JWT claims (user-owned keys).
func resolveKeyID(ctx *server.RequestContext, poolMapping map[string]string) string {
	// Check if this is a BYOK request
	// The key source and BYOK key ID are set by the auth middleware
	// from the JWT claims (KeySource and BYOKKeyID fields)
	if ctx.KeySource == "byok" && ctx.BYOKKeyID != "" {
		return ctx.BYOKKeyID
	}

	// Default: pool mode — look up from the server's key mapping
	keyID, ok := poolMapping[ctx.ProviderID]
	if !ok {
		return ""
	}
	return keyID
}
