// Package middleware - kms.go injects provider API keys into the request context.
//
// SECURITY CRITICAL:
//   - This middleware fetches the real API key from KMS just before proxying
//   - The key is stored in RequestContext.ProviderAPIKey as SecureBytes
//   - The key MUST be zeroed after the proxy completes (handled by pipeline)
//   - Keys are never logged, cached, or written to disk
//   - If KMS is unreachable, the request fails gracefully (no fallback to plaintext)
//
// KEY SOURCE RESOLUTION:
//   - Current runtime supports key_source="pool" only.
//   - key_source="byok" is reserved until server-side owner/provider binding exists.
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
//   - BYOK mode: reserved and rejected before KMS lookup
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

		// Inject key into request context.
		// SECURITY: This will be closed by the pipeline after request completion.
		ctx.ProviderAPIKey = secureKey

		next()

		// Defense in depth: zero the key even though pipeline also does it
		secureKey.Close()
		ctx.ProviderAPIKey = nil
	}
}

// resolveKeyID determines which KMS key to fetch based on the Virtual Key's source.
//
// For "pool" mode: Uses the server's pool mapping (developer-owned keys).
// For "byok" mode: Fails closed until the runtime has server-side owner/provider
// binding for user-owned keys.
func resolveKeyID(ctx *server.RequestContext, poolMapping map[string]string) string {
	if ctx.KeySource != "" && ctx.KeySource != KeySourcePool {
		return ""
	}

	// Default: pool mode — look up from the server's key mapping
	keyID, ok := poolMapping[ctx.ProviderID]
	if !ok {
		return ""
	}
	return keyID
}
