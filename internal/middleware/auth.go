// Package middleware implements the core Aegis middleware pipeline components.
//
// Each middleware in this package follows the Aegis Middleware signature:
//
//	func(ctx *server.RequestContext, next func())
//
// Middleware MUST:
//   - Call next() to pass control to the next layer (or not, to short-circuit)
//   - Never log request/response bodies
//   - Zero any sensitive data after use
package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yknothing/AegisLLM/internal/server"
	"github.com/yknothing/AegisLLM/internal/virtualkey"
)

// AuthConfig holds authentication middleware configuration.
type AuthConfig struct {
	SigningKey []byte        // JWT signing key (loaded from env, zeroed on shutdown)
	Issuer     string        // Expected JWT issuer
	Expiry     time.Duration // Maximum accepted token lifetime
	Revocation RevocationStore
}

const (
	// MinJWTSigningKeyBytes is the minimum HS256 signing-key length accepted by runtime.
	MinJWTSigningKeyBytes = virtualkey.MinSigningKeyBytes

	// KeySourcePool is the only key source supported by the v0.2.1 runtime.
	KeySourcePool = virtualkey.KeySourcePool
	keySourceBYOK = "byok" // Kept for package-level reserved-mode tests.
)

// RevocationStore checks if a virtual key has been revoked.
// Current runtime uses a durable local checker; shared revocation is a reserved
// cluster-mode target. The in-memory implementation below is test-only.
type RevocationStore interface {
	Check(ctx context.Context, issuer, keyID string) (bool, error)
}

// VirtualKeyClaims is retained as an alias for middleware callers. The
// issuance and validation contract is owned by internal/virtualkey.
type VirtualKeyClaims = virtualkey.Claims

// Auth creates the authentication middleware.
// This is the FIRST middleware in the pipeline - it rejects unauthorized
// requests before any expensive processing occurs.
//
// SECURITY:
//   - Uses constant-time comparison for token validation
//   - Checks revocation list on every request
//   - Never reveals why authentication failed (timing attacks)
func Auth(cfg AuthConfig) server.Middleware {
	return func(ctx *server.RequestContext, next func()) {
		// Extract bearer token from Authorization header
		authHeader := ctx.Request.Header.Get("Authorization")
		if authHeader == "" {
			ctx.Abort(http.StatusUnauthorized, authFailureJSON())
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			ctx.Abort(http.StatusUnauthorized, authFailureJSON())
			return
		}

		token := parts[1]

		// Validate the virtual key (JWT)
		claims, err := validateToken(token, cfg.SigningKey, cfg.Issuer, cfg.Expiry)
		if err != nil {
			// SECURITY: Do not reveal specific validation failure reason
			ctx.Abort(http.StatusUnauthorized, authFailureJSON())
			return
		}

		// Check revocation state. Missing or unavailable state cannot safely
		// produce an allow decision.
		if cfg.Revocation == nil {
			ctx.Abort(http.StatusServiceUnavailable, authUnavailableJSON())
			return
		}
		revoked, err := cfg.Revocation.Check(ctx.Request.Context(), claims.Issuer, claims.KeyID)
		if err != nil {
			ctx.Abort(http.StatusServiceUnavailable, authUnavailableJSON())
			return
		}
		if revoked {
			ctx.Abort(http.StatusUnauthorized, authFailureJSON())
			return
		}

		// Populate request context with identity information
		ctx.VirtualKeyID = claims.KeyID
		ctx.Permissions = claims.Models
		ctx.Budget = claims.BudgetUSD
		ctx.KeySource = claims.KeySource
		ctx.BYOKKeyID = claims.BYOKKeyID
		ctx.MaxRPM = claims.MaxRPM
		ctx.MaxTPM = claims.MaxTPM
		ctx.MaxConcurrency = claims.MaxConcurrency

		next()
	}
}

// validateToken verifies the JWT signature and claims.
// SECURITY: Uses constant-time comparison to prevent timing attacks.
func validateToken(token string, signingKey []byte, expectedIssuer string, maxTokenTTL time.Duration) (*VirtualKeyClaims, error) {
	return virtualkey.Validate(token, signingKey, expectedIssuer, maxTokenTTL)
}

func authFailureJSON() []byte {
	return errorJSON("invalid or expired virtual key")
}

func authUnavailableJSON() []byte {
	return errorJSON("authentication temporarily unavailable")
}

// errorJSON creates a standard authentication error response body.
func errorJSON(msg string) []byte {
	resp := struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}{}
	resp.Error.Message = msg
	resp.Error.Type = "authentication_error"
	b, _ := json.Marshal(resp)
	return b
}

// --- In-Memory Revocation Store ---

// MemoryRevocationStore is a simple thread-safe set for revoked key IDs.
type MemoryRevocationStore struct {
	mu      sync.RWMutex
	revoked map[string]struct{}
}

// NewMemoryRevocationStore creates a test-only in-memory revocation store.
func NewMemoryRevocationStore() *MemoryRevocationStore {
	return &MemoryRevocationStore{revoked: make(map[string]struct{})}
}

// Revoke adds a key ID to the revocation list.
func (s *MemoryRevocationStore) Revoke(issuer, keyID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[issuer+"\x00"+keyID] = struct{}{}
}

// Check reports whether an issuer/key ID pair has been revoked.
func (s *MemoryRevocationStore) Check(ctx context.Context, issuer, keyID string) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.revoked[issuer+"\x00"+keyID]
	return ok, nil
}
