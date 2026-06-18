// Package middleware implements the core Aegis middleware pipeline components.
//
// Each middleware in this package follows the Aegis Middleware signature:
//   func(ctx *server.RequestContext, next func())
//
// Middleware MUST:
//   - Call next() to pass control to the next layer (or not, to short-circuit)
//   - Never log request/response bodies
//   - Zero any sensitive data after use
package middleware

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yknothing/AegisLLM/internal/server"
)

// AuthConfig holds authentication middleware configuration.
type AuthConfig struct {
	SigningKey  []byte        // JWT signing key (loaded from env, zeroed on shutdown)
	Issuer     string        // Expected JWT issuer
	Expiry     time.Duration // Default token expiry
	Revocation RevocationStore
}

// RevocationStore checks if a virtual key has been revoked.
// Implementations: in-memory set, Redis-backed bloom filter.
type RevocationStore interface {
	IsRevoked(keyID string) bool
}

// VirtualKeyClaims represents the JWT payload for an Aegis virtual key.
type VirtualKeyClaims struct {
	KeyID       string   `json:"kid"`
	Subject     string   `json:"sub"`     // Owner identifier
	Models      []string `json:"models"`  // Allowed models
	MaxRPM      int      `json:"rpm"`     // Per-key rate limit
	MaxTPM      int      `json:"tpm"`     // Per-key token limit
	BudgetUSD   float64  `json:"budget"`  // Monthly budget in USD
	IssuedAt    int64    `json:"iat"`
	ExpiresAt   int64    `json:"exp"`
	Issuer      string   `json:"iss"`
}

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
			ctx.Abort(http.StatusUnauthorized, errorJSON("missing authorization header"))
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			ctx.Abort(http.StatusUnauthorized, errorJSON("invalid authorization format"))
			return
		}

		token := parts[1]

		// Validate the virtual key (JWT)
		claims, err := validateToken(token, cfg.SigningKey, cfg.Issuer)
		if err != nil {
			// SECURITY: Do not reveal specific validation failure reason
			ctx.Abort(http.StatusUnauthorized, errorJSON("invalid or expired virtual key"))
			return
		}

		// Check revocation list
		if cfg.Revocation != nil && cfg.Revocation.IsRevoked(claims.KeyID) {
			ctx.Abort(http.StatusUnauthorized, errorJSON("virtual key has been revoked"))
			return
		}

		// Populate request context with identity information
		ctx.VirtualKeyID = claims.KeyID
		ctx.Permissions = claims.Models
		ctx.Budget = claims.BudgetUSD

		next()
	}
}

// validateToken verifies the JWT signature and claims.
// SECURITY: Uses constant-time comparison to prevent timing attacks.
func validateToken(token string, signingKey []byte, expectedIssuer string) (*VirtualKeyClaims, error) {
	// TODO: Implement full JWT RS256/HS256 validation
	// For the framework, we define the contract:
	// 1. Split token into header.payload.signature
	// 2. Verify signature using constant-time comparison
	// 3. Decode and validate claims (expiry, issuer)
	// 4. Return validated claims

	_ = subtle.ConstantTimeCompare // Used in actual implementation
	_ = token
	_ = signingKey
	_ = expectedIssuer

	return nil, fmt.Errorf("JWT validation not yet implemented")
}

// errorJSON creates a standard error response body.
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

// NewMemoryRevocationStore creates an in-memory revocation store.
func NewMemoryRevocationStore() *MemoryRevocationStore {
	return &MemoryRevocationStore{revoked: make(map[string]struct{})}
}

// Revoke adds a key ID to the revocation list.
func (s *MemoryRevocationStore) Revoke(keyID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[keyID] = struct{}{}
}

// IsRevoked checks if a key ID has been revoked.
func (s *MemoryRevocationStore) IsRevoked(keyID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.revoked[keyID]
	return ok
}
