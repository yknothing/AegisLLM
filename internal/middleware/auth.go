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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
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
	SigningKey []byte        // JWT signing key (loaded from env, zeroed on shutdown)
	Issuer     string        // Expected JWT issuer
	Expiry     time.Duration // Maximum accepted token lifetime
	Revocation RevocationStore
}

const (
	// MinJWTSigningKeyBytes is the minimum HS256 signing-key length accepted by runtime.
	MinJWTSigningKeyBytes = 32
	maxClockSkew          = 60 * time.Second

	// KeySourcePool is the only key source supported by the v0.2.0 runtime.
	KeySourcePool = "pool"
	keySourceBYOK = "byok"
)

// RevocationStore checks if a virtual key has been revoked.
// Current runtime uses an in-memory set; Redis-backed shared revocation is a
// reserved cluster-mode target.
type RevocationStore interface {
	IsRevoked(keyID string) bool
}

// VirtualKeyClaims represents the JWT payload for an Aegis virtual key.
type VirtualKeyClaims struct {
	KeyID          string   `json:"kid"`
	Subject        string   `json:"sub"`                   // Owner identifier
	Models         []string `json:"models"`                // Allowed models
	MaxRPM         int      `json:"rpm"`                   // Per-key rate limit (0 = unlimited)
	MaxTPM         int      `json:"tpm"`                   // Per-key token limit (0 = unlimited)
	MaxConcurrency int      `json:"max_concurrency"`       // Per-key concurrent requests (0 = default)
	BudgetUSD      float64  `json:"budget"`                // Monthly budget in USD (0 = unlimited)
	KeySource      string   `json:"key_source"`            // Runtime: "pool"; reserved: "byok"
	BYOKKeyID      string   `json:"byok_key_id,omitempty"` // Reserved until BYOK binding exists
	PoolGroup      string   `json:"pool_group,omitempty"`  // Pool group for server-hosted keys
	IssuedAt       int64    `json:"iat"`
	ExpiresAt      int64    `json:"exp"`
	Issuer         string   `json:"iss"`
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

		// Check revocation list
		if cfg.Revocation != nil && cfg.Revocation.IsRevoked(claims.KeyID) {
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
	if len(signingKey) < MinJWTSigningKeyBytes {
		return nil, fmt.Errorf("signing key must be at least %d bytes", MinJWTSigningKeyBytes)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid token header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("invalid token header JSON: %w", err)
	}
	if header.Alg != "HS256" {
		return nil, fmt.Errorf("unsupported signing algorithm")
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid token signature: %w", err)
	}

	mac := hmac.New(sha256.New, signingKey)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	expectedSignature := mac.Sum(nil)
	if subtle.ConstantTimeCompare(signature, expectedSignature) != 1 {
		return nil, fmt.Errorf("invalid signature")
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid token payload: %w", err)
	}
	var claims VirtualKeyClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("invalid token claims: %w", err)
	}

	now := time.Now().Unix()
	if claims.KeyID == "" {
		return nil, fmt.Errorf("missing key id")
	}
	if len(claims.Models) == 0 {
		return nil, fmt.Errorf("missing model permissions")
	}
	if claims.ExpiresAt <= now {
		return nil, fmt.Errorf("token expired")
	}
	if claims.IssuedAt > now+int64(maxClockSkew.Seconds()) {
		return nil, fmt.Errorf("token issued in the future")
	}
	if maxTokenTTL > 0 {
		if claims.IssuedAt <= 0 {
			return nil, fmt.Errorf("missing issued-at claim")
		}
		if claims.ExpiresAt <= claims.IssuedAt {
			return nil, fmt.Errorf("token expires before issued-at")
		}
		tokenTTL := time.Unix(claims.ExpiresAt, 0).Sub(time.Unix(claims.IssuedAt, 0))
		if tokenTTL > maxTokenTTL {
			return nil, fmt.Errorf("token lifetime exceeds configured maximum")
		}
	}
	if expectedIssuer != "" && claims.Issuer != expectedIssuer {
		return nil, fmt.Errorf("invalid issuer")
	}
	if claims.KeySource == "" {
		claims.KeySource = KeySourcePool
	}
	switch claims.KeySource {
	case KeySourcePool:
		if claims.BYOKKeyID != "" {
			return nil, fmt.Errorf("byok_key_id is reserved for unsupported BYOK mode")
		}
	case keySourceBYOK:
		return nil, fmt.Errorf("BYOK key source is not implemented")
	default:
		return nil, fmt.Errorf("invalid key source")
	}
	if claims.MaxRPM < 0 {
		return nil, fmt.Errorf("RPM limit must not be negative")
	}
	if claims.BudgetUSD < 0 {
		return nil, fmt.Errorf("budget must not be negative")
	}
	if claims.BudgetUSD > 0 {
		return nil, fmt.Errorf("budget enforcement is not implemented")
	}
	if claims.MaxTPM < 0 {
		return nil, fmt.Errorf("TPM limit must not be negative")
	}
	if claims.MaxTPM > 0 {
		return nil, fmt.Errorf("TPM enforcement is not implemented")
	}
	if claims.MaxConcurrency < 0 {
		return nil, fmt.Errorf("concurrency limit must not be negative")
	}

	return &claims, nil
}

func authFailureJSON() []byte {
	return errorJSON("invalid or expired virtual key")
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
