// Package admin provides the administrative API scaffold for Aegis.
//
// The admin API is intended to be a separate HTTP handler group that manages:
//   - Virtual Key issuance and revocation
//   - BYOK key registration and deletion
//   - Usage and quota queries
//   - Provider channel management
//
// SECURITY:
//   - The admin API MUST be served on a separate port or behind mTLS
//   - Admin endpoints require a separate admin token (not a Virtual Key)
//   - All admin operations are audit-logged
//   - BYOK key submission is the ONLY path for user keys to enter the system
package admin

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/yknothing/AegisLLM/internal/kms"
)

// Handler provides the admin API endpoints.
type Handler struct {
	kmsProvider kms.Provider
	logger      *slog.Logger
	adminToken  []byte // Admin API authentication token
}

// Config holds admin API configuration.
type Config struct {
	AdminTokenEnv string // Environment variable holding the admin token
	ListenAddr    string // Separate listen address for admin API (e.g., ":9090")
}

// NewHandler creates a new admin API handler.
func NewHandler(kmsProvider kms.Provider, logger *slog.Logger, adminToken []byte) *Handler {
	return &Handler{
		kmsProvider: kmsProvider,
		logger:      logger,
		adminToken:  adminToken,
	}
}

// RegisterRoutes registers admin API routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /admin/keys/virtual", h.authMiddleware(h.issueVirtualKey))
	mux.HandleFunc("DELETE /admin/keys/virtual/{id}", h.authMiddleware(h.revokeVirtualKey))
	mux.HandleFunc("POST /admin/keys/byok", h.authMiddleware(h.registerBYOK))
	mux.HandleFunc("DELETE /admin/keys/byok/{id}", h.authMiddleware(h.deleteBYOK))
	mux.HandleFunc("GET /admin/usage/{keyId}", h.authMiddleware(h.getUsage))
	mux.HandleFunc("GET /admin/health", h.healthCheck)
}

// --- BYOK Endpoints ---

// BYOKRequest represents a request to register a user's own API key.
type BYOKRequest struct {
	UserID   string   `json:"user_id"`  // Owner identifier
	Provider string   `json:"provider"` // e.g., "openai", "anthropic"
	APIKey   string   `json:"api_key"`  // The user's real API key (will be encrypted)
	Models   []string `json:"models"`   // Models the user wants to access
}

// BYOKResponse is the planned response after successful BYOK registration.
type BYOKResponse struct {
	VirtualKey string `json:"virtual_key"` // The issued Virtual Key (JWT)
	KeyID      string `json:"key_id"`      // KMS key identifier for management
	ExpiresAt  int64  `json:"expires_at"`  // Virtual Key expiry (Unix timestamp)
}

// registerBYOK handles POST /admin/keys/byok
//
// SECURITY: This endpoint fails closed until key storage and virtual-key
// issuance are implemented as one atomic flow. It must never store a user key
// without returning a valid virtual key for that same key source.
func (h *Handler) registerBYOK(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "BYOK registration not yet implemented")
}

// deleteBYOK handles DELETE /admin/keys/byok/{id}
func (h *Handler) deleteBYOK(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "BYOK deletion not yet implemented")
}

// --- Virtual Key Endpoints ---

// issueVirtualKey handles POST /admin/keys/virtual
func (h *Handler) issueVirtualKey(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "virtual key issuance not yet implemented")
}

// revokeVirtualKey handles DELETE /admin/keys/virtual/{id}
func (h *Handler) revokeVirtualKey(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "virtual key revocation not yet implemented")
}

// --- Usage Endpoints ---

// getUsage handles GET /admin/usage/{keyId}
func (h *Handler) getUsage(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "usage query not yet implemented")
}

// --- Health ---

func (h *Handler) healthCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "aegis-admin"})
}

// --- Auth Middleware ---

// authMiddleware wraps a handler with admin token authentication.
// SECURITY: Uses constant-time comparison to prevent timing attacks.
func (h *Handler) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Admin-Token")
		if token == "" {
			writeError(w, http.StatusUnauthorized, "admin token required")
			return
		}

		// Constant-time comparison
		if !constantTimeEqual([]byte(token), h.adminToken) {
			writeError(w, http.StatusUnauthorized, "invalid admin token")
			return
		}

		next(w, r)
	}
}

// constantTimeEqual performs a constant-time byte comparison.
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{
			"message": message,
			"type":    "admin_error",
		},
	})
}
