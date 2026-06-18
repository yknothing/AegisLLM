// Package admin provides the administrative API for Aegis.
//
// The admin API is a separate HTTP handler group that manages:
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
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/yknothing/AegisLLM/internal/kms"
	"github.com/yknothing/AegisLLM/internal/utils"
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
	UserID   string `json:"user_id"`   // Owner identifier
	Provider string `json:"provider"`  // e.g., "openai", "anthropic"
	APIKey   string `json:"api_key"`   // The user's real API key (will be encrypted)
	Models   []string `json:"models"`  // Models the user wants to access
}

// BYOKResponse is returned after successful BYOK registration.
type BYOKResponse struct {
	VirtualKey string `json:"virtual_key"` // The issued Virtual Key (JWT)
	KeyID      string `json:"key_id"`      // KMS key identifier for management
	ExpiresAt  int64  `json:"expires_at"`  // Virtual Key expiry (Unix timestamp)
}

// registerBYOK handles POST /admin/keys/byok
//
// SECURITY FLOW:
//  1. Validate admin authentication
//  2. Read and validate the BYOK request
//  3. Encrypt the user's API key via KMS
//  4. Generate a Virtual Key (JWT) with key_source="byok"
//  5. Zero the plaintext API key from memory
//  6. Return the Virtual Key to the caller
//
// The user's real API key is encrypted and stored in KMS.
// It is NEVER returned in any API response after this point.
func (h *Handler) registerBYOK(w http.ResponseWriter, r *http.Request) {
	// Read request body with size limit (prevent memory exhaustion)
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	defer r.Body.Close()

	var req BYOKRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Validate required fields
	if req.UserID == "" || req.Provider == "" || req.APIKey == "" {
		writeError(w, http.StatusBadRequest, "user_id, provider, and api_key are required")
		return
	}

	// Construct KMS key ID for this user's key
	kmsKeyID := "byok-" + req.UserID + "-" + req.Provider

	// Encrypt and store the user's API key
	// SECURITY: The plaintext will be zeroed by StoreKey
	plaintext := []byte(req.APIKey)
	if err := h.kmsProvider.StoreKey(r.Context(), kmsKeyID, plaintext); err != nil {
		h.logger.Error("failed to store BYOK key",
			"user_id", req.UserID,
			"provider", req.Provider,
			// NEVER log the actual key
		)
		writeError(w, http.StatusInternalServerError, "failed to store key")
		return
	}

	// SECURITY: Zero the API key from the request struct
	utils.MemZeroString(&req.APIKey)

	// TODO: Generate Virtual Key (JWT) with claims:
	//   key_source: "byok"
	//   byok_key_id: kmsKeyID
	//   models: req.Models
	//   rpm: 0 (unlimited)
	//   tpm: 0 (unlimited)
	//   budget: 0 (unlimited)

	resp := BYOKResponse{
		VirtualKey: "vk_placeholder", // TODO: Generate real JWT
		KeyID:      kmsKeyID,
		ExpiresAt:  0, // TODO: Set expiry
	}

	h.logger.Info("BYOK key registered",
		"user_id", req.UserID,
		"provider", req.Provider,
		"kms_key_id", kmsKeyID,
		// NEVER log the actual key
	)

	writeJSON(w, http.StatusCreated, resp)
}

// deleteBYOK handles DELETE /admin/keys/byok/{id}
func (h *Handler) deleteBYOK(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("id")
	if keyID == "" {
		writeError(w, http.StatusBadRequest, "key id is required")
		return
	}

	if err := h.kmsProvider.DeleteKey(r.Context(), keyID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete key")
		return
	}

	h.logger.Info("BYOK key deleted", "kms_key_id", keyID)
	w.WriteHeader(http.StatusNoContent)
}

// --- Virtual Key Endpoints ---

// issueVirtualKey handles POST /admin/keys/virtual
func (h *Handler) issueVirtualKey(w http.ResponseWriter, r *http.Request) {
	// TODO: Accept parameters (user_id, models, rpm, tpm, budget, key_source)
	// Generate and sign a JWT Virtual Key
	writeError(w, http.StatusNotImplemented, "virtual key issuance not yet implemented")
}

// revokeVirtualKey handles DELETE /admin/keys/virtual/{id}
func (h *Handler) revokeVirtualKey(w http.ResponseWriter, r *http.Request) {
	// TODO: Add key ID to revocation list
	writeError(w, http.StatusNotImplemented, "virtual key revocation not yet implemented")
}

// --- Usage Endpoints ---

// getUsage handles GET /admin/usage/{keyId}
func (h *Handler) getUsage(w http.ResponseWriter, r *http.Request) {
	// TODO: Query quota store for usage data
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
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{
			"message": message,
			"type":    "admin_error",
		},
	})
}
