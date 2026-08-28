// Package admin provides the loopback administrative API for Aegis (ADR-007).
//
// SECURITY:
//   - Mounted only on a loopback listener; never on the data-plane port.
//   - Admin endpoints require X-Admin-Token with constant-time comparison.
//   - Request and response bodies are never logged. Issued JWTs are not logged.
//   - BYOK remains 501 until owner/provider binding exists.
package admin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/yknothing/AegisLLM/internal/gatewayconst"
	"github.com/yknothing/AegisLLM/internal/kms"
	"github.com/yknothing/AegisLLM/internal/quota"
	"github.com/yknothing/AegisLLM/internal/revocation"
	"github.com/yknothing/AegisLLM/internal/utils"
	"github.com/yknothing/AegisLLM/internal/virtualkey"
)

const (
	adminTokenHeader      = "X-Admin-Token"
	adminAuthFailedError  = "admin authentication failed"
	adminIssueInvalid     = "invalid issue request"
	adminIssueFailed      = "virtual key issuance failed"
	adminRevokeFailed     = "virtual key revocation failed"
	adminUsageUnavailable = "usage query unavailable"
	adminJSONContentType  = gatewayconst.JSONContentType
	pathAdminVirtualKeys  = "/admin/keys/virtual"
	pathAdminVirtualKey   = "/admin/keys/virtual/{id}"
	pathAdminBYOK         = "/admin/keys/byok"
	pathAdminBYOKID       = "/admin/keys/byok/{id}"
	pathAdminUsage        = "/admin/usage/{keyId}"
	pathAdminHealth       = "/admin/health"
)

// KeyRevoker durably revokes a virtual-key ID.
type KeyRevoker interface {
	Revoke(ctx context.Context, issuer, keyID string, now time.Time, maxTokenTTL time.Duration) (revocation.CommitResult, error)
}

// UsageReader returns current in-memory usage for a virtual key.
type UsageReader interface {
	UsageOf(ctx context.Context, keyID string) (*quota.Usage, error)
}

// Services are the control-plane dependencies for issue/revoke/usage.
type Services struct {
	SigningKey    []byte
	Issuer        string
	MaxTTL        time.Duration
	AllowedModels []string
	Revoker       KeyRevoker
	Quota         UsageReader
	Now           func() time.Time
}

// Handler provides the admin API endpoints.
type Handler struct {
	kmsProvider kms.Provider
	logger      *slog.Logger
	adminToken  []byte
	services    Services
}

// Config holds admin API configuration.
type Config struct {
	AdminTokenEnv string
	ListenAddr    string
}

// NewHandler creates an admin API handler without issue/revoke/usage services.
func NewHandler(kmsProvider kms.Provider, logger *slog.Logger, adminToken []byte) *Handler {
	return NewHandlerWithServices(kmsProvider, logger, adminToken, Services{})
}

// NewHandlerWithServices creates an admin API handler with control-plane services.
func NewHandlerWithServices(
	kmsProvider kms.Provider,
	logger *slog.Logger,
	adminToken []byte,
	services Services,
) *Handler {
	if services.Now == nil {
		services.Now = time.Now
	}
	return &Handler{
		kmsProvider: kmsProvider,
		logger:      logger,
		adminToken:  adminToken,
		services:    services,
	}
}

// Close zeros admin token and signing-key copies. Safe to call twice.
func (h *Handler) Close() error {
	if h == nil {
		return nil
	}
	utils.MemZero(h.adminToken)
	h.adminToken = nil
	utils.MemZero(h.services.SigningKey)
	h.services.SigningKey = nil
	return nil
}

// RegisterRoutes registers admin API routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc(gatewayconst.HTTPRoute(http.MethodPost, pathAdminVirtualKeys), h.authMiddleware(h.issueVirtualKey))
	mux.HandleFunc(gatewayconst.HTTPRoute(http.MethodDelete, pathAdminVirtualKey), h.authMiddleware(h.revokeVirtualKey))
	mux.HandleFunc(gatewayconst.HTTPRoute(http.MethodPost, pathAdminBYOK), h.authMiddleware(h.registerBYOK))
	mux.HandleFunc(gatewayconst.HTTPRoute(http.MethodDelete, pathAdminBYOKID), h.authMiddleware(h.deleteBYOK))
	mux.HandleFunc(gatewayconst.HTTPRoute(http.MethodGet, pathAdminUsage), h.authMiddleware(h.getUsage))
	mux.HandleFunc(gatewayconst.HTTPRoute(http.MethodGet, pathAdminHealth), h.authMiddleware(h.healthCheck))
}

// --- BYOK Endpoints ---

// BYOKRequest represents a request to register a user's own API key.
type BYOKRequest struct {
	UserID   string   `json:"user_id"`
	Provider string   `json:"provider"`
	APIKey   string   `json:"api_key"`
	Models   []string `json:"models"`
}

// BYOKResponse is the planned response after successful BYOK registration.
type BYOKResponse struct {
	VirtualKey string `json:"virtual_key"`
	KeyID      string `json:"key_id"`
	ExpiresAt  int64  `json:"expires_at"`
}

func (h *Handler) registerBYOK(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "BYOK registration not yet implemented")
}

func (h *Handler) deleteBYOK(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "BYOK deletion not yet implemented")
}

type issueVirtualKeyRequest struct {
	Subject        string   `json:"subject"`
	Models         []string `json:"models"`
	TTL            string   `json:"ttl"`
	MaxRPM         int      `json:"rpm"`
	MaxTPM         int      `json:"tpm"`
	MaxConcurrency int      `json:"max_concurrency"`
	BudgetUSD      float64  `json:"budget"`
}

type issueVirtualKeyResponse struct {
	VirtualKey string `json:"virtual_key"`
	KeyID      string `json:"key_id"`
	ExpiresAt  int64  `json:"expires_at"`
}

// issueVirtualKey signs a pool virtual key after validating models against the catalog.
func (h *Handler) issueVirtualKey(w http.ResponseWriter, r *http.Request) {
	if len(h.services.SigningKey) < virtualkey.MinSigningKeyBytes {
		writeError(w, http.StatusServiceUnavailable, adminIssueFailed)
		return
	}
	var req issueVirtualKeyRequest
	if err := decodeAdminJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, adminIssueInvalid)
		return
	}
	if strings.TrimSpace(req.Subject) == "" || len(req.Models) == 0 {
		writeError(w, http.StatusBadRequest, adminIssueInvalid)
		return
	}
	if !modelsAllowed(req.Models, h.services.AllowedModels) {
		writeError(w, http.StatusBadRequest, adminIssueInvalid)
		return
	}
	var ttl time.Duration
	if strings.TrimSpace(req.TTL) != "" {
		parsed, err := time.ParseDuration(req.TTL)
		if err != nil {
			writeError(w, http.StatusBadRequest, adminIssueInvalid)
			return
		}
		ttl = parsed
	}
	token, claims, err := virtualkey.Issue(h.services.SigningKey, virtualkey.IssueOptions{
		Subject:        req.Subject,
		Models:         req.Models,
		MaxRPM:         req.MaxRPM,
		MaxTPM:         req.MaxTPM,
		MaxConcurrency: req.MaxConcurrency,
		BudgetUSD:      req.BudgetUSD,
		TTL:            ttl,
		MaxTTL:         h.services.MaxTTL,
		Issuer:         h.services.Issuer,
		Now:            h.services.Now(),
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, adminIssueInvalid)
		return
	}
	writeJSON(w, http.StatusOK, issueVirtualKeyResponse{
		VirtualKey: token,
		KeyID:      claims.KeyID,
		ExpiresAt:  claims.ExpiresAt,
	})
}

// revokeVirtualKey durably revokes the path key ID.
func (h *Handler) revokeVirtualKey(w http.ResponseWriter, r *http.Request) {
	if h.services.Revoker == nil {
		writeError(w, http.StatusServiceUnavailable, adminRevokeFailed)
		return
	}
	keyID := strings.TrimSpace(r.PathValue("id"))
	if keyID == "" {
		writeError(w, http.StatusBadRequest, adminRevokeFailed)
		return
	}
	_, err := h.services.Revoker.Revoke(
		r.Context(),
		h.services.Issuer,
		keyID,
		h.services.Now(),
		h.services.MaxTTL,
	)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, adminRevokeFailed)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type usageResponse struct {
	KeyID        string  `json:"key_id"`
	TotalCostUSD float64 `json:"total_cost_usd"`
	TotalTokens  int64   `json:"total_tokens"`
	RequestCount int64   `json:"request_count"`
}

func (h *Handler) getUsage(w http.ResponseWriter, r *http.Request) {
	if h.services.Quota == nil {
		writeError(w, http.StatusServiceUnavailable, adminUsageUnavailable)
		return
	}
	keyID := strings.TrimSpace(r.PathValue("keyId"))
	if keyID == "" {
		writeError(w, http.StatusBadRequest, adminUsageUnavailable)
		return
	}
	usage, err := h.services.Quota.UsageOf(r.Context(), keyID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, adminUsageUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, usageResponse{
		KeyID:        keyID,
		TotalCostUSD: usage.TotalCostUSD,
		TotalTokens:  usage.TotalTokens,
		RequestCount: usage.RequestCount,
	})
}

func (h *Handler) healthCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "aegis-admin"})
}

func (h *Handler) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get(adminTokenHeader)
		if token == "" {
			writeError(w, http.StatusUnauthorized, adminAuthFailedError)
			return
		}

		if !constantTimeEqual([]byte(token), h.adminToken) {
			writeError(w, http.StatusUnauthorized, adminAuthFailedError)
			return
		}

		next(w, r)
	}
}

func constantTimeEqual(a, b []byte) bool {
	aHash := sha256.Sum256(a)
	bHash := sha256.Sum256(b)
	sameLength := len(a) == len(b)
	sameHash := subtle.ConstantTimeCompare(aHash[:], bHash[:]) == 1
	return sameLength && sameHash
}

func decodeAdminJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	limited := http.MaxBytesReader(w, r.Body, gatewayconst.MaxAdminRequestBytes)
	defer func() { _ = limited.Close() }()
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if extra != nil {
		return errors.New("multiple JSON values are not allowed")
	}
	return nil
}

func modelsAllowed(requested, allowed []string) bool {
	catalog := make(map[string]struct{}, len(allowed))
	for _, model := range allowed {
		catalog[model] = struct{}{}
	}
	if len(catalog) == 0 {
		return false
	}
	for _, model := range requested {
		if _, ok := catalog[strings.TrimSpace(model)]; !ok {
			return false
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", adminJSONContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", adminJSONContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{
			"message": message,
			"type":    "admin_error",
		},
	})
}
